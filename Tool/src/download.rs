use crate::AppResult;
use crate::config::Config;
use crate::geosite;
use futures::stream::{self, StreamExt};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs as async_fs;
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
struct DownloadTask {
    category: String,
    url: String,
    save_path: PathBuf,
}

#[derive(Debug)]
struct GeositeTask {
    category: String,
    selector: String,
    database_url: String,
    save_path: PathBuf,
}

pub(crate) async fn download_all_rules(config: &Config) -> AppResult<()> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; RuleTool/1.0)")
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|error| format!("创建HTTP客户端失败: {}", error))?;

    let url_tasks = collect_download_tasks(config)?;
    let geosite_tasks = collect_geosite_tasks(config)?;
    let total = url_tasks.len() + geosite_tasks.len();
    println!("准备处理 {} 个规则源...", total);

    let mut success = 0usize;
    let mut failed = 0usize;

    for (category, selector, result) in process_geosite_tasks(&client, &geosite_tasks).await {
        match result {
            Ok(rule_count) => {
                success += 1;
                println!(
                    "  ✓ [{}] geosite:{} ({} 条规则)",
                    category, selector, rule_count
                );
            }
            Err(error) => {
                failed += 1;
                eprintln!("  ✗ [{}] geosite:{} {}", category, selector, error);
            }
        }
    }

    let results: Vec<_> = stream::iter(url_tasks)
        .map(|task| {
            let client = client.clone();
            async move {
                let result = download_file(&client, &task.url, &task.save_path).await;
                (task.category, task.url, result)
            }
        })
        .buffer_unordered(config.concurrent_downloads())
        .collect()
        .await;

    for (category, url, result) in results {
        match result {
            Ok(()) => {
                success += 1;
                println!("  ✓ [{}] {}", category, url);
            }
            Err(error) => {
                failed += 1;
                eprintln!("  ✗ [{}] {}", category, error);
            }
        }
    }

    println!("\n下载完成: {} 成功, {} 失败", success, failed);

    if failed > 0 && success == 0 {
        return Err("所有下载都失败了".to_string());
    }

    Ok(())
}

async fn process_geosite_tasks(
    client: &reqwest::Client,
    tasks: &[GeositeTask],
) -> Vec<(String, String, AppResult<usize>)> {
    if tasks.is_empty() {
        return Vec::new();
    }

    let database_results = download_geosite_databases(client, tasks).await;

    tasks
        .iter()
        .map(|task| {
            let result = match database_results.get(&task.database_url) {
                Some(Ok(bytes)) => {
                    geosite::write_rules_file(bytes, &task.selector, &task.save_path)
                }
                Some(Err(error)) => Err(format!("下载 geosite_db 失败: {}", error)),
                None => Err("geosite_db 下载结果不存在".to_string()),
            };

            (task.category.clone(), task.selector.clone(), result)
        })
        .collect()
}

async fn download_geosite_databases(
    client: &reqwest::Client,
    tasks: &[GeositeTask],
) -> BTreeMap<String, AppResult<Vec<u8>>> {
    let mut unique_urls = tasks
        .iter()
        .map(|task| task.database_url.clone())
        .collect::<Vec<_>>();
    unique_urls.sort_unstable();
    unique_urls.dedup();

    let results: Vec<_> = stream::iter(unique_urls)
        .map(|url| {
            let client = client.clone();
            async move {
                let result = download_bytes(&client, &url).await;
                (url, result)
            }
        })
        .buffer_unordered(4)
        .collect()
        .await;

    results.into_iter().collect()
}

fn collect_download_tasks(config: &Config) -> AppResult<Vec<DownloadTask>> {
    let mut tasks = Vec::new();

    for (category_name, category) in &config.categories {
        let category_dir = config.temp_dir.join(category_name);
        fs::create_dir_all(&category_dir)
            .map_err(|error| format!("创建目录失败 {:?}: {}", category_dir, error))?;

        for (index, url) in category.urls.iter().enumerate() {
            tasks.push(DownloadTask {
                category: category_name.clone(),
                url: url.clone(),
                save_path: category_dir.join(build_filename(url, index)),
            });
        }
    }

    Ok(tasks)
}

fn collect_geosite_tasks(config: &Config) -> AppResult<Vec<GeositeTask>> {
    let mut tasks = Vec::new();

    for (category_name, category) in &config.categories {
        let Some(selector) = category.geosite.as_ref() else {
            continue;
        };

        let Some(database_url) = category.geosite_db.as_ref() else {
            return Err(format!("分类 {} 缺少 geosite_db 配置", category_name));
        };

        let category_dir = config.temp_dir.join(category_name);
        fs::create_dir_all(&category_dir)
            .map_err(|error| format!("创建目录失败 {:?}: {}", category_dir, error))?;

        let sanitized = sanitize_filename(selector);
        tasks.push(GeositeTask {
            category: category_name.clone(),
            selector: selector.clone(),
            database_url: database_url.clone(),
            save_path: category_dir.join(format!("geosite_{sanitized}.list")),
        });
    }

    Ok(tasks)
}

async fn download_file(client: &reqwest::Client, url: &str, save_path: &Path) -> AppResult<()> {
    let content = download_bytes(client, url).await?;

    let mut file = async_fs::File::create(save_path)
        .await
        .map_err(|error| format!("创建文件失败 {:?}: {}", save_path, error))?;

    file.write_all(&content)
        .await
        .map_err(|error| format!("写入文件失败 {:?}: {}", save_path, error))?;

    Ok(())
}

async fn download_bytes(client: &reqwest::Client, url: &str) -> AppResult<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("请求失败 {}: {}", url, error))?;

    if !response.status().is_success() {
        return Err(format!("下载失败 {}: HTTP {}", url, response.status()));
    }

    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|error| format!("读取响应失败 {}: {}", url, error))
}

fn build_filename(url: &str, index: usize) -> String {
    url.rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty() && segment.contains('.'))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("list_{index}.txt"))
}

fn sanitize_filename(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{build_filename, sanitize_filename};

    #[test]
    fn build_filename_prefers_url_tail() {
        assert_eq!(
            build_filename("https://example.com/path/rules.list", 0),
            "rules.list"
        );
    }

    #[test]
    fn build_filename_falls_back_to_index() {
        assert_eq!(
            build_filename("https://example.com/download", 2),
            "list_2.txt"
        );
    }

    #[test]
    fn sanitize_filename_replaces_non_safe_characters() {
        assert_eq!(sanitize_filename("cn@ads/all"), "cn_ads_all");
    }
}
