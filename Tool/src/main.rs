mod dedup;

use futures::stream::{self, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::fs as async_fs;
use tokio::io::AsyncWriteExt;

/// 配置文件结构
#[derive(Debug, Deserialize)]
struct Config {
    /// 临时文件存放路径
    temp_dir: String,
    /// 输出目录（去重后的规则文件）
    output_dir: Option<String>,
    /// 并发下载数
    concurrent_downloads: Option<usize>,
    /// 分类定义
    categories: HashMap<String, Category>,
}

/// 分类配置
#[derive(Debug, Deserialize)]
struct Category {
    /// 输入规则类型（Rulesets / ABP / ADG）
    #[serde(default)]
    r#type: dedup::CategoryType,
    /// 规则文件URL列表
    urls: Vec<String>,
}

/// 下载单个文件
async fn download_file(
    client: &reqwest::Client,
    url: &str,
    save_path: &Path,
) -> Result<(), String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("请求失败 {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("下载失败 {}: HTTP {}", url, response.status()));
    }

    let content = response
        .bytes()
        .await
        .map_err(|e| format!("读取响应失败 {}: {}", url, e))?;

    let mut file = async_fs::File::create(save_path)
        .await
        .map_err(|e| format!("创建文件失败 {:?}: {}", save_path, e))?;

    file.write_all(&content)
        .await
        .map_err(|e| format!("写入文件失败 {:?}: {}", save_path, e))?;

    Ok(())
}

/// 下载所有分类的规则文件
async fn download_all_rules(config: &Config) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; RuleTool/1.0)")
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("创建HTTP客户端失败: {}", e))?;

    let temp_dir = Path::new(&config.temp_dir);

    // 收集所有下载任务
    let mut tasks: Vec<(String, String, std::path::PathBuf)> = Vec::new();

    for (category_name, category) in &config.categories {
        let category_dir = temp_dir.join(category_name);

        // 创建分类目录
        fs::create_dir_all(&category_dir)
            .map_err(|e| format!("创建目录失败 {:?}: {}", category_dir, e))?;

        for (index, url) in category.urls.iter().enumerate() {
            // 从URL提取文件名或使用索引
            let filename = url
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty() && s.contains('.'))
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("list_{}.txt", index));

            let save_path = category_dir.join(&filename);
            tasks.push((category_name.clone(), url.clone(), save_path));
        }
    }

    let total = tasks.len();
    println!("准备下载 {} 个规则文件...", total);

    let concurrent = config.concurrent_downloads.unwrap_or(10);

    // 并发下载
    let results: Vec<_> = stream::iter(tasks)
        .map(|(category, url, path)| {
            let client = client.clone();
            async move {
                let result = download_file(&client, &url, &path).await;
                (category, url, result)
            }
        })
        .buffer_unordered(concurrent)
        .collect()
        .await;

    // 统计结果
    let mut success = 0;
    let mut failed = 0;

    for (category, url, result) in results {
        match result {
            Ok(()) => {
                success += 1;
                println!("  ✓ [{}] {}", category, url);
            }
            Err(e) => {
                failed += 1;
                eprintln!("  ✗ [{}] {}", category, e);
            }
        }
    }

    println!("\n下载完成: {} 成功, {} 失败", success, failed);

    if failed > 0 && success == 0 {
        return Err("所有下载都失败了".to_string());
    }

    Ok(())
}

/// 加载配置文件
fn load_config(path: &str) -> Result<Config, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("读取配置文件失败 {}: {}", path, e))?;

    toml::from_str(&content).map_err(|e| format!("解析配置文件失败: {}", e))
}

async fn run() -> Result<(), String> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    println!("========================================");
    println!("       规则去重工具 v0.1.0");
    println!("========================================\n");

    // 加载配置
    println!("加载配置: {}", config_path);
    let config = load_config(&config_path)?;

    println!("临时目录: {}", config.temp_dir);
    println!("分类数量: {}", config.categories.len());
    for (name, cat) in &config.categories {
        println!("  - {}: {:?}, {} 个URL", name, cat.r#type, cat.urls.len());
    }
    println!();

    // 清理并创建临时目录
    let temp_dir = Path::new(&config.temp_dir);
    if temp_dir.exists() {
        println!("清理临时目录...");
        if let Err(e) = fs::remove_dir_all(temp_dir) {
            eprintln!("警告: 清理临时目录失败: {}", e);
        }
    }
    fs::create_dir_all(temp_dir)
        .map_err(|e| format!("创建临时目录失败 {:?}: {}", temp_dir, e))?;

    // 下载规则文件
    println!("\n===== 下载规则文件 =====");
    download_all_rules(&config).await?;

    // 运行去重
    println!("\n===== 去重处理 =====");
    let category_types: HashMap<String, dedup::CategoryType> = config
        .categories
        .iter()
        .map(|(name, cat)| (name.clone(), cat.r#type))
        .collect();
    dedup::run(&config.temp_dir, &category_types)?;

    // 如果指定了输出目录，移动结果文件
    if let Some(output_dir) = &config.output_dir {
        println!("\n===== 移动输出文件 =====");
        let output_path = Path::new(output_dir);
        fs::create_dir_all(output_path)
            .map_err(|e| format!("创建输出目录失败 {:?}: {}", output_path, e))?;

        // 移动所有 .list 文件到输出目录
        let entries = fs::read_dir(temp_dir)
            .map_err(|e| format!("读取临时目录失败 {:?}: {}", temp_dir, e))?;

        for entry in entries {
            let entry = match entry {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("警告: 读取目录项失败: {}", e);
                    continue;
                }
            };

            let path = entry.path();
            if path.extension().map(|e| e == "list").unwrap_or(false) {
                let Some(file_name) = path.file_name() else {
                    eprintln!("警告: 跳过异常文件名路径 {:?}", path);
                    continue;
                };

                let dest = output_path.join(file_name);
                if let Err(e) = fs::rename(&path, &dest) {
                    // 如果跨文件系统，尝试复制后删除
                    if let Err(e2) = fs::copy(&path, &dest) {
                        eprintln!("移动文件失败 {:?}: {} / {}", path, e, e2);
                    } else {
                        if let Err(remove_err) = fs::remove_file(&path) {
                            eprintln!("警告: 删除原文件失败 {:?}: {}", path, remove_err);
                        }
                        println!("已复制: {}", dest.display());
                    }
                } else {
                    println!("已移动: {}", dest.display());
                }
            }
        }

        println!("\n===== 生成 Clash YAML =====");
        generate_clash_yaml_files(output_path)?;
    }

    println!("\n========================================");
    println!("              全部完成!");
    println!("========================================");

    Ok(())
}

fn generate_clash_yaml_files(output_dir: &Path) -> Result<(), String> {
    let clash_dir = output_dir.join("Clash");
    fs::create_dir_all(&clash_dir)
        .map_err(|e| format!("创建 Clash 输出目录失败 {:?}: {}", clash_dir, e))?;

    let entries = fs::read_dir(output_dir)
        .map_err(|e| format!("读取输出目录失败 {:?}: {}", output_dir, e))?;

    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                eprintln!("警告: 读取输出目录项失败: {}", e);
                continue;
            }
        };

        let path = entry.path();
        if path.extension().map(|e| e == "list").unwrap_or(false) {
            let Some(stem) = path.file_stem() else {
                eprintln!("警告: 跳过异常文件名路径 {:?}", path);
                continue;
            };

            let yaml_path = clash_dir.join(format!("{}.yaml", stem.to_string_lossy()));
            write_clash_yaml(&path, &yaml_path)?;
        }
    }

    Ok(())
}

fn write_clash_yaml(list_path: &Path, yaml_path: &Path) -> Result<(), String> {
    let content = fs::read_to_string(list_path)
        .map_err(|e| format!("读取规则文件失败 {:?}: {}", list_path, e))?;

    let mut payload: Vec<String> = Vec::new();
    let mut skipped = 0usize;

    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if is_clash_payload_rule(line) {
            payload.push(line.to_string());
        } else {
            skipped += 1;
        }
    }

    let mut out = String::with_capacity(payload.len() * 32 + 16);
    out.push_str("payload:\n");
    for rule in &payload {
        out.push_str("  - ");
        out.push_str(rule);
        out.push('\n');
    }

    fs::write(yaml_path, out).map_err(|e| format!("写入 YAML 失败 {:?}: {}", yaml_path, e))?;

    println!(
        "已生成: {} ({} 条, 跳过 {} 条非 Clash 规则)",
        yaml_path.display(),
        payload.len(),
        skipped
    );

    Ok(())
}

fn is_clash_payload_rule(line: &str) -> bool {
    ["DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "IP-CIDR,", "IP-CIDR6,"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}
