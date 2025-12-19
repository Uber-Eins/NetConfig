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

#[tokio::main]
async fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    println!("========================================");
    println!("       Clash 规则去重工具 v0.1.0");
    println!("========================================\n");

    // 加载配置
    println!("加载配置: {}", config_path);
    let config = match load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    };

    println!("临时目录: {}", config.temp_dir);
    println!("分类数量: {}", config.categories.len());
    for (name, cat) in &config.categories {
        println!("  - {}: {} 个URL", name, cat.urls.len());
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
    fs::create_dir_all(temp_dir).expect("创建临时目录失败");

    // 下载规则文件
    println!("\n===== 下载规则文件 =====");
    if let Err(e) = download_all_rules(&config).await {
        eprintln!("下载失败: {}", e);
        std::process::exit(1);
    }

    // 运行去重
    println!("\n===== 去重处理 =====");
    if let Err(e) = dedup::run(&config.temp_dir) {
        eprintln!("去重失败: {}", e);
        std::process::exit(1);
    }

    // 如果指定了输出目录，移动结果文件
    if let Some(output_dir) = &config.output_dir {
        println!("\n===== 移动输出文件 =====");
        let output_path = Path::new(output_dir);
        fs::create_dir_all(output_path).expect("创建输出目录失败");

        // 移动所有 .list 文件到输出目录
        for entry in fs::read_dir(temp_dir).expect("读取临时目录失败") {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().map(|e| e == "list").unwrap_or(false) {
                    let dest = output_path.join(path.file_name().unwrap());
                    if let Err(e) = fs::rename(&path, &dest) {
                        // 如果跨文件系统，尝试复制后删除
                        if let Err(e2) = fs::copy(&path, &dest) {
                            eprintln!("移动文件失败 {:?}: {} / {}", path, e, e2);
                        } else {
                            fs::remove_file(&path).ok();
                            println!("已复制: {}", dest.display());
                        }
                    } else {
                        println!("已移动: {}", dest.display());
                    }
                }
            }
        }
    }

    println!("\n========================================");
    println!("              全部完成!");
    println!("========================================");
}
