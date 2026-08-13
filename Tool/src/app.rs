use crate::config::Config;
use crate::{AppResult, dedup, download, output};
use std::env;
use std::fs;
use std::path::Path;

pub async fn run() -> AppResult<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    print_banner();
    println!("加载配置: {}", config_path);
    let config = Config::load(&config_path)?;

    print_config_summary(&config);
    prepare_temp_dir(&config.temp_dir)?;

    println!("\n===== 下载规则文件 =====");
    download::download_all_rules(&config).await?;

    println!("\n===== 去重处理 =====");
    dedup::run(&config.temp_dir)?;

    if let Some(output_dir) = config.output_dir.as_deref() {
        output::export_results(
            &config.temp_dir,
            output_dir,
            &config.yaml_skipped_categories(),
            &config.mem_optimised_categories(),
        )?;
    }

    println!("\n========================================");
    println!("              全部完成!");
    println!("========================================");

    Ok(())
}

fn print_banner() {
    println!("========================================");
    println!("       Seshat v0.1.5");
    println!("========================================\n");
}

fn print_config_summary(config: &Config) {
    println!("临时目录: {}", config.temp_dir.display());
    println!("分类数量: {}", config.categories.len());
    for (name, category) in &config.categories {
        let memory_optimisation = if category.mem_optimise {
            ", mem_optimise=true"
        } else {
            ""
        };
        match category.geosite.as_deref() {
            Some(geosite) => {
                println!(
                    "  - {}: {} 个URL, geosite={}{}",
                    name,
                    category.urls.len(),
                    geosite,
                    memory_optimisation
                );
            }
            None => {
                println!(
                    "  - {}: {} 个URL{}",
                    name,
                    category.urls.len(),
                    memory_optimisation
                );
            }
        }
    }
    println!();
}

fn prepare_temp_dir(temp_dir: &Path) -> AppResult<()> {
    if temp_dir.exists() {
        println!("清理临时目录...");
        if let Err(error) = fs::remove_dir_all(temp_dir) {
            eprintln!("警告: 清理临时目录失败: {}", error);
        }
    }

    fs::create_dir_all(temp_dir)
        .map_err(|error| format!("创建临时目录失败 {:?}: {}", temp_dir, error))
}
