use crate::AppResult;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn export_results(
    temp_dir: &Path,
    output_dir: &Path,
    yaml_skipped_categories: &BTreeSet<String>,
) -> AppResult<()> {
    println!("\n===== 移动输出文件 =====");
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("创建输出目录失败 {:?}: {}", output_dir, error))?;

    for source_path in list_rule_files(temp_dir)? {
        let Some(file_name) = source_path.file_name() else {
            eprintln!("警告: 跳过异常文件名路径 {:?}", source_path);
            continue;
        };

        let destination = output_dir.join(file_name);
        move_rule_file(&source_path, &destination)?;
    }

    println!("\n===== 生成 Clash YAML =====");
    generate_clash_yaml_files(output_dir, yaml_skipped_categories)
}

fn list_rule_files(dir: &Path) -> AppResult<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for entry in fs::read_dir(dir).map_err(|error| format!("读取目录失败 {:?}: {}", dir, error))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("警告: 读取目录项失败: {}", error);
                continue;
            }
        };

        let path = entry.path();
        if path
            .extension()
            .map(|extension| extension == "list")
            .unwrap_or(false)
        {
            paths.push(path);
        }
    }

    paths.sort_unstable();
    Ok(paths)
}

fn move_rule_file(source_path: &Path, destination: &Path) -> AppResult<()> {
    match fs::rename(source_path, destination) {
        Ok(()) => {
            println!("已移动: {}", destination.display());
            Ok(())
        }
        Err(rename_error) => match fs::copy(source_path, destination) {
            Ok(_) => {
                fs::remove_file(source_path)
                    .map_err(|error| format!("删除原文件失败 {:?}: {}", source_path, error))?;
                println!("已复制: {}", destination.display());
                Ok(())
            }
            Err(copy_error) => Err(format!(
                "移动文件失败 {:?}: {} / {}",
                source_path, rename_error, copy_error
            )),
        },
    }
}

fn generate_clash_yaml_files(
    output_dir: &Path,
    yaml_skipped_categories: &BTreeSet<String>,
) -> AppResult<()> {
    let clash_dir = output_dir.join("Clash");
    fs::create_dir_all(&clash_dir)
        .map_err(|error| format!("创建 Clash 输出目录失败 {:?}: {}", clash_dir, error))?;

    for list_path in list_rule_files(output_dir)? {
        let Some(stem) = list_path.file_stem() else {
            eprintln!("警告: 跳过异常文件名路径 {:?}", list_path);
            continue;
        };
        let category = stem.to_string_lossy();
        if yaml_skipped_categories.contains(category.as_ref()) {
            println!("跳过 YAML: {} 使用 geosite 数据源", category);
            continue;
        }

        let yaml_path = clash_dir.join(format!("{category}.yaml"));
        write_clash_yaml(&list_path, &yaml_path)?;
    }

    Ok(())
}

fn write_clash_yaml(list_path: &Path, yaml_path: &Path) -> AppResult<()> {
    let content = fs::read_to_string(list_path)
        .map_err(|error| format!("读取规则文件失败 {:?}: {}", list_path, error))?;

    let (output, rule_count) = build_yaml_payload(&content);

    fs::write(yaml_path, output)
        .map_err(|error| format!("写入 YAML 失败 {:?}: {}", yaml_path, error))?;

    println!("已生成: {} ({} 条规则)", yaml_path.display(), rule_count);

    Ok(())
}

fn build_yaml_payload(content: &str) -> (String, usize) {
    let payload: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    let mut output = String::with_capacity(payload.len() * 40 + 16);
    output.push_str("payload:\n");
    for rule in &payload {
        output.push_str("  - ");
        output.push_str(&yaml_quote(rule));
        output.push('\n');
    }

    (output, payload.len())
}

fn yaml_quote(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{build_yaml_payload, yaml_quote};

    #[test]
    fn build_yaml_payload_keeps_all_non_comment_rules() {
        let (yaml, count) = build_yaml_payload(
            r#"
# comment
DOMAIN,example.com
PROCESS-NAME,Firefox
DOMAIN-REGEX,^ad[sx]?\.
"#,
        );

        assert_eq!(count, 3);
        assert!(yaml.contains("  - 'DOMAIN,example.com'\n"));
        assert!(yaml.contains("  - 'PROCESS-NAME,Firefox'\n"));
        assert!(yaml.contains("  - 'DOMAIN-REGEX,^ad[sx]?\\.'\n"));
    }

    #[test]
    fn yaml_quote_escapes_single_quotes() {
        assert_eq!(yaml_quote("DOMAIN,foo'bar.com"), "'DOMAIN,foo''bar.com'");
    }

    #[test]
    fn yaml_skip_set_contains_geosite_categories() {
        let skipped = BTreeSet::from([String::from("CN")]);
        assert!(skipped.contains("CN"));
        assert!(!skipped.contains("Block"));
    }
}
