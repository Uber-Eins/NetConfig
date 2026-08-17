use crate::{AppResult, mrs};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn export_results(
    temp_dir: &Path,
    output_dir: &Path,
    mem_optimised_categories: &BTreeSet<String>,
) -> AppResult<()> {
    println!("\n===== 暂存输出文件 =====");
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("创建输出目录失败 {:?}: {}", output_dir, error))?;

    let staging_dir = create_work_dir(output_dir, "staging")?;
    let result = (|| {
        for source_path in list_rule_files(temp_dir)? {
            let file_name = source_path
                .file_name()
                .ok_or_else(|| format!("规则文件缺少文件名: {:?}", source_path))?;
            let staged_path = staging_dir.join(file_name);
            fs::copy(&source_path, &staged_path).map_err(|error| {
                format!(
                    "暂存规则文件失败 {:?} -> {:?}: {}",
                    source_path, staged_path, error
                )
            })?;
        }

        println!("\n===== 生成 Clash 规则集 =====");
        generate_clash_files(&staging_dir, mem_optimised_categories)?;

        println!("\n===== 发布输出文件 =====");
        publish_staged_files(&staging_dir, output_dir)
    })();

    finish_with_cleanup(result, &staging_dir)
}

fn list_rule_files(dir: &Path) -> AppResult<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for entry in fs::read_dir(dir).map_err(|error| format!("读取目录失败 {:?}: {}", dir, error))?
    {
        let entry = entry.map_err(|error| format!("读取目录项失败 {:?}: {}", dir, error))?;

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

fn generate_clash_files(
    output_dir: &Path,
    mem_optimised_categories: &BTreeSet<String>,
) -> AppResult<()> {
    let clash_dir = output_dir.join("Clash");
    fs::create_dir_all(&clash_dir)
        .map_err(|error| format!("创建 Clash 输出目录失败 {:?}: {}", clash_dir, error))?;

    for list_path in list_rule_files(output_dir)? {
        let stem = list_path
            .file_stem()
            .ok_or_else(|| format!("规则文件缺少文件名: {:?}", list_path))?;
        let category = stem.to_string_lossy();

        let yaml_path = clash_dir.join(format!("{category}.yaml"));
        if mem_optimised_categories.contains(category.as_ref()) {
            let domain_mrs_path = clash_dir.join(format!("{category}-domain.mrs"));
            let ipcidr_mrs_path = clash_dir.join(format!("{category}-ipcidr.mrs"));
            let legacy_mrs_path = clash_dir.join(format!("{category}.mrs"));
            write_mem_optimised_clash_files(
                &list_path,
                &yaml_path,
                &domain_mrs_path,
                &ipcidr_mrs_path,
            )?;
            remove_generated_file_if_exists(&legacy_mrs_path)?;
        } else {
            write_clash_yaml(&list_path, &yaml_path)?;
        }
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

fn write_mem_optimised_clash_files(
    list_path: &Path,
    yaml_path: &Path,
    domain_mrs_path: &Path,
    ipcidr_mrs_path: &Path,
) -> AppResult<()> {
    let content = fs::read_to_string(list_path)
        .map_err(|error| format!("读取规则文件失败 {:?}: {}", list_path, error))?;
    let split = split_mem_optimised_rules(&content);

    if split.domain_rules.is_empty() {
        remove_generated_file_if_exists(domain_mrs_path)?;
    } else {
        mrs::write_domain_rules(&split.domain_rules, domain_mrs_path)?;
        println!(
            "已生成: {} ({} 条域名规则)",
            domain_mrs_path.display(),
            split.domain_rules.len()
        );
    }

    if split.ipcidr_rules.is_empty() {
        remove_generated_file_if_exists(ipcidr_mrs_path)?;
    } else {
        mrs::write_ipcidr_rules(&split.ipcidr_rules, ipcidr_mrs_path)?;
        println!(
            "已生成: {} ({} 条 IP-CIDR 规则)",
            ipcidr_mrs_path.display(),
            split.ipcidr_rules.len()
        );
    }

    let (output, rule_count) = build_yaml_from_rules(&split.classical_rules);
    fs::write(yaml_path, output)
        .map_err(|error| format!("写入 YAML 失败 {:?}: {}", yaml_path, error))?;
    println!(
        "已生成: {} ({} 条其余规则)",
        yaml_path.display(),
        rule_count
    );

    Ok(())
}

fn remove_generated_file_if_exists(path: &Path) -> AppResult<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            println!("已移除过期输出: {}", path.display());
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除旧输出失败 {:?}: {}", path, error)),
    }
}

#[derive(Debug)]
struct PublishEntry {
    staged_path: PathBuf,
    destination: PathBuf,
    backup_path: PathBuf,
    had_existing_file: bool,
}

fn create_work_dir(output_dir: &Path, label: &str) -> AppResult<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("系统时间无效: {}", error))?
        .as_nanos();

    for attempt in 0..100_u8 {
        let path = output_dir.join(format!(
            ".seshat-{label}-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!("创建工作目录失败 {:?}: {}", path, error));
            }
        }
    }

    Err(format!("无法在 {:?} 下创建唯一工作目录", output_dir))
}

fn finish_with_cleanup(result: AppResult<()>, directory: &Path) -> AppResult<()> {
    let cleanup = fs::remove_dir_all(directory)
        .map_err(|error| format!("清理工作目录失败 {:?}: {}", directory, error));

    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!("{}；{}", error, cleanup_error)),
    }
}

fn publish_staged_files(staging_dir: &Path, output_dir: &Path) -> AppResult<()> {
    let staged_files = list_files_recursively(staging_dir)?;
    let backup_dir = create_work_dir(output_dir, "backup")?;
    let result =
        publish_staged_files_with_backup(staging_dir, output_dir, &backup_dir, staged_files);

    match result {
        Ok(()) => finish_with_cleanup(Ok(()), &backup_dir),
        Err(error) => match list_files_recursively(&backup_dir) {
            Ok(files) if files.is_empty() => finish_with_cleanup(Err(error), &backup_dir),
            Ok(_) => Err(format!(
                "{}；旧输出备份已保留在 {}",
                error,
                backup_dir.display()
            )),
            Err(inspect_error) => Err(format!(
                "{}；无法确认备份目录状态，已保留 {}: {}",
                error,
                backup_dir.display(),
                inspect_error
            )),
        },
    }
}

fn publish_staged_files_with_backup(
    staging_dir: &Path,
    output_dir: &Path,
    backup_dir: &Path,
    staged_files: Vec<PathBuf>,
) -> AppResult<()> {
    let mut entries = Vec::with_capacity(staged_files.len());

    for staged_path in staged_files {
        let relative = staged_path
            .strip_prefix(staging_dir)
            .map_err(|error| format!("无法解析暂存文件路径 {:?}: {}", staged_path, error))?;
        let destination = output_dir.join(relative);
        let backup_path = backup_dir.join(relative);
        let had_existing_file = match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.is_dir() => {
                return Err(format!("输出文件目标是目录: {:?}", destination));
            }
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!("检查输出文件失败 {:?}: {}", destination, error));
            }
        };

        entries.push(PublishEntry {
            staged_path,
            destination,
            backup_path,
            had_existing_file,
        });
    }

    let mut backed_up = 0usize;
    for entry in entries.iter().filter(|entry| entry.had_existing_file) {
        if let Some(parent) = entry.backup_path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            let rollback = restore_backups(&entries, backed_up);
            return Err(with_rollback_error(
                format!("创建备份目录失败 {:?}: {}", parent, error),
                rollback,
            ));
        }

        if let Err(error) = fs::rename(&entry.destination, &entry.backup_path) {
            let rollback = restore_backups(&entries, backed_up);
            return Err(with_rollback_error(
                format!(
                    "备份旧输出失败 {:?} -> {:?}: {}",
                    entry.destination, entry.backup_path, error
                ),
                rollback,
            ));
        }
        backed_up += 1;
    }

    for (installed, entry) in entries.iter().enumerate() {
        if let Some(parent) = entry.destination.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            let rollback = rollback_publication(&entries, installed, backed_up);
            return Err(with_rollback_error(
                format!("创建输出目录失败 {:?}: {}", parent, error),
                rollback,
            ));
        }

        if let Err(error) = fs::rename(&entry.staged_path, &entry.destination) {
            let rollback = rollback_publication(&entries, installed, backed_up);
            return Err(with_rollback_error(
                format!(
                    "发布输出失败 {:?} -> {:?}: {}",
                    entry.staged_path, entry.destination, error
                ),
                rollback,
            ));
        }
    }

    for entry in &entries {
        println!("已发布: {}", entry.destination.display());
    }

    Ok(())
}

fn list_files_recursively(root: &Path) -> AppResult<Vec<PathBuf>> {
    let mut directories = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("读取暂存目录失败 {:?}: {}", directory, error))?
        {
            let entry =
                entry.map_err(|error| format!("读取暂存目录项失败 {:?}: {}", directory, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("读取暂存文件类型失败 {:?}: {}", entry.path(), error))?;
            if file_type.is_dir() {
                directories.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            } else {
                return Err(format!("暂存目录包含不支持的文件类型: {:?}", entry.path()));
            }
        }
    }

    files.sort_unstable();
    Ok(files)
}

fn rollback_publication(
    entries: &[PublishEntry],
    installed: usize,
    backed_up: usize,
) -> AppResult<()> {
    let mut errors = Vec::new();

    for entry in entries[..installed].iter().rev() {
        if let Some(parent) = entry.staged_path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            errors.push(format!("重建暂存目录 {:?} 失败: {}", parent, error));
            continue;
        }
        if let Err(error) = fs::rename(&entry.destination, &entry.staged_path) {
            errors.push(format!(
                "撤回新输出失败 {:?} -> {:?}: {}",
                entry.destination, entry.staged_path, error
            ));
        }
    }

    if let Err(error) = restore_backups(entries, backed_up) {
        errors.push(error);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

fn restore_backups(entries: &[PublishEntry], backed_up: usize) -> AppResult<()> {
    let mut errors = Vec::new();
    let backed_up_entries = entries
        .iter()
        .filter(|entry| entry.had_existing_file)
        .take(backed_up)
        .collect::<Vec<_>>();

    for entry in backed_up_entries.into_iter().rev() {
        if let Err(error) = fs::rename(&entry.backup_path, &entry.destination) {
            errors.push(format!(
                "恢复旧输出失败 {:?} -> {:?}: {}",
                entry.backup_path, entry.destination, error
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

fn with_rollback_error(error: String, rollback: AppResult<()>) -> String {
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => format!("{}；回滚失败: {}", error, rollback_error),
    }
}

struct SplitRules {
    domain_rules: Vec<String>,
    ipcidr_rules: Vec<String>,
    classical_rules: Vec<String>,
}

fn split_mem_optimised_rules(content: &str) -> SplitRules {
    let mut domain_rules = Vec::new();
    let mut ipcidr_rules = Vec::new();
    let mut classical_rules = Vec::new();

    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((rule_type, rest)) = line.split_once(',') else {
            classical_rules.push(line.to_string());
            continue;
        };
        let value = rest.split(',').next().unwrap_or_default().trim();

        if rule_type.trim().eq_ignore_ascii_case("DOMAIN") {
            domain_rules.push(value.to_string());
        } else if rule_type.trim().eq_ignore_ascii_case("DOMAIN-SUFFIX") {
            domain_rules.push(format!("+.{value}"));
        } else if rule_type.trim().eq_ignore_ascii_case("IP-CIDR")
            || rule_type.trim().eq_ignore_ascii_case("IP-CIDR6")
        {
            ipcidr_rules.push(value.to_string());
        } else {
            classical_rules.push(line.to_string());
        }
    }

    SplitRules {
        domain_rules,
        ipcidr_rules,
        classical_rules,
    }
}

fn build_yaml_payload(content: &str) -> (String, usize) {
    let payload: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    build_yaml_from_rules(&payload)
}

fn build_yaml_from_rules<T: AsRef<str>>(payload: &[T]) -> (String, usize) {
    let mut output = String::with_capacity(payload.len() * 40 + 16);
    output.push_str("payload:\n");
    for rule in payload {
        output.push_str("  - ");
        output.push_str(&yaml_quote(rule.as_ref()));
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
}
