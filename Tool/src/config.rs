use crate::AppResult;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) temp_dir: PathBuf,
    pub(crate) output_dir: Option<PathBuf>,
    pub(crate) concurrent_downloads: Option<usize>,
    pub(crate) categories: BTreeMap<String, Category>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Category {
    #[serde(default)]
    pub(crate) urls: Vec<String>,
    pub(crate) geosite: Option<String>,
    pub(crate) geosite_db: Option<String>,
    #[serde(default)]
    pub(crate) mem_optimise: bool,
}

impl Config {
    pub(crate) fn load(path: impl AsRef<Path>) -> AppResult<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|error| format!("读取配置文件失败 {:?}: {}", path, error))?;

        let config: Self =
            toml::from_str(&content).map_err(|error| format!("解析配置文件失败: {}", error))?;

        config.validate()?;
        Ok(config)
    }

    pub(crate) fn concurrent_downloads(&self) -> usize {
        self.concurrent_downloads.unwrap_or(10)
    }

    pub(crate) fn mem_optimised_categories(&self) -> BTreeSet<String> {
        self.categories
            .iter()
            .filter(|(_, category)| category.mem_optimise)
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn validate(&self) -> AppResult<()> {
        if !self.temp_dir.is_absolute() {
            return Err(format!(
                "temp_dir 必须使用绝对路径，不能使用相对路径: {}",
                self.temp_dir.display()
            ));
        }

        let current_dir =
            env::current_dir().map_err(|error| format!("无法获取当前工作目录: {}", error))?;
        let temp_dir = normalize_path(&self.temp_dir, &current_dir);

        if temp_dir.parent().is_none() {
            return Err("temp_dir 不能是文件系统根目录".to_string());
        }

        if current_dir.starts_with(&temp_dir) {
            return Err(format!(
                "temp_dir 不能是当前工作目录或其上级目录: {}",
                temp_dir.display()
            ));
        }

        if let Some(output_dir) = self.output_dir.as_deref() {
            let output_dir = normalize_path(output_dir, &current_dir);
            if temp_dir.starts_with(&output_dir) || output_dir.starts_with(&temp_dir) {
                return Err(format!(
                    "temp_dir 与 output_dir 不能相同或互相包含: {} / {}",
                    temp_dir.display(),
                    output_dir.display()
                ));
            }
        }

        if self.concurrent_downloads == Some(0) {
            return Err("concurrent_downloads 必须大于 0".to_string());
        }

        if self.categories.is_empty() {
            return Err("至少需要配置一个分类".to_string());
        }

        for (name, category) in &self.categories {
            if !is_safe_category_name(name) {
                return Err(format!(
                    "分类名称只能是单个路径组件，不能包含路径分隔符、. 或 ..: {}",
                    name
                ));
            }

            if category.urls.is_empty() && category.geosite.is_none() {
                return Err(format!(
                    "分类 {} 至少需要配置 urls 或 geosite 其中之一",
                    name
                ));
            }

            if category.geosite.is_some() && category.geosite_db.is_none() {
                return Err(format!(
                    "分类 {} 配置了 geosite 时必须同时配置 geosite_db",
                    name
                ));
            }

            if category.geosite.is_none() && category.geosite_db.is_some() {
                return Err(format!(
                    "分类 {} 配置了 geosite_db，但没有对应的 geosite",
                    name
                ));
            }

            let mut unique_urls = BTreeSet::new();
            for url in &category.urls {
                if url.trim().is_empty() {
                    return Err(format!("分类 {} 包含空 URL", name));
                }
                if !unique_urls.insert(url) {
                    return Err(format!("分类 {} 包含重复 URL: {}", name, url));
                }
            }
        }

        Ok(())
    }
}

fn normalize_path(path: &Path, current_dir: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };
    let mut normalized = PathBuf::new();

    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

fn is_safe_category_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(test)]
impl Config {
    fn load_from_str(content: &str) -> AppResult<Self> {
        let config: Self =
            toml::from_str(content).map_err(|error| format!("解析配置文件失败: {}", error))?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn config_accepts_categories_without_type() {
        let config = toml::from_str::<Config>(
            r#"
temp_dir = "/tmp/rules"

[categories.Block]
urls = ["https://example.com/block.list"]
"#,
        )
        .unwrap();

        assert_eq!(config.categories.len(), 1);
        assert_eq!(config.categories["Block"].urls.len(), 1);
    }

    #[test]
    fn config_rejects_removed_category_type() {
        let error = toml::from_str::<Config>(
            r#"
temp_dir = "/tmp/rules"

[categories.Block]
type = "Rulesets"
urls = ["https://example.com/block.list"]
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field `type`"));
    }

    #[test]
    fn config_accepts_geosite_only_category() {
        let config = Config::load_from_str(
            r#"
temp_dir = "/tmp/rules"

[categories.CN]
geosite = "CN"
geosite_db = "https://example.com/geosite.dat"
"#,
        )
        .unwrap();

        assert!(config.categories["CN"].urls.is_empty());
        assert_eq!(config.categories["CN"].geosite.as_deref(), Some("CN"));
    }

    #[test]
    fn config_rejects_geosite_without_database() {
        let error = Config::load_from_str(
            r#"
temp_dir = "/tmp/rules"

[categories.CN]
geosite = "CN"
"#,
        )
        .unwrap_err();

        assert!(error.contains("geosite_db"));
    }
}
