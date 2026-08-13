use crate::AppResult;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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

    pub(crate) fn yaml_skipped_categories(&self) -> BTreeSet<String> {
        self.categories
            .iter()
            .filter(|(_, category)| category.uses_geosite())
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub(crate) fn mem_optimised_categories(&self) -> BTreeSet<String> {
        self.categories
            .iter()
            .filter(|(_, category)| category.mem_optimise)
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn validate(&self) -> AppResult<()> {
        for (name, category) in &self.categories {
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
        }

        Ok(())
    }
}

impl Category {
    pub(crate) fn uses_geosite(&self) -> bool {
        self.geosite.is_some()
    }
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

    #[test]
    fn config_marks_geosite_categories_for_yaml_skip() {
        let config = Config::load_from_str(
            r#"
temp_dir = "/tmp/rules"

[categories.CN]
geosite = "CN"
geosite_db = "https://example.com/geosite.dat"

[categories.Block]
urls = ["https://example.com/block.list"]
"#,
        )
        .unwrap();

        let skipped = config.yaml_skipped_categories();
        assert!(skipped.contains("CN"));
        assert!(!skipped.contains("Block"));
    }
}
