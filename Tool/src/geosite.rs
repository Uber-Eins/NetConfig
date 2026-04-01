use crate::AppResult;
use prost::{Enumeration, Message};
use std::fs;
use std::path::Path;

#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<Domain>,
    #[prost(bytes = "vec", tag = "3")]
    resource_hash: Vec<u8>,
    #[prost(string, tag = "4")]
    code: String,
}

#[derive(Clone, PartialEq, Message)]
struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<Attribute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
enum DomainType {
    Plain = 0,
    Regex = 1,
    RootDomain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(oneof = "attribute::TypedValue", tags = "2, 3")]
    typed_value: Option<attribute::TypedValue>,
}

mod attribute {
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GeositeSelector<'a> {
    list: &'a str,
    attr: Option<&'a str>,
}

pub(crate) fn write_rules_file(
    bytes: &[u8],
    selector: &str,
    output_path: &Path,
) -> AppResult<usize> {
    let rules = extract_rules(bytes, selector)?;

    let output = if rules.is_empty() {
        String::new()
    } else {
        let mut output = rules.join("\n");
        output.push('\n');
        output
    };

    fs::write(output_path, output)
        .map_err(|error| format!("写入 geosite 规则失败 {:?}: {}", output_path, error))?;

    Ok(rules.len())
}

fn extract_rules(bytes: &[u8], selector: &str) -> AppResult<Vec<String>> {
    let selector = parse_selector(selector)?;
    let geosite =
        GeoSiteList::decode(bytes).map_err(|error| format!("解析 geosite.dat 失败: {}", error))?;

    let entry = geosite
        .entry
        .iter()
        .find(|entry| site_code(entry).eq_ignore_ascii_case(selector.list))
        .ok_or_else(|| format!("geosite 中不存在条目 {}", selector.list))?;

    let rules = entry
        .domain
        .iter()
        .filter(|domain| matches_attribute(domain, selector.attr))
        .map(to_ruleset_line)
        .collect::<Vec<_>>();

    Ok(rules)
}

fn parse_selector(selector: &str) -> AppResult<GeositeSelector<'_>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err("geosite 不能为空".to_string());
    }

    let (list, attr) = match selector.split_once('@') {
        Some((list, attr)) => (list.trim(), Some(attr.trim())),
        None => (selector, None),
    };

    if list.is_empty() {
        return Err("geosite 名称不能为空".to_string());
    }

    if attr.is_some_and(str::is_empty) {
        return Err(format!("geosite 属性选择器无效: {}", selector));
    }

    Ok(GeositeSelector { list, attr })
}

fn site_code(entry: &GeoSite) -> &str {
    if entry.code.is_empty() {
        &entry.country_code
    } else {
        &entry.code
    }
}

fn matches_attribute(domain: &Domain, attr: Option<&str>) -> bool {
    let Some(attr) = attr else {
        return true;
    };

    domain
        .attribute
        .iter()
        .any(|attribute| attribute.key.eq_ignore_ascii_case(attr))
}

fn to_ruleset_line(domain: &Domain) -> String {
    let value = domain.value.trim();
    match DomainType::try_from(domain.r#type).unwrap_or(DomainType::Full) {
        DomainType::Plain => format!("DOMAIN-KEYWORD,{value}"),
        DomainType::Regex => format!("DOMAIN-REGEX,{value}"),
        DomainType::RootDomain => format!("DOMAIN-SUFFIX,{value}"),
        DomainType::Full => format!("DOMAIN,{value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn extract_rules_converts_supported_domain_types() {
        let payload = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "cn".to_string(),
                code: "CN".to_string(),
                resource_hash: Vec::new(),
                domain: vec![
                    Domain {
                        r#type: DomainType::RootDomain as i32,
                        value: "example.cn".to_string(),
                        attribute: Vec::new(),
                    },
                    Domain {
                        r#type: DomainType::Full as i32,
                        value: "www.example.cn".to_string(),
                        attribute: Vec::new(),
                    },
                    Domain {
                        r#type: DomainType::Plain as i32,
                        value: "wechat".to_string(),
                        attribute: Vec::new(),
                    },
                    Domain {
                        r#type: DomainType::Regex as i32,
                        value: "^ad[sx]?\\.".to_string(),
                        attribute: Vec::new(),
                    },
                ],
            }],
        }
        .encode_to_vec();

        let rules = extract_rules(&payload, "cn").unwrap();

        assert_eq!(
            rules,
            vec![
                "DOMAIN-SUFFIX,example.cn",
                "DOMAIN,www.example.cn",
                "DOMAIN-KEYWORD,wechat",
                "DOMAIN-REGEX,^ad[sx]?\\.",
            ]
        );
    }

    #[test]
    fn extract_rules_filters_by_attribute() {
        let payload = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "steam".to_string(),
                code: "steam".to_string(),
                resource_hash: Vec::new(),
                domain: vec![
                    Domain {
                        r#type: DomainType::RootDomain as i32,
                        value: "store.steampowered.com".to_string(),
                        attribute: vec![Attribute {
                            key: "cn".to_string(),
                            typed_value: Some(attribute::TypedValue::BoolValue(true)),
                        }],
                    },
                    Domain {
                        r#type: DomainType::RootDomain as i32,
                        value: "steamcommunity.com".to_string(),
                        attribute: Vec::new(),
                    },
                ],
            }],
        }
        .encode_to_vec();

        let rules = extract_rules(&payload, "steam@cn").unwrap();
        assert_eq!(rules, vec!["DOMAIN-SUFFIX,store.steampowered.com"]);
    }

    #[test]
    fn parse_selector_rejects_empty_input() {
        assert!(parse_selector(" ").is_err());
        assert!(parse_selector("cn@ ").is_err());
    }
}
