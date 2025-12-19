use ipnet::{Ipv4Net, Ipv6Net};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use walkdir::WalkDir;

/// 规则类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RuleType {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(Ipv4Net),
    IpCidr6(Ipv6Net),
    Other(String), // 其他规则类型，直接保留
}

/// 解析后的规则
#[derive(Debug, Clone)]
struct Rule {
    rule_type: RuleType,
    original_line: String,
    category: String, // 分类名称（从目录结构提取）
}

/// 域名后缀Trie树节点
#[derive(Default)]
struct SuffixTrieNode {
    children: HashMap<String, SuffixTrieNode>,
    is_end: bool, // 标记是否是一个完整的后缀规则
}

/// 域名后缀Trie树（反向存储域名段）
struct SuffixTrie {
    root: SuffixTrieNode,
}

impl SuffixTrie {
    fn new() -> Self {
        SuffixTrie {
            root: SuffixTrieNode::default(),
        }
    }

    /// 插入一个域名后缀（如 test.com -> ["com", "test"]）
    fn insert(&mut self, suffix: &str) {
        let parts: Vec<&str> = suffix.split('.').rev().collect();
        let mut node = &mut self.root;
        for part in parts {
            node = node.children.entry(part.to_lowercase()).or_default();
        }
        node.is_end = true;
    }

    /// 检查给定域名是否被某个后缀覆盖
    fn is_covered(&self, domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut node = &self.root;
        for part in parts {
            let lower = part.to_lowercase();
            if let Some(child) = node.children.get(&lower) {
                if child.is_end {
                    return true; // 找到一个匹配的后缀
                }
                node = child;
            } else {
                return false;
            }
        }
        false
    }

    /// 检查给定后缀是否被另一个更短的后缀覆盖
    fn is_suffix_covered(&self, suffix: &str) -> bool {
        let parts: Vec<&str> = suffix.split('.').rev().collect();
        let mut node = &self.root;
        for (i, part) in parts.iter().enumerate() {
            let lower = part.to_lowercase();
            if let Some(child) = node.children.get(&lower) {
                // 如果在到达末尾之前找到了一个结束标记，说明有更短的后缀覆盖了当前后缀
                if child.is_end && i < parts.len() - 1 {
                    return true;
                }
                node = child;
            } else {
                return false;
            }
        }
        false
    }
}

/// IPv4 CIDR 管理器
struct Ipv4CidrManager {
    // 按前缀长度分组，从大（更宽泛）到小（更具体）
    cidrs: Vec<Ipv4Net>,
}

impl Ipv4CidrManager {
    fn new() -> Self {
        Ipv4CidrManager { cidrs: Vec::new() }
    }

    fn add(&mut self, net: Ipv4Net) {
        self.cidrs.push(net);
    }

    /// 构建并返回非冗余的CIDR列表
    fn get_non_redundant(&mut self) -> HashSet<Ipv4Net> {
        // 按前缀长度排序（从小到大，即从最宽泛到最具体）
        self.cidrs.sort_by_key(|n| n.prefix_len());

        let mut result: Vec<Ipv4Net> = Vec::new();

        for net in &self.cidrs {
            // 检查是否被已有的更宽泛的网段覆盖
            let is_covered = result.iter().any(|existing| existing.contains(net));
            if !is_covered {
                result.push(*net);
            }
        }

        result.into_iter().collect()
    }
}

/// IPv6 CIDR 管理器
struct Ipv6CidrManager {
    cidrs: Vec<Ipv6Net>,
}

impl Ipv6CidrManager {
    fn new() -> Self {
        Ipv6CidrManager { cidrs: Vec::new() }
    }

    fn add(&mut self, net: Ipv6Net) {
        self.cidrs.push(net);
    }

    fn get_non_redundant(&mut self) -> HashSet<Ipv6Net> {
        self.cidrs.sort_by_key(|n| n.prefix_len());

        let mut result: Vec<Ipv6Net> = Vec::new();

        for net in &self.cidrs {
            let is_covered = result.iter().any(|existing| existing.contains(net));
            if !is_covered {
                result.push(*net);
            }
        }

        result.into_iter().collect()
    }
}

/// 解析单行规则
fn parse_rule(line: &str, file_path: &str) -> Option<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.splitn(3, ',').collect();
    if parts.len() < 2 {
        return Some(Rule {
            rule_type: RuleType::Other(line.to_string()),
            original_line: line.to_string(),
            category: file_path.to_string(),
        });
    }

    let rule_type_str = parts[0].trim().to_uppercase();
    let value = parts[1].trim();

    let rule_type = match rule_type_str.as_str() {
        "DOMAIN" => RuleType::Domain(value.to_lowercase()),
        "DOMAIN-SUFFIX" => RuleType::DomainSuffix(value.to_lowercase()),
        "DOMAIN-KEYWORD" => RuleType::DomainKeyword(value.to_lowercase()),
        "IP-CIDR" => {
            if let Ok(net) = value.parse::<Ipv4Net>() {
                RuleType::IpCidr(net)
            } else {
                RuleType::Other(line.to_string())
            }
        }
        "IP-CIDR6" => {
            if let Ok(net) = value.parse::<Ipv6Net>() {
                RuleType::IpCidr6(net)
            } else {
                RuleType::Other(line.to_string())
            }
        }
        _ => RuleType::Other(line.to_string()),
    };

    Some(Rule {
        rule_type,
        original_line: line.to_string(),
        category: file_path.to_string(),
    })
}

/// 读取单个文件的所有规则
fn read_rules_from_file(file_path: &Path, category: &str) -> Vec<Rule> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("无法打开文件 {:?}: {}", file_path, e);
            return Vec::new();
        }
    };

    let reader = BufReader::with_capacity(1024 * 1024, file); // 1MB buffer

    reader
        .lines()
        .filter_map(|line| line.ok())
        .filter_map(|line| parse_rule(&line, category))
        .collect()
}

/// 扫描目录获取所有规则文件，返回 (文件路径, 分类名称)
fn scan_rule_files(base_path: &Path) -> Vec<(std::path::PathBuf, String)> {
    WalkDir::new(base_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            // 从路径中提取分类：SPATH/{分类}/file
            let path = e.path().to_path_buf();
            let relative = path.strip_prefix(base_path).ok()?;
            let category = relative
                .components()
                .next()?
                .as_os_str()
                .to_string_lossy()
                .to_string();
            Some((path, category))
        })
        .collect()
}

/// 主去重逻辑
fn deduplicate_rules(rules: Vec<Rule>) -> Vec<Rule> {
    // 第一步：收集所有规则
    let mut domains: Vec<(String, Rule)> = Vec::new();
    let mut domain_suffixes: Vec<(String, Rule)> = Vec::new();
    let mut domain_keywords: HashSet<String> = HashSet::new();
    let mut domain_keyword_rules: Vec<Rule> = Vec::new();
    let mut ipv4_manager = Ipv4CidrManager::new();
    let mut ipv4_rules: HashMap<Ipv4Net, Rule> = HashMap::new();
    let mut ipv6_manager = Ipv6CidrManager::new();
    let mut ipv6_rules: HashMap<Ipv6Net, Rule> = HashMap::new();
    let mut other_rules: Vec<Rule> = Vec::new();

    for rule in rules {
        match &rule.rule_type {
            RuleType::Domain(d) => {
                domains.push((d.clone(), rule));
            }
            RuleType::DomainSuffix(s) => {
                domain_suffixes.push((s.clone(), rule));
            }
            RuleType::DomainKeyword(k) => {
                domain_keywords.insert(k.clone());
                domain_keyword_rules.push(rule);
            }
            RuleType::IpCidr(net) => {
                ipv4_manager.add(*net);
                ipv4_rules.insert(*net, rule);
            }
            RuleType::IpCidr6(net) => {
                ipv6_manager.add(*net);
                ipv6_rules.insert(*net, rule);
            }
            RuleType::Other(_) => {
                other_rules.push(rule);
            }
        }
    }

    let mut result: Vec<Rule> = Vec::new();

    // 第二步：处理DOMAIN-KEYWORD（优先级最高，直接保留）
    // 先去重keyword本身
    let unique_keywords: HashSet<String> = domain_keywords.clone();
    let mut seen_keywords: HashSet<String> = HashSet::new();
    for rule in domain_keyword_rules {
        if let RuleType::DomainKeyword(k) = &rule.rule_type {
            if !seen_keywords.contains(k) {
                seen_keywords.insert(k.clone());
                result.push(rule);
            }
        }
    }

    // 第三步：处理DOMAIN-SUFFIX
    // 1. 先过滤掉被DOMAIN-KEYWORD覆盖的后缀
    // 2. 构建Trie树去除被更短后缀覆盖的规则
    let filtered_suffixes: Vec<(String, Rule)> = domain_suffixes
        .into_iter()
        .filter(|(suffix, _)| {
            // 检查是否被某个keyword覆盖
            !unique_keywords.iter().any(|kw| suffix.contains(kw))
        })
        .collect();

    // 构建后缀Trie
    let mut suffix_trie = SuffixTrie::new();
    let mut suffix_set: HashSet<String> = HashSet::new();

    // 先按长度排序，短的优先（更宽泛的规则）
    let mut sorted_suffixes = filtered_suffixes.clone();
    sorted_suffixes.sort_by_key(|(s, _)| s.len());

    for (suffix, _) in &sorted_suffixes {
        if !suffix_trie.is_suffix_covered(suffix) && !suffix_set.contains(suffix) {
            suffix_trie.insert(suffix);
            suffix_set.insert(suffix.clone());
        }
    }

    // 保留非冗余的后缀规则
    let mut seen_suffixes: HashSet<String> = HashSet::new();
    for (suffix, rule) in filtered_suffixes {
        if suffix_set.contains(&suffix) && !seen_suffixes.contains(&suffix) {
            seen_suffixes.insert(suffix);
            result.push(rule);
        }
    }

    // 第四步：处理DOMAIN
    // 过滤掉被DOMAIN-KEYWORD或DOMAIN-SUFFIX覆盖的域名
    let mut seen_domains: HashSet<String> = HashSet::new();
    for (domain, rule) in domains {
        // 检查是否被keyword覆盖
        let covered_by_keyword = unique_keywords.iter().any(|kw| domain.contains(kw));
        if covered_by_keyword {
            continue;
        }

        // 检查是否被suffix覆盖
        if suffix_trie.is_covered(&domain) {
            continue;
        }

        // 去重
        if !seen_domains.contains(&domain) {
            seen_domains.insert(domain);
            result.push(rule);
        }
    }

    // 第五步：处理IP-CIDR
    let non_redundant_ipv4 = ipv4_manager.get_non_redundant();
    for net in non_redundant_ipv4 {
        if let Some(rule) = ipv4_rules.remove(&net) {
            result.push(rule);
        }
    }

    // 第六步：处理IP-CIDR6
    let non_redundant_ipv6 = ipv6_manager.get_non_redundant();
    for net in non_redundant_ipv6 {
        if let Some(rule) = ipv6_rules.remove(&net) {
            result.push(rule);
        }
    }

    // 第七步：添加其他规则
    result.extend(other_rules);

    result
}

/// 获取规则的排序权重
fn rule_order(rule: &Rule) -> u8 {
    match &rule.rule_type {
        RuleType::Domain(_) => 0,
        RuleType::DomainSuffix(_) => 1,
        RuleType::DomainKeyword(_) => 2,
        RuleType::IpCidr(_) => 3,
        RuleType::IpCidr6(_) => 4,
        RuleType::Other(_) => 5,
    }
}

/// 按分类合并并写入文件
fn write_rules_by_category(rules: Vec<Rule>, base_path: &Path) {
    // 按分类分组
    let mut category_rules: HashMap<String, Vec<Rule>> = HashMap::new();

    for rule in rules {
        category_rules
            .entry(rule.category.clone())
            .or_default()
            .push(rule);
    }

    // 写入每个分类的文件
    for (category, mut rules) in category_rules {
        // 按规则类型排序
        rules.sort_by_key(|r| rule_order(r));

        let output_path = base_path.join(format!("{}.list", category));
        let line_count = rules.len();

        match File::create(&output_path) {
            Ok(file) => {
                let mut writer = BufWriter::new(file);
                for rule in rules {
                    writeln!(writer, "{}", rule.original_line).ok();
                }
                println!("已写入: {} ({} 条规则)", output_path.display(), line_count);
            }
            Err(e) => {
                eprintln!("无法写入文件 {:?}: {}", output_path, e);
            }
        }
    }
}

/// 运行去重处理
/// 
/// # Arguments
/// * `spath` - 规则文件所在的基础路径
/// 
/// # Returns
/// * `Ok(())` - 成功
/// * `Err(String)` - 错误信息
pub fn run(spath: &str) -> Result<(), String> {
    let base_path = Path::new(spath);
    if !base_path.exists() {
        return Err(format!("路径不存在: {}", spath));
    }

    println!("扫描规则文件: {}", spath);

    // 扫描所有规则文件
    let files = scan_rule_files(base_path);
    println!("找到 {} 个规则文件", files.len());

    // 并行读取所有规则
    println!("读取规则中...");
    let all_rules: Vec<Rule> = files
        .par_iter()
        .flat_map(|(path, category)| read_rules_from_file(path, category))
        .collect();

    let total_rules = all_rules.len();
    println!("共读取 {} 条规则", total_rules);

    // 去重
    println!("去重处理中...");
    let deduped_rules = deduplicate_rules(all_rules);
    let after_dedup = deduped_rules.len();

    println!("\n========== 统计信息 ==========");
    println!("处理文件数: {}", files.len());
    println!("原始规则数: {}", total_rules);
    println!("去重后规则数: {}", after_dedup);
    println!("移除重复项: {}", total_rules - after_dedup);
    if total_rules > 0 {
        println!(
            "压缩率: {:.2}%",
            (1.0 - after_dedup as f64 / total_rules as f64) * 100.0
        );
    }
    println!("================================\n");

    // 按分类写入合并后的文件
    write_rules_by_category(deduped_rules, base_path);

    println!("去重完成!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_trie() {
        let mut trie = SuffixTrie::new();
        trie.insert("test.com");

        assert!(trie.is_covered("1.test.com"));
        assert!(trie.is_covered("a.b.test.com"));
        assert!(!trie.is_covered("test.org"));
        assert!(!trie.is_covered("nottest.com"));
    }

    #[test]
    fn test_suffix_coverage() {
        let mut trie = SuffixTrie::new();
        trie.insert("com");

        assert!(trie.is_suffix_covered("test.com"));
        assert!(trie.is_suffix_covered("example.com"));
    }

    #[test]
    fn test_ipv4_cidr_dedup() {
        let mut manager = Ipv4CidrManager::new();
        manager.add("10.0.0.0/8".parse().unwrap());
        manager.add("10.0.0.0/24".parse().unwrap());
        manager.add("10.0.1.0/24".parse().unwrap());

        let result = manager.get_non_redundant();
        assert_eq!(result.len(), 1);
        assert!(result.contains(&"10.0.0.0/8".parse().unwrap()));
    }

    #[test]
    fn test_domain_keyword_coverage() {
        let keywords: HashSet<String> = vec!["test".to_string()].into_iter().collect();
        let suffix = "test.com";

        assert!(keywords.iter().any(|kw| suffix.contains(kw)));
    }

    #[test]
    fn test_parse_rule() {
        let rule = parse_rule("DOMAIN,example.com", "test.txt").unwrap();
        assert!(matches!(rule.rule_type, RuleType::Domain(_)));

        let rule = parse_rule("DOMAIN-SUFFIX,example.com", "test.txt").unwrap();
        assert!(matches!(rule.rule_type, RuleType::DomainSuffix(_)));

        let rule = parse_rule("IP-CIDR,10.0.0.0/8", "test.txt").unwrap();
        assert!(matches!(rule.rule_type, RuleType::IpCidr(_)));
    }
}
