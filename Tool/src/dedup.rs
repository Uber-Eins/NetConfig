use ipnet::{Ipv4Net, Ipv6Net};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// 规则类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RuleType {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(Ipv4Net),
    IpCidr6(Ipv6Net),
    Other,
}

/// 解析后的规则
#[derive(Debug, Clone)]
struct Rule {
    rule_type: RuleType,
    original_line: String,
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

fn deduplicate_ipv4_rules(rules: HashMap<Ipv4Net, Rule>) -> Vec<Rule> {
    let mut rules = rules.into_iter().collect::<Vec<_>>();
    rules.sort_unstable_by(|(left, _), (right, _)| {
        u32::from(left.network())
            .cmp(&u32::from(right.network()))
            .then_with(|| u32::from(right.broadcast()).cmp(&u32::from(left.broadcast())))
    });

    let mut covered_until = None;
    let mut result = Vec::with_capacity(rules.len());

    for (network, rule) in rules {
        let end = u32::from(network.broadcast());
        if covered_until.is_some_and(|covered_end| end <= covered_end) {
            continue;
        }

        covered_until = Some(end);
        result.push(rule);
    }

    result
}

fn deduplicate_ipv6_rules(rules: HashMap<Ipv6Net, Rule>) -> Vec<Rule> {
    let mut rules = rules.into_iter().collect::<Vec<_>>();
    rules.sort_unstable_by(|(left, _), (right, _)| {
        u128::from(left.network())
            .cmp(&u128::from(right.network()))
            .then_with(|| u128::from(right.broadcast()).cmp(&u128::from(left.broadcast())))
    });

    let mut covered_until = None;
    let mut result = Vec::with_capacity(rules.len());

    for (network, rule) in rules {
        let end = u128::from(network.broadcast());
        if covered_until.is_some_and(|covered_end| end <= covered_end) {
            continue;
        }

        covered_until = Some(end);
        result.push(rule);
    }

    result
}

/// 解析单行规则
fn parse_rule(line: &str) -> Option<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    parse_ruleset_line(line)
}

fn parse_ruleset_line(line: &str) -> Option<Rule> {
    let mut parts = line.splitn(3, ',');
    let rule_type_raw = parts.next()?;
    let Some(value) = parts.next() else {
        return Some(Rule {
            rule_type: RuleType::Other,
            original_line: line.to_string(),
        });
    };

    let rule_type_str = rule_type_raw.trim().to_uppercase();
    let value = value.trim();

    let rule_type = match rule_type_str.as_str() {
        "DOMAIN" => RuleType::Domain(value.to_lowercase()),
        "DOMAIN-SUFFIX" => RuleType::DomainSuffix(value.to_lowercase()),
        "DOMAIN-KEYWORD" => RuleType::DomainKeyword(value.to_lowercase()),
        "IP-CIDR" => {
            if let Ok(net) = value.parse::<Ipv4Net>() {
                RuleType::IpCidr(net)
            } else {
                RuleType::Other
            }
        }
        "IP-CIDR6" => {
            if let Ok(net) = value.parse::<Ipv6Net>() {
                RuleType::IpCidr6(net)
            } else {
                RuleType::Other
            }
        }
        _ => RuleType::Other,
    };

    Some(Rule {
        rule_type,
        original_line: line.to_string(),
    })
}

/// 读取单个文件的所有规则
fn read_rules_from_file(file_path: &Path) -> Result<Vec<Rule>, String> {
    let file = File::open(file_path)
        .map_err(|error| format!("无法打开规则文件 {:?}: {}", file_path, error))?;

    let reader = BufReader::with_capacity(1024 * 1024, file); // 1MB buffer
    let mut rules = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "读取规则文件 {:?} 第 {} 行失败: {}",
                file_path,
                index + 1,
                error
            )
        })?;
        if let Some(rule) = parse_rule(&line) {
            rules.push(rule);
        }
    }

    Ok(rules)
}

/// 扫描目录获取所有规则文件
fn scan_rule_files(base_path: &Path) -> Result<BTreeMap<String, Vec<PathBuf>>, String> {
    let mut files_by_category = BTreeMap::<String, Vec<PathBuf>>::new();

    for entry in WalkDir::new(base_path) {
        let entry = entry.map_err(|error| format!("扫描规则目录失败: {}", error))?;
        if !entry.file_type().is_file() {
            continue;
        }

        // 从路径中提取分类：SPATH/{分类}/file
        let path = entry.path().to_path_buf();
        let relative = path
            .strip_prefix(base_path)
            .map_err(|error| format!("无法解析规则文件路径 {:?}: {}", path, error))?;
        let category = relative
            .components()
            .next()
            .ok_or_else(|| format!("规则文件缺少分类目录: {:?}", path))?
            .as_os_str()
            .to_string_lossy()
            .to_string();
        files_by_category.entry(category).or_default().push(path);
    }

    Ok(files_by_category)
}

/// 单个分类内的去重逻辑
fn deduplicate_category_rules(rules: Vec<Rule>) -> Vec<Rule> {
    let total_rules = rules.len();

    // 第一步：收集所有规则
    let mut domains: Vec<(String, Rule)> = Vec::new();
    let mut domain_suffixes: Vec<(String, Rule)> = Vec::new();
    let mut domain_keywords: HashSet<String> = HashSet::new();
    let mut domain_keyword_rules: Vec<Rule> = Vec::new();
    let mut ipv4_rules: HashMap<Ipv4Net, Rule> = HashMap::new();
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
                ipv4_rules.insert(*net, rule);
            }
            RuleType::IpCidr6(net) => {
                ipv6_rules.insert(*net, rule);
            }
            RuleType::Other => {
                other_rules.push(rule);
            }
        }
    }

    let mut result: Vec<Rule> = Vec::with_capacity(total_rules);

    // 第二步：处理DOMAIN-KEYWORD（优先级最高，直接保留）
    // 先去重keyword本身
    let mut seen_keywords: HashSet<String> = HashSet::new();
    for rule in domain_keyword_rules {
        if let RuleType::DomainKeyword(k) = &rule.rule_type
            && seen_keywords.insert(k.clone())
        {
            result.push(rule);
        }
    }

    // 第三步：处理DOMAIN-SUFFIX
    // 1. 先过滤掉被DOMAIN-KEYWORD覆盖的后缀
    // 2. 构建Trie树去除被更短后缀覆盖的规则
    let filtered_suffixes: Vec<(String, Rule)> = domain_suffixes
        .into_iter()
        .filter(|(suffix, _)| {
            // 检查是否被某个keyword覆盖
            !domain_keywords.iter().any(|kw| suffix.contains(kw))
        })
        .collect();

    // 构建后缀Trie
    let mut suffix_trie = SuffixTrie::new();
    let mut suffix_set: HashSet<String> = HashSet::new();

    // 先按长度排序，短的优先（更宽泛的规则）
    let mut filtered_suffixes = filtered_suffixes;
    filtered_suffixes.sort_unstable_by_key(|(s, _)| s.len());

    for (suffix, _) in &filtered_suffixes {
        if !suffix_trie.is_suffix_covered(suffix) && suffix_set.insert(suffix.clone()) {
            suffix_trie.insert(suffix);
        }
    }

    // 保留非冗余的后缀规则
    let mut seen_suffixes: HashSet<String> = HashSet::new();
    for (suffix, rule) in filtered_suffixes {
        if suffix_set.contains(&suffix) && seen_suffixes.insert(suffix) {
            result.push(rule);
        }
    }

    // 第四步：处理DOMAIN
    // 过滤掉被DOMAIN-KEYWORD或DOMAIN-SUFFIX覆盖的域名
    let mut seen_domains: HashSet<String> = HashSet::new();
    for (domain, rule) in domains {
        // 检查是否被keyword覆盖
        let covered_by_keyword = domain_keywords.iter().any(|kw| domain.contains(kw));
        if covered_by_keyword {
            continue;
        }

        // 检查是否被suffix覆盖
        if suffix_trie.is_covered(&domain) {
            continue;
        }

        // 去重
        if seen_domains.insert(domain) {
            result.push(rule);
        }
    }

    // 第五步：处理IP-CIDR
    result.extend(deduplicate_ipv4_rules(ipv4_rules));

    // 第六步：处理IP-CIDR6
    result.extend(deduplicate_ipv6_rules(ipv6_rules));

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
        RuleType::Other => 5,
    }
}

/// 写入单个分类的合并规则。
fn write_category_rules(
    category: &str,
    mut rules: Vec<Rule>,
    base_path: &Path,
) -> Result<(), String> {
    rules.sort_unstable_by(|left, right| {
        rule_order(left)
            .cmp(&rule_order(right))
            .then_with(|| left.original_line.cmp(&right.original_line))
    });

    let output_path = base_path.join(format!("{}.list", category));
    let line_count = rules.len();

    match File::create(&output_path) {
        Ok(file) => {
            let mut writer = BufWriter::new(file);
            for rule in rules {
                writeln!(writer, "{}", rule.original_line)
                    .map_err(|e| format!("写入文件失败 {:?}: {}", output_path, e))?;
            }
            writer
                .flush()
                .map_err(|e| format!("刷新文件失败 {:?}: {}", output_path, e))?;
            println!("已写入: {} ({} 条规则)", output_path.display(), line_count);
        }
        Err(e) => {
            return Err(format!("无法写入文件 {:?}: {}", output_path, e));
        }
    }

    Ok(())
}

/// 运行去重处理
///
/// # Arguments
/// * `base_path` - 规则文件所在的基础路径
///
/// # Returns
/// * `Ok(())` - 成功
/// * `Err(String)` - 错误信息
pub fn run(base_path: &Path) -> Result<(), String> {
    if !base_path.exists() {
        return Err(format!("路径不存在: {}", base_path.display()));
    }

    println!("扫描规则文件: {}", base_path.display());

    // 扫描所有规则文件
    let files_by_category = scan_rule_files(base_path)?;
    let file_count = files_by_category.values().map(Vec::len).sum::<usize>();
    println!("找到 {} 个规则文件", file_count);

    let mut total_rules = 0usize;
    let mut after_dedup = 0usize;

    println!("按分类读取和去重中...");
    for (category, files) in files_by_category {
        let rule_batches: Result<Vec<Vec<Rule>>, String> = files
            .par_iter()
            .map(|file_path| read_rules_from_file(file_path))
            .collect();
        let rule_batches = rule_batches?;
        let category_rule_count = rule_batches.iter().map(Vec::len).sum::<usize>();
        let mut rules = Vec::with_capacity(category_rule_count);
        for batch in rule_batches {
            rules.extend(batch);
        }

        total_rules += category_rule_count;
        let deduped_rules = deduplicate_category_rules(rules);
        after_dedup += deduped_rules.len();
        write_category_rules(&category, deduped_rules, base_path)?;
    }

    println!("\n========== 统计信息 ==========");
    println!("处理文件数: {}", file_count);
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
    fn test_cidr_dedup() {
        let rules = vec![
            parse_rule("IP-CIDR,10.0.0.0/8").unwrap(),
            parse_rule("IP-CIDR,10.0.0.0/24").unwrap(),
            parse_rule("IP-CIDR,10.0.1.0/24").unwrap(),
            parse_rule("IP-CIDR,192.168.0.0/16").unwrap(),
            parse_rule("IP-CIDR6,2001:db8::/32").unwrap(),
            parse_rule("IP-CIDR6,2001:db8:1::/48").unwrap(),
            parse_rule("IP-CIDR6,2001:db9::/32").unwrap(),
        ];

        let result = deduplicate_category_rules(rules);
        assert_eq!(
            result
                .iter()
                .filter(|rule| matches!(rule.rule_type, RuleType::IpCidr(_)))
                .count(),
            2
        );
        assert_eq!(
            result
                .iter()
                .filter(|rule| matches!(rule.rule_type, RuleType::IpCidr6(_)))
                .count(),
            2
        );
        assert!(
            result
                .iter()
                .any(|rule| rule.original_line == "IP-CIDR,10.0.0.0/8")
        );
        assert!(
            result
                .iter()
                .any(|rule| rule.original_line == "IP-CIDR6,2001:db8::/32")
        );
        assert!(
            result
                .iter()
                .any(|rule| rule.original_line == "IP-CIDR,192.168.0.0/16")
        );
        assert!(
            result
                .iter()
                .any(|rule| rule.original_line == "IP-CIDR6,2001:db9::/32")
        );
    }

    #[test]
    fn test_domain_keyword_coverage() {
        let keywords: HashSet<String> = vec!["test".to_string()].into_iter().collect();
        let suffix = "test.com";

        assert!(keywords.iter().any(|kw| suffix.contains(kw)));
    }

    #[test]
    fn test_parse_rule() {
        let rule = parse_rule("DOMAIN,example.com").unwrap();
        assert!(matches!(rule.rule_type, RuleType::Domain(_)));

        let rule = parse_rule("DOMAIN-SUFFIX,example.com").unwrap();
        assert!(matches!(rule.rule_type, RuleType::DomainSuffix(_)));

        let rule = parse_rule("IP-CIDR,10.0.0.0/8").unwrap();
        assert!(matches!(rule.rule_type, RuleType::IpCidr(_)));
    }

    #[test]
    fn test_deduplicate_category_rules_basic_coverage() {
        let rules = vec![
            parse_rule("DOMAIN-KEYWORD,test").unwrap(),
            parse_rule("DOMAIN-SUFFIX,test.com").unwrap(),
            parse_rule("DOMAIN,a.test.com").unwrap(),
            parse_rule("IP-CIDR,10.0.0.0/8").unwrap(),
            parse_rule("IP-CIDR,10.0.0.0/24").unwrap(),
        ];

        let deduped = deduplicate_category_rules(rules);

        assert!(
            deduped
                .iter()
                .any(|r| matches!(r.rule_type, RuleType::DomainKeyword(_)))
        );
        assert!(
            !deduped
                .iter()
                .any(|r| matches!(r.rule_type, RuleType::DomainSuffix(_)))
        );
        assert!(
            !deduped
                .iter()
                .any(|r| matches!(r.rule_type, RuleType::Domain(_)))
        );

        let ipv4_count = deduped
            .iter()
            .filter(|r| matches!(r.rule_type, RuleType::IpCidr(_)))
            .count();
        assert_eq!(ipv4_count, 1);
    }

    #[test]
    fn test_run_processes_categories_independently() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_path = std::env::temp_dir().join(format!("seshat-dedup-{nonce}"));
        let first_category = base_path.join("First");
        let second_category = base_path.join("Second");
        std::fs::create_dir_all(&first_category).unwrap();
        std::fs::create_dir_all(&second_category).unwrap();
        std::fs::write(
            first_category.join("rules.list"),
            "DOMAIN-SUFFIX,example.com\nDOMAIN,a.example.com\n",
        )
        .unwrap();
        std::fs::write(second_category.join("rules.list"), "DOMAIN,a.example.com\n").unwrap();

        run(&base_path).unwrap();

        assert_eq!(
            std::fs::read_to_string(base_path.join("First.list")).unwrap(),
            "DOMAIN-SUFFIX,example.com\n"
        );
        assert_eq!(
            std::fs::read_to_string(base_path.join("Second.list")).unwrap(),
            "DOMAIN,a.example.com\n"
        );
        std::fs::remove_dir_all(base_path).unwrap();
    }

    #[test]
    fn test_parse_rule_skips_comments_and_blank_lines() {
        assert!(parse_rule("# comment").is_none());
        assert!(parse_rule("   ").is_none());
    }
}
