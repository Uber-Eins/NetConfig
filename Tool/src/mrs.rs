use crate::AppResult;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

const MRS_MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];
const DOMAIN_BEHAVIOR: u8 = 0;
const DOMAIN_SET_VERSION: u8 = 1;

#[derive(Default)]
struct TrieNode {
    children: BTreeMap<u8, TrieNode>,
    is_leaf: bool,
}

#[derive(Default)]
struct DomainSet {
    leaves: Vec<u64>,
    label_bits: Vec<u8>,
    labels: Vec<u8>,
}

pub(crate) fn write_domain_rules(rules: &[String], path: &Path) -> AppResult<()> {
    if rules.is_empty() {
        return Err(format!("无法生成空的 MRS 规则集: {}", path.display()));
    }

    let mut trie = TrieNode::default();
    for rule in rules {
        insert_domain(&mut trie, rule)?;
    }

    let domain_set = DomainSet::from_trie(&trie);
    let file =
        File::create(path).map_err(|error| format!("创建 MRS 失败 {:?}: {}", path, error))?;
    let writer = BufWriter::new(file);
    let mut encoder = zstd::stream::write::Encoder::new(writer, 0)
        .map_err(|error| format!("创建 MRS 压缩流失败 {:?}: {}", path, error))?;

    encoder
        .write_all(&MRS_MAGIC)
        .and_then(|_| encoder.write_all(&[DOMAIN_BEHAVIOR]))
        .and_then(|_| write_i64(&mut encoder, rules.len() as i64))
        .and_then(|_| write_i64(&mut encoder, 0))
        .and_then(|_| domain_set.write_to(&mut encoder))
        .map_err(|error| format!("写入 MRS 失败 {:?}: {}", path, error))?;

    let mut writer = encoder
        .finish()
        .map_err(|error| format!("完成 MRS 压缩失败 {:?}: {}", path, error))?;
    writer
        .flush()
        .map_err(|error| format!("刷新 MRS 失败 {:?}: {}", path, error))?;

    Ok(())
}

fn insert_domain(root: &mut TrieNode, domain: &str) -> AppResult<()> {
    if domain.is_empty()
        || domain.ends_with('.')
        || domain.starts_with(char::is_whitespace)
        || domain.ends_with(char::is_whitespace)
        || domain.contains('/')
    {
        return Err(format!("无法转换为 behavior=domain 的无效域名: {domain}"));
    }

    let domain = domain.to_lowercase();
    let parts = domain.split('.').collect::<Vec<_>>();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return Err(format!("无法转换为 behavior=domain 的无效域名: {domain}"));
    }

    if parts.first() == Some(&"+") {
        let Some(base) = domain.strip_prefix("+.") else {
            return Err(format!("无法转换为 behavior=domain 的无效域名: {domain}"));
        };
        insert_key(root, base);
        insert_key(root, &domain);
    } else {
        insert_key(root, &domain);
    }

    Ok(())
}

fn insert_key(root: &mut TrieNode, domain: &str) {
    let mut node = root;
    let reversed = domain.chars().rev().collect::<String>();
    for byte in reversed.as_bytes() {
        node = node.children.entry(*byte).or_default();
    }
    node.is_leaf = true;
}

impl DomainSet {
    fn from_trie(root: &TrieNode) -> Self {
        let mut domain_set = Self::default();
        let mut queue = vec![root];
        let mut index = 0;

        while index < queue.len() {
            let node = queue[index];
            if node.is_leaf {
                set_bit(&mut domain_set.leaves, index);
            }

            for (label, child) in &node.children {
                domain_set.labels.push(*label);
                queue.push(child);
                domain_set.label_bits.push(0);
            }
            domain_set.label_bits.push(1);
            index += 1;
        }

        domain_set
    }

    fn write_to(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_all(&[DOMAIN_SET_VERSION])?;

        write_i64(writer, self.leaves.len() as i64)?;
        for value in &self.leaves {
            writer.write_all(&value.to_be_bytes())?;
        }

        let packed_bitmap = pack_bits(&self.label_bits);
        write_i64(writer, packed_bitmap.len() as i64)?;
        for value in packed_bitmap {
            writer.write_all(&value.to_be_bytes())?;
        }

        write_i64(writer, self.labels.len() as i64)?;
        writer.write_all(&self.labels)
    }
}

fn set_bit(bitmap: &mut Vec<u64>, index: usize) {
    while index / 64 >= bitmap.len() {
        bitmap.push(0);
    }
    bitmap[index / 64] |= 1_u64 << (index % 64);
}

fn pack_bits(bits: &[u8]) -> Vec<u64> {
    let mut packed = Vec::new();
    for (index, bit) in bits.iter().enumerate() {
        if *bit != 0 {
            set_bit(&mut packed, index);
        } else if index / 64 >= packed.len() {
            packed.push(0);
        }
    }
    packed
}

fn write_i64(writer: &mut impl Write, value: i64) -> std::io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}
