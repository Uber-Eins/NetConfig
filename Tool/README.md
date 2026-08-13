# 简要介绍

Seshat 是一个使用 Rust 编写的规则去重工具。

它的职责很单一：从多个 URL 拉取规则文件，或从 `geosite.dat` 提取指定条目，按分类合并，做基础去重与覆盖裁剪，然后输出整理后的结果文件。项目本身只关注规则处理，不承担其他额外职责。

# 目前支持

- 按分类组织规则源，每个分类可配置多个 `urls`
- 按分类引用 `geosite.dat` 中的指定 geosite 条目，并先转换成文本规则再参与去重
- 并发下载远程规则文件
- 合并同一分类下的多个来源并输出单个 `.list` 文件
- 对以下规则做去重和覆盖裁剪
  - `DOMAIN`
  - `DOMAIN-SUFFIX`
  - `DOMAIN-KEYWORD`
  - `IP-CIDR`
  - `IP-CIDR6`
- 忽略空行和以 `#` 开头的注释行
- 对无法识别的规则行按原样保留
- 如果配置了 `output_dir`，会把结果导出到目标目录，并额外生成对应的 YAML 文件
- 分类可启用 `mem_optimise`，将 `DOMAIN` / `DOMAIN-SUFFIX` 拆分为 Mihomo MRS 域名规则集
- 如果分类使用了 `geosite`，则该分类不会生成 YAML 文件

# 用法说明

## 1. 准备配置文件

可以直接参考仓库中的 [config.example.toml](/home/camellia/Documents/NetConfig/Tool/config.example.toml)。

最小配置示例：

```toml
temp_dir = "/tmp/rules"
output_dir = "./Rules"
concurrent_downloads = 16

[categories.Block]
mem_optimise = true
urls = [
    "https://example.com/a.list",
    "https://example.com/b.list",
]

[categories.CN]
geosite = "CN"
geosite_db = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
urls = [
    "https://example.com/cn.list",
]
```

配置说明：

- `temp_dir`：下载文件和处理中间结果的目录
- `output_dir`：可选，最终输出目录
- `concurrent_downloads`：可选，并发下载数，默认 `10`
- `categories.<name>.urls`：分类下的规则源列表
- `categories.<name>.geosite`：可选，指定要展开的 geosite 名称，支持 `name@attr`
- `categories.<name>.geosite_db`：可选，`geosite.dat` 下载地址；配置了 `geosite` 时必须提供
- `categories.<name>.mem_optimise`：可选布尔值，默认 `false`。启用后将 `DOMAIN` 与 `DOMAIN-SUFFIX` 规则写入 `Clash/<name>.mrs`，其余规则写入 `Clash/<name>.yaml`

注意：`categories` 下只保留 `urls`，不要再写 `type` 字段。

## 2. 运行程序

使用默认配置文件 `config.toml`：

```bash
cargo run --release
```

指定配置文件路径：

```bash
cargo run --release -- ./config.toml
```

## 3. 查看输出

程序会先在 `temp_dir` 下按分类下载源文件，并在去重后生成 `分类名.list`。

如果设置了 `output_dir`：

- 去重后的 `.list` 文件会被导出到 `output_dir`
- Clash 文件会生成到 `output_dir/Clash` 中
- 普通分类生成 `分类名.yaml`
- `mem_optimise = true` 的分类同时生成 `分类名.mrs`（用于 `behavior: domain`、`format: mrs`）和不含 `DOMAIN` / `DOMAIN-SUFFIX` 的 `分类名.yaml`
- 如果某个分类配置了 `geosite`，该分类只输出 `.list`，不会生成 YAML

## 4. 输入格式要求

当前只接受 ruleset 风格的规则行，例如：

```text
DOMAIN,example.com
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,example
IP-CIDR,10.0.0.0/8
IP-CIDR6,2001:db8::/32
```

当分类配置了 `geosite` 时，程序会先把 geosite 条目转换成近似的 ruleset 文本：

- `RootDomain` -> `DOMAIN-SUFFIX`
- `Full` -> `DOMAIN`
- `Plain` -> `DOMAIN-KEYWORD`
- `Regex` -> `DOMAIN-REGEX`
