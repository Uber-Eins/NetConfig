# HTTP META 节点检测

四个脚本均用于 **Sub-Store Node.js**，可独立添加为脚本操作，无需加载同目录模块。
需要可访问的 HTTP META 服务；供应商脚本另需 Sub-Store 的 `ProxyUtils.MMDB` 和本地 MMDB 文件。
每个脚本只在有未命中缓存的兼容节点时启动 HTTP META，并在检测结束后关闭自己的进程。

## 推荐顺序

| 顺序 | 脚本 | 职责与默认参数 |
| --- | --- | --- |
| 1 | `http_meta_availability.js` | 经节点请求 `url=https://www.gstatic.com/generate_204`；HTTP 200–399 为可用 |
| 2 | `http_meta_udp.js` | 使用 HTTP META `/udp` 探测 `ntp=time.apple.com`，成功后添加 `UDP` 标签 |
| 3 | `http_meta_provider.js` | 经节点请求 `api=https://api.ip.sb/ip` 获取出口 IP，再查本地 MMDB，按国家与 AS 组织名称重命名 |
| 4 | `http_meta_node_info.js` | 经节点请求 `api=https://my.ippure.com/v1/info`，添加纯净度与类型标签 |

在每个脚本 URL 后单独设置参数，例如：

```text
http_meta_availability.js#url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&remove_failed=true
http_meta_udp.js#ntp=time.apple.com&udp_timeout=5000
http_meta_provider.js#api=https%3A%2F%2Fapi.ip.sb%2Fip
http_meta_node_info.js#api=https%3A%2F%2Fmy.ippure.com%2Fv1%2Finfo
```

这里省略了脚本 URL 的仓库前缀。需要缓存时，分别添加 `&cache=true`；前置代理和 HTTP META 地址也应分别配置。
不需要某项检测时，直接不添加该脚本。四步组合示例：`[12|🏠|🌱|UDP|x2] 🇭🇰 Example Network`。
UDP 与元数据脚本维护名称开头的 `[...]` 标签组；供应商脚本保留这些标签及原节点倍率。

## 失败判定

- **只有可用性脚本**设置节点的 `_check_failed`；请求异常或 HTTP 状态不在 200–399 时判为失败。
  只有该脚本的 `remove_failed=true` 会删除检测失败节点，默认保留。
- UDP 探测不成功只移除 `UDP` 标签，不代表 TCP/HTTP 不可用，也不能证明所有 UDP 流量都不可用。
- 出口 IP API 或 MMDB 失败时保留节点，不使用 `server`（入口 IP）冒充出口 IP，也不使用 API 返回的供应商替代 MMDB。
- 纯净度 API 失败时保留节点，不显示旧的纯净度/类型标签；缺失字段不默认标为机房或广播类型。
- HTTP META 启动失败属于运行环境错误，脚本直接报错，不写入节点失败缓存；关闭失败会记录日志。
- ClashMeta 无法转换的节点会跳过检测，只有可用性脚本的 `remove_incompatible=true` 可以删除它们。
  `remove_failed` 不隐含删除不兼容节点。后三个脚本忽略这两个删除参数。

## 专用参数

### 可用性

- `url`：测试 URL。
- `method`：HTTP 方法，默认 `get`。
- `remove_failed` / `remove_incompatible`：默认均为 `false`。

### UDP

- `ntp`：NTP 测试服务器。
- `udp_timeout`：UDP 探测超时（毫秒），默认沿用 `timeout`。

### 供应商

- `api`：返回纯文本 IP 或 `{ "ip": "..." }` 的出口 IP API，兼容 IPv4/IPv6。
  IP.SB 端点格式见 [官方文档](https://ip.sb/api/)。
- `method`：默认 `get`。
- `mmdb_country`：默认 `/opt/app/data/GeoLite2-Country.mmdb`。
- `mmdb_asn`：默认 `/opt/app/data/GeoLite2-ASN.mmdb`。
- 供应商来自 MMDB 的 AS 组织名称；组织名称无效时退回 `AS编号`，均缺失时不改名。

### 节点信息

- `api` / `method`：默认 IPPure API / `get`。
- 更换 API 时，返回对象须使用 `ip`、`fraudScore`、`isResidential`、`isBroadcast` 这些字段；
  不自动适配其他供应商的字段结构。参见 [IPPure 官方字段示例](https://ippure.com/MyIP-Info-API)。
- 保留原脚本的图标映射：`isResidential` 的 `true/false` 对应 `🏠/🏢`，
  `isBroadcast` 的 `true/false` 对应 `🌱/📡`；缺失或非布尔值不显示图标。
  有 `fraudScore` 时显示分数；仅 IPv6 且没有分数时显示 `IPv6`。
- 不再把另一条 IPv4 节点的元数据复制到 IPv6 节点，也不覆盖供应商脚本获得的出口 IP。

## 通用参数

| 参数 | 默认值 / 说明 |
| --- | --- |
| `http_meta_protocol` / `http_meta_host` / `http_meta_port` | `http` / `127.0.0.1` / `9876` |
| `http_meta_authorization` | 空，原样用于 HTTP META 的 Authorization 请求头 |
| `http_meta_start_delay` | `3000` 毫秒 |
| `http_meta_proxy_timeout` | `10000` 毫秒，用于计算 HTTP META 进程存活时间 |
| `timeout` | `5000` 毫秒 |
| `retries` / `retry_delay` | `1` 次重试 / `1000` 毫秒，按重试次数递增间隔 |
| `concurrency` | `10` |
| `cache` | `false`；启用 Sub-Store `scriptResourceCache`，有效期由宿主管理 |
| `disable_failed_cache` / `ignore_failed_error` | `false`；启用后重新检测该步骤的失败缓存，不影响节点失败判定 |
| `dialer_proxy` / `front_proxy` / `upstream_proxy` | 前置代理 URL，支持 HTTP(S)、SOCKS/SOCKS5 |
| `include_unsupported_proxy` | `false`；传递给 ClashMeta 转换器 |
| `incompatible` | `false`；保留本次检测的 `_incompatible` 字段 |
| `node_info` | `false`；可用性保留 `_check_failed`、`_latency`，UDP 保留 `_udp`，供应商保留 `_provider`，元数据保留 `_node_info`、`_ippure` |

各步骤只清理自己负责的信息字段，不清理其他步骤的检测结果；名称标签的组合不依赖 `node_info=true`。
缓存按检测步骤、接口/方法、前置代理和节点配置隔离，不复用旧版混合检测缓存。
`_provider.ip` 与 `_node_info.ip` 分别代表访问两个 API 时观察到的出口，分流或双栈场景下可能不同。

## 从旧版迁移

原 `http_meta_node_info.js` 现在**只获取元数据**，不再检测可用性、UDP 或查 MMDB。
要保持完整功能，按推荐顺序添加前三个新脚本；把 `remove_failed` 移到可用性脚本，
把 `ntp`、`udp_timeout` 和前置代理等所需参数配置到对应脚本。
原先的 `udp=false` 改为不添加 UDP 脚本。
