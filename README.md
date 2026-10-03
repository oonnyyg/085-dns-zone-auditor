# zonecheck — 离线 DNS 区域核查工具

`zonecheck` 读取一个区域（zone）的名称与记录列表（JSON），在**完全离线**
的情况下核查记录合法性、CNAME 别名链与 MX 目标，然后把诊断报告写成 JSON。
工具只使用 Go 标准库，**不会发送任何 DNS 查询**。

## 运行

```sh
go run ./cmd/zonecheck -in records.json -out report.json
```

- `-in`：输入 JSON 文件路径。
- `-out`：报告 JSON 输出路径（即使存在错误也会写入）。

退出码：

- `0`：未发现任何问题；
- `1`：输入可解析但核查发现问题（报告仍已写出），或输入 JSON 非法；
- `2`：参数缺失、输入文件无法读取或报告无法写入。

## 输入格式

```json
{
  "zone": "example.com.",
  "records": [
    {"name": "www.example.com.", "type": "A",     "ttl": 300, "data": "192.0.2.10"},
    {"name": "www.example.com.", "type": "CNAME", "ttl": 300, "data": "host.example.net."},
    {"name": "example.com.",     "type": "MX",    "ttl": 60,  "data": "10 mail.example.com."}
  ]
}
```

- 仅支持 `A`、`CNAME`、`MX`，出现其它类型会报告 `unsupported_type` 并拒绝该条。
- `A` 的 `data` 必须是合法点分十进制 IPv4。
- `CNAME` 的 `data` 是一个以点结尾的绝对域名。
- `MX` 的 `data` 是 `"优先级 目标主机"`，优先级为 0–65535 的整数。
- `ttl` 必须是非负整数；同名同类型记录的 TTL 必须一致，否则报告 `ttl_mismatch`。

## 名称规则

- 必须是以点（`.`）结尾的 ASCII 绝对域名，比较时忽略大小写。
- 每个标签长 1–63 字符，只含字母、数字和连字符，首尾不得为连字符。
- 去掉末尾点后总长度不超过 253。
- 不支持通配符（包含 `*` 的名称直接拒绝）。
- 记录属主必须等于区域本身，或区域按标签划分的子域，否则报告 `out_of_zone`。

## 冲突与合并

- 完全相同的记录（名称、类型、rdata 一致）自动合并为一条。
- 一个名称只能有一个 CNAME 目标，多个不同目标报告 `cname_multiple_targets`。
- CNAME 不得与任何其它类型共存，否则报告 `cname_coexists`。
- 冲突节点标记为 `conflict`，其别名链**不再继续解析**。

## CNAME 链解析状态

每条 CNAME 都会报告完整 `path`（含起点与终点）以及以下状态之一：

| 状态 | 含义 |
| --- | --- |
| `resolved` | 链终点存在 A 记录，`addresses` 为按数值排序去重的 IPv4 列表 |
| `no_address` | 终点在区域内有其它记录（如 MX）但没有 A |
| `dangling` | 终点名称在区域内不存在任何记录（悬空引用） |
| `conflict` | 链上存在冲突 CNAME 节点，解析在此中止 |
| `loop` | 链中重复出现某个节点，构成环路 |
| `external_unknown` | 链走出区域；离线无法验证，**不会**当作悬空，也不会联网补全 |

## MX 核查

- 目标在区域内时：必须**直接**拥有 A 记录，且自身不能是别名。
  - 有 A：`resolved`，给出地址；
  - 是 CNAME：`alias`；
  - 不存在或没有 A：`missing`。
- 目标在区域外：状态为 `external_unverified`，不做进一步判断。

## 输出稳定性

问题列表按 `(名称, 错误码)` 稳定排序，CNAME 按名称排序，MX 按
`(属主, 优先级, 目标)` 排序。**调换输入记录的顺序不会改变任何结论。**

## 简化范围

这是一个教学/审计用途的简化模型，明确不包含：

- 真实 DNS 查询、递归解析与缓存（区域外名称一律标记为未验证）；
- `AAAA`、`NS`、`SOA`、`TXT`、`SRV`、PTR 等其它记录类型；
- 通配符、IDN（非 ASCII）名称、相对名称与 $ORIGIN/$TTL 等 zone file 语法；
- DNSSEC、CNAME 到 DNAME 的展开、MX 目标的多级别名追踪（MX 目标必须直达 A）。

## 测试

```sh
go test ./...
```

测试覆盖名称与字段校验、六种 CNAME 链状态、MX 四种核查结果、重复记录合并、
TTL 一致性，以及输入顺序无关性和大小写不敏感比较。
