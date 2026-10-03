# DNS Zone Auditor

离线 DNS 区域核查工具：读取一份区域描述 JSON，检查别名冲突与悬空引用，
解析每条 CNAME 的最终指向，并把诊断报告写成 JSON。**只使用 Go 标准库，
绝不发送任何 DNS 查询**。

## 用法

```sh
go run ./cmd/zonecheck -in examples/zone.json -out report.json
```

- 发现问题时以非零状态码退出，但报告仍会完整写入 `-out` 指定的文件。
- 输入顺序不影响结论：输出中的问题、CNAME 与 MX 结果均按名称稳定排序。

## 输入格式

```json
{
  "zone": "example.com.",
  "records": [
    {"name": "www.example.com.", "type": "A",     "ttl": 300, "data": "192.0.2.1"},
    {"name": "web.example.com.", "type": "CNAME", "ttl": 300, "target": "www.example.com."},
    {"name": "example.com.",     "type": "MX",    "ttl": 300, "preference": 10, "exchange": "www.example.com."}
  ]
}
```

## 简化范围

- 仅支持 `A`、`CNAME`、`MX` 三种记录，其他类型一律拒绝。
- 不支持通配符（`*` 会因名称校验失败而被拒绝）。
- 名称必须是以点结尾的 ASCII 完整域名，比较时忽略大小写；
  标签 1–63 字符，仅含字母、数字、连字符，首尾不可为连字符；
  去掉末点后总长不超过 253。
- 记录所属名称必须是区域本身或其按标签划分的子域。
- `A` 记录必须是合法 IPv4；MX 优先级 0–65535；TTL 为非负整数，
  同名称同类型的 TTL 必须一致。
- 完全相同的记录自动合并；同名只能有一个 CNAME 目标，
  且 CNAME 不得与其他类型共存（否则记为冲突，冲突节点不再解析）。

## 报告语义

每条 CNAME 报告完整解析路径与终点状态：

- `resolved`：终点有 A 记录，`addresses` 为按数值排序去重后的地址。
- `dangling`：终点在区域内但没有任何记录。
- `missing-address`：终点有其他记录但没有 A 记录。
- `loop`：路径中出现重复节点（环路）。
- `external`：路径走到区域外，标记为外部未知——既不当作悬空，也不联网补全。
- `conflict`：节点存在冲突，不继续解析。

MX 检查：交换主机在区域内时必须直接拥有 A 记录且不能是别名
（`ok` / `is-alias` / `no-address`）；在区域外只标记 `unverified-external`。

## 测试

```sh
go test ./...
```
