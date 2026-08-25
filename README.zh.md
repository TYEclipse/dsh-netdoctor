# dsh-netdoctor 🩺 网络诊断工具箱

DeepSeek Harness (dsh) 插件：7 个只读网络探针，**零运行时依赖**（仅 Node.js 内置模块）。

让 Agent 直接排查常见网络问题——"服务器连不上？端口通不通？证书何时过期？公共 DNS 返回了什么？域名是谁注册的、何时到期？"——而不必猜测或绕道 shell 命令。

## 工具一览

| 工具 | 用途 | 实现 |
|------|------|------|
| `dns_lookup` | 查询 A / AAAA / CNAME / MX / TXT / NS / SOA / SRV / PTR / CAA 记录，可指定自定义 DNS 服务器（验证解析生效情况） | `node:dns` |
| `ping_host` | ICMP ping，报告丢包率与 min/avg/max 往返时延 | 系统 `ping` |
| `check_port` | TCP 连接探测：**开放 / 关闭 / 被过滤 / 不可达**，含连接耗时 | `node:net` |
| `check_tls` | 真实 TLS 握手；报告协议、加密套件、证书主体/签发者、有效期、**剩余天数**、SAN、SHA-256 指纹（只检查不信任，可诊断自签名/过期证书） | `node:tls` |
| `trace_route` | 逐跳路由追踪，含每跳时延 | 系统 `traceroute` / `tracert` |
| `my_ip` | 本机公网 IP，可选归属地信息（国家/地区/城市/运营商/AS/时区/坐标，ip-api.com 免费免密钥），失败自动降级为纯 IP | HTTP(S) GET |
| `whois` | WHOIS 注册信息查询（经典 TCP 43 协议）：经 whois.iana.org 引用链自动发现注册局服务器（附常见 TLD→注册局兜底表，IP 字面量走 ARIN），返回原始 WHOIS 文本 + 结构化摘要（注册商/状态/创建·更新·到期日期/NS 服务器） | `node:net` 裸 socket |

## 安全模型

- 全部工具**只读**：不写文件、不改配置、无副作用。
- 外部命令（`ping`/`traceroute`/`tracert`）以**固定参数数组**调用、**绝不经过 shell**；目标地址先经严格校验。
- 每个探针都有**硬超时**，绝不拖死会话。
- `whois` 仅向注册局服务器发起 TCP 43 出站连接并发送单行查询——无凭据、无第三方 API 密钥。
- `my_ip` 的归属地查询可逐次关闭（`includeGeo: false`）或配置全局关闭，隐私可控。

## 安装

```yaml
plugins:
  dsh-netdoctor:
    github: TYEclipse/dsh-netdoctor
```

或在 DSH Web GUI 插件市场 / 任意 dsh 插件目录中搜索 `dsh-netdoctor`（topic `dsh-plugin`）。

## 用法

直接提问即可，工具自动可用：

- "检查 db.internal.example.com 的 5432 端口是否开放"
- "example.com 的 TLS 证书什么时候过期？"
- "追踪到 1.1.1.1 的路由，找出丢包的位置"
- "用 8.8.8.8 查询 example.com 的 A 记录"
- "我们的公网 IP 是多少？在哪个城市？"
- "example.com 是谁注册的？域名注册什么时候到期？"

每个工具返回结构化结果 + 会话内的紧凑文本摘要。

## 配置

全部可选，默认值如下：

```yaml
plugins:
  dsh-netdoctor:
    timeoutMs: 3000        # TCP/TLS 探测默认超时（100–60000 毫秒）
    pingCount: 4           # 默认 ping 次数（1–20）
    pingTimeoutSec: 2      # ping 每包等待秒数（1–60）
    maxHops: 20            # traceroute 最大跳数（1–64）
    traceTimeoutSec: 2     # traceroute 每跳等待秒数（1–30）
    includeGeo: true       # my_ip 是否附带归属地信息
    httpTimeoutMs: 5000    # my_ip HTTP 请求超时（1000–60000 毫秒）
    whoisTimeoutMs: 5000   # WHOIS 查询超时（TCP 43，1000–60000 毫秒）
```

## 平台说明

- **Windows**：系统自带 `ping` 与 `tracert`，开箱即用。
- **macOS**：`ping` 开箱即用；`traceroute` 默认未安装，缺失时工具会给出 `brew install traceroute` 的明确提示。
- **Linux**：两者均为标准工具（`iputils` / `traceroute`）；极简容器可能需要 `iputils-ping` 与 `traceroute` 包。
- 少数环境（如受限 ICMP 策略）下 ping/traceroute 可能需要提权；失败会显式报告而非静默吞掉。

## 开发

```bash
pnpm install
pnpm build      # tsc → dist/
pnpm test       # vitest — 67 个用例，全程离线（mock DNS、本地 TCP/TLS 服务器、解析器夹具）
pnpm lint       # oxlint src test
```

## License

MIT © TYEclipse
