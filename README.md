# dsh-netdoctor 🩺

Network diagnostics toolbox for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh) — six read-only probes, **zero runtime dependencies** (Node.js built-ins only).

When your agent needs to answer *"why can't I reach this server?"*, *"is the port open?"*, *"when does this certificate expire?"* or *"what does the public DNS actually return?"* — instead of guessing or fumbling through shell commands, it can call these tools directly and read structured results.

> 中文简介：dsh-netdoctor 是 DeepSeek Harness 的网络诊断工具箱插件，提供 6 个只读探针（DNS 查询、ICMP ping、TCP 端口探测、TLS 证书检查、traceroute 路由追踪、公网 IP 与归属地查询），零运行时依赖、纯 Node 内置模块实现。适合让 Agent 直接排查"连不上服务器/端口不通/证书要过期/DNS 解析异常"等常见网络问题。

## Tools

| Tool | What it does | Backend |
|------|--------------|---------|
| `dns_lookup` | Query A / AAAA / CNAME / MX / TXT / NS / SRV / PTR records, optionally against a custom nameserver (great for testing DNS propagation) | `node:dns` |
| `ping_host` | ICMP ping with packet-loss and min/avg/max RTT summary | system `ping` |
| `check_port` | TCP connect probe: **open / closed / filtered / unreachable** with connect time | `node:net` |
| `check_tls` | Real TLS handshake; reports protocol, cipher, cert subject/issuer, validity window, **days to expiry**, SANs, SHA-256 fingerprint. Certificates are inspected but never trusted, so expired/self-signed certs can be diagnosed | `node:tls` |
| `trace_route` | Hop-by-hop path trace with per-hop RTTs | system `traceroute` / `tracert` |
| `my_ip` | This machine's public IP, optionally with geo info (country/region/city/ISP/AS/timezone/coordinates) via ip-api.com's free keyless endpoint, with plain-IP fallback | HTTPS/HTTP GET |

## Safety model

- Every tool is **read-only** — nothing is written, configured, or changed.
- External binaries (`ping`, `traceroute`, `tracert`) are invoked with **fixed argument arrays, never through a shell**, and every target is validated against a strict hostname/IP pattern before use.
- Every probe has a **hard timeout**; a hung probe can never hang a session.
- `my_ip` geo lookup can be disabled per call (`includeGeo: false`) or in config — privacy by choice.

## Install

Add the plugin to your dsh configuration:

```sh
dsh plugin --profile web add github:TYEclipse/dsh-netdoctor
# or a pinned release:
dsh plugin --profile web add github:TYEclipse/dsh-netdoctor#v0.1.0
```

The first git-hosted install builds the package from source via its `prepare`
script; pnpm ≥10 blocks build scripts of new git dependencies until allowed —
follow dsh's hint (add the package key under `allowBuilds` in the profile's
`pnpm-workspace.yaml`, then re-run).

Or install it through the DSH web GUI plugin browser / any dsh plugin marketplace by searching `dsh-netdoctor` (topic `dsh-plugin`).

## Usage

Just ask your agent — the tools appear automatically:

- "Is port 5432 open on db.internal.example.com?"
- "When does the TLS certificate for example.com expire?"
- "Trace the route to 1.1.1.1 and find where packets stall."
- "What A records does example.com return from 8.8.8.8?"
- "What's our public IP and where does it geolocate to?"

Each tool returns a structured result plus a compact text summary in the conversation.

## Configuration

All settings are optional; defaults are shown:

```yaml
plugins:
  dsh-netdoctor:
    timeoutMs: 3000        # default timeout for TCP/TLS probes (100–60000)
    pingCount: 4           # default ICMP echo count (1–20)
    pingTimeoutSec: 2      # default per-reply wait for ping, seconds (1–60)
    maxHops: 20            # default traceroute max hops (1–64)
    traceTimeoutSec: 2     # per-hop wait for traceroute, seconds (1–30)
    includeGeo: true       # attach geo info to my_ip results
    httpTimeoutMs: 5000    # timeout for my_ip HTTP lookups (1000–60000)
```

## Platform notes

- **Windows**: `ping` and `tracert` ship with the OS — both probes work out of the box.
- **macOS**: `ping` works out of the box; `traceroute` is not installed by default — `brew install traceroute` (the tool reports a clear hint if it's missing).
- **Linux**: both utilities are standard (`iputils` / `traceroute`); on minimal containers `ping` may require `iputils-ping` and `traceroute` may require the `traceroute` package.
- Ping/traceroute may need elevated privileges in rare setups (e.g. restricted ICMP policies); results report failures explicitly instead of failing silently.

## Develop

```bash
pnpm install
pnpm build      # tsc → dist/
pnpm test       # vitest — 50 tests, fully offline (mock DNS, local TCP/TLS servers, parser fixtures)
pnpm lint       # oxlint src test
```

## License

MIT © TYEclipse
