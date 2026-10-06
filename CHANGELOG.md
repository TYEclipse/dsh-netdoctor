# CHANGELOG · dsh-netdoctor

> 版本口径：patch 修 bug/补测试｜minor 新增用户可见功能｜major 破坏性变更。安装：`dsh plugin --profile web add github:TYEclipse/dsh-netdoctor`

## [0.3.0] — 2026-10-07
### Minor · R62
- [自主进化] R62 新增 dns_propagation（多解析器 DNS 传播对比 + 失败/超时如实上报）；dns_lookup 的自定义解析器改为 IP 字面量校验

## [0.2.3] — 2026-09-11
### Patch · R31
- [自主进化] 接入版本与覆盖率门禁（工具链）

## [0.2.2] — 2026-09-11
### Patch · R31
- [自主进化] 接入版本与覆盖率门禁（工具链）

## [0.2.1] — 2026-09-11
### Patch · R31
- [自主进化] 修复 IP 目标的 TLS 探测（Node ≥20 拒绝对 IP 字面量设置 SNI，ERR_TLS_SNI）+ 接入覆盖率门禁

