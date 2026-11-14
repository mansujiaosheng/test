# HYP-doip-003 — 网关存在 SecurityAccess，可逆 seed/key 解锁更多 DID

**提出** 2026-11-14 09:19（任务书优先项：27 01 seed → 27 02 key）
**状态** 已证伪（2026-11-14 09:30）
**证据** `03_EVIDENCE/cgw/doip_service_sweep.jsonl`（1534 条请求记录）、
`doip_layer_probe.jsonl`

## 假设
网关有 `27 01` 可拿 seed，用可逆算法算出 key 解锁扩展会话，从而读到 F190/F1A0 之外的 DID。

## 证伪方法
1. 直接 `27 01`（default session）→ `7F 27 11` = **serviceNotSupported**，
   不是 `0x12`（subFunctionNotSupported）也不是 `0x7F`（服务在当前会话不支持）。
   0x11 表示 **SID 0x27 根本没被分发**，不存在"先开扩展会话才有 SecurityAccess"这种前置。
2. 全 SID 扫描：0x00–0xFF 每个 SID 用 6 种 payload 形状（空 / `00` / `01` / `0000` / `0100` /
   `010000`）共 **1534 次请求**，除 `0x22` 外**全部**返回 `7F <sid> 11`。
3. `10 01` / `10 02` / `10 03` 也都是 `7F 10 11` —— 会话控制本身不存在，
   所以"提升会话"这条链在第一步就断了。

## 结论
**网关没有实现 SecurityAccess、也没有实现 DiagnosticSessionControl。**
seed 拿不到，key 无从谈起；本组未做任何 SecurityAccess 暴力穷举（无用功已避免）。
0x27 这条线在 13400 上判死。
