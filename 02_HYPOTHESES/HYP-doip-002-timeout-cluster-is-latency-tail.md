# HYP-doip-002 — 0x000A/0x000B/0x0022..0x0033 等 TA 无响应 = 隐藏 ECU 地址段

**提出** 2026-11-14 09:24（lead 转述：这些 TA 全部 TIMEOUT，其余秒回 NACK）
**状态** 已证伪（2026-11-14 09:27）
**证据** `03_EVIDENCE/cgw/doip_no_routing_activation.txt`（前段重测）、
`doip_ta_matrix.txt`、console `doip_ta_sweep_reclassified.txt`

## 假设
这些 TA 稳定无响应，别的 TA 稳定回 `7F 3E 31`，说明它们被路由到别处（等不到 ECU 答），
是"网关后面有哪些 ECU"的线索。

## 证伪方法
用 5.0s timeout 重测每个地址，且换 probe（`3E00` 与 `22F190` 各一次），再在整轮 898 个 TA
的矩阵里看它们的位置：

```
TA=0x000A 3E00   -> 7F3E31  391ms      TA=0x000A 22F190 -> 7F2231  382ms
TA=0x000B 3E00   -> 7F3E31  390ms      TA=0x0022 3E00   -> 7F3E31  377ms
TA=0x0033 3E00   -> 7F3E31  386ms      TA=0x0033 22F190 -> 7F2231  390ms
```

它们与 0x0001/0x0009/0x000C/0x0021/0x0034 的表现**完全一致**，没有任何区别。

## 真实成因：网关偶发慢应答
- 稳定 RTT ≈ 40–60ms；
- 但会偶发 **800ms ~ 1s**（甚至个别 >4s）的慢应答：150 连发测得 p95=799ms、max=1014ms；
  另一轮 4s timeout 的 DID 重测里 0xA7EA/0xA7F2/0xA7F3 各命中一次 4.0s 超时。
- 无速率限制：gap=0 连发 150 次，150/150 全部应答。

0.8s 的 timeout 正好切在这条长尾里，慢的那几次被记成 TIMEOUT。

## 结论
**不是隐藏地址段，是超时阈值卡在长尾上。** 纪律：任何 TIMEOUT 必须用 ≥3s timeout 复测
≥3 次才可采信；本组后续所有判定都遵守这条（`doip_client.py sweep-ta --retries 2
--retry-timeout 4.0` 已内建）。
