# 归档：中间过程文档

这里的文件是任务 01–04 推进过程中的**阶段性记录**（部分结论后来被推翻）。

正式交付请看上级目录：

- `01-tsp-bola/writeup.md`
- `02-ota-firmware/writeup.md`
- `03-mtls-ticket/writeup.md`
- `04-security-access/writeup.md`

## 为什么归档

- `01-tsp-ota/REPORT.md`、`tsp/T01_no_ota_endpoint.md`：**结论被推翻**——当时判定"TSP 的 /graphql 是桩，没有 OTA 端点"，
  实际是匹配键用错了（应为 `variables.vin`，不是 query 参数）。保留作为"错误判据"的反面教材。
- `03-mtls-diag-auth/writeup.md`：mTLS 侧早期记录，结论（证书墙不可硬闯、钥匙在工程包里）是对的，
  但当时还没拿到票据，也没有 `POST /api/v1/diag/session`。
- `cgw/*.md`、`tbox/*.md`：网关与 T-BOX 的中间侦察笔记。
