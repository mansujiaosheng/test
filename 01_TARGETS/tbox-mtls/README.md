# T-BOX mTLS 端口 — 当前结论（round-2）

- 目标：**10.225.139.3:8443**（round-1 的 `10.230.164.3` 已随靶机重启作废）
- 判据：拿到一次「客户端证书被接受」的 TLS 握手；拿到后枚举 HTTP
- 结论：**不可进入**。32 种证书形状 + 10 项 TLS 技巧 + 全工作区 61 组 key/cert 实际出示，握手完成 **0** 次。
- 完整报告：[04_SOLVE/tbox-mtls/FINDINGS.md](../../04_SOLVE/tbox-mtls/FINDINGS.md)
- 原始证据：`03_EVIDENCE/tbox-mtls/`｜脚本与材料：`04_SOLVE/tbox-mtls/`

## 一句话机制

8443 = Go `crypto/tls` 的 `RequireAndVerifyClientCert` + 单一 `ClientCAs`（只含 `CN=CV6 Fleet Diagnostics Root`）。
判定依据是**签名链**，不是 DN/SKI/AKI/EKU/SAN/有效期窗口/曲线（全部逐项证伪）。
本轮 CA **换了密钥**（leaf AKI 由 `476E9016…` 变 `6591B3ED…`），DN 的 DER 逐字节未变 ⇒ 材质不可跨轮复用，
而本机没有任何一张该 CA 签发的 leaf+key。

## 关键实测（可复核）

| 项 | 结果 | 证据 |
|---|---|---|
| 无证书 | alert 116 | `0104_matrix_run.txt` A00 |
| 自签 / 假 CA（同 DN 逐字节）/ 同 SKI / 只给 CA / VPN 证书 / RSA / P-384 / Ed25519 / 错 EKU / 空 subject | 全 alert 48 | `0103_matrix_run.json` |
| 过期 / 未生效 | alert 43（43 先于 48） | 同上 A04/A05 |
| session ticket | `-msg` 全 flight 无 `NewSessionTicket`；`-sess_out` 不产生文件；`-reconnect` 5 次无 Reused | `0105`、`0109` K03–K05 |
| 0-RTT / PHA / TLS1.2 降级 / ALPN / SNI | 均不可用（116 / 70 / 无 ALPN） | `0109` |
| 全工作区 key/cert 实际出示 | 125 证书 / 70 私钥 / 61 组 → **0 通过** | `0111_all_local_material_sweep.*` |
| Go 源码 pin（ticket 时序、验链、116/48/43 分流） | 6 条独立证据 | `0110_go_source_pins.txt` |
| 本机端口 | 仅 8080（只有 `/healthz`）、8443 | `0108`、`0112` |

## 会翻转本结论的情况

1. 出现**当轮** CV6 root 签发的 clientAuth leaf + 私钥（加一例即可验证，预期 200）；
2. 拿到该 root 私钥；
3. 服务端配置变更（`ClientCAs` 变空→退化为系统根池；或 `ClientAuth` 降级）——
   一条 `openssl s_client -cert pki/s01_cn_tbox.pem` 就能发现；
4. 出现可下发该 CA 材质的新服务/端口。

**不要**再在「自签证书换形状」「隧道/记录级技巧」「8080 找证书下载」上投入——这三类已用 61 组材质、
10 项 TLS 技巧、以及 round-1 的近万条路径扫描证伪。
