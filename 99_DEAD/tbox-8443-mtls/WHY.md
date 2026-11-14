# 死路：T-BOX `10.230.164.3:8443` 的 mTLS

- 判定时间：2026-11-14 09:45 CST
- 判定人：agent `tbox`
- 证据：`03_EVIDENCE/tbox_s09/0002_ovpn_cert_mtls_reconfirm.txt`、`03_EVIDENCE/tbox_s09/0006_FINDINGS.md`
  以及上一轮 `03_EVIDENCE/tbox/0001..0014_*`、`03_EVIDENCE/fleet/tbox_8443_*`（A–G 七组对照）

## 结论

**在不持有 `CV6 Fleet Diagnostics Root` 真实签发的 clientAuth 证书+私钥的前提下，8443 无法进入。不存在非证书旁路。**

不建议再投入人力。若日后从固件/OTA 包里取到该根 CA 的签发能力或一张已签发的客户端证书，本结论即失效，直接回来重测。

## 为什么（实现级，不只是「试过不行」）

8443 是 **Go `net/http` + `tls.Config{ClientAuth: RequireAndVerifyClientCert, ClientCAs: <仅 CV6 根>}`**。四条独立证据：

1. 明文打 8443 回 `Client sent an HTTP request to an HTTPS server.` —— 该字符串出自 Go `net/http` 对 `tls.RecordHeaderError` 的处理分支，说明监听者是 `http.Server` + `*tls.Conn`。
2. ALPN 恒为 `No ALPN negotiated` —— Go `http.Server` 未配 `NextProtos` 时就是空，与该实现自洽。
3. 任何非根签发证书 → `alert 48 unknown ca` —— Go `processCertsFromClient` 对**所有** `Verify()` 失败一律发 `alertUnknownCA`，48 正是标准验链失败的签名（若是「不验签」的 `RequireAnyClientCert`，自签证书会握手成功）。
4. `CertificateRequest` 的 CA 列表恰好一行 `CN = CV6 Fleet Diagnostics Root` —— Go 用 `ClientCAs.Subjects()` 填这个列表，故信任池非空且只有一个根。

第 4 条同时**证伪了「`ClientCAs` 为 nil 而退化为系统根池」这一经典配置错误**（那种情况下 CA 列表为空、公网 CA 签发的 clientAuth 证书即可进入）。本靶场不适用。

## 已逐条证伪的旁路（勿重复）

| 旁路 | 结果 |
|---|---|
| 不出示证书 | `alert 116 certificate_required`（TLS1.3 强制） |
| 自签 `CN=client` | `alert 48` |
| 自签 `CN=tbox`（同名同 SAN、EKU 正确） | `alert 48` |
| 伪造 CA，DN 与 SKI 均照抄真根 | `alert 48`（验的是签名，不是名字） |
| **VPN 客户端证书**（`CN=cc-715a9a…`，EKU=clientAuth，合规客户证书） | `alert 48`（VPN CA 不在信任池） |
| TLS1.2 / 1.1 降级 | `alert 70 protocol_version`，在证书交换**之前**即拒 |
| SNI 变体（`tbox`/`TBOX`/`tbox.cybercar`/空/错 SNI） | 同一张叶证书，同一 `alert 116` |
| 0-RTT early data | 结构性不可达（要先有一次成功握手才能拿到 ticket） |
| 后握手认证 PHA | 握手阶段即被 116 拒，进不到 PHA |
| 13401 当 DoIP-over-TLS 取链 | 非 TLS、非 DoIP，收到字节即关闭 |
| 8080 隐藏路由取证书 | 9351 条路径 × 7 方法，只有 `/healthz` |

## 顺带死掉的

- `10.230.164.3:8080` 只有 `/healthz`（9351 路径 × 7 方法的 405-判别式扫描 + 串行复测）。没有任何 OTA/诊断/证书下载路由。
- `10.230.164.3` 全 65535 端口只有 8080/8443，无第 3 个服务。
- 网关 `13401`（两个别名）：哑端口。
