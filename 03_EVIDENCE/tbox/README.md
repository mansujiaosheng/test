# T02 证据索引（T-BOX OTA 与 mTLS 诊断）

> 维护：tbox-mtls｜最后更新 2026-11-14 09:45 CST
> 一句话结论：`10.230.164.3:8443` 是**标准实现的双向认证**，全部配置级绕过已排除；
> 通过的唯一条件是由 `CN = CV6 Fleet Diagnostics Root` 签发的客户端证书+私钥。`.3:8080` 只有 `/healthz`。

## 按阅读顺序

| 文件 | 内容 | 一句话结论 |
|---|---|---|
| `../web/8443_tls_probe_matrix.txt` | 历史：版本/ALPN/SNI/明文 400 | TLS1.3 only，ALPN 不协商，无客户端证书即 116 |
| `../web/8443_s_client_servername_tbox.txt` | 历史：证书链 + 可接受客户端 CA | 链长 1（只发叶），CA 名 = CV6 Fleet Diagnostics Root |
| `../web/8443_ciphers_groups.txt` | 历史：套件/曲线/会话恢复 | 3 套件 3 曲线全接受，无 ticket 重用 |
| `0001`–`0004` | 早期：VPN 证书试打 + 自签对照 | VPN 信任域≠fleet 信任域，均 48 |
| **`0005_mtls_cert_construction_matrix.txt`** | **12 组客户端证书构造**（含同 DN 假 CA 双证链、伪造 SKI、过期、v1） | **全 48，唯过期给 43** |
| **`0006_sni_sweep.txt`** | **46 个 SNI 值**（含无 SNI、VIN） | 同一张证书 + 一律 116，无 SNI 分支 |
| `0008_tcpsweep_164_24.txt` | /24 × 12 端口共 3048 次 | 只有 .2/.3/.4，无第四台主机 |
| `0009_probe_13401.txt` | .4:13401 指纹 | 连上静默、发数据即 RST，非 TLS 非 HTTP（lead 已接手） |
| `0010_host_scoped_and_filtered.txt` | nmap 报 filtered 的 21 端口重测 + 8080 首轮 host 变体 | 无隐藏服务 |
| `0011_host_scoped_sweep.txt` | 1169 路径 × 3 Host + 1036 header 变体 | 仅 /healthz |
| `0012_retry_timeouts.txt` | 0011 的 18 条超时串行复核 | 全部 404（并发客户端超时） |
| `0013_vehicle_audit_timing.txt` | 唯一 3s 疑似慢路由复测 24 次 | 抖动，无慢路由 |
| **`0014_cert_facts.txt`** + `0014_srv_leaf_tbox.pem/.der` | 叶证书全量事实（实时抓取，SHA256 `9b88669e…`） | 根证书**未线上传输**，不可导出 |
| **`0015_lab_go_alert_mapping.md`** | **本机 go1.24.2 复现同形服务端** | alert 三元组 116/48/43 **逐条一致**；池内根签发 → HTTP 200 |
| `TLS_BYPASS_NEGATIVE.md` | 负面结果全文（9 节，含复现命令） | 已排除 8 类方向，剩 2 条真实路径 |
| `../../02_HYPOTHESES/HYP-tbox-01-mtls.md` | 假设台账 H1–H11 | H1–H10 全部否决，H11（云侧签发）未验证 |

## 写 writeup 时可直接引用的三条硬结论

1. 服务端 = `RequireAndVerifyClientCert` + `ClientCAs={fleet root}` + `MinVersion=TLS1.3`，与 Go 标准库默认行为**逐字节一致**（本地复现）。
2. 「同 DN 假 CA + 双证链」被拒（alert 48）⇒ 不存在"信任客户端自带链"的配错；「过期证书」给 43 而非 48 ⇒ 不存在自写校验分支。
3. 一旦持有真根签发的 leaf+key，8443 立即给 HTTP 200（本地正例已证），OTA/诊断接口才第一次暴露——**当前环境未提供该材料**。

## 未做 / 待定

- `.2:8080`（TSP）的 host-scoped + method + header 矩阵：已设计（`04_SOLVE/tbox/host_scoped_sweep.py` 改 HOST_IP 即可），等 lead 分配以免与 tsp-gql 撞车。
- 若 TSP 也无签发接口 ⇒ T02 在本环境不可解，按"预期路径缺失"上报。
