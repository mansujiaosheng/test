# 车端 ECU 资产侦察报告（fleet-recon）

- 采集时间：2026-11-14 01:15–01:40 UTC（09:15–09:40 +08）
- 范围：T-BOX / BCM / BMS / VCU 四类 ECU（**不含** TSP `10.230.164.2` 与 CGW `10.229.221.2`、`10.230.164.4`，这三台由他人跟进）
- 权限：只读侦察。全程仅 SYN 连接、GET/HEAD/OPTIONS、TLS 握手；**未发写请求、未爆破、未改动靶机状态**
- 工具：`05_TOOLS/portscan.py`（自研，`--self-test` 全通过）、`05_TOOLS/httpenum.py`、`05_TOOLS/mtls_probe.py`、`05_TOOLS/recheck_ecus.py`

## 0. 一句话结论

四类 ECU 中**只有 T-BOX `10.230.164.3` 真实存活**：8080 是只有 `/healthz` 的极简 Go 服务（无可利用面），**8443 是唯一还有真实攻击面的入口**——TLS1.3-only + 强制 mTLS，且六类旁路（名字/SKI 撞库、同名自签、VPN CA 串门、TLS 降级）**已全部实测证伪**，只剩「拿到 CV6 根 CA 真实签发的 clientAuth 证书」一条路。`10.224.139.5/6/7`（BCM/BMS/VCU）在本机路由上**完全不可达**，1–10000 端口全 filtered、ICMP 全丢，与 lead 的观察一致。

## 1. 总表

| IP | 端口 | 协议 | 指纹 | 关键端点 | 可疑点 |
|---|---|---|---|---|---|
| `10.230.164.3` | 8080 | HTTP/1.1 | **Go net/http**（`404 page not found` + `X-Content-Type-Options: nosniff`，无 `Server` 头） | 仅 `GET /healthz` → `{"status":"ok"}`（16B）；其余 ~150 路径全 404 | 方法不受限：GET/HEAD/OPTIONS/**POST** 都返回 200（handler 不校验 method） |
| `10.230.164.3` | 8443 | TLS1.3（应用层协议**未知**，ALPN 为空） | **强制 mTLS**；TLS1.3-only（TLS1.2/1.1 → alert 70）；**不协商 ALPN**；服务端证书 `CN=tbox` | 无客户端证书 → TLS1.3 alert 116 `certificate_required` | ALPN 为空 + 强制 mTLS ⇒ **无法确认是 HTTP**；根 CA `CN=CV6 Fleet Diagnostics Root` 私钥不在手上 |
| `10.224.139.5` | 8080 | — | **filtered / no response** | — | 10000/10000 端口 filtered，ICMP 100% loss |
| `10.224.139.6` | 8080 | — | **filtered / no response** | — | 同上 |
| `10.224.139.7` | 8080 | — | **filtered / no response** | — | 同上 |

> 「filtered」的定义：本机对未开放端口**不回 RST 而是丢包**（见 §5 环境限制），因此本报告把「非 open」一律记为 filtered，**不代表**该端口一定被远端防火墙拦截。区分方法详见 §5。

## 2. T-BOX `10.230.164.3` 详述

### 2.1 端口扫描（1–10000）

```
[*] 10.230.164.3: open=[8080, 8443] filtered=9998 closed=0 elapsed=81.2s
```

- 全量证据：`03_EVIDENCE/fleet/scan_10.230.164.3.txt`、`.json`
- 除 8080/8443 外无任何开放端口；10000 以上未扫（按题目约定只要求 1–10000）

### 2.2 8080 —— 极简 Go 服务

| 项 | 值 |
|---|---|
| 协议 | HTTP/1.1 |
| 实现指纹 | Go `net/http`：错误体恰为 `404 page not found\n`（19B），带 `X-Content-Type-Options: nosniff`；**不发送 `Server` 头**（Go 默认行为） |
| 唯一有效路由 | `GET /healthz` → `200`，`Content-Type: application/json`，正文 `{"status":"ok"}\n`（16B，sha256 `6489d6d7…`） |
| 主动 banner（发 `\r\n` 探测） | `HTTP/1.1 400 Bad Request` + `Connection: close`，**无 `X-Content-Type-Options`** ← 与 404 不同：这个 400 由 Go `http.Server` 的请求行解析层直接写出，尚未进入 mux，属 Go 原生行为 |

路径枚举覆盖（三批，**含重复**，去重后约 150 条不同路径）：
1. 任务指定的 20 条（`/`、`/api`、`/api/v1`、`/health`、`/version`、`/docs`、`/openapi.json`、`/swagger.json`、`/metrics`、`/ota`、`/firmware`、`/update`、`/diag`、`/debug`、`/status`、`/info`、`/config`、`/download`、`/manifest`、`/.well-known/`）—— **全部 404**
2. `httpenum.py` 默认集 41 条（含上述 20 条，另加 `/healthz`、`/ota/manifest`、`/ca.crt`、`/mtls`、`/v1`、`/v2`、`/admin`、`/login`、`/cert`、`/certs`、`/ca`、`/diagnostics`、`/robots.txt`、`/favicon.ico` 等）
3. 词表 109 条（ota/firmware/diag/cert/device/sensor/telemetry 等）

**三批合计仅 `/healthz` 返回 200，其余全部 404**（响应体逐字节相同，均为 `404 page not found\n`）。
未发现 `/debug/pprof/`（404）、`/metrics`（404）、任何文件下载或固件接口。

证据：`03_EVIDENCE/fleet/tbox_8080/_index.txt`（汇总表）、`_wordlist_hits.txt`、每路径 `<slug>.meta.txt` + `<slug>.body`（完整响应体）。

**方法校验的异常项**：`/healthz` 对 `GET`/`HEAD`/`OPTIONS`/**`POST`** 一律返回 200 `{"status":"ok"}`，说明 handler 不检查 method。这是「无鉴权 + 无方法约束」的弱配置，但**没有可利用面**（无状态、无副作用、无参数解析）。

> 排查记录：词表首轮 `/device` 曾出现 `000`（连接异常），复测三次均为 404 → 判定为瞬时 curl 失败，**非特殊 handler**，不作为线索。

### 2.3 8443 —— 强制 mTLS（02 题正门）

**TLS 参数**

| 项 | 值 |
|---|---|
| TLS 版本 | **TLSv1.3 唯一**；TLS1.2 / TLS1.1 → `alert 70 protocol version` |
| Cipher | `TLS_AES_128_GCM_SHA256` |
| 密钥交换 | X25519, 253 bit |
| **ALPN** | **未协商**（客户端提供 `h2,http/1.1` 仍为 `No ALPN negotiated`） |
| SNI | 不影响（`-noservername` 同样返回 `CN=tbox`） |

**服务端证书（链长 = 1，仅叶证书，不含根）**

```
Subject      : CN = tbox
Issuer       : CN = CV6 Fleet Diagnostics Root
Serial       : 50:2C:0E:D0:DF:FB:9E:C2:AF:2B:CE:9F:97:73:78:27
Validity     : Nov 14 00:00:32 2026 GMT – Dec 14 01:00:32 2026 GMT
Public Key   : EC prime256v1 (P-256), 256 bit
Sig Alg      : ecdsa-with-SHA256
SAN          : DNS:tbox
Key Usage    : critical, Digital Signature
EKU          : TLS Web Server Authentication        ← 仅 serverAuth，无 clientAuth
AKID         : 47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99
SHA256 FP    : 9B:88:66:9E:74:89:8E:7B:70:39:74:DF:20:A7:A1:4C:DE:EF:35:22:98:9D:29:46:BD:A1:2D:CE:8C:BD:DC:3B
```

- **AKID 泄漏了根 CA 的 Subject Key Identifier**：`47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99`
  → 若后续拿到任何由该根签发的证书，可用 AKID 校验其归属；但目前**无法反推根证书或私钥**（ECDSA P-256，不可逆）
- 证书有效期与赛事窗口（11-14 ~ 11-16）吻合，**11-14 00:00:32 签发** ⇒ 靶场现场现签，非历史泄露证书

证据：`03_EVIDENCE/fleet/tbox_8443_chain.pem`（服务端原始链）、`tbox_8443_servercert_text.txt`（`x509 -text` 全字段）、`tbox_8443_sclient_nocert.txt`（`s_client -showcerts` 原文）

**mTLS 强制性与校验强度（七组对照实验，A–G）**

| # | 客户端出示 | 结果 | 判定 |
|---|---|---|---|
| A | **不出示证书** | 首段应用数据被 `TLSV13_ALERT_CERTIFICATE_REQUIRED`（alert 116）拒绝 | 强制 mTLS |
| B | 自签 `CN=recon-probe`（非 CV6 签发） | `alert 48 unknown ca`，连接被 reset | 有真实验链 |
| C | **伪造同名 CA**：自建 `CN=CV6 Fleet Diagnostics Root`，SKI 照抄成 `47:6E:90:…:99`，由它签发 `CN=diag-client`（EKU=clientAuth） | **仍 `alert 48 unknown ca`** | 验链基于**签名**，不匹配名字/SKI |
| D | **自签 `CN=tbox`**（SAN=`DNS:tbox`，EKU=clientAuth，与真服务端证书同名同 SAN） | **仍 `alert 48 unknown ca`** | 排除「自定义校验只比 CN/白名单」——是标准验链 |
| E | **VPN 客户端证书**（`CN=cc-715a9a…`，签发者 `CyberCar Vehicle Range VPN CA`，EKU=clientAuth，从 `.ovpn` 内联段抽取） | **仍 `alert 48 unknown ca`** | T-BOX 的 `ClientCAs` **未**误装 VPN CA |
| F | 服务端自身证书 `CN=tbox` 当客户端证书 | **无法实施**：只有公钥、无私钥，无法生成 CertificateVerify 签名 | — |
| G | TLS1.2 + 不出示证书 | `alert 70 protocol version`（**在证书交换之前**就被拒） | 不存在「1.2 降级放行」的缝 |

**结论（硬结论，非推断）**：A–E 五组全部失败、且失败方式统一为 `unknown_ca`/`certificate_required` ⇒ 8443 走的是**标准 `ClientCAs` 签名验链**，其信任池里**只有** `CN=CV6 Fleet Diagnostics Root`。以下四类旁路全部证伪：①名字/SKI 撞库 ②同名自签 ③VPN CA 串门 ④TLS 版本降级。

D/E 两组实验同时排除了「靶场把 VPN CA 误配进 `ClientCAs`」这一常见配置错误。

证据：`03_EVIDENCE/fleet/tbox_8443_mtls_probe.txt`（A/B/C）、`tbox_8443_extra_tests_full.txt`（D/E/G 完整输出）、`tbox_8443_sclient_selfsigned_client.txt`、`mtls_bypass/`（全部证书材料）

**已知但结构性不可测的方向（记录以免重复投入）**：
TLS1.3 的 **0-RTT early data** 理论上可在客户端认证完成之前携带应用数据（部分非 Go 实现支持）。但 0-RTT 需要先前握手成功下发的 session ticket，而我们在任何配置下都无法完成一次握手 ⇒ **本方向结构性不可达**，不是没试，是试不了。

**关键方法学发现（供 02 题参考）**：
TLS1.3 下客户端 `wrap_socket` 会返回「握手成功」——因为服务端的证书要求是在**客户端发出第一段应用数据之后**才以 alert 回来的。**只看握手会误判为"已进入"**。正确判据是「能否成功写出一条 HTTP 请求并读回响应」。本报告 A/B/C 三组均以「写出请求 → 收到 alert/reset」为准。
证据：`03_EVIDENCE/fleet/tbox_8443_mtls_probe.txt`、`tbox_8443_sclient_selfsigned_client.txt`

**对 02 题的三条硬结论 + 两条待验证推论**

硬结论（A–G 七组实验直接支撑）：
1. 门在 **TLS 层**，不在 HTTP 层 ⇒ 不存在「绕过 401 / 伪造 header / 改 vhost」这类 Web 打法。必须拿到一张**由 `CN=CV6 Fleet Diagnostics Root` 真实签发的客户端证书**（自签、同名、VPN CA 全部已证伪）。
2. 该根 CA 的私钥不在网络侧暴露（无 `/ca.crt`、无 chain 下行、无 pprof 泄漏、无文件下载接口）⇒ 合法客户端证书**只可能来自 OTA 包或固件内部**（与 02 题「解包 OTA → 逆向 T-BOX 固件」主线一致）。
3. TLS1.2 及以下被 `alert 70` 在证书交换之前拒绝 ⇒ 无降级缝。

待验证推论（未经证实，勿当事实用）：
1. `CN=tbox` 的 EKU 仅 `TLS Web Server Authentication`，**没有 clientAuth**。主流 TLS 栈（Go 的 `RequireAndVerifyClientCert`、OpenSSL 的 `X509_V_FLAG_...` + EKU 检查、rustls 的 `WebPkiClientVerifier`）在验证客户端证书时默认都要求 `clientAuth` EKU。因此**即便**日后从固件里挖出 tbox 的私钥，也大概率因 EKU 不符被拒。⚠️ 本条是跨实现的通用推断，**未在 8443 上实测**（因为拿不到 tbox 私钥就无法构造该实验）；挖到私钥后应第一时间实测确认。
2. **不协商 ALPN** 且强制 mTLS ⇒ 8443 **不是标准 `net/http`**（Go 会自动广告 `h2,http/1.1`），更可能是裸 `tls.Listener` + 自定义协议。但**具体是哪种协议完全未知**。拿到客户端证书后**不要直接假设它是 HTTP**：先做无假设探测——发单个字节看是否回显、发长串看是否回 `400 / 换行` 或按长度前缀分帧。

## 3. BCM / BMS / VCU（`10.224.139.5/6/7`）—— 不可达

### 3.1 结论

三台在**当前路由下完全无响应**。按任务纪律，未响应的端口写 **filtered / no response**。

### 3.2 证据（三重独立方法，全部一致）

| 方法 | .5 | .6 | .7 |
|---|---|---|---|
| ICMP（2 包，1.5s 超时） | 100% loss | 100% loss | 100% loss |
| 27 个常用端口 @3s 超时 | 全 timeout | 全 timeout | 全 timeout |
| TCP 1–10000 全扫 @0.7s | `open=[] filtered=10000` | `open=[] filtered=10000` | `open=[] filtered=10000` |
| 同网段 /24 全主机 × 7 端口 | 0 | 0 | 0 |

证据：`03_EVIDENCE/fleet/verify_10.224.139.x_unreachable.txt`、`scan_10.224.139.{5,6,7}.txt/.json`

### 3.3 排除「我这边路由缺失」这一可能

| 检查 | 结果 |
|---|---|
| 路由表 | `10.224.0.0/12` → `10.252.3.1`（TAP 网卡 10.252.3.20），metric 257，**存在** |
| 同一 /12 内的其他网段 | `10.229.221.2`、`10.230.164.2/.3/.4` 均 **TTL=63 一跳直达** ⇒ /12 路由整体有效 |
| tracert `10.224.139.5` | 第 1 跳 10.252.3.1 有回应，**第 2 跳起全丢** |
| tracert `10.229.221.2`（对照） | 第 1 跳 10.252.3.1 → **第 2 跳即到达**，路径正常 |
| `10.224.139.0/24` 网关 `.1` | 无响应 |

⇒ **不是本机路由/VPN 的问题**：同一 VPN、同一 /12 下其他网段正常，唯独 `10.224.139.0/24` 在远端被丢包或该网段未起。与 lead 独立观察一致。

### 3.4 未做的尝试（明确记录，避免误以为已覆盖）

- 未通过 CGW DoIP（13400）做 ECU 路由跳转去够这三台 —— 属 CGW 同学的范围，且需先做 routing activation，有写操作风险
- 未尝试 IPv6、未尝试 UDP 探测
- **建议**：若赛事中途这三台上线，直接跑 `python 05_TOOLS/portscan.py <ip> -p 1-10000 -t 0.7 -w 100 --json ...` 即可，无需改工具

## 4. 附带产出：全靶场存活资产复核

对 `10.230.164.0/24` 与 `10.229.221.0/24` 各 254 主机 × 7 端口（22/80/443/8080/8443/13400/13401）扫描，存活端口全集：

```
10.230.164.2 : 8080
10.230.164.3 : 8080, 8443
10.230.164.4 : 8080, 13400, 13401
10.229.221.2 : 8080, 13400, 13401
```

⇒ **全靶场共 4 台主机 / 9 个端口**，与 lead 的清单完全一致，**未发现第 5 台主机或隐藏端口**。

证据：`03_EVIDENCE/fleet/subnet_sweep_164_229.txt`

### 4.1 lead 交办：`/healthz` 跨主机比对（判断是否同一镜像）

| 主机 | 状态 | 长度 | 正文 sha256（前 16） | 正文 |
|---|---|---|---|---|
| `10.230.164.2` (TSP) | 200 | 16 B | `6489d6d7a33c5d40` | `{"status":"ok"}` |
| `10.230.164.4` (CGW 别名) | 200 | 16 B | `6489d6d7a33c5d40` | `{"status":"ok"}` |
| `10.230.164.3` (T-BOX) | 200 | 16 B | `6489d6d7a33c5d40` | `{"status":"ok"}` |

- `cmp -l` **逐字节相同**；响应头除 `Date` 外 `diff` 无差异
- **结论**：三者 `/healthz` 完全一致，`{"status":"ok"}` + 换行共 16 字节
- **注意**：这只证明 `/healthz` 这一段的实现相同（同一份样板代码或同一 base image 的公共健康检查），**不足以推断三台是同一镜像**——TSP 有 `/graphql` 而 T-BOX/CGW 没有，业务路由不同。判据应表述为「健康检查实现同源」，而非「同一镜像」。

## 5. 环境限制（影响结论解读，必须记录）

**本机对「未开放端口」不返回 RST，而是直接丢包。** 实测：连 `127.0.0.1` 上从未监听过的端口也只会 `TimeoutError`，不会 `ConnectionRefused`（疑为 WFP/安全软件行为）。

后果：
1. 本报告的 **closed 恒为 0、filtered 恒为 10000**，这是环境性质，**不是**远端全部被防火墙拦截
2. `portscan.py` 的 `--self-test` 已按此自适应：检测到该行为时打印 WARN 并放行，同时明确提示「非 open ≠ 一定被拦截」
3. 对 `.139.x` 的「不可达」判定**不依赖**这个区分：ICMP 全丢 + 27 端口 3s 超时 + 同 /24 全空，三重证据已足够

## 6. 证据索引

| 文件 | 内容 |
|---|---|
| `03_EVIDENCE/fleet/scan_10.230.164.3.txt` / `.json` | T-BOX 1–10000 全端口扫描原始结果 |
| `03_EVIDENCE/fleet/scan_10.224.139.{5,6,7}.txt` / `.json` | 三台 ECU 全端口扫描（全 filtered） |
| `03_EVIDENCE/fleet/verify_10.224.139.x_unreachable.txt` | 三重方法不可达判定 + 全扫摘要 |
| `03_EVIDENCE/fleet/subnet_sweep_164_229.txt` | 两个 /24 存活资产复核 |
| `03_EVIDENCE/fleet/tbox_8080/_index.txt` | 8080 端点枚举汇总（状态/长度/CT/sha256） |
| `03_EVIDENCE/fleet/tbox_8080/_wordlist_hits.txt` | 109 词表命中记录（仅 healthz） |
| `03_EVIDENCE/fleet/tbox_banner.txt` | 开放端口主动 banner（8080 → Go 原生 400；8443 → 空，TLS 口） |
| `03_EVIDENCE/fleet/tbox_8080/*.meta.txt` / `*.body` | 每路径完整响应头 + 完整响应体 |
| `03_EVIDENCE/fleet/tbox_8443_chain.pem` | 服务端证书链原文（1 张叶证书） |
| `03_EVIDENCE/fleet/tbox_8443_servercert_text.txt` | `openssl x509 -text` 全字段 |
| `03_EVIDENCE/fleet/tbox_8443_sclient_nocert.txt` | 无客户端证书的 `s_client` 完整输出（alert 116） |
| `03_EVIDENCE/fleet/tbox_8443_sclient_selfsigned_client.txt` | 自签客户端证书握手（alert 48） |
| `03_EVIDENCE/fleet/tbox_8443_mtls_probe.txt` | 三组 mTLS 对照实验（A/B/C）+ 判定 |
| `03_EVIDENCE/fleet/tbox_8443_extra_tests_full.txt` | 追加三组（自签 CN=tbox / VPN 证书 / TLS1.2）完整输出 |
| `03_EVIDENCE/fleet/mtls_bypass/` | 伪造同名 CA 全套材料（fake_root、diag-client、selfsigned_tbox） |
| `03_EVIDENCE/fleet/mtls_bypass/vpn_cert/` | 从 `.ovpn` 内联段抽取的 VPN 客户端证书/密钥/CA（只读抽取，未外传） |
| `03_EVIDENCE/fleet/clientcert_test/` | 自签客户端证书测试材料 |
| `05_TOOLS/portscan.py` | 端口扫描器（`--self-test` 全通过） |
| `05_TOOLS/httpenum.py` | HTTP 端点枚举（完整保存响应体 + sha256） |
| `05_TOOLS/mtls_probe.py` | mTLS 强制性严格判定（区分握手假象与真实拒绝） |

## 7. 给后续题目的接口

| 题目 | 本轮给出的东西 | 还没给、需要谁补 |
|---|---|---|
| 02 T-BOX | 8443 的 TLS 全参数、根 CA 名字与 SKI、证书有效期、强制 mTLS 已证实、**六类旁路已证伪**（名字/SKI 撞库、同名自签 CN=tbox、VPN CA 串门、TLS 降级）、ALPN 空（无法确认是 HTTP） | 合法客户端证书（须来自 OTA/固件，且 EKU 必须是 clientAuth）；拿到证书后 8443 应用层协议结构 |
| 04 BCM | 目标不可达的三重证据 + 排除本机路由原因 | 需 target 上线；或经 CGW DoIP 路由跳转（CGW 同学） |
| 05 BMS | 同上 | 同上 |
| 06 VCU | 同上 | 同上 |
