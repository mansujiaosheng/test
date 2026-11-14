# 任务 03：完成 TLS 1.3 双向证书认证（mtls-diagnostic-auth，250 分）

- **靶机轮次**：2026-11-14 第二轮（门户重启后，gen-2）
- **入口**：`https://10.225.139.3:8443`（T-BOX mTLS 诊断面）；材质来自任务 01 下载的 OTA 工程包 `diagnostics/` 目录
- **结论**：使用工程包内 `CV6 Fleet Diagnostics Root` CA 与 ECDSA P-256 客户端证书完成 **TLS 1.3 双向认证**（verify OK）；在 8443 的最小路由面上定位到唯一诊断入口 **`POST /api/v1/diag/session`**，取得**有时效的诊断票据**（40 字节，10 分钟有效期）及 DoIP 侧 tester 逻辑地址 `0xE442`，为任务 04 的 DoIP SecurityAccess 提供了票据绑定输入。

## 1. mTLS 材质（来自任务 01 工程包）

工程包 `cv6-engineering-bundle.zip` 解包后的 `diagnostics/` 三件套：

| 文件 | 说明 |
|---|---|
| `ca.pem` | `CN=CV6 Fleet Diagnostics Root`（自签根，ECDSA P-256） |
| `client.pem` | `CN=CV6 Engineering Diagnostic Client`，签发者同上，**ECDSA P-256（prime256v1）/ ecdsa-with-SHA256**，EKU = `TLS Web Client Authentication` |
| `client-key.pem` | 与 client.pem 公钥匹配的 EC 私钥 |

**注意**：工程包按请求动态生成——每次下载证书 `notBefore` 都等于下载时刻（+30 天有效期），因此 mTLS 材质是"随包现签"的，无法跨轮复用；换 generation 后需重新走任务 01 下载链路。

## 2. 建立 TLS 1.3 双向认证会话

关键点：服务端证书 `CN=tbox`，而我们是按 IP 访问，**必须显式设置 `server_hostname="tbox"`** 完成 SNI 与主机名校验，否则握手失败。

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations("ca.pem")
ctx.load_cert_chain("client.pem", "client-key.pem")
ctx.check_hostname = True
sock = socket.create_connection(("10.225.139.3", 8443), timeout=8)
s = ctx.wrap_socket(sock, server_hostname="tbox")
```

实测握手（openssl s_client 带客户端证书）：

```
subject=CN=tbox
issuer=CN=CV6 Fleet Diagnostics Root
Protocol: TLSv1.3
Cipher    : TLS_AES_128_GCM_SHA256
Verify return code: 0 (ok)
```

服务端**强制要求客户端证书**：不带 client.pem 时请求即被 fatal alert 拒绝；带证书后 TLS 层即通过。

## 3. 定位诊断入口（路由面探测）

8443 是一个极小的 Go 服务：

- `GET/POST` 对 `/`、`/healthz`、`/ticket`、`/api/v1/*`（约 150 个候选路径字典）全部 **404 `404 page not found`**；
- 对每条候选路径做 **GET+POST 双方法矩阵**后，仅一处非 404：

| 方法 | 路径 | 结果 |
|---|---|---|
| GET | `/api/v1/diag/session` | `405 {"error":"method not allowed"}` |
| POST | `/api/v1/diag/session`（空 body） | **`200`** |
| PUT/PATCH/DELETE/OPTIONS | 同上 | `405` |
| HEAD | 同上 | `405`（空 body） |

⇒ **唯一诊断入口 = `POST /api/v1/diag/session`**，且 body 可为空（`Content-Length: 0` 即可），VIN 等字段并非必需。

## 4. 取得有时效的诊断票据

```json
POST /api/v1/diag/session
→ HTTP/1.1 200 OK
{
  "cgwEndpoint": "cgw:13400",
  "diagnosticTicket": "jPyHlY-Iu2LJeKMpx_TduAAAAABq98tABbHmv0tHj-Mbpa64JtlaNw",
  "logicalAddress": "0xE442"
}
```

三个字段的用途：

| 字段 | 含义 |
|---|---|
| `diagnosticTicket` | base64url（无填充），**解码后固定 40 字节**，DoIP 侧绑定的凭据 |
| `logicalAddress` | `0xE442` —— 任务 04 RoutingActivation 应使用的 **tester 逻辑地址** |
| `cgwEndpoint` | `cgw:13400` —— 下一步 DoIP 连接点 |

### 票据结构分析（实测推断）

连续取两张票据对比（间隔 3 秒）：

```
t1: exp_u32=0x6af7cb76  exp=1794624374  fetch_at=1794623774  delta=600s
t2: exp_u32=0x6af7cb7a  exp=1794624378  fetch_at=1794623777  delta=601s
t1[0:16] != t2[0:16]   （随机）
t1[24:]  != t2[24:]    （MAC 随票据变化）
t1[16:20] == t2[16:20] == 00000000
```

⇒ 40 字节布局：**[0..15] 随机会话 ID ＋ [16..19] 全零（版本/保留）＋ [20..23] 过期时间 u32（大端，恒为签发时刻 +600 s）＋ [24..39] 16 字节校验标签**。

⇒ **票据有效期 = 10 分钟**，过期需重新走 mTLS 会话获取；这正是任务描述中"有时效的诊断票据"。

## 5. 与任务 04 的衔接

票据的消费点在 DoIP 侧（`cgw:13400`）：RoutingActivation（0x0005）使用 `logicalAddress=0xE442` 作为源地址、并将票据字节放入激活载荷进行绑定（`doip_bind.py` / `stage4_*.py` 已验证绑定位置），随后才能在扩展会话中通过 SecurityAccess。该部分属任务 04 范围，此处只产出票据与入口。

## 6. 复现

```bash
python mtls_probe.py     # 8443 基础路由面探测（需先完成任务01取得 diagnostics/）
python diag_session.py   # 方法矩阵 + POST /api/v1/diag/session 取票据
python doip_bind.py      # 票据结构解析 + DoIP RA 绑定尝试（任务04衔接）
```

依赖：任务 01 的 `ota/diagnostics/{ca.pem,client.pem,client-key.pem}` 与工程包 manifest。

## 7. 判据与边界

- **已验证**：TLS 1.3 双向认证握手（verify OK）、`POST /api/v1/diag/session` 票据获取、票据 40 字节结构与 600 s 有效期、tester 逻辑地址 `0xE442`（均为实测）。
- **未验证/推断**：票据 [24..39] 的具体 MAC 算法（HMAC/CMAC、密钥来源）未逆向——不影响使用；票据在 CGW 侧的校验逻辑属任务 04。
- **风险提示**：`client-key.pem`、`diagnosticTicket` 属敏感材料，交付时按需脱敏；票据 10 分钟过期，作证时需现场现取。
