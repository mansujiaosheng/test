# 任务 07 — 未授权 OTA 签名接口：FINDINGS

> 执行者 ota-sign ｜ 2026-11-14 10:17–11:15 CST ｜ 证据 `03_EVIDENCE/sign/` ｜ 工具 `04_SOLVE/sign/`
> 结论状态：**接口已找到并完整刻画；签名未取得**——服务端 campaign 闸门对该 campaign 恒关闭，请求侧无任何输入可打开。

## 1. 一句话结论

任务 07 要的「OTA 签名接口」**确实存在，且确实未授权**，就在 `TSP 10.225.139.2:8080 POST /graphql`，
operation 名 **`signFirmwareUpdate`**（另有同族 `assignFirmwareUpdate` / `countersignFirmwareUpdate` / `cosignFirmwareUpdate`）。
但它在拿到 `variables.vin` 之后撞上一个**服务端状态闸门**：

```
{"errors":[{"message":"update campaign validation failed"}]}
```

这个闸门不读任何其它请求字段（下表是证伪清单），因此**本轮没有拿到 ECDSA P-256/SHA-256 签名**，
任务 10/11 需要的签名格式参数只能给出「待签名落地后即可确定」的验签口径，不能杜撰签名值。

## 2. 接口与契约（已确证）

### 2.1 派发机制

TSP 的 `/graphql` 不是 GraphQL 引擎，是**子串匹配器**：

| 输入 | 结果 | 判据 |
|---|---|---|
| `{"query":"vehicleDiagnostics","variables":{"vin":"<已登记VIN>"}}` | 返回该车诊断对象 | 已知（任务 01） |
| `{"query":"xx vehicleDiagnostics yy","variables":{"vin":VIN}}` | 同样返回 | query 是**子串**匹配，不是解析 |
| `{"query":"VEHICLEDIAGNOSTICS",...}` | guest 回退 | 大小写敏感 |
| `{"query":"A"*20000+" vehicleDiagnostics",...}` | 仍然派发 | 无长度限制 ⇒ 可做「散弹」批量试探 |
| `{"query":"","variables":{"vin":VIN}}` | guest 回退 | query 必须命中 op 名 |

guest 回退特征串：
`{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}`

### 2.2 operation 清单（穷尽）

用「散弹 + 二分」法测了 **30 859** 个候选名（63 动词 × 55 名词 双向拼接 + 三段名 + 领域手选名），
活着的 operation 只有 5 个：

| operation | variables 键 | 响应 |
|---|---|---|
| `vehicleDiagnostics` | `vin` | 该车 OTA 诊断对象（campaignId / firmwareDownload / firmwareCredential / packageKey / tboxEndpoint / diagnosticEndpoint） |
| **`signFirmwareUpdate`** | `vin` | `{"errors":[{"message":"update campaign validation failed"}]}` |
| `assignFirmwareUpdate` | `vin` | 同上 |
| `countersignFirmwareUpdate` | `vin` | 同上 |
| `cosignFirmwareUpdate` | `vin` | 同上 |

四个 `*FirmwareUpdate` 名指向**同一个 handler**（响应字节完全一致）。
复现：`python 04_SOLVE/sign/sign_vcu.py discover` → `03_EVIDENCE/sign/T1_discover.txt`。

### 2.3 签名接口的两级闸门（状态机）

```
variables {}                        -> {"errors":[{"message":"vehicle campaign not found"}]}
variables {vin:"CV622697F82A936A1"} -> {"errors":[{"message":"update campaign validation failed"}]}
variables {vin:"<任何其它值>"}        -> {"errors":[{"message":"vehicle campaign not found"}]}
```

- 闸门 1 是**车辆 → campaign 归属查询**：只有本车 VIN 命中（`CAMP-243892C376D4CB2D5F826953`），
  连本轮的旧 VIN `CV6FF52FEE9EDDD86`、demo VIN `CV6000000DEMO0001` 都返回 not found。
  VIN 必须**逐字节相等**（前后加空格、换小写、加 `\n` 全部掉回 not found）。
- 闸门 2 是**「update campaign 校验」**，恒失败。

## 3. 闸门 2 的证伪清单（为什么不是「我没试对参数」）

| 维度 | 覆盖量 | 结果 | 证据 |
|---|---|---|---|
| 单键名 × 值 | 1 701 组（~85 键 × 20 值，含 campaign/campaignId/rollback/rollbackCounter/sha256/digest/firmware/size/address/packageKey/firmwareCredential…） | 全 SAME | `H_var_contract.json` |
| 宽键名 × 值 | **15 125** 组（~700 键含复合名 `updateCampaignId`/`campaignRollbackCounter`/`vcuRollbackValue`… × 25 值） | 仅 `vin` 自身被改时变化 | `M_key_sweep.json` |
| variables 结构形状 | **15 984** 组（5 328 形状 × 3 op：键组合 1–7 元、`input`/`update`/`request`/`payload`/`campaign`/`firmwareUpdate` 嵌套、字符串化 payload、数字/字符串/布尔/数组类型变体） | 只有 2 种响应 | `J_shapes.json` |
| 类型混淆探针 | **5 649** 组（807 键 × 对象/数组/超大整数/5000 字符/null/布尔/浮点） | 仅 `vin` 换类型时变化；其余键**连解析报错都不产生** | `P_type_oracle.json` |
| bundle 派生材料 | 616 组（该次 bundle 的 `nonce`/`packageKey`/`firmwareCredential`/`client cert SHA`/`zip SHA`/`vcu sha256` × ~44 键） | 全 SAME | `L_bundle_binding.json` |
| manifest 原样回灌 | 扁平 10 字段、原生类型版、嵌套、JSON 字符串版、`vcuRollback+vcuReferenceSize+vcuUpdateAddress` 三元组 | 全 SAME | `N_manifest_attempt.json` |
| query 文本形态 | 带 inline 参数 `(vin:"…",campaignId:"…",rollback:2)`、`mutation{…}`、声明 `$vin/$campaignId/$rollback` 变体 | 全 SAME | 本轮会话记录 |
| HTTP 头 | Host 10 种 vhost（tsp/tbox/cv6/fleet/localhost/…）、`X-Forwarded-For/Host/Proto`、`X-Real-IP`、`X-Client-Cert`、`X-SSL-Client-Verify/…-DN`、`X-Authenticated-User`、`X-Scope/X-Role`、UA、Referer | 全 SAME | 本轮会话记录 |
| 认证 | Basic 7 组（`diag:<cred>`、`<VIN>:<cred>`、空口令…）、Bearer cred/packageKey、`X-API-Key`/`X-Token`/Cookie | 全 SAME（本接口**完全不看认证**） | 本轮会话记录 |
| URL query | `/graphql?vin=…&campaignId=…&rollback=2` 等 5 组 | 全 SAME | 本轮会话记录 |
| 调用序列 | 每次重下 bundle 后 `assign → sign → countersign` 连跑 3 轮；`sign` 连发 8 次 | 全 SAME（不是顺序/计数状态机） | `N_manifest_attempt.json` |
| 顶层 body 键 | 把 campaignId/rollback/sha256/firmware/input 放到 `variables` 之外 | 全 SAME | `K_bundle_stability.json` 同批次 |

**判据**：如果 handler 真的读取某个键并做比较，那么「键名对但值错」与「键名错」会给出不同响应；
5 649 组类型混淆探针里除了 `vin` 之外**没有任何键能触发解析错误或换一句话**，
再加上 15 125 组宽键名扫描，可以判定：**handler 只读 `variables.vin`，闸门 2 是服务端固定状态**。

## 4. 环境面：签名接口不在别处（穷尽）

| 目标 | 手段 | 结果 | 证据 |
|---|---|---|---|
| TSP `10.225.139.2` | **全 65535 端口** TCP 扫描 | 仅 8080 | `F_fullport.log` |
| T-BOX `10.225.139.3` | 全 65535 | 8080 / 8443 | 同上 |
| CGW `10.226.193.2` | 全 65535 | 8080 / 13400 / 13401 | 同上 |
| CGW 别名 `10.225.139.4` | 全 65535 | 8080 / 13400 / 13401 | `F2_host4_fullport.log` |
| `10.225.139.0/24`、`10.226.193.0/24` | 254 主机 × 11 常用口 | 只有上述 4 台 | `F2_host4_fullport.log` |
| TSP 8080 | 1 729 路径 × GET/POST × 2 认证 = 13 832 | 真实路由只有 `/healthz`、`/graphql`、`/api/v1/objectives/final`、`/internal/audit` | `E_route_brute.json` |
| T-BOX 8080 | 同上 | 只有 `/healthz`、`/api/v1/ota/engineering-bundle` | 同上 |
| T-BOX 8443（**持合法 mTLS 客户端证书**） | 1 255 路径 × 2 方法 = 2 510 | **全部 `404 page not found`，连 `/` 都是 404** | `G_tbox8443_routes.json` |
| T-BOX 8443 | 前缀子树 oracle（`<prefix>/__probe_zz__`） | 无任何已注册子树 | `C2_tbox8443_prefix.json` |
| `/internal/audit`（三台一致） | 6 方法 × 9 body × 2 认证 | 恒 `{"error":"not found"}`（22 B JSON，与 Go 默认 404 不同，但无输入依赖） | `C_prefix_oracle.json` |
| 工程包 REST | `?vin/campaignId/rollback/sign/signature/signed/includeSignature/withSignature/vcu/sha256` 17 组；Basic 15 组凭据变体 | manifest 键集恒定、只有 `nonce` 每次变；凭据只有 `diag:<firmwareCredential>` 有效 | `K_bundle_stability.json` |

补充事实（可能对任务 03 有用）：工程包**每次下载都会用 Fleet Root 现签一张新的 client cert**，
subject/serial 固定（`CN=CV6 Engineering Diagnostic Client`，serial `5EDD0F6A2FD8A173DE7319628F7DEA1E`），
但**公钥每次不同**；`ca.pem` 恒定。接受 `cn`/`subject`/`serial` 参数的尝试全部无效（TBS 不可控），
所以它不是任意 TBS 的签名 oracle。

## 5. 签名格式：目前能确定什么

没有拿到签名，因此**不能**断言「签的是哪段字节 / 有没有 AAD / R‖S 还是 DER」。目前只有间接证据：

- 曲线/算法：Fleet 体系均为 **EC P-256（prime256v1）+ ecdsa-with-SHA256**（`01_TARGETS/web/service_map.md` 服务端证书；
  `diagnostics/ca.pem` / `client.pem` 同族）。
- manifest 的 VCU 更新参数固定：`vcuReferenceSize=1024`、`vcuRollback=2`、`vcuUpdateAddress=0x08040000`；
  `vcu-reference.bin` 1024 B，magic `CV6VCU1\0`，**跨下载稳定**，sha256 `2f3692767f605ef72fb47e1a779f2dfaeca802b4df1e35d38f8bb66d53ce6ea7`。
- 1116 B 更新包 = `12 nonce + 16 GCM tag + 64 raw-sig + 1024 ciphertext` 的假设仍未被任何证据支持或推翻。

**拿到签名后 5 分钟内可定论**：`04_SOLVE/sign/sign_vcu.py verify --message <signed-bytes> --signature <hex|b64> --pubkey <pem>`
会自动依次试 DER 与 raw `r‖s`，并打印命中的编码。

## 6. 为什么闸门关着（推断，非确证）

标注 **(推演生成)**：handler 在 `vin` 命中后调用一个 `validateUpdateCampaign`，它校验的是
**服务端 campaign 记录的状态**，而不是请求参数。该记录对本轮 campaign 处于「未就绪」，
最可能的两个来源：

1. **依赖前序任务推进的靶场状态**：`/api/v1/objectives/final` 现在 409
   `{"error":"VCU has not committed an authorized update"}`，说明靶场确实有「已提交授权更新」这个全局状态位；
   campaign 的可用性可能与它同源。
2. **campaign 记录需要由 T-BOX/车端侧先「登记」**：工程包是动态生成的，但 manifest 里没有任何 campaign/update 标识，
   说明 TSP 与 T-BOX 之间可能还有一步未做（T-BOX 8080 只有 1 条真实路由，也印证它没实现登记接口）。

两条都指向「任务 07 不是纯云侧可解」，需要 lead 决策下一步。

## 7. 建议的下一步（按性价比）

1. **让 03/05/06 先推进，再回来重测**：本接口是幂等只读的，`sign_vcu.py bind` 一条命令即可复测；
   一旦 campaign 闸门打开，同一脚本会直接把 signature 打出来。
2. **查 TSP 进程侧材料**（若拿到镜像/符号）：grep `update campaign validation failed` 与 `signFirmwareUpdate`
   可直接读出 handler 的校验条件——这是唯一能确定性解开闸门 2 的手段。
3. **换 campaign/车辆维度试探**：目前只有 1 台已登记车、1 个 campaign，`vehicleDiagnostics` 对任何 VIN 都要求已登记，
   所以无第二个样本可做差分。
4. 不建议继续在本接口上做参数爆破：已覆盖 15 k 键值组 + 16 k 形状 + 5.6 k 类型探针，边际收益为零。

## 8. 纪律声明

本轮**只做只读探测与签名请求**：未刷写、未上传固件、未改变车辆状态；
`signFirmwareUpdate` 是幂等请求（连发 8 次响应不变），未产生任何服务端可见副作用。

## 9. 复现

```bash
python 04_SOLVE/sign/sign_vcu.py discover   # operation 清单（4 请求）
python 04_SOLVE/sign/sign_vcu.py bind       # 本次提交（含 control 对照）
python 04_SOLVE/sign/sign_vcu.py verify --message m.bin --signature <hex> --pubkey pub.pem
# 其它过程脚本（按阶段）：gql_enum / rest_enum / prefix_oracle / shotgun{,2,3,4} /
#   route_brute / mtls_routes / var_contract / key_sweep / shape_hunt / type_oracle /
#   bundle_check / bundle_binding / manifest_attempt / inventory
```
