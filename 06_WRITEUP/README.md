# CyberCar 车联网靶场 — 任务 01–04 Writeup

> 攻击面：云（TSP）→ 管（T-BOX / CGW）→ 端（ECU）。
> 本轮完成 01–04 四段：云端对象级越权、OTA 包解包与车端固件逆向、mTLS 诊断认证、64 位双 lane SecurityAccess。

## 总览

| 任务 | 标题 | 关键突破 | 状态 |
|---|---|---|---|
| 01 | 云侧对象级越权与 OTA 定位 | `/graphql` 匹配键是 `variables.vin`，query 参数是幌子 | ✅ |
| 02 | 解包 OTA 并逆向 T-BOX ARM 固件 | `CV6-OTA-1` = `nonce(12)‖ct‖tag(16)`，key=`packageKey` | ✅ |
| 03 | TLS 1.3 双向证书认证 | 8443 强 mTLS，钥匙在工程包里；票据 40 B / TTL 600 s | ✅ |
| 04 | 恢复 64 位 DoIP/UDS SecurityAccess | **票据必须送 ASCII 原文**进 DID `F1A1` | ✅ |

## 一条链串起来

```
① DoIP 0x0001 @ CGW:13400              -> VIN CV622697F82A936A1
② TSP /graphql  variables.vin          -> campaign / 工程包路径 / 诊断入口 / 凭据 / packageKey
③ Basic diag:<cred> 下载工程包          -> manifest + tbox-firmware.img + diagnostics/*.pem
④ AES-256-GCM(packageKey, nonce)       -> 16384 B ARMv7-M 固件
⑤ 逆向 0x080006fc / 0x08000668         -> KEK 派生 + RFC3394 解封 + 双 lane hash
⑥ mTLS @ T-BOX:8443                    -> 诊断票据（40 B，TTL 600 s）
⑦ UDS 10 03 -> 2E F1A1+ASCII票据       -> 6E F1A1
⑧ 27 01 -> seed ; hash8(seed,SHA256(VIN)[:8]) -> 27 02 -> 67 02 解锁
⑨ 22 F1A3                              -> 64 位 freshness 0000002daac9f4e3
```

## 各任务文档

| 文档 | 内容 |
|---|---|
| [01 云侧对象级越权](01-tsp-bola/writeup.md) | GraphQL 契约逆向（类型错误 oracle 发现只解析 `query`/`variables`）、BOLA 判据、工程包获取 |
| [02 OTA 解包与固件逆向](02-ota-firmware/writeup.md) | 容器格式反推、AES-GCM 解密、9 个密码原语、SoC 绑定、RFC 3394、双 lane hash、VCU 镜像定性 |
| [03 mTLS 与诊断票据](03-mtls-ticket/writeup.md) | 证书墙画像与证伪、mTLS 客户端、`POST /api/v1/diag/session`、票据结构解剖、tag 不可本地验证 |
| [04 SecurityAccess](04-security-access/writeup.md) | `0x1220` 节点画像、`F1A1` 票据槽、ASCII 关键格式、双 lane Seed/Key、完整可重放链路 |

## 关键数据速查

```
VIN                 CV622697F82A936A1
campaignId          CAMP-243892C376D4CB2D5F826953
firmwareCredential  5e7f07b4a81153ecd5868cc02557f823
packageKey          3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0
T-BOX 固件明文 sha256 88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229
派生 KEK            0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318
unwrap 出的密钥      693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d
C_DEV (hash8 常量)   e224dd2bb23a15b8
freshness           0000002daac9f4e3
```

## 一键复现

> **注意：比赛结束后靶机已关闭**（`10.225.139.x` / `10.226.193.2` 全部超时），
> 需要联网的脚本现在无法跑通，报 `TimeoutError` 属预期。
> 只有 `verify_all.py`（纯离线）仍可跑。

```bash
# 01 云侧越权 + 取包 + mTLS 验证        [需靶机]
python 04_SOLVE/task01/solve_task01.py

# 04 完整解锁链（自动下包 -> 取票 -> 解锁 -> 探测）  [需靶机]
python 04_SOLVE/uds/solve_task04.py

# 02 固件结论一键复核（C1-C6 应全 True）  [纯离线，可跑]
python 04_SOLVE/fw/verify_all.py

# 02 从工程包重新解密固件并校验摘要          [纯离线]
python 04_SOLVE/fw/decrypt_tbox.py work/t5/x/tbox-firmware.img \
       work/t5/x/manifest.json 3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0
```

### 离线可复核的最小证据集

即使靶机没了，下面这些能让 01–04 的结论被独立验证：

| 结论 | 离线判据 | 数据 |
|---|---|---|
| 02 解密正确 | 明文 sha256 == manifest.tboxSha256 | `work/t5/tbox.dec.bin` → `88b09d09…229` ✅ |
| 02 KEK 派生 | `SHA256("CV6-TBOX-KEK" ‖ fw[0x2000:0x2010] ‖ SHA256(fw[0:0x2000]))` | `0fd6e171…b318` |
| 02 RFC3394 | `aes_key_unwrap(KEK, fw[0x2040:0x2068])` 且 re-wrap 逐字节相等 | `693d2ab0…693d` |
| 02 hash8 原语 | `hash8(0,0,e224dd2bb23a15b8)` == 固件 Unicorn 执行结果 | `77be1f61090854c7` ✅ |
| 03 票据结构 | base64url 解码 40 B = `nonce(16)‖exp(8)‖tag(16)` | `03_EVIDENCE/ticket/0203_ticket_sample.json` |
| 04 解锁链 | 原始 trace 里的 `6ef1a1 / 6701… / 6702` | `03_EVIDENCE/cgw/`、`03_EVIDENCE/uds/` |

## 三个最有价值的教训

1. **"泛化响应"会掩盖缺陷**：TSP 对一切未命中都回 guest demo，导致 1000+ 次枚举全部"看起来一样"。真正判据必须是**类型错误**（`{"query":123}` → 400）这种能二值化的信号，而不是肉眼比对响应内容。

2. **`2E` 写 DID 的零长度探测无效**：零长度会在 DID 查表前被长度校验拒掉，让"表里有没有这个 DID"这一信息完全丢失。必须用**真实长度数据**重扫，才暴露出 `F1A1` 的 `NRC 0x35`。

3. **同一个 NRC 可以有两种成因**：`0x1220` 的 `27` 恒回 `7E`（子功能不支持），而 `2E F1A1` 送错格式回 `35`（invalidKey）。前者是"派发前拒"，后者是"校验后拒"——把 `35` 误当"服务没实现"就会一直绕圈。

## 未完成部分（供后续）

- **05 / 06**：`13401` 在所有测试条件下（含解锁态、14 种 framing、源端口、UDP、TLS、单字节 0x00–0xFF 握手）均为 accept-then-close，CAN FD 桥未能打开；`0x1220` 全 65536 RID 扫描无任何 RoutineControl 例程，`0x1000` 只实现 `0x22`。
- **07**：`signFirmwareUpdate` 等 4 个 operation 确实存在且未授权，但服务端闸门恒返回 `update campaign validation failed`，15 125 组键值 + 15 984 组形状 + 5 649 组类型混淆探针均无法改变该状态，判定为服务端固定状态而非请求参数问题。
