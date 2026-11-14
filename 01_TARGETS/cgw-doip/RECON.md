# CGW / DoIP (ISO 13400-2) 侦察报告

- 目标：`10.229.221.2`（CGW），端口 8080 / 13400 / 13401
- 同构主机：`10.230.164.4`（Lead 全网段扫描发现，不在题目清单内，8080/13400/13401 与 CGW 相同）
- 采集时间：2026-11-14 09:29 ~ 09:35 (+08:00)
- 客户端：`04_SOLVE/cgw-doip/doip_client.py`
- 证据：`03_EVIDENCE/cgw-doip/E-cgw-*.txt`（27 份，含 tx/rx 十六进制与解码 JSON）
- 一键重放：`python 04_SOLVE/cgw-doip/capture_evidence.py`

---

## 0. 结论速览

| 项 | 结果 |
|---|---|
| **VIN** | **`CV6FF52FEE9EDDD86`** |
| 取得方式 | ① DoIP 车辆识别 `0x0001`→`0x0004`；② UDS `22 F1 90` 经 DoIP 诊断通道。两路一致 |
| DoIP LogicalAddress | `0x1000` |
| DoIP EID | `06:00:00:00:10:00` |
| DoIP GID | `00:00:00:00:00:00`（全零，不属于任何 group） |
| FurtherAction | `0x0000` |
| 支持的 UDS 服务 | **仅 `0x22` ReadDataByIdentifier**；其余全部 NRC `0x11` serviceNotSupported |
| 可读 DID | **仅 2 个**：`0xF190`(VIN)、`0xF1A0`(诊断逻辑地址表) |
| `0xF1A0` 内容 | `07E0 07E8 07E1 07E9` → 两对 OBD-II 请求/响应地址 |
| 13401 | 非 DoIP、非 TLS，三元组握手后立即被关闭。**无攻击面** |
| 8080 | 只有 `/healthz` → `{"status":"ok"}`，其余全 Go 默认 404 |
| UDP 13400 | 无任何响应（车辆发现/公告面关闭） |
| `10.230.164.4` | **与 `10.229.221.2` 是同一个 DoIP 实体**（见 §6） |

---

## 1. 端口指纹

| 端口 | 协议 | 状态 | 指纹 |
|---|---|---|---|
| 8080/TCP | HTTP/1.1 | OPEN | Go `net/http`。无 `Server` 头；404 为经典 `404 page not found\n` + `X-Content-Type-Options: nosniff`。仅 `/healthz` 存在 |
| 13400/TCP | **DoIP ISO 13400-2 明文** | OPEN | 标准 8 字节头 `02 FD`，响应规范 |
| 13400/UDP | — | 无响应 | 发包后 3 秒静默 |
| 13401/TCP | 未知（非 DoIP 明文、非 TLS） | OPEN 但不服务 | 连接建立后服务端立即 FIN/RST，零字节 |

### 8080 细节
- `/healthz` → `200 {"status":"ok"}`（16 字节，`Content-Type: application/json`）
- **方法不校验**：GET/POST/PUT/DELETE/OPTIONS 全部 `200`，无 `Allow` 头
- 扫描 493 条路径（含 `/api`、`/api/v1/*`、`/vehicles`、`/vin`、`/doip`、`/can`、`/ota`、`/ota/`、`/update`、`/firmware`、`/diag`、`/metrics`、`/debug/pprof/`、`/debug/vars`、`/admin`、`/graphql`、`/swagger`、`/openapi.json`、`/.git/HEAD` 等），**除 `/healthz` 外全部默认 404**
- 带 VIN 的参数路径（`/vehicle/CV6FF52FEE9EDDD86`、`/vin/CV6FF52FEE9EDDD86` 等）同样 404
- `//healthz`、`/./healthz` → `307` 重定向到 `/healthz`（Go ServeMux 标准行为）
- h2c prior-knowledge（`PRI * HTTP/2.0`）→ `400 Bad Request`，不支持 h2c
- 结论：8080 是一个**只有健康检查的 sidecar**，不含任何业务接口

---

## 2. 车辆识别（VIN 取证）

### 2.1 DoIP 层：`0x0001` → `0x0004`

请求（payload 长度 0，符合 ISO 13400-2）：

```
TX  02fd 0001 00000000
```

响应：

```
RX  02fd 0004 00000021
    4356364646353246454539454444443836   → VIN "CV6FF52FEE9EDDD86"
    1000                                 → LogicalAddress 0x1000
    060000001000                         → EID 06:00:00:00:10:00
    000000000000                         → GID 全零
    0000                                 → FurtherAction 0x0000
```

证据：`E-cgw-identify-01.txt`

> 单次 TCP 连接、8 字节即可拿到车辆身份，**无需任何认证**。这是 DoIP 的规范设计（车辆发现必须免认证），本身不算漏洞；问题在于它把「响应 payload 长度」也一起放宽了，见 H-003。

### 2.2 UDS 层交叉复核：`22 F1 90`

```
TX  02fd 0005 00000009 0E00 E0 00000000 00000000      (RoutingActivation, SA=0x0E00)
RX  02fd 0006 00000009 0E00 1000 10 00000000           (code 0x10 SUCCESSFUL)

TX  02fd 8001 00000018 1000 0E00 22F190
RX  02fd 8001 00000018 1000 0E00 62F190 4356364646353246454539454444443836
                                     └─ "CV6FF52FEE9EDDD86"
```

证据：`E-cgw-uds-vin-01.txt`

**两条独立路径给出同一 VIN**，且与 TSP 侧 guest 账号只能看到的 `CV6000000DEMO0001`（Guest demo vehicle）不同 —— 真车身份只能从车上取，符合预期。

### 2.3 VIN 结构旁证

`CV6 FF5 2F EE 9EDDD86` 按 WMI/VDS/VIS 切分，`CV6` 为厂商代码。该前缀与 T-BOX `10.230.164.3:8443` 证书链的 CA 名 `CN=CV6 Fleet Diagnostics Root` 完全一致 —— 说明 `CV6` 是该车队的真实厂商代码，不是随机填充值。此条对 02 题（mTLS 诊断）的「证书链属于该车专属 PKI」论证有支撑作用。

> 注：该结论由 Lead 提供的 T-BOX 证书事实推得，本文档未独立验证 T-BOX 侧。

---

## 3. 逻辑地址表

| 地址 | 角色 | 实测行为 |
|---|---|---|
| `0x1000` | **DoIP 网关实体自身** | 唯一有真实应答的实体。支持 `0x22`，`F190`/`F1A0` 有值 |
| `0x0E00` / `0x0E80` / `0x0FFE` / `0x0100` / `0x0000` / `0x0001` / `0x0FFF` / `0xE000` / `0xFFFF` | 均可作为 tester 源地址 | **全部被接受**，见 H-002 |
| `0x07E0` ↔ `0x07E8` | 发动机 ECU（OBD-II 标准地址对） | 由 `0xF1A0` 泄露；实测**地址存在但无处理逻辑**：任何 UDS 服务均返回 `7f .. 31` requestOutOfRange |
| `0x07E1` ↔ `0x07E9` | 变速箱 ECU（OBD-II 标准地址对） | 同上 |

**为什么判定 `0x07E0` 是"存在但无实现"而不是"地址不存在"**：网关自身 `0x1000` 对不支持的服务返回 **NRC `0x11`**（serviceNotSupported），而 `0x07E0` 对**同一服务**返回 **NRC `0x31`**（requestOutOfRange）。两者 NRC 不同，说明目标地址确实改变了服务端的处理分支 —— 网关认得这个地址，只是没有为它挂处理逻辑。

证据：`E-cgw-uds-f1a0-01.txt`、`E-cgw-sid-matrix-01.txt`

### 只读 DID 全集（0xF100–0xF1FF + 常见值，共 269 个）

| DID | 值 | 说明 |
|---|---|---|
| `0xF190` | `CV6FF52FEE9EDDD86` | VIN |
| `0xF1A0` | `07E0 07E8 07E1 07E9` | 诊断逻辑地址表 |
| 其余 267 个 | `7f 22 31` | requestOutOfRange |

证据：`E-cgw-did-bulk-01.txt`

---

## 4. UDS 服务面

对网关 `0x1000` 的完整服务矩阵：

| 服务 | UDS | 结果 |
|---|---|---|
| ReadDataByIdentifier | `22` | **POSITIVE**（唯一可用） |
| DiagnosticSessionControl | `10 01` | `7f 10 11` serviceNotSupported |
| ECUReset | `11 01` | `7f 11 11` |
| ReadDTCInformation | `19 01` | `7f 19 11` |
| ReadMemoryByAddress | `23 …` | `7f 23 11` |
| SecurityAccess | `27 01` | `7f 27 11` |
| CommunicationControl | `28 00 01` | `7f 28 11` |
| RoutineControl | `31 01 00 01` | `7f 31 11` |
| TesterPresent | `3E 00` | `7f 3E 11` |
| ControlDTCSetting | `85 01` | `7f 85 11` |
| WriteDataByIdentifier | `2E F190` | `7f 2E 11` |
| RequestDownload | `34 …` | `7f 34 11` |
| TransferData | `36 01` | `7f 36 11` |

证据：`E-cgw-sid-matrix-01.txt`

**重要含义**：这是高度裁剪的实现 —— 连 `10`（会话控制）和 `3E`（TesterPresent）都不支持。因此：
- 没有任何会话/安全访问面可打（`0x27` 直接 serviceNotSupported，不存在 SecurityAccess 绕过问题）
- 没有刷写通道（`0x34`/`0x36` 不支持）→ **DoIP 侧不存在 OTA 写入面**，OTA 只能走别的通道（T-BOX / 云侧）
- 所有写服务均 returned `0x11`，**本次侦察未改变任何车辆状态**

---

## 5. 安全发现（按严重度）

### H-002 · DoIP RoutingActivation 无认证、无源地址校验（高）

按 ISO 13400-2 表 47，未注册的 source address 必须被拒（response code `0x00`），重复注册须返回 `0x02`/`0x03`。实测：

1. **45/45 组合全部返回 `0x10` SUCCESSFUL**
   - 源地址：`0x0E00`、`0x0E80`、`0x0100`、`0x0000`、`0x0001`、`0x1000`、`0x0FFF`、`0xE000`、`0xFFFF`
   - 激活类型：`0x00`、`0x01`、`0x02`、`0xE0`、`0xFF`（含保留值）
   - 其中 `0x1000` = **冒充网关自身逻辑地址**；`0xFFFF` = 广播地址；`0x0000` = 保留地址
2. **重复注册被允许**：同一 SA `0x0E00` 在两条不同 TCP 连接上先后激活，两条都得到 `0x10`，且第一条连接的诊断会话仍正常工作 → 无会话隔离、无单会话约束

影响：任何能访问 13400 的主体都能获得完整诊断路由，并可任意伪造 tester 身份。对量产车而言，这是诊断面完全无鉴权的入口级缺陷。

证据：`E-cgw-ra-matrix-01.txt`、`E-cgw-ra-duplicate-01.txt`

### H-003 · Vehicle Identification Request 不校验 payload 长度（中）

ISO 13400-2 规定 `0x0001` 请求的 payload 长度必须为 0。实测发送 8 字节 ASCII 垃圾、64 字节 `0xAA` 垃圾，服务器**照常返回完整 VIN 与 EID/GID**。

影响：实现层未做长度校验，说明其报文分派只看 header 的 type 字段。虽然 VIN 泄露本身符合 DoIP 设计，但这暴露出**解析器对输入不做一致性检查**，是进一步构造畸形报文的基础。

证据：`E-cgw-identify-junk-01.txt`、`E-cgw-identify-junk-02.txt`

### H-005 · DID `0xF1A0` 泄露内部 ECU 诊断地址表（中）

`22 F1 A0` 返回 `07E0 07E8 07E1 07E9`，即两对 OBD-II 请求/响应地址，等价于把车内 ECU 拓扑（至少 2 个 ECU 及其诊断地址）对外公开。攻击者据此可定向构造针对具体 ECU 的请求，无需盲扫。

证据：`E-cgw-uds-f1a0-01.txt`

### H-006 · 声明长度大于实际数据时连接被无限期占用（中，DoS 面，未验证利用）

发送 `02fd 0001 0000FFFF`（声明 65535 字节 payload 但一个字节都不发），服务器 4 秒后仍在静默等待，socket 被占住，不返回错误、不超时、不断开。

- 已验证部分：服务端确实按声明长度阻塞等待
- **未验证部分**：是否按声明长度预分配内存（若按 `0xFFFFFFFF` 预分配则为内存耗尽型 DoS）。**未测试**，避免影响共享靶场环境

证据：`E-cgw-malformed-08.txt`（declared len 0xFFFF 用例，rx 为空 + `TIMEOUT`）

### 观察 · 版本号错误时静默断开（低）

| 输入 | 期望（ISO） | 实测 |
|---|---|---|
| `03fd …`（version 0x03） | NACK `0x00` incorrect pattern format | 静默，无响应 |
| `02fe …`（inverse 0xFE） | NACK `0x00` | 静默 |
| `0200 …`（inverse 0x00） | NACK `0x00` | 静默 |
| 未知类型 `0x9999` | NACK `0x01` unknown payload type | ✅ `02fd 0000 00000001 01` |
| `0x8001` payload 0 字节 | NACK `0x04` invalid payload length | ✅ `02fd 0000 00000001 04` |
| `0x0005` payload 0 字节 | NACK `0x04` | ✅ 同上 |

即：**type 校验与长度校验正确，版本校验缺失**（静默丢弃而非 NACK）。偏差较轻，记录备查。

证据：`E-cgw-malformed-*.txt`

### 阴性结论（已排除，不必再投入）

- **没有 SecurityAccess 面**：`0x27` 直接 NRC `0x11`，不存在 27 服务的实现，因此不存在 seed/key 绕过、时间延迟绕过、默认密钥等问题。
- **没有刷写面**：`0x34`/`0x36`/`0x2E` 全部 `0x11`，DoIP 侧无法写任何东西。
- **UDP 车辆发现面关闭**：无响应，不存在 UDP 侧的伪造公告攻击面。
- **13401 无面**：非明文 DoIP、非 TLS，立即关闭。怀疑是按 IP 白名单分流或占位监听，但客户端侧探测不到任何可交互内容。

---

## 6. `10.230.164.4` 与 `10.229.221.2` 的同一性

Lead 在整网段扫描中发现 `10.230.164.4` 同样开放 8080/13400/13401。逐项对比：

| 探测 | `10.230.164.4` | `10.229.221.2` | 判定 |
|---|---|---|---|
| `0x0001` → `0x0004` | VIN `CV6FF52FEE9EDDD86`, LA `0x1000`, EID `060000001000`, GID 全零, FA `0x0000` | 同 | **字节级相同** |
| `22 F1 90` | `62 f190 CV6FF5…` | 同 | 相同 |
| `22 F1 A0` | `62 f1a0 07e007e807e107e9` | 同 | 相同 |
| `10 01` | `7f 10 11` | 同 | 相同 |
| 未知类型 `0x9999` | `02fd 0000 00000001 01` | 同 | 相同 |
| `0x0001` 带垃圾 payload | 照常返回 VIN | 同 | 相同 |
| 8080 `/healthz` | `200 {"status":"ok"}` | 同 | 相同 |
| 8080 `/`、`/api`、`/vehicles` | Go 默认 404，头部完全一致 | 同 | 相同 |
| 13401 | 连接被立即关闭 | 同 | 相同 |

**结论：同一台 DoIP 实体，两个 IP 暴露。** 依据是 ISO 13400-2 规定 EID 唯一标识一个 DoIP entity —— 两台主机返回同一个 EID，且所有可观测行为逐字节一致。最可能的实现形态是同一后端服务绑定在两个网络接口上（或经端口转发/代理）。

自动化对比（6 项探测，`identical` 全为 `true`）：`E-cgw-peer-compare-01.txt`
13401 行为对比：`E-cgw-peer-compare-13401.txt`

**因此环境里只有一台车（VIN `CV6FF52FEE9EDDD86`），不存在第二套 DoIP 端点。**

### 6.1 关于间歇性连接超时（供全队参考）

采集期间偶发 `connect()` 超时（首次探测失败、随后同样探测成功）。已排除的原因与已确认的边界：

| 假设 | 实测 | 结论 |
|---|---|---|
| 速率限制 | 40 次无间隔连接 40/40 成功；40 次带 100 ms 间隔也 40/40 成功 | **不是限流** |
| 并发连接数上限 | 同时保持 **60** 条连接全部成功，其中一条收发正常 | 60 并发内无上限 |
| 声明长度不匹配 | 声明 65535 字节不发数据 → 服务端静默阻塞等待（`E-cgw-malformed-08.txt`） | **这是最可能的"假超时"来源** |

实践建议：① 发 `0x0001` 时 `len` 字段必须为 `00000000`；② 若声明长度大于实际发送字节数，服务端不会报错，而是无声挂住直到超时；③ 遇到单次 connect 超时直接重试一次即可（`capture_evidence.py` 已内置 3 次重试）。

---

## 7. 待办 / 未覆盖

| 项 | 说明 | 建议 |
|---|---|---|
| H-006 内存耗尽未验证 | 声明超大 length 是否触发预分配 | 需在可重启的独立环境验证，勿在共享靶场直接打 |
| 13401 真实用途 | 客户端侧探测不到任何交互 | 若能从靶机内部或 T-BOX 侧观察监听配置，可再确认 |
| `0x07E0`/`0x07E1` 是否有隐藏条件 | 当前任何服务都 `0x31` | 可试不同 activation type + OEM 字段组合；但 H-002 已证明 OEM 字段不被校验，预期无解 |
| DoIP 侧 OTA 面 | 已确认 `0x34/0x36/0x2E` 不支持 | **OTA 不在 DoIP 上**，应转向 T-BOX 8443 / 云侧（01 题主线） |
| `0xF1A0` 语义确认 | 推断为诊断地址表 | 已被 `0x07E0` 的差异化 NRC 行为佐证 |

---

## 8. 复现方式

```bash
cd D:/qwb/04_SOLVE/cgw-doip

# 离线自检（不联网，验证解析器）
python doip_client.py --self-test

# 拿 VIN（最快路径）
python doip_client.py identify
python doip_client.py --host 10.230.164.4 identify

# UDS 复核
python doip_client.py uds --src 0x0E00 --target 0x1000 --uds 22F190
python doip_client.py uds --src 0x0FFE --target 0x1000 --uds 22F1A0

# RoutingActivation 全矩阵（验证 H-002）
python doip_client.py routing-activation

# 全量证据重采（会重写 03_EVIDENCE/cgw-doip/）
python capture_evidence.py
```

`doip_client.py` 子命令：`identify` / `udp-identify` / `announce` / `routing-activation` / `uds` / `raw`，全局参数 `--host` / `--port` / `--self-test`。
