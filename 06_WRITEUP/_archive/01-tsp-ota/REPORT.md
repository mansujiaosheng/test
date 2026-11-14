# 01 云侧对象级越权与 OTA 定位 — 阶段报告

**状态：部分达成**。车辆识别已完成并双路径取证；TSP 侧对象级越权**在当前部署下不可达**（端点被证实为静态桩）。
T-BOX 侧 mTLS 为硬门；BCM/BMS/VCU 三台不可路由。

---

## 一、目标车辆识别（已完成，双路径互证）

| 项 | 值 |
|---|---|
| **VIN** | **CV6FF52FEE9EDDD86** |
| LogicalAddress | 0x1000 |
| EID | 06:00:00:00:10:00 |
| GID | 00:00:00:00:00:00 |
| FurtherAction | 0x0000 |

**路径 A（DoIP 车辆识别）**：`10.229.221.2:13400` 发 `02fd 0001 00000000`
→ RX `02fd 0004 00000021` + VIN + LA + EID + GID + FA

**路径 B（UDS 读 DID）**：RoutingActivation 后 `22 F1 90` → `62 F1 90 <17 字节 VIN>`

**同源性判定**：`10.230.164.4:13400` 与 `10.229.221.2:13400` 六项探测逐字节相同且 EID 相同，
按 ISO 13400-2「EID 唯一标识 DoIP 实体」，是**同一实体被两个 IP 暴露**。

证据：`03_EVIDENCE/cgw-doip/`（27 份 dump），工具 `04_SOLVE/cgw-doip/doip_client.py`。

---

## 二、TSP 对象级越权：当前部署下不可达（关键结论）

目标：`http://10.230.164.2:8080/graphql`（POST）。

### 2.1 端点能力边界
```
POST /graphql  → 200 {"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}
GET  /graphql  → 405 {"error":"method not allowed"}
非法 JSON      → 400 {"error":"invalid GraphQL request"}
GET  /healthz  → 200 {"status":"ok"}
其余 3500 条路径 → Go 默认 404
```

### 2.2 判定它是"静态桩"的三条硬证据
1. **选择集不被尊重**：`{ vehicles { ONLY_VIN } }` 仍返回 `label`+`vin`。真实 GraphQL 会报未知字段错。
2. **语法错误照样 200**：`{`、`}{`、`{ vehicles { vin` 全部返回同一常量。无解析。
3. **类型 oracle 反推 handler**：`query` 是 string（传数字→400，null→200）；`variables` 是
   `map[string]interface{}`（传数字/字符串/数组→400，传对象→200，对象内值任意类型→200）。
   即 `struct{ Query string; Variables map[string]interface{} }`，解码后**不看内容**直接回常量。

### 2.3 已穷举、全部阴性
3500 条路径 × (GET/POST) · 270 个 variables key × 真 VIN · 30 个 operationName ·
23 个 vhost · 12 个 UA · 8 个 X-Client-Id · 7 个 IP 伪造头 × 4 个源 IP ·
路径混淆（`/./`、`/x/../`、`%67raphql`）· h2c prior-knowledge · multipart ·
`application/graphql` · persisted query · `X-HTTP-Method-Override`。

### 2.4 唯一异常点（未利用）
`/internal/audit` 在**四台主机上一致**返回 `404 application/json {"error":"not found"}`，
而同前缀的 `/internal`、`/internal/x`、`/internal/audit/` 均为 Go 文本 404。
⇒ 存在一个精确匹配 `/internal/audit` 的独立 handler，且对未授权请求返回 JSON 404（隐蔽式拒绝）。
试过 22 个查询参数名 + 12 个身份头，均无非 404 响应。**未取得突破**，保留为后续入口。

### 2.5 结论与旁证
该端点不承载任何对象级授权逻辑，**无法用于取得 OTA 工程资源 / campaign / 诊断入口**。
旁证：用户浏览器历史中平台页面反复出现「题目实例未找到」（16 次）「题目实例暂时不可用」（5 次），
与"车辆题目实例未按预期起起来"一致。**需向出题方确认 TSP 实例是否正常下发**。

---

## 三、T-BOX mTLS（10.230.164.3:8443）：硬门，网络侧无旁路

七组对照全部证伪：

| 尝试 | 结果 |
|---|---|
| 不带客户端证书 | `alert 116 certificate_required` |
| 自签 CN=recon-probe | `alert 48 unknown ca` |
| 伪造同名 CA（CN=CV6 Fleet Diagnostics Root，SKI 照抄） | `alert 48` |
| 自签 CN=tbox（SAN/EKU 全对） | `alert 48` |
| VPN 客户端证书（EKU=clientAuth，真 CA 签发） | `alert 48` |
| 服务端 tbox 证书当客户端证书 | 无法实施（只有公钥无私钥） |
| TLS 1.2 不带证书 | `alert 70 protocol version`（早于证书交换） |

⇒ 验链是**标准 X.509 签名校验**，信任池只有一张 `CN=CV6 Fleet Diagnostics Root`，
无名字匹配、无 CA 串门、无版本降级。**唯一可行路径是从 OTA 包/固件内取得 clientAuth 合法证书**。

补充事实：`CN=tbox` 的 EKU **只有 serverAuth**，即便日后拿到 tbox 私钥也会因 incompatible key usage 被拒。

---

## 四、其余目标

| 目标 | 状态 |
|---|---|
| BCM 10.224.139.5 / BMS 10.224.139.6 / VCU 10.224.139.7 | **不可路由**（tracert 第 2 跳起全丢；同 /12 内 .229/.230 一跳直达，排除本机路由问题） |
| CGW 13401（两台） | 三次握手后立即关闭，非 DoIP 非 TLS，无攻击面 |

## 五、DoIP 侧已确认漏洞（4 条）

- **H-002 高**：RoutingActivation 零认证零源地址校验，45/45 组合全 `0x10`，含冒充网关自身 `0x1000`
- **H-005 中**：DID `0xF1A0` 泄露内部 ECU 诊断地址表 `07E0/07E8/07E1/07E9`
- **H-003 中**：`0x0001` 不校验 payload 长度，8/64 字节垃圾照样吐 VIN
- **H-006 中**：声明长度 > 实际数据时无限期阻塞占 socket（内存耗尽面未测，避免打挂共享环境）

## 六、待办 / 需要人决定

1. **TSP 实例是否正常**：这是 01 题的唯一阻塞点，需要向平台侧确认。
2. `/internal/audit` 的 handler 身份未知，值得在拿到实例正常后重测。
3. 02 题（OTA 包）需要先有包来源 —— 而包来源本应来自 01 的 TSP 结果，形成依赖闭环。
