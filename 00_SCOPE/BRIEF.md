# 共享简报（所有 agent 开工前必读）

CTF_ROOT = `D:\qwb`（唯一可写根）。CHALLENGE_DIR = 无（纯远程靶场）。
**写盘纪律**：只写自己分到的子目录；公共事实写回本文件「已确认事实」区（追加，不改别人条目）。

## 网络

- OpenVPN TAP 本机 10.252.3.20，路由 `10.224.0.0/12 -> 10.252.3.1`。
- 本机**非管理员**（`net session` = ADMIN=no），无法 `route add`。
- 可达主机（已普查 10.230.164.0/24、10.229.221.0/24、10.224.139.0/24）：
  - 10.230.164.2:8080      TSP
  - 10.230.164.3:8080/8443 T-BOX
  - 10.230.164.4:8080/13400/13401  中央网关（= 10.229.221.2，同一服务）
- **10.224.139.0/24 整段无响应**（ICMP 与 TCP 全部超时，无 RST ⇒ 该网段未部署或需经网关转发）。

## 已确认事实（勿重复验证）

1. 全部 8080 服务为 Go net/http，`/healthz` → `{"status":"ok"}`（16 字节），其余 404 `404 page not found`。
2. TSP `/graphql`：POST 任意**合法 JSON**（含 `{"query":""}`、语法错误的 query）→ 恒定
   `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}`；
   非法 JSON → `{"error":"invalid GraphQL request"}`；GET/HEAD/PUT → 405。
   ⇒ 它**不解析 GraphQL**，是硬编码桩。字符串 "Guest demo vehicle" 提示「未认证 = demo 数据」。
3. 三台主机的 8080 对 1168 条路径词表（含 sign/ota/firmware/campaign/cert/pki）全部 404，仅 `/healthz`（TSP 另有 `/graphql`）。
4. T-BOX 8443：TLS1.3 only，强制客户端证书。服务端证书 `CN=tbox`、SAN `DNS:tbox`、
   签发者 `CN=CV6 Fleet Diagnostics Root`，P-256/ECDSA-SHA256。无客户端证书 → alert 116；
   自签/伪造 CA 的客户端证书 → `alert 48 unknown ca`。
5. CGW DoIP 13400：车辆识别返回 VIN `CV6FF52FEE9EDDD86`；routing activation (SA 0x0E00) 成功，
   tester 逻辑地址 0x1000；UDS `22F190` → VIN 正常；`10 03` → `7F 10 11`；
   其余服务/逻辑地址（0x0001-0x0010、0x1001-0x1010、0xE000、0xE400 等）一律 NRC 0x11/0x31。
6. CGW 13401：TCP 可连，收到任意字节后**立即关闭且不回包**（0.03s），疑似死端口/诱饵。

## 本轮任务（用户点名，唯一判据）

**07 利用未授权 OTA 签名接口**：把 VCU 参考固件绑定到真实 VIN（`CV6FF52FEE9EDDD86`）、
campaign、`rollback=2`，取得 **ECDSA P-256 / SHA-256** 签名。

⇒ 需要先找到「OTA 签名接口」在哪个服务上，以及「VCU 参考固件」从哪来。

## flag / 产出判据

- flag 正则未定，宽松判据 `[A-Za-z0-9_]{2,20}\{[ -~]{1,120}\}`；拿到第一条立即回填。
- 每条结论必须可追溯到 `03_EVIDENCE/<area>/` 里的原始输出（命令 + 输入 + 输出 + 时间）。

## 目录分工（避免互相覆盖）

| 目录 | 归属 |
|---|---|
| `03_EVIDENCE/tsp/` `04_SOLVE/tsp/` `01_TARGETS/tsp/` | tsp（TSP 10.230.164.2） |
| `03_EVIDENCE/tbox/` `04_SOLVE/tbox/` `01_TARGETS/tbox/` | tbox（T-BOX 10.230.164.3） |
| `03_EVIDENCE/cgw/` `04_SOLVE/cgw/` `01_TARGETS/cgw/` | cgw（10.229.221.2 / 10.230.164.4） |
| `05_TOOLS/` `INDEX.md` `00_SCOPE/` | lead 统一维护（新工具先报 lead） |
