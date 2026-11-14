# ROUND 2 共享简报（2026-11-14 09:30 起）

CTF_ROOT = `D:\qwb`（唯一可写根）。CHALLENGE_DIR = 无。
**写盘纪律**：只写自己分到的子目录；公共事实写回本文件「已确认事实」区（追加，不改别人条目）。

## 一、本轮已知事实（承接 ROUND 1，勿重复验证）

### 网络
- OpenVPN TAP 本机 `10.252.3.20`，只推 `10.224.0.0/12 -> 10.252.3.1` 一条路由。
- 本机 **非管理员**（`net session` = ADMIN=no）⇒ `route add` 不可用。
- `tracert 10.229.221.2` → 1 跳（`10.252.3.1`）即达，说明 CGW 直连 VPN 服务器。
- `tracert 10.224.139.7` → 第 1 跳 `10.252.3.1` 之后 **全部超时**。
  ⇒ **10.224.139.0/24 在 VPN 对端没有路由，不是被防火墙挡**。该段只能经 CGW 侧进入。

### 服务面（已证伪的部分）
1. `10.230.164.2/3/4:8080` 全部 Go net/http，只挂 `/healthz`（任意方法 200）。
   `.2` 另有 `/graphql`，为**硬编码桩**（任意合法 JSON → 固定 demo 车）。
   两轮词表 1576 路径 × 3 主机全 404。详见 `04_SOLVE/web/FINDINGS.md`。
2. `10.230.164.3:8443` TLS1.3-only + `RequireAndVerifyClientCert`。
   服务端 leaf `CN=tbox`，issuer `CN=CV6 Fleet Diagnostics Root`（P-256/ECDSA-SHA256）。
   无证书 → alert 116；自签 / 冒名 / 复刻 issuer DN 的伪 CA → 一律 alert 48 `unknown ca`（**真验签**）。
3. `10.229.221.2:13400` DoIP：`VehicleIdentification` 返回 VIN `CV6FF52FEE9EDDD86`；
   tester SA `0x0E00` routing activation 成功；`22 F190` 可读 VIN；
   **`10 01/10 03` → `7F 10 11`（serviceNotSupported）；`3E 00` → NRC 0x31**；
   `0x0001-0x0010 / 0x1001-0x1010 / 0xE000 / 0xE400 / 0x07E0` 全部 NRC 0x11/0x31，
   且**响应源地址恒为 0x1000**（说明只有一个 DoIP 实体在应答，不是真实多 ECU 转发）。
4. `10.229.221.2:13401`：TCP 可连，收到任意字节后**立即关闭且不回包**（0.03 s）。协议未识别。

## 二、赛题目标（用户本轮点名）

| 代号 | 名称 | 目标 | 说明 |
|---|---|---|---|
| C01 | TSP 云服务与 OTA 签名 | `10.230.164.2:8080` | 未授权 OTA 签名接口：把 VCU 固件绑定 VIN `CV6FF52FEE9EDDD86` + campaign + `rollback=2`，取 ECDSA P-256/SHA-256 签名 |
| C02 | T-BOX OTA 与 mTLS 诊断 | `10.230.164.3:8080/8443` | 进 8443 需要真 CA 签发的 client cert |
| C03 | 中央网关 / DoIP / CAN FD 桥 | `10.229.221.2:8080/13400/13401` | **本轮的枢纽**：BT/ECU 只能从这里进 |
| C04 | BCM SecOC 车身控制器 | `10.224.139.5:8080` | 直连不可达 |
| C05 | BMS RV32IM 固件与密钥派生 | `10.224.139.6:8080` | 直连不可达 |
| C06 | VCU 签名刷写 Bootloader | `10.224.139.7:8080` | 直连不可达 |
| **C10** | **赛题 10：双向 ISO-TP 传输加密签名固件包** | VCU | 构造 **1116 字节**更新包（nonce + GCM tag + P-256 签名 + 密文），**按块序号传输并响应 VCU 的 FC / BlockSize / STmin** |

**1116 字节的结构假设（待验证）**：`12 (GCM nonce) + 16 (tag) + 64 (P-256 raw sig r||s) + 1024 (密文) = 1116`。
其它可能：签名用 DER（~70-72 B）、nonce 8/16 B、明文 512/1024 B。**先证伪再采信**。

## 三、分工（避免互相覆盖）

| 角色 | 负责目录 | 交付物 |
|---|---|---|
| **lead** | `INDEX.md` `00_SCOPE/` `05_TOOLS/` + 综合研判 | 全局结论、跨服务链路、写 up |
| **tsp-tbox** | `03_EVIDENCE/tsp/` `04_SOLVE/tsp/` `03_EVIDENCE/tbox/` `04_SOLVE/tbox/` | C01 + C02 |
| **cgw-bridge** | `03_EVIDENCE/cgw*/` `04_SOLVE/cgw*/` | C03，**核心 KPI：找到进 10.224.139.0/24 的路** |
| **isotp-vcu** | `03_EVIDENCE/ecu/` `04_SOLVE/ecu/` | C10 传输层与 1116 字节组包器（可先离线做） |

## 四、判据与纪律

- **flag 正则未定**：宽松判据 `[A-Za-z0-9_]{2,20}\{[ -~]{1,120}\}`；另把「票据 / token / 证书 / 密钥 / 固件包」等可验证产物当候选。
- 每条结论必须可追溯到 `03_EVIDENCE/<area>/` 的原始输出（命令 + 输入 + 输出 + 时间）。
- **证伪优先**：先写判据再跑实验；连续 3 个实验无新信息 ⇒ 报 DEAD 并换路，不要硬耗。
- 不对靶机做破坏性操作（刷写/擦除）；只读优先。
