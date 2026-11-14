# CyberCar 车联网靶场 — 团队共享工作区

CTF 目标：从云端一路打到动力域，完成 VCU 固件刷写并读取最终 Flag。
本仓库是**团队协作与代码沉淀**用，不是交付包。

## 目录

| 目录 | 内容 |
|---|---|
| `00_SCOPE/` | 赛事情报、资产四表、约束 |
| `01_TARGETS/` | 目标侦察档案（只读素材） |
| `02_HYPOTHESES/` | 假设台账（证伪优先） |
| `03_EVIDENCE/` | 原始证据（按任务线分目录，只增不改） |
| `04_SOLVE/` | 可重放脚本（按任务线分目录） |
| `05_TOOLS/` | 通用工具（DoIP、端口扫描等） |
| `06_WRITEUP/` | 任务交付 writeup |
| `work/` | 本轮共享事实与中间产物（**敏感材料已 gitignore**） |

## 关键入口

- 共享事实：`work/BRIEF_R2.md`（每轮开工必读）
- 主索引：`INDEX.md`

## 任务线

| 任务 | 负责人 | 卡 |
|---|---|---|
| 01 云侧对象级越权 | lead | 已完成 |
| 02 逆向 T-BOX ARM 固件 | fw-re | `f586e2c0` |
| 03 mTLS 诊断票据 | ticket | 已完成 ✅ |
| 04 DoIP/UDS SecurityAccess | lead | `c30d0556` |
| 05+06 CAN FD SecOC / ISO-TP | canfd | `d84eecfb` |
| 07 未授权 OTA 签名 | ota-sign | `c342b1f9` |

## 安全提醒

`.gitignore` 已排除 VPN 私钥、工程包、客户端证书私钥、凭据与票据。
**如果发现敏感材料进了提交历史，立刻作废该轮靶机凭据并重下工程包**（工程包按请求动态签发，天然可轮换）。

## 已知攻击链（已验证部分）

```
DoIP 识别 (13400) → VIN
  → TSP GraphQL 对象级越权（variables.vin 匹配）
  → campaign / OTA 工程包路径 / 诊断入口 / firmwareCredential / packageKey
  → Basic diag:<cred> 下载工程包
  → AES-256-GCM 解密 T-BOX 固件（key=packageKey, nonce=b64(manifest.nonce)）
  → mTLS(8443) 取诊断票据（40B: nonce‖exp‖tag，绑定 LA 0xE442）
  → DoIP 0xE442 → UDS 0x1220 的 27（待打通）
  → 31 01 开 CAN FD 桥(13401) → BCM/BMS/VCU
```
