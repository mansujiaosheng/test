<!-- DSH-FORMAT: md-v1 -->
<!-- DSH-TITLE: 赛题08：BMS root key → HKDF → VCU 二级 SecurityAccess 解锁 -->
<!-- DSH-STATUS: ready-for-agent -->
<!-- DSH-LABELS: ready-for-agent -->
<!-- DSH-IDEMPOTENCY-KEY: deck-f89188ca-5982066 -->
<!-- DSH-CREATED: 2026-11-14T01:32:59.467Z -->

## 目的

复现赛题 08 的完整密钥链，并在 VCU 上解锁编程会话：

1. 从 BMS 固件（RV32IM）恢复 root key；
2. `HKDF-SHA256(ikm=root_key, salt=SHA256(完整镜像), info=VIN, L=32)` 派生；
3. 用派生密钥算二级 SecurityAccess HMAC，对 VCU 发 `27 02 + key`，期望 `67 02`；
4. 解锁后确认编程会话（`10 02`）可用。

## 当前阻塞

- `10.224.139.6`（BMS）与 `10.224.139.7`（VCU）在 IP 层完全不可达（ICMP 无、TCP 8080 无、`10.224.139.0/24` 全灭）。VPN 路由 `10.224.0.0/12` 存在。
- 因此**固件样本与在线验证通道都缺失**，链路的第 1 步和第 3 步都无法执行。

## 验收标准

- 强：拿到 `67 02`，并记录编程会话切换成功的原始 DoIP/UDS 交互。
- 弱（在线不可达时的可接受交付）：`derive_key.py --self-test` 通过 + 对每个候选公式给出判据 + 说明为何在当前可达面内不可完成，附互斥观测证据。

## 不在本规格

- TSP/T-BOX Web 面找 OTA 包（属 `web-ota` 队友）
- CGW DoIP 逻辑地址/内存读（属 `cgw-doip` 队友）

## 证据位置

`03_EVIDENCE/{vcu,bms}/`、`04_SOLVE/{vcu,bms}/`、看板卡 `c827cba4`（根）与其子卡。

## 进度
