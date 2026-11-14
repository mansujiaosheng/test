# INDEX（唯一入口）

- **CTF_ROOT**：D:\qwb          **CHALLENGE_DIR**：无（远程靶场）
- 当前主线：**01 已收口**（部分达成）→ 阻塞在 TSP 实例
- 关键事实：
  - 目标车 VIN = `CV6FF52FEE9EDDD86`（DoIP 0x0004 + UDS 22F190 双路径互证）
  - `10.230.164.4` ≡ `10.229.221.2`（同一 DoIP 实体，EID 相同）
  - TSP `10.230.164.2:8080/graphql` = **静态桩**，无输入依赖行为
  - T-BOX `10.230.164.3:8443` = 标准 mTLS 验链，七组旁路全灭
  - `10.224.139.5/6/7` 不可路由
- 交付：[01 报告](06_WRITEUP/01-tsp-ota/REPORT.md) · [假设台账](02_HYPOTHESES/LEDGER.md) · [TSP 判据链](03_EVIDENCE/tsp/E-tsp-stub-01.md)
- 目录：00_SCOPE 情报 / 01_TARGETS 侦察 / 02_HYPOTHESES 假设 / 03_EVIDENCE 证据 / 04_SOLVE 脚本 / 05_TOOLS 工具 / 06_WRITEUP 交付 / 07_LESSONS 坑 / 99_DEAD 死路

## 任务 01 结果（2026-11-14，第二轮靶机）

- 目标车辆：VIN `CV622697F82A936A1`（CGW 10.226.193.2:13400 DoIP 识别）
- 越权点：TSP `POST http://10.225.139.2:8080/graphql`，`vehicleDiagnostics` + `variables.vin` 无归属校验
- 取得：campaign `CAMP-243892C376D4CB2D5F826953`、OTA 包 `/api/v1/ota/engineering-bundle`、诊断入口 `https://10.225.139.3:8443`
- 工程包凭据：Basic `diag:<firmwareCredential>`；包内 mTLS 客户端证书已实测打通 8443（TLS1.3 verify ok）
- 交付：`06_WRITEUP/01-tsp-bola/writeup.md`、`04_SOLVE/task01/solve_task01.py`
