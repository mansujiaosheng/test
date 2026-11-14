# T02 阻塞点与需要用户执行的动作（10 分钟可解）

## 现状
T02 的技术面已经全部证伪（见 `T02_mTLS_findings.md`）：8443 是标准 Go mTLS，只认 `CN=CV6 Fleet Diagnostics Root` 签发的客户端证书；8080 只有 `/healthz`。**本机没有任何该 CA 的证书，也没有 OTA ZIP。**

## 唯一可行路径：从赛事平台下载 T02 的题目附件
平台：`https://175.27.210.153:9989/`
赛题：`competition-ed3e7d452581978ccae13421`
本队用户：`usr_b2ad80d021e26b5fb4b02b8619302912`

### 用户动作（约 1 分钟）
1. 在已登录的 Chrome 里打开：
   `https://175.27.210.153:9989/?competitionId=competition-ed3e7d452581978ccae13421#challenges`
2. 在「车辆题目」里找到 **T-BOX OTA 与 mTLS 诊断（10.230.164.3:8080/8443）** 那张卡。
3. 卡上的「题目附件 · N 个（点击下载）」逐个点下载（默认落到 `D:\下载文件`）。
4. 如果是压缩包/证书包，保持原文件名不要改名。
5. 下载完通知 agent 一声即可。

### 为什么必须在平台上点下载
平台前端 `app.js` 的 `disqualificationRuleLabel()` 里有反作弊项：
`attachment_without_download` = 「未下载附件即正确提交」→ **平台会核对账号是否真的下载过附件**。
所以附件必须用本队账号正常下载一次；绕过去拿文件即使做出来也可能被判作弊。

### 拿到文件后 agent 立刻做什么
- `sha256sum` + 解包 + 结构识别（ZIP/OTA 头/AES-GCM/RFC3394）
- 从包里取 client cert/key → 打 8443 mTLS → 枚举 `/`、`/diag`、`/ota`、`/firmware`、`/tbox/*`
- OTA ZIP → AES-256-GCM 解密 → ARMv7-M Thumb-2 反汇编 → SoC 绑定测量 → RFC 3394 解包密钥

## 备选：如果用户愿意给账号
把账号密码给 lead，agent 用 `04_SOLVE/tbox/platform_harvest.py --login <user> <pass>` 正常登录并拉取全部附件（服务端同样记账为"已下载"）。脚本已就绪。

---

## 2026-11-14 10:01 更新：靶场已重开，新地址如下
- TSP：`10.225.139.2:8080`
- **T-BOX：`10.225.139.3:8080 / 8443`** ← T02 目标
- CGW：`10.225.139.4:8080 / 13400 / 13401`（VIN `CV622697F82A936A1`）
- 旧 `10.230.164.x` 已全部下线。

平台重开后，`#challenges` 里题目卡片上的接入地址与附件都会对应新一代；请按上面的步骤下载 **T-BOX OTA 与 mTLS 诊断** 的附件（本代 PKI 重新生成，旧代证书无效）。
