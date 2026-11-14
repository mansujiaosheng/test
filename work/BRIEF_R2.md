# 第二轮共享事实（02-13 链）— 所有 agent 开工前必读

工作根 D:\\qwb。只写自己分到的子目录。公共事实追加到本文件末尾「追加区」。

## 靶机地址（2026-11-14 04:0x 实测存活）
- TSP        10.225.139.2:8080   /graphql, /api/v1/objectives/final
- T-BOX      10.225.139.3:8080   (OTA bundle, Basic auth)  10.225.139.3:8443 (mTLS)
- CGW        10.226.193.2:8080/13400/13401   别名 10.225.139.4
- BCM/BMS/VCU 10.226.197.5/6/7:8080  ← IP 层不可达（路由器无路由），必须经开桥后的 13401
- VIN = CV622697F82A936A1   GW LA = 0x1000   EID = 060000001000

## 第一题已打通（复用这些，不要重做）
1) TSP 的 /graphql 不是真引擎，是「字段名 + variables」匹配器。
   `{"query":"query { vehicleDiagnostics { vin } }","variables":{"vin":"<已登记VIN>"}}` → 返回该车诊断对象。
   query 里的 (vin:...) 是幌子；匹配键是 variables.vin。
2) 返回：campaignId=CAMP-243892C376D4CB2D5F826953, firmwareDownload=/api/v1/ota/engineering-bundle,
   diagnosticEndpoint=https://tbox:8443, tboxEndpoint=http://tbox:8080,
   firmwareCredential=5e7f07b4a81153ecd5868cc02557f823, packageKey=3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0
3) 工程包下载：GET http://10.225.139.3:8080/api/v1/ota/engineering-bundle  Basic  diag:<firmwareCredential>
   包按请求动态生成（nonce 与客户端证书每次都不同），**每次要新材料必须重下**。
4) 包内容：manifest.json / vcu-reference.bin(1024B, magic CV6VCU1) / tbox-firmware.img(16412B)
   / diagnostics/{ca,client,client-key}.pem  (CN=CV6 Engineering Diagnostic Client, issuer CN=CV6 Fleet Diagnostics Root)

## 已破解：T-BOX 固件解密（任务 02 第一半，已完成，勿重做）
格式 CV6-OTA-1：tbox-firmware.img = nonce(12) || ciphertext(16384) || tag(16)，共 16412 B
  nonce = base64decode(manifest.nonce)
  key   = bytes.fromhex(packageKey)        # 32 字节 AES-256
  AESGCM(key).decrypt(nonce, img[12:16384+12] + img[-16:], None) → 16384 B 明文
校验：sha256(明文) == manifest.tboxSha256 == 88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229  ✅ 已匹配
明文已落盘：work/bundle2/tbox-firmware.dec.bin（16384 B）
已有线索：明文 offset 0xaa0 处有字符串 "CV6-TBOX-KEK"（虚拟地址 0x08000aa0）；向量表 SP=0x20010000 Reset=0x08000755

## manifest.json（本轮）
{"cipher":"AES-256-GCM","format":"CV6-OTA-1","nonce":"<每次不同>","tboxAddress":"0x08000000",
 "tboxArchitecture":"ARMv7-M Thumb-2 raw","tboxSha256":"88b09d09…","tboxSize":16384,
 "vcuReferenceSize":1024,"vcuRollback":2,"vcuUpdateAddress":"0x08040000"}

## 车端事实（cgw-doip 上一轮已确认，可直接用）
- DoIP 13400：ident 0x0001→0x0004；RA(SA=0x0E00, type=0x00)→ code 0x10 成功
- LA 0x1000 上只有 22F190(VIN) / 22F1A0(07E0 07E8 07E1 07E9)，其余 7F..11/31
- **功能地址 0xE442 → 被转发到 UDS 节点 0x1220**（全 65536 个 LA 里唯一异源）
- 0x1220：`10 03`→`50 03`（唯一可用会话）；`22 F1A3`→`7F2233`（DID 存在但受保护）；
  `27 xx`→`7F277E`（此时缺票据/凭据）；`31 xx`→`7F3133`；`2E` 写表为空
- 13401：开桥前 accept-then-close（+25.6ms FIN，13 种载荷 0 回包）。开桥后才会工作。

## 终点闸门
GET http://10.225.139.2:8080/api/v1/objectives/final → 现在 409 {"error":"VCU has not committed an authorized update"}
必须真的完成 05→12 的 VCU 提交更新，才会给 flag。

## 目录分工（严禁越界写）
| 范围 | 目录 |
|---|---|
| 02 固件逆向 | 03_EVIDENCE/fw/ 04_SOLVE/fw/ |
| 03 mTLS 票据 | 03_EVIDENCE/ticket/ 04_SOLVE/ticket/ |
| 04 DoIP SecurityAccess | 03_EVIDENCE/uds/ 04_SOLVE/uds/ |
| 05+06 CAN FD / SecOC / ISO-TP | 03_EVIDENCE/canfd/ 04_SOLVE/canfd/ |
| 07 OTA 签名 | 03_EVIDENCE/sign/ 04_SOLVE/sign/ |
