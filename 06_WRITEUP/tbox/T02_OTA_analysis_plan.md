# T02 OTA ZIP 到手后的分析路线（预先写好的执行清单）

> 目标原文：`02 解包 OTA 并逆向 T-BOX ARM 固件 — 取得 OTA ZIP，完成 AES-256-GCM 解密，分析 ARMv7-M Thumb-2 代码、SoC 绑定测量和 RFC 3394 包装密钥。`
> 工具已备：`04_SOLVE/tbox/ota_toolkit.py`（inspect / gcm / unwrap / thumb）。

## 0. 落盘与指纹
```
mkdir -p 01_TARGETS/tbox/ota
cp <下载的 zip> 01_TARGETS/tbox/ota/
sha256sum 01_TARGETS/tbox/ota/*
unzip -l 01_TARGETS/tbox/ota/<zip>
```

## 1. ZIP 结构识别
- 看 `ota.json` / `manifest.json` / `metadata.json`：version、target SoC、image list、hash、signature。
- 若 ZIP 本身加密：ZIP 的 AES-256（WinZip AE-2）或条目为 `.enc`。
- 若条目是自定义容器：`python 04_SOLVE/tbox/ota_toolkit.py inspect <file>` 找 magic / 熵 / ARM 向量表（`0x2000xxxx` SP + `0x08xxxxxx` Reset）。

## 2. AES-256-GCM 解密
- 需要：key(32B)、nonce/IV(12B)、AAD、tag(16B)。
- key 的来源通常是：
  a) manifest 里的 RFC 3394 包装密钥（`4.` 解出来的 DEK）；
  b) 由 SoC 绑定测量派生（`3.`）；
  c) 固件里硬编码的 KEK。
- 离线试解：
```
python 04_SOLVE/tbox/ota_toolkit.py gcm <ct.bin> --key <hex32> --nonce <hex12> [--aad <hex>] [--tag <hex>]
```
- 校验：明文首 4 字节通常是 `0x2000xxxx`（MSP）——Thumb-2 向量表。

## 3. SoC 绑定测量
- 常见形式：`HMAC(device_secret, fw_digest)` 或 `SHA256(uid || fw_digest)`，比对 manifest 中的 measurement。
- 在固件里搜 `0xE000ED00`（SCB）、UID 地址（如 nRF52 `0x10000060`、STM32 `0x1FFF7A10`）、`CMAC`/`HMAC` 常量。

## 4. RFC 3394 包装密钥
```
python 04_SOLVE/tbox/ota_toolkit.py unwrap <wrapped_hex> --kek <hex>
```
- 包装数据长度必须为 8 的倍数且 ≥24；解出 16/24/32B DEK。
- KEK 来源：manifest、固件常量、或 SoC 测量派生链。

## 5. ARMv7-M Thumb-2 分析
```
python 04_SOLVE/tbox/ota_toolkit.py thumb <fw.bin> --base 0x08000000 --offset 0 --count 400
```
- 关注：字符串表（flag 常见于校验失败/成功分支）、`0xE000ED00` SCB、`__disable_irq`、CRC 表、AES 常量 S-box（`63 7C 77 7B`）。
- flag 判据：`grep -aoE '[A-Za-z0-9_]{2,20}\{[ -~]{1,120}\}'` 全产物扫一遍。

## 6. 若 ZIP 内含 client cert/key（T-BOX mTLS 材料）
```
python 04_SOLVE/web/tools/tls_client.py 10.230.164.3 8443 --cert client.pem --key client.key \
  --path / --path /healthz --path /diag --path /diagnostics --path /ota --path /firmware --path /update
```
- 有 `ca.pem` 时加 `--ca ca.pem` 做严格校验。
- 先 GET，再对 `openapi.json`/`docs` 等试探测；一旦有 200 立刻全量落盘。
