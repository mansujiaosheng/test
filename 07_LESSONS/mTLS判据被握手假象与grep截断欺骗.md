# 坑：mTLS 判据被「握手成功」与「grep 截断」双重欺骗

- 日期：2026-11-14
- 场景：CyberCar T-BOX `10.230.164.3:8443` 强制 mTLS 判定（fleet-recon）
- 代价：差点把「验链失败」误报成「mTLS 已突破」，若当时直接汇报会污染 02 题的整个方向

## 坑 1：TLS 1.3 下「握手成功」是假象

`ssl.SSLSocket.wrap_socket()` 在**没有客户端证书**的情况下**正常返回**，`version()`/`cipher()` 都拿得到值，看起来像进了。原因：TLS 1.3 的服务端证书要求（CertificateRequest）与客户端响应发生在客户端视角的「握手完成」之后，服务端的拒绝是以 **alert 116 `certificate_required`** 的形式在客户端写出**第一段应用数据**时才回来的。

**受害写法**：
```python
tls = ctx.wrap_socket(raw, server_hostname=sni)   # 成功！
return "握手 OK -> 不需要客户端证书"                # 错
```

**正确判据**：
```python
tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # 必须真的写出请求
data = tls.recv(4096)                              # 再读；此处才会收到 alert
```
判据必须落在「**能不能写出请求并读回响应**」上，不能落在 `wrap_socket` 是否抛异常。

## 坑 2：用 `grep -E "alert"` 汇总 openssl 输出会漏掉 alert

同一批实验里我用
```bash
openssl s_client ... 2>&1 | grep -E "alert|Verify return|SSL handshake has read"
```
汇总三组结果。第三组（自签 `CN=tbox`）的输出里**没有出现 alert 行**，因为该 alert 位于输出**最末尾**，且被本地 error 前缀包着：
```
B0060100:error:0A000418:SSL routines:ssl3_read_bytes:tlsv1 alert unknown ca:...SSL alert number 48
```
这行包含 "alert"，本应被匹配——实际是 grep 与 `timeout`/管道缓冲叠加后丢了尾部，导致这一组看起来「没有 alert = 可能过了」。

**规则**：安全判定类实验**永远保存完整原始输出再读**，不要用 grep 的命中与否充当判据。`handshake OK`、`written N bytes`、甚至「没看到 alert」都不等于通过。
本仓库对应的正确产物：`03_EVIDENCE/fleet/tbox_8443_extra_tests_full.txt`（三组完整输出，含 3 条 alert）。那份被删掉的 grep 摘要版就是反面教材。

## 坑 3（同场景附带）：同名 CA 撞库无效，但值得先试

自制 `CN=CV6 Fleet Diagnostics Root` 且把 SKI 照抄成与真根一致的 `47:6E:90:…:99`，再拿它签客户端证书 —— 一度以为能过，实际 `alert 48 unknown ca`。
结论：**标准 `ClientCAs` 验链是签名校验**，不比对 subject name，也不比对 SKI。SKI 只在客户端「选哪张证书去响应 CertificateRequest」时有用，服务端不拿它做信任判断。
价值不在于它能过，而在于**它能一次性判定「实现是标准验链还是自定义白名单」**——成本 5 分钟，收益是把推断变硬结论。

## 通用教训

1. 判据要落在「**动作是否真的产生效果**」，不要落在「上一步没报错」。
2. 攻击面判定（mTLS / 鉴权 / 授权）的实验，一律保留完整原始输出，禁止用 grep 命中当结论。
3. 遇到「看起来过了」的瞬间，先把完整输出读一遍再说 —— 假阳性比假阴性贵得多。
