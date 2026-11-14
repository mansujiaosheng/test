# T02 — 本地 Go 复现：8443 的 alert 三元组 = 标准库默认行为

> 目的：把 `TLS_BYPASS_NEGATIVE.md` §4 的**推断**（服务端走 Go 标准 `x509.Verify`）变成**实测**。
> 时间：2026-11-14 09:38–09:41 CST｜本机：Windows 11 / go1.24.2 windows/amd64
> 复现物：`04_SOLVE/tbox/lab/`（lab_server.go + srv.pem/key + root.pem）

## 1. 复现配置（刻意与靶机同形）

```go
TLSConfig: &tls.Config{
    Certificates: []tls.Certificate{cert},          // CN=localhost
    ClientAuth:   tls.RequireAndVerifyClientCert,   // 强制双向
    ClientCAs:    pool,                             // 池里只有一个根
    MinVersion:   tls.VersionTLS13,                 // 只允许 TLS1.3
}
```

`root.pem` 用 `04_SOLVE/tbox/mat/v4_fakeca_sameDN.pem`（subject 逐字 `CN = CV6 Fleet Diagnostics Root`，CA:TRUE，密钥自造）——即"池里放的是真根"的等价物。

## 2. 对照结果

| 客户端证书 | 靶机 10.230.164.3:8443 | 本地 Go 1.24.2（同一配置） | 一致 |
|---|---|---|---|
| 不提供证书 | `TLSV13_ALERT_CERTIFICATE_REQUIRED` (116) | `TLSV13_ALERT_CERTIFICATE_REQUIRED` (116) | ✅ |
| Ed25519 自签（CN=tbox） | `TLSV1_ALERT_UNKNOWN_CA` (48) | `TLSV1_ALERT_UNKNOWN_CA` (48) | ✅ |
| 过期自签（2020 有效期） | `SSLV3_ALERT_CERTIFICATE_EXPIRED` (43) | `SSLV3_ALERT_CERTIFICATE_EXPIRED` (43) | ✅ |
| 由池内根签发的 leaf（对照正例） | —（靶机无此材料） | **HTTP 200 `ok peer=tbox-client`** | 证明池内根签发即可通过 |

原始两半：
- 靶机侧：`0005_mtls_cert_construction_matrix.txt`
- 本地侧：本文件 §2（探针脚本与靶机侧同为 `ssl.PROTOCOL_TLS_CLIENT` + `check_hostname=False` + `CERT_NONE`）

## 3. 结论

1. **alert 三元组 (116 / 48 / 43) 是 Go 标准库默认行为**，不是靶机特有的怪癖。因此靶机不可能是"自写校验 / 比 DN / 比 SKI / 信任客户端链"——那些实现不会在过期证书上先抱怨有效期。
2. 靶机 `ClientCAs` 池 = {真根}，`ClientAuth = RequireAndVerifyClientCert`，且**只要持有池内根签发的 leaf 就能拿到 HTTP 200**（本地正例已证）。
3. 由此 T02 的攻击面收敛为唯一一件事：**拿到真根签发的 client cert + key**。不存在第二种解法（除非能拿到根私钥本身）。

## 4. 复现步骤

```
cd 04_SOLVE/tbox/lab
go build -o lab_server.exe lab_server.go
./lab_server.exe &                     # 监听 127.0.0.1:9443
cd ..  &&  python mtls_lab_probe.py    # 或按 §2 的五行探针
```

> 注：第一次用 `go run` 时端口被残留实例占用过一次（`bind: Only one usage of each socket address`），
> 结束时已用 `Stop-Process` 清掉，`netstat` 确认 9443 无监听。靶机侧未做任何写操作。
