# HYP-doip-005 — DoIP 长度字段/协议版本畸形可打到内存破坏或崩溃

**提出** 2026-11-14 09:37
**状态** 已证伪（在只读、低强度范围内）
**证据** `03_EVIDENCE/cgw/doip_layer_probe.jsonl`（68 条记录）、`doip_socket_semantics.txt`

## 假设
ISO 13400-2 栈的经典 bug 面是通用头里的 `payload length` 与实际字节数不符、`protocol version`
与 `inverse version` 不互补。若实现是裸缓冲区解析，可能越界读或崩溃。

## 实测
| 输入 | 结果 |
|---|---|
| `0x0001` declared=8 actual=0 | 无响应，服务端阻塞等后续字节（3.0s 后放弃） |
| `0x0001` declared=0 actual=8 | 立即回 `0x0004` 识别响应，多余 8 字节留在流里 |
| `0x8001` declared=4 actual=6（合法 SA/TA、UDS 为空） | `0x0000` NACK `0x01`（incorrect pattern format） |
| `0x8001` declared=0xFFFF actual=6 | 无响应，阻塞等 65535 字节 |
| `0x0005` declared=1 actual=7 | 无响应 |
| `0x8001` 实际塞入 60 KB UDS | `7F 22 11`，**socket 之后仍可正常 `22F190`** |
| ver=0x01/0x03/0x04、inv 不互补 | **完全静默**（规范要求回 NACK 0x00 incorrect protocol version） |

## 结论
- 没有观察到崩溃、断连、越界迹象；错误只以"静默丢弃 / 阻塞等长度 / 通用头 NACK"三种方式表现。
- 长度不匹配时服务端**按声明长度阻塞读取**，这是"慢速耗尽"型的资源占用面，不是内存破坏面——
  且需要攻击者持续占连接，价值低，未继续。
- 版本不匹配静默丢弃（而非 NACK 0x00）是**合规性缺陷**，与 HYP-doip-004 一并记入协议偏离清单。

## 未覆盖（诚实边界）
未做高强度模糊测试（会打崩共用靶机，且 13401 由 cgw 组在用）。若后续需要，应限制在
单连接、≤200 例、且与 cgw 组约好时间窗。
