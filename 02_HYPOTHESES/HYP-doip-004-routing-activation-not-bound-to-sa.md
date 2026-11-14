# HYP-doip-004 — routing activation 只是"连上就算"的摆设，SA 不被校验

**提出** 2026-11-14 09:34
**状态** **已证实**（真阳性，ISO 13400-2 偏离）
**证据** `03_EVIDENCE/cgw/doip_no_routing_activation.txt`、`doip_socket_semantics.txt`、
`doip_layer_probe.jsonl`

## 假设
ISO 13400-2 规定：诊断报文里的 SA 必须已在该 socket 上完成 routing activation，否则实体应回
DoIP `0x8003` negative acknowledge（code 0x02 invalid source address）。
本组怀疑目标没做这个绑定。

## 实测

### 1) 未激活前：有闸门，但用错了协议层
```
（不发送 0x0005，直接发 0x8001）
22F190 -> 7F 22 22     22F1A0 -> 7F 22 22
10 01  -> 7F 10 22     3E 00  -> 7F 3E 22
```
返回的不是 DoIP NACK，而是一条 **UDS 负响应 `7F <sid> 22`（NRC 0x22 conditionsNotCorrect）**，
且 `from=0x1000 to=0x0E00`。也就是说"未激活"被当成 ECU 条件不满足，而不是 DoIP 路由错误。

### 2) 激活之后：任意 SA 都放行
```
socket 上先激活 SA=0x0E00  -> code 0x10 routing successfully activated
然后依次用不同 SA 发 22F190：
  SA=0x0E00 -> 62F1904356364646353246454539454444443836
  SA=0x0E80 -> 62F1904356364646353246454539454444443836   ← 未激活的 SA 也通过
  SA=0x0777 -> 62F1904356364646353246454539454444443836   ← 同上
```

### 3) 同一条诊断报文里的 SA 完全由客户端指定，回包也照着抄
```
00 00 10 00 22 F1 90  ->  from=0x1000 to=0x0000  62F190...
10 00 10 00 22 F1 90  ->  from=0x1000 to=0x1000  62F190...   ← 直接冒充网关自身地址
07 E0 10 00 22 F1 90  ->  from=0x1000 to=0x07E0  62F190...   ← 用 CAN ID 当 SA
```
响应里的 TA 就是请求里的 SA。既没有 SA↔socket 绑定，也没有 SA 合法性检查。

### 4) 同一个 SA 可以在多个 socket 上同时"激活"
规范要求第二个 socket 得到 `0x03`（SA already active in a different socket）：
```
socket A activate SA=0x0E00 -> 0x10
socket B activate SA=0x0E00 -> 0x10   ← 应为 0x03
socket B 随后改用 SA=0x0E80  -> 0x10   ← 已激活的 socket 可随意换 SA 再激活
```

### 5) 激活类型也全收
`activation type` = 0x00/0x01/0x02/0x03/0x04/0xE0(OEM)/0xFF(保留) **全部返回 0x10 成功**，
且 OEM 附加数据（`01020304`、`DEADBEEF`）被完全忽略。规范要求不支持的激活类型回 `0x06`。

## 结论
13400 的 DoIP 层是**有连接状态、无身份状态**的：routing activation 只把 socket 置"已激活"这一个
布尔位，之后 SA 由客户端自由声明。这不构成可读取更多数据的漏洞（网关后面只有一个只读 UDS 实现），
但它是一条可写进报告的**协议合规性缺陷**：攻击者可在报文层任意冒充 SA（含网关自身 0x1000），
在车端多实体拓扑里这足以绕过"哪个 tester 能访问哪个 ECU"的访问控制设计。

## 影响边界（不夸大）
本靶场的 13400 后面**没有第二个实体**（见 HYP-doip-005 / TA 矩阵），因此该缺陷当前只体现为
伪造 `source address` 成功，未观察到越权读取。定级应记为**中低危：缺失 SA 绑定校验**，
不要写成"可越权访问任意 ECU"。
