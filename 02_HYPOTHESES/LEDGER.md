# 假设台账

| ID | 一句话机制 | 判据 | 状态 | 证据 |
|---|---|---|---|---|
| HYP-tsp-01 | TSP /graphql 是真实 GraphQL，只是 guest 身份只能看到 demo 车 | 用真 VIN 查 `vehicle(vin:)` 会返回真车数据 | **DEAD** | 任意 query 均返回同一常量；选择集不被尊重 |
| HYP-tsp-02 | TSP 依赖 operationName 分流到 OTA/campaign resolver | 换 operationName 会改变响应 | **DEAD** | 30 个 operationName 全部同一响应 |
| HYP-tsp-03 | TSP 从 variables 取 vin/vehicleId 做对象查询 | variables 换 key/换值会改变响应 | **DEAD** | 270 个 key × 真 VIN 全部同一响应 |
| HYP-tsp-04 | TSP 按 vhost / UA / X-Client-Id 分流（车端客户端才给真数据） | 换 Host/UA/Client-Id 会改变响应 | **DEAD** | 23 vhost + 12 UA + 8 Client-Id 全同一响应 |
| HYP-tsp-05 | TSP 还有未发现的路由（OTA/签名/诊断） | 大字典能扫出非 404 路由 | **DEAD** | 3500 条路径仅命中 /graphql、/healthz |
| HYP-tsp-06 | TSP handler 结构体可用类型错配探测 | 已知字段类型错 → 400 | **CONFIRMED** | 仅 `query`(string)、`variables`(map[string]interface{}) 两个字段 |
| HYP-cgw-01 | DoIP RoutingActivation 无认证 | 任意 src/activation type 都返回 0x10 | **CONFIRMED** | cgw-doip: 15 组组合全成功 |
| HYP-cgw-02 | DoIP 车辆识别返回真车 VIN | 0x0001 → 0x0004 含 17 字节 VIN | **CONFIRMED** | VIN=CV6FF52FEE9EDDD86，0x22F190 复核一致 |
| HYP-cgw-03 | 0xF1A0 泄露内部 ECU 地址表 | 读 DID F1A0 返回地址对 | **CONFIRMED** | 07E0/07E8/07E1/07E9 |
| HYP-cgw-04 | DoIP 按声明长度预分配内存 → DoS | 超大 len 触发 OOM | **未验证** | 未测（避免打挂共享环境） |
| HYP-tbox-01 | 8443 mTLS 强制客户端证书，验链为标准 X.509 | 无证书 → alert 116；伪造 CA → alert 48 | **CONFIRMED** | fleet-recon: tbox_8443_mtls_probe.txt |
| HYP-tbox-02 | 自签 CN=tbox 可绕过（自定义校验） | 自签 CN=tbox 能进 8443 | **PROBING** | 已派给 fleet-recon |
| HYP-tbox-03 | VPN 客户端证书被 T-BOX 信任（靶场配错） | VPN cert 能进 8443 | **PROBING** | 已派给 fleet-recon |
