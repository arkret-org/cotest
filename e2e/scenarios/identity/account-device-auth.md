# 账户认证与设备授权闭环

首次注册把三种证据按职责串联：账户 handoff 证明账号归属；identity root 承诺 PCR genesis 与首设备；设备私钥证明 possession。PCR accepted receipt 出现之前不得签发 Principal 操作 grant；之后直接写入 Standard SessionGrant issuer ledger。

后续设备走 `accepted_device` 配对，全设备丢失走 PCR-policy re-anchor。SessionGrant 的 refresh/revoke/supersede/introspection 继续遵循 issuer-local durable ledger 与 DPoP 约束，设备授权变化会级联使不再有效的 grant 失活。
