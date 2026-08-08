# 真实账户首次注册

## 目标

验证一次账户登录与一次 Recovery Key 确认即可完成唯一创建链：客户端在任何网络副作用前持久化 root、设备签名、设备 HPKE、DPoP 与完整 PCR genesis draft；Coauth 发布 DID 后透明转发客户端签名的两条 Event；Soland 原子接受 PCR genesis；Coauth 收到可验证 receipt 后直接签发 Standard SessionGrant。

## 顺序

1. 用户完成账户注册/登录和 OIDC handoff，Coauth 分配带 fence 的 identity-creation lease。
2. 客户端生成并持久化 24 词、identity root、首设备签名/HPKE key、DPoP key 与 initial-session request。
3. 客户端构造 `ak.device.authorize` payload，设备私钥签 possession proof。
4. root 在 `ak.realm.create.founding_device_descriptor` 中承诺该 payload digest，再签 create Event。
5. 客户端把 authorize 的 `prev_refs` 固定为 create Event ID，并用设备 key 签 Event proof。
6. root 签 `identity_creation_control_proof`，覆盖 DID operation、lease fence、PCR payload digests、ordered unit 和 initial-session digest。
7. 一次 `account_register` 提交完整 draft。Coauth 不生成、不修改、不签 PCR Event。
8. Soland 只在两条 Event、root commitment、设备 PoP、lease 与 DID entry 0 全部匹配时原子接受，并返回 `pcr_genesis_unit` receipt。
9. Coauth 验 receipt 后绑定账号并直接返回 durable Standard SessionGrant；不存在临时 grant 或 promotion。
10. 客户端完成首个 Seal、recovery policy 与 `did_recovery` backup 后进入 Ready。

## 必测恢复

- 请求/响应丢失、刷新或崩溃：逐字节重放同一 draft，返回同一 receipt 和 grant。
- DID 已发布但 PCR 未接受、原设备丢失：新设备凭 Recovery Key 取得递增 fence，重建 draft 后继续。
- 旧 genesis 已先接受：不得创建第二个 PCR，改走 root-anchored re-anchor。
- 任一 root/device/DPoP/lease/digest/device/HPKE/algorithm/order mutation：拒绝且零写入。

## DID 边界

DID Document 只含 identity-root key log 与预轮换承诺；设备目录、账户状态、SessionGrant 与业务授权均不进入 DID。
