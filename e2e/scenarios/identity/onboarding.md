# 真实账户注册 (Onboarding)

## 目标

验证用户通过 passkey / OIDC / email 完成客户端冷根 onboarding：先生成并确认恢复秘密冷保管，客户端构造并签署 `did:webvh` entry 0，Coauth 只验证绑定并作为 B 模型设备入册权威，随后原子创建 principal control Realm + 首设备授权、关闭 recovery-material gate，再颁发首个 session grant。**完全脱离 dev-login 短路**，覆盖 `account-lifecycle.md §2.1` 的真实流程。

不验证:多设备配对(见 identity/multi-device)、设备撤销(见 identity/multi-device)、账户恢复(见 identity/recovery)、handle 转移(见 identity/handle)。

## Spec 锚点

- `identity/account-lifecycle.md` §2.1 — 服务账户与 Principal 绑定
- `identity/account-lifecycle.md` §2.1.1 — `ak.account.create` 流程
- `identity/identity-did.md` §2 — DID 主体 + root/update authority
- `identity/identity-did.md` §3.4 — `did:webvh` genesis entry
- `identity/key-management.md` §5.0.1 — cold-custody confirmation + entry 0 + closed bootstrap unit + recovery-material gate
- `identity/key-management.md` §5.0.5 — root proof 只允许 self PCR genesis
- `identity/key-management.md` §5.0.6 — A/B 入册权威排他
- `identity/key-management.md` §5.1 — Cross-signing 三对密钥(PSK / SSK / USK)
- `identity/key-management.md` §6 — Session grant
- `crypto-media/device-lifecycle.md` §3 — 注册路径选项
- `crypto-media/device-lifecycle.md` §3.2 — passkey / WebAuthn / OIDC binding

## 拓扑

- 1 × soland (principal server) + 1 × coauth (auth server)
- coauth 必须真的做账户绑定,不能走 dev-login 旁路

## Actors

| 名字 | 注册路径 | DID 形态 | 注释 |
|---|---|---|---|
| alice | passkey/WebAuthn | `did:webvh:<scid>:<host>` | 主路径 |
| bob | OIDC (mock IdP) | `did:webvh:...` | 次路径,验证 OIDC 桥 |
| carol | email-only | `did:webvh:...` | 验证邮件验证流程(若实现) |

## Pre-conditions

- coauth 启动并完成 migration
- WebAuthn (or mock) provider 配置好
- Mock IdP 已注入到 coauth 的 OIDC bridge

## Steps

### Phase A — alice 通过 passkey 注册

1. alice 进 `/onboarding`,选择"Register with passkey"
2. inkson 本地生成 device key + WebAuthn credential，并生成恢复秘密；用户明确确认 24 词/选定冷保管 profile 已安全持有。
3. 客户端通过规范 KDF 派生 root generation 0、预承诺 generation 1、recovery-proof signing key 与 backup-only X25519 HPKE key；任何 secret/seed 不上 wire。
4. 客户端读取 Coauth 暴露的 typed B-model enrollment-authority descriptor，用 SDK canonical builder 构造并由 root 签署 entry 0：root/next-root 只在 `parameters.updateKeys/nextKeyHashes`，DID Document 只含 `id`、principal server 与唯一 `ArkretDeviceEnrollmentAuthority` service。
5. Coauth 校验 client-signed operation 后绑定该 DID，不生成、不持有、不恢复 root；Soland 接受 registry entry 后，客户端原子提交 root-signed `ak.realm.create` + authority-signed `ak.device.authorize`。
6. 首设备覆盖 bootstrap unit 的首个 Seal，发布 active recovery policy（signing/HPKE key 分离），再发布 genesis `did_recovery` backup 或确认 root-signed offline receipt；gate 完成前禁止普通写入/第二设备。
7. Coauth 颁发 device-bound `ak.session.grant`；Inkson 只保存非 secret 的 DID、generation/checkpoint 和会话材料。

### Phase B — alice 验证 onboarding 落地

8. alice 进 `/settings/account` 应看到:
   - DID 形如 `did:webvh:<scid>:...`
   - 当前设备列表只有这一台(显示 `ak:device:...` + cross-signing fingerprint)
   - Principal control Realm ID 已记录(可能不在 UI,但 inkson 客户端状态有)
9. 测试用 alice 的 session credential 调标准 `/_arkret/self/account/viewer`，断言 DID、handle、active generation 与 device 信息一致。

### Phase C — alice 的 DID Document 可被外部解析

10. 测试侧从标准 resolver/document/log surface 取得 DID Document 与 canonical history。
11. 断言:
   - `id` = alice.did
   - root/next-root 不在 DID Document `verificationMethod`；B 模型允许该数组为空
   - DID Document 恰有一个外部 `ArkretDeviceEnrollmentAuthority`，且无 `capabilityDelegation`
   - `service.ArkretPrincipalServer.serviceEndpoint` = soland 的 base URL
12. 验证 history chain：SCID、entry hash、root proof、current active root 与 `nextKeyHashes` 全部由 SDK canonical verifier 通过。

### Phase D — bob 通过 OIDC 注册

11. bob 进 `/onboarding`,选择"Sign in with Google"(mock IdP)
12. inkson 重定向 mock IdP,mock 直接返回 ID token
15. coauth OIDC bridge 接住 ID token，进入同一 client-signed cold-root DID binding 流程
14. 断言 onboarding 完成,bob 拿到 session
15. 断言:bob 的 DID **不同于** alice 的,但 service endpoint 都指向同一个 soland

### Phase E — carol email + 短期 token (3PID 路径)

16. carol 进 `/onboarding`,提交邮箱 `carol@example.com`
17. (mock 邮件服务发出含 verification token 的链接)
18. carol 点链接 → inkson 把 token 提交回 coauth
21. coauth 颁发 binding proof，carol 仍须提交自己 root-signed 的 entry 0 才完成 DID 绑定
20. 断言:onboarding 成功,carol DID 有效

## Observable assertions(合并)

- 三个 actor 的 DID 都形如 `did:webvh:`,SCID 各异
- 每个 DID 都有可解析的 `did.jsonl` history chain
- 三个 actor 的 service endpoint 都指向 soland alpha
- 每个 actor 都有有效 session token,能调 `/_soland/self/account/me`
- 每个 actor 的 principal control Realm 已创建,device 列表只有 1 台
- 三个 actor 都完成 recovery-material gate；B 模型不发布 SSK，设备 key 只存在 device registry

## Edge cases / sub-tests

- **E7.1**:重复用同一 passkey 注册 → coauth 拒绝(`account_already_registered`)
- **E7.2**:OIDC ID token 过期 → 注册失败,UI 显示 token expired
- **E7.3**:email verification 链接已用过 → 拒绝,UI 显示 already consumed
- **E7.4**:WebVH host 不可达(DNS 故障)→ resolver 进入 `degraded_no_witness` 状态(≤24h)([identity-did.md §4.2.1](../../../arkret-spec/spec/v1/zh/identity/identity-did.md))
- **E7.5**:handle conflict (`@alice-s7` 已被占)→ coauth 拒绝 `handle_already_claimed`,客户端要求另选

## Implementation notes

- **Coauth 缺口**：registration start/describe 必须在 entry 0 构造前公开 typed enrollment-authority descriptor；finish 必须校验 `operation.proof`，不得错误要求空的顶层 Event proofs。
- **Inkson/Garth 缺口**：实现 custody confirmation、durable inception draft、原子 PCR bootstrap 与 recovery-material gate；崩溃后从同一 checkpoint 续跑。
- **Cotest 缺口**：上述端到端 strand 在 typed discovery 与客户端 workflow 落地前保持 fixme，不得回退到 Coauth/server mint。
- **coauth 缺口**:OIDC bridge handler 完整度需要审。
- **harness 缺口**:mock IdP service、mock email service — `scripts/run-joint-e2e.ps1` 需要 `-StartMockIdp` / `-StartMockEmail` 开关。

## 总耗时预估

完整跑约 2-3 分钟(3 actors × 注册 + verification 等待 + WebVH publish 延迟)。
