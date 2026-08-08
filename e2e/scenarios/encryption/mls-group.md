# MLS 群组加密(E2EE Realm 生命周期)

## 目标

验证 `encryption_profile=mls_rfc9420` 的 Realm 的完整加密生命周期:alice 创建 E2EE Realm → bob 通过 MLS welcome 加入 → 双向发加密消息(timeline 渲染明文,服务端只见 ciphertext)→ 增减成员触发 epoch advance → governance_binding 校验。

不验证:加密附件(encryption/encrypted-attachments)、密钥备份(encryption/key-backup)、audited E2EE 反审(encryption/audited-e2ee)、跨服务器 MLS 联邦(后续 scenario)。

## Spec 锚点

- `crypto-media/encryption-and-audit.md` §2 — MLS architecture
- `crypto-media/encryption-and-audit.md` §2.2 — Welcome / Commit 握手
- `crypto-media/encryption-and-audit.md` §2.2.1 — Welcome 通过 durable Event 发送
- `crypto-media/encryption-and-audit.md` §2.3-§2.3.3 — Application data envelope + plaintext routing metadata
- `crypto-media/encryption-and-audit.md` §2.4-§2.4.1 — Sync 与 epoch 窗口、`decryption_pending`/`epoch_update_required`
- `crypto-media/encryption-and-audit.md` §2.5-§2.5.3 — Governance Binding(GroupContext extension `0xF1C0`、`covered_frontier_cell`)
- `crypto-media/encryption-and-audit.md` §2.6 — KeyPackage 发布与索取
- `crypto-media/encryption-and-audit.md` §5 — Proposal / Commit / epoch 进展
- `crypto-media/device-lifecycle.md` §9 — `/_arkret/self/keys/keypackages/claim` API
- `models/realm-and-space.md` §2.2 — Realm `encryption_profile` 字段
- `models/realm-and-space.md` §3.7.2 — E2EE Realm (`encryption_profile=mls_rfc9420`)

## 拓扑

- 1 × soland + 1 × coauth(包含 KeyPackage 存储 endpoint)

## Actors

| 名字 | 角色 | MLS 设备 |
|---|---|---|
| alice | Realm owner + group creator | 1 个 leaf node |
| bob | 第二个 member | 1 个 leaf node |
| carol | 第三个 member,Phase D 加入,验证 epoch advance | 1 个 leaf node |
| mallory | 非成员,验证非成员不能解密 | (没 leaf) |

## Pre-conditions

- 三人都已注册 + 拿到 session token
- 参与 Welcome 的设备已上传 KeyPackage 到 `POST /_arkret/self/keys/keypackages/upload`

## Steps

### Phase A — alice 创建 E2EE Realm + MLS group genesis

1. alice 进 `/setup`,新建 Realm,**关键字段**:`encryption_profile = "mls_rfc9420"`
2. inkson 后台:
   - 生成 MLS group context、cipher suite(默认 `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`)
   - 写 `ak.mls.genesis` Move(epoch 0、初始 ratchet tree、`governance_binding`)
   - 写 `ak.realm.create` Move,关联 genesis
3. 断言:`/realms/${realmId}/admin/security` 显示 MLS 管理控件
4. 断言:`GET /_arkret/self/realms/${realmId}` 返回 `encryption_profile = "mls_rfc9420"`

### Phase B — bob 加入(Welcome)

5. alice 调用 `POST /_arkret/self/keys/keypackages/claim?actor=bob.did` → 拿到 bob 的 KeyPackage
6. alice 客户端:
   - 计算 `ak.mls.commit`:Add 提案(bob.leaf)
   - 派生新 epoch secrets
   - 为 bob 生成 `ak.mls.welcome`(用 bob KeyPackage 的 InitKey 加密)
   - `governance_binding` 仅嵌入唯一 `security_frontier_digest`，并固定 scope/group/epoch/profile
7. alice 提交 commit + welcome 到 soland;welcome 通过 durable Event 路由给 bob(spec §2.2.1)
8. bob inkson 拉 sync → 解 welcome → 派生 epoch 1 secrets
9. 断言:bob `/timeline/${realmId}` 可访问,timeline 渲染说"Welcome to encrypted Realm"

### Phase C — 双向加密消息

10. alice 发消息 `M_a`:`payload` 明文 `"alice greet"`,客户端用 epoch 1 的 application key 加密 → AEAD 输出存进 `encrypted_payload`,plaintext metadata 含 `realm_id`, `event_kind`, `causal_refs`
11. soland Sync Service:**只**用 plaintext metadata 路由,不解 `encrypted_payload`(关键 invariant)
12. bob 拉 sync → 用 epoch 1 application key 解密 → timeline 渲染 `"alice greet"`
13. 断言:bob timeline 包含 `"alice greet"`
14. 测试 harness 直接 `GET /_arkret/self/events?realms=${realmId}&include_raw=true` → 断言 returned event 的 payload 是 ciphertext,**不含** 明文 `"alice greet"`
15. bob 反向发 `M_b`,alice 同步可见,断言对称

### Phase D — carol 加入触发 epoch advance

16. alice `POST /_arkret/self/keys/keypackages/claim?actor=carol.did`
17. alice 客户端:`ak.mls.commit` Add carol;epoch 1 → epoch 2;新 application key
18. soland 接受 commit + welcome → carol 拉 welcome → 派生 epoch 2 secrets
19. 断言:carol `/timeline/${realmId}` 可见;**但** carol 解 Phase C 的 `M_a` / `M_b`?
    - 看 `history_visibility`:joined → carol 看不到加入前的 `M_a/M_b`(spec §3.4 + §2.4.1 `decryption_pending` for pre-join)
20. alice 发新消息 `M_a_post_carol`,用 epoch 2 key
21. 断言:三方 timeline 都有 `M_a_post_carol`
22. 断言:bob 之前用 epoch 1 解密的 `M_a` 仍在 bob 视图(本地缓存的明文)

### Phase E — Membership frontier ≠ MLS epoch → `epoch_update_required`

23. alice 提交 `ak.member.state{ban}` 把 bob 踢出 — 这是 Realm governance 层动作
24. governance frontier 前进;但 MLS commit 还没跟上
25. alice 客户端在 `max_mls_commit_delay_ms`(默认 30s)内必须发起 MLS Remove + 新 commit
26. 断言:在 alice 提交 Remove commit 之前的 30s 窗内,客户端 send 应进入 `epoch_update_required` 状态(timeline 显示"Waiting for encryption to set up...")
27. alice 完成 MLS Remove → epoch 3 → bob 失去新 epoch key,后续消息 bob 不能解
28. 断言:bob 在 epoch 3 上线时无法解新消息,timeline 显示"decryption_pending"标记

### Phase F — Non-member ciphertext-only

29. mallory(非成员)调 `GET /_arkret/self/events?realms=${realmId}` → soland 应拒(403 / not a member)
30. 即使 mallory 拿到 raw event(假设泄漏),没有 epoch key → 无法解密

## Observable assertions(合并)

- Phase A 步骤 4:`encryption_profile` 字段持久化
- Phase B 步骤 9:bob 加入成功,welcome 解码
- Phase C 步骤 13:bob 看到 alice 明文
- Phase C 步骤 14:服务端只见 ciphertext
- Phase D 步骤 19:carol 不能看 pre-join messages
- Phase D 步骤 21:carol 看到 post-join 明文
- Phase E 步骤 26:`epoch_update_required` 状态
- Phase E 步骤 28:bob 失去新 epoch 后无法解密
- Phase F 步骤 29:非成员被拒访问

## Edge cases / sub-tests

- **E11.1 并发 commits**:alice 和 bob 同时提交 commit(竞态)→ `covered_frontier_cell` 返回 ⊥,clients 进入 `decryption_pending`,后续 commit 解决(spec §2.5.2)
- **E11.2 Governance binding mismatch**:测试 harness 改 alice 提交的 `governance_binding.realm_policy_digest` → soland 拒绝整批,reducer reason `governance_binding_mismatch`
- **E11.3 KeyPackage 不可用**:bob 没上传 KeyPackage → alice claim 失败,`POST /keypackages/claim` 返回 404 / `no_keypackage`
- **E11.4 加入前已发消息 + history_visibility=shared**:把 Phase D 改用 `history_visibility=shared` — carol 加入后应当能解(spec §3.4 shared rule + §6 offline epoch retention)
- **E11.5 Cipher suite negotiation**:不同 cipher suite → alice 创建 Realm 时指定 suite,bob 的 KeyPackage 不支持 → soland 提示客户端
- **E11.6 Realm encryption_profile create-locked**(active):对已建的 `mls_rfc9420` Realm 发送夹带 `encryption_profile` 的 `ak.realm.policy_bundle` → closed payload schema 以 `schema_violation` 拒绝。`encryption_profile` 只有 genesis carrier，任何可变 facet 都不能把已加密 Realm 静默降级成明文。
- **E11.7 Circle encryption_profile create-locked**(fixme,blocking-on soland#circle-submit-validation-gap):在加密 Realm 下按 floor 建 Circle 后,`ak.circle.update` patch `encryption_profile`。**实测确认 gap**:soland 提交时**接受**(返回 200),因为 `operation_schema_for_kind` 无 circle arm → 提交时操作校验整段被跳过;create-lock 只在异步 reducer 兜底(状态安全但响应误导)。修后转 active:断言 wire code `circle_encryption_profile_create_locked`。
- **E11.8 未就绪不得静默降级**(fixme,blocking-on inkson#mls-not-ready-write-guard):未收 welcome、未恢复账户密钥的同账户新设备尝试写私有内容 → 客户端必须呈现可恢复的"MLS 未就绪"提示并拒绝提交,**绝不**把明文 `ak.strand.update` 发给服务端(也不应触发 `content_encryption_floor_violation`)。需第二设备 rig + 实跑确认未就绪 UX 后从 fixme 升 active。

## Implementation notes

- **当前 live 覆盖**:`encryption_profile=mls_rfc9420` 创建路径、非成员 raw events 拒绝、`ak.mls.genesis`、KeyPackage claim CAS、durable `ak.mls.welcome` pending queue + 一次性 drain、`ak.mls.commit` epoch `0 -> 1`、stale commit `mls_epoch_skew`、加入后的 Bob 解密 Alice post-join timeline 密文且 raw event 不含明文、ban 后 inkson 显示 `epoch_update_required` 并禁用发送。
- **剩余缺口**:双向 E2EE 消息交换、carol pre-join history、并发 commit 的 `decryption_pending`、governance binding mismatch 的精确拒绝路径。
- **测试侧难点**:断言"服务端只见 ciphertext"需要 soland 暴露一个 raw event endpoint;若没有,可以从 service log 抓 + grep

## 风险

- MLS 完整实现复杂度高;当前已覆盖本地 lifecycle 投射和 epoch pause,但真正的客户端加解密、多成员历史窗口和并发 frontier 收敛仍需后续阶段补齐。

## 总耗时预估

约 90s-2 分钟。
