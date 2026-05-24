# MLS 群组加密(E2EE Space 生命周期)

## 目标

验证 `encryption_profile=mls_rfc9420` 的 space 的完整加密生命周期:alice 创建 E2EE space → bob 通过 MLS welcome 加入 → 双向发加密消息(timeline 渲染明文,服务端只见 ciphertext)→ 增减成员触发 epoch advance → governance_binding 校验。

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
- `crypto-media/device-lifecycle.md` §9 — `/api/v1/keys/keypackages/claim` API
- `models/space-and-place.md` §2.2 — Space `encryption_profile` 字段
- `models/space-and-place.md` §3.7.2 — E2EE Space (`encryption_profile=mls_rfc9420`)

## 拓扑

- 1 × soland + 1 × coauth(包含 KeyPackage 存储 endpoint)

## Actors

| 名字 | 角色 | MLS 设备 |
|---|---|---|
| alice | space owner + group creator | 1 个 leaf node |
| bob | 第二个 member | 1 个 leaf node |
| carol | 第三个 member,Phase D 加入,验证 epoch advance | 1 个 leaf node |
| mallory | 非成员,验证非成员不能解密 | (没 leaf) |

## Pre-conditions

- 三人都已注册 + 拿到 session token
- 每人都已上传 KeyPackage 到 `POST /api/v1/keys/keypackages/upload`

## Steps

### Phase A — alice 创建 E2EE space + MLS group genesis

1. alice 进 `/setup`,新建 space,**关键字段**:`encryption_profile = "mls_rfc9420"`(yougen 当前的 setup wizard 没这个选项,见 implementation notes)
2. yougen 后台:
   - 生成 MLS group context、cipher suite(默认 `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`)
   - 写 `cx.mls.genesis` Move(epoch 0、初始 ratchet tree、`governance_binding`)
   - 写 `cx.space.create` Move,关联 genesis
3. 断言:`/space/${spaceId}/admin` 显示"Encryption: MLS RFC9420"标识
4. 断言:`GET /api/v1/spaces/${spaceId}` 返回 `encryption_profile = "mls_rfc9420"`

### Phase B — bob 加入(Welcome)

5. alice 调用 `POST /api/v1/keys/keypackages/claim?actor=bob.did` → 拿到 bob 的 KeyPackage
6. alice 客户端:
   - 计算 `cx.mls.commit`:Add 提案(bob.leaf)
   - 派生新 epoch secrets
   - 为 bob 生成 `cx.mls.welcome`(用 bob KeyPackage 的 InitKey 加密)
   - `governance_binding` 嵌入 `space_policy_hash` + `membership_frontier` + `reducer_profile_digest`
7. alice 提交 commit + welcome 到 soland;welcome 通过 durable Event 路由给 bob(spec §2.2.1)
8. bob yougen 拉 sync → 解 welcome → 派生 epoch 1 secrets
9. 断言:bob `/timeline/${spaceId}` 可访问,timeline 渲染说"Welcome to encrypted space"

### Phase C — 双向加密消息

10. alice 发消息 `M_a`:`payload` 明文 `"alice greet"`,客户端用 epoch 1 的 application key 加密 → AEAD 输出存进 `encrypted_payload`,plaintext metadata 含 `space_id`, `event_kind`, `causal_refs`
11. soland Sync Service:**只**用 plaintext metadata 路由,不解 `encrypted_payload`(关键 invariant)
12. bob 拉 sync → 用 epoch 1 application key 解密 → timeline 渲染 `"alice greet"`
13. 断言:bob timeline 包含 `"alice greet"`
14. 测试 harness 直接 `GET /api/v1/spaces/${spaceId}/events?include_raw=true` → 断言 returned event 的 payload 是 ciphertext,**不含** 明文 `"alice greet"`
15. bob 反向发 `M_b`,alice 同步可见,断言对称

### Phase D — carol 加入触发 epoch advance

16. alice `POST /api/v1/keys/keypackages/claim?actor=carol.did`
17. alice 客户端:`cx.mls.commit` Add carol;epoch 1 → epoch 2;新 application key
18. soland 接受 commit + welcome → carol 拉 welcome → 派生 epoch 2 secrets
19. 断言:carol `/timeline/${spaceId}` 可见;**但** carol 解 Phase C 的 `M_a` / `M_b`?
    - 看 `history_visibility`:joined → carol 看不到加入前的 `M_a/M_b`(spec §3.4 + §2.4.1 `decryption_pending` for pre-join)
20. alice 发新消息 `M_a_post_carol`,用 epoch 2 key
21. 断言:三方 timeline 都有 `M_a_post_carol`
22. 断言:bob 之前用 epoch 1 解密的 `M_a` 仍在 bob 视图(本地缓存的明文)

### Phase E — Membership frontier ≠ MLS epoch → `epoch_update_required`

23. alice 提交 `cx.member.state{ban}` 把 bob 踢出 — 这是 space governance 层动作
24. governance frontier 前进;但 MLS commit 还没跟上
25. alice 客户端在 `max_mls_commit_delay_ms`(默认 30s)内必须发起 MLS Remove + 新 commit
26. 断言:在 alice 提交 Remove commit 之前的 30s 窗内,客户端 send 应进入 `epoch_update_required` 状态(timeline 显示"Waiting for encryption to set up...")
27. alice 完成 MLS Remove → epoch 3 → bob 失去新 epoch key,后续消息 bob 不能解
28. 断言:bob 在 epoch 3 上线时无法解新消息,timeline 显示"decryption_pending"标记

### Phase F — Non-member ciphertext-only

29. mallory(非成员)调 `GET /api/v1/spaces/${spaceId}/events` → soland 应拒(403 / not a member)
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
- **E11.2 Governance binding mismatch**:测试 harness 改 alice 提交的 `governance_binding.space_policy_hash` → soland 拒绝整批,reducer reason `governance_binding_mismatch`
- **E11.3 KeyPackage 不可用**:bob 没上传 KeyPackage → alice claim 失败,`POST /keypackages/claim` 返回 404 / `no_keypackage`
- **E11.4 加入前已发消息 + history_visibility=shared**:把 Phase D 改用 `history_visibility=shared` — carol 加入后应当能解(spec §3.4 shared rule + §6 offline epoch retention)
- **E11.5 Cipher suite negotiation**:不同 cipher suite → alice 创建 space 时指定 suite,bob 的 KeyPackage 不支持 → soland 提示客户端

## Implementation notes

- **soland 缺口**:`cx.mls.genesis/welcome/commit` Move kinds、`governance_binding` 校验、`covered_frontier_cell` 更新、`decryption_pending` projection — 部分实现(core MLS frame 可能有,governance binding 可能滞后)
- **yougen 缺口**:`/setup` wizard 缺 `encryption_profile` 选项;timeline 缺 `decryption_pending` 标记 UI;`/space/:id/admin` 缺 encryption 标识。**这些都阻塞 UI 层验证**,测试需要先通过 API 调用创建 E2EE space
- **测试侧难点**:断言"服务端只见 ciphertext"需要 soland 暴露一个 raw event endpoint;若没有,可以从 service log 抓 + grep

## 风险

- MLS 完整实现复杂度高;`covered_frontier_cell` 是 spec 新概念,soland 应当还在实现中。Phase E (epoch_update_required) 完全是 fixme territory。

## 总耗时预估

约 90s-2 分钟。
