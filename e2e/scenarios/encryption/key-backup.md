# 密钥备份 + 跨设备恢复 + 历史消息解密

## 目标

完整的"丢设备 → 新设备恢复 → 历史 E2EE 消息可解"链路。`cx.key_backup.v1` envelope 用 Argon2id 派生密钥 + XChaCha20-Poly1305 加密;new device 通过 passphrase 恢复 backup;再回放 MLS commit chain 把当前 + 必要的旧 epoch keys 派生回来,解之前在 E2EE space 收到的消息。

identity/recovery(账户恢复)的姊妹篇,但 encryption/key-backup 聚焦在**消息解密** 和 MLS epoch 重建,identity/recovery 更偏 device identity。

## Spec 锚点

- `identity/key-management.md` §7 — Key backup 概览
- `identity/key-management.md` §7.1 — Backup 内容隔离(`backup_class`)
- `identity/key-management.md` §7.2 — Envelope schema(Argon2id KDF + XChaCha20-Poly1305 + key_commitment)
- `identity/key-management.md` §7.3 — Restore flow(passphrase, commitment 校验, 解密)
- `identity/key-management.md` §7.4 — Ownership proof / decryption proof
- `identity/key-management.md` §12 — Backup API(`PUT/GET/DELETE /api/v1/keys/backups`)
- `crypto-media/device-lifecycle.md` §12-§12.1 — Key backup durable form + API
- `crypto-media/encryption-and-audit.md` §2.4 — MLS epoch backfill
- `crypto-media/encryption-and-audit.md` §6 — Offline support, epoch key retention

## 拓扑

- 1 × soland(含 backup storage API)+ 1 × coauth
- 一个 E2EE space `S_e2ee` 包含 alice + bob

## Actors

| 名字 | 设备 | 角色 |
|---|---|---|
| alice | device-A | 主用户;Phase A 备份,Phase D 在 device-B 恢复 |
| alice | device-B | "丢失 device-A 后" 的新设备 |
| bob | 单设备 | 在 `S_e2ee` 中给 alice 发消息(在 device-B 恢复之前) |

## Pre-conditions

- alice 已 onboard,device-A 在 `S_e2ee` 中(epoch N)
- bob 在 `S_e2ee` 中
- alice 的 passphrase 是测试用 `"hunter2-Strong-encryption/key-backup"`

## Steps

### Phase A — alice 在 device-A 设置 passphrase backup

1. alice 进 `/settings/recovery` → "Set up key backup"
2. UI 输入 passphrase 两次,显示强度提示("uses ~60MB memory, ~3 seconds to compute")
3. 客户端:
   - Argon2id(salt=random 16 bytes, memoryCost=64MB, iterations=3)→ `derived_key`
   - XChaCha20-Poly1305 加密 `{ self_signing_key, user_signing_key, mls_history_backup_key }`
   - `key_commitment = SHA256(HKDF(derived_key, info="contrix-key-backup-commitment-v1"))`
4. `PUT /api/v1/keys/backups/<backup_id>` body 含:
   - `backup_class: "secret_storage"`
   - `kdf_params: { algorithm: "argon2id", salt, memory_cost, iterations }`
   - `ciphertext` (base64)
   - `ciphertext_digest: sha256:...`
   - `key_commitment: sha256:...`
5. 断言:`GET /api/v1/keys/backups` 列出该 backup,**metadata only**(no plaintext, no passphrase)
6. UI 显示 "Backup active. Save your passphrase somewhere safe."

### Phase B — bob 在 alice device-A 离线时给 alice 发消息

7. (假设 device-A 关闭、不同步)
8. bob 在 `S_e2ee` 发消息 `M1`,`M2`,使用 epoch N 的 key
9. soland 接受;消息 ciphertext 落到 sync 队列等 alice 拉

### Phase C — Device-A "丢失"

10. (测试 harness 模拟)放弃 device-A 的 browser context
11. (可选)alice 在 device-B 上远程触发 device-A revoke — 但这会导致 MLS Remove + 新 epoch,使 backup 恢复更复杂;为简化 encryption/key-backup,**不** 在恢复之前 revoke;留到 identity/multi-device 测

### Phase D — Device-B 恢复

12. 开新 browser context = device-B,空 storage,进 `/onboarding`
13. 选 "Restore from backup",UI 提示输入 passphrase
14. 客户端:
    - 生成本地 device-B key(用于这台设备的 device authorization,后续)
    - Argon2id 派生(用 backup 提供的 kdf_params)→ derived_key
    - 计算 commitment,与 backup 的 `key_commitment` 比对
    - **commitment mismatch → 客户端在本地拒绝,不向服务器发任何 oracle 查询**(spec §7.2)
    - commitment match → 用 derived_key 解 ciphertext → 拿回 SSK / USK / mls_history_backup_key
15. 客户端签 `cx.device.authorized` (包含 recovery proof,引用 USK 或 control signature)
16. 提交到 soland;recovery policy 校验通过 → device-B 接入
17. 断言:device-B `/settings/devices` 显示 alice 的 device 列表(可能含 device-A,看是否 revoke;此时未 revoke,所以 A 还在)

### Phase E — Device-B 从 MLS commit chain 重建 epoch keys + 解 bob 的消息

18. device-B 拉 `S_e2ee` 的 sync:
    - 自 epoch 0 起回放 `cx.mls.commit` 事件
    - 用 backup 提供的 `mls_history_backup_key` 派生历史 epoch secrets(spec §2.4 backfill)
    - 当前 epoch 应当 = device-A 离线时的 N(因为没有 commit advance)
19. device-B 用 epoch N application key 解 `M1`,`M2`
20. 断言:device-B `/timeline/<S_e2ee>` 显示 `M1`,`M2` 明文
21. UI 显示 "Recovered X messages, Y epochs"

### Phase F — Device-B 可以正常收发新消息

22. alice (device-B) 在 `S_e2ee` 发 `M3`
23. bob 拉同步,看到 `M3` 明文
24. 断言:device-B 的写入路径正常

### Phase G — 备份后被禁用的 MLS epoch(若 device-A 已 revoke)

(可选 sub-test,与 identity/multi-device 联动)
25. 在 Phase C 之后,device-A 在 mid-recovery 时被远程 revoke
26. 触发 MLS Remove,生成 epoch N+1,device-A 失去新 key
27. 但 device-B 已用 backup 恢复了 SSK/USK → device-B 应该被 alice 主动 Add 进 MLS group(via Commit Add)
28. spec §12 line 724:"old message access honors current membership" — device-B 恢复后,过滤 access by current frontier

## Observable assertions(合并)

- Phase A 步骤 5:backup metadata exposed,plaintext 不暴露
- Phase D 步骤 14(错 passphrase):commitment mismatch,客户端本地拒绝(无服务器 oracle)
- Phase D 步骤 17:device-B 加入 alice device set
- Phase E 步骤 20:device-B 看到 `M1`、`M2` 明文
- Phase F 步骤 23:bob 看到 device-B 发的 `M3`

## Edge cases / sub-tests

- **E13.1 错 passphrase**:客户端 commitment 阶段拒绝;**不发** GET 到服务器(避免服务端做 oracle);客户端连续错 N 次触发本地 cooldown
- **E13.2 篡改 ciphertext**:digest 校验失败,客户端拒绝(spec §7.2 line 328)
- **E13.3 backup AAD domain/audience mismatch**:测试改 envelope 的 AAD → 拒绝
- **E13.4 mixed-domain backup**:`mixed_secret_storage=true` 只在 `personal_node` profile 接受;`high_assurance` 部署 MUST 拒(§7.1)
- **E13.5 epoch gap**:bob 在 device-A 离线期间发了 commits + 消息,backup 的 `mls_history_backup_key` 不含某些 epoch → 那些消息标 `decryption_pending`(spec §2.4)
- **E13.6 backup 在 recovery policy 变更后**:alice 在 Phase A 之后改了 recovery policy → device-B 恢复时,reducer 校验新 policy,若新 policy 拒绝 → 恢复失败
- **E13.7 删除 backup**:`DELETE /api/v1/keys/backups/<id>` 应需要 ownership proof(SSK 签名),无法仅凭 session token 删

## Implementation notes

- **soland 缺口**:`cx.schema.key_backup.v1` schema、backup API、recovery policy state、MLS epoch backfill(spec §2.4 + §7.3 step 6)— 大块未实现
- **yougen 缺口**:`/settings/recovery` 设置向导(passphrase 强度 meter、确认、bytes 估算)、`/onboarding` Restore 入口、recovery 进度页(`"Decrypting backup..."`、`"Recovered X / Y messages"`)
- **harness**:Argon2id KDF 计算耗时 ~3s(intentional);测试要给足 timeout

## 风险

- spec §7 整章是 v1 必须项,但 soland 实现度未知。**整个 scenario 大概率 fixme starter**。
- MLS epoch backfill 非常复杂(spec §2.4),若 device-A 缺很多 epochs,backup 必须含 enough state — 实际工程上往往需要 server-side 配合提供 commit log。

## 总耗时预估

约 2-3 分钟(含 Argon2id × 2 + MLS commit replay)。
