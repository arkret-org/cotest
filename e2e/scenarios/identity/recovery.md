# 账户恢复 (Recovery)

## 目标

验证用户在丢失主设备后,通过预设的恢复手段(passphrase / 阈值恢复 shares / 信任恢复服务)在新设备上完整恢复访问。包含:恢复前的备份设置、跨设备使用 backup envelope 解密、新设备的 `ck.device.authorize` 写入、E2EE 历史消息解密。

不验证:首次 onboarding(见 identity/onboarding)、多设备配对(见 identity/multi-device)、device 撤销(见 identity/multi-device)。

## Spec 锚点

- `identity/key-management.md` §3.3 — Recovery key + threshold scheme + trusted recovery service
- `identity/key-management.md` §7 — Key backup 概览,`backup_class` domain
- `identity/key-management.md` §7.1 — 各 backup_class 的内容隔离
- `identity/key-management.md` §7.2 — Backup envelope schema(Argon2id KDF + XChaCha20-Poly1305 + key_commitment)
- `identity/key-management.md` §7.3 — Restore flow
- `identity/key-management.md` §7.4 — Ownership proof vs decryption proof
- `identity/key-management.md` §8 — Threshold recovery service
- `identity/key-management.md` §12 — Backup API (PUT/GET/DELETE)
- `crypto-media/device-lifecycle.md` §12 — Key backup durable form

## 拓扑

- 1 × soland + 1 × coauth + 1 × backup storage service(可能就在 soland 里;或独立)
- 若用 threshold recovery:外加 N 个 share-holder

## Actors

| 名字 | 角色 |
|---|---|
| alice | 主用户;Phase A 设置备份,Phase C 在新设备恢复 |
| alice-device-1 | 主设备 |
| alice-device-2 | "丢失"后的新设备(实际是另一个 browser context) |
| (E2EE 子测试)bob | 与 alice 在同一 E2EE space,恢复后 alice 解 bob 发的旧消息 |

## Steps

### Phase A — 设置 passphrase-protected backup

1. alice (device-1) 进 `/settings/recovery`
2. UI 引导 alice 输入 passphrase(强度提示),确认
3. 客户端:
   - Argon2id KDF 生成 derived_key(salt + memoryCost + iterations,固化在 envelope)
   - 用 XChaCha20-Poly1305 加密 `{ self_signing_key, user_signing_key, MLS history backup key }`
   - 计算 `key_commitment = SHA256(HKDF(derived_key, info="cokret-key-backup-commitment-v1"))`
4. `PUT /_cokret/self/keys/backups/<backup_id>` 上传 envelope:`{ backup_class: "secret_storage", kdf_params, ciphertext, ciphertext_digest, key_commitment }`
5. 服务端**只能存** ciphertext,不接受明文 passphrase
6. 断言:`GET /_cokret/self/keys/backups` 列出该 backup,metadata 含 kdf_params,**不含** plaintext

### Phase B — (可选)alice 在 E2EE space 中收发消息

7. alice 与 bob 在 space `S_e2ee` (`encryption_profile=mls_rfc9420`) 中交换若干消息
8. 关键:其中至少 1 条消息使用 backup 之前的 MLS epoch key

### Phase C — Device 1 "丢失",alice 在 Device 2 恢复

9. 开新 browser context = device-2,空 localStorage
10. alice 进 `/onboarding`,选"Restore from backup"
11. UI 提示输入 passphrase
12. 客户端:
    - 生成新 device key(本地)
    - Argon2id 派生 → 计算 key_commitment → 拉 backup envelope → 比对 commitment(快速失败如果 passphrase 错)
    - 解 ciphertext → 拿回 self_signing_key + user_signing_key + MLS backup key
13. 客户端签 `ck.device.authorize` (包含 recovery proof,引用 recovery key 或 control signature)
14. 提交到 soland;soland 校验 recovery policy → 接受
15. 断言:device-2 上 `GET /_soland/self/account/me` 返回 alice.did,设备列表新增 device-2

### Phase D — alice 在 device-2 上 sync E2EE history

16. device-2 拉 `S_e2ee` 的 MLS state(commit chain 回放)
17. 用 backup 提供的 MLS history backup key 解 epoch 历史
18. 断言:Phase B 时 bob 发的消息现在在 device-2 timeline 可见、明文渲染

## Observable assertions(合并)

- Phase A 步骤 6:backup metadata 暴露 ✓,plaintext 不暴露 ✓
- Phase C 步骤 12:passphrase 错误 → 客户端在 commitment 阶段就拒,**不发请求到服务器**(避免 oracle)
- Phase C 步骤 15:device-2 成功注册,alice 的 device 列表有 2 台
- Phase D 步骤 18:历史消息明文渲染

## Edge cases / sub-tests

- **E8.1 弱 passphrase**:仅 6 字符 → 客户端 UI 拒绝(spec §7.2 强度要求);若 bypass,服务端 MAY 拒绝
- **E8.2 篡改 ciphertext**:测试 harness 改 backup 的 1 byte → 客户端 digest 校验失败,MUST 拒绝
- **E8.3 错 passphrase 重试限制**:连续 N 次 commitment 不匹配 → 客户端要求 cooldown(防止暴力)
- **E8.4 threshold recovery (3 of 5 shares)**:alice 用恢复 shares 而非 passphrase;3 个 share holder 各自签发响应,客户端拼凑出 recovery key → 解密 envelope。覆盖 `key-management.md §8`
- **E8.5 trusted recovery service**:走第三方恢复服务(`ck.recovery.service.v1`)发起,验证服务端的 attestation,客户端最终拿到 backup decryption key
- **E8.6 Mixed-domain backup**:`mixed_secret_storage=true` only 允许在 `personal_node` profile;`high_assurance` 部署 MUST 拒(§7.1)
- **E8.7 Backup 在 device revoke 后**:device-1 被远程 revoke(spec §5.2);Phase C 恢复仍然成功,但**新设备的 historical access 仍按当前 membership 评估**(spec §12 line 724)

## Implementation notes

- **soland 缺口**:`ck.key_backup.v1` schema、recovery policy state machine、recovery proof 校验。整条 scenario 大部分 fixme。
- **yougen 缺口**:`/settings/recovery` 设置 UI、`/onboarding` 的 Restore from backup 入口。当前不存在;参考 spec §7.1-7.3 的 client UI 暗示。
- **harness**:测试需要在 step 9 真的把 device-1 的 browser context 丢掉(不仅是关页面,而是新 context 完全空 storage)

## 风险 / 前置依赖

- spec §7-§8 是 v1 候选,soland 大概率没实现完整。**整条 fixme 起步**。
- E2EE history backup key 是否能跨 MLS epoch 解 backfill,实现复杂度高(spec §7.3 step 6)。

## 总耗时预估

约 2 分钟(包含 Argon2id KDF 计算的 ~3s + MLS commit 回放)。
