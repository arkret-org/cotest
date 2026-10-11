# 账户恢复 (Recovery)

## 目标

验证用户在丢失主设备后,通过预设的恢复手段(24 词 Recovery Key / 阈值恢复 shares / 信任恢复服务)在新设备上完整恢复访问。包含:冷保管确认、恢复策略、加密账户备份、跨设备解密、PCR-policy 授权的原子 `ak.device.reanchor` / replacement authorize、generation fence 及 E2EE 历史恢复。Recovery Key 是唯一的内容恢复用户凭证,但派生出的 DID root、recovery-proof Ed25519 key 与 backup-only X25519 HPKE key 必须角色分离。

不验证:首次 onboarding(见 identity/onboarding)、多设备配对(见 identity/multi-device)、device 撤销(见 identity/multi-device)。

## Spec 锚点

- `identity/key-management.md` §3.3 — Recovery Key(24 词 BIP-39,唯一内容恢复凭证)+ threshold scheme + trusted recovery service
- `identity/key-management.md` §7 — Key backup 概览,`backup_kind` domain
- `identity/key-management.md` §7.1 — 各 backup_kind 的内容隔离
- `identity/key-management.md` §7.2 — Backup envelope schema(Argon2id KDF + XChaCha20-Poly1305 + key_commitment)
- `identity/key-management.md` §7.3 — Restore strand(凭证 = Recovery Key)
- `identity/key-management.md` §7.4 — Ownership proof vs decryption proof
- `identity/key-management.md` §7.5.1 — `passphrase_kdf` 仅用于 `secret_storage`;`mls_history` MUST NOT 使用,即便作为 fallback
- `identity/key-management.md` §7.7 — Recovery UI:解密凭证 MUST 是 Recovery Key
- `identity/key-management.md` §7.10 — 自动持续备份
- `identity/key-management.md` §8 — Threshold recovery service
- `crypto-media/device-lifecycle.md` §12-§12.1 — Key backup durable form + Backup API (PUT/GET/DELETE)
- `crypto-media/device-lifecycle.md` 的 PCR-policy 恢复与 device generation fence — 原子 re-anchor unit、旧代拒绝与冲突 quarantine

## 拓扑

- 1 × coland + 1 × coauth + 1 × backup storage service(可能就在 coland 里;或独立)
- 若用 threshold recovery:外加 N 个 share-holder

## Actors

| 名字 | 角色 |
|---|---|
| alice | 主用户;Phase A 设置备份,Phase C 在新设备恢复 |
| alice-device-1 | 主设备 |
| alice-device-2 | "丢失"后的新设备(实际是另一个 browser context) |
| (E2EE 子测试)bob | 与 alice 在同一 E2EE Realm,恢复后 alice 解 bob 发的旧消息 |

## Steps

### Phase A — 生成 Recovery Key(备份自动上传)

1. alice 在 onboarding 的 inception draft 尚未发布前生成 24 词 BIP-39 Recovery Key,只显示一次并完成冷保管确认;未确认不得发布 entry 0。已存在身份的 `recovery-key-regenerate` 是独立权威存在时的两 entry handoff,不得原地替换当前 root。
2. 客户端持久化可续跑的 draft/checkpoint,但不把词串写入普通设备状态、wire、日志或服务端 backup。
3. 客户端:
   - 按规范 HKDF 从 Recovery Key 派生代际 DID root、独立 recovery-proof signing key 与 backup-only HPKE key
   - entry 0 的 `updateKeys` 使用 root;root 不进入 DID Document `verificationMethod`
   - 发布或确认同时绑定 recovery signing / HPKE pair 的 genesis recovery policy accepted
   - 只用配对的 X25519 backup key HPKE 加密账户 secret;不得把 signing key 当 recipient
4. `PUT /_arkret/self/keys/backups/<backup_id>` 上传 envelope:`{ backup_kind: "secret_storage", encryption.recipient_method: "recovery_public_key", recovery_policy_ref, ciphertext, ciphertext_digest }`
5. 服务端**只能存** ciphertext,不接受 Recovery Key 词串明文
6. 断言:
   - `GET /_arkret/root/identity/recovery-policy` 返回 non-null `active_policy`
   - `GET /_arkret/self/keys/backups?backup_kind=secret_storage` 至少 1 条(有本地 account MLS secret 时)
   - metadata **不含** Recovery Key plaintext;此后新材料按 §7.10 自动持续备份

### Phase B — (可选)alice 在 E2EE Realm 中收发消息

7. alice 与 bob 在 Realm `R_e2ee` (`encryption_profile=mls_rfc9420`) 中交换若干消息
8. 关键:其中至少 1 条消息使用 backup 之前的 MLS epoch key

### Phase C — Device 1 "丢失",alice 在 Device 2 恢复

9. 开新 browser context = device-2,空 localStorage
10. alice 登录进入 app;若当前设备未在 durable device list 中,UI 先进入 existing-device authorization。只有用户确认旧设备不可用且服务器存在 active policy 时,才进入 Recovery Key restore。新浏览器不得自动生成第二套 24 词。
11. 检测到服务器有可用备份但本地无 MLS state → 自动弹出 `MlsUnlockPrompt`(`/recover` 独立路由已不存在;手动入口是 `/settings/recovery` restore 面板)
12. UI 提示输入已有 24 词 Recovery Key("Decrypt with Recovery Key")
13. 客户端:
    - 生成新 device key(本地)
    - 24 词 BIP-39 输入校验(非法词串本地拒绝)→ 派生 recovery private key → HPKE open `recovery_public_key` envelope
    - 解 ciphertext → 拿回 MLS backup key
14. 客户端根据 accepted recovery policy/session 构造 policy-authorized `ak.device.reanchor` + 新设备自签 PoP 的 replacement `ak.device.authorize` 原子 unit；RecoveryTransaction 不发布 DID operation。
15. create 冻结两条原签 Event 与 `reanchor_commit_intent={realm_id,predecessor_ref,unit_event_digests}`，不产生恢复效果。唯一 `commit_recovery_unit` 携 replacement-device-signed receipt；治理 Station 在同一 stream-head/generation CAS 中签发两条连续 RealmCommit，原子保存新 generation、设备授权与 session consumption。错 predecessor、policy、session 或 generation 零恢复副作用拒绝。
16. 断言 typed receipt 与 completion attestation 同时绑定两个 Event 及其 CommittedEventRef;`GET /_arkret/self/account/viewer` 显示 device-2 active,当前 PCR generation 单调推进且不使用 DID `versionId`,所有旧代设备的新请求被 `device_generation_fenced` 拒绝。
17. 客户端以仍有效的 Bound AccountHandoff、terminal receipt、completion attestation、replacement authorize 与 `InitialSessionGrantIntent` 调用 recovery-completion issuance；Coauth 直接返回 DPoP-bound Standard grant。exact retry 返回逐字节相同 outcome；不存在临时 recovery grant、第二次 OIDC 或换发步骤。
    - `identity/multi-device.spec.ts` 的 `completion_grant_response_loss` 在真实 issuer 接受后丢弃响应并 reload；`account_config_commit_failure` 在 grant 已保存后令首次账号配置提交失败。两者都断言原 canonical issuance request 重放，且没有第二个 recovery session、transaction 或 terminal continue。
    - 本地 pending transaction pointer 保留到账号与会话耐久提交；completed 续接不重新用 consumed recovery session 解锁备份。最终清理绑定原 namespace，不删除后来创建的 pending transaction。

### Phase D — alice 在 device-2 上 sync E2EE history

18. device-2 拉 `R_e2ee` 的 MLS state(commit chain 回放)
19. 用 backup 提供的 MLS history backup key 解 epoch 历史
20. 断言:Phase B 时 bob 发的消息现在在 device-2 timeline 可见、明文渲染

## Observable assertions(合并)

- Phase A 步骤 6:backup metadata 暴露 ✓,plaintext 不暴露 ✓
- Phase A 步骤 6:`active_policy` accepted 才算 recovery-material gate configured；普通本地指纹不得绕过 gate
- Phase C 步骤 10:fresh browser 优先 existing-device authorization;无 active policy 时 fail closed,不尝试 recovery proof,不生成新 24 词
- Phase C 步骤 13:Recovery Key 错误 → 非法 24 词在输入校验即拒;合法但错误的词串在本地 HPKE open / envelope 校验阶段拒,**不发解锁请求到服务器**(避免 oracle)
- Phase C 步骤 16:device-2 成功注册、generation 推进,旧代离线队列不重放
- Phase D 步骤 20:历史消息明文渲染

## Edge cases / sub-tests

- **E8.1 非法 Recovery Key 输入**:不是 24 个合法 BIP-39 词 → 客户端输入归一化阶段拒绝,不派生不发请求(`normalize_recovery_key_input`;新流程不存在用户自选弱口令,§7.7)
- **E8.2 篡改 ciphertext**:测试 harness 改 backup 的 1 byte → 客户端 digest 校验失败,MUST 拒绝
- **E8.3 错 Recovery Key 重试限制**:连续 N 次 commitment 不匹配 → 客户端要求 cooldown(防止暴力)
- **E8.4 threshold recovery (3 of 5 shares)**:alice 用恢复 shares 而非 24 词词串;3 个 share holder 各自签发响应,客户端拼凑出 recovery key → 解密 envelope。覆盖 `key-management.md §8`(门限是 recovery policy 层,§7.5.4)
- **E8.5 trusted recovery service**:走第三方恢复服务(`ak.recovery.service.v1`)发起,验证服务端的 attestation,客户端最终拿到 backup decryption key
- **E8.6 Mixed-domain backup**:`mixed_secret_storage=true` only 允许在 `personal_node` profile;`high_assurance` 部署 MUST 拒(§7.1)
- **E8.7 Backup 在 device revoke 后**:device-1 被远程 revoke;恢复仍由 accepted PCR policy/session 完成,不依赖旧设备,且历史访问仍按当前 membership 评估。
- **E8.8 authority 混用**：replacement authorize 不为 `pcr_recovery` 或携带额外授权来源时，必须 fail closed。
- **E8.9 同 generation 冲突**:同 previous/result PCR generation 的不同 re-anchor unit 均不得 first-seen winner；冲突必须 fail closed/quarantine。
- **E8.10 恢复秘密疑似泄露**:若没有预先存在的独立权威,禁止同 DID 原地 handoff,必须重铸 DID 并重建信任;有独立权威时按 durable checkpoints 完成两 entry handoff、re-anchor、policy、全 active backup series 重封装、pointer 推进,最后撤销旧 policy key。

## Implementation notes

- **当前可执行 conformance**：Rust `identity_root_conformance` 已直接运行正式 KDF KAT、SDK typed genesis/re-anchor helper 与 generation fence；`recovery_completion_grant` 运行真实 signed receipt/attestation、direct Standard outcome、exact replay 与逐字段 mutation 矩阵。原子 admission/reducer 与 live PCR-policy re-anchor 在对应 runner 落地前仍按未覆盖记录，不得把 fixture 名称检查计作执行。
- **inkson 现状**:`/settings/recovery` RecoveryPanel(生成/轮换/copy + restore 面板)与 `/settings/encryption` SettingsMlsRecoveryPanel 已存在;fresh device 先按 device authorization fail-closed,只有 active policy + backup 可用时才进入输入已有 24 词的 restore。旧 `/recover` 路由、Vault passphrase 面板与 `/settings/security` 的手动备份按钮已删除(security 页只剩只读状态 + `key-backup-setup-link`)。
- **harness**:测试需要在 step 9 真的把 device-1 的 browser context 丢掉(不仅是关页面,而是新 context 完全空 storage)

## 风险 / 前置依赖

- threshold / recovery service 的客户端 reconstruction、完整 PCR-policy re-anchor harness，以及覆盖全部正式 case 的 Cotest admission/reducer runner 仍是端到端前置依赖；内容恢复段由 `encryption/key-backup` A1/A2 live 覆盖。
- E2EE history backup key 是否能跨 MLS epoch 解 backfill,实现复杂度高(spec §7.3 step 6)。

## 总耗时预估

约 2 分钟(包含 Argon2id KDF 计算的 ~3s + MLS commit 回放)。
