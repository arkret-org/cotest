# 账户恢复 (Recovery)

## 目标

验证用户在丢失主设备后,通过预设的恢复手段(24 词 Recovery Key / 阈值恢复 shares / 信任恢复服务)在新设备上完整恢复访问。包含:恢复前的 Recovery Key 生成(备份自动上传)、跨设备使用 backup envelope 解密、新设备的 `ak.device.authorize` 写入、E2EE 历史消息解密。Recovery Key 是唯一的内容恢复用户凭证(spec §3.3/§7.7);独立 vault passphrase 凭证层已弃用(§7.5.1)。

不验证:首次 onboarding(见 identity/onboarding)、多设备配对(见 identity/multi-device)、device 撤销(见 identity/multi-device)。

## Spec 锚点

- `identity/key-management.md` §3.3 — Recovery Key(24 词 BIP-39,唯一内容恢复凭证)+ threshold scheme + trusted recovery service
- `identity/key-management.md` §7 — Key backup 概览,`backup_class` domain
- `identity/key-management.md` §7.1 — 各 backup_class 的内容隔离
- `identity/key-management.md` §7.2 — Backup envelope schema(Argon2id KDF + XChaCha20-Poly1305 + key_commitment)
- `identity/key-management.md` §7.3 — Restore strand(凭证 = Recovery Key)
- `identity/key-management.md` §7.4 — Ownership proof vs decryption proof
- `identity/key-management.md` §7.5.1 — 独立 vault passphrase 凭证层 deprecated(wire method 仍合法)
- `identity/key-management.md` §7.7 — Recovery UI:解密凭证 MUST 是 Recovery Key
- `identity/key-management.md` §7.10 — 自动持续备份
- `identity/key-management.md` §8 — Threshold recovery service
- `crypto-media/device-lifecycle.md` §12-§12.1 — Key backup durable form + Backup API (PUT/GET/DELETE)

## 拓扑

- 1 × soland + 1 × coauth + 1 × backup storage service(可能就在 soland 里;或独立)
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

1. alice (device-1) 进 `/settings/recovery`(RecoveryPanel)
2. alice 点 "Generate"(`recovery-key-regenerate`):UI 生成 24 词 BIP-39 Recovery Key,只显示一次并要求抄写;本地只存 SHA-256 指纹,词串不上传(spec §3.3/§7.7;首次创建 encrypted Realm 时 `MlsBackupPrompt` 也会自动走同一流程)
3. 客户端:
   - 从 24 词确定性派生 recovery private/public key
   - 发布或确认 genesis recovery policy accepted
   - 上传 `backup_class="did_recovery"`、`series_seq=0`、`recipient_method="recovery_public_key"`、带 `recovery_policy_ref` 的 first-backup envelope
   - 用同一个 recovery public key HPKE 加密账户 secret(`mls_account_secret` 等 `secret_storage` 域材料)
4. `PUT /_arkret/self/keys/backups/<backup_id>` 上传 envelope:`{ backup_class: "did_recovery" | "secret_storage", encryption.recipient_method: "recovery_public_key", recovery_policy_ref?, ciphertext, ciphertext_digest }`
5. 服务端**只能存** ciphertext,不接受 Recovery Key 词串明文
6. 断言:
   - `GET /_arkret/root/identity/recovery-policy` 返回 non-null `active_policy`
   - `GET /_arkret/self/keys/backups?backup_class=did_recovery` 至少 1 条
   - `GET /_arkret/self/keys/backups?backup_class=secret_storage` 至少 1 条(有本地 account MLS secret 时)
   - metadata **不含** Recovery Key plaintext;此后新材料按 §7.10 自动持续备份

### Phase B — (可选)alice 在 E2EE Realm 中收发消息

7. alice 与 bob 在 Realm `R_e2ee` (`encryption_profile=mls_rfc9420`) 中交换若干消息
8. 关键:其中至少 1 条消息使用 backup 之前的 MLS epoch key

### Phase C — Device 1 "丢失",alice 在 Device 2 恢复

9. 开新 browser context = device-2,空 localStorage
10. alice 登录进入 app;若当前设备未在 durable device list 中,UI 先进入 existing-device authorization。只有用户确认旧设备不可用,且服务器存在 active policy + `did_recovery` backup 时,才进入 Recovery Key restore。新浏览器不得自动生成第二套 24 词。
11. 检测到服务器有可用备份但本地无 MLS state → 自动弹出 `MlsUnlockPrompt`(`/recover` 独立路由已不存在;手动入口是 `/settings/recovery` restore 面板)
12. UI 提示输入已有 24 词 Recovery Key("Decrypt with Recovery Key")
13. 客户端:
    - 生成新 device key(本地)
    - 24 词 BIP-39 输入校验(非法词串本地拒绝)→ 派生 recovery private key → HPKE open `recovery_public_key` envelope
    - 解 ciphertext → 拿回 self_signing_key + user_signing_key + MLS backup key
14. 客户端签 `ak.device.authorize` (包含 recovery proof,引用 recovery key 或 control signature)
15. 提交到 soland;soland 校验 recovery policy → 接受
16. 断言:device-2 上 `GET /_soland/self/account/me` 返回 alice.did,设备列表新增 device-2

### Phase D — alice 在 device-2 上 sync E2EE history

17. device-2 拉 `R_e2ee` 的 MLS state(commit chain 回放)
18. 用 backup 提供的 MLS history backup key 解 epoch 历史
19. 断言:Phase B 时 bob 发的消息现在在 device-2 timeline 可见、明文渲染

## Observable assertions(合并)

- Phase A 步骤 6:backup metadata 暴露 ✓,plaintext 不暴露 ✓
- Phase A 步骤 6:`active_policy` + `did_recovery` 同时存在才算 recovery configured;仅有本地 `recovery.state.v1` 指纹或 `backups=[]` 必须显示 incomplete
- Phase C 步骤 10:fresh browser 优先 existing-device authorization;无 active policy / 无 `did_recovery` 时 fail closed,不尝试 recovery proof,不生成新 24 词
- Phase C 步骤 13:Recovery Key 错误 → 非法 24 词在输入校验即拒;合法但错误的词串在本地 HPKE open / envelope 校验阶段拒,**不发解锁请求到服务器**(避免 oracle)
- Phase C 步骤 16:device-2 成功注册,alice 的 device 列表有 2 台
- Phase D 步骤 19:历史消息明文渲染

## Edge cases / sub-tests

- **E8.1 非法 Recovery Key 输入**:不是 24 个合法 BIP-39 词 → 客户端输入归一化阶段拒绝,不派生不发请求(`normalize_recovery_key_input`;新流程不存在用户自选弱口令,§7.7)
- **E8.2 篡改 ciphertext**:测试 harness 改 backup 的 1 byte → 客户端 digest 校验失败,MUST 拒绝
- **E8.3 错 Recovery Key 重试限制**:连续 N 次 commitment 不匹配 → 客户端要求 cooldown(防止暴力)
- **E8.4 threshold recovery (3 of 5 shares)**:alice 用恢复 shares 而非 24 词词串;3 个 share holder 各自签发响应,客户端拼凑出 recovery key → 解密 envelope。覆盖 `key-management.md §8`(门限是 recovery policy 层,§7.5.4)
- **E8.5 trusted recovery service**:走第三方恢复服务(`ak.recovery.service.v1`)发起,验证服务端的 attestation,客户端最终拿到 backup decryption key
- **E8.6 Mixed-domain backup**:`mixed_secret_storage=true` only 允许在 `personal_node` profile;`high_assurance` 部署 MUST 拒(§7.1)
- **E8.7 Backup 在 device revoke 后**:device-1 被远程 revoke(spec §5.2);Phase C 恢复仍然成功,但**新设备的 historical access 仍按当前 membership 评估**(`crypto-media/encryption-and-audit.md` §2.3.5/§2.4)

## Implementation notes

- **soland 缺口**:recovery policy state machine、recovery proof(`ak.schema.recovery_session.v1`)与 `ak.device.authorize` 的端到端绑定仍未贯通;key-backup CRUD + series 链 + unlock-proof 门已实现。整条 scenario 的 device-authorize 段仍 fixme。
- **inkson 现状**:`/settings/recovery` RecoveryPanel(生成/轮换/copy + restore 面板)与 `/settings/encryption` SettingsMlsRecoveryPanel 已存在;fresh device 先按 device authorization fail-closed,只有 active policy + backup 可用时才进入输入已有 24 词的 restore。旧 `/recover` 路由、Vault passphrase 面板与 `/settings/security` 的手动备份按钮已删除(security 页只剩只读状态 + `key-backup-setup-link`)。
- **harness**:测试需要在 step 9 真的把 device-1 的 browser context 丢掉(不仅是关页面,而是新 context 完全空 storage)

## 风险 / 前置依赖

- spec §8(threshold / recovery service)与 §7.4 recovery proof 绑定 soland 实现不完整。**device-authorize 恢复段 fixme 起步**;内容恢复段(MLS account secret)已由 `encryption/key-backup` A1/A2 live 覆盖。
- E2EE history backup key 是否能跨 MLS epoch 解 backfill,实现复杂度高(spec §7.3 step 6)。

## 总耗时预估

约 2 分钟(包含 Argon2id KDF 计算的 ~3s + MLS commit 回放)。
