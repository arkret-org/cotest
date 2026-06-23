# 密钥备份 + 跨设备恢复 + 历史消息解密

## 目标

完整的"丢设备 → 新设备恢复 → 历史 E2EE 消息可解"链路。`ck.key_backup.v1` envelope 用 Argon2id 派生密钥 + XChaCha20-Poly1305 加密;new device 通过 24 词 Recovery Key(唯一内容恢复凭证,spec §3.3/§7.7)恢复 backup;再回放 MLS commit chain 把当前 + 必要的旧 epoch keys 派生回来,解之前在 E2EE Realm 收到的消息。

identity/recovery(账户恢复)的姊妹篇,但 encryption/key-backup 聚焦在**消息解密** 和 MLS epoch 重建,identity/recovery 更偏 device identity。

## Spec 锚点

- `identity/key-management.md` §3.3 — Recovery Key = 唯一内容恢复凭证(24 词 BIP-39)
- `identity/key-management.md` §7 — Key backup 概览
- `identity/key-management.md` §7.1 — Backup 内容隔离(`backup_class`)
- `identity/key-management.md` §7.2 — Envelope schema(Argon2id KDF + XChaCha20-Poly1305 + key_commitment)
- `identity/key-management.md` §7.3 — Restore strand(Recovery Key, commitment 校验, 解密)
- `identity/key-management.md` §7.4 — Ownership proof / decryption proof
- `identity/key-management.md` §7.5.1/§7.5.2 — `passphrase_kdf`(独立 vault passphrase 凭证层 deprecated,仍是合法 wire method)/ `recovery_public_key`(新写入 SHOULD)
- `identity/key-management.md` §7.7 — Recovery UI:备份解密凭证 MUST 是 Recovery Key
- `identity/key-management.md` §7.10 — 自动持续备份
- `crypto-media/device-lifecycle.md` §12-§12.1 — Key backup durable form + API(`PUT/GET/DELETE /_cokret/self/keys/backups`)
- `crypto-media/encryption-and-audit.md` §2.4 — MLS epoch backfill
- `crypto-media/encryption-and-audit.md` §6 — Offline support, epoch key retention

## 拓扑

- 1 × soland(含 backup storage API)+ 1 × coauth
- 一个 E2EE Realm `R_e2ee` 包含 alice + bob

## Actors

| 名字 | 设备 | 角色 |
|---|---|---|
| alice | device-A | 主用户;Phase A 备份,Phase D 在 device-B 恢复 |
| alice | device-B | "丢失 device-A 后" 的新设备 |
| bob | 单设备 | 在 `R_e2ee` 中给 alice 发消息(在 device-B 恢复之前) |

## Pre-conditions

- alice 已 onboard,device-A 在 `R_e2ee` 中(epoch N)
- device-A 是已授权 key-management 设备(存在 accepted `ck.device.authorize` / service-attested enrollment,device list 状态为 active);未授权 dev-login 设备 MUST NOT 生成新的 Recovery Key root
- bob 在 `R_e2ee` 中
- alice 在 Phase A 生成的 24 词 Recovery Key 由测试捕获并跨 browser context 传递(UI 只显示一次)

## Steps

### Phase A — alice 在 device-A 生成 Recovery Key(备份自动上传)

1. alice 进 `/settings/recovery`(RecoveryPanel)点 "Generate"(`recovery-key-regenerate`);或首次创建 encrypted Realm 时自动弹出 `MlsBackupPrompt`(`mls-backup-modal`),点 `mls-backup-submit` 自动生成 — **无用户口令输入**(spec §7.7/§7.10)
2. UI 生成 24 词 BIP-39 Recovery Key,只显示一次并要求抄写(`mls-backup-generated-key` / `recovery-key-current`);本地只保存 SHA-256 指纹,词串不上传
3. 客户端用 Recovery Key 建立 `recovery_public_key` 恢复根,发布 `backup_class="did_recovery"` envelope 并保存本地 recovery public key metadata。若此时本地已经存在 account MLS secret,客户端同时上传 HPKE `recovery_public_key` 的 `mls_account_secret` envelope;若 account MLS secret 尚未生成,则在首次加密写入后由 §7.10 自动补传。
4. 首次 encrypted write 生成/轮换 account MLS secret 后,客户端自动上传 `PUT /_cokret/self/keys/backups/<backup_id>`:
   - `backup_class: "secret_storage"`
   - `encryption.recipient_method: "recovery_public_key"`
   - `contents[].item_type: "mls_account_secret"`
   - `ciphertext` / `ciphertext_digest` 等 envelope metadata
5. 断言:`GET /_cokret/self/keys/backups` 列出该 backup,**metadata only**(no plaintext, no Recovery Key words)
6. UI 显示 recovery root 已配置;`mls_account_secret` 与自有内容 sidecar / 轮换材料按 §7.10 自动持续备份,无需手动触发
> **§7.10 持续备份时序(yougen 实现语义)**:RK 已配置的账号上,任一加密写引发的
> `ck.mls.commit` 被接受后约 **1.5s(debounce)** 内,该 Realm 的 `mls_history`
> successor envelope PUT 上行;同 Realm 后续 commit 受 **5min min-interval** 合并补传。
> 服务端可断言:同一 Realm 的连续上传 `series_id` 不变、`series_seq` 严格 +1、带
> `supersedes`/`supersedes_digest`(每 Realm 单系列,不再堆平行 genesis)。
> RK 未配置时 commit 路径不产生任何 `mls_history` 上传。
> `/settings/security` 状态位:`key-backup-history-pending`(未传完最新 epoch 的
> Realm 数,传完为 "0")、`key-backup-history-last-uploaded-at`(从未传过为 "never")、
> `key-backup-history-error`(仅出现过失败后渲染);失败 5s 起指数退避,连败 5 次
> park 待下次 commit 唤醒。恢复侧每个 `mls_history` 系列只全文取回尾部一条(§7.8 配额友好)。

### Phase B — bob 在 alice device-A 离线时给 alice 发消息

7. (假设 device-A 关闭、不同步)
8. bob 在 `R_e2ee` 发消息 `M1`,`M2`,使用 epoch N 的 key
9. soland 接受;消息 ciphertext 落到 sync 队列等 alice 拉

### Phase C — Device-A "丢失"

10. (测试 harness 模拟)放弃 device-A 的 browser context
11. (可选)alice 在 device-B 上远程触发 device-A revoke — 但这会导致 MLS Remove + 新 epoch,使 backup 恢复更复杂;为简化 encryption/key-backup,**不** 在恢复之前 revoke;留到 identity/multi-device 测

### Phase D — Device-B 恢复

12. 开新 browser context = device-B,空 storage,登录进入 app
13. 检测到服务器存在备份但本地无 MLS state → 自动弹出 `MlsUnlockPrompt`(`mls-unlock-modal`),UI 提示输入 24 词 Recovery Key("Decrypt with Recovery Key";也可走 `/settings/recovery` restore 面板的 `restore-recovery-key` 输入框)
14. 客户端:
    - 生成本地 device-B key(用于这台设备的 device authorization,后续)
    - 输入先做 24 词 BIP-39 校验(非法词串本地拒绝,不发请求)
    - Argon2id 派生(词串为 KDF 输入,用 backup 提供的 kdf_params)→ derived_key;或对 `recovery_public_key` envelope 做 HPKE open
    - 计算 commitment,与 backup 的 `key_commitment` 比对
    - **commitment mismatch → 客户端在本地拒绝,不向服务器发任何 oracle 查询**(spec §7.2)
    - commitment match → 用 derived_key 解 ciphertext → 拿回 SSK / USK / mls_history_backup_key
15. 客户端签 `ck.device.authorize` (包含 recovery proof,引用 USK 或 control signature)
16. 提交到 soland;recovery policy 校验通过 → device-B 接入
17. 断言:device-B `/settings/devices` 显示 alice 的 device 列表(可能含 device-A,看是否 revoke;此时未 revoke,所以 A 还在)

### Phase E — Device-B 从 MLS commit chain 重建 epoch keys + 解 bob 的消息

18. device-B 拉 `R_e2ee` 的 sync:
    - 自 epoch 0 起回放 `ck.mls.commit` 事件
    - 用 backup 提供的 `mls_history_backup_key` 派生历史 epoch secrets(spec §2.4 backfill)
    - 当前 epoch 应当 = device-A 离线时的 N(因为没有 commit advance)
19. device-B 用 epoch N application key 解 `M1`,`M2`
20. 断言:device-B `/timeline/<R_e2ee>` 显示 `M1`,`M2` 明文
21. UI 显示 "Recovered X messages, Y epochs"

### Phase F — Device-B 可以正常收发新消息

22. alice (device-B) 在 `R_e2ee` 发 `M3`
23. bob 拉同步,看到 `M3` 明文
24. 断言:device-B 的写入路径正常

### Phase G — 备份后被禁用的 MLS epoch(若 device-A 已 revoke)

(可选 sub-test,与 identity/multi-device 联动)
25. 在 Phase C 之后,device-A 在 mid-recovery 时被远程 revoke
26. 触发 MLS Remove,生成 epoch N+1,device-A 失去新 key
27. 但 device-B 已用 backup 恢复了 SSK/USK → device-B 应该被 alice 主动 Add 进 MLS group(via Commit Add)
28. spec `crypto-media/encryption-and-audit.md` §2.3.5/§2.4:old message access honors current membership — device-B 恢复后,过滤 access by current frontier

## Observable assertions(合并)

- Phase A 步骤 5:backup metadata exposed,plaintext 不暴露
- Phase D 步骤 14(错 Recovery Key):非法 24 词在输入校验即拒;合法但错误的词串在 commitment 阶段本地拒绝(无服务器 oracle)
- Phase D 步骤 17:device-B 加入 alice device set
- Phase E 步骤 20:device-B 看到 `M1`、`M2` 明文
- Phase F 步骤 23:bob 看到 device-B 发的 `M3`

## Edge cases / sub-tests

- **E13.1 错 Recovery Key**:非法 24 词(不是合法 BIP-39 词表组合)在输入归一化阶段拒绝;合法但错误的词串在 commitment 阶段拒绝;**不发** GET 到服务器(避免服务端做 oracle);客户端连续错 N 次触发本地 cooldown
- **E13.2 篡改 ciphertext**:digest 校验失败,客户端拒绝(spec §7.2 line 328)
- **E13.3 backup AAD domain/audience mismatch**:测试改 envelope 的 AAD → 拒绝
- **E13.4 mixed-domain backup**:`mixed_secret_storage=true` 只在 `personal_node` profile 接受;`high_assurance` 部署 MUST 拒(§7.1)
- **E13.5 epoch gap**:bob 在 device-A 离线期间发了 commits + 消息,backup 的 `mls_history_backup_key` 不含某些 epoch → 那些消息标 `decryption_pending`(spec §2.4)
- **E13.6 backup 在 recovery policy 变更后**:alice 在 Phase A 之后改了 recovery policy → device-B 恢复时,reducer 校验新 policy,若新 policy 拒绝 → 恢复失败
- **E13.7 删除 backup**:`DELETE /_cokret/self/keys/backups/<id>` 应需要 ownership proof(SSK 签名),无法仅凭 session token 删

## Implementation notes

- **当前 live 覆盖**:`encryption/key-backup-restore` 已验证 soland key-backup CRUD、owner 隔离、Argon2id floor、mixed-secret stronger floor、metadata-only list、bearer-only ciphertext read 拒绝(§7.7.1 unlock proof)、DELETE ownership proof,以及 yougen Argon2id + XChaCha20-Poly1305 seal/open round trip、wrong-Recovery-Key local reject(commitment)、24 词 BIP-39 输入校验、late-recovery banner helper。
- **剩余缺口**:本 scenario 的完整"丢设备 → 新设备授权 → MLS commit chain backfill → 历史 E2EE 消息可解"仍未贯通;`key-backup.spec.ts` 保留这些全链路 fixme。
- **2026-05-30 A1 live**:`key-backup.spec.ts` 覆盖同账号两个 fresh browser profile 的验收路径:device-A 创建 `mls_rfc9420` realm 并写历史 timeline 卡片、`MlsBackupPrompt` 自动生成 24 词 Recovery Key 并上传 `mls_account_secret` backup、device-B 空 profile 登录后出现 `MlsUnlockPrompt`、输入 24 词恢复、device-B 写入后 device-A 可见,同时收集 `keys/backups` PUT 和 subscribe/describe/events/MLS runtime 错误信号。
- **2026-06-01 A2 live**:`key-backup.spec.ts` 覆盖 Kanban 专用回归:creator device 新建 encrypted Realm 时必须生成并上传 initial `mls_history` backup;fresh browser restore 后打开同一 Board/Card,保存 card description 时不得出现 `MissingWelcome` 或 `ck.mls.commit` payload `schema_violation`,另一端能看到详情更新。
- **harness**:Argon2id KDF 计算耗时 ~3s(intentional);测试要给足 timeout

## 风险

- spec §7 整章是 v1 必须项,但 soland 实现度未知。**整个 scenario 大概率 fixme starter**。
- MLS epoch backfill 非常复杂(spec §2.4),若 device-A 缺很多 epochs,backup 必须含 enough state — 实际工程上往往需要 server-side 配合提供 commit log。

## 总耗时预估

约 2-3 分钟(含 Argon2id × 2 + MLS commit replay)。
