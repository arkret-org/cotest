# Key backup restore live path

验证 T-P1-02 的可执行子集:soland 必须保存、隔离、校验、按 ownership proof 删除 `ck.schema.key_backup.v1` envelope;inkson 必须继续用真实 Argon2id + XChaCha20-Poly1305 做客户端备份加解密——用户侧唯一解密凭证是 24 词 Recovery Key(spec `identity/key-management.md` §3.3/§7.7;独立 vault passphrase UI 已删除,`passphrase_kdf` 仅作为 wire method 保留,§7.5.1),并能从 `late_recovery_original_event_id` 生成 late-recovery banner 数据。

## 范围

- `PUT /_arkret/self/keys/backups/{backup_id}` 接受 `passphrase_kdf` envelope(含 §7.6 series 链字段 `series_id`/`series_seq`),且 actor 必须等于当前 session actor。
- `POST /_arkret/self/keys/backups/{backup_id}/unlock` 只允许 owner 携带 JSON body `proof` 解锁全密文; bearer-only 必须被拒(spec §7.7.1/§7.8)。
- `GET /_arkret/self/keys/backups` 按 owner 过滤,不得暴露 Recovery Key 词串或 plaintext key material。
- Argon2id floor:常规 backup 至少 `memory_kib=65536, iterations=3, parallelism>=1`;`mixed_secret_storage=true` 走更高 floor。
- `DELETE /_arkret/self/keys/backups/{backup_id}` 不接受 session-token-only 删除,必须带 ownership proof header。
- inkson client crypto 对真实 Argon2id + XChaCha20-Poly1305 seal/open round trip、wrong-Recovery-Key commitment 拒绝、24 词 BIP-39 输入校验和 late recovery banner typed lift 保持 live。

## 不验证

- 完整 MLS commit replay 与真实历史明文消息批量解密。当前用 inkson crypto 单元合同 + soland envelope 持久化合同钉住这条链路的可落地部分。
- threshold/social recovery 与第三方 recovery service。

## Live 用例

1. Device-A 上传 secret_storage backup,列表为 metadata-only(不含 Recovery Key 词串/plaintext);bearer-only 的单条全密文 GET 被拒且不泄露密文。
2. Device-B/其他 actor 不能读取或枚举 Alice 的 backup。
3. actor_id mismatch 的 backup PUT 被拒。
4. 低于 Argon2id floor 的 envelope 被拒。
5. `mixed_secret_storage=true` 必须使用更高 KDF floor。
6. session-token-only DELETE 被拒;带 ownership proof 后删除成功。
7. inkson 真实 crypto:Argon2id + XChaCha20-Poly1305 seal/open round trip、wrong-Recovery-Key commitment reject、24 词 BIP-39 输入校验、late recovery banner 从 `late_recovery_original_event_id` 构造。
8. A3 real OIDC: 用真实 coauth 密码/OIDC 登录获取 `ck.session.grant`,Device-A 上传 MLS account-secret backup,Device-B fresh browser 用同一账号登录后输入 24 词 Recovery Key 恢复 MLS;所有 `/_arkret/self/*` / `/_arkret/root/*` grant 请求必须带 DPoP holder proof,unlock 必须带 body `proof`,并明确拒绝 bearer-only unlock。
