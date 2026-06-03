# E2EE 加密附件

## 目标

在 `encryption_profile=mls_rfc9420` 的 space 中,alice 给消息附图;bob(成员)能下载并解密看到明文;mallory(非成员)拿不到 ciphertext(opaque 403/404);blob 存储服务**只见 ciphertext**,不知道 plaintext filename / content / size 准确值。Audited 模式下,服务端只看到 `cx.moderation.franking_proof` 收据(可证存在但不可解密)。

不验证:MLS 群组生命周期本身(encryption/mls-group 前置)、密钥备份(encryption/key-backup)、calls 中的媒体(calls/webrtc)。

## Spec 锚点

- `crypto-media/media-and-blob.md` §3 — 加密附件 metadata(`encryption.algorithm = "MLS"`、`group_state_ref`、`ciphertext_digest`)
- `crypto-media/media-and-blob.md` §5 — 认证下载、authz、cache 规则
- `crypto-media/media-and-blob.md` §5.1 — Content-Type / Content-Disposition 不能泄漏 plaintext
- `crypto-media/media-and-blob.md` §5.2-§5.3 — Caching + thumbnail
- `crypto-media/media-and-blob.md` §6 — Asset Privacy Policy(`download_mode=provider_proxy` 默认)
- `crypto-media/encryption-and-audit.md` §2.3.1 — `key_ref` for MLS profile
- `crypto-media/audited-e2ee.md` §3 — Audit agent 进入(需要 explicit policy)
- `crypto-media/audited-e2ee.md` §4 — `cx.moderation.franking_proof` / `cx.audit.accessed`

## 拓扑

- 1 × soland(含 Blob Service)+ 1 × coauth
- (sub-test E12.4)外置 audit agent

## Actors

| 名字 | 角色 |
|---|---|
| alice | space owner,上传附件 |
| bob | 成员,下载 + 解密 |
| mallory | 非成员,验证 ACL |
| audit-agent (sub-test) | `did:web:audit.example`,持 `cx.audit.read` capability |

## Pre-conditions

- encryption/mls-group 已实现到能创建 E2EE space 且 alice/bob 都是成员
- alice、bob、mallory 都注册
- Blob Service endpoint 在 soland 同进程或独立

## Steps

### Phase A — alice 上传 + 发送加密附件

1. alice 在 E2EE space `S_e2ee` 中准备发消息,附图 `cat.png`(plaintext)
2. yougen 客户端:
   - 生成本地 AEAD key + nonce
   - 用 XChaCha20-Poly1305 加密 `cat.png` → ciphertext
   - 计算 `ciphertext_digest = sha256(ciphertext)`
3. `POST /api/v1/blob/put` 上传:
   - body: ciphertext bytes
   - meta: `{ space_id, media_type: "application/octet-stream", encryption: { algorithm: "MLS", group_state_ref: { epoch, key_ref } }, ciphertext_digest }`
   - **关键 invariant**:不带明文文件名、不带 plaintext media type
4. soland Blob Service 返回 `blob_ref: sha256:...`
5. alice 客户端组消息 `cx.message.create`:
   - `encrypted_payload`(明文 = "look at this", `attachments: [{ blob_ref, encryption, ciphertext_digest }]`)
   - 用 MLS 当前 epoch key 加密整个 payload
6. 提交事件 → soland 接受,Sync 路由

### Phase B — bob 下载 + 解密

7. bob yougen 拉 sync → 解 message → 拿到 plaintext `attachments` 数组
8. bob 客户端 `GET /api/v1/blob/get?blob_ref=<sha>` with `Authorization: Bearer <bob_token>`
9. soland Blob Service 校验:
   - bob 是 `S_e2ee` 的当前成员
   - `covered_frontier_cell` 包含必要的 governance frontier(若 E2EE Space 要求)
10. 返回 ciphertext bytes + `Content-Type: application/octet-stream` + `Cache-Control: private, no-store`(spec §5.1)
11. bob 客户端用 plaintext attachments 里携带的 key_ref → 派生解密 key → 解 ciphertext → 拿到原始 `cat.png`
12. yougen 渲染图片(lock icon + "Encrypted attachment, X KB")
13. 断言:bob timeline 上消息含 image preview

### Phase C — Ciphertext digest 校验

14. 测试 harness 强制让 bob 客户端拿到一个**篡改过 1 byte 的 ciphertext**(通过 `route.fulfill` 替换响应)
15. bob 客户端计算 sha256,与 `ciphertext_digest` 不匹配
16. 断言:客户端**丢弃** 这份 bytes,不解密,timeline 显示"Failed integrity check"或等价错误标记(spec §5)

### Phase D — Non-member access denied

17. mallory(非 `S_e2ee` 成员)拿到 `blob_ref`(假设外漏)
18. mallory `GET /api/v1/blob/get?blob_ref=<sha>` with `mallory_token`
19. soland 应拒绝;返回**不可区分** 的 opaque 403(同样的错误码 + body 对"不存在"和"无权限"都返回)
20. 断言:status 403/404;response 不暴露 space_id / blob 是否存在

### Phase E — Storage 服务只见 ciphertext

21. 测试 harness 通过 service log 抓 Blob Service 写盘记录(假设 service log 暴露 metadata)
22. 断言:写盘 metadata 含 `blob_ref`、`size`(ciphertext size,不是 plaintext)、`media_type = "application/octet-stream"`
23. 断言:写盘 metadata **不含** plaintext filename、不含 `image/png` 或类似 plaintext media type

### Phase F — (sub-test E12.4)Audited E2EE 模式

24. 重新建一个 audit-enabled space `S_audit`(`audit_disclosure_policy` 含 audit-agent 的 DID)
25. alice 在 `S_audit` 发加密附件 — 同 Phase A
26. audit-agent 拉 `GET /api/v1/audit/events?space_id=<S_audit>` → 应当看到 `cx.moderation.franking_proof` 收据(franking proof:存在 + 时间戳 + 发送方 DID + ciphertext_digest),**但**不含明文
27. audit-agent **不能** 直接拿到 plaintext attachment;若要审,需要触发 `cx.audit.accessed`(spec §4),记录到 audit trail

## Observable assertions(合并)

- Phase A 步骤 4-5:blob_ref 生成、消息携带 encrypted attachment metadata
- Phase B 步骤 13:bob 看到 image
- Phase B 步骤 10:Content-Type 是 octet-stream,不泄漏
- Phase C 步骤 16:digest 失败客户端拒绝
- Phase D 步骤 19-20:non-member 拿到 opaque 错误
- Phase E 步骤 22-23:Blob Service 只见 ciphertext
- Phase F 步骤 26-27:audit franking 存在但不泄漏明文

## Edge cases / sub-tests

- **E12.1 message redact 后 attachment 仍可访问?**:alice redact 消息,但 `blob_ref` 在 storage 仍存在 → blob GC policy 决定何时清理。spec 暗示 redact 不立刻删 blob(`media-and-blob.md` §3),但 `cx.blob.gc` event 触发后清理
- **E12.2 thumbnail derivation**:E2EE 模式下,服务端**不能**生成 thumbnail(因为没明文)→ client-side 生成 + 重新加密上传(§5.3)
- **E12.3 download_mode=provider_proxy**:大文件经过 Sync proxy 中转(防止 client 跨域)→ proxy 只见 ciphertext,不解密(spec §6)
- **E12.4 audited e2ee**:见 Phase F
- **E12.5 大文件 + chunked upload**:>10MB 文件分块上传,每块独立 encrypted + digested

## Implementation notes

- **2026-05-25 P2-044 local close**:soland `POST /api/v1/blob/upload` 对 encrypted attachment 强制 `media_type=application/octet-stream`,丢弃明文 filename,校验 `ciphertext_digest` 与 ciphertext bytes 匹配,成员可直接下载 ciphertext,非成员拿到 opaque `not_found`,E2EE blob presign fail-closed。
- **2026-05-25 P2-044 local close**:yougen 新增客户端 XChaCha20-Poly1305 MLS attachment helper,thumbnail 作为独立 ciphertext asset 加密并携带独立 digest/nonce;`CokretApi::upload_encrypted_mls_attachment_asset` 发送 ciphertext-only headers。
- **仍待 audited-e2ee**:`cx.moderation.franking_proof`、audit-agent invite、`cx.audit.accessed` 与 tamper verification 归入 `encryption/audited-e2ee` / GAP-P2-045。
- **仍待 UI polish**:E2EE attachment lock icon、"Decrypting..." 进度、integrity check 失败的错误 UI 可作为后续用户体验强化,不再阻塞 P2-044 protocol/privacy closure。

## 总耗时预估

约 60-90s(含 KDF 不计入,XChaCha20 很快;主要时间在 MLS sync 和 image preview load)。
