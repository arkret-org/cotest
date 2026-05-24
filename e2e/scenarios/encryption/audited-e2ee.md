# Audited E2EE(franking + moderator decryption attestation)

## 目标

E2EE space 启用 audited mode 后,服务端能记录每条消息的 franking 收据(`cx.moderation.franking_proof`),证明"该 ciphertext 在某时间点存在 + 来自某 sender";audit agent 可以在用户明确 audit_disclosure_policy 下,通过 attested ceremony 解密 + 写入 `cx.audit.accessed`。

## Spec 锚点

- `crypto-media/audited-e2ee.md` §2 — 设计目标(可审 + 不破坏 forward secrecy)
- `crypto-media/audited-e2ee.md` §3 — Audit agent 进入条件
- `crypto-media/audited-e2ee.md` §4 — Franking schema + `cx.audit.accessed`
- `crypto-media/encryption-and-audit.md` §3 — Audited mode 集成
- `governance/content-moderation.md` §3.4 — E2EE 举报 franking

## 拓扑

- 1 × soland + 1 × coauth + 1 × audit agent service(独立 DID)

## Actors

| 名字 | 角色 |
|---|---|
| alice | space owner,启用 audit mode |
| bob | 成员,发被举报的消息 |
| reporter | 成员,举报 |
| audit-agent | 第三方 audit service,`did:web:audit.example.com` |

## Steps

### Phase A — 启用 audited E2EE

1. alice createSpace,`encryption_profile=mls_rfc9420` + `audit_disclosure_policy = { agent_did: "did:web:audit.example.com", trigger: "report_filed" }`
2. alice 邀请 bob、reporter,both 接受

### Phase B — bob 发消息,franking 自动生成

3. bob 发加密消息 `M1` 到 space `S_audit`
4. soland Sync Service:
   - 接受 ciphertext + plaintext metadata
   - 同时生成 `cx.moderation.franking_proof`,payload `{ ciphertext_digest, sender_did, receiving_service_did, timestamp }`,服务端 service DID 签
5. 断言:`GET /api/v1/audit/events?space_id=<S_audit>&kind=cx.moderation.franking_proof` 返回该 franking 记录
6. 断言:franking record **不含** 明文消息内容,只含 ciphertext_digest

### Phase C — reporter 举报

7. reporter 举报 `M1`,`POST /api/v1/moderation/report { space_id, target_ref: M1.event_id, reason: "harassment" }`
8. Report 触发 `audit_disclosure_policy.trigger = report_filed`
9. soland 通知 audit-agent service:`POST <agent_url>/api/v1/audit/request`

### Phase D — audit-agent 进入 + 解密

10. audit-agent 收到 request → 调 `GET /api/v1/spaces/<S>/events/<M1.event_id>/audit-access`
11. soland 校验 audit-agent 是 audit_disclosure_policy.agent_did → 允许
12. audit-agent 调 MLS KeyPackage / out-of-band 拿到 epoch key(spec 留 mechanism;可能需要群组重新加 audit-agent 进 MLS)
13. audit-agent 解密 `M1` 得到 plaintext
14. **关键**:audit-agent 必须写 `cx.audit.accessed { auditor_did, target_ref, accessed_at, reason: "moderation_report" }`
15. 断言:audit log 含该 accessed record
16. 断言:alice 进 `/space/${spaceId}/admin/audit` 看到这条 access entry

### Phase E — Audit-agent 私自访问被拒

17. audit-agent 不在 audit_disclosure_policy 时(假设 alice 改了 policy),audit-agent 调同样的 endpoint → 拒,403
18. 断言:soland 拒绝 + 写入 `cx.audit.rejected_access` 记录

## Edge cases

- **E25.1 franking 完整性**:测试 harness 改 franking record 的 ciphertext_digest → 后续校验失败,reducer 拒
- **E25.2 audit-agent 单独看到 frank 但解不开**:audit-agent 拿到 frank record,但因为不在 MLS group 中所以解不了密(spec 行为)
- **E25.3 alice 撤销 audit policy 中途**:撤销后,audit-agent 后续请求被拒;已 access 的记录保留(不可篡改)
- **E25.4 报告人 = 加害人**:bob 举报自己的消息 → 触发 audit?spec 可能禁止 self-report 进 audit pipeline

## Implementation notes

- **soland 缺口**:`cx.moderation.franking_proof` 自动生成、`audit_disclosure_policy` 字段、`/audit/events` endpoint、`cx.audit.{accessed,rejected_access}` event kinds
- **harness 缺口**:audit-agent mock service(注册 DID + 接收 audit request callback + 模拟解密)
- **yougen 缺口**:audit log viewer in space admin

## 总耗时预估

约 90s(audit-agent 解密 + 写回 audit log)。
