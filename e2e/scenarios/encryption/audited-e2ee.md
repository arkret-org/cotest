# S25 — Moderation Franking 与 Audited E2EE 边界

## 目标

验证普通治理举报与 Audit Applet release 是两条彼此独立的协议流程：

- E2EE 消息可生成本地 `ak.moderation.franking_proof`，且 proof 不包含明文；
- `POST /_arkret/self/moderation/report` 只把举报送入目标 Realm / Circle 的 moderation workflow；
- 普通举报不得自动派生 `ak.audit.session.request`、`ak.audit.session.authorize`、`ak.audit.release` 或 `ak.audit.accessed`；
- 只有 active `ak.audit.applet_binding` 加上完整 sealed release session 才能向 Audit Applet 释放有界历史材料。本场景不伪造该跨服务 transport。

## 规范映射

- `crypto-media/audited-e2ee.md` §2、§8 — Audit Applet 控制面与治理举报边界
- `governance/content-moderation.md` §3.1–§3.4 — 举报、scoped moderation routing、E2EE evidence / franking
- `crypto-media/encryption-and-audit.md` §2.3.3 — `payload_digest`

## Actors

| Actor | 角色 |
|---|---|
| alice | Realm owner / scoped administrator |
| bob | E2EE 消息发送者 |
| reporter | 可见目标消息的普通 Realm 成员 |

## 主流程

1. alice 创建 `encryption_profile=mls_rfc9420` 的 Realm；不配置旧式 `audit_disclosure_policy`。
2. bob 提交只含 ciphertext、AAD 与 digest 的 `ak.message.create`。
3. alice 从部署本地审计查询面读取 `ak.moderation.franking_proof`：
   - proof 绑定消息 event、ciphertext digest、接收服务与 canonical event digest；
   - proof 不含 plaintext；
   - proof 不携带 `audit_disclosure_policy` 或 Audit Applet endpoint。
4. 使用本地 verifier 验证 proof；篡改 `ciphertext_digest` 后必须返回 `franking_tampered`。
5. reporter 对该消息调用 `POST /_arkret/self/moderation/report`。
6. 响应为 `{report_id,status:"submitted"}`；普通 reporter 不获得具体 `routed_to` DID。
7. reporter 从自身可见的部署本地审计查询面看到 `moderation.report` 留痕，确认举报已被本地受理。
8. 查询该 Realm 的内部审计记录，确认本次举报没有产生：
   - `org.arkret.soland.audit.report`
   - `ak.audit.accessed`
   - `ak.audit.session.request`
   - `ak.audit.session.authorize`
   - `ak.audit.release`

## 明确不覆盖

本场景不模拟 Audit Applet identity、invite、inbox 或自动 plaintext access。若未来需要跨服务 Audit Applet transport，必须先在规范中完整登记身份认证、session/notice/authorize/release schema、重放与重试、recipient key/attestation、撤销与顺序语义，然后再增加真实互操作测试。

## 预算

约 45 秒。
