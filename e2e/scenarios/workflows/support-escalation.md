# Support Escalation Workflow

## 目标

支持工程师 Alex 在客户报问题后,把工单升级给后端工程师 Sam。两人在一个共享 Realm 里通过 reply chain 讨论,Alex 编辑工单摘要补充新事实,Sam 提出修复方案,最后用 kanban 把工单状态推进到 Resolved。

这个 scenario 关注"reply chain + edit + kanban 反映状态"的真实使用,跟 sprint-planning 的"批量计划"互补。

## Spec 锚点

- `models/strand-and-message.md` §8 (reply / edit / redact)
- `models/realm-and-space.md` §4 (Space / Kanban)

## 拓扑

1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alex | 一线支持(Realm owner) |
| sam | 后端工程师(升级目标) |

## Steps

### Phase A — Alex 开 ticket Realm

1. Alex `createRealm` `"Support escalation #1042"`,seed Sam
2. Sam `acceptInvite`
3. Alex 显式授予 Sam Realm-scoped `ak.message.create` capability（加入 Realm 本身不隐式授权）
4. Alex 在 timeline 发 ticket summary:`"Ticket #1042 — customer X's checkout fails with 500 on /api/charge."`
5. Sam reply:`"Got logs? When did it start?"`(对 Alex 的 summary)
6. Alex reply Sam:`"Started ~14:30 UTC; HTTP body says 'gateway timeout'."`
7. Sam 提出 hypothesis(reply Alex 的最新一条):`"Sounds like payment gateway pool exhausted. I'll bump max_conn."`

### Phase B — Alex 编辑原始 summary(摘要补丁)

8. Alex 在自己最初的 summary 上 edit,加上 root cause:`"Ticket #1042 — customer X's checkout fails with 500 on /api/charge. (ROOT CAUSE: payment gateway pool exhausted, see Sam's reply below)"`
9. Sam 视图自动看到 edit 后的版本

### Phase C — Kanban 推进状态

10. Alex 进 `/kanban`,建三列:`Triage`、`In Progress`、`Resolved`
11. Alex 在 `Triage` 列建卡 `"Ticket #1042 — checkout 500"`
12. Sam 表示 fix 已提交:发 reply `"Fix deployed in 5min, can you verify?"`
13. Alex 验证后,在 `Triage` 列 archive 那张卡,在 `Resolved` 列加同名卡
14. Alex 发最后一条 reply `"Verified — ticket resolved. Thanks Sam!"`

### Phase D — Reply 链完整性

15. Sam 视图能看到完整的 6+1=7 条 timeline 事件,reply 链按时间排序

## Observable assertions

- Phase A 步骤 7:Sam 的 hypothesis 在 timeline 带 `reply-indicator`
- Phase B 步骤 8:write-status 含 `revised`,timeline 里看不到原始 summary 文字(只看到编辑后的)
- Phase C 步骤 13:`Triage` 列空,`Resolved` 列有卡,archive 列也有卡
- Phase D 步骤 15:reply 链上下文清晰

## Edge cases

- **E-support.1** Alex redact 一条 PII 泄露的 reply,tombstone 显示
- **E-support.2** Sam 在 ticket Realm 加另一个工程师 — 升级链扩大(需要 inviteFromAdmin)
- **E-support.3** Customer 申请加入 ticket Realm(knock strand)— 需要 knock-application

## 总耗时预估

约 45-60 秒。
