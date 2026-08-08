# 离线编辑 / 重连同步 / 冲突修复

## 目标

bob 在网络断开时编辑(本地 outbox);重连后 sync 上传所有 pending move。Realm title / summary / avatar 的唯一写入面 `ak.realm.profile` 使用 `ak.component.realm.profile.v1` 的 `cas_register / bottom=reject`：同一 single-chain Seal 中的互斥 sibling 必须至多接受一条，因果有序的后继 profile 保持单值；它不得被误报成 `bottom=expose`。当前规范还没有注册可由 inkson 提交的 repair event kind,所以 Realm admin 的 repair 区保持只读,不渲染未注册的修复提交控件。

## Spec 锚点

- `sync/client-sync.md` §2 — Sync 协议 + cursor
- `sync/operations-sync.md` §2 — Conflict resolution via Lattice join
- `sync/operations-sync.md` §2.1 — `bottom_cells` 暴露
- `authz/event-auth-state-resolution.md` §2 — Bottom cell diagnostics
- `authz/event-auth-state-resolution.md` §8.1 — 冲突恢复 Move(`state_witness` / `inclusion_proof`)

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字  | 角色            |
| ----- | --------------- |
| alice | 在线,持续编辑   |
| bob   | 离线编辑,后重连 |

## Steps

### Phase A — Setup space

1. alice createRealm,seedMembers=[bob],bob acceptInvite
2. alice 和 bob 各自打开 `/timeline/<S>`

### Phase B — bob 离线

3. 测试 harness 用 `page.context().setOffline(true)` 把 bob 断网
4. bob 在 inkson 中尝试发消息 `M_b_offline`
5. inkson 客户端:看到网络错误,把 move 写入本地 outbox(IndexedDB / localStorage)
6. UI 显示 `M_b_offline` 标 "pending sync" (`pending-sync-message` testid)
7. 同时 alice 在线发 `M_a_online`

### Phase C — bob 重连

8. `page.context().setOffline(false)`
9. bob 客户端检测网络恢复 → 自动 flush outbox 到 soland
10. 断言:30s 内 `M_b_offline` 状态从 pending 变 persisted;UI 标记移除
11. 断言:alice 和 bob 双方都看到 `M_a_online` 和 `M_b_offline`

### Phase D — 因果有序 title update 不产生 bottom

12. alice 在线提交完整 `ak.realm.profile`，等待其 Seal finality；bob 再以该后继 basis 提交第二条完整 profile
13. soland 因果应用两条 Realm profile 更新，保持 `ak.component.realm.profile.v1` 单值，不得把它误投影成 `bottom=expose`
14. 断言:`GET /_soland/admin/realms/<S>/bottom` 返回空数组

### Phase E — repair 区仍为只读

15. 断言:inkson 不渲染 `prefer-safer-side-button`、`repair-target-cell-input`、`repair-winner-json-input`、`repair-submit-button`
16. 断言:`GET /_soland/admin/realms/<S>/bottom` 仍为空,直到有标准 bottom producer 与 repair event kind 注册并被实现
17. 备注:后续 AKP 注册 repair kind 后,本阶段再升级为提交标准 repair Move 并验证目标 cell 回到 active

### Phase F — Backfill via pull

20. (sub-test)假设 bob 离线很久,本地缺很多 events;重连后先用 `GET /_arkret/self/account/subscribe?after=<old>&catchup=true`,缺口再用 `GET /_arkret/self/events?after=<old>`
21. 断言:bob timeline 自动补齐离线期间的所有消息

## Edge cases

- **E26.1 outbox 满**:bob 长期离线,outbox 满;客户端 UI 显示 "Too many pending changes, please reconnect"
- **E26.2 冲突未决期间再写**:仅跨不可达 Seal leaf 的真实并发可把该 `bottom=reject` cell 推入 `⊥`；之后普通写 fail closed,reason `cell_in_bottom_state`,UI 提示必须先走标准 conflict recovery
- **E26.3 repair Move 被拒**:等待标准 repair event kind 注册后恢复;测试 harness 让 bob 提交 repair 但 `state_witness` 篡改 → reducer 拒,bottom 诊断保留
- **E26.4 重连后冲突 + 排序**:多个 cell 同时 bottom_expose;bob 必须逐个 repair

## Implementation notes

- **soland 已落地**:`ak.realm.profile` 完整值更新不产生 bottom diagnostics;admin bottom diagnostics 在没有标准 bottom producer 时返回空数组。
- **inkson 已落地**:Realm admin repair 区当前不 mint 未注册的 `ak.conflict.repair`,无 bottom 时保持只读空态。
- **测试侧已激活**:offline outbox / pending reconcile 在 `sync/offline-queue-replay` live 覆盖;本 scenario 覆盖因果有序 title update 的单值语义与 read-only repair surface。同 Seal sibling 的 `cas_conflict` / defer 义务由 control-state conformance vectors 覆盖。
- **剩余边界**:outbox capacity、标准 bottom producer、bottom 状态下再写拒绝、篡改 witness 拒绝、多个 bottom cell 排序仍保留为后续边界 fixme。

## 总耗时预估

约 90s。
