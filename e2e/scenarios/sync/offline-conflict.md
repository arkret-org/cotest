# 离线编辑 / 重连同步 / 冲突修复

## 目标

bob 在网络断开时编辑(本地 outbox);重连后 sync 上传所有 pending move。Realm title / metadata 的并发 `ck.realm.update` 不属于当前规范注册的 bottom producer,不得把它当作 `bottom_expose` 冲突来源。当前规范还没有注册可由 inkson 提交的 repair event kind,所以 Realm admin 的 repair 区保持只读,不渲染未注册的修复提交控件。

## Spec 锚点

- `sync/client-sync.md` §2 — Sync 协议 + cursor
- `sync/operations-sync.md` §2 — Conflict resolution via Lattice join
- `sync/operations-sync.md` §2.1 — `bottom_cells` 暴露
- `authz/event-auth-state-resolution.md` §2 — Bottom cell diagnostics
- `authz/event-auth-state-resolution.md` §8.1 — 冲突恢复 Move(`state_witness` / `inclusion_proof`)

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 在线,持续编辑 |
| bob | 离线编辑,后重连 |

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

### Phase D — 并发 title update 不产生 bottom

12. alice 和 bob 都在网,测试 harness 直接提交两条同 anchor basis 的 `ck.realm.update { patch.title }`
13. soland 接受/归并 Realm metadata 更新,但不得把 title patch 投影为 `cx.component.realm.organization.v1` 的 cas-register bottom
14. 断言:`GET /_soland/admin/realms/<S>/bottom` 返回空数组

### Phase E — repair 区仍为只读

15. 断言:inkson 不渲染 `prefer-safer-side-button`、`repair-target-cell-input`、`repair-winner-json-input`、`repair-submit-button`
16. 断言:`GET /_soland/admin/realms/<S>/bottom` 仍为空,直到有标准 bottom producer 与 repair event kind 注册并被实现
17. 备注:后续 CKP 注册 repair kind 后,本阶段再升级为提交标准 repair Move 并验证目标 cell 回到 active

### Phase F — Backfill via pull

20. (sub-test)假设 bob 离线很久,本地缺很多 events;重连后先用 `GET /_cokret/self/account/subscribe?after=<old>&catchup=true`,缺口再用 `GET /_cokret/self/events?after=<old>`
21. 断言:bob timeline 自动补齐离线期间的所有消息

## Edge cases

- **E26.1 outbox 满**:bob 长期离线,outbox 满;客户端 UI 显示 "Too many pending changes, please reconnect"
- **E26.2 冲突未决期间再写**:Phase D 后 cell 还在 bottom_expose,bob 再尝试写该 cell → reducer 拒,reason `cell_bottom_state`,UI 提示必须先 repair
- **E26.3 repair Move 被拒**:等待标准 repair event kind 注册后恢复;测试 harness 让 bob 提交 repair 但 `state_witness` 篡改 → reducer 拒,bottom 诊断保留
- **E26.4 重连后冲突 + 排序**:多个 cell 同时 bottom_expose;bob 必须逐个 repair

## Implementation notes

- **soland 已落地**:`ck.realm.update` title patch 不产生 bottom diagnostics;admin bottom diagnostics 在没有标准 bottom producer 时返回空数组。
- **inkson 已落地**:Realm admin repair 区当前不 mint 未注册的 `ck.conflict.repair`,无 bottom 时保持只读空态。
- **测试侧已激活**:offline outbox / pending reconcile 在 `sync/offline-queue-replay` live 覆盖;本 scenario 覆盖并发 title update 的 non-bottom 语义与 read-only repair surface。
- **剩余边界**:outbox capacity、标准 bottom producer、bottom 状态下再写拒绝、篡改 witness 拒绝、多个 bottom cell 排序仍保留为后续边界 fixme。

## 总耗时预估

约 90s。
