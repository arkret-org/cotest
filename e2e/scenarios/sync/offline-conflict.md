# 离线编辑 / 重连同步 / 冲突修复

## 目标

bob 在网络断开时编辑(本地 outbox);重连后 sync 上传所有 pending move;若离线期间 alice 改了同 cell,冲突进入 bottom diagnostics。当前规范还没有注册可由 yougen 提交的 repair event kind,所以 Realm admin 只读展示 bottom 诊断;人工 repair 通过后续 CKP 注册的标准事件恢复。

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
4. bob 在 yougen 中尝试发消息 `M_b_offline`
5. yougen 客户端:看到网络错误,把 move 写入本地 outbox(IndexedDB / localStorage)
6. UI 显示 `M_b_offline` 标 "pending sync" (`pending-sync-message` testid)
7. 同时 alice 在线发 `M_a_online`

### Phase C — bob 重连

8. `page.context().setOffline(false)`
9. bob 客户端检测网络恢复 → 自动 flush outbox 到 soland
10. 断言:30s 内 `M_b_offline` 状态从 pending 变 persisted;UI 标记移除
11. 断言:alice 和 bob 双方都看到 `M_a_online` 和 `M_b_offline`

### Phase D — 制造同 cell 冲突

12. alice 和 bob 都在网,但模拟一次极短"双方都基于相同 frontier 写 same cell"的情形:
    - 测试 harness 用 `route.fulfill` 拦掉双方 sync 请求 5s
    - alice 提交 `ck.space.update { title: "renamed by alice" }`
    - bob 提交 `ck.space.update { title: "renamed by bob" }`
    - 取消拦截 → 两条 move 都到 soland,但因为都基于旧 frontier,reducer 检测到 cas-register 冲突
13. soland 把该 cell 标 `bottom_expose`,并通过 admin bottom diagnostics 暴露未决 cell
14. 断言:`GET /_soland/admin/realms/<S>/bottom` 返回 kind=`conflict` 且 cell_id 指向 `cx.component.realm.organization.v1`

### Phase E — repair 仍为只读诊断

15. 断言:yougen 不渲染 `prefer-safer-side-button`、`repair-target-cell-input`、`repair-winner-json-input`、`repair-submit-button`
16. 断言:`GET /_soland/admin/realms/<S>/bottom` 仍返回该 bottom cell,直到标准 repair event kind 注册并被实现
17. 备注:后续 CKP 注册 repair kind 后,本阶段再升级为提交标准 repair Move 并验证 cell 回到 active

### Phase F — Backfill via pull

20. (sub-test)假设 bob 离线很久,本地缺很多 events;重连后先用 `GET /_cokret/self/account/subscribe?after=<old>&catchup=true`,缺口再用 `GET /_cokret/self/events?after=<old>`
21. 断言:bob timeline 自动补齐离线期间的所有消息

## Edge cases

- **E26.1 outbox 满**:bob 长期离线,outbox 满;客户端 UI 显示 "Too many pending changes, please reconnect"
- **E26.2 冲突未决期间再写**:Phase D 后 cell 还在 bottom_expose,bob 再尝试写该 cell → reducer 拒,reason `cell_bottom_state`,UI 提示必须先 repair
- **E26.3 repair Move 被拒**:等待标准 repair event kind 注册后恢复;测试 harness 让 bob 提交 repair 但 `state_witness` 篡改 → reducer 拒,bottom 诊断保留
- **E26.4 重连后冲突 + 排序**:多个 cell 同时 bottom_expose;bob 必须逐个 repair

## Implementation notes

- **soland 已落地**:`ck.realm.update` 同 anchor basis 的 cas-register 冲突进入 `bottom=expose`;admin bottom diagnostics 可列出未决 cell。
- **yougen 已落地**:sync 解析 bottom diagnostics;Realm admin repair 区当前只读展示冲突,不再 mint 未注册的 `ck.conflict.repair`。
- **测试侧已激活**:offline outbox / pending reconcile 在 `sync/offline-queue-replay` live 覆盖;本 scenario 的 `bottom_expose` diagnostics 与 read-only repair surface 为 live。
- **剩余边界**:outbox capacity、bottom 状态下再写拒绝、篡改 witness 拒绝、多个 bottom cell 排序仍保留为后续边界 fixme。

## 总耗时预估

约 90s。
