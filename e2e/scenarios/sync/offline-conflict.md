# 离线编辑 / 重连同步 / 冲突修复

## 目标

bob 在网络断开时编辑(本地 outbox);重连后 sync 上传所有 pending move;若离线期间 alice 改了同 cell,冲突进 `bottom_cells_banner`;bob 在 `/space/:id/admin/repair` 用 `prefer-safer-side` 决议;最终 alice/bob 两端收敛。

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

1. alice createSpace,seedMembers=[bob],bob acceptInvite
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
13. soland 把该 cell 标 `bottom_expose`,生成 `bottom_cells_banner` 数据
14. 断言:bob `/space/<S>/admin` 进入 → `bottom-cells-banner` 可见;`bottom-cell-row` 显示该 cell 的两个 head

### Phase E — bob 用 prefer-safer-side 决议

15. bob 点 `prefer-safer-side-button`(对应 member.state 或 cell 安全侧)
16. yougen 客户端把 `repair-winner-json-input` 填好(spec 安全语义)
17. bob 提交 repair Move,reducer 接受 → cell 回到 `active`
18. 断言:banner 消失;cell value 是 "safer" 那一方
19. alice 拉 sync → 看到 cell 现在的 value;她那侧的 banner 也消失

### Phase F — Backfill via pull

20. (sub-test)假设 bob 离线很久,本地缺很多 events;重连后先用 `GET /_cokret/self/account/subscribe?after=<old>&catchup=true`,缺口再用 `GET /_cokret/self/events?after=<old>`
21. 断言:bob timeline 自动补齐离线期间的所有消息

## Edge cases

- **E26.1 outbox 满**:bob 长期离线,outbox 满;客户端 UI 显示 "Too many pending changes, please reconnect"
- **E26.2 冲突未决期间再写**:Phase D 后 cell 还在 bottom_expose,bob 再尝试写该 cell → reducer 拒,reason `cell_bottom_state`,UI 提示必须先 repair
- **E26.3 repair Move 被拒**:测试 harness 让 bob 提交 prefer-safer-side 但 `state_witness` 篡改 → reducer 拒,banner 留着
- **E26.4 重连后冲突 + 排序**:多个 cell 同时 bottom_expose;bob 必须逐个 repair

## Implementation notes

- **soland 已落地**:`ck.realm.update` 同 anchor basis 的 cas-register 冲突进入 `bottom=expose`;`ck.conflict.repair` 验证 `conflict_heads`、`state_witness` / recovery capability shape 后清理 bottom;account sync 输出 `anchor_view.bottom_cells`。
- **yougen 已落地**:sync 解析 `anchor_view.bottom_cells`;admin repair UI 为 realm organization conflict 填充 safer-side winner;repair Move 使用当前 session actor 提交。
- **测试侧已激活**:offline outbox / pending reconcile 在 `sync/offline-queue-replay` live 覆盖;本 scenario 的 `bottom_expose` 与 `prefer-safer-side-button` repair 流程已从 fixme 升为 live。
- **剩余边界**:outbox capacity、bottom 状态下再写拒绝、篡改 witness 拒绝、多个 bottom cell 排序仍保留为后续边界 fixme。

## 总耗时预估

约 90s。
