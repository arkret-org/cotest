# 项目模拟(多用户 board + assignees + due dates + status FSM + reorder + archive)

## 目标

kanban/end-to-end 的多用户进阶版:三个用户(alice 项目经理 + bob/carol 开发)在一个 Realm 内运行一个完整 sprint 节奏 —— alice 建 board、把任务 assign 给 bob/carol、设 due dates、bob/carol 自己更新 status 推进任务到 done、alice 跨列移动逾期任务、最终 alice archive board。每一步对应一个 spec 事件,并验证 cas-register 的并发安全和 relation 的 cardinality 约束。

不验证:基础 kanban CRUD(kanban/end-to-end 已覆盖)、加密(encryption/mls-group)。

## Spec 锚点

- `models/realm-and-space.md` §3.5 — 自动解析 join 路径(bob/carol 通过 claim 或 invite 加入)
- `models/realm-and-space.md` §4 — Space
- `models/strand-and-message.md` §3 — Strand 字段(`fields.status`、`fields.due_date`)
- `models/relation.md` §3.2 — `assigned_to` cardinality(many_to_many,但同一 actor only one active assignment per strand)
- `models/relation.md` §6 — 并发 assignment 的冲突解决(`deterministic_winner` profile)
- `authz/event-auth-state-resolution.md` §3.2 — Effect: fsm 转换 + multi-cell Moves

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | PM,Realm owner |
| bob | dev,Phase B 加入,负责 Card 1 / Card 3 |
| carol | dev,Phase B 加入,负责 Card 2 |

## Steps

### Phase A — alice 建 sprint board

1. alice createRealm `"Sprint 24"`,`joinRule = invite`
2. alice 建 board `"Sprint 24 board"`(`ak.space.create kind=board`)
3. 建三个 list:`Todo`、`In Progress`、`Done`
4. 建三张 Card:
   - `Card 1: "Implement login"` (fields: status=todo, due_date=2026-05-20)
   - `Card 2: "Write tests"` (fields: status=todo, due_date=2026-05-22)
   - `Card 3: "Deploy staging"` (fields: status=todo, due_date=2026-05-23)
5. 全部初始放在 `Todo` 列

### Phase B — bob 和 carol 加入

6. alice `inviteFromAdmin` 邀请 bob、carol
7. bob、carol `acceptInvite`
8. 断言:三人都在 Realm 成员列表

### Phase C — alice 分配 Cards

9. alice 在 Card 1 详情点 "Assign" → 选 bob.did → 提交 `ak.relation.create`:`{ relation_kind: "assigned_to", source: Card1.strand_id, target: bob.did, fields: { role: "primary" } }`
10. 同理 alice 把 Card 2 分给 carol,Card 3 分给 bob
11. 断言:Card 1 / Card 3 卡片上显示 bob 的头像;Card 2 显示 carol 的头像
12. 断言:bob 进 inkson,`/notifications` 或 dashboard 显示"You were assigned to: Card 1, Card 3"

### Phase D — bob 推进 Card 1 进度(status FSM)

13. bob 在 Card 1 点 "Move to In Progress"
14. inkson 提交两个动作:
    - `ak.strand.move` 把 Card 1 从 `Todo.child_order` 挪到 `InProgress.child_order`
    - `ak.strand.update`:`fields.status = "in_progress"`,这是 FSM 转换(spec §3.2 Effect: fsm)
15. 若 inkson 把 status 建模为独立 FSM cell(`ak:cell:ak.component.strand.status_fsm.v1`),precondition 是 `from=todo`、effect `to=in_progress`
16. 断言:Card 1 在 InProgress 列;alice/bob/carol 三方视图一致
17. bob 继续 → `in_progress → done`

### Phase E — carol 推进 Card 2

18. carol 同样把 Card 2 从 todo → in_progress
19. carol 半天后再 → done
20. 断言:Done 列含 Card 1 + Card 2

### Phase F — alice 跨列拖动逾期 Card 3

21. 假设当前日期 = 2026-05-24(测试用 env stub system time;或不严格,只要 due_date 在 today 之前即可)
22. alice 注意到 Card 3 仍在 Todo,逾期
23. alice 把 Card 3 直接拖到 In Progress(跳过 status FSM 显式更新?)— 取决于 inkson 是否要求 FSM transition
24. 若 inkson 强 enforce,alice 必须先点 "Move to In Progress" 按钮触发 FSM;若 inkson 让 drag 自由,drag 自动触发 `fields.status = in_progress`
25. bob 收到通知 / Card 3 旁红色逾期标记

### Phase G — 并发 assignment 冲突

26. 测试 harness 用两个 alice session(等价于 alice 在两台设备并发):
    - 设备 1:alice 把 Card 2 从 carol 改成 bob
    - 设备 2(同时):alice 把 Card 2 从 carol 改成 alice 自己
27. 两条 `ak.relation.create` 并发到 soland
28. 按 spec §6:relation profile `on_conflict = deterministic_winner` → reducer 仅接受一条(HLC 大者赢),另一条 rejected
29. 断言:Card 2 的最终 assignee 是 deterministic 的(测试可以读 HLC 知道),不出现两个 active assignment

### Phase H — Board archive

30. sprint 结束,alice 在 board 视图点 "Archive board"
31. inkson 提交 `ak.space.update`:`fields.state = "archived"`(或 cascade Move)
32. 断言:board 主视图不再列出 Sprint 24 board;archive view 中能找到
33. 断言:archived board 内的 cards / lists 仍然存在但 read-only(spec §4.4 cascade rules)

## Observable assertions(合并)

- Phase A 步骤 5:三张 Card 落地
- Phase B 步骤 8:三人都是成员
- Phase C 步骤 11-12:assignment 渲染 + bob 收到通知
- Phase D 步骤 17:Card 1 → Done
- Phase F 步骤 25:逾期标记
- Phase G 步骤 29:并发 assignment 收敛
- Phase H 步骤 32:archive 行为

## Edge cases / sub-tests

- **E16.1 unassign**:alice 撤销 Card 1 的 bob assignment → `ak.relation.tombstone`(spec §3.2 tombstoned 状态);bob 视图 Card 1 不再标"assigned to me"
- **E16.2 bob 离职**:alice 把 bob ban 出 Realm(`ak.member.state{ban}`)→ bob 名下的 cards 怎么办?spec 不强 cascade;inkson 可能把 assignment 显示为 "orphaned"
- **E16.3 status FSM 非法转换**:bob 尝试 Card 1 直接从 todo 跳到 done(跳过 in_progress)→ FSM precondition 失败,reducer 拒(spec §3.8 类比 membership FSM)
- **E16.4 due date 修改**:alice 改 Card 3 的 due_date,所有 actor 视图更新
- **E16.5 board search / filter**:在 archive 之前,搜 "Implement" 应找到 Card 1;archive 之后看 archive filter 是否过滤
- **E16.6 多设备实时同步**:alice 在 device-1 改 Card 1 status;device-2 应在 ~1s 内看到变化(sync push)

## Implementation notes

- **soland 缺口**:`ak.relation.create assigned_to`、`ak.space.update state=archived`、cascade rules — 多数 partial。Strand `fields.status` FSM 已由 `ak.strand.update` reducer preflight 覆盖(todo → in_progress → done、investigating → mitigated → resolved)
- **inkson 缺口**:assignment UI、due date picker、archive board 按钮、逾期红色标记、`assigned-to-actor` testid
- **测试侧难点**:Phase G 需要并发提交,Playwright 的 single-context 比较难;可能要用 fetch API 直接打 soland 模拟双设备

## 总耗时预估

约 2-3 分钟(多用户 + 多 Card + sync 等待)。
