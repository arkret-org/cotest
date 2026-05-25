# Kanban 端到端(Board / List / Card / Drag / Archive / Comments)

## 目标

验证 kanban 完整 CRUD 与跨 list 拖拽:alice 在 space 内建 Board (Place);加 List (Place children);加 Card (Flow);跨 List 拖动 Card(`cx.flow.move` cas-register);archive Card;在 Card 内发 comment(discussion track)。

不验证:多用户协作(见 kanban/project-simulation)、跨 board 移动(后续)、文档编辑(documents/collaboration)。

## Spec 锚点

- `models/space-and-place.md` §4 — Place 概念(Board / List 等结构容器)
- `models/space-and-place.md` §4.2 — Place schema
- `models/space-and-place.md` §4.5 — `cx.place.parent` cas-register basis
- `models/space-and-place.md` §4.6 — `cx.flow.move` / `cx.flow.reorder` cas-register basis(防止并发移动)
- `models/space-and-place.md` §4.7 — Board / List 示例
- `models/flow-and-message.md` §2-§3 — Flow 概念 + schema(state、fields)
- `models/flow-and-message.md` §4.3 — Discussion track(per-Flow 评论)
- `models/relation.md` §3.2 — `contains` 关系(Place 含 Flow,cardinality)

## 拓扑

- 1 × soland + 1 × coauth + 1 × yougen

## Actors

| 名字 | 角色 |
|---|---|
| alice | space 创建者,kanban 主驱动 |

(单用户即可覆盖 kanban CRUD;多用户工作流见 kanban/project-simulation)

## Steps

### Phase A — Setup space

1. alice createSpace,`title = "Kanban kanban/end-to-end"`,`discoverability = listed`,`joinRule = invite`,seedMembers=[]

### Phase B — 建 Board

2. alice 进 `/kanban`(或 space-scoped `/spaces/${spaceId}/kanban`,看 yougen 实现)
3. 点 "New Board" → 填名字 `"Sprint 23"`
4. yougen 提交 `cx.place.create`:`{ space_id, kind: "board", title }`
5. 断言:`/kanban` 页面渲染 board 卡片(`board-card` testid),title 是 `"Sprint 23"`,记录 `boardId`

### Phase C — 加三个 List

6. alice 进 board,点 "Add list" 三次,分别命名 `Todo`、`In Progress`、`Done`
7. 每次 yougen 提交 `cx.place.create`:`{ kind: "list", parent_place: boardId, title }`
8. 内部:更新 `cx:cell:cx.component.place.child_order.v1:<boardId>` (ordered-log) 记录三个 list 的顺序
9. 断言:board 视图渲染三列(`list-column` testid × 3),按创建顺序排列

### Phase D — 在 Todo 加两个 Card

10. alice 在 `Todo` 列点 "Add card",填 title `"Card A"`、description `"first task"`
11. yougen 提交 `cx.flow.create`:`{ space_id, title, content: {text}, fields: { status: "todo" } }`,然后 `cx.relation.create` 把 flow 关到 List(`relation_kind: contains`)
12. 同样建 `"Card B"` 在 Todo 列
13. 断言:Todo 列渲染两张卡片(`flow-card` testid × 2),按创建顺序

### Phase E — 拖动 Card A 到 In Progress

14. alice drag-and-drop `"Card A"` 从 Todo 拖到 In Progress 列
15. yougen 客户端:
    - 提交 `cx.flow.move`(Move kind,cas-register)
    - precondition:Card A 当前在 `Todo` list 的 `child_order` cell 中(state_witness)
    - effect:从 `Todo.child_order` 移除,插入 `InProgress.child_order` 末尾
    - 可选同时 `cx.flow.update.fields = { status: "in_progress" }`
16. soland reducer 接受 → 双 cell 更新原子
17. 断言:刷新后 Card A 在 In Progress 列,Todo 列只剩 Card B
18. 断言:`fields.status` 字段也更新

### Phase F — Card 内发 comment

19. alice 点 Card A 进详情(`/spaces/${spaceId}/kanban/cards/${flowId}` 或类似)
20. 进 Discussion 区,发 `"Started this morning"`
21. yougen 提交 `cx.message.create`,`flow_id = flowId_of_card_A`,落到 Flow 的 discussion track
22. 断言:Card A 详情页 Comments 区显示该消息(`discussion-message` testid)

### Phase G — Archive Card

23. alice 在 Card A 详情点 "Archive"
24. yougen 提交 `cx.flow.update`:`fields.state = "archived"`(或 Move)
25. 断言:Card A 在 board 主视图消失(被 archive filter 过滤);进 archive 视图能看到 (`archived-card` testid)
26. 断言:Card A 的 discussion track 仍存在;`cx.message.create` 不再允许在 archived flow(spec §4.6 archived 状态的写入约束)

### Phase H — Reorder list

27. alice 在 board 视图把 `Done` 列拖到 `Todo` 之前
28. yougen 提交 `cx.place.reorder`(或 `cx.flow.move` 等价),更新 `boardId` 的 `child_order` cell
29. 断言:刷新后列序变 `Done / Todo / In Progress`

## Observable assertions(合并)

- Phase B 步骤 5:board 创建成功,boardId 持久化
- Phase C 步骤 9:三列按序渲染
- Phase D 步骤 13:Todo 含两卡
- Phase E 步骤 17-18:跨列移动 + status 更新
- Phase F 步骤 22:Card 内 comment 渲染
- Phase G 步骤 25:archive 行为正确
- Phase H 步骤 29:列 reorder 持久

## Edge cases / sub-tests

- **E15.1 并发跨列移动**:alice 在 device-1 把 Card A 拖到 In Progress;同时(测试 harness 用另一 session)alice 在 device-2 把 Card A 拖到 Done → cas-register 仅允许一个 winner,另一个 Move 被拒(reason `cas_register_conflict`)。客户端 UI 显示 "card moved by another device, please refresh"
- **E15.2 cross-space contains**:alice 尝试把 board 在 `S_a` 的 Card 加到 `S_b` 的 list → reducer 拒绝,reason `cross_space_structural_relation` (spec §3.2)
- **E15.3 archive list**:alice archive `Todo` 列 → 列内现存 Card 怎么办?spec 没明说,看 yougen 行为(可能 cascade archive,可能拒绝 archive 非空列)
- **E15.4 delete board**:有 cards / lists → cascade delete 应当按 spec §4.4 的 lifecycle/cascade 规则;测试 alice 删 board,断言所有 children 都失效(`is_deleted` 状态)
- **E15.5 Discussion in archived flow**:Phase G 之后再尝试发 comment → reducer 拒绝;客户端 UI 显示 "Card archived, cannot comment"
- **E15.6 Drag 自己回原列**:alice drag Card A 从 Todo 拖出再放回 Todo → Move 应当是 no-op 或返回当前位置,不报错

## Implementation notes

- **soland 缺口**:`cx.place.create/reorder/archive`、`cx.flow.move` cas-register、`cx:cell:cx.component.place.child_order.v1` ordered-log、archive cascade — 大概率 partial 实现
- **yougen**:`/kanban` 视图已稳定 `kanban-column`、`column-drag-handle`、`column-drop-target-before`、`kanban-column-title` 与本地列重排；server `child_order` 持久化仍由 P1-031 覆盖。
- **harness**:Playwright 的 drag-and-drop 用 `locator.dragTo(target)`;但 dioxus 的拖拽可能需要 mouse event sequence(`mouse.down`/`mouse.move`/`mouse.up`)

## 总耗时预估

约 60-90s。
