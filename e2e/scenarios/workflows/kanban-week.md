# Kanban Week-in-Review Workflow

## 目标

一个用户(产品经理 Pat)用 kanban 走完一个工作日:开 space → 建 Today/Doing/Done 三列 → 加四张任务 → 把已完成的卡 archive 出 Today → 一张误 archive 的卡 restore 回 Today。

这是 kanban end-to-end 的真实使用流程版,关注"一周/一天日常管理"模式而不是单纯的 CRUD 测试。单用户避开当前的 kanban 跨用户同步缺口。

## Spec 锚点

- `models/realm-and-space.md` §3 (Space container / Board / List)
- `common-fields.md` §5.1 (lifecycle / archive cascade)

## 拓扑

1 × coland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| pat | 产品经理(单用户) |

## Steps

### Phase A — 起 board

1. Pat createRealm `"Week 21 ops"`
2. 进 `/kanban`,建三列 `Today` / `Doing` / `Done`

### Phase B — 计划当日任务

3. `Today` 列加 4 张卡:
   - `Triage support inbox`
   - `Review PR backlog`
   - `Spec the Q4 roadmap doc`
   - `Plan tomorrow's standup agenda`

### Phase C — 完成两张

4. archive `Triage support inbox`(完成)
5. archive `Plan tomorrow's standup agenda`(完成)
6. 断言:`Today` 列还剩两张;archive 列有那两张

### Phase D — 误 archive,restore 回来

7. archive `Review PR backlog`(以为完了,其实没)
8. 立刻在 archive 列找到那张,点 restore
9. 断言:`Today` 列又有 `Review PR backlog`,且 rank 顺序仍在 `Spec the Q4 roadmap doc` 之前

### Phase E — 整列 archive / restore cascade

10. archive `Today` list
11. 断言:`Today` list 进入 archived-lists,`Review PR backlog` 与 `Spec the Q4 roadmap doc` 的 Strand projection state 变为 `archived`
12. restore `Today` list
13. 断言:`Today` list 回到 board,两张卡 Strand projection state 回到 `active`,rank 字段未丢失

## Observable assertions

- 步骤 3:Today 列有 4 张
- 步骤 6:Today 列 2 张,archive 列 2 张
- 步骤 9:restore 后 Today 列 3 张(`Review PR backlog` 回来),顺序仍按原 rank
- 步骤 11-13:整列 archive / restore 级联卡片 lifecycle,且 restore 后保留原 rank

## Edge cases

- **E-kanbanweek.1** restore 后卡顺序按原 rank 保留
- **E-kanbanweek.2** archive list (整列归档) 级联到 contained cards
- **E-kanbanweek.3** Pat 改名一张卡(card title edit)— 需要 card-detail-modal 里有 edit 入口

## 总耗时预估

约 30-45 秒。
