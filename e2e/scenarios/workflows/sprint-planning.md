# Sprint Planning Workflow

## 目标

技术 lead Mei 在一个 sprint 启动会上和两个工程师(Bob、Carol)共同规划一周的工作:开 sprint Realm → 介绍 user stories → 在 kanban 上把 backlog 卡片承诺到 Todo → 每个人挑一张 → 在 timeline 上互相 ack。

这是个把"messaging + kanban + 多用户协调"串成真实使用流程的综合测试。

## Spec 锚点

- `models/realm-and-space.md` §2-§4 (Space lifecycle / Board / List)
- `models/strand-and-message.md` §8 (reply chain)

## 拓扑

1 × coland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| mei | tech lead,Realm owner |
| bob | engineer |
| carol | engineer |

## Steps

### Phase A — Sprint kickoff Realm

1. Mei `createRealm` `"Sprint 24"`,seed Bob 和 Carol
2. Bob、Carol `acceptInvite`
3. Mei 发 timeline 消息 `"Sprint 24 starts now — pick a Backlog card and reply with your choice."`
4. 两个工程师都收到这条消息(timeline contains)

### Phase B — kanban: backlog + todo + doing + done

5. Mei 进 `/kanban`,建 4 列:`Backlog`、`Todo`、`Doing`、`Done`
6. Mei 在 `Backlog` 列加 5 张卡:
   - `Story A: User auth strand`
   - `Story B: Payment gateway integration`
   - `Story C: Analytics dashboard`
   - `Story D: Email templates refactor`
   - `Story E: Performance hotfix`

### Phase C — 每人挑一张

7. Mei "承诺"前 3 张:依次 archive `Story A` / `Story B` / `Story C` 出 Backlog,然后在 `Todo` 列加同名卡。这模拟 "move Backlog → Todo"(inkson 目前没有 cross-column move,所以走 archive + recreate)
8. Bob 在 timeline 回 `"I'll take Story A."` (reply to Mei's kickoff)
9. Carol 在 timeline 回 `"I'll grab Story B."` (reply to Mei's kickoff)
10. Mei 在 timeline 回 `"I'll cover Story C. Let's regroup Friday."`

### Phase D — 三人状态一致

11. Bob/Carol/Mei 各自 reload `/kanban/${realmId}`,都看到:
    - `Backlog`:`Story D` + `Story E`
    - `Todo`:`Story A` + `Story B` + `Story C`
    - archived list:`Story A` + `Story B` + `Story C`(因为是 archive + recreate)
12. 三人都看到 4 条 timeline 消息(kickoff + 三条 ack)

## Observable assertions

- 步骤 7:Backlog 有 2 张,Todo 有 3 张,archived 列有 3 张
- 步骤 10:Mei 视图能看到 Bob、Carol 的 reply(reply-indicator)
- 步骤 11:Bob/Carol fresh `/kanban/:realmId` mount 都通过 server projection hydrate 同一个 board id、4 个 column 与 Backlog 中的 story cards

## Edge cases

- **E-sprint.1** 真正的 cross-column move(不是 archive 再加):inkson 拖拽支持 / 需要 causal-register move API
- **E-sprint.2** 一个工程师把承诺的卡 archive 掉(等价 "我不做了"),timeline 应当通知 Mei
- **E-sprint.3** Mei 在 sprint 结束时 archive 整个 Sprint board(批量归档)

## 总耗时预估

约 60-90 秒(多 column + 多 card + 多 reply)。
