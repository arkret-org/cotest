# Team Onboarding Workflow

## 目标

模拟一个真实场景:Mei(经理)给新人 Yuki 做入职引导。串联 Realm 创建、邀请、timeline 消息(reply + edit)和 kanban 任务列表。这是一个综合性的"day-1 onboarding"流程,目的是让多个已经可用的原语在同一个用户故事里跑通。

不验证:profile 注册细节、多设备配对、E2EE。

## Spec 锚点

- `models/realm-and-space.md` §2-§3 — Realm 生命周期、Join Policy、Space container
- `models/strand-and-message.md` §8 — Message reply/edit
- `models/realm-and-space.md` §4 — Space / Board / List

## 拓扑

- 1 × coland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| mei | 经理,Realm owner |
| yuki | 新人,Phase A 接受邀请 |

## Steps

### Phase A — Mei 准备入职 Realm

1. Mei `createRealm` `"Welcome to the team"`,`joinRule = invite`,`seedMembers = [yuki.did]`
2. Yuki `acceptInvite`
3. Mei 通过显式 `ak.capability.grant` 授予 Yuki Realm 范围的 `ak.message.create`；membership 本身不作为授权来源（`authz/capabilities.md` §3.2）
4. Mei 进 timeline,发 `"Hi Yuki, welcome aboard! Ping me if anything blocks you."`
5. Yuki 回复 Mei 的欢迎消息:`"Thanks Mei — happy to be here."`
6. Mei 在自己的欢迎消息上 edit,补充入职日链接:`"Hi Yuki, welcome aboard! Ping me if anything blocks you. (Onboarding hub: https://corp.example/onboarding)"`

### Phase B — Mei 用 kanban 列出入职任务

6. Mei 进 `/kanban`,加三列:`Today`、`This week`、`Done`
7. 在 `Today` 列加两张卡:`"Set up dev laptop"`、`"Read the team handbook"`
8. 在 `This week` 列加两张卡:`"1:1 with each teammate"`、`"Submit first PR"`

### Phase C — Yuki 跑完一天

9. Yuki 进 `/kanban`(同 Realm),看到 Mei 建的四张卡
10. Yuki archive `"Set up dev laptop"`(完成了)
11. Mei 在 timeline 发 `"Great progress today — see you tomorrow"`
12. Yuki 回复 `"Will do, see you tomorrow!"`

## Observable assertions

- Phase A 步骤 4:Yuki 的 reply 在 Mei 视图带 `reply-indicator`
- Phase A 步骤 5:Mei 视图能看到编辑后的文字 + `write-status` 含 `revised`
- Phase B 步骤 7-8:四张卡分别落在两列
- Phase C 步骤 10:`"Set up dev laptop"` 不再在 active 列,但在 `kanban-archived-card-row` 里
- Phase C 步骤 12:Mei 视图看到 Yuki 的 reply

## Edge cases

- **E-onboarding.1** Yuki 在 `This week` 列也 archive 一张,确认两列的 archive 各自独立
- **E-onboarding.2** Mei restore `"Set up dev laptop"`(看错了 archive),卡回到 `Today`
- **E-onboarding.3** Mei 编辑 timeline 欢迎消息两次,write-status 计数器 `revised x2`(需要 inkson 暴露 revision count)

## 总耗时预估

约 45-60 秒。
