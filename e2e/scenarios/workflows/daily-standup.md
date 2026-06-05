# Async Daily Standup Workflow

## 目标

模拟 3 人小队的异步晨会:每人在 timeline 上发自己的"Yesterday / Today / Blockers",然后互相 reply 解决 blockers。最后,有人意识到自己写错了 ETA 并 edit。

这个 scenario 关注:多用户并发往同一个 space 写 + reply chain 在 messages-from-different-actors 间的交错。

## Spec 锚点

- `models/flow-and-message.md` §8 (reply / edit)
- `models/realm-and-space.md` §2 (Space)

## 拓扑

1 × soland + 1 × coauth

## Actors

3 个工程师:Lin / Pat / Quincy。Lin owns the space。

## Steps

### Phase A — 准备 standup space

1. Lin createRealm `"Team Daily"`,seed Pat + Quincy(每天都是同一个 space,但我们 stamp 让每次 e2e 跑用一个新的)
2. Pat、Quincy acceptInvite

### Phase B — 三个人陆续 post

3. Lin 发自己的 standup:
   ```
   [Standup] Yesterday: shipped onboarding. Today: code review. Blockers: none.
   ```
4. Pat 发:
   ```
   [Standup] Yesterday: kanban bug. Today: deploy fix. Blockers: need Lin's review on PR #88.
   ```
5. Quincy 发:
   ```
   [Standup] Yesterday: design draft. Today: write tests. Blockers: ETA on test infra?
   ```

### Phase C — Lin 解 Pat 的 blocker

6. Lin reply Pat:`"Reviewing PR #88 now, ack in 30min."`

### Phase D — Pat 解 Quincy 的 blocker

7. Pat reply Quincy:`"Test infra lands by EOD."`

### Phase E — Pat 改自己 ETA

8. Pat 意识到不是 EOD 而是明天,edit 步骤 7 的回复:`"Test infra lands by EOD. ACTUALLY: tomorrow noon, sorry."`
9. Quincy 视图看到 edited 版本

## Observable assertions

- 三条 standup 都在 timeline 上;每条都来自正确的 actor(DID 不同)
- Lin 的 reply 在 Pat 视图带 `reply-indicator`
- Pat 的 reply 在 Quincy 视图带 `reply-indicator`
- Pat 编辑过后 timeline 含 "ACTUALLY: tomorrow noon" 字样

## Edge cases

- **E-standup.1** Pat 写完准备发的时候断网 — 离线 outbox(需要 sync 完整)
- **E-standup.2** Lin 发完之后立即 redact 自己 standup(写错了 standup 模板)— tombstone 显示
- **E-standup.3** 4 个人 standup,timeline 滚动到底部锚定行为 — UI 体验

## 总耗时预估

约 40-50 秒。
