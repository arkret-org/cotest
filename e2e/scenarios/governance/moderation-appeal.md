# Moderation appeal

## 目标

验证 moderation decision 被用户申诉后的完整状态机和关键负向约束:提交申诉、管理员接手复审、作出 verdict、关闭申诉;同一个 moderator 不能复审自己作出的 decision;重复 active appeal 必须拒绝;overturn 必须配套 decision lift。

## Spec 锚点

- `arkret-spec/spec/v1/zh/governance/content-moderation.md` — moderation appeal 和职责分离
- `arkret-spec/spec/v1/zh/models/governance-objects.md` — moderation decision / appeal event family
- `arkret-spec/spec/v1/zh/sync/operations-sync.md` — durable event / state transition 语义

## 拓扑

- 1 × soland Station
- actors:
  - appellant:被 moderation decision 影响并提交 appeal
  - moderator:签发原始 moderation decision
  - reviewer:接手 appeal review / decision / close

## Steps

1. appellant / moderator / reviewer 注册并获取 dev session。
2. moderator 创建 Realm,加入 appellant / reviewer;appellant 写入一条 target message。
3. moderator 通过 `POST /_arkret/self/events` 提交 `ak.moderation.decision`。
4. appellant 通过 `POST /_arkret/self/events` 提交 `ak.moderation.appeal.submit`。
5. reviewer 通过 `POST /_arkret/self/events` 依次提交:
   - `ak.moderation.appeal.review`
   - `ak.moderation.appeal.decision`
   - `ak.moderation.appeal.close`
6. `GET /_soland/admin/moderation/appeals/{appeal_id}` 是实现私有只读投影,返回四段 history,状态依次为 `submitted → under_review → decided → closed`。

## Negative paths

- 原 moderator 复审自己的 decision 必须失败。
- active appeal 重复提交必须返回 conflict。
- `decision` 在 `review` 前调用必须失败。
- `close` 在 `decision` 前调用必须失败。
- `verdict=overturn` 未带 paired lift 必须失败。
- 带 decision lift 后 `verdict=overturn` 可进入 decided。
