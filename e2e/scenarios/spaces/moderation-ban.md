# 审核封禁与脱敏

## 目标

验证独立的 Realm 审核能力：无权限成员不能封禁他人；Realm owner 可以提交
`ak.member.state{membership="ban"}`，被封成员的后续写入被拒；owner 可以通过
`ak.message.redact` 脱敏既有内容。个人 blocklist 仍是 Actor-Private 本地状态。

## Spec 锚点

- `governance/content-moderation.md`：审核能力、个人屏蔽和内容脱敏
- `ak.member.state{membership="ban"}`：成员封禁
- `ak.message.redact`：消息脱敏

## 场景

1. alice 创建 Realm，bob、mallory、carol 加入。
2. mallory 发布一条消息。
3. bob 尝试封禁 mallory，服务以 `capability_denied` 拒绝且不写入状态。
4. alice 封禁 mallory；成员投影不再包含 mallory。
5. mallory 尝试继续发消息，服务拒绝该写入。
6. alice 脱敏原消息；alice、bob、carol 的公开时间线均不再含原文。
7. 重复提交同状态 ban，以 `failed_precondition/invalid_membership_transition` 拒绝。
8. 在 Inkson Realm 成员管理页执行 owner ban，验证 UI 与服务端成员投影一致。

## 可观察断言

- 非 moderator 的 ban 不产生持久化变化。
- owner ban 后，被封成员不在成员列表中且不能写入。
- redact 后所有可见视图都不泄露原正文。
- 重复 ban 不重复写入，也不会恢复被封成员。
- Inkson 管理成员行可以完成同一条 canonical ban 路径。
