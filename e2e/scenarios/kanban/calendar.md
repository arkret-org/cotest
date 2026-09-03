# Calendar schedule 与 RSVP

## 目标

验证 Calendar 不是独立对象/API，而是由 Inkson 在 Card Strand 上激活 `ak.schema.calendar_event.v1`、写入 `metadata.fields.calendar`，并通过 `ak.rsvp.set` 表达回应。

## Spec 锚点

- `models/calendar-event.md` §1–§4：schema ref 与 calendar 子树双向共现、required core、timezone/recurrence。
- `models/calendar-event.md` §8–§9：RSVP authoring 与本地投影。
- `models/strand-and-message.md`：Calendar 的对象载体仍是 Strand。

## 流程与断言

1. 用户通过 Inkson 创建 Realm，并由 Realm owner 经 Admin/Security 为自己授予 `ak.rsvp.set` capability。
2. 用户创建 Board、List 与 Card。
3. 在 Card detail 添加 start/end、`Asia/Shanghai`、location 和 weekly recurrence。
4. 断言 Inkson 产生且 Soland 接受 `ak.strand.update`，wire 同时携带 calendar schema requirement 与 schedule 数据。
5. 断言 UI 显示 schedule，再次打开编辑器时字段保持。
6. 对整个 series 选择 Accept，断言携带显式 capability 的 `ak.rsvp.set` 被接受，UI 投影为 `You: accepted` 和 `1 yes`。

## Evidence 边界

所有业务对象与 Event 均由 Inkson 产生；身份建立使用 session injection，因此不声明注册/登录 UI 覆盖。
