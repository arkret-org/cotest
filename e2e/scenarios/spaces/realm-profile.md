# Realm 资料修改

## 目标

验证 Realm owner 从 Inkson 管理页修改 title/summary，并通过完整 `ak.realm.profile` replacement 清除可选 summary。刷新后的 UI 投影必须一致。

## Spec 锚点

- `models/realm-and-space.md`：Realm profile 字段与 owner 权限。
- `models/event-and-patch.md`：Realm profile singleton 的 `head_eq` CAS replacement。

## 流程与断言

1. 用户从 Inkson UI 创建 Realm 并进入 Profile 管理面。
2. 修改 title 与 summary，保存并等待 Soland 接受 `ak.realm.profile`。
3. 刷新 UI，断言 title 与 summary 保持。
4. 清空 summary 再保存，断言新完整 payload 省略 summary，且 `head_eq` 前态仍携旧 summary；再次刷新后 summary 保持为空。

## Evidence 边界

Realm create/profile write 与刷新后的投影均由 Inkson 表面产生；`GET /_arkret/self/realms/{realm_id}` 按 spec 只返回 lifecycle view，不被误用为 profile oracle。身份建立使用 session injection，不声明注册/登录 UI 覆盖。
