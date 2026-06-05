# `history_visibility=world_readable` 未加入也能读历史

## 目标

messaging/triad-collaboration 主流程的小变种:验证 `world_readable` 这个 history_visibility 选项 — **未加入** space 的 actor 应当能通过 `/timeline/<spaceId>` 看历史消息(适用于公开公告板 / 社区入口 space)。

## Spec 锚点

- `models/space-and-place.md` §3.4 — `history_visibility` 与 `default_join_rule` 交叉表
- `models/space-and-place.md` §3.7 — 加密与隐私(non-E2EE 才允许 world_readable)

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 状态 |
|---|---|
| alice | space owner |
| bob | member |
| outsider | **未加入** space,验证 world_readable |
| anonymous | **未登录** 任何账号,验证 anon read |

## Steps

1. alice createRealm `S_open`,`discoverability=public`,`join_rule=public`,`history_visibility=world_readable`
2. alice 邀请 bob 后 bob acceptInvite;两人交换若干消息 `M1..M5`
3. **outsider**(已登录,非成员)访问 `/timeline/<S_open>` 或 API `GET /_soland/self/spaces/<S_open>/events`
4. 断言:outsider 看得到 `M1..M5`(world_readable 允许)
5. **anonymous**(没有 session token)访问 same endpoint
6. 断言:也能看到(spec §3.7 world_readable 允许非加密 spaces 的匿名读)
7. outsider 尝试**发** 消息(非成员)
8. 断言:capability 拒(world_readable 只允许读,写要求 join)

## Edge cases

- **E1.3.1 E2EE space 中 world_readable 应不可设**:试 `encryption_profile=mls_rfc9420` + `history_visibility=world_readable` → reducer 拒,reason `incompatible_history_with_encryption`
- **E1.3.2 world_readable 改 joined 后**:已经被 anon 读过的事件还能再读吗?spec 倾向于把 history_visibility 变更视为前向语义,旧事件不撤回

## Implementation notes

- **soland 缺口**:`history_visibility=world_readable` 的 API authz 跳过(可能默认 require auth);anon endpoint 接入
- **yougen 缺口**:anon 访问 `/timeline/:id` 路由(当前要求 session token)

## 总耗时预估

约 30s。
