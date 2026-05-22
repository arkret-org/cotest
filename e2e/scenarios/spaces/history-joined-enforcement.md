# `history_visibility=joined` 加入前历史不可读

## 目标

验证 `history_visibility=joined` 在服务端读路径真实生效:成员只能读取自己加入之后的消息,不能因为已经是成员就回看加入前历史。

## Spec 锚点

- `models/space-and-place.md` §3.4 — `history_visibility=joined`
- `models/realm-and-space.md` §2.6 — Realm 创建者是 bootstrap owner
- `models/events.md` — `cx.events.query` / `cx.events.subscribe`

## 拓扑

- 1 × soland

## Actors

| 名字  | 状态                                    |
| ----- | --------------------------------------- |
| alice | Realm owner,写入历史消息                |
| bob   | late member,加入后只能读 post-join 消息 |

## Steps

1. Alice 通过 `POST /api/v1/events` 创建 public + `history_visibility=joined` Realm。
2. Alice 写入 5 条 pre-join `cx.message.create`。
3. Alice 提交 `cx.member.state{membership=join}` 让 Bob 加入。
4. Alice 写入 post-join 消息。
5. Bob 调 `GET /api/v1/events?realms=<realm>`。
6. 断言:Bob 只看到 post-join 消息,看不到 5 条 pre-join 消息。
7. Alice 调同一路径,断言 owner 仍看到完整历史。
8. 对照组:`history_visibility=shared` 下 late member 可以读 pre-join 消息。
9. Streaming 读路径 `account/subscribe` 与 `events/subscribe` 同样不泄漏 pre-join 消息。

## Edge cases

- Bob 的 join 事件必须产生真实 joined_at 投影;普通成员不能回退到 Realm 创建时间。
- Owner 可以回退到 Realm 创建时间,否则 bootstrap owner 会丢失初始历史。

## Implementation notes

- 不使用旧 `/api/v1/spaces` mutation,测试全程走 canonical `POST /api/v1/events`。
- `cx.member.state` 用 `delivery_status=unroutable` 让 reducer 记录 joined_at,但不要求 DID delivery binding。
- `@blocking-on: soland#history-visibility-read-path` 已在测试文件保留,作为曾经的服务端缺口标记。
