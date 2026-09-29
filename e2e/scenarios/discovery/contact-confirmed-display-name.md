# 联系人确认显示名与 petname 优先

## 目标

holder 侧身份确认闭环：authorized profile resolve → 首次显式确认 → 对方改名后的提醒与旧确认值 →
holder 显式刷新快照。同时证明 `petname` 不随对方改名变化，且 profile 写入不隐式发布 Directory。

## Spec 锚点

- `discovery/profiles-presence.md` §2.3 — 全局 Profile 只经 `ak.self.actor_profile.read.resolve.v1` 对外
- `discovery/client-preferences.md` §3.6 — `petname` / `confirmed_display_name` 语义、显示优先级、改名提示
- `sync/service-http-binding.md` §5.1 — profile create/update 自服务面与证明边界

## 拓扑

- 1 × soland + 1 × coauth，alice 走浏览器；bob 只在创建 Direct Conversation 时开浏览器，其余走 API

## Actors

| 名字 | 角色 |
|---|---|
| alice | holder：确认身份、设置备注名、处理改名提醒 |
| bob | 被确认方：author profile create / update |

## Steps

1. alice、bob 注册；两人通过 API 完成 contact request → accept。accept 本身不创建共享 Realm：
   normal 分支的 founder 是 responder bob，由 bob 的客户端打开 Direct Conversation 行并提交 founding unit
   （`identity/contact-and-direct-conversation.md` §5.2 / §5.5），该 Realm 才是 resolve 的授权基础。
   Contact UI 不参与本场景的前置，避免联系人界面失败时整段被 skip。
2. bob 以 `ak.profile.create` 发布 `display_name = D1`（API）。
3. alice 打开 `/settings/contacts`：该行显示经 resolve 取得的 live profile display `D1`
   （`contact-profile-display-<peer>`），并出现首次确认入口 `contact-confirm-identity-<peer>`。
4. alice 点 `contact-confirm-name-<peer>` → `confirmed_display_name = D1`；首次确认入口消失。
5. alice 保存备注名 `P`（`contact-petname-<peer>` + `contact-petname-save-<peer>`）；
   断言备注名角标出现，`confirmed_display_name` 未被覆盖。
6. bob 以 `ak.profile.update` 把 `display_name` 改为 `D2`（API，delta patch）。
7. alice 重新打开该页：出现 `contact-display-name-changed-<peer>`，正文同时含旧确认值 `D1` 与当前 `D2`；
   备注名输入框仍为 `P`（petname 不随对方改名变化）。
8. alice 点 `contact-confirm-name-<peer>` → 提醒消失，`confirmed_display_name = D2`，备注名仍为 `P`。

## Edge cases

- **profile 不可达**：无共同 Realm 时既不显示提醒也不显示首次确认入口，状态是 unknown，不得伪报 changed。
- **Directory 正交**：current-v1 Directory 没有 actor/profile 查询，因此 profile 写入不会形成
  Directory 可发现性能力。

## Implementation notes

- 前置全部走 `contact-api.ts` 的 `requestContactArkret` / `respondContactArkret`，profile 走
  `/_arkret/self/account/profile`；只有确认与备注名交互在浏览器里完成。
- confusable 比较基准集同时纳入 `petname` 与 `confirmed_display_name`，由
  `ak.vector.encoding.confusable_check.v1` 与 inkson 单元测试闭合，不在本场景重复。

## 总耗时预估

约 90s。
