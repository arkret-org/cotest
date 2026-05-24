# Read marker(私有已读位置)生命周期

## 目标

验证 actor-private read marker(read position)在 alice 多设备之间通过 to-device 通道收敛到一致,
派生的 client-side notification(inbox 投影)随之消长;最终 `mark-all-read` 在任一设备触发后,
另一设备在 sync 窗口内 unread count 归零。

不验证:server-side 持久化的 read receipt 事件(read marker 是 actor-private account data,**不是**
durable Event;见 `models/private-objects.md` §2);notification 的 push fan-out 与 push prefs / DnD
(见 discovery/notifications);MLS epoch 推进与 device 撤销(见 identity/multi-device)。

## Spec 锚点

- `contrix-spec/spec/v1/zh/models/private-objects.md` §2 — Private object 总览:read marker 属于
  actor-scope account data;与 Event 链解耦,只在 actor 自己的 device 之间复制
- `contrix-spec/spec/v1/zh/models/private-objects.md` §3 — Read marker schema(`last_read_at` 时间锚 +
  optional `last_read_anchor` event_id);to-device propagation;eventual consistency 窗口
- `contrix-spec/spec/v1/zh/discovery/read-receipts.md` — server 不持久化 per-message read state;
  marker 是单点游标,inbox unread 一律由 marker 衍生
- `contrix-spec/spec/v1/zh/discovery/push-notifications.md` §2-§4 — notification 是 client-side
  projection,read marker 推进后该 device 的 inbox 清零
- `contrix-spec/spec/v1/zh/crypto-media/device-lifecycle.md` §7 — to-device queue,marker 同步走这条
  通道

## 拓扑

- 1 × soland (principal server) — 监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth;alice 两台 device 都从这个 coauth 取 access token

(cotest 现有 harness 已经提供这套拓扑,不需要改 `scripts/run-joint-e2e.ps1`。)

## Actors

| 名字 | 设备 | DID / device_id | 角色 |
|---|---|---|---|
| alice | alice-device-1 (laptop) | `did:web:alice-s11-<uuid>.example` / `cx:device:...-d1` | reader,首次记录 read marker |
| alice | alice-device-2 (phone)  | 同上 actor,不同 device_id `cx:device:...-d2` | 第二台 device,接收 to-device 同步;最后触发 mark-all-read |
| bob   | bob 默认设备            | `did:web:bob-s11-<uuid>.example`              | sender,在共享 space 里发 M1/M2/M3/M4 |

## Pre-conditions

- alice 和 bob 的 DID 都通过 `POST /api/v1/account/register` 注册过
- alice 两台 device 各持一个有效 dev session token(`POST /api/v1/auth/dev-login`,actor 相同、
  `device_id` 不同 — 沿用 `identity/multi-device` Phase A 的 dev-login proxy)
- bob 持有效 dev session token
- 三个 browser context 都通过 `yougen.config.v1` localStorage 注入 server_url + account_did +
  device_id + session_token

## Steps

### Phase A — Baseline:注册 + 多设备 + 共享 space

1. 注册 alice / bob;为 alice 通过 `issueDevSession` 取两个 token —— 对应 alice-device-1 与
   alice-device-2(参考 `identity/multi-device` Phase A,真实 QR 配对 + cross-signing 还未上线,
   这里复用 dev-login 双 token 作为代理)
2. alice (device-1) 通过 `/setup` 多步向导建空间 `S`:
   - title = `"models/private-read-cursor S ${stamp}"`
   - discoverability = `listed`,join_rule = `invite`,history_visibility = `joined`
   - seed_members = `[bob.did]`
3. 断言:`space-lifecycle-flow` 含 `created cx:space:...`,记录 `spaceId`
4. bob 通过 `acceptInvite(spaceId)` 加入空间

### Phase B — bob 发 M1, M2, M3

5. bob 进 `/timeline/${spaceId}`,顺序发 `M1 = "bob M1 ${stamp}"`、`M2 = "bob M2 ${stamp}"`、
   `M3 = "bob M3 ${stamp}"`
6. 断言:三条都 `write-status` 含 `persisted`

### Phase C — alice device-1 读取并记录 read marker(到 M2)

7. alice (device-1) 进 `/timeline/${spaceId}`,等到 `timeline-event` 至少含 M1/M2/M3
8. alice (device-1) 把视口滚到 M2(`scrollIntoView`),停留到 yougen 触发 read-position 上报
9. 客户端通过 `POST /api/v1/account/data/m.read_cursor`(account data API,private object 写路径)
   推 marker,payload 含 `last_read_at = <ts(M2)>` + `last_read_anchor = M2.event_id`
   - 备用路径:直接 `POST /api/v1/notifications/mark-all-read` 把游标推到 M2(参考 spec §3 的
     "marker write" 等价接口)
10. 断言:`GET /api/v1/notifications` 返回 `last_read_at` 等于步骤 9 写入的 ts,
    `unread_count` 反映"M3 是未读、M1/M2 已读"

### Phase D — alice device-1 settings 显示 marker 位置

11. alice (device-1) 进 `/settings`(或 `/settings/read-position`)
12. 断言:settings 面板显示 "Last read in S: M2"(测试用 testid `read-position-row` / 文本含 `M2`)

### Phase E — alice device-2 通过 to-device 收到 marker

13. alice (device-2) 打开第二个 browser context,进 `/settings`(`gotoSettings()`)
14. 等待 sync 窗口(测试上界 30s);yougen 应通过 to-device 同步把 marker 落到本地
15. 断言:device-2 的 settings 也显示 "Last read in S: M2"
16. 断言:device-2 的 `GET /api/v1/notifications` `last_read_at` 与 device-1 一致

### Phase F — bob 发 M4,两台 device 的 inbox 都显示未读

17. bob 发 `M4 = "bob M4 ${stamp}"`
18. 断言:device-1 进 `/notifications` 后,M4 出现在 inbox(`notifications-panel` 含 M4 文本);
    `unread_count = 1`
19. 断言:device-2 同样在 `/notifications` 看到 M4;`unread_count = 1`

### Phase G — alice device-2 mark-all-read,device-1 在 sync 后归零

20. alice (device-2) `POST /api/v1/notifications/mark-all-read`,断言 200 + `marked_at` >
    Phase C 的 marker ts
21. 断言:device-2 `GET /api/v1/notifications` `unread_count = 0`,`last_read_at = marked_at`
22. 等待 to-device 同步窗口(测试上界 30s)
23. 断言:device-1 `GET /api/v1/notifications` `unread_count = 0`,`last_read_at` 与 device-2 收敛
    到同一 `marked_at`

## Observable assertions(合并清单)

- Phase A 步骤 3:`spaceId` 形如 `cx:space:...`
- Phase B 步骤 6:M1/M2/M3 三条都 persisted
- Phase C 步骤 10:`last_read_at` 写入成功,`unread_count` 反映 M3 未读
- Phase D 步骤 12:device-1 settings 上 marker 文本可见
- Phase E 步骤 15-16:device-2 settings + notifications API 与 device-1 收敛
- Phase F 步骤 18-19:新消息 M4 在两台 device 都计入 unread
- Phase G 步骤 23:device-2 触发 mark-all-read 后,device-1 在 sync 窗口内 `unread_count = 0`

## Edge cases / sub-tests

- **E10.1 multi-device read marker eventual consistency**:device-1 写 marker → device-2 收到
  marker 之间允许有一个有界窗口(spec §3:30s);窗口内 device-2 的 `last_read_at` MAY 落后,但
  最终一定收敛到 device-1 写入的最新值
- **E10.2 E2EE space 中 notification 脱敏**:把 `spaceId` 切到一个 `encryption_locus =
  per_space_mls` 的 space;bob 发的 M4 在 server 侧 payload 是密文,但 server 仍能投递 to-device
  wake;notification 投影由 client 在解密后产生 — 测试断言 server `GET /api/v1/notifications` 不
  暴露明文 body,只暴露 envelope 元数据(event_id、sender_did、ts、`encrypted: true`)
- **E10.3 discussion realm 的 read marker 独立于 parent space**:在 space `S` 下开 discussion realm
  `D`(`POST /api/v1/spaces/${spaceId}/discussions`,realm linkage 见 `models/realm-links.md`);
  alice 在 `D` 里把 marker 推到一条 `D.M1`,但 `S` 的 marker 保持在 M2;断言两个 marker 在
  account data 里以**不同 key**存储(`m.read_cursor:${realm_id}`),互不污染

## Implementation notes

- **soland gap(关键)**:read marker 的 **to-device propagation** 当前未实现 — `POST
  /api/v1/account/data/m.read_cursor` 与 `POST /api/v1/notifications/mark-all-read` 在 alice 当前
  device 上写 account_data OK,但 device 间的 fan-out(to-device channel)不通,因此 Phase E /
  Phase G 的 cross-device 断言会 fail。主流程标 `test.fixme`,内联注释说明 gap
- **soland 现状**:`POST /api/v1/notifications/mark-all-read` 已 live(参考 `discovery/notifications`
  spec),`GET /api/v1/notifications` 返回 `last_read_at` / `unread_count` 也 live —— 单 device 的
  marker 写 / 读路径已可断言,可作为非 fixme 的子测试
- **yougen gap**:`/settings` 当前没有 `read-position-row` testid;Phase D / E 的 UI 断言依赖该
  testid 上线后才能跑(或者改成纯 API 断言绕过)
- **multi-device dev-login proxy**:沿用 `identity/multi-device` Phase A 的做法 — 对同一 actor 调
  `dev-login` 两次得到两个 session token(可能相同也可能不同),分别注入两个 browser context
- **E2EE 子测试(E10.2)**:cotest 当前没有可靠的 "create encrypted space" 入口;先标 fixme,等
  encryption realm scenario 提供 helper 再补
- **discussion realm 子测试(E10.3)**:依赖 discussion realm 的 e2e helper / API(spec `models/realm-
  links.md`),目前未实装,标 fixme

## 总耗时预估

主流程跑通后约 90s-2 分钟(3 个 browser context、7 阶段、~20 步);当前因 to-device gap 主流程
fixme,实际执行时间由非 fixme 子断言决定(< 20s)。
