# 个人 blocklist (client-side filter)

## 目标

验证用户**个人 blocklist** 的端到端语义:alice 把 bob 的完整 ActorId 加入个人 blocklist 后，bob 的消息不再在 alice 的 timeline / notifications 中渲染(client-side filter)；unblock 后可见性恢复；blocklist 记录走 actor-private encrypted account_data 跨设备 sync。跨服务器场景继续收取 canonical Event，且不得把 block 状态或命中结果泄露给 federation peer。

不验证(明确区分):
- Realm-level ban / kick / quarantine — 那是**服务端**对内容/成员的强制隔离,见 `spaces/moderation-ban`、`governance/content-moderation` 的 quarantine 流程
- mute(通知静默,消息仍可见)— 见 `discovery/notifications.md`

## Spec 锚点

- `arkret-spec/spec/v1/zh/discovery/client-preferences.md` §3.5–§3.5.1 — `ak.account.blocklist`
  的唯一结构、精确 ActorId 匹配、receive-before-filter、隐私和解除语义
- `arkret-spec/spec/v1/zh/governance/content-moderation.md` §4 — Personal blocklist 与共享 Realm
  moderation / federation 的边界

## 拓扑

- Phase A–F:1 × coland (Station) + 1 × coauth(单服务器即可覆盖个人 blocklist 主流程)
- Phase G:2 × coland (`server1`、`server2`) + 共享 coauth — 用于验证 federation 隐私与收取边界

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s31-<uuid>.example` | 执行 block 的 user | 测试开始前 |
| bob | `did:webvh:z6mkfixture:bob-s31-<uuid>.example` | 被 block 的 user;同 Realm 成员 | 测试开始前 |

## Pre-conditions

- alice / bob 都通过 `POST /_coland/self/account/register` 注册
- alice / bob 都持有有效 dev session token
- 两个 actor 的 browser context 都注入了 `inkson.config.v1` localStorage

## Steps

### Phase A — 注册 + 共享 Realm

1. alice、bob 注册
2. **alice** 通过 `/setup` 建 Realm `R`(`discoverability=listed`、`join_rule=invite`、`history_access=since_join`、`seed_members=[bob.did]`)
3. **bob** acceptInvite(`S`);双方都能进 `/timeline/${realmId}`

### Phase B — bob 发 M1,alice 可见(基线)

4. **bob** 进 `/timeline/${realmId}`,发 `M1 = "bob says hi ${stamp}"`
5. **alice** 进 `/timeline/${realmId}` 同步
   - 断言:`timeline-event` 含 `M1` 文本
   - 这是 baseline:未 block 时一切正常

### Phase C — alice 进 settings 把 bob 加入 blocklist

6. **alice** 进 `/settings/blocked-users`
   - 断言:`blocked-users-panel` 可见;`blocked-users-list` 渲染(可能为空)
7. **alice** 在 `block-target-input` 填 bob 的完整 composite ActorId(JSON,
   `{"kind":"account","account_id":{"principal_id","station_id"}}`),点 `block-user-button`
   - `client-preferences.md` §3.5 的机读 schema `account_blocklist_payload` 要求
     `target.actor_id` 是完整 ActorId；裸 principal DID 命名不出 Station，不能作为 target。
     service 自身作为发送者时也使用 `kind=actor` 加 `ActorId.service`；不得按 Organization、
     Realm、托管 Station 或转发 service 关系隐式扩张规则。
   - 断言:`blocked-users-list` 新增一条 `blocked-user-row`,显示 bob.handle / bob.did
   - 断言:`write-status` 含 `blocklist updated` 或等效文本

### Phase D — client 提交 account_data blocklist event

8. alice 的 inkson client 应该把这次 block 持久化为 coland 的 actor-private account_data event:
   - 调用:`POST /_arkret/self/events`,提交 `ak.account_data.set`,payload `{ key: "ak.account.blocklist", owner: alice.did, body: <ak.schema.account_data_encrypted_value.v1 envelope>, updated_at: <ts> }`
   - 断言 (HTTP 层):events submit 返回 `status=accepted`
   - 断言 (跨设备 sync):`GET /_arkret/self/account/subscribe?catchup=true` 的 `account_data.events` 返回不透明 carrier / marker, 且不包含 bob DID 明文
   - 备注:这是 actor-private — 只对 alice 自己的 device 同步,bob 拿不到

### Phase E — bob 发 M2,alice 看不到(client-side filter)

9. **bob** 进 `/timeline/${realmId}`,发 `M2 = "bob says hi again ${stamp}"`
   - bob 自己的 timeline 上 `M2` 正常显示(他不知道被 alice block 了)
10. **alice** 同步 `/timeline/${realmId}`
    - 断言:`timeline-event` **不含** `M2`(client-side filter 按 bob 的 exact ActorId 过滤)
    - `M1` / `M2` 都仍被正常收取、验证和保留；默认视图是否显示旧内容由 entry 的 mode/surface
      投影决定，不得在网络层丢弃
11. **alice** 进 `/notifications`
    - 断言:`notifications-panel` 中没有 bob 在 Phase E 发的 `M2` 通知

### Phase F — unblock 恢复可见

12. **alice** 回 `/settings/blocked-users`,在 bob 那行点 `unblock-button`
    - 断言:`blocked-users-list` 不再含 bob 行
    - 断言:client 提交下一 revision 的完整 `ak.account_data.set` value，并从 `entries` 中省略该 entry；
      不存在 `kind: "unblock"` 增量事件
13. **bob** 再发 `M3 = "bob is back ${stamp}"`
14. **alice** sync `/timeline/${realmId}`
    - 断言:`timeline-event` 含 `M3`
    - 断言:在 retention 仍保留的前提下，Phase E 的 `M2` 重新可见；解除只重算 holder projection，
      不补写曾在网络层丢弃的数据

### Phase G — Federation 隐私与收取边界

15. 拓扑切到 2 server:`alice@server1`、`bob@server2`,通过 federation peering 共享 Realm `R_fed`
16. **alice@server1** 在 `/settings/blocked-users` 中 block `bob@server2`
17. server1 只同步 alice 的 holder-private encrypted account data：
    - 不得向 server2 发送 block hint、blocklist event 或 `alice → bob` 的命中结果
    - server2 不得知道 alice 屏蔽了 bob，也不得据此停止 canonical Realm Event 的 federation
18. **bob@server2** 在 `S_fed` 发 `M_fed`
19. 断言:
    - `M_fed` 仍正常 federation 到 server1，并由 alice 的客户端收取、验证和保留
    - alice 的默认 timeline 在本地按 bob 的 exact ActorId 隐藏 `M_fed`
    - 只有经 alice 显式授权读取 blocklist 明文的 holder-private confidential service 才可替她抑制 push；
      普通 Station / federation peer 不得通过猜测或明文 hint 执行过滤

## Observable assertions(合并清单)

- Phase B 步骤 5:alice 在 block 之前能看到 `M1`
- Phase C 步骤 7:`blocked-users-list` 新增 bob 行
- Phase D 步骤 8:`ak.account_data.set` 与 `ak.self.account.stream.subscribe.v1` 返回不透明私有 account_data, 且不泄露 block target 明文
- Phase E 步骤 10:alice timeline 不含 `M2`
- Phase E 步骤 11:alice notifications 不含 `M2` 通知
- Phase F 步骤 12-14:unblock 后 `M3` 可见
- Phase G 步骤 19:server2 不获知 block 命中且继续 federation canonical Event；alice client 收取后仍过滤 `M_fed`

## Edge cases / sub-tests

- **E11.1 Quarantine vs block**:同一个 Realm 中 admin 把 bob 的某条消息 quarantine(`POST /_arkret/self/moderation/quarantine`)— 这是**服务端**操作,影响**所有**成员;alice 的个人 block 只影响 alice 自己。验证两者**互不依赖**:即使 alice 没 block bob,quarantine 的消息对 alice 也不可见(以 placeholder 渲染);即使 admin 没 quarantine,alice block 也能让 bob 的消息对 alice 单独不可见。
- **E11.2 mute vs block 差异**:alice 在 `/settings/notifications` 把 bob mute(不是 block)→ bob 的消息在 alice timeline **仍可见**,但 push notification 不送达(`notifications-panel` 中无新条目)。这与 block 的"完全隐藏"形成对照。
- **E11.3 被 block 的用户视角**:bob 在 `/timeline/${realmId}` 自己看自己的消息,M1/M2/M3 都正常显示,`write-status` 全部 `persisted`;bob 的 `/notifications` 不会出现"You were blocked by alice"这类提示(spec §4 明确:block 不可被被 block 方探测,反 social-graph 泄露)。
- **E11.4 account_data overwrite**:同一 `client.*` account_data_key 重复 `PUT /_arkret/self/account_data/{account_data_key}` 只保留最新 `content`;direct GET/list 与 `ak.self.account.stream.subscribe.v1` 都只能看到一个最新 entry。

## Implementation notes

- **inkson 实现**:`/settings/blocked-users` 页面已写入 `LocalStateStore::client_blocklist` 并通过 `ak.account.blocklist` account_data 同步;`blocked-users-panel` / `blocked-users-list` / `blocked-user-row` / `block-target-input` / `block-user-button` / `unblock-button` / `write-status` testids 已接入。
- **coland 实现**:`ak.account_data.set` + `ak.self.account.stream.subscribe.v1` 已用于个人 blocklist;普通 Sync Service 不读取 encrypted/opaque blocklist 明文,只同步 holder-private carrier。客户端本地 timeline / notifications 负责最终过滤;只有显式授权的 holder-private confidential service 才能做服务器侧 target 过滤。
- **测试侧**:主流程、E11.1、E11.2、E11.3、E11.4 均为 live tests；Phase G 需要双 coland harness
  同时观察 federation receive 与 alice 本地 projection，不能用明文 hint 或远端 outbox suppression 代替。

## 风险

- Phase G 尚未被单服务器主流程覆盖；增加双服务器断言时，必须同时证明远端不获知 block 命中、
  canonical Event 仍被收取，以及 holder 默认视图在本地过滤。
- 主流程的 block / unblock / receive-before-filter 是 MUST；规范不定义 federation block hint。

## 总耗时预估

约 60-90s(单服务器主流程);Phase G federation 子测试加 30-45s。
