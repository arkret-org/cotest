# 跨服务器联邦

## 目标

验证两个独立 Station 之间的联邦链路:跨服务器定向邀请、被邀方经自己 Station 加入、双向消息、committed replication、
按 stream 的 peer scan 恢复,以及成员退出后停止 fanout。信任根是 producer 签名 Event + 治理 Station 签发的
RealmCommit + RFC 9421 HTTP Message Signature;单一服务器不是全局权威。

不验证:第三方邮件邀请 (后续 invites/third-party,本 scenario 用 DID-to-DID 直接邀请)、moderation (spaces/moderation-ban)。

## Spec 锚点

- `arkret-spec/spec/v1/zh/sync/federation.md` §3 — 复制单元是单条 stream 的 `(RealmCommit, Event)`;非治理接收方以治理签名为准;`QUERY peer/events` 不属于 v1
- `arkret-spec/spec/v1/zh/sync/federation.md` §3.2 — 服务签名先于任何内层对象处理
- `arkret-spec/spec/v1/zh/sync/federation.md` §4.1.1 — fanout 目标 = effective joined 成员的 routing service;`committed_replication` 分支;接收方重验本机托管成员资格
- `arkret-spec/spec/v1/zh/sync/federation.md` §5.3.1 — invite 只携 locator candidate,由自己 Station 验证 nonce-bound bundle
- `arkret-spec/spec/v1/zh/sync/invite-addressing.md` §7 — 定向邀请以 `ak.account.invite_delivery` account data 送达;§7.1 加入预览/准备的权威来源
- `arkret-spec/spec/v1/zh/sync/api-conventions.md` Event submit 幂等 — `replication_outcomes[]` 与 `replications[]` 同序,没有顶层 `accepted[]`／`duplicate[]`
- `authority-commit-operations.schema.json#/$defs/peer_submit_request`、`#/$defs/stream_scan_request`

## Steps

### Phase A — alice@server1 创建 Realm + 跨域 invite

1. **alice** 通过 server1 的 inkson 进 `/setup`,建 Realm `R`:
   - discoverability = `listed`
   - join_rule = `invite`
   - history_access = `since_join`
   - seed_members = `[]`(本次不在创建阶段邀,改用空间管理面 invite 流程,这样能精确捕获 `ak.invite.create` 事件)
2. 记录 `realmId`
3. **alice** 进 `/realms/${realmId}/admin`,通过 `invite-member` 邀请 `bob.did`
   - 在 server1 侧产生 `ak.invite.create` Event,subject_did = bob.did
4. 断言:server1 侧 `realm-admin-panel` 显示 `invited bob.did`

### Phase B — 定向邀请送达 server2

5. server1 经 `ak.self.invites.command.dispatch.v1` 把 invite 投递到 bob 的 Station (`POST /_arkret/peer/invites`)
6. server2 按 bob 的 invite receive policy 写入 `ak.account.invite_delivery`,entry 携 `authority_locator_hints`
7. 断言:bob 在 server2 的 account data 中读到该 delivery entry(server2 不持有 Invite 对象,也不在加入前持有 Realm)

### Phase C — bob@server2 经自己 Station 加入

8. bob 以 delivery entry 的 hints 调 server2 的 `self/realm-joins/prepare`;server2 取回并验证 server1 的 nonce-bound bundle
9. bob 签署 `ak.invite.accept`(`previous_state=pending`、`invitee_account_id`)提交给 server2,由它 `authority_forward` 到 server1
10. server1 接纳并签发 RealmCommit;精确重放同一 Event 返回 `duplicate`
11. 断言:server1 上成员列表含 bob 的完整 AccountId

### Phase D — 双向消息推送

15. **alice** (在 server1) 进 `/timeline/${realmId}` 发 `M_a = "alice from server1 ${stamp}"`
    - server1 上 reducer 接受,push 到 server2
16. 断言:server2 那边 bob 进 `/timeline/${realmId}` 后 30s 内 timeline 含 `M_a`
17. **bob** (在 server2) 发 `M_b = "bob from server2 ${stamp}"`
    - server2 上 reducer 接受,push 到 server1
18. 断言:server1 那边 alice 30s 内 timeline 含 `M_b`
19. (Edit + redact 子流程可选;主要验证传播方向,不重复 messaging/triad-collaboration 的 message 内部细节)

### Phase E — Committed replication 与 peer scan

20. 加入前,harness 以 server1 身份把 Realm bootstrap 的精确 `(RealmCommit, Event)` 送到 server2 的
    `committed_replication`:server2 不托管 joined 成员,每项 `rejected` 且零写
21. 加入后,harness 以 server2 身份对 server1 做 `ak.peer.committed_event.read.scan.v1`,取到消息的 Commit 行;
    送回 server2 为 `duplicate`,精确重放仍为 `duplicate`
22. 恢复用例:同一 scan 行经 `committed_replication` 送到 server2 为 `stored` 或 `duplicate`,server2 上只物化一次

### Phase F — 成员退出后停止 fanout

23. bob 在 server2 签署 `ak.member.state{leave}`,经 server2 转发到 server1
24. **alice** 再发 `M_after_leave`
25. 断言:server1 已接纳该消息,server2 不持有其 Commit(bob 的 committed-event 读取为 404)

## Observable assertions (合并清单)

- 步骤 7:定向邀请以 account data 送达 server2
- 步骤 10-11:own-Station 加入被 server1 提交,server1 视图中 bob 是 member
- 步骤 16、18:两边消息双向 30s 内可见
- 步骤 20:无托管成员的 Station 逐项拒绝 committed replication
- 步骤 21-22:peer scan + committed replication 幂等,不重复物化
- 步骤 25:成员退出后不再向 server2 fanout

## Edge cases / sub-tests

- **E2.5 signature 失败**:篡改 server1 的 HTTP signature header,server2 整批拒绝;断言 4xx + 不可区分的认证失败 envelope
- **未签名 peer scan**:缺少 RFC 9421 签名的 `POST /_arkret/peer/streams/scan` 被拒绝(<500)

## Implementation notes — harness 改动

这是这条 scenario 最关键的部分,scripts/run-joint-e2e.ps1 需要扩展:

1. **双 soland 启动**:
   - 当前 script 只起一个 soland。需要参数化:`-SolandInstances 2` 或新加参数 `-Soland2Manifest`、`-Soland2BaseUrl`
   - 每个 soland 自己的 service DID、自己的 service_id 配置、自己的 objects root 目录
   - coauth 的 `arkret.stations[]` 配置要包含两个 soland 的 entry
2. **soland 之间的联邦发现**:
   - 需要 soland 支持 "已知 federation peers" 配置(看 soland 实现是 env var 还是 config)
   - 或者 soland 通过 DID Document 中 `type="ArkretService"` 且
     `serviceKind="station"` 的 service entry 自动发现
   - **依赖 soland**:这条 scenario 在 soland 不能联邦的情况下无法跑
3. **环境变量**给测试用:
   - `COTEST_SOLAND_SERVER1_BASE_URL` / `COTEST_SOLAND_SERVER1_SERVICE_ID`
   - `COTEST_SOLAND_SERVER2_BASE_URL` / `COTEST_SOLAND_SERVER2_SERVICE_ID`
4. **新 helper**:
   - `openUserPage(browser, user, { server: "server1" | "server2" })` — 在指定 soland 上注册并打开 inkson
   - 当前 inkson 通过 `inkson.config.v1.server_url` 决定连哪个 soland,所以只要切 server_url 就能实现
   - 但 alice@server1 和 bob@server2 需要分别用 server1 / server2 的 base url 注入

## 风险 / 前置依赖

- **当前加入链路仍待验收**：下面的 typed authoring / bootstrap 用例经申请人自己 Station prepare，使用正式 `ak.invite.accept`；旧 helper 和历史成员投影不能证明来源准入、受限状态与 covering Seal 导入已闭合。

## 总耗时预估

单次跑约 3-5 分钟(双服务器启动、跨域 push 重试窗口、frontier 检查)。


## 当前 typed authoring / bootstrap 验收（2026-09-12）

`prepared authoring and join` 是 2214/2247 的当前验收入口；上文旧 invite helper 和历史通过记录不证明新链路可用。两个用例独立执行，失败不跳过另一个。

1. 通过真实 Coauth/Station 注册两个来源的账户，受邀者先通过自己的正式接口设置通知接收策略。
2. Alice 创建 Realm 并签署定向邀请；客户端请求自己 Station dispatch，接收通知仅建立私有邀请投影。
3. Alice 用 closed message intent 调用消息 prepare，逐字段核对 unsigned Event、重新计算 EventId、仅附加设备 proof，通过原 self submit 提交；同 prepare 原样重放、同身份异请求冲突和原签名提交 duplicate 均独立断言。
4. 历史用例额外加入并退出本地成员，再接受 18 条合计超过 8 MiB 的真实 schema Control Move。传输层合成大包不能替代此历史。
5. Bob 从自己 Station 的受保护邀请通知读取 locator，调用自己的 Realm join prepare；不从客户端查询远端 Seal，也不伪造 peer 身份。
6. Bob 核对完整 unsigned Event 并签名，经原 self submit 和来源耐久转发提交。受限 application-status 只报告正式状态；来源须取回并独立验证 covering Seal 后才能确认本地成员。
7. 双方以 typed message prepare 发送消息，并验证对端可读及最终状态一致。

上述用例使用允许的明文 Realm，验证网络 authoring / admission / bootstrap。真实 MLS 的加密、prepare 密文冻结、解密与重放负例另由 `crates/test-support/tests/message_prepare_crypto.rs` 验证；组合单元测试不能代替双 Station MLS 网络验收。当前 self/peer application-status 与来源/目标分阶段加入链的缺口记录于 arkret-work 1636；不得把 prepare 成功或通知到达当作整条链路完成。

`20260912-094216-joint-full-selection` 实际完成前置 owner 消息与两种历史的 bootstrap/prepare。大历史原始缓存为两页，control payload 共 9,443,673 bytes，包含真实成员加入的覆盖 Seal 和退出；两条业务均在来源 self submit 的 `dependency_missing` 停止（本地 Realm digest-suite 未物化）。该结果是 7 项 provisioning 与 1 项 build-id 通过、2 条完整业务失败；不记为跨站加入或消息收敛通过。

`20260912-100215-joint-full-selection` 使用修正下载持久进度后的新二进制复现相同断点；来源数据库已保存完整两页（24 Seals、31 Control Moves、24 治理依赖），bootstrap Realm 未进入来源 canonical Event/accepted Seal。PostgreSQL adapter 重建恢复回归另有 1 passed；完整业务仍为 2 failed。
