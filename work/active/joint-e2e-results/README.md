# cotest joint-e2e 剩余问题跟踪

## 当前基线

- 运行时间：2026-07-19 04:21–05:03（Asia/Shanghai）
- 标准命令：`.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- profile / project：`joint-full` / `chrome`
- 发现 476 个测试：234 passed、37 failed、104 skipped、101 did not run。
- 标准 Soland + coauth + Inkson 拓扑已启动并进入全部 Playwright suites。
- 权威 artifacts：[`artifacts/runs/20260719-042118/joint-e2e`](../../../artifacts/runs/20260719-042118/joint-e2e)。
- 本文件只保留尚未闭环的问题；一类问题完成 spec 对照、定向测试和相关回归后即从本文件删除。所有问题清零并通过标准全量回归后删除本文件。

当前 37 个失败包含原报告无法执行到的后续场景。先完成下列已确认根因，再根据新的 JUnit 结果继续去重归因。

## 剩余问题

### RC-3：Directory 测试把 profile update 误当作隐式 announce

`discovery/directory.spec.ts` 更新 account profile 后要求 Directory actor row 顶层出现 `bio`。`arkret-spec/spec/v1/zh/sync/service-http-binding.md` 明确规定：

- `ak.self.account.command.update_profile` 写入/等价产生 `ak.profile.update`；
- 它不隐式触发 `ak.find.directory.command.announce` 或 `ak.account_data.set`；
- 需要可发现 profile 时必须显式走 Directory announce；
- `bio` 的 ActorProfile canonical 落点是 `profile_fields.bio`，Directory projection 仍受 schema、授权和隐私策略限制。

待完成：

1. account profile 用例只在 `/_arkret/self/account/viewer` 验证 canonical profile。
2. Directory 可发现性用例显式 announce，并只断言对应 discovery profile 允许公开的字段。
3. 不得通过让 Soland 隐式公开 bio 来迎合测试。

### RC-4：account_data REST 写未进入 initial-sync durable Event 来源

`governance/personal-blocklist.spec.ts` 的 PUT、GET、list 均能看到最新值，但 initial `GET /_arkret/self/account/subscribe?catchup=true` 的 `account_data.events` 找不到该 key。

实现差异：

- `routing/identity/account_data.rs` 的 REST PUT 只写 `account_data_application()` 并发送低延迟 actor-private update；
- `routing/events/sync/snapshot.rs::account_data_events()` 只从 `events_store()` 中的 `EventKind::ACCOUNT_DATA_SET` 重建 baseline；
- REST write 没有持久化规范所要求的 `ak.account_data.set` actor-private Event。

测试也把 `account_data.events[]` 当作 REST DTO，读取根级 `entry.data_type` / `entry.content`；规范和 schema 定义这里是 EventContainer，应该读取 `event.kind` 与 `event.payload.key/body/tombstone`。

待完成：

1. REST replace/delete 经统一 Event acceptance 管线事务性持久化 actor-private Event，并更新 application projection/发送 wakeup。
2. initial baseline 从 durable authority 重建最新 key，服务重启后结果不丢失。
3. 测试改为 canonical Event shape。
4. 覆盖 overwrite、另一设备 live fanout、restart baseline、delete tombstone、敏感 key encrypted carrier。

### RC-5：MIMI consent update 使用错误 proof 类型

`mimi-operations.schema.json#/$defs/signature` 是非 Event generic detached proof，使用 `payload_digest`。但 `arkret-rust-sdk/crates/core/src/http/bodies.rs::MimiUpdateConsentRequestBody.signature` 当前类型是 Event `Proof`，要求 `event_digest` 且拒绝未知字段。Soland 的强类型 `JsonBody<MimiUpdateConsentRequestBody>` 因而在业务处理前对 spec-correct body 返回 422。

待完成：

1. SDK 字段改为与 schema 完全同构的 generic detached payload proof 类型，不能把测试改成 `event_digest`。
2. 明确并验证 MIMI object-family signing context、canonical payload、actor/consent/request/replay、domain/audience binding。
3. SDK 增加 schema round-trip/unknown-field tests。
4. Soland 增加 `payload_digest` 成功、`event_digest` 失败、digest/binding/replay 失败的集成测试。
5. cotest 使用真实签名，不让 bearer session 分支掩盖 proof 验证。

### RC-6：invite locator 测试要求接受被 spec 禁止的 token

`invites/invite-addressing.spec.ts` 自行构造 `base64url(JSON({subject_id, nonce, expires_at}))` 并直接调用 open resolve。`sync/invite-addressing.md` 明确要求 token 是 CSPRNG 生成的不透明 bearer secret，服务端只保存 digest，并明确禁止可解码的 `base64url(JSON)`。

待完成：

1. 以认证 session 调用 `POST /_arkret/self/invite-locators` 发行 token。
2. raw token 只放在 resolve JSON body。
3. 验证 query/path 泄漏拒绝、unknown token 不可枚举、rotate/revoke、TTL、one-time 并发、`Cache-Control: private, no-store`。
4. 验证存储、audit 和日志中不出现 raw token。

## 执行顺序

1. RC-3 Directory 测试契约。
2. RC-4 account_data durable sync。
3. RC-5 MIMI payload proof typed DTO。
4. RC-6 invite locator 生命周期。
5. 对最新全量运行新增的失败继续按 spec 真源聚类、修复、复核和提交。
6. 标准 `joint-full` 达到所有可执行用例通过、仅保留有明确 profile 原因的 expected skip 后，删除本文件。
