# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-120727/joint-e2e`
- 476 tests：261 passed，30 failed，107 expected/profile skipped，78 因 serial 前置失败未运行。
- 测试阶段耗时 26.1 分钟，runner 总耗时 1738.65 秒；托管服务失败数为 0。
- 与 `20260719-113109` 的 JUnit 失败集合相比，已解决的 `identity/multi-device.spec.ts` E10.E `message_id` 失败消失；串行解锁后新增 `identity/device-key-lifecycle.spec.ts` 超时。`workflows/support-escalation.spec.ts` 只是同一 serial suite 的首个失败位置发生变化，不视为新增根因。

## RC-11：personal Agent provisioning 两阶段契约漂移

### 现象

`joint/contact-agent-sidebar.spec.ts` 在创建尚未配对的 Agent 时返回：

```text
HTTP 422 schema_violation
missing field `phase`
```

旧场景一次性调用 `POST /_arkret/self/agents`，请求只包含 `display_name`、`slug`、`requested_scope` 和 `accountability:null`。

### 初步归类与近期更新相关性

- arkret-spec 2026-07-18 提交 `d0186d03` 把 `ak.self.agent.command.provision` 从单次创建改为闭合的两阶段 operation；该近期规范/schema 更新与失败直接相关。
- 新 schema 要求所有请求携带 `phase`。`prepare` 只分配 Agent DID/PCR、返回 controller realm 和 scope digest，不得产生 durable Agent 状态；`commit` 必须原样带回 allocation、完整 scope，以及由 Arkret SDK 权威 authoring API 生成的 `ak.identity.accountability_grant` + `ak.agent.selector_claim` controller-owned Event pair。
- 旧请求中的 `accountability` 已不属于闭合 schema；仅补 `phase:"prepare"` 只能绕过第一层校验，不能满足完整 provisioning、幂等、proof、普通 Event admission 与 durable state 语义。
- Soland 按当前 canonical schema 返回 422 是正确行为；现有证据指向 cotest 场景漂移，而不是应放松服务端校验。

### 复核要求

- 复用 arkret-rust-sdk 的统一 authoring API，不在测试内手工拼 canonical payload、proof transcript 或 Event envelope。
- 验证 prepare 无 durable Agent/selector/pairing 副作用，客户端重算并匹配 `requested_scope_digest`。
- commit 必须让两条 controller-owned Event 经普通 schema/proof/authz/frontier/reducer admission durable accepted，并返回 `status=complete` 与一次性 pairing handle。
- 验证精确 commit retry 幂等，并保留原场景目标：从 Contacts sidebar 和 Agents count 中隐藏从未 effective 的 `pending_runtime_key` Agent。
- 定向场景与标准全量复核均通过后，删除本节并提交。

## 尚待聚类的失败信号

其余失败仍需逐类核对 spec、实现、测试数据和近期库更新，包括：

- 新暴露的 `device-key-lifecycle` grant observation 超时；需先判断 coauth/Inkson 最新提交、监听时序和测试观察器哪个相关。
- proof/admission：多处 Event proof JWS verification failed。
- capability basis：circle/moderation grant 返回 `capability_registry_basis_unavailable`。
- UI/同步：locator 可见性、离线队列、redaction tombstone、Kanban 拖拽等超时或投影断言。
- 个别 MLS 登录、account-data 和 workflow 串行断言。

这些信号尚未假定为同一根因；RC-11 提交后继续逐类分析。
