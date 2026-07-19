# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-095243/joint-e2e`
- 476 tests：261 passed，30 failed，104 expected/profile skipped，81 因 serial 前置失败未运行。
- JUnit：9 errors、21 failures；本轮使用 4 workers，测试阶段 25.1 分钟。

## RC-8：service describe 未声明 canonical account-handoff operation

### 现象

`identity/onboarding.spec.ts` 在读取 coauth `/_arkret/describe` 后失败：

```text
Expected supported_operations to contain:
ak.gate.account.exchange.create_handoff
```

实际 account-handoff endpoint 可用且其独立协议组全部通过，但 describe operation catalog 未包含该 operation。

### 初步归类

- spec 的 service HTTP binding 已定义 canonical authentication-handoff endpoint 与 outcome。
- 测试断言使用 registry 中的 canonical operation 名称，不是测试自造 wire 值。
- 当前证据指向 coauth 的 service-describe 实现/registry 同步遗漏，而不是 endpoint 行为失败。
- 是否与近期 registry/contract 库更新相关，需在本类中通过 spec registry、SDK 常量、coauth catalog blame 和依赖提交差异确认。

### 复核要求

- operation catalog 与 spec/SDK registry 一致；不得仅删除断言或改成旧 operation 名称。
- onboarding 定向用例、service-describe 单元测试和标准全量复跑均不再出现该遗漏。
- 本类完全通过并提交后，从本报告移除 RC-8。

## 尚待聚类的失败信号

其余失败将在 RC-8 提交后逐类确认，目前可见的信号包括：

- schema drift：to-device 缺 `message_id`、某请求缺 `phase`；
- proof/admission：多处 Event proof JWS verification failed；
- capability basis：circle/moderation grant 返回 `capability_registry_basis_unavailable`；
- UI/同步：locator 可见性、离线队列、redaction tombstone、Kanban 拖拽等超时或投影断言；
- 个别 idempotency conflict、MLS 登录和 account-data 断言。

这些信号尚未假定为同一根因；后续必须分别核对 spec、实现、测试数据与近期库更新。
