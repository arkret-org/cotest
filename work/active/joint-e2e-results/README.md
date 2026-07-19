# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-191827/joint-e2e`
- 480 tests：284 passed，24 failed，107 expected/profile skipped，65 因 serial 前置失败未运行。
- 测试阶段耗时 25.2 分钟，runner 总耗时 1538.3 秒；托管服务失败数为 0。
- JUnit 记录 17 个直接失败；Playwright 汇总中的另外 7 个是 serial suite 前置失败后的派生失败/未完成项，不能重复作为独立根因计数。

## RC-15：capability registry basis 不可用

### 现象

本次全量有两处在测试准备阶段返回相同服务端判定：

- `governance/moderation-appeal.spec.ts`：授予 `ak.moderation.appeal.review` 返回 `412 capability_registry_basis_unavailable`；
- `identity/circle-member.spec.ts`：授予 `ak.circle.manage` 返回 `412 capability_registry_basis_unavailable`。

两条失败都发生在目标业务事件之前，且共用 capability grant helper。应先审计 capability registry 的权威 basis 解析与近期 SDK registry 更新，不分别修改 moderation/Circle reducer。

### 初步归类

- Soland 的 `412` 是 fail-closed 的 precondition 结果；不能通过跳过 capability grant 或默认放行让用例通过。
- 同一全量中其它 capability-chain 用例通过，说明不是所有 grant 全局失效，更可能是这两个 action 的 registry basis、resource selector 或测试 helper 所用 grant 形态发生了局部漂移。
- 需要对照 spec 的 capability action registry、SDK 生成 artifacts、Soland 运行时 registry 装载结果，以及近期库更新，确认 action 是否仍 active、basis 是否必须由显式父 grant/治理声明提供。

### 复核要求

- 比较两个失败 action 与同批成功 action 的 registry row、basis source、resource selector 和 grant payload。
- 判断是 cotest 仍构造旧 grant 形态、SDK artifact 漂移，还是 Soland 未装载/未投影当前 registry basis。
- 增加能同时覆盖有效 basis 与缺失 basis fail-closed 的回归。
- 两个直接失败及各自 serial 后续场景全部通过，标准全量无该类别失败后提交并从报告移除。

## 后续待聚类信号

除 RC-15 外，本轮 JUnit 的直接失败信号包括：

- account-data / UI projection：personal blocklist、consent、support escalation；
- session/sync：terminal auth polling 计数、quiet long-poll 首帧、offline queue 状态；
- Realm/Kanban：Sidecar discoverability 值漂移、跨成员加密投影、列拖放/邀请状态；
- messaging：reaction/reply/mention routing 投影；
- invite/workflow：admin invite 状态、多个 workflow 的 invite/join、offline 或 redaction 前置项；
- workflow 的其余失败需在上游 serial 前置项解锁后重新确认，不能基于当前派生失败过早归因。

这些信号尚未假定为同一根因；RC-15 提交后继续逐类分析。
