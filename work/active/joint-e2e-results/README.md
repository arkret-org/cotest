# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-173740/joint-e2e`
- 480 tests：272 passed，27 failed，107 expected/profile skipped，74 因 serial 前置失败未运行。
- 测试阶段耗时 26.0 分钟，runner 总耗时 1582.3 秒；托管服务失败数为 0。
- JUnit 记录 18 个直接失败；Playwright 汇总中的另外 9 个是 serial suite 前置失败后的派生失败/未完成项，不能重复作为独立根因计数。
- 已解决的 RC-13 presence 场景在定向干净复跑和本次全量中均通过，已从报告移除。

## RC-14：Event proof JWS transcript / signer 漂移

### 现象

本次全量有三处直接返回相同服务端判定：

- `identity/contact-graph.spec.ts`：publish cross-signing 返回 `400 invalid_proof`；
- `invites/third-party.spec.ts`：`ak.invite.claim` 被拒绝，`event proof JWS verification failed`；
- `joint/joint-inkson-smoke.spec.ts`：提交 `ak.member.state` 返回 `400 invalid_proof`。

这三条覆盖不同业务域，却在 Event proof 的通用验证边界失败，优先按共享 signer / canonical transcript 漂移聚类，而不是分别修改业务 reducer。

### 初步归类

- Soland 在 proof JWS 校验失败时 fail closed 符合 spec；没有证据支持放宽服务端校验。
- 失败发生在 reducer/admission 之前，业务 payload 本身尚未成为决定因素。
- RC-13 已发现 7 月 SDK 把 ephemeral proof 切换到专用 canonical binding；RC-14 需独立审计近期 Event proof API、domain/audience、created_at 规范化和 fixture signer 调用是否也发生过类似迁移，不能直接套用 ephemeral 修复。

### 复核要求

- 找出三条场景使用的共享/不同签名 helper，逐字节比较客户端签名 transcript 与 Soland verifier transcript。
- 用 SDK verifier 为 cotest 生成的真实 proof 增加互操作回归；保留篡改 proof 的负向拒绝断言。
- 不通过固定占位签名、跳过验证或放宽 Soland admission 让测试变绿。
- 三条直接失败的定向场景全部通过，并复核受其 serial 阻塞的后续场景；标准全量无该类别失败后提交并从报告移除。

## 后续待聚类信号

除 RC-14 外，本轮 JUnit 的直接失败信号包括：

- capability basis：moderation appeal、Circle lifecycle 的 grant 返回 `412 capability_registry_basis_unavailable`；
- account-data / UI projection：personal blocklist、consent、support escalation；
- session/sync：terminal auth polling 计数、quiet long-poll 首帧、offline queue 状态；
- Realm/Kanban：Sidecar discoverability 值漂移、create Realm 404、跨成员加密投影超时；
- messaging：reaction/reply 投影、read receipt 400；
- workflow 的其余失败需在上游 serial 前置项解锁后重新确认，不能基于当前派生失败过早归因。

这些信号尚未假定为同一根因；RC-14 提交后继续逐类分析。
