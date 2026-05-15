# Joint E2E Scenarios

每条 scenario 描述一个 spec-aligned 业务流程,作为 playwright 测试代码的契约。改 spec 行为时先改 scenario 文档,再改对应测试。

## 状态(截至最近一次本目录更新)

| ID | 文档 | 测试代码 | live tests | fixme tests | 备注 |
|---|---|---|---|---|---|
| **S1** | [S1-single-server-triad.md](S1-single-server-triad.md) | [tests/s1-single-server-triad.spec.ts](../tests/s1-single-server-triad.spec.ts) | 3 | 0 | 主流程 + E1.1 idempotent invite + E1.2 history_visibility=shared |
| **S2** | [S2-cross-server-federation.md](S2-cross-server-federation.md) | [tests/s2-cross-server-federation.spec.ts](../tests/s2-cross-server-federation.spec.ts) | 3 | 6 | live:健康检查 + 双服务器分离 + 本地 invite。fixme:跨服务器 push、双向消息、pull、幂等、revoke fanout、RFC 9421。需要 `-DualSoland` 启动 |
| **S5** | [S5-moderation-ban.md](S5-moderation-ban.md) | [tests/s5-moderation-ban.spec.ts](../tests/s5-moderation-ban.spec.ts) | 2 | 0 | 主流程 (举报 + 三层 gate + ban + redact tombstone) + E5.3 idempotent ban |
| **S6** | [S6-knock-cooldown.md](S6-knock-cooldown.md) | [tests/s6-knock-cooldown.spec.ts](../tests/s6-knock-cooldown.spec.ts) | 1 | 6 | live:knock state 写入。fixme:application/review/cooldown/refs/TTL/visibility — 等 soland 把 spec §3.6 落地 |

总计:**9 live tests + 13 fixme tests = 22**

## Soland 实现度 (2026-05 审计,影响 fixme 数量)

| 区域 | 状态 | 影响 scenario |
|---|---|---|
| Federation push/pull endpoint 路由 + ingest | ✓ | S2 |
| RFC 9421 HTTP Message Signature 验证 | ✗ | S2 |
| `service_binding_ref.reducer_profile_hash` 验证 | ✗ | S2 |
| Outbound federation push (server → server HTTP) | ✗ (stub,只打 log) | S2 |
| `cx.invite.create` 远程 DID 触发自动推送 | ✗ | S2 |
| `cx.component.moderation_state.v1` cell 写入 | 部分 (需查 cell projection) | S5 |
| `POST /api/v1/moderation/report` | 部分 (yougen api 绑定存在,soland handler 待确认) | S5 |
| `cx.member.state{membership="ban"}` reducer | ✓ | S5 |
| `PUT /api/v1/spaces/:id/policy` (join_rule="knock") | ✓ | S6 |
| `cx.member.state{membership="knock"}` Move | ✓ | S6 |
| `member.application` / `member.application.review` event kinds | ✗ | S6 |
| `cooldown_after_reject` 时间约束 | ✗ | S6 |
| `cx.invite.create.refs[role="join_authorised_by"]` | ✗ | S6 |
| `space.join_policy` cell family | ✗ | S6 |

Spec `models/space-and-place.md` §3.1 自己说 join-policy 还是候选,所以 S6 的 fixme 是已知 gap,不是回归。

## 编排约定

- 每个 scenario 一个 `*.spec.ts` 文件,文件名跟 scenario id (`s1-*.spec.ts` 等)
- `test.describe.configure({ mode: "serial" })` — actor 之间有时序依赖
- 每个 scenario 用 `uniqueUser("sN-actor")` 避免跨 scenario 状态污染
- 关键 phase 末尾 `stepShot()` 留证据图;artifact 落在 `artifacts/runs/<ts>/joint-e2e/screenshots/`
- 子 case (E1.1、E5.2 等) 用 `test.describe(...)` 嵌套或独立 `test()`
- 因为 spec 尚未落地导致暂时跑不通的契约,用 `test.fixme()` 写出来,正文留 spec § 引用和 soland gap 说明 — 等实现到位 `git grep "test.fixme"` 删 `fixme` 即可激活
- 不写 "这里之前是 X" 历史性注释;git log 是历史的家

## 运行

```pwsh
# 单服务器 (S1 / S5 / S6 + S2 sanity probes)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full

# 双服务器 (再激活 S2 联邦测试)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -RunProfile joint-full

# 跑单个 scenario
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -Grep "S2"
```

## 产物

跑完后 `artifacts/runs/<ts>/joint-e2e/`:
- `summary.md` — 整体 status + 配置参数
- `scenarios.md` — 按 scenario 维度聚合 pass/fail/skipped/fixme
- `junit.xml` — CI 友好结构化结果
- `playwright-report/` — HTML 报告 (含 trace、video、failure screenshot)
- `playwright.stdout.log` / `playwright.stderr.log`
- `services/` — soland / coauth / yougen 进程日志
- `screenshots/` — scenario step 截图,按 scenario 子目录
- `diagnostics/` — 每个 actor 的 console / network HAR

## 后续(尚未落地的 scenario)

| ID | 主题 | 触发条件 |
|---|---|---|
| S3 | 第三方邮件邀请 (`cx.invite.third_party`) | 需要 mock 邮件验证服务 |
| S4 | 账户注册 + 设备授权 (`cx.device.authorized`) | 需要 coauth 真注册流程接入 + 多设备 browser context |
| S5+S2 组合 | 跨服务器 ban anchor 一致性 | S2 outbound push 在 soland 落地后 |
| S6.2 | 自动解析 join 路径 (`cx.member.state{join, gate_proofs}`) | soland 落 `space.join_policy` cell + gate verifier |
| S1.3 | history_visibility=world_readable 未加入也能读 | yougen 需要支持匿名 timeline 访问 |
