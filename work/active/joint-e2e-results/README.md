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

### RC-6：invite locator 测试要求接受被 spec 禁止的 token

`invites/invite-addressing.spec.ts` 自行构造 `base64url(JSON({subject_id, nonce, expires_at}))` 并直接调用 open resolve。`sync/invite-addressing.md` 明确要求 token 是 CSPRNG 生成的不透明 bearer secret，服务端只保存 digest，并明确禁止可解码的 `base64url(JSON)`。

待完成：

1. 以认证 session 调用 `POST /_arkret/self/invite-locators` 发行 token。
2. raw token 只放在 resolve JSON body。
3. 验证 query/path 泄漏拒绝、unknown token 不可枚举、rotate/revoke、TTL、one-time 并发、`Cache-Control: private, no-store`。
4. 验证存储、audit 和日志中不出现 raw token。

## 执行顺序

1. RC-6 invite locator 生命周期。
2. 对最新全量运行新增的失败继续按 spec 真源聚类、修复、复核和提交。
3. 标准 `joint-full` 达到所有可执行用例通过、仅保留有明确 profile 原因的 expected skip 后，删除本文件。
