# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-104636/joint-e2e`
- 476 tests：264 passed，30 failed，104 expected/profile skipped，78 因 serial 前置失败未运行。
- 测试阶段耗时 26.2 分钟；托管服务失败数为 0。
- RC-8 的原始 `supported_operations` 失败已消失；同一串行套件继续执行后暴露了下面的 RC-9，因此失败总数暂时仍为 30。

## RC-9：joint-full 未提供可读取的邮箱验证码

### 现象

`identity/onboarding.spec.ts` 的 account-first PCR bootstrap 场景完成账户创建后停留在 coauth 邮箱验证页：

```text
Incorrect code. Please try again.
expected getByTestId("onboarding-panel") to be visible
```

测试仅在 `COTEST_MOCK_EMAIL_BASE_URL` 可用时读取实际验证码；本次标准 `joint-full` 未启动或注入 mock email，因此测试退回硬编码 `123456`，而 coauth 实际生成随机验证码。

### 待确认

- 对照 account-first registration spec，确认邮箱验证是必须真实完成的前置步骤，不能绕过或放松断言。
- 核对 cotest joint profile、mock-email 启动逻辑及近期依赖/配置更新，确定是运行编排缺口、测试数据错误还是 coauth 行为变化。
- 修复后必须覆盖验证码获取、PCR bootstrap 完整链路，并保证标准全量命令不依赖偶然的固定验证码。

## 尚待聚类的失败信号

其余失败仍需逐类核对 spec、实现、测试数据和近期库更新，包括：

- schema drift：to-device 缺 `message_id`、某请求缺 `phase`；
- proof/admission：多处 Event proof JWS verification failed；
- capability basis：circle/moderation grant 返回 `capability_registry_basis_unavailable`；
- UI/同步：locator 可见性、离线队列、redaction tombstone、Kanban 拖拽等超时或投影断言；
- 个别 idempotency conflict、MLS 登录和 account-data 断言。

这些信号尚未假定为同一根因；RC-9 提交后继续逐类分析。
