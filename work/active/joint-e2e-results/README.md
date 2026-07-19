# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-113109/joint-e2e`
- 476 tests：265 passed，29 failed，104 expected/profile skipped，78 因 serial 前置失败未运行。
- 测试阶段耗时 26.0 分钟；runner 总耗时 1578.92 秒；托管服务失败数为 0。

## RC-10：to-device sender-assigned `message_id` 契约漂移

### 现象

`identity/multi-device.spec.ts` 的 E10.E grace-drop 场景在入队前被 schema 拒绝：

```text
to-device send returned 422
schema_violation: missing field `message_id`
```

测试发送的 `DeviceMessageTarget` 只有 `kind`、`expires_at` 和 `content`，因此尚未实际覆盖“撤销设备后清除已排队消息”的目标行为。

### 初步归类与近期更新相关性

- arkret-spec 2026-07-16 提交 `6e5cadc4` 把 sender-assigned `message_id` 加入 `DeviceMessageTarget` 和 `DeviceMessageEnvelope` 的 required 字段，用于重投递去重、冲突检测及 E2EE AAD 绑定；该近期规范/schema 更新与失败直接相关。
- cotest 场景创建于 2026-06-25，7 月 16 日后没有同步新增 `message_id`，明确存在测试数据漂移。
- spec 自身仍有一处不一致：`service-http-binding.md` 的 endpoint 表和 operation 阅读视图仍把 target 写成 `{kind, content, expires_at}`，而 canonical JSON Schema、device lifecycle、client sync 和 conformance vector 均要求 sender-assigned `message_id`。
- soland 按最新 canonical schema 返回 422，当前证据不支持放松服务端校验。

### 复核要求

- 先消除 spec prose 与 canonical schema 的冲突，确认 `message_id` 由 sender 生成并原样物化到 envelope，而非回退为 server-assigned。
- 测试使用合法 `ak:device_message:<uuidv7>`，并继续验证入队可见、device revoke 成功、撤销后队列不可达/清除。
- 核对 soland 的幂等与 purge 实现是否符合更新后的 identity key；不能只让 422 消失。
- 定向场景和标准全量均通过后，删除本节并提交各独立仓库。

## 尚待聚类的失败信号

其余失败仍需逐类核对 spec、实现、测试数据和近期库更新，包括：

- 另一处 schema drift：contact-agent 请求缺 `phase`；
- proof/admission：多处 Event proof JWS verification failed；
- capability basis：circle/moderation grant 返回 `capability_registry_basis_unavailable`；
- UI/同步：locator 可见性、离线队列、redaction tombstone、Kanban 拖拽等超时或投影断言；
- 个别 MLS 登录、account-data 和 workflow 串行断言。

这些信号尚未假定为同一根因；RC-10 提交后继续逐类分析。
