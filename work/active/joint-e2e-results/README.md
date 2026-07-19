# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-141911/joint-e2e`
- 476 tests：264 passed，30 failed，107 expected/profile skipped，75 因 serial 前置失败未运行。
- 测试阶段耗时 26.3 分钟，runner 总耗时 1598.98 秒；托管服务失败数为 0。
- 已解决的 contact 接受后 Directory 精确 DID 行失败消失；`discovery` serial suite 解锁到下一条 presence 场景。总体统计中的其它变化来自既有时序用例波动，按 JUnit testcase 集合分别归类。

## RC-13：presence 场景使用未授权 device 与占位 proof

### 现象

`discovery/directory.spec.ts` 的 presence 场景首次被串行解锁后，在第一次发送 `ak.presence` 时返回：

```text
HTTP 400 invalid_param
ephemeral proof device is not active and authorized
reason_code=proof_invalid
```

### 初步归类

- 场景用 `ensureRegistered` + dev session 创建用户，却没有证明 `device_id` 已完成 active authorization。
- `presenceEnvelope` 只计算 `event_digest`，JWS 固定为占位字符串 `eyJhbGciOiJFZERTQSJ9..c2ln`；它不是由对应 device event signer 生成的可验证签名。
- Soland fail closed 符合 presence/ephemeral proof 安全边界；当前证据指向 cotest fixture/签名数据问题，不支持放松服务端 proof 校验。

### 近期更新相关性与复核要求

- 审计 Arkret device authorization、ephemeral proof 和 Inkson presence emitter 的近期提交，确认服务端何时从 shape-only 升级为 active-device + real-JWS 验证，以及 cotest 为何未同步。
- 复用 cotest/SDK 已有的真实 event signer 与 device enrollment helper，不在场景中手工伪造 proof transcript。
- 验证 online → offline → online 投影，并保留 accepted-contact 可见性前置；另加未授权 device/伪造 proof 的负向拒绝断言，不能只让 happy path 通过。
- 定向场景与标准全量复核均通过后，删除本节并提交。

## 尚待聚类的失败信号

其余失败仍需逐类核对 spec、实现、测试数据和近期库更新，包括：

- proof/admission：多处 Event proof JWS verification failed。
- capability basis：circle/moderation grant 返回 `capability_registry_basis_unavailable`。
- UI/同步：离线队列、redaction tombstone、Kanban 拖拽等超时或投影断言。
- 个别 MLS 登录、account-data、recovery 和 workflow 串行断言。

这些信号尚未假定为同一根因；RC-13 提交后继续逐类分析。
