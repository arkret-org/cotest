# cotest joint-e2e 全量复核

## 当前基线

- 命令：`./scripts/run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall`
- 完整运行：`artifacts/runs/20260719-132626/joint-e2e`
- 476 tests：268 passed，27 failed，107 expected/profile skipped，74 因 serial 前置失败未运行。
- 测试阶段耗时 25.6 分钟，runner 总耗时 1570.71 秒；托管服务失败数为 0。
- 与 `20260719-120727` 相比：通过数 +7、失败数 -3、未运行数 -4；JUnit 首轮失败 testcase 从 21 降到 19。已解决的 `joint/contact-agent-sidebar.spec.ts` 422 `missing phase` 完全消失。

## RC-12：contact 接受后 Directory 可见性/投影断裂

### 现象

`discovery/directory.spec.ts` 已连续多轮稳定失败。Alice 向 Bob 发起 contact request，Bob 接受，双方 contact list 和 direct conversation 前置断言均完成；Alice 随后在 Directory 搜索 Bob 时，30 秒内找不到精确 DID 行：

```text
actor-result-did[title="<bob did>"] not visible
```

失败发生在 UI 搜索结果可见性，而不是 contact request/accept HTTP 状态。

### 待确认的根因边界与近期更新相关性

- 先核对 spec 对 `direct_message` contact 接受后 directory discoverability 的要求：它是必须立即进入联系人可见集合、依赖独立 directory/profile publication，还是旧测试把 contact graph 与 public directory 错误耦合。
- 对照 Soland 的 contact projection、directory/search API 响应和 Inkson Directory 过滤逻辑，确定数据在哪一层丢失；不得用延长 locator timeout 掩盖缺失投影。
- 审计 arkret-spec、Soland、Inkson 和 SDK 最近关于 contact graph、directory privacy、handle/profile publication 的提交，区分直接相关变更与无关依赖更新。
- 若 API 已返回 Bob 而 UI 不渲染，归类为 Inkson 实现问题；若 API 未返回但 spec 要求返回，归类为 Soland 投影问题；若 spec 明确要求独立 publication，修正 cotest 场景前置条件。

### 复核要求

- 定向场景必须同时断言 contact graph、directory/search 原始 API 结果与 UI 精确 DID 行，建立端到端因果链。
- 验证非 contact principal 不因修复而被泄露，保留 directory privacy/fail-closed 边界。
- 定向场景与标准全量复核均通过后，删除本节并提交相关独立仓库。

## 尚待聚类的失败信号

其余失败仍需逐类核对 spec、实现、测试数据和近期库更新，包括：

- proof/admission：多处 Event proof JWS verification failed。
- capability basis：circle/moderation grant 返回 `capability_registry_basis_unavailable`。
- UI/同步：离线队列、redaction tombstone、Kanban 拖拽等超时或投影断言。
- 个别 MLS 登录、account-data、recovery 和 workflow 串行断言。

这些信号尚未假定为同一根因；RC-12 提交后继续逐类分析。
