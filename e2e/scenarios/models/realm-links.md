# Realm link graph：关系可见，状态不传播

## 目标

验证 current-v1 的 Realm link 只是治理、发现、迁移与导航关系，不是 authority 或 policy carrier。建立
`governed_by`、`discoverable_from` 或其它标准 link 后，目标 Realm 仍必须用自己的本地 Event 表达 membership、
capability、policy、retention 与 notification 状态。

旧的 automatic inheritance cluster 已 clean break：

- `ak.realm.inheritance_policy` 与 `ak.capability.derived` 不再是 Event kind；
- `inherits_policy_from` 不再是 link kind；
- effective-policy merge operation／DTO 与 inheritance typed current family 不再存在；
- 旧 row 不重解释、不 alias、不双读。

## Spec 锚点

- `arkret-spec/spec/v1/zh/models/realm-links.md` §2 — link graph 不承载跨 Realm 状态继承；
- 同文 §3 — 标准 link kind closed set；
- 同文 §5 — membership、capability、policy、retention、notification 等不得隐式级联；
- 同文 §6 — 每个目标 Realm 必须由本 Realm controller／issuer 分别签发本地 Event；
- `arkret-work/decisions/0046-realm-inheritance-clean-break-and-co-governed-join-gate.md`。

## Static conformance（已落地）

`tests/realm_link_clean_break.rs::rejects_automatic_realm_inheritance_without_current_v1_carrier` 从正式 artifacts 验证：

1. 两个旧 Event kind 不在 event-kind registry；
2. effective-policy operation 不在 operation registry；
3. inheritance current-result family与旧 payload／response schema 不再可达；
4. `realm_link_payload.link_kind` 接受 `governed_by`、`join_gate_from`，拒绝 `inherits_policy_from`；
5. link payload 没有 `inherits`、`policy_rules`、`capability_bundles` 或 `notification_defaults` carrier。

这组检查证明 canonical wire 无法因 link 传播 policy、capability 或 notification；它不是 Coland 生产存储／HTTP
行为的替代品。

## Production scenario（待 runner）

### Phase A — link 仍可表达关系

1. Alice 创建 source Realm `G`，Bob 创建 target Realm `T`。
2. Bob 在 `T` 中写 active `ak.realm.link{target_realm_id:G, link_kind:"governed_by"}`。
3. 读取 `ak.self.realm_link.read.list.v1`，断言 link 作为关系存在。

### Phase B — policy 不传播

4. Alice 在 `G` 写本地 policy；`T` 不写相应本地 policy。
5. 对同一输入分别执行 `G` 与 `T` 的 admission；只有 `G` 使用该 policy，`T` 不能读取或合并它。
6. 向 `T` 提交旧 `ak.realm.inheritance_policy` 必须以 schema／unknown-kind 类错误拒绝且零写入；旧
   effective-policy endpoint 不得继续作为 alias 暴露。

### Phase C — capability 不传播

7. Alice 只在 `G` 持有 `ak.realm.admin`，不在 `T` 持有 grant。
8. Alice 尝试在 `T` 执行 admin action，必须按 `T` 的本地 capability state 拒绝。
9. 向 `T` 提交旧 `ak.capability.derived` 必须拒绝且零写入；只有 `T` 的 controller／issuer 新签本地
   `ak.capability.grant` 才能授权。

### Phase D — notification 不传播

10. `G` 配置本地 notification rule，`T` 不配置。
11. 在 `T` 触发相同业务输入，不得从 `G` 读取默认通知或生成 derived notification state。
12. 旧 `notification_defaults` inheritance payload 必须 schema reject；建立、拒绝或 tombstone link 都不得改写
    `T` 的 notification current state。

### Phase E — clean-break migration

13. 用含旧 inheritance rows 的数据库启动升级后 Coland；这些 row 只按迁移策略删除／隔离，不能重解释为本地 policy、
    grant 或 notification。
14. 对升级前后 `T` 的本地 current rows 做 exact comparison；除显式新写入外不得发生变化。

## 当前缺口

- 当前 Cotest 没有能启动含旧 inheritance row 的生产 Coland 数据库并观测 Event、RealmCommit 与多个 current family
  零写入的 durable migration runner。
- 因此旧 API-only Playwright 正向继承场景已删除，不把 Coland 内存 reducer 测试或 static registry check 宣称为产品闭环。
- 补齐 runner 后，必须执行上述五个 phase，并以数据库事务前后快照证明拒绝路径零写入。
