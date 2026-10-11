# Snapshot／Query／Scalability 联合测试

入口：`e2e/tests/conformance/realm-state-snapshot-query-scalability.spec.ts`。
2026-10-12 对齐当前 inline RealmSnapshot；旧 chunk／Cell／state-root 正例与对应开发端点已删除。

## 规范与边界

- `sync/authority-commit-log.md`、`realm-state-snapshot.schema.json`：当前治理 Station 签名的 inline snapshot，以同一耐久 cut 提供 visible stream heads、typed current 与 history floors。
- `conformance/query-schema.md`、`conformance/scalability-constraints.md`：query 闭合形状、游标与限额；开发 harness 的 `barrier` 是私有测试结果，不是共享协议 frontier。
- `/_arkret/_conformance/query` 只在 development_mode 开启；无生产认证 claim。

## 具名验证

- Phase B：真实账号创建 Realm，从正式 self API 读取 head 与 exact snapshot，获取 nonce-bound authority bundle 和 retained Station history，经 cotest-wire 调用 Garth／SDK 验证。变更 generation、signature、method 或 nonce 均拒绝；不依赖开发 snapshot harness。
- Phase C–E：开发 query harness 的过滤、排序、opaque pagination、未知操作／未经授权字段拒绝与容量限额。不能据此声称生产 query executor 或 Realm snapshot 容量已完成。
- Phase F：仅 fixture loader 观察，不作为能力完成证据。
- Phase G：describe 的 development_mode 与 query 测试端点可达性一致。

共享 Commit／Handoff 序列化与签名 KAT 位于 SDK `test-kit/fixtures/authority-object-canonical.json`，由各仓 Rust 测试复用。它不替代真实 handoff import、授权历史或多 Station 验收。
