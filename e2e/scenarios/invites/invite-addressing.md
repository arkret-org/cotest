# invites/invite-addressing

2026-10-15：原 API-only Playwright 文件已迁为 Rust，旧步骤仅保留产品目标与历史来源，**不证明真实 UI 通过**。

当前具名执行入口：

- `tests/invite_addressing_api.rs::invite_addressing_api_migration`（isolated_station）。

operation→Rust test 与原选择数量见 `api-only-migration.json.native_live_migrations`。无筛选 joint 强制执行全部 primary／supporting 用例；release-gate 通过其 joint 阶段执行，跳过联合阶段不能发布为 release 通过。缺少环境、零测试、ignore 与失败均不能代替通过。日志位于本轮 `native-api-migrations/`，映射本身不是运行证据。

## 历史场景与独立产品目标
