# Joint E2E 改造任务清单

生成日期: 2026-05-12

状态说明:

- `[x]` 已完成
- `[>]` 正在处理
- `[ ]` 未开始

## Phase 0: 任务拆分和边界确认

- [x] T0.1 梳理当前 `cotest` 的 API/协议测试能力和 UI E2E 缺口，形成 `_report.md`。
- [x] T0.2 将联合 E2E 改造拆成可执行任务，并保存到 `_todos.md`。
- [x] T0.3 在每个阶段完成后更新本文件状态，避免后续工作失焦。

## Phase 1: live soland + yougen UI smoke 骨架

- [x] T1.1 新增 `scripts/run-joint-e2e.ps1`，负责编排 soland、yougen、可选 coauth，创建运行目录并收集产物。
- [x] T1.2 新增 `e2e/package.json` 和 `e2e/playwright.config.ts`，把 Playwright 输出固定到 `artifacts/runs/<timestamp>/joint-e2e/`。
- [x] T1.3 新增 E2E helper，统一读取 `COTEST_*` 环境变量、创建多用户 browser context、保存步骤截图。
- [x] T1.4 新增 live smoke tests: 环境健康、错误 server URL、Alice/Bob 独立 dev-login、Alice 创建 Space 并持久化消息。
- [x] T1.5 运行静态/配置级验证，确保新增脚本和 TypeScript 配置可解析。
- [x] T1.6 在 `docs/test-strategy.md` 补充 UI E2E 与现有 API conformance 的边界。
- [x] T1.7 修复 live smoke 暴露的本地服务编排问题: 隔离 `DATABASE_URL`/`.env`，并递归清理 soland/yougen 子进程。
- [x] T1.8 修复 live smoke 暴露的跨项目兼容问题: soland CORS 放行 yougen 写事件头，yougen 只对 `sx:` sync token 发送 `X-Contrix-Wait-For`。

## Phase 2: coauth live 接入

- [x] T2.1 扩展 `run-joint-e2e.ps1` 的 coauth 启动参数，支持 live `CoauthBaseUrl` 和本地 `CoauthCommand`。
- [x] T2.2 复用或增强 `coauth_bootstrap`，生成测试用 coauth 配置和 ephemeral PostgreSQL。
- [x] T2.3 明确 soland 与 coauth 的测试配置映射: audience、endpoint、service DID、introspection URL、bearer。
- [x] T2.4 新增 coauth discovery/topology smoke: `/health`、OIDC discovery、`/api/v1/server/describe`、principal server 配置。
- [x] T2.5 新增 coauth 登录失败和 session grant 失败 UI 流程。

## Phase 3: 多用户真实流程矩阵

- [x] T3.1 新增 Alice/Bob/Admin/Guest page objects，隔离 localStorage、token、device id。
- [x] T3.2 新增注册用户流程: 生成/绑定 DID、填写 handle/display name/device、提交注册、截图归档。
- [x] T3.3 新增联系人流程: Alice 搜索 Bob、请求、Bob 接受、重复请求冲突。
- [x] T3.4 新增 Space 管理流程: 创建 private Space、邀请/添加成员、修改元数据/策略、移除成员、删除。
- [x] T3.5 新增双向消息流程: Alice 发送、Bob 同步、Bob 回复、编辑、redaction/tombstone。
- [x] T3.6 新增权限流程: Guest/非成员/非 owner 的 UI 禁用和 API 403/401 校验。
- [x] T3.7 新增会话流程: refresh/logout/revoked token。
- [x] T3.8 新增移动端核心路径: 登录、导航、timeline、发送消息、Space admin 截图。

## Phase 4: 报告、CI 和视觉稳定化

- [x] T4.1 将 joint E2E summary 链接到 `artifacts/latest/`，并输出截图索引。
- [x] T4.2 增加 `joint-smoke` 与 `joint-full` 运行 profile 或独立脚本参数。
- [x] T4.3 引入 trace/video/HAR/console/network 失败归档。
- [x] T4.4 对登录页、Space admin、timeline、权限错误页建立可控视觉 baseline。
- [x] T4.5 为 CI 准备 Node、Playwright browser、Dioxus CLI、Docker/PostgreSQL 前置检查。
- [x] T4.6 将稳定后的 joint smoke 纳入 release-gate 前置检查。
