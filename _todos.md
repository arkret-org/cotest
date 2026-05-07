# cotest — Contrix Black-box Test Harness TODO

> 整理日期：2026-05-07
> 协议参考：`contrix-spec/spec/v1/zh/conformance/` + `contrix-spec/spec/v1/artifacts/`。
> 项目栈：Rust（cargo test 入口） + PowerShell harness scripts + 可选 Docker compose；定位类似 Matrix Complement。

## 标记说明

- 🅿 parallel-safe：单 scenario / 单 vector / 单 fixture
- 🔒 sequential：动 harness.rs / process orchestrator / 默认 SUT manifest
- ⚠ high-risk：跨多服务真实联调 / federation 两边节点 / quarantine policy

## 当前状态摘要

- **代码量**：`src/conformance/*.rs`（11 子模块）+ `src/harness.rs` + 18 个场景文件，总 ~6K 行 Rust。
- **运行模式**：`process` 直接 `cargo run` SUT；`compose` 通过 `run-compose.ps1` 统一 bridge contract matrix；`docker` 与 Complement 同形态。
- **release gate**：`--Profile release-gate` 已落地，12 个测试通过。
- **conformance fixtures**：14 个 fixture 测试全部通过；`schema_validation` 覆盖全部 34 个 schema。
- **已完成**：F1 compose harness、F2 conformance.rs 拆分、F3 spec artifact 同步 gate、F4 artifacts 输出整理、F5 secret scan、A2 schema validation、A6 剔除清理、S2 release gate、Q5 profile 支持。

---

## P0 · v1 wire model rework conformance ⚠ 🔒

> 起源：`contrix-spec` 2026-05-07 完成 Phase 1-5。详见根 [`../_todos.md` C10.C](../_todos.md) 与 [`../contrix-spec/_state_todos.md`](../contrix-spec/_state_todos.md)。
>
> Gate：本仓 SUT 升级（contrix-rust-sdk W1-W13 + soland T2.5）后才能跑通；现有 fixture 直接 sync 会因 schema 变化（state_key 字段移除、新 event kinds、新 proof 类型）失败。

| # | 任务 | 文件 |
|---|---|---|
| **W1** ⚠ | 同步 `contrix-spec/spec/v1/artifacts/`：active event kind 110 → **129**（+19 新 kinds）、profiles 48 → **50**（+`hub_writer` / `peer_mesh`）。`schema_validation` 全量重跑；预期会发现 fixture 引用 stale schema/kind。 | `src/conformance/state_resolution.rs`、所有 fixture |
| **W2** ⚠ | Fixture 全部移除 envelope-level `state_key` 字段；`cx.member.state` payload 加 `actor_id`；composite state subject 用 `state_subject` 派生而非 `state_key`。本仓 `src/conformance/state_resolution.rs` 4 处 state_key 引用同步。 | `src/conformance/state_resolution.rs`、`tests/fixtures/*.json` |
| **W3** ⚠ | 新 fixture `host_endorsement_fixture.json`：hub Space happy path / 缺 endorsement → `proof_missing` reject / wrong host_did → `host_mismatch` reject / peer_mesh Space 出现 endorsement → `schema_violation` reject / activation_frontier 边界。 | 新 `tests/fixtures/host_endorsement_fixture.json`、`scenarios/space_permissions.rs` |
| **W4** ⚠ | 新 fixture `host_transfer_fixture.json`：smooth dual-sign happy / 单签 reject / emergency without quorum reject / activation_frontier 后旧 host endorsement reject / standby_hosts 之外的 new_host warning。 | 新 `tests/fixtures/host_transfer_fixture.json`、`scenarios/space_permissions.rs` |
| **W5** ⚠ | 新 fixture `consent_fixture.json`：consent grant → invite 接受 / consent revoke → invite reject / scope=any 全覆盖 / pseudonym DID 场景 / `require_consent` profile 强制路径。 | 新 `tests/fixtures/consent_fixture.json`、`scenarios/api_contracts_auth.rs` |
| **W6** ⚠ | `state-resolution-fixture.json`：本仓识别新 `state_slot` 描述符字段（spec 已重写）；hub fork diagnostic vector（§9.5）：双 host endorsement 同 slot → 整 slot quarantine。 | `src/conformance/state_resolution.rs` |
| **W7** | `mls_state_binding.full.v1` 必需 component 验证：E2EE Space commit 缺 `policy_root_required_components` 中任一 → reject；`pending_mls_binding` 状态可见性。 | `scenarios/delivery_media.rs`、`scenarios/protocol_payloads.rs` |
| **W8** | MIMI consent / room policy components 互译矩阵：按 `mimi-interop.md` §9.1 / §9.2 互译表跑双向 round-trip。 | `scenarios/api_contracts_auth.rs` |
| **W9** | `profile_tiers` schema_validation：含 `writer_model_profiles` 新顶层 section + `hardening_profiles.cx.profile.mls_state_binding.full.v1` 已从 e2ee_client optional_extensions 升为 inherits。 | `src/conformance/profile_validation.rs` |
| **W10** 🔒 | release gate 12/12 → 增量保持全绿；新 fixture 加入 `release-gate` profile。 | `scripts/run-release-gate.ps1`、`profile_tiers` 配置 |
| **W11** | Stream B4（composite state-key encoding round-trip）改名为 composite **state subject** encoding round-trip；测试向量按 spec encoding.md §9.5 重写。 | `scenarios/protocol_payloads.rs`（B4） |
| **W12** | Stream A1 active event kind 数 110 → 129 全覆盖。新 kinds 至少各 1 positive + 1 negative：`cx.space.policy / join_rule / history_visibility / discovery / policy_server / policy_components / history_sharing_policy / asset_privacy_policy / moderation_policy / plaintext_visible_services / media_service / schema / inheritance_policy / archive / freeze / tombstone / destroy / host / host.transfer / consent.grant / consent.revoke`。 | `scenarios/protocol_payloads.rs` (A1) |

---

## P1 · 并行扩面（六路）

### Stream A · Protocol Payload / Event-kind / Schema 覆盖

| # | 任务 | 文件 |
|---|---|---|
| A1 🅿 | 把 `event-kind-registry.json` 当前 active event kind（110）的 negative + positive vector 全覆盖。 | `scenarios/protocol_payloads.rs` |
| A3 🅿 | `operation-registry.json` 现有 83 个 operation 的 happy-path + 2 个 negative path。 | 同上 |
| A4 🅿 | `error-code-registry.json` 现有 42 个 error code 的产生路径回归。 | 同上 |
| A5 🅿 | `cx.key.verification.*` + `cx.schema.device_message.v1` + `cx.schema.key_backup.v1` negative vectors 扩展到所有 sub-kind。 | 同上 |

### Stream B · State Resolution / Reducer / Auth State

| # | 任务 | 文件 |
|---|---|---|
| B1 🅿 | quarantine-on-fork 算法的 fork / merge / lose / replay 五条向量。 | `scenarios/space_permissions.rs` |
| B2 🅿 | redaction reducer：`actor_seq` 保留 / `payload` 清除 / 不串改 envelope hash。 | `scenarios/protocol_payloads.rs` |
| B3 🅿 | history_visibility 三档与 join_rule × discoverability 矩阵。 | `scenarios/space_permissions.rs` |
| B4 🅿 | composite state-key encoding round-trip + 碰撞 negative vectors。 | `scenarios/protocol_payloads.rs` |
| B5 🅿 | membership transition 合法 / 非法状态机覆盖。 | `scenarios/space_permissions.rs` |

### Stream C · Authz / Capability / Policy

| # | 任务 | 文件 |
|---|---|---|
| C1 🅿 | v1.0 constraint 8 family + subtype 全覆盖：每个 family 至少 1 positive + 1 negative。 | `scenarios/authz_policy_presence.rs` |
| C2 🅿 | condition.kind 全覆盖。 | 同上 |
| C3 🅿 | invite ↔ grant ↔ policy 三者联动。 | 同上 |
| C4 🅿 | `evaluation_class` 缓存桶行为差异向量。 | 同上 |
| C5 🅿 | deny / quarantine / require_review / allow 的优先级断言。 | 同上 |
| C6 🅿 | obligation 实际执行回归。 | 同上 |

### Stream D · Crypto / E2EE / Devices

| # | 任务 | 文件 |
|---|---|---|
| D1 ⚠ | MLS proposal / commit / welcome / keypackage / epoch round-trip 多设备真实场景。 | `scenarios/delivery_media.rs` |
| D2 🅿 | KeyPackage shape 统一（spec B-10）。 | 同上 |
| D3 🅿 | KeyBackup envelope negative vectors。 | 同上 |
| D4 🅿 | encrypted envelope AAD 漂移拒绝。 | `scenarios/protocol_payloads.rs` |
| D5 🅿 | RYW receipt event kind 注册 + audit profile marketing-term 拒绝向量。 | `scenarios/authz_policy_presence.rs` |

### Stream E · Federation / MIMI

| # | 任务 | 文件 |
|---|---|---|
| E1 🔒 | **真实双节点 federation**：harness 启动 2 个 soland 实例 + service DID 互信；事件交换 / frontier exchange / replay / quarantine 全流程。 | `src/harness.rs`、`scenarios/federation_*.rs` |
| E2 🅿 | RFC 9421 transcript fields 合法 / 缺失 / 重放向量。 | 同上 |
| E3 🅿 | Content-Digest 合法 / 错算 / 缺失向量。 | 同上 |
| E4 🅿 | CommitFork detection。 | 同上 |
| E5 🅿 | MIMI room_update / notify / room_message / consent / key_material / identifiers_query happy + negative 向量。 | `scenarios/api_contracts_auth.rs` |
| E6 🅿 | revocation fan-out TTL + 重试策略。 | 同上 |

### Stream F · Recovery / Push / Identity 联动

| # | 任务 | 文件 |
|---|---|---|
| F-1 🅿 | `[~]` recovery bridge 全链路：`coauth principal-snapshot` → `principal-cache fetch/refresh/invalidate` → `restore ticket` 全状态机。release gate 已覆盖 soland scaffold surface；真实 coauth→soland refresh 仍是后续。 | `scenarios/bridge_contracts.rs` |
| F-2 🅿 | `[~]` restore approval / executor / artifact 全套失败路径和 durable worker。 | 同上 |
| F-3 🅿 | push privacy 黑盒矩阵（spec B-14）：DID 进 token / payload / TURN credential 全部 fail closed。 | `scenarios/delivery_media.rs` |
| F-4 🅿 | push gateway drift detection。 | 同上 |
| F-5 🅿 | identity progressive disclosure verifier authority chain。 | `scenarios/identity_directory_index.rs` |
| F-6 🅿 | `[~]` DID resolver policy：已新增 `starid_optional_resolver_profile_is_discoverable`；trust roots / live StarID vectors 仍待补。 | `scenarios/bridge_contracts.rs` |

---

## P2 · Profile / Conformance / Release Gate

| # | 任务 | 文件 |
|---|---|---|
| S1 🔒 | **profile_tiers 校验**：把 `conformance-profiles.json` 的 tier 划分作为 `--profile=core` / `--profile=ext` CLI 选项。 | `src/harness.rs`、`scripts/*` |
| S3 🅿 | `summary.html` 加 profile coverage matrix + delta vs last run + flake list。 | `src/harness.rs` |
| S4 🅿 | flake guard：每个 vector 标注期望 deterministic / nondeterministic。 | 同上 |

---

## P3 · 工程质量 / 可观测性

| # | 任务 | 文件 |
|---|---|---|
| Q1 🅿 | scenarios 模块化：每个文件 < 1000 行。 | `src/scenarios/*` |
| Q2 🅿 | 共享 fixture 抽到 `tests/common/` 或 `src/fixtures/`。 | `src/scenarios/*` |
| Q3 🅿 | tracing：harness 内部子进程 stdout/stderr 走结构化 transcript。 | `src/harness.rs` |
| Q4 🅿 | docker 模式：`build-soland-image.ps1` 改 multi-stage，镜像 < 100MB。 | `docker/*`、`scripts/*` |

---

## 并行调度建议

| Sprint | 可并行 |
|---|---|
| Sprint 1（扩面） | A · B · C · D · E · F 六路；其中 E1 双节点 federation 是 ⚠，C stream 先按 8 family + subtype 重写测试矩阵 |
| Sprint 2（gate） | S1 / S3 / S4 + Q1..Q4 |

**冲突点**：
- E1（双节点 federation）/ F-1..F-2（recovery 多服务）/ F-3..F-4（push 多服务）必须等 compose harness 稳定
- A1..A5 与 SUT（soland）真实实现进度强耦合

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C4 | push wakeup + session-grant push registration 场景已覆盖。 |
| C5 | recovery restore surface 已进入 release gate；真实 coauth→soland refresh 待补。 |
| C6 | optional StarID resolver discovery 已进入 release gate；live vectors 待补。 |
| C8 | release gate 12/12 通过。 |
| C10.C | **本仓是 C10 联调最后一关**——SDK + soland 消化 wire 改动后，cotest fixture 全量 refresh + 双轨（hub / peer_mesh）conformance 套件就位。P0 W1-W12 是本仓全部 C10 任务。 |

## 不在本轮范围

- 多 region / 多数据中心 federation 真实压测
- 不同 SUT（非 soland）适配
- WebRTC 端到端通话媒体真实抓包测试

## 已完成（changelog）

- `[x]` F1 compose harness 默认化。
- `[x]` F2 conformance.rs 拆分（11 子模块）。
- `[x]` F3 spec artifact 同步 gate。
- `[x]` F4 artifacts 输出整理。
- `[x]` F5 secret scan & redaction。
- `[x]` A2 schema validation（34 schema，124+31+46+192 vectors）。
- `[x]` A6 剔除清理（`cx.(subject|room|card).` 零命中）。
- `[x]` S2 release gate 12/12 通过。
- `[x]` Q5 `--Profile` 支持（fast-smoke / compose / release-gate / full-nightly）。
