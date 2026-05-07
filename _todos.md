# cotest — Contrix Black-box Test Harness TODO

> 整理日期：2026-05-07
> 协议参考：`contrix-spec/spec/v1/zh/conformance/` + `contrix-spec/spec/v1/artifacts/`。
> 项目栈：Rust（cargo test 入口） + PowerShell harness scripts + 可选 Docker compose；定位类似 Matrix Complement。

## 标记说明

- 🅿 parallel-safe：单 scenario / 单 vector / 单 fixture
- 🔒 sequential：动 harness.rs / process orchestrator / 默认 SUT manifest
- ⚠ high-risk：跨多服务真实联调 / federation 两边节点 / quarantine policy

## 当前状态摘要

- **代码量**：`src/conformance/*.rs`（12 子模块）+ `src/harness.rs` + 18 个场景文件，总 ~6K 行 Rust。
- **运行模式**：`process` 直接 `cargo run` SUT；`compose` 通过 `run-compose.ps1` 统一 bridge contract matrix；`docker` 与 Complement 同形态。
- **release gate**：`--Profile release-gate` 已落地，**17** 个测试通过（+host_endorsement / host_transfer / consent / composite_state_subject / mimi_components）。
- **conformance fixtures**：**19** 个 fixture 测试全部通过；`schema_validation` 覆盖全部 34 个 schema；event-kind registry 强制 ≥129 active kinds + ≥50 profiles + 每个 active state kind 必须声明 cardinality/component_type/criticality（per_subject 还需 state_subject_field）。
- **已完成**：F1 compose harness、F2 conformance.rs 拆分、F3 spec artifact 同步 gate、F4 artifacts 输出整理、F5 secret scan、A2 schema validation、A6 剔除清理、S2 release gate、Q5 profile 支持；P0 W1 / W3 / W4 / W5 / W6（cotest 侧）/ W7 / W8 / W9 / W10 / W11 / W12（partial）。

---

## P0 · v1 wire model rework conformance ⚠ 🔒

> 起源：`contrix-spec` 2026-05-07 完成 Phase 1-5。详见根 [`../_todos.md` C10.C](../_todos.md) 与 [`../contrix-spec/_state_todos.md`](../contrix-spec/_state_todos.md)。
>
> Gate：本仓 SUT 升级（contrix-rust-sdk W1-W13 + soland T2.5）后才能跑通；现有 fixture 直接 sync 会因 schema 变化（state_key 字段移除、新 event kinds、新 proof 类型）失败。

| # | 任务 | 文件 |
|---|---|---|
| **W1** ⚠ | `[x]` `schema_validation` 全量重跑；event-kind registry 强制 ≥129 active kinds + 强制存在 `cx.space.host` / `cx.space.host.transfer` / `cx.consent.{grant,revoke}`；profile registry 强制 ≥50 profile id 并识别 `writer_model_profiles` / `encoding_extension_profiles` / 各 hardening section 中的 `cx.profile.*` 入口。 | `src/conformance/registry.rs` |
| **W2** ⚠ | `[~]` Fixture 已在 spec 侧重写（spec Phase 1 完成）；本仓 `state_resolution.rs` 中 4 处 `state_key` 引用是 container/field-position register key（合法的本地概念，非 envelope state_key），保留。剩余动作只在 SUT 升级后跑通端到端 vector 时会被触及。 | `src/conformance/state_resolution.rs`、`tests/fixtures/*.json` |
| **W3** ⚠ | `[x]` `tests/fixtures/host_endorsement_fixture.json` + `run_host_endorsement_fixture_suite`：hub happy / proof_missing / host_mismatch / peer_mesh 出 endorsement → schema_violation / activation_frontier 后旧 host reject / 双 endorsement 同 slot → host_fork_diagnostic quarantine。 | `tests/fixtures/host_endorsement_fixture.json`、`src/conformance/wire_model.rs` |
| **W4** ⚠ | `[x]` `tests/fixtures/host_transfer_fixture.json` + `run_host_transfer_fixture_suite`：smooth dual-sign accept / 单签 proof_missing / emergency 无 quorum insufficient_quorum / activation_frontier 后旧 host follow_up host_mismatch / standby 外 new_host warning。 | `tests/fixtures/host_transfer_fixture.json`、`src/conformance/wire_model.rs` |
| **W5** ⚠ | `[x]` `tests/fixtures/consent_fixture.json` + `run_consent_fixture_suite`：grant → invite accept / revoke → invite reject(consent_required) / scope=any 覆盖语音呼叫 / pseudonym DID grant / require_consent profile 阻挡 unconsented invite。 | `tests/fixtures/consent_fixture.json`、`src/conformance/wire_model.rs` |
| **W6** ⚠ | `[x]` 本仓在 `run_state_resolution_artifact_suite` 中识别 `state_slot` 描述符并断言 candidate kind 与 slot kind 一致；hub fork diagnostic vector 通过 `host_endorsement_fixture` 的 `hub_space_double_host_endorsement_same_slot_quarantines` 覆盖。 | `src/conformance/state_resolution.rs`、`src/conformance/wire_model.rs` |
| **W7** | `[~]` Registry 侧已强制 `mls_state_binding.full.v1` 三组 `*_required_components` 非空且每个 component_type 在 event-kind registry 注册（Phase 3 校验）。E2EE Space commit 缺 component → reject 与 `pending_mls_binding` 可见性需 SUT 实装后由 `delivery_media` 真实场景覆盖。 | `src/conformance/registry.rs`、`scenarios/delivery_media.rs` |
| **W8** | `[x]` `tests/fixtures/mimi_components_fixture.json` + `run_mimi_components_fixture_suite`：§9.2 criticality 三档 round-trip（required↔must_understand / optional↔should_understand / ignore↔silently_drop）；§9.1 component_type 矩阵 ≥5 bidirectional + ≥5 contrix_only；contrix_only 必须用 `application/vnd.contrix.component+json` facade media-type；hub-writer host / host.transfer 强制 contrix_only。component_type 全部 cross-check 进 event-kind registry。 | `tests/fixtures/mimi_components_fixture.json`、`src/conformance/wire_model.rs` |
| **W9** | `[x]` `validate_profile_registry` 新增 `writer_model_profiles` 收录、`encoding_extension_profiles` 识别、各 `*_hardening` / `mimi_interop` 中 `cx.profile.*` 收录；`validate_profile_requirements` 强制 `cx.profile.e2ee_client.v1.inherits` 包含 `cx.profile.mls_state_binding.full.v1`。 | `src/conformance/registry.rs` |
| **W10** 🔒 | `[x]` release gate 12/12 → **17/17**：新增 host_endorsement / host_transfer / consent / composite_state_subject / mimi_components fixture 进 `release-gate` cargo_filters。 | `config/ci-profiles.json` |
| **W11** | `[x]` `tests/fixtures/composite_state_subject_fixture.json` + `run_composite_state_subject_fixture_suite`：§9.5 5 种标准 composite kind（flow.branch.member / flow.branch.history_visibility / flow.branch.policy_components / device.authorized / device.revoked）的 components_array → canonical_json → sha256 → base64url_nopad 全链路；同 components_array 不同 kind 共享 hash 验证；revoke / authorized 共享 slot；reorder negative + pipe-form negative MUST 与 canonical 不同。 | `tests/fixtures/composite_state_subject_fixture.json`、`src/conformance/wire_model.rs` |
| **W12** | `[~]` registry 侧覆盖闸门已落地：每个 active state-bearing kind 必须声明 `state_cardinality` + `component_type` + `criticality`，per_subject 还需 `state_subject_field`；4 个新 wire-model kind 强制 (cardinality, criticality) 精确值。SUT 实装后再补每 kind ≥1 positive + 1 negative 真实场景向量。 | `src/conformance/registry.rs`、`scenarios/protocol_payloads.rs` (A1) |

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
- `[x]` 2026-05-07 P0 wire-model rework conformance（两波合并）：
  - W1：event-kind registry 强制 ≥129 active kinds + 4 个新关键 kinds 必存；profile registry 强制 ≥50 profile id（包含 `writer_model_profiles`）。
  - W3 / W4 / W5：新增 `tests/fixtures/host_endorsement_fixture.json` / `host_transfer_fixture.json` / `consent_fixture.json` 共 16 条 vector，由 `src/conformance/wire_model.rs` 的 3 个 suite 函数静态校验。
  - W6（本仓侧）：`run_state_resolution_artifact_suite` 识别 `state_slot` 描述符并断言 slot/kind 一致；hub fork diagnostic 在 host_endorsement fixture 中覆盖。
  - W7（registry 侧）：`mls_state_binding.full.v1` 三组 `*_required_components` 全部 cross-check 进 event-kind registry 的 component_type。
  - W8：新增 `tests/fixtures/mimi_components_fixture.json` + `run_mimi_components_fixture_suite`，覆盖 §9.1（component_type 互译，5+ bidirectional + 5+ contrix_only）和 §9.2（criticality 三档）。
  - W9：`validate_profile_registry` 新增 `writer_model_profiles` / `encoding_extension_profiles` / `*_hardening` / `mimi_interop` 的 `cx.profile.*` 收录；`e2ee_client.v1` 强制 inherit `mls_state_binding.full.v1`。
  - W10：release-gate 由 12/12 升至 **17/17**。
  - W11：新增 `tests/fixtures/composite_state_subject_fixture.json` + `run_composite_state_subject_fixture_suite`（§9.5 全 5 种 composite kind 的 hash 形态 + reorder/pipe negative）。
  - W12（partial）：每个 active state-bearing kind 必须声明 cardinality + component_type + criticality；4 个新 wire-model kind 锁定精确 cardinality / criticality。
  - 19 / 19 conformance fixture 测试 + 17 / 17 release-gate 全绿。
