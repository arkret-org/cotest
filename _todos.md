# cotest — Contrix Black-box Test Harness TODO

> 整理日期：2026-05-07
> 协议参考：`contrix-spec/spec/v1/zh/conformance/` + `contrix-spec/spec/v1/artifacts/`。
> 项目栈：Rust（cargo test 入口） + PowerShell harness scripts + 可选 Docker compose；定位类似 Matrix Complement。

## 标记说明

- 🅿 parallel-safe：单 scenario / 单 vector / 单 fixture
- 🔒 sequential：动 harness.rs / process orchestrator / 默认 SUT manifest
- ⚠ high-risk：跨多服务真实联调 / federation 两边节点 / quarantine policy

## 当前状态摘要

- **代码量**：`src/conformance/*.rs`（13 子模块，含 lattice_round_trip 18-case）+ `src/harness.rs` + 18 个场景文件，总 ~6K 行 Rust。
- **运行模式**：`process` 直接 `cargo run` SUT；`compose` 通过 `run-compose.ps1` 统一 bridge contract matrix；`docker` 与 Complement 同形态。
- **release gate**：`--Profile release-gate` 已落地。Move/Anchor/Lattice rebase 后 host_endorsement / host_transfer fixture 已删除（C11），release-gate 当前 **15** 个测试通过；目标 ≥18（含 anchorer_cell / lattice_round_trip / conflict_repair）— 见下方 P0 Move/Anchor/Lattice fixture refresh M3-M13。
- **conformance fixtures**：**20** 个 fixture 测试全部通过（含新增 lattice_round_trip 直接 exercise SDK contrix-lattice crate 真实 join 语义）；`schema_validation` 覆盖全部 34 个 schema；event-kind registry 强制 ≥129 active kinds + ≥50 profiles + 每个 active state kind 必须声明 cardinality/component_type/criticality（per_subject 还需 state_subject_field）。
- **已完成**：F1 compose harness、F2 conformance.rs 拆分、F3 spec artifact 同步 gate、F4 artifacts 输出整理、F5 secret scan、A2 schema validation、A6 剔除清理、S2 release gate、Q5 profile 支持；C11 旧 host_endorsement / host_transfer / mimi-host fixture 清理（2026-05-08）；C13.C state_resolution.rs 重写为 move_anchor_lattice 委派 + composite/consent/mimi fixture 措辞对齐；**C10.C lattice_round_trip suite (2026-05-09)** 新增 `src/conformance/lattice_round_trip.rs` 9 case 直接调用 SDK lattice crate 验 OrSet/CasRegister/Counter/Fsm/MvRegister/OrderedLog 真实 join 语义。

---

## P0 · Move / Anchor / Lattice fixture refresh ⚠ 🔒

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 替换旧模型。详见根 [`../_todos.md` C10.C](../_todos.md)。
>
> Gate：contrix-rust-sdk M0-M12 + soland MAL-1~MAL-12 落地后才能跑端到端 verify_move / apply_anchor。registry/schema 静态校验可立即开始。

| # | 状态 | 任务 | 文件 |
|---|---|---|---|
| **M1** ⚠ | `[x]` | 删除 `tests/fixtures/host_endorsement_fixture.json` / `host_transfer_fixture.json` + 对应 suite 函数；release-gate 17/17 → 15/15（C11 完成 2026-05-08）。 | `tests/fixtures/`、`src/conformance/wire_model.rs`、`config/ci-profiles.json` |
| **M2** ⚠ | `[x]` | `move-anchor-lattice-fixture.json` 全识别 + 静态校验：`state_resolution.rs` 重写为 `run_move_anchor_lattice_fixture_suite`，`state_resolution_fixture_suite_matches_reference_semantics` + `move_anchor_lattice_fixture_suite_matches_reference_semantics` 两条 cargo test 名都进了 release-gate。 | `src/conformance/wire_model.rs`、`src/conformance/state_resolution.rs` |
| **M3** | `[~]` | (2026-05-09) `src/conformance/lattice_round_trip.rs` 内嵌 5 case：4 profile happy path（single_did / threshold k-of-n / open_set / mixed）+ 并发 reconfig→Bottom Conflict（split anchorer = Space-wide pause）。signature mismatch / threshold below quorum / recovery anchorer 上位是 verify_move + anchorer worker 行为（lattice 层之上），等 LatticeRegistry 接到 Move/Anchor receive pipeline 后再黑盒覆盖。 | `src/conformance/lattice_round_trip.rs` |
| **M4** | `[x]` | (2026-05-09) **不走 fixture JSON，走真实 SDK round-trip**：`src/conformance/lattice_round_trip.rs` 9 个 case 直接 exercise SDK `contrix-lattice` crate 的 `join` 语义。覆盖 OrSet 因果 add/remove + 幂等 re-add、CasRegister 并发→`Bottom::Conflict` + 单写→Value、Counter PN sum (5+3-2=6)、Fsm legal/illegal、MvRegister 并发多值（accept Value-array 或 Bottom-with-heads）、OrderedLog per-issuer monotonic append。`run_lattice_round_trip_suite` exposed via `cotest::conformance` + `tests/conformance_fixtures.rs::lattice_round_trip_suite_matches_reference_semantics` 进 release-gate。 | `src/conformance/lattice_round_trip.rs`、`src/conformance/mod.rs`、`tests/conformance_fixtures.rs` |
| **M5** | `[~]` | (2026-05-09) `src/conformance/lattice_round_trip.rs` 内嵌 2 case：head_in 修复 Move 单 anchored op 后 cas-register 解 Bottom→Value、自我授权 winner 在 lattice 层不被解读为 winner（payload 不被窥探）。`bottom_escalation_after_ms` 超时不自动选 winner 是 anchorer worker 行为，等 C10.B 后续。 | `src/conformance/lattice_round_trip.rs` |
| **M6** | `[ ]` | 新增 `tests/fixtures/anchor_view_compaction_fixture.json`：多 leaf Anchor effective_anchor_view 纯函数 / signed compaction Anchor 等价 / compaction 不丢失 bottom diagnostics。 | `tests/fixtures/` |
| **M7** | `[~]` | (2026-05-09) `src/conformance/lattice_round_trip.rs` 内嵌 2 case：covered_frontier or-set 累积 governance refs（含重复 add 幂等）+ rotation 后 causal remove 仅消旧 ref 保留其他。E2EE message Move 缺 covered_frontier → fail_precondition / governance Move 不受阻 / MLS commit Move 三 cell 写入是 verify_move + 多 cell coordination 层（lattice 之上），等 LatticeRegistry 接到 Move/Anchor receive pipeline 后再黑盒覆盖。 | `src/conformance/lattice_round_trip.rs` |
| **M8** | `[ ]` | 改写 `tests/fixtures/consent_fixture.json` 为 consent cell or-set Move 形式：grant=add tag, revoke=remove tag；invite gate 改为 invite Move 在 consent cell join 值上的 precondition。 | `tests/fixtures/consent_fixture.json` |
| **M9** | `[ ]` | 重新评估 `tests/fixtures/composite_state_subject_fixture.json`：5 种 composite 形态映射到 cell_subject 的 `composite` descriptor；保留 hash 形态 + reorder/pipe negative。 | `tests/fixtures/composite_state_subject_fixture.json` |
| **M10** | `[ ]` | 改写 `mimi_components_fixture` §9.1：hub-writer host / host.transfer 强制 contrix_only 项作废 → anchorer cell value 在 contrix_only 标注。 | `tests/fixtures/mimi_components_fixture.json` |
| **M11** | `[ ]` | `validate_event_kind_registry` 阈值更新到 spec 2026-05-08 active 数（≥134）；要求每个 reducer-input durable kind 声明 cell_family / cell_subject / lattice / bottom；强制 cx.move.v1 / cx.anchor.v1 必存。 | `src/conformance/registry.rs` |
| **M12** | `[ ]` | profile_tiers schema_validation：`writer_model_profiles` 移除；如 spec 引入 `anchor_profile_tiers` 则纳入。 | `src/conformance/registry.rs` |
| **M13** 🔒 | `[ ]` | release gate 重新拉到全绿。目标 ≥18：15 旧通过 + move_anchor_lattice (M2 已纳入) + anchorer_cell + lattice_round_trip + conflict_repair（其余 fixture 视成熟度纳入 nightly）。 | `config/ci-profiles.json` |

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
