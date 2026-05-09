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
- **release gate**：`--Profile release-gate` 已落地。Move/Anchor/Lattice rebase 后 host_endorsement / host_transfer fixture 已删除（C11）。Round-21 (2026-05-09) 收紧：anchorer_cell / conflict_repair / mls_move_covered_frontier / discovery_profile 全部纳入 cargo_filters，release-gate 当前 **22/22** 通过（17 个 conformance fixture 套件 + 5 个 scenario 套件），远超 ≥18 目标。
- **conformance fixtures**：**25** 个 fixture 测试全部通过（含 round-21 新增 `discovery_profile_fixture_suite`）；`schema_validation` 覆盖全部 34 个 schema；event-kind registry 强制 ≥132 active kinds（spec 当前快照 active=132，floor 与 spec 同步）+ ≥47 profiles + reducer-input durable + cell_family 必同时声明 cell_subject (null 形 = 空间单例显式声明)；`writer_model_profiles` 顶层 group key 严拒；`anchor_profile_tiers` shape 校验 + `anchor_profiles` cx.profile.anchor.* namespace 校验；**round-21 typed-id validator hardening**：`validate_typed_id_ref` 对非 special-form (cursor/blob/mls/pseudonym/anchor/cell) 的 id kind 强制 36-char UUIDv7 wire form (RFC 9562 v7+variant ∈ {8,9,a,b})，与 SDK round-20 envelope 校验对齐；cotest src 与 fixtures 中残留的 `cx:event:01js0...` / `cx:event:gov:01` / `cx:event:proof-demo` / `cx:space:fixture` / `cx:snapshot:01JS0...` 等非 UUIDv7 字面量全部 flip 为确定性 UUIDv7。
- **已完成**：F1 compose harness、F2 conformance.rs 拆分、F3 spec artifact 同步 gate、F4 artifacts 输出整理、F5 secret scan、A2 schema validation、A6 剔除清理、S2 release gate、Q5 profile 支持；C11 旧 host_endorsement / host_transfer / mimi-host fixture 清理（2026-05-08）；C13.C state_resolution.rs 重写为 move_anchor_lattice 委派 + composite/consent/mimi fixture 措辞对齐；**C10.C lattice_round_trip suite (2026-05-09)** 新增 `src/conformance/lattice_round_trip.rs` 9 case 直接调用 SDK lattice crate 验 OrSet/CasRegister/Counter/Fsm/MvRegister/OrderedLog 真实 join 语义；**C19/C20/C21 wire-break 验证 (2026-05-09 spec f724863)**: `validate_id_kind_registry` 接受新 top-level `uuid_pattern` / `typed_uuid_pattern`、reject 旧 `ulid_pattern` / `typed_ulid_pattern` + 旧 `<ulid>` token；`validate_value_refs` 在所有 fixture 走 (a) reject `actor_type` key (C20: spec 改 `actor_kind`), (b) reject content_block 形 `{body, type, !kind}` 中 type=cx.content.* / text / image / file (C21: spec 改 `content_block.kind` / `content_kind`)；M6 anchor_view_compaction_fixture + suite + release-gate 已加入；M8 consent_fixture or-set Move 改写完成。

---

## P0 · Move / Anchor / Lattice fixture refresh ⚠ 🔒

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 替换旧模型。详见根 [`../_todos.md` C10.C](../_todos.md)。
>
> Gate：contrix-rust-sdk M0-M12 + soland MAL-1~MAL-12 落地后才能跑端到端 verify_move / apply_anchor。registry/schema 静态校验可立即开始。

| # | 状态 | 任务 | 文件 |
|---|---|---|---|
| **M1** ⚠ | `[x]` | 删除 `tests/fixtures/host_endorsement_fixture.json` / `host_transfer_fixture.json` + 对应 suite 函数；release-gate 17/17 → 15/15（C11 完成 2026-05-08）。 | `tests/fixtures/`、`src/conformance/wire_model.rs`、`config/ci-profiles.json` |
| **M2** ⚠ | `[x]` | `move-anchor-lattice-fixture.json` 全识别 + 静态校验：`state_resolution.rs` 重写为 `run_move_anchor_lattice_fixture_suite`，`state_resolution_fixture_suite_matches_reference_semantics` + `move_anchor_lattice_fixture_suite_matches_reference_semantics` 两条 cargo test 名都进了 release-gate。 | `src/conformance/wire_model.rs`、`src/conformance/state_resolution.rs` |
| **M3** | `[x]` | (2026-05-09 round-20) Stand-alone JSON fixture `tests/fixtures/anchorer_cell_fixture.json` + `run_anchorer_cell_fixture_suite`：4 happy-path（single_did / threshold k-of-n / open_set / mixed_recovery）+ 并发 reconfig→Bottom Conflict + 4 negative（signature mismatch / threshold below quorum / k>n geometry / registry drift canary）。lattice 层 join 语义仍由 `lattice_round_trip.rs` 5 case 真 SDK round-trip 兜底；JSON fixture 是 SUT 黑盒形态。 | `tests/fixtures/anchorer_cell_fixture.json`、`src/conformance/wire_model.rs`、`src/conformance/lattice_round_trip.rs` |
| **M4** | `[x]` | (2026-05-09) **不走 fixture JSON，走真实 SDK round-trip**：`src/conformance/lattice_round_trip.rs` 9 个 case 直接 exercise SDK `contrix-lattice` crate 的 `join` 语义。覆盖 OrSet 因果 add/remove + 幂等 re-add、CasRegister 并发→`Bottom::Conflict` + 单写→Value、Counter PN sum (5+3-2=6)、Fsm legal/illegal、MvRegister 并发多值（accept Value-array 或 Bottom-with-heads）、OrderedLog per-issuer monotonic append。`run_lattice_round_trip_suite` exposed via `cotest::conformance` + `tests/conformance_fixtures.rs::lattice_round_trip_suite_matches_reference_semantics` 进 release-gate。 | `src/conformance/lattice_round_trip.rs`、`src/conformance/mod.rs`、`tests/conformance_fixtures.rs` |
| **M5** | `[x]` | (2026-05-09 round-20) Stand-alone JSON fixture `tests/fixtures/conflict_repair_fixture.json` + `run_conflict_repair_fixture_suite`：3 positive（head_in 单 anchored op 解 Bottom / self-authorising winner 在 lattice 层不被解读 / 手动 repair 走 recovery_capability + anchorer_endorsement）+ 2 negative（missing recovery_capability / head_in 与 prior_bottom 不匹配的 drift）。lattice 层语义仍由 `lattice_round_trip.rs` 2 case 真 SDK round-trip 兜底。 | `tests/fixtures/conflict_repair_fixture.json`、`src/conformance/wire_model.rs`、`src/conformance/lattice_round_trip.rs` |
| **M6** | `[x]` | (2026-05-09 spec f724863) 新增 `tests/fixtures/anchor_view_compaction_fixture.json` + `run_anchor_view_compaction_fixture_suite` (in `wire_model.rs`)：3 positive vector（single-leaf passthrough / 2-leaf concurrent compaction / bottom diagnostics preservation）+ 2 negative vector（dropped bottom diagnostic, drifted state_root）。fixture 验 (a) effective_anchor_view.leaves == input anchor id set, (b) concurrent multi-leaf frontier == leaves, (c) signed compaction state_root + frontier 与 view 完全一致, (d) compaction.bottom_diagnostics ⊇ view.bottom_diagnostics（信息保留）, (e) anchor id 形式 cx:anchor:sha256:<64-hex>。conformance_fixtures 20/20 → **21/21**, release-gate 同步加入。 | `tests/fixtures/anchor_view_compaction_fixture.json`、`src/conformance/wire_model.rs`、`tests/conformance_fixtures.rs`、`config/ci-profiles.json` |
| **M7** | `[x]` | (2026-05-09 round-20) Stand-alone JSON fixture `tests/fixtures/mls_move_covered_frontier_fixture.json` + `run_mls_move_covered_frontier_fixture_suite`：4 positive（accumulate or-set 含幂等 re-add / rotation→causal remove 仅消旧 ref / governance Move preconditions=[] 不受阻 / MLS commit 单 Move 写 3 cells (covered_frontier + epoch + group_state)）+ 2 negative（E2EE 缺 covered_frontier precondition → fail_precondition / 陈旧 attests_to ref 不在 active_tags → fail_precondition）。lattice 层 or-set 语义仍由 `lattice_round_trip.rs` 2 case 兜底。 | `tests/fixtures/mls_move_covered_frontier_fixture.json`、`src/conformance/wire_model.rs`、`src/conformance/lattice_round_trip.rs` |
| **M8** | `[x]` | (2026-05-09 spec f724863) `tests/fixtures/consent_fixture.json` 完整改写为 or-set Move 形式：每个 vector 改 `events[]` → `moves[]`，每个 move 携带 `move_id` (cx:event:<uuidv7>) + `effects[]`（grant=or_set_add tag {peer, scope}, revoke=or_set_remove referencing prior grant move_ids）+ 下游 invite/message/call Move 的 `preconditions[]` (`consent_active{holder, peer, scope}`)。`run_consent_fixture_suite` 完整重写：replay or-set state per cell（map<cell_id, map<move_id, (peer, scope)>>），revoke 必须 reference prior op_id（causal predecessor），precondition 解析以 `scope=any` 作 wildcard。新增第 6 个 vector `idempotent_re_grant_after_revoke` 验 fresh grant 创建独立 op_id 不复活旧 tag。所有 typed id 用 UUIDv7 (C19)。 | `tests/fixtures/consent_fixture.json`、`src/conformance/wire_model.rs` |
| **M9** | `[ ]` | 重新评估 `tests/fixtures/composite_state_subject_fixture.json`：5 种 composite 形态映射到 cell_subject 的 `composite` descriptor；保留 hash 形态 + reorder/pipe negative。 | `tests/fixtures/composite_state_subject_fixture.json` |
| **M10** | `[x]` | (2026-05-09 verified) `tests/fixtures/mimi_components_fixture.json` 已无 host / host.transfer 引用；当前 contrix_only 项是 anchorer-class 私 surface（policy / policy_server / plaintext_visible_services / media_service / schema / inheritance_policy / consent.grant.v1），与 anchorer cell governance 模型一致。W8 旧 host_endorsement / host.transfer entries 在 C11 已清理。 | `tests/fixtures/mimi_components_fixture.json` |
| **M11** | `[x]` | (2026-05-09 round-20) `validate_event_kind_registry` 阈值升至 ≥132 (spec snapshot f724863 实际 active 数)；reducer-input durable kind 若声明 `cell_family` 则**必须**显式声明 `cell_subject` 字段（null 形 = 空间单例 = 19 个 cx.space.* 政策类，必须明确写 null 而非缺失）；其余 ≥45 个携带主体的 kind 强制 `field` / `composite` / `tuple` shape。负面 fixture 在 `anchorer_cell_fixture.json::missing_cell_family_for_anchorer_kind_rejected` 中以 canary 形式登记 reason_code = `registry_kind_missing_cell_family`。 | `src/conformance/registry.rs`、`tests/fixtures/anchorer_cell_fixture.json` |
| **M12** | `[x]` | (2026-05-09 round-20) `validate_profile_registry` 顶层 `writer_model_profiles` group key 严拒（清晰 error msg 指出 spec post-2026-05-08 已删除）；`anchor_profile_tiers` 若存在则校验 shape (object<tier_name, array<cx.profile.anchor.*>>)；`anchor_profiles` flat list 必须全部 `cx.profile.anchor.*` namespace；新增 `lattice_extension_profiles` / `interop_compat_profiles` / `hash_extension_profiles` / `anchor_profiles` 计入扩展集合（profile 总数仍 ≥47 不变）。 | `src/conformance/registry.rs` |
| **M13** 🔒 | `[x]` | (2026-05-09 round-21) release gate 拉至 **22/22** 全绿：新增 `anchorer_cell_fixture_suite` / `conflict_repair_fixture_suite` / `mls_move_covered_frontier_fixture_suite` / `discovery_profile_fixture_suite` 四条进 cargo_filters；旧 17 条全部保留。≥18 目标超额完成。 | `config/ci-profiles.json` |

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

- `[x]` 2026-05-09 round-21 release-gate refresh + discovery profile fixture + typed-id validator hardening：
  - M13 release-gate cargo_filters 从 17 → 22：新增 anchorer_cell / conflict_repair / mls_move_covered_frontier / discovery_profile 四条 conformance fixture 套件。
  - 新增 `tests/fixtures/discovery_profile_fixture.json` + `run_discovery_profile_fixture_suite`：6 个 positive vector（core-only / blob_storage 单独 / realtime_media 单独 / moderation_reports 单独 / mimi_interop bridge / applet bridge）+ 5 个 negative vector（bridge 在外部协议未支持时不可调用 / extension 未广告则被拒 / 旧 `moderation` 名 reject / 旧 `media` 合并名 reject / bridge 不蕴含 in-spec bridges_to）；validator 对照 live operation-registry surface_groups + 检查 post-C16 surface 名（blob_storage / realtime_media / moderation_reports）必存。
  - `validate_typed_id_ref` 收紧：非 special-form (cursor/blob/mls/pseudonym/anchor/cell) 的 id kind payload 必须是 36-char UUIDv7 (RFC 9562 v7 + variant ∈ {8,9,a,b})；新增 `is_uuidv7_shaped` 辅助函数。
  - 修正所有 `cx:<kind>:<not-uuidv7>` 字面量：`tests/fixtures/anchorer_cell_fixture.json` / `conflict_repair_fixture.json` / `mls_move_covered_frontier_fixture.json` 中 41 个 ULID-shape `cx:event:01js0...` 全部映射到确定性 UUIDv7；`src/conformance/encoding.rs` 的 `cx:event:proof-demo` / `cx:space:proof-demo` / `cx:relation:01js0r1...`、`capability.rs` 的 `cx:space:01JS0SP...`、`sync.rs` 的 `cx:snapshot:01JS0SN...` / `cx:space:fixture`、`federation.rs` 的 `cx:space:fork`、`redaction.rs` 的 `cx:event:redaction|missing|late|target`、`lattice_round_trip.rs` 的 `cx:event:gov:01|02|rotated|still_valid` 全部 flip。
  - active-event-kind floor 维持 ≥132（spec snapshot f724863 实际 active=132；提升空间留给后续 spec drift）。
  - conformance fixtures 24 → **25**，全部通过。
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
