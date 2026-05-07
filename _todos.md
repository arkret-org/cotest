# cotest — Contrix Black-box Test Harness TODO

> 整理日期：2026-05-07
> 协议参考：`contrix-spec/spec/v1/zh/conformance/` + `contrix-spec/spec/v1/artifacts/`。
> 项目栈：Rust（cargo test 入口） + PowerShell harness scripts + 可选 Docker compose；定位类似 Matrix Complement。

## 标记说明

- 🅿 parallel-safe：单 scenario / 单 vector / 单 fixture
- 🔒 sequential：动 harness.rs / process orchestrator / 默认 SUT manifest
- ⚠ high-risk：跨多服务真实联调 / federation 两边节点 / quarantine policy

## 当前状态摘要

- **代码量**：`src/conformance/*.rs`（11 子模块，新增 `schema_validation`）+ `src/harness.rs`（1176）+ 18 个场景文件，总 ~6K 行 Rust。
- **运行模式**：`process` 直接 `cargo run` SUT；`compose` 通过 `run-compose.ps1` 统一 bridge contract matrix 和可选 side-service；`docker` 与 Complement 同形态。
- **SUT 默认**：`soland`；harness 通过 `COTEST_SUT_MANIFEST` 切换。
- **多服务支持**：已支持 `COAUTH_BASE_URL` / `FLORIA_BASE_URL` 切到 live external，bridge contract matrix 已是可执行 scaffold（live `soland` rows + placeholder `coauth/floria` rows）。
- **artifacts**：每次跑写 `summary.{md,html,json}` + `transcript.ndjson` + `junit.xml` + coverage/gap reports + secret scan + spec sync gate；`artifacts/latest/` 维护最新一组。
- **release gate**：`--Profile release-gate` 已落地，输出 `release-gate.{json,md}`；当前稳定 gate 为 12 个测试，新增覆盖 recovery restore surface 与 optional StarID resolver discovery，live directory anti-enumeration 场景仍归后续 hang/flake 治理。
- **conformance fixtures**：14 个 fixture 测试全部通过（registry, schema_validation, encoding, redaction, capability, envelope, sync, federation, privacy, state_resolution）；新加 `schema_validation` 覆盖全部 34 个 schema 的 $id / const / required / enum / typed-id 校验向量。
- **缺失**：bridge matrix 仍允许 coauth/floria placeholder rows；docker compose 和真实 side-service 默认命令仍是后续项。
- **协议计数注意**：`contrix-spec` 当前 artifact lint 报告 110 event kinds；所有覆盖率任务以 `spec/v1/artifacts/registry/*` 实际输出为准，不再手写固定数量。

---

## P0 · Foundation（先于扩面）

| # | 任务 | 涉及文件 | 阻塞下游 |
|---|---|---|---|
| F1 🔒 | `[x]` **Compose harness 默认化**：已新增 `compose` CI profile、`tests/bridge_contracts.rs` 执行入口和 `scripts/run-compose.ps1` process-mode 编排；`soland` 由 cotest 生命周期启动，`coauth/floria/sodmin/yougen` 可通过 base URL 或 managed command 接入；docker 模式后续跟进。 | `src/harness.rs`、`scripts/run-cotest.ps1`、`scripts/run-compose.ps1`、`tests/bridge_contracts.rs` | P1 联调全部 |
| F2 ✅ | **Conformance.rs 拆分**：`src/conformance.rs`（4209 行）按 spec plane 拆 `conformance/{events,sync,authz,crypto,federation,recovery,push,identity,encoding,profiles}.rs`。 | `src/conformance/*.rs` | Stream A/B 全部 |
| F3 ✅ | **Spec artifact 同步 gate**：CI 跑 `python ../contrix-spec/tools/artifact_pipeline.py check` + 把 `artifacts/registry/{contract-catalog,event-kind-registry,schema-registry,operation-registry,error-code-registry,profiles/conformance-profiles}.json` 作为只读输入，每次 run 校验 SUT `/server/describe` / `/integration/describe` 与之对齐。 | `scripts/run-cotest.ps1` | 协议漂移阻断 |
| F4 ✅ | **artifacts 输出整理**：当前 `artifacts/latest/` 已统一；扩展 `coverage/gap.md`，列出"已注册 event kind / schema / operation / error code 中尚未被任何 vector 覆盖"的 diff。 | `scripts/run-cotest.ps1` | release readiness |
| F5 ✅ | **secret scan & redaction**：`transcript.ndjson` 必须脱敏（DID / token / PII）；CI 跑 `gitleaks` 类工具。 | `scripts/run-cotest.ps1` | 安全 |

---

## P1 · 并行扩面（F1/F2 后六路）

### Stream A · Protocol Payload / Event-kind / Schema 覆盖

| # | 任务 | 文件 |
|---|---|---|
| A1 🅿 | 把 `event-kind-registry.json` 当前 active event kind（2026-05-07 lint: 110）的 negative + positive vector 全覆盖。 | `scenarios/protocol_payloads.rs` |
| A2 ✅ | **完成（2026-05-07）**：`src/conformance/schema_validation.rs` 拉取 34 个 schema，每个 schema 跑 $id 一致性 + const ↔ schema_id 一致性 + JSON Schema 2020-12 编译 + 非对象 payload 拒绝（124 vec）+ 空对象拒绝（31 vec）+ 枚举非法值拒绝（46 vec）+ typed-id pattern 非法值拒绝（192 vec）；canonical-JSON 由现有 `run_encoding_fixture_suite` 覆盖。 | `src/conformance/schema_validation.rs`、`tests/conformance_fixtures.rs` |
| A3 🅿 | `operation-registry.json` 现有 83 个 operation 的 happy-path + 2 个 negative path（auth / payload）。 | 同上 |
| A4 🅿 | `error-code-registry.json` 现有 42 个 error code 的产生路径回归（每个至少 1 个能稳定触发的 vector）。 | 同上 |
| A5 🅿 | `cx.key.verification.*` + `cx.schema.device_message.v1` + `cx.schema.key_backup.v1` 与 2026-05-04 spec delta 对齐的 negative vectors（已部分落地，需扩展到所有 sub-kind）。 | 同上 |
| A6 ✅ | **剔除清理完成（2026-05-07）**：grep `cx\.(subject|room|card)\.` 在所有 `*.rs` 中零命中；`cx:card:legacy-card` 仅作为 federation/push 黑盒负向输入存在（验证 SUT 拒绝未注册 typed-id 命名空间）。`cx.flow.*` / `cx.flow.branch.*` / `cx.message.*` 主链路向量扩面仍待补（与 A1 同源 SUT 进度）。 | 同上 |

### Stream B · State Resolution / Reducer / Auth State

| # | 任务 | 文件 |
|---|---|---|
| B1 🅿 | quarantine-on-fork 算法的 fork / merge / lose / replay 五条向量（spec event-auth-state-resolution.md §state resolution）。 | `scenarios/space_permissions.rs` |
| B2 🅿 | redaction reducer：`actor_seq` 保留 / `payload` 清除 / 不串改 envelope hash 的全套（spec B-09）。 | `scenarios/protocol_payloads.rs` |
| B3 🅿 | history_visibility 三档（`world_readable` / `shared` / `invited` / `restricted`）与 join_rule × discoverability 矩阵（spec B-03）。 | `scenarios/space_permissions.rs` |
| B4 🅿 | composite state-key encoding（spec B-18）：percent-encode `|` 与 `%` 的 round-trip + 碰撞 negative vectors。 | `scenarios/protocol_payloads.rs` |
| B5 🅿 | membership transition 合法 / 非法状态机覆盖（join → leave → ban → unban → knock）。 | `scenarios/space_permissions.rs` |

### Stream C · Authz / Capability / Policy

| # | 任务 | 文件 |
|---|---|---|
| C1 🅿 | v1.0 constraint 8 family + subtype 全覆盖（`grant-constraint.schema.json`）：每个 family 至少 1 positive + 1 negative；历史 14 constraint 名称只作为 subtype/迁移用例。 | `scenarios/authz_policy_presence.rs` |
| C2 🅿 | condition.kind 全覆盖（以当前 spec/authz/capabilities.md 和 schema 输出为准）。 | 同上 |
| C3 🅿 | invite ↔ grant ↔ policy 三者联动（accept invite 自动产生 grant；revoke invite 撤销 grant）。 | 同上 |
| C4 🅿 | `evaluation_class` 缓存桶（stateless / grant_local / space_state / external）行为差异向量。 | 同上 |
| C5 🅿 | deny / quarantine / require_review / allow 的优先级断言（"any-hit-wins"）。 | 同上 |
| C6 🅿 | obligation 实际执行回归（不只 echo）。 | 同上 |

### Stream D · Crypto / E2EE / Devices

| # | 任务 | 文件 |
|---|---|---|
| D1 ⚠ | MLS proposal / commit / welcome / keypackage / epoch round-trip 的多设备真实场景（依赖 SUT 真实 MLS 实现）。 | `scenarios/delivery_media.rs` |
| D2 🅿 | KeyPackage shape 统一（spec B-10）：`principal_id / device_id / keypackage_id / device_signature / expires_at`。 | 同上 |
| D3 🅿 | KeyBackup envelope（spec B-11）：`backup_class / key_commitment / HKDF info` 的 negative vectors（错算 commitment / 错域 / 缺失字段）。 | 同上 |
| D4 🅿 | encrypted envelope AAD 漂移：`event_kind` vs `event_type` 的歧义拒绝（spec M-01 / SDK T1-20）。 | `scenarios/protocol_payloads.rs` |
| D5 🅿 | RYW receipt event kind 注册 + audit profile（attested / disclosed）的 marketing-term 拒绝向量。 | `scenarios/authz_policy_presence.rs` |

### Stream E · Federation / MIMI

| # | 任务 | 文件 |
|---|---|---|
| E1 🔒 | **真实双节点 federation**：harness 启动 2 个 soland 实例 + 它们的 service DID 互信；事件交换 / frontier exchange / replay / quarantine 全流程。 | `src/harness.rs`、`scenarios/federation_*.rs` |
| E2 🅿 | RFC 9421 transcript fields（spec B-06）：合法 / 缺失 / 重放向量。 | 同上 |
| E3 🅿 | Content-Digest（RFC 9530）：合法 / 错算 / 缺失向量。 | 同上 |
| E4 🅿 | CommitFork detection：相同 `actor_seq` 不同 `event_id` 触发 quarantine record。 | 同上 |
| E5 🅿 | MIMI room_update / notify / room_message / consent / key_material / identifiers_query 的 happy + negative 向量（spec extensions/mimi-interop.md）。 | `scenarios/api_contracts_auth.rs` |
| E6 🅿 | revocation fan-out TTL + 重试策略（spec M-18）。 | 同上 |

### Stream F · Recovery / Push / Identity 联动

| # | 任务 | 文件 |
|---|---|---|
| F-1 🅿 | `[~]` recovery bridge 全链路：`coauth principal-snapshot` → `principal-cache fetch/refresh/invalidate` → `restore ticket` 全状态机；当前 release gate 覆盖 soland key-backup / restore-ticket / recovery discovery surface，真实 coauth→soland refresh 仍是后续。 | `scenarios/bridge_contracts.rs`、`scenarios/protocol_payloads.rs` |
| F-2 🅿 | `[~]` restore approval / executor / artifact 全套（result / receipt / bundle / activity / timeline / audit-feed / materialized-device-handoff）已由 `repo_keys_device_blob_push_and_moderation_surfaces_work` 覆盖 scaffold happy path；失败路径和 durable worker 仍待补。 | 同上 |
| F-3 🅿 | push privacy 黑盒矩阵（spec B-14）：DID 进 token / payload / TURN credential 全部 fail closed。 | `scenarios/delivery_media.rs` |
| F-4 🅿 | push gateway drift detection：floria contract digest 漂移时 soland 应保留旧 snapshot；本场景模拟 floria 升级。 | 同上 |
| F-5 🅿 | identity progressive disclosure verifier authority chain（spec identity-handles.md §16）。 | `scenarios/identity_directory_index.rs` |
| F-6 🅿 | `[~]` DID resolver policy（method allow-list / trust roots / TTL / fail-mode）：已新增 `starid_optional_resolver_profile_is_discoverable`，覆盖 soland optional `did:webvh` discovery；trust roots / live StarID vectors 仍待补。 | `scenarios/bridge_contracts.rs`、`scenarios/identity_directory_index.rs` |

---

## P2 · Profile / Conformance / Release Gate

| # | 任务 | 文件 |
|---|---|---|
| S1 🔒 | **profile_tiers 校验**：把 `artifacts/profiles/conformance-profiles.json` 的 `v1_core_implementation` / `v1_1_extension_implementation` 划分作为 `--profile=core` / `--profile=ext` CLI 选项；core 默认 fail-closed，extension 走 opt-in。 | `src/harness.rs`、`scripts/*` |
| S2 🅿 | `[x]` release gate：`profile conformance` + `privacy boundary` + `anti-enumeration` + `recovery restore surface` + `push wakeup` + `device/session revoke` + `federation replay` + `session-grant bridge` + `optional StarID resolver discovery` 已作为 `release-gate.json` / `release-gate.md` 自动判定。live directory anti-enumeration 扩展保留到 hang/flake 治理后再加入默认 gate。 | `scripts/run-cotest.ps1`、`config/ci-profiles.json`、`artifacts/*/release-gate.*` |
| S3 🅿 | `summary.html` 加 profile coverage matrix + delta vs last run + flake list。 | `src/harness.rs` |
| S4 🅿 | flake guard：每个 vector 标注期望 deterministic / nondeterministic；nondeterministic 的失败重试 N 次再判定。 | 同上 |

---

## P3 · 工程质量 / 可观测性

| # | 任务 | 文件 |
|---|---|---|
| Q1 🅿 | scenarios 模块化：每个文件 < 1000 行；按 spec plane 重新对齐目录。 | `src/scenarios/*` |
| Q2 🅿 | 共享 fixture 抽到 `tests/common/` 或 `src/fixtures/`，避免 18 个场景各自造数据。 | `src/scenarios/*` |
| Q3 🅿 | tracing：harness 内部子进程 stdout/stderr 走结构化 transcript，按 service 分桶。 | `src/harness.rs` |
| Q4 🅿 | docker 模式：`build-soland-image.ps1` 改 multi-stage，镜像 < 100MB。 | `docker/*`、`scripts/*` |
| Q5 🅿 | `[x]` `scripts/run-cotest.ps1` 已支持 `--Profile fast-smoke` / `compose` / `release-gate` / `full-nightly`。 | `scripts/run-cotest.ps1`、`config/ci-profiles.json` |

---

## 并行调度建议

| Sprint | 可并行 |
|---|---|
| Sprint 1（foundation） | F1（compose harness）→ F2（conformance.rs 拆分）；F3 / F4 / F5 并行 |
| Sprint 2（扩面） | A · B · C · D · E · F 六路；其中 E1 双节点 federation 是 ⚠，C stream 先按 8 family + subtype 重写测试矩阵 |
| Sprint 3（gate） | S1 / S2 / S3 / S4 + Q1..Q5 |

**冲突点**：
- F1（compose harness）→ E1（双节点 federation）/ F-1..F-2（recovery 多服务）/ F-3..F-4（push 多服务）必须等 F1
- F2（拆分）→ A/B/C/D/E/F 并行
- A1..A6 与 SUT（soland）真实实现进度强耦合：SUT reducer 21% 时不可能跑通 80% vectors

## 不在本轮范围

- 多 region / 多数据中心 federation 真实压测（非 conformance 范畴）
- 不同 SUT（非 soland）适配（理论上 cotest 是 SUT-agnostic，但暂只跑 soland）
- WebRTC 端到端通话媒体真实抓包测试（属于 webrtc-signaling extension profile）
