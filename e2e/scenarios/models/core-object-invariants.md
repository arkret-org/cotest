# 核心对象不变量 (common fields / patch precondition / cascade / relation cardinality / view fallback)

## 目标

验证 Arkret 协作图 **所有 canonical object** 在线必须维持的五条核心不变量：

1. **公共字段完整性** — 任何 durable Event 与 Materialized Object 在 wire 上 MUST 携带 `common-fields.md` §3 列出的公共字段（`id` / typed prefix、`created_at`、actor 主体引用、`lifecycle_state` 等价物），不允许在 happy-path serializer 上"省略"以节省字节。
2. **位置前像 CAS** — `ak.strand.move` 是普通数据 Event；可选 `expected_position` 必须完整匹配当前 `{list_space_id, rank}`，不匹配时 MUST `failed_precondition` 且零写入，不推进 stream head。不得附加 `head_eq`、`seal_basis` 或 producer-authored effects。
3. **Cascade / archive / delete** — Realm/Space lifecycle event 在 archive / tombstone / destroy 时 MUST 按 `realm-and-space.md` §2.5.1 / §3.4 的级联规则处理 child resource：`ak.space.archive` 不自动级联子 Space，`ak.space.tombstone` 在 live 子结构存在时 MUST `failed_precondition`，`ak.realm.destroy` 后 child Space 进入 `realm_destroyed_orphan` locked projection。
4. **Relation 基数** — 在已注册了 `max_to_per_from=1` 等基数约束的 `relation_kind`（典型：`has_default_view`、单负责人 `assigned_to`）上写入第二条同源 active edge 时，reducer MUST 关闭旧 edge 或返回 `failed_precondition`；同 `(realm_id, relation_kind, from_ref, to_ref)` 重复写入 MUST 幂等去重。
5. **View projection fallback** — 请求一个 Space / Board 未显式声明的 View 时，server MUST 按 `views.md` §6 的派生规则返回**默认 view projection**（`kind="collection" + renderer="board"` 等响应族默认），而不是 404 — 让一个全新的 Space 在没有 user-defined View 时也能渲染。

不验证：encoding canonical JSON / digest（见 `conformance/encoding-vectors`）、registry drift（见 `conformance/registry-drift`）、realm link 图与 inherited policy（见 `models/realm-links`）、actor-private read marker propagation（见 `models/private-read-cursor`）、消息/聊天交互流（见 `messaging/*`）。

## Spec 锚点

- `arkret-spec/spec/v1/zh/models/common-fields.md` §3 — Common Object Fields 表（`id` / `created_at` / `created_by` / `state` / `state_changed_at` / `schema`）
- `arkret-spec/spec/v1/zh/models/common-fields.md` §5、§5.1 — Lifecycle state 枚举与 canonical state-transition 表（`<kind>_not_active` / `<kind>_already_terminal` / 同 state self-transition 禁止）
- `arkret-spec/spec/v1/zh/models/event-and-patch.md` §2.2 — Event Envelope 必填字段（`event_id` / `kind` / `actor_id` / `actor_seq` / `created_at` / `prev_refs` / `refs` / `payload` / `proofs`）
- `arkret-spec/spec/v1/zh/models/event-and-patch.md` §2.6 — `actor_seq` fork 约束（同 `(actor_id, actor_seq)` sibling fork 上限）
- `arkret-spec/spec/v1/zh/models/event-and-patch.md` §4.2.3 / §4.2.4 / §4.2.5 — Patch selector 语义、redactable 字段保护、reducer-managed 字段保护、`preconditions[].head_eq` CAS 不匹配时 `failed_precondition`
- `arkret-spec/spec/v1/zh/models/realm-and-space.md` §2.5 / §2.5.1 — Realm tombstone vs destroy；destroy 后 `realm_terminal_state` / child cascade / erasure receipt
- `arkret-spec/spec/v1/zh/models/realm-and-space.md` §3.4 — Space lifecycle：`ak.space.archive` 不级联子 Space、`ak.space.tombstone` 存在 live dependents 时 `space_has_live_dependents`
- `arkret-spec/spec/v1/zh/models/relation.md` §3.1 / §3.2 — 标准 relation_kind 与默认基数表；未声明为 multi-edge 的 Relation MUST 按 `(realm_id, relation_kind, from_ref, to_ref)` 去重
- `arkret-spec/spec/v1/zh/models/relation.md` §4.4 — 跨 Realm 强约束（`contains` / `belongs_to` MUST NOT 跨 Realm）

## 拓扑

- 1 × soland (Station) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (private authentication process) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth；alice 与 bob 的 session credential 都来自这个 coauth

(都是 cotest 现有 harness 直接提供的，不需要改 `scripts/run-joint-e2e.ps1`。本 scenario 主要走 soland HTTP API，少量 inkson UI 用于 Phase A 的 Realm + Space 创建。)

## Actors

| 名字  | DID                                                | 在 models/core-object-invariants 中的角色                                                   | 注册时机   |
| ----- | -------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------- |
| alice | `did:webvh:z6mkfixture:alice-coinv-<uuid>.example` | Space 创建者；patch / archive / tombstone 的发起者；Relation 与 View 的写入端               | 测试开始前 |
| bob   | `did:webvh:z6mkfixture:bob-coinv-<uuid>.example`   | 第二个 actor；用于 Phase D 中验证 `assigned_to` / `has_default_view` 等需要第二主体的基数边 | 测试开始前 |

## Pre-conditions

- 两个 DID 都通过 `POST /_soland/self/account/register` 注册过（与现有 `ensureRegistered` 行为一致）
- 两个 actor 都持有有效 dev session token (`POST /_soland/gate/auth/dev-login`)
- alice 的 browser context 通过 `inkson.config.v1` localStorage 注入 server_url + account_did + device_id + session_credential
- Phase B–D 不需要 browser context，纯 soland HTTP API 直调即可

## Steps

### Phase A — Common fields integrity（live）

1. **alice** 先通过 `JointUserPage.createRealm({...})` 走 `/setup` 多步向导建 Realm `R`，再通过 New Space 表单在 `R` 内建 Space `S`
   - Realm title = `"models/core-object-invariants Realm ${stamp}"`
   - Space title = `"models/core-object-invariants Space ${stamp}"`
   - discoverability = `listed`，join_rule = `invite`，history_access = `since_join`
2. 断言：`realm-lifecycle-strand` 含 `created ak:realm:...`，记录 `realmId`；`new-space-created-id` 含 `ak:space:...`，记录 `spaceId`
3. **alice** 调 `GET /_soland/self/spaces/${spaceId}`，断言返回 JSON 至少包含以下 wire 字段（spec §3 公共字段在 soland 当前 serializer 上的等价表达）：
   - `space_id` — `id:space` typed prefix，对应 spec `id`
   - `owner` — Space 的 owner DID，对应 spec `created_by` / actor 主体引用
   - `members` — 数组，至少含 `owner`
   - `deleted` — boolean，对应 spec `lifecycle_state`（`false` ⇒ 等价 `active`）
4. **alice** 调 `GET /_arkret/self/events?realms=${realmId}&limit=20`，断言响应 `events[]` 至少有一条 `event_kind` 形如 `ak.space.*` 且 `payload.space_id == spaceId`（典型 `ak.space.create` / `ak.space.archive`），且每条 event 都携带：
   - `event_id` — 对应 spec Event Envelope `event_id`
   - `created_at` — RFC 3339 timestamp，对应 spec `created_at`
   - `sender` — DID，对应 spec `actor_id`
   - `event_kind` — kind 字符串，标识 lifecycle 转换的来源
5. 这一步是 spec §3 "所有 durable canonical object SHOULD 使用以下公共字段" 的最低 wire-level guard——若 soland serializer 把任何一项静默 drop，本步立刻 fail。

### Phase B — 普通位置 Event 的显式 CAS（live）

按 `realm-and-space.md` §3.6，position family 是 `strand_position:<board_space_id>:<strand_id>`，
执行类别为 data，前像保护使用 payload 的可选完整 `expected_position`。

6. **alice** 真实创建 Strand `F`、Board `B`、三个以 `B` 为 parent 的 List：源 `L1`、错误前像 `L_stale` 和目标 `L2`。所有 ID 从各自 accepted create Event 派生，不使用未创建的随机对象。
7. 初次 `ak.strand.move` 省略 `from_space_id` 与 `expected_position`，把位置从 null 写为 `{list_space_id:L1,rank:"m"}`，验证 stream head 推进。Event 不携带 `preconditions` 或 `seal_basis`。
8. 提交 `expected_position={list_space_id:L_stale,rank:"m"}` 的 move 到 `L2`：断言 HTTP409、`failed_precondition`，原 Realm stream head 不变。
9. 使用完整正确前像 `{list_space_id:L1,rank:"m"}` 提交 move 到 `L2`、rank `z`，验证提交成功和 head 推进。再次以旧前像尝试返回 `L1`，断言失败且 head 不变；以新前像 `{list_space_id:L2,rank:"z"}` 返回 `L1` 则成功。独立认证 stream scan 必须恰有这三条 accepted move，且没有两条 rejected Event，证明拒绝零写入与成功位置耐久更新。

### Phase C — 独立 Space lifecycle 与活依赖删除屏障（live）

10. **alice** 真实创建 parent Board 和以它为 parent 的 child List，ID 从 accepted create Event 派生；使用当前 Space schema 的顶层 title，不提交旧 metadata 镜像。
11. 归档 parent 后，通过认证 `GET /_arkret/self/realms/{realm_id}/spaces?include_terminal=true` 验证 parent archived、child active。parent tombstone 必须 HTTP409 `failed_precondition`，`reason_code=space_has_live_dependents`，stream head 不变。
12. 单独归档 child，验证两个对象均 archived；parent tombstone 仍拒绝且零写入。恢复 parent 后验证 parent active、child 仍 archived，再次确认归档的 child 仍阻止 parent tombstone。
13. 显式 tombstone child，确认 parent 仍 active、child tombstoned；之后 parent tombstone 成功，两个对象均 tombstoned。历史 child parent 引用不能把已终结 child 当成活依赖。
14. 对已 tombstoned parent 的普通 `ak.space.update` 必须 HTTP409 `failed_precondition / space_not_active`；restore 和新 tombstone 必须 HTTP409 `failed_precondition / space_already_terminal`。三次拒绝均不推进 head、不改变对象状态。独立认证 stream scan 必须包含全部 accepted Space Event（含两个 tombstone），没有任何 rejected Event；不把 Space 终态误当成 Realm 或无关 Strand 终态。

### Phase D — Relation cardinality（live）

15. **alice** 创建两个 View `V1` / `V2`（`POST /_arkret/self/realms/${realmId}/views`），都以 `spaceId` 作为 source Space。
16. **alice** 提交第一条 `ak.relation.create` `relation_kind="has_default_view"`，`from_ref=spaceId`，`to_ref=V1.id`：断言 HTTP 201，关系 active。
17. **alice** 提交第二条 `ak.relation.create` `relation_kind="has_default_view"`，`from_ref=spaceId`，`to_ref=V2.id`：spec §3.2 表 — `has_default_view` 基数为 `many_to_one`，"设置新默认 View MUST 关闭旧 active edge"。断言以下二者之一：
    - 服务端接受，但 `V1.id` 那条 edge 自动翻成 `tombstone`（reducer 决定性关闭旧 winner）；或
    - 服务端拒绝并返回 `failed_precondition` + `reason = "relation_cardinality_violation"`（早期 reducer 选择 fail-closed）。
    - 测试断言"二选一"，但 MUST NOT 同时存在两条 active edge（这是基数违反，会让 board projection 出现非确定 default view）。
18. **alice** 重复提交完全相同的 edge（同 `from_ref` / `to_ref` / `relation_kind`）：断言幂等——服务端要么 200 + 同一个 `relation_id`，要么 409，**MUST NOT** 创建第二条 active 副本（spec §3.2 末段 "未声明为 multi-edge 的 Relation MUST 由 reducer 按 `(realm_id, relation_kind, from_ref, to_ref)` 去重"）。
19. **alice** 提交一条跨 Realm 的 `ak.relation.create` `relation_kind="contains"`，`from_ref` 在 `spaceId` 而 `to_ref` 指向另一个 Realm 的 Strand：断言 HTTP 4xx + `error_code = "failed_precondition"` + `reason = "cross_space_structural_relation"`（spec §4.4）。

## Observable assertions（合并清单）

- Phase A 步骤 3：`/_soland/self/spaces/${spaceId}` 返回 `space_id` / `owner` / `members` / `deleted` 四字段齐全
- Phase A 步骤 4：`/_arkret/self/events?realms=${realmId}` 返回的 Space event item 含 `event_id` / `created_at` / `sender` / `event_kind` 四字段，且 `payload.space_id == spaceId`
- Phase B 步骤 8-9：陈旧完整 position CAS 返回 HTTP409 `failed_precondition`、stream head 不变；正确前像成功，独立 scan 仅有三条 accepted move，无 rejected Event。
- Phase C 步骤 11-14：parent archive/restore 不级联，active/archived child 都阻止删除；显式终结 child 后 parent 可删除。精确拒绝码、零 head 推进、最终两对象终态及完整 accepted 历史必须一致，不接受 generic conflict 或状态镜像推断。
- Phase D 步骤 17：`has_default_view` 第二条 edge 不与第一条同时 active
- Phase D 步骤 18：完全重复的 Relation create 幂等
- Phase D 步骤 19：跨 Realm `contains` 被 reducer 拒绝

## Edge cases / sub-tests

- **E_inv.1 reducer-managed 字段保护**：客户端尝试通过 `ak.patch.v1` 直接 `set` 一个 reducer-managed 字段（`id` / `schema` / `realm_id` / `created_by` / `created_at` / `state` / `state_changed_at`）—— reducer MUST 返回 `schema_violation` reason=`patch_path_reducer_managed`（spec §4.2.5）。
- **E_inv.2 actor-supplied state_changed_at 被忽略**：客户端在 `ak.space.archive` 的 wire payload 中塞一个伪造的 `state_changed_at`（早于 Event 的 `created_at`），断言 reducer 写入的物化对象上的 `state_changed_at` 等于已验证 Event 的 `created_at`，而**不是**客户端给的值（spec §5 normative 段）。
- **E_inv.3 same-state self-transition 拒绝**：对 `state == "archived"` 的 Space 再发一次 `ak.space.archive`，MUST 返回 `space_not_active`（spec §5.1 "不允许 same-state self-transition"，不能当作 idempotent no-op）。
- **E_inv.4 redactable 字段 `unset` 防御**：客户端通过 `ak.patch.v1` 把 `Message.content` 字段 `$op="unset"`——reducer MUST 返回 `schema_violation` reason=`patch_unset_redactable_field`（spec §4.2.4 redaction escape 防御）。

后四条建议拆成独立的小 spec（`models/core-object-invariants.2` 等），保持主 scenario 紧凑。

## Implementation notes

- **soland 当前覆盖**：Phase A 的 `GET /_soland/self/spaces/{space_id}` 走 `SpaceLifecycleResponse`（`wire.rs`），实际 wire 字段是 `ok` / `space_id` / `owner` / `members` / `deleted`，**不**包含 `created_at` 与显式 `lifecycle_state`——这些字段从 events query (`/_arkret/self/events?realms=...`) 中匹配 `payload.space_id == spaceId` 的 event item 上读 `created_at` / `sender` / `event_kind` 三项，再加 `event_id`，凑齐 spec §3 公共字段语义的最低 4 项。后续若 soland 在 `SpaceLifecycleResponse` 中补 `created_at` / `state` 字段，Phase A 的 assertion 应直接迁移到 spaces endpoint，不再依赖 events query 兜底。
- **soland/harness gap**：Phase B 的首次 `ak.strand.move` 可以被接收，但 joint
  harness 尚不能产出一个真正覆盖该 accepted Control Move 的后续 Seal。
  conformance `realm-basis` 只建立独立 fixture basis，不会把待处理 Move 纳入
  `control_event_set_root`。因此测试保留完整可执行断言并等待 sealing path，
  不能把读取到的旧 Seal 或无关 fixture Seal 当作 accepted state。
- **Phase C**：使用真实 parent/child 与已登记 Space 列表及认证 stream scan。活依赖规则拒绝、独立归档/恢复、显式终结和终态写入屏障均为精确断言；静态 live 标记不是运行通过证据。
- **已落地**：Phase D 覆盖 `ak.relation.create` reducer、`has_default_view` many-to-one、duplicate idempotency 与 cross-Realm structural relation reject。
- **不需要新 helper**：Phase A 复用 `JointUserPage.createRealm()` 和现有 New Space 表单 helper、`ensureRegistered`、`issueUserSession`、`openUserPage`。Phase B–D 只用 Playwright `request` fixture 直打 soland，并为真实 Standard grant 生成逐请求 DPoP，不需要 browser context。
- **测试侧 wire-shape 容忍度**：spec 用中文写公共字段语义（"创建主体" / "最近一次 state 转换时间"），但 soland wire 上的字段名是 snake_case（`owner` / `deleted` / `created_at` / `sender`）。本 scenario 的断言**绑定到 wire field 名**，spec 锚点用 §号 引用语义。如果 soland 将来改名（如把 `deleted` 改成 `state`），断言要相应更新，但本 scenario 仍是 spec §3 公共字段的 e2e guard。

## 总耗时预估

当前 live Phase A + D：约 15-25s（1 个 browser context + HTTP 调用）。
全 phase live 后预计 30-45s（Phase B–D 都是 HTTP 直调，无 browser context）。
