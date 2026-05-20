# 核心对象不变量 (common fields / patch precondition / cascade / relation cardinality / view fallback)

## 目标

验证 Contrix 协作图 **所有 canonical object** 在线必须维持的五条核心不变量：

1. **公共字段完整性** — 任何 durable Event 与 Materialized Object 在 wire 上 MUST 携带 `common-fields.md` §3 列出的公共字段（`id` / typed prefix、`created_at`、actor 主体引用、`lifecycle_state` 等价物），不允许在 happy-path serializer 上"省略"以节省字节。
2. **Patch precondition (CAS)** — 任何携带 `preconditions[].head_eq` 的 Move/patch 在 pre-state 与 actor 声明值不一致时 MUST `failed_precondition`，并且 **不得** 对目标 cell 执行 `effects[]`（不能"先写后报错"）。
3. **Cascade / archive / delete** — Realm/Space lifecycle event 在 archive / tombstone / destroy 时 MUST 按 `realm-and-space.md` §2.5.1 / §3.4 的级联规则处理 child resource：`cx.space.archive` 不自动级联子 Space，`cx.space.tombstone` 在 live 子结构存在时 MUST `failed_precondition`，`cx.realm.destroy` 后 child Space 进入 `realm_destroyed_orphan` locked projection。
4. **Relation 基数** — 在已注册了 `max_to_per_from=1` 等基数约束的 `relation_kind`（典型：`has_default_view`、单负责人 `assigned_to`）上写入第二条同源 active edge 时，reducer MUST 关闭旧 edge 或返回 `failed_precondition`；同 `(realm_id, relation_kind, from_ref, to_ref)` 重复写入 MUST 幂等去重。
5. **View projection fallback** — 请求一个 Space / Board 未显式声明的 View 时，server MUST 按 `views.md` §6 的派生规则返回**默认 view projection**（`kind="collection" + renderer="board"` 等响应族默认），而不是 404 — 让一个全新的 Space 在没有 user-defined View 时也能渲染。

不验证：encoding canonical JSON / digest（见 `conformance/encoding-vectors`）、registry drift（见 `conformance/registry-drift`）、realm link 图与 inherited policy（见 `models/realm-links`）、actor-private read marker propagation（见 `models/private-read-marker`）、morph schema migration（见 `models/morph-schema-migration`，G1.T7 owner）、消息/聊天交互流（见 `messaging/*`）。

## Spec 锚点

- `contrix-spec/spec/v1/zh/models/common-fields.md` §3 — Common Object Fields 表（`id` / `created_at` / `created_by` / `state` / `state_changed_at` / `schema`）
- `contrix-spec/spec/v1/zh/models/common-fields.md` §5、§5.1 — Lifecycle state 枚举与 canonical state-transition 表（`<kind>_not_active` / `<kind>_already_terminal` / 同 state self-transition 禁止）
- `contrix-spec/spec/v1/zh/models/event-and-patch.md` §2.2 — Event Envelope 必填字段（`event_id` / `kind` / `actor_id` / `actor_seq` / `created_at` / `prev_refs` / `refs` / `payload` / `proofs`）
- `contrix-spec/spec/v1/zh/models/event-and-patch.md` §2.6 — `actor_seq` fork 约束（同 `(actor_id, actor_seq)` sibling fork 上限）
- `contrix-spec/spec/v1/zh/models/event-and-patch.md` §4.2.3 / §4.2.4 / §4.2.5 — Patch selector 语义、redactable 字段保护、reducer-managed 字段保护、`preconditions[].head_eq` CAS 不匹配时 `failed_precondition`
- `contrix-spec/spec/v1/zh/models/realm-and-space.md` §2.5 / §2.5.1 — Realm tombstone vs destroy；destroy 后 `realm_terminal_state` / child cascade / erasure receipt
- `contrix-spec/spec/v1/zh/models/realm-and-space.md` §3.4 — Space lifecycle：`cx.space.archive` 不级联子 Space、`cx.space.tombstone` 存在 live dependents 时 `space_has_live_dependents`
- `contrix-spec/spec/v1/zh/models/relation.md` §3.1 / §3.2 — 标准 relation_kind 与默认基数表；未声明为 multi-edge 的 Relation MUST 按 `(realm_id, relation_kind, from_ref, to_ref)` 去重
- `contrix-spec/spec/v1/zh/models/relation.md` §4.4 — 跨 Realm 强约束（`contains` / `belongs_to` MUST NOT 跨 Realm）
- `contrix-spec/spec/v1/zh/models/views.md` §2.2 / §6 — View.kind 是响应族；Board projection 按 query → contains → flow 派生，不依赖预先注册 View
- `contrix-spec/spec/v1/zh/models/views.md` §6.3 — `CollectionProjectionResponse` 形状（`view_id` 缺失时仍能返回派生 projection）

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 共享同一个 coauth；alice 与 bob 的 access token 都来自这个 coauth

(都是 cotest 现有 harness 直接提供的，不需要改 `scripts/run-joint-e2e.ps1`。本 scenario 主要走 soland HTTP API，少量 yougen UI 用于 Phase A 的 Space 创建复用现有 `JointUserPage.createSpace()`。)

## Actors

| 名字 | DID | 在 models/core-object-invariants 中的角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-coinv-<uuid>.example` | Space 创建者；patch / archive / tombstone 的发起者；Relation 与 View 的写入端 | 测试开始前 |
| bob | `did:web:bob-coinv-<uuid>.example` | 第二个 actor；用于 Phase D 中验证 `assigned_to` / `has_default_view` 等需要第二主体的基数边 | 测试开始前 |

## Pre-conditions

- 两个 DID 都通过 `POST /api/v1/account/register` 注册过（与现有 `ensureRegistered` 行为一致）
- 两个 actor 都持有有效 dev session token (`POST /api/v1/auth/dev-login`)
- alice 的 browser context 通过 `yougen.config.v1` localStorage 注入 server_url + account_did + device_id + session_token
- Phase B–E 不需要 browser context，纯 soland HTTP API 直调即可

## Steps

### Phase A — Common fields integrity（live）

1. **alice** 通过 `JointUserPage.createSpace({...})` 走 `/setup` 多步向导建空间 `S`
   - title = `"models/core-object-invariants Space ${stamp}"`
   - discoverability = `listed`，join_rule = `invite`，history_visibility = `joined`
2. 断言：`space-lifecycle-flow` 含 `created cx:space:...`，记录 `spaceId`
3. **alice** 调 `GET /api/v1/spaces/${spaceId}`，断言返回 JSON 至少包含以下 wire 字段（spec §3 公共字段在 soland 当前 serializer 上的等价表达）：
   - `space_id` — `id:space` typed prefix，对应 spec `id`
   - `owner` — Space 的 owner DID，对应 spec `created_by` / actor 主体引用
   - `members` — 数组，至少含 `owner`
   - `deleted` — boolean，对应 spec `lifecycle_state`（`false` ⇒ 等价 `active`）
4. **alice** 调 `GET /api/v1/events?spaces=${spaceId}&limit=20`，断言响应 `events[]` 至少有一条 `event_kind` 形如 `cx.space.*`（典型 `cx.space.create` / `cx.space.lifecycle`），且每条 event 都携带：
   - `event_id` — 对应 spec Event Envelope `event_id`
   - `created_at` — RFC 3339 timestamp，对应 spec `created_at`
   - `sender` — DID，对应 spec `actor_id`
   - `event_kind` — kind 字符串，标识 lifecycle 转换的来源
5. 这一步是 spec §3 "所有 durable canonical object SHOULD 使用以下公共字段" 的最低 wire-level guard——若 soland serializer 把任何一项静默 drop，本步立刻 fail。

### Phase B — Patch precondition CAS fail（fixme，需要 soland Move endpoint）

6. **alice** 在 `spaceId` 内创建一个 Flow `F`（`POST /api/v1/realms/${spaceId}/flows`，或 `POST /api/v1/events` 提交 `cx.flow.create`），记录 `flowId` 与初始 `fields.status = "open"`。
7. **alice** 发一个 `cx.flow.update` Move，`preconditions[].head_eq` 指向**陈旧**的 `prev_revision`（例如 `expected_revision: 0`，但服务端当前 revision 已经 ≥ 1，或者把 `fields.status` 的预期值故意写错为 `"closed"` 而当前态是 `"open"`）。
8. 断言：HTTP 4xx + `error_code = "failed_precondition"` + `reason` 来自 spec §5.1 reason-code 表或 `event-and-patch.md` §4.2.4 reducer 失败枚举。
9. 断言：再次 `GET /api/v1/realms/${spaceId}/flows/${flowId}`，`fields.status` 仍然是步骤 6 写入的初值；任何 cell（`cx.component.flow.fields.v1` 等）的 head 都没有被该失败 Move 触动——验证 spec §2.2 "preconditions 与 effects 同步原子"。

### Phase C — Cascade / archive / delete（fixme，需要 soland lifecycle reducer）

10. **alice** 在 `spaceId` 下再建一个 child Space `S_child`（如果当前 soland 不支持嵌套 Space 拓扑，则改成在 `spaceId` 内创建一个 Flow `F_child` 作为 "live dependent" 的代理）。
11. **alice** 提交 `cx.space.archive` 指向 `spaceId`，断言 HTTP 200。再调 `GET /api/v1/spaces/${spaceId}`：
    - 断言：`spaceId` 的 lifecycle 状态翻到 `archived`（wire 上当前是 `deleted=false` + 额外的 `state="archived"` 字段，或 soland 后续在 `SpaceLifecycleResponse` 中补充 `lifecycle_state`）
    - 断言：child `S_child` / `F_child` **没有**自动跟随翻成 `archived`（spec §3.4 — `cx.space.archive` 不自动 archive child）
12. **alice** 在 child 仍 live 的情况下提交 `cx.space.tombstone` 指向 `spaceId`：断言 HTTP 4xx + `error_code = "failed_precondition"` + `reason = "space_has_live_dependents"`（spec §3.4 错误码表）。
13. **alice** 先 tombstone 掉所有 child，再 `cx.space.tombstone` 指向 `spaceId`：断言 HTTP 200 + state 翻到 `tombstoned`。
14. 断言：tombstoned 之后再提交任何普通 write event（`cx.message.create` / `cx.flow.update`）MUST 返回 `realm_terminal_state` 或 `space_already_terminal`，且 audit log 中 tombstone event 自身仍然可读（hash chain stub 保留——spec §2.5.2）。

### Phase D — Relation cardinality（fixme，需要 soland relation reducer + cardinality check）

15. **alice** 创建两个 View `V1` / `V2`（`POST /api/v1/realms/${spaceId}/views`），都以 `spaceId` 作为 source space。
16. **alice** 提交第一条 `cx.relation.create` `relation_kind="has_default_view"`，`from_ref=spaceId`，`to_ref=V1.id`：断言 HTTP 201，关系 active。
17. **alice** 提交第二条 `cx.relation.create` `relation_kind="has_default_view"`，`from_ref=spaceId`，`to_ref=V2.id`：spec §3.2 表 — `has_default_view` 基数为 `many_to_one`，"设置新默认 View MUST 关闭旧 active edge"。断言以下二者之一：
    - 服务端接受，但 `V1.id` 那条 edge 自动翻成 `tombstone`（reducer 决定性关闭旧 winner）；或
    - 服务端拒绝并返回 `failed_precondition` + `reason = "relation_cardinality_violation"`（早期 reducer 选择 fail-closed）。
    - 测试断言"二选一"，但 MUST NOT 同时存在两条 active edge（这是基数违反，会让 board projection 出现非确定 default view）。
18. **alice** 重复提交完全相同的 edge（同 `from_ref` / `to_ref` / `relation_kind`）：断言幂等——服务端要么 200 + 同一个 `relation_id`，要么 409，**MUST NOT** 创建第二条 active 副本（spec §3.2 末段 "未声明为 multi-edge 的 Relation MUST 由 reducer 按 `(realm_id, relation_kind, from_ref, to_ref)` 去重"）。
19. **alice** 提交一条跨 Realm 的 `cx.relation.create` `relation_kind="contains"`，`from_ref` 在 `spaceId` 而 `to_ref` 指向另一个 Realm 的 Flow：断言 HTTP 4xx + `error_code = "failed_precondition"` + `reason = "cross_space_structural_relation"`（spec §4.4）。

### Phase E — View projection fallback（fixme，需要 soland board projection endpoint）

20. **alice** 在新建的 `spaceId` 上请求一个"用户从未注册过"的 view：`GET /api/v1/spaces/${spaceId}/views/projection?renderer=board`（或 `?kind=collection&renderer=board`）。这是一个全新 Space，没有调用过 `cx.view.create`，因此**不存在**任何 user-defined View 对象。
21. 断言：HTTP 200（**不是** 404），响应 body 形如 `views.md` §6.3 `CollectionProjectionResponse`：
    - `kind = "collection"`
    - `renderer = "board"`
    - `view_id` 为派生默认（典型实现：`cx:view:default:${spaceId}` 或服务端临时 id；测试侧只断言字段存在 + 是 `cx:view:` typed prefix，不 hardcode 具体 uuid）
    - `frontier` 至少有一项 `cx:event:...`（这个 Space 至少有 create event）
    - `groups[]` 是数组（可以为空，因为没有 List Space / Flow placement，但字段必须存在 — spec §2.2 View.kind 是响应族）
22. 再请求同一 endpoint 但用一个 spec 没注册的 renderer：`?renderer=bogus_renderer_${stamp}`：断言 HTTP 4xx + `error_code = "unknown_renderer"`（或类似），**MUST NOT** 静默回退到 `board`——fallback 只对"未注册 View"生效，不对"未注册 renderer"生效。这是 spec §2.2 "保留 5 个 View.kind 作为 response family" 与 §11 "未声明 renderer MUST fail-closed" 的边界。

## Observable assertions（合并清单）

- Phase A 步骤 3：`/api/v1/spaces/${spaceId}` 返回 `space_id` / `owner` / `members` / `deleted` 四字段齐全
- Phase A 步骤 4：`/api/v1/events?spaces=${spaceId}` 返回的 event item 含 `event_id` / `created_at` / `sender` / `event_kind` 四字段
- Phase B 步骤 8-9：陈旧 precondition Move 返回 `failed_precondition` 且 cell head 未变
- Phase C 步骤 11：archive 不级联子 Space
- Phase C 步骤 12：存在 live 子结构时 tombstone MUST `space_has_live_dependents`
- Phase C 步骤 14：tombstone 后普通 write 返回 `realm_terminal_state` / `space_already_terminal`
- Phase D 步骤 17：`has_default_view` 第二条 edge 不与第一条同时 active
- Phase D 步骤 18：完全重复的 Relation create 幂等
- Phase D 步骤 19：跨 Realm `contains` 被 reducer 拒绝
- Phase E 步骤 21：没有 user-defined View 时 board projection 仍返回 200 + canonical 响应族字段
- Phase E 步骤 22：未注册 renderer fail-closed

## Edge cases / sub-tests

- **E_inv.1 reducer-managed 字段保护**：客户端尝试通过 `cx.patch.v1` 直接 `set` 一个 reducer-managed 字段（`id` / `schema` / `realm_id` / `created_by` / `created_at` / `state` / `state_changed_at`）—— reducer MUST 返回 `schema_violation` reason=`patch_path_reducer_managed`（spec §4.2.5）。
- **E_inv.2 actor-supplied state_changed_at 被忽略**：客户端在 `cx.space.archive` 的 wire payload 中塞一个伪造的 `state_changed_at`（早于 Event 的 `created_at`），断言 reducer 写入的物化对象上的 `state_changed_at` 等于 Event 的 `created_at` / anchored_at，而**不是**客户端给的值（spec §5 normative 段）。
- **E_inv.3 same-state self-transition 拒绝**：对 `state == "archived"` 的 Space 再发一次 `cx.space.archive`，MUST 返回 `space_not_active`（spec §5.1 "不允许 same-state self-transition"，不能当作 idempotent no-op）。
- **E_inv.4 redactable 字段 `unset` 防御**：客户端通过 `cx.patch.v1` 把 `Message.content` 字段 `$op="unset"`——reducer MUST 返回 `schema_violation` reason=`patch_unset_redactable_field`（spec §4.2.4 redaction escape 防御）。

后四条建议拆成独立的小 spec（`models/core-object-invariants.2` 等），保持主 scenario 紧凑。

## Implementation notes

- **soland 当前覆盖**：Phase A 的 `GET /api/v1/spaces/{space_id}` 走 `SpaceLifecycleResponse`（`wire.rs`），实际 wire 字段是 `ok` / `space_id` / `owner` / `members` / `deleted`，**不**包含 `created_at` 与显式 `lifecycle_state`——这些字段从 events query (`/api/v1/events?spaces=...`) 中的 event item 上读 `created_at` / `sender` / `event_kind` 三项，再加 `event_id`，凑齐 spec §3 公共字段语义的最低 4 项。后续若 soland 在 `SpaceLifecycleResponse` 中补 `created_at` / `state` 字段，Phase A 的 assertion 应直接迁移到 spaces endpoint，不再依赖 events query 兜底。
- **soland gap**：Phase B 的 patch precondition 路径需要 soland 暴露通用 Move endpoint（带 `preconditions[].head_eq`）；当前只有零散的 cell 更新通道，未统一到 `cx.events` 提交路径。主流程标 `test.fixme`，并在 fixme body 中以 `request.post(...)` 形态 sketch 出预期调用。
- **soland gap**：Phase C cascade 规则在 soland 当前 lifecycle 实现里部分落地（archive / delete 路径存在），但 `space_has_live_dependents` 错误码与 child cascade locked projection 尚未在 wire 上稳定。整 phase 标 fixme，sketch API。
- **soland gap**：Phase D Relation cardinality 检查需要 soland 实现 `cx.relation.create` reducer 与 `has_default_view` 基数表；当前 `routing/spaces/relation.rs` 存在但 cardinality enforcement 弱。整 phase 标 fixme。
- **soland gap**：Phase E `/api/v1/spaces/{id}/views/projection` board fallback endpoint 当前未实现；这是 spec §6 "派生响应" 的 wire 出口，需要 soland 在 view module 中补一条"无 View 时也能跑 query → contains → flow 派生"的 path。整 phase 标 fixme。
- **不需要新 helper**：Phase A 复用 `JointUserPage.createSpace()`、`ensureRegistered`、`issueDevSession`、`openUserPage`，与 `messaging/triad-collaboration` 完全一致。Phase B–E 只用 Playwright `request` fixture 直打 soland，不需要 browser context。
- **测试侧 wire-shape 容忍度**：spec 用中文写公共字段语义（"创建主体" / "最近一次 state 转换时间"），但 soland wire 上的字段名是 snake_case（`owner` / `deleted` / `created_at` / `sender`）。本 scenario 的断言**绑定到 wire field 名**，spec 锚点用 §号 引用语义。如果 soland 将来改名（如把 `deleted` 改成 `state`），断言要相应更新，但本 scenario 仍是 spec §3 公共字段的 e2e guard。

## 总耗时预估

主流程（仅 Phase A live）：约 10-15s（1 个 browser context + 2 个 HTTP 调用）。
全 phase live 后预计 30-45s（Phase B–E 都是 HTTP 直调，无 browser context）。
