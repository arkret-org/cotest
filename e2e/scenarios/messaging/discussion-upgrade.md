# Discussion scope 升级为独立 Strand + Circle

## 目标

一个 Strand 的 discussion track 内消息增长后，alice 把后续私密讨论迁移到一条新的 discussion Strand，并把新 Strand 绑定到 Realm 内的窄 Circle。原 Strand 的 synthesis / discussion 保留在原 effective scope；新讨论 Strand 通过 `confidential_discussion_of` Relation 指回原 Strand。协议层不使用 `discussion_space_ref`，也不把 Space 当成成员、访问策略或 E2EE 边界。

## Spec 锚点

- `models/strand-and-message.md` §5 — Strand 只有一个 effective scope；track 不拥有独立 access
- `models/circle.md` §7.2 — "宽 synthesis + 窄 discussion" 用两个 Strand + Relation 表达
- `models/relation.md` §3.2 — `promoted_from_discussion` / 语义 Relation
- `authz/resource-selector-grammar.md` — Strand / Circle / Realm scoped selector
- `discovery/read-receipts.md` §2.5 — Circle 可在 Realm policy 允许时进一步收紧 read receipt policy

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 原 Strand owner，触发升级 |
| bob | 原 discussion 参与者 |
| carol | Phase D 新加入私密 Circle 的成员 |

## Steps

### Phase A — 创建原 Strand + 初期 discussion

1. alice createRealm `R_parent`, seedMembers=[bob]
2. alice 在 `R_parent` 中创建 Strand `F_public`，`scope_circle_id = null`，discussion track 默认启用
3. alice、bob 在 `F_public` discussion 中互发 10 条消息 `M1..M10`
4. 断言:两人都看到 `M1..M10` 在 `F_public` 详情的 Comments 区

### Phase B — alice 创建窄 Circle + discussion Strand

5. alice 在 `F_public` 详情点 "Promote discussion to private thread"
6. inkson 客户端:
   - 创建 Circle `C_discussion`，members=[alice, bob]，必要时设置 `encryption_profile = "mls_rfc9420"`
   - 创建新 Strand `F_discussion`，`scope_circle_id = C_discussion.id`
   - 创建 Relation `confidential_discussion_of`：`from_ref = F_discussion.id`，`to_ref = F_public.id`
   - 在 `F_public` 上写入展示用 metadata / relation projection，指向 `F_discussion`
7. 断言:`F_public` 详情 UI 提示 "Discussion promoted to private thread"

### Phase C — 新消息路由到 discussion Strand

8. alice 在 promoted discussion 输入新消息 `M11`
9. inkson 客户端因为当前 composer 绑定 `F_discussion`，提交 `ak.message.create` 到 `F_discussion` 的 discussion track
10. 断言:`M11` 出现在 `F_discussion` timeline；不出现在 `F_public` 的原 discussion track
11. `F_public` 详情的 Comments 区可展示一个 promoted-thread summary；展开后进入 `F_discussion`，老消息 `M1..M10` 仍留在 `F_public`

### Phase D — Circle 独立成员管理 + E2EE

12. alice 把 carol 加入 `C_discussion`，但 carol 不是 `R_parent` 的普通成员扩权对象之外的默认参与者
13. carol 打开 `F_discussion`:能看到 `M11` 以及之后的新消息
14. 断言:carol 看不到 `F_public` 的 `M1..M10`，除非 Realm/Circle policy 另行授予
15. 若 `C_discussion.encryption_profile = "mls_rfc9420"`，断言 `F_discussion` 新消息使用该 Circle 的 MLS scope，不复用 `R_parent` 默认 scope

### Phase E — Read receipt scope override

16. `R_parent` 的 read receipt policy 是 `disclosure = optional`
17. alice 把 `C_discussion` 的 policy 改为 `disclosure = required`（前提是 Realm policy 允许 Circle 收紧）
18. 断言:`F_discussion` 的 receipt 强制开，即使 carol 偏好关闭也会被强制发

## Observable assertions

- Phase A 步骤 4:`M1..M10` 在原 Strand discussion
- Phase B 步骤 7:升级后 UI 提示并创建 `C_discussion` + `F_discussion`
- Phase C 步骤 10-11:新消息路由到新 Strand，原 Strand 不被追加新消息
- Phase D 步骤 14:carol 看不到 pre-upgrade 原 Strand 消息
- Phase E 步骤 18:Circle policy 对新 discussion Strand 生效

## Edge cases / sub-tests

- **E21.1 Circle 不存在**:alice 把 `scope_circle_id` 指向不存在的 Circle → reducer 拒绝 `ak.strand.create` / `ak.strand.update`,reason `circle_not_found` 或 `circle_realm_mismatch`
- **E21.2 scope rebind forbidden**:已存在的 `F_public` 不允许把 `scope_circle_id` 从 null 改成 `C_discussion`;必须创建新 Strand
- **E21.3 relation 缺失**:存在 `F_discussion` 但没有 `confidential_discussion_of` relation 时，UI 不应把它展示为原 Strand 的 promoted discussion
- **E21.4 E2EE Circle key 独立**:Realm 默认明文、Circle E2EE 时，`F_discussion` 消息必须加密；Realm 默认 E2EE、Circle E2EE 时，也必须使用 Circle scope 的 key material
- **E21.5 跨服务器 Circle member**:carol 的 Station 在 β，`C_discussion` membership / key delivery 走 federation peer API

## Implementation notes

- **soland 缺口**:Circle-backed `scope_circle_id` enforcement、`confidential_discussion_of` relation profile、promoted thread projection。
- **inkson 缺口**:"Promote discussion" 按钮、创建 Circle + discussion Strand 的组合 UI、promoted thread summary / drill-in UI。
- **协议禁项**:`discussion_space_ref` / `discussion_realm_ref` 都不得出现在当前 wire；测试必须 hard-reject 这些字段。

## 总耗时预估

约 60-90s。
