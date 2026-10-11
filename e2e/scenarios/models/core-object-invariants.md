# 核心对象不变量

此场景验证当前 v1 的真实接纳、原 Event／RealmCommit、位置 CAS、Space 生命周期及 Relation 基数。真相源为 `arkret-spec/spec/v1/zh/` 正式正文及机器工件，测试使用既有 Cotest managed Coauth／Coland；浏览器 Phase A 经真实 DPoP 登录。API 阶段使用既有注册及会话 helper，不构造未接纳的结构对象作为成功前置。

## 规范锚点

- `models/common-fields.md §3/§5`：公共字段和生命周期。
- `models/event-and-patch.md §2/§4`：闭合签名 Event 与目标验证。
- `models/realm-and-space.md §3.2/§3.4/§3.6`：Space 字段、非级联生命周期及 Strand 位置。
- `models/relation.md §4.4/§6`：跨 Realm 结构拒绝及 primary conflict domain。
- `sync/authority-commit-log.md`：唯一 accepted RealmCommit head 与完整原 Event。

## Phase A：公共字段

真实用户通过 Inkson 创建 Realm。读取 accepted stream，核对 event-derived ID、原 Event 的 `created_at`／Account actor／kind／scope 及原 Commit。由实际注册 DTO 判断字段，不用已退役 `Space.owner/members/deleted` 模型或私有旧 events 列表。

## Phase B：位置 CAS

1. 注册 Alice，创建 Realm、Strand、真实 Board Space 和三条具有 accepted parent 的 List Space。
2. 以普通 `ak.strand.move` 将 Strand 首次放到源 List，rank 为 `m`。首次放置不带 `from_space_id` 或 `expected_position`；保存 accepted RealmCommit head。
3. 提交陈旧完整前像 `expected_position={list_space_id:L_stale,rank:"m"}`。期望 HTTP 409、`failed_precondition`，并断言 accepted head 不变。
4. 使用实际前像 `{list_space_id:L_source,rank:"m"}` 提交目标 List／rank `z`，期望成功及 accepted head 推进。该成功也证明上次拒绝没有安装目标位置。
5. 使用旧前像尝试返回源 List，须拒绝且 head 不变；使用新前像 `{list_space_id:L_target,rank:"z"}` 返回源 List须成功。独立认证 stream scan 恰有三条 accepted move，没有两条被拒 Event。

`expected_position` 是可选的完整 payload CAS；缺席时不得添加隐式保护。此阶段不使用 Seal、control-plane、cell、`head_eq`、`effects[]` 或 `preconditions[]`。

## Phase C：非级联生命周期

1. 创建真实 Board 与 List 子项，Space 标题使用正式顶层 `title`。
2. archive 父项，读取注册 spaces 投影（包含终态），断言父项 archived、子项 active。
3. 子项 active 时 tombstone 父项，期望 HTTP 409／`failed_precondition`／`space_has_live_dependents`；accepted head 不变。
4. 显式 archive 子项，再次 tombstone 父项；仍须以相同原因拒绝，head 不变。archived 子项仍是依赖。
5. restore 父项，确认父项 active、子项仍 archived；父项 tombstone 仍以活依赖拒绝且 head 不变。
6. 显式 tombstone 子项，确认父项仍 active，然后 tombstone 父项，二者都成功且投影为 tombstoned。历史 parent 事实保留，但终态子项不算活依赖。
7. 对终态父项尝试普通 title update，期望 `failed_precondition / space_not_active`；restore 和重复 tombstone 均须 `failed_precondition / space_already_terminal`。三次拒绝都不推进 head。独立认证 stream scan 包含全部 accepted Space Event，没有被拒 Event。

不以 UI 可见列表证明无依赖，不隐式级联或删除 canonical parent／position 事实。

## Phase C2：完整父项与活依赖

真实 Board、List 和 Card 使用同一 accepted cut。archive 不级联，子项的 typed current value／revision 保持原件；非终态子 Space 和真实 Card placement 都以已登记的 `space_has_live_dependents` 阻止父项 tombstone，拒绝不推进 head／current。显式移除依赖后父项才可终结。终态父项的 restore／update 及终态 List move 必须精确拒绝；exact retry 保留原 Commit、head 和 current。独立认证 stream scan 保留全部 accepted 原件并排除被拒 Event。

## Phase D：Relation

真实 Strand 的 `has_default_view` primary domain 首次 create 成功。第二个同源 active create 以 `failed_precondition` 拒绝，head 不变，active 列表只含首条。另一个 `references` Event 的 exact replay 返回原 Commit。跨 Realm 的 structural `contains` 返回 `failed_precondition / cross_realm_structural_relation`。

不允许“自动关闭旧 edge 或拒绝二选一”的宽松断言；不将 `assigned_to` 的多人分配误写为单负责人互斥。

## 验收

Phase A、B、C、C2、D 都有可执行断言，不使用 retained fixme。修复后的 TypeScript 检查和最新 live 终态记录在对应本轮报告；文档更新和夹具准备本身不计 live 通过。
