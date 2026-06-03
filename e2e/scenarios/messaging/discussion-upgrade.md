# Discussion track 升级为独立 child Space

## 目标

一个 Flow 的 discussion track 内消息增长后,alice 把 discussion 升级为独立 child Space:Flow 设置 `discussion_space_ref` 指向新建子 Space;之后新评论路由到子 Space,**老评论保留** 在原 Flow;子 Space 可独立配置访问策略 / E2EE 群组;父 Space 的 synthesis track 不受影响。

## Spec 锚点

- `models/flow-and-message.md` §5 — `discussion_space_ref` 字段
- `models/flow-and-message.md` §5.1 — Track / discussion_space_ref 关系图
- `models/flow-and-message.md` §4.3 — Discussion track(不支持 hybrid 访问)
- `models/space-hierarchy.md` §3-§4 — `ck.space.child`/`ck.space.parent` confirmed edge
- `models/space-hierarchy.md` §3.4(可继承的能力 bundles)
- `discovery/read-receipts.md` §2.5 — Disclosure scope override

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | Flow 拥有者,触发升级 |
| bob | Flow discussion 参与者 |
| carol | Phase D 新加入子 Space 的成员 |

## Steps

### Phase A — 创建 Flow + 初期 discussion

1. alice createSpace `S_parent`,seedMembers=[bob]
2. alice 在 `S_parent` 中创建 Flow `F1` (Card),`discussion` track 默认启用
3. alice、bob 在 `F1` discussion 中互发 10 条消息 `M1..M10`
4. 断言:两人都看到 `M1..M10` 在 `F1` 详情的 Comments 区

### Phase B — alice 升级 discussion 为子 Space

5. alice 在 `F1` 详情点 "Promote discussion to separate space"
6. yougen 客户端:
   - 创建新 Space `S_discussion`:`ck.space.create`,parent_space_id = `S_parent`
   - 更新 `F1`:`ck.flow.update`,`discussion_space_ref = S_discussion.id`
   - 父子边互相确认:`ck.space.child`(在 `S_parent` 写入)+ `ck.space.parent`(在 `S_discussion` 写入)
   - 两条边都 status=active 后,reducer 标记 edge `confirmed`(spec §3-§4)
7. 断言:`F1` 详情 UI 提示 "Discussion moved to child space `S_discussion`"

### Phase C — 新消息路由到子 Space

8. alice 在 `F1` discussion 输入新消息 `M11`
9. yougen 客户端:因为 `F1.discussion_space_ref = S_discussion`,`ck.message.create` 应路由到 `S_discussion`(不是 `S_parent`)
10. 断言:`M11` 出现在 `S_discussion` 的 timeline;**不出现** 在 `S_parent` 的 timeline
11. `F1` 详情的 Comments 区:既显示 `M1..M10`(老,落在 S_parent)+ `M11`(新,落在 S_discussion)— 客户端把两端拼起来显示

### Phase D — 子 Space 独立成员管理 + 独立 E2EE

12. alice 在 `S_discussion` 邀请 carol(carol **不在** `S_parent`!)
13. carol acceptInvite
14. carol 进 `/timeline/S_discussion`:能看到 `M11`(以及 Phase E 之后的新消息)
15. 断言:carol **看不到** `M1..M10`(那些在 `S_parent`,carol 非该 space 成员)
16. (可选)alice 把 `S_discussion` 改为 E2EE:`encryption_profile = "mls_rfc9420"` — 子 Space 有独立的 MLS group key

### Phase E — 老消息保留在父 Space

17. alice 在 `S_parent` 视图查 `M1..M10` → 应当能看到(它们在 `S_parent` 的 history)
18. bob 同样

### Phase F — Read receipts scope_overrides_allowed

19. `S_parent` 的 read receipt policy 是 `disclosure = optional`
20. alice 把 `S_discussion` 改为 `disclosure = required`(spec §2.5 scope_overrides_allowed)
21. 断言:`S_discussion` 的 receipt 强制开,即使 carol 偏好关闭也会被强制发

## Observable assertions(合并)

- Phase A 步骤 4:`M1..M10` 在 Flow discussion
- Phase B 步骤 7:升级后 UI 提示
- Phase C 步骤 10-11:新消息路由到子 Space,UI 拼接老+新
- Phase D 步骤 15:carol 看不到 pre-upgrade 消息
- Phase E 步骤 17:老消息保留
- Phase F 步骤 21:子 Space 独立 policy

## Edge cases / sub-tests

- **E21.1 子 Space 不存在**:alice 把 `discussion_space_ref` 指向不存在的 space → reducer 拒绝 `ck.flow.update`,reason `orphan_discussion_space_ref`
- **E21.2 切换 primary track**:升级后 alice 切回原 `inline` discussion → spec §4.6 切换规则,但**不**删除已有 messages
- **E21.3 父子边未确认**:alice 只写了 `ck.space.child` 但 reducer 未收到 `ck.space.parent`(假设网络问题)→ edge 状态 `unconfirmed`,继承策略不应用
- **E21.4 E2EE 父 + 非 E2EE 子**:父 `S_parent` 是 E2EE,子 `S_discussion` 是 plain text → spec §9 要求 parent 的 MLS key MUST NOT 解 child,验证密钥独立
- **E21.5 跨服务器子 Space**:`S_parent` 在 α、`S_discussion` 在 β → 联邦 hierarchy(与 federation/cross-server 联动)

## Implementation notes

- **soland 缺口**:`ck.flow.update.discussion_space_ref`、`ck.space.child`/`parent` 双向 confirm、cross-space 消息路由 — partial
- **yougen 缺口**:"Promote discussion" 按钮、跨 space 拼接 comments 显示、子 Space 切换 policy UI

## 总耗时预估

约 60-90s。
