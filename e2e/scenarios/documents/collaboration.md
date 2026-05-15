# 文档协作编辑

## 目标

alice 建文档(Morph),bob 加入并发编辑;光标 presence 通过 ephemeral 通道实时传播;评论关联到 document range;通过 anchor finality 实现版本化;从早期 anchor 恢复一个版本。

不验证:加密文档(后续 scenario,Morph + E2EE 是 encryption/mls-group + encryption/encrypted-attachments 的组合)、文档导出格式细节。

## Spec 锚点

- `models/morph.md` §2 — Morph schema(`morph_type`,`encrypted_payload`)
- `models/morph.md` §4 — Facets(`documentable`)
- `models/content-types.md` §2-§3 — Content Block 结构
- `models/flow-and-message.md` §4.3 — Discussion track(评论 vs 文档主体)
- `models/flow-and-message.md` §5 — `discussion_space_ref`(文档评论可上升到 child space,见 messaging/discussion-upgrade)
- `models/relation.md` §3.2 — `replies_to`(comment thread)
- `models/relation.md` §4.3 — Author space vs discussion space 读权限分割
- `discovery/profiles-presence.md` §3 — Presence(光标位置 ephemeral)
- `authz/event-auth-state-resolution.md` §2-§4 — Move / Anchor / Lattice
- `authz/event-auth-state-resolution.md` §8.1 — 冲突恢复 Move(`state_witness`/`inclusion_proof`)

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | document author |
| bob | 协作者 |

## Steps

### Phase A — alice 建文档

1. alice 进 `/document/new`(或 space-scoped `/spaces/${spaceId}/documents/new`)
2. 输入 title `"Design doc documents/collaboration"`,正文 `"# Goals\n\nFirst section..."`
3. yougen 提交 `cx.morph.create`:`{ morph_type: "document", payload: { blocks: [...] }, space_id }`
4. 记录 `morphId`
5. 断言:`/document/${morphId}` 渲染文档,alice 视图可编辑

### Phase B — bob 加入

6. alice 创建 space `S_doc`,seedMembers=[bob],把 morph 关联到 space
7. bob acceptInvite,进 `/document/${morphId}`
8. 断言:bob 看到 alice 的初始文档

### Phase C — 并发编辑

9. alice 在 offset 100 处插入 `"hello"`
10. yougen 发 `cx.morph.update` Move,effect 修改 `cx:cell:cx.component.morph.v1:<morphId>` 的 content
11. 同时(并发)bob 在 offset 50 处插入 `"world"`
12. soland reducer:两个 Move 各自更新文档,以 anchor frontier 为收敛点
13. 断言:30s 内,alice 和 bob 都看到 **合并后** 文档(双方插入都体现);若 lattice 选 `mv-register` 允许多值,UI 用 OT-like 算法合并

### Phase D — 光标 presence(ephemeral)

14. alice 移动光标到 offset 150
15. yougen 发 `cx.presence` ephemeral signal,payload `{ space_id, morph_id, cursor_offset: 150, ttl_ms: 30000 }`
16. 断言:bob 视图在 offset 150 处显示 alice 的 cursor marker(`presence-cursor-alice` testid)
17. bob 移动光标到 offset 200
18. 断言:alice 视图显示 bob 的 cursor

### Phase E — 评论关联到 document range

19. bob 选中文档 offset 100-110 → 点 "Add comment"
20. yougen 提交 `cx.message.create`(到 morph 的 discussion track),payload 含 `{ anchor_range: { start: 100, end: 110 }, text: "needs more detail" }`
21. 断言:alice 视图文档 offset 100-110 区域旁边出现 comment 卡片
22. alice 回复 bob 的评论 → `cx.message.create` 带 `reply_to: bob_comment.event_id`
23. 断言:comment thread 树形展示

### Phase F — Anchor finality + 版本快照

24. soland 周期性写 anchor(或 alice 手动触发"Lock version")
25. 当前 anchor 覆盖所有 Phase C 的 edits
26. 断言:`/document/${morphId}/versions` 列出版本快照(每个 anchor 一个版本,带 timestamp)

### Phase G — 恢复历史版本

27. (前提:Phase C 之前的状态是 V0;Phase C 之后是 V1)
28. alice 进 `/document/${morphId}/versions`,选 V0,点 "Restore"
29. yougen 提交 `cx.morph.update` Move,effect 把当前 content 改回 V0 内容
30. spec §8.1:恢复 Move 必须含 `state_witness`(指向 V0 anchor)+ `inclusion_proof`(证明 V0 anchor 在 history 中存在)
31. soland reducer 校验后接受
32. 断言:文档主视图回到 V0;V1 之间的 edits 在历史中可见但不在 current state

## Observable assertions(合并)

- Phase A 步骤 5:morph 创建
- Phase B 步骤 8:bob 看到初始文档
- Phase C 步骤 13:并发编辑双方都体现
- Phase D 步骤 16/18:光标 presence 双向
- Phase E 步骤 22-23:评论 thread
- Phase F 步骤 26:版本列表
- Phase G 步骤 32:版本恢复

## Edge cases / sub-tests

- **E17.1 并发同位置编辑**:alice 和 bob 同时在 offset 100 处插入不同内容 → lattice 资讯(`mv-register` 多值暴露 / `cas-register` 选一个 winner)。yougen UI 必须明确显示冲突状态
- **E17.2 评论指向已删 range**:bob 评论的 range 在 alice edit 之后已不存在 → comment 状态从 active 变 `orphaned` / `locked`
- **E17.3 group 密钥旋转中的 edit**:E2EE 文档 + 成员变化导致 MLS epoch advance → 文档 cell 用 `mv-register` 合并两个 epoch 的内容(spec edge case)
- **E17.4 retention policy purge V0**:V0 anchor 因 retention 被 GC → 恢复请求失败,`anchor_purged_by_retention`
- **E17.5 文档导出**:alice 选 "Export Markdown" → yougen 触发本地下载,文件内容应是当前 state 的 markdown 序列化
- **E17.6 大文档(10k 行)**:测性能,断言 sync 时间 < N 秒

## Implementation notes

- **soland 缺口**:`cx.morph.create/update`、`cx:cell:cx.component.morph.v1` lattice 类型、anchor finality 的 frontier 计算、`state_witness` + `inclusion_proof` 校验 — 实现度未知
- **yougen 缺口**:`/document` 视图、collaborative cursor(`presence-cursor-*`)、anchor range 的 comment UI、版本浏览器 — 这些 testid 当前 yougen 可能没有完整实现
- **测试侧难点**:并发编辑要用 Playwright 两个 page 同时输入,timing 敏感

## 总耗时预估

约 2 分钟。
