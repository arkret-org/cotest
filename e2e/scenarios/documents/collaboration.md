# 文档协作编辑

## 目标

验证 Document Morph 的本地 1.0 可用链路:服务端接受 `ck.morph.create/update`,投影当前正文、版本快照、关联 Relation、range comment 与 orphan comment;yougen 提供 `/document/:realm_id` 和 `/document/:realm_id/morph/:morph_id` UI,可创建、查看、保存版本、提交 range comment,并渲染 cursor presence 外壳。

不验证:真正并发 CRDT/OT 合并、ephemeral cursor 跨端实时传播、带 `state_witness`/`inclusion_proof` 的历史版本恢复、加密文档、导出格式。这些属于后续协作深水区,不再阻塞 GAP-P2-040/041。

## Spec 锚点

- `models/morph.md` §2 — Morph schema(`morph_type=document`)
- `models/morph.md` §4 — Facets(`documentable`)
- `models/content-types.md` §2-§3 — Content Block 结构
- `models/strand-and-message.md` §4.3 — Discussion track(评论)
- `models/relation.md` §3.2 — range comment / replies relation 语义
- `discovery/profiles-presence.md` §3 — Presence UI shell
- `authz/event-auth-state-resolution.md` §2-§4 — version boundary / anchor-oriented history

## 拓扑

- 1 × soland + 1 × coauth + 1 × yougen

## Actors

| 名字 | 角色 |
|---|---|
| alice | document author |
| bob | collaborator/commenter |

## Live coverage

### Phase A — soland Document Morph projection

1. alice 注册并创建 Realm。
2. harness 直接提交 `ck.morph.create`:`morph_type=document`,带 `schema_refs=["ck.schema.morph.v1"]`、`facets.documentable` 和 document body。
3. harness 提交 `ck.relation.create`,把 document Morph 关联回 Realm/incident ref。
4. harness 提交 `ck.message.create`,content 含 `anchor_range:{target_ref,start,end}` 与 comment body。
5. harness 提交 `ck.morph.update`,把 document body 缩短。
6. 断言 `GET /_cokret/self/realms/:realm_id/morphs/:morph_id` 返回:
   - current body 为更新后的 body
   - `versions[]` 含 create/update 两个快照
   - `relations[]` 含刚创建的 relation
   - `comments[]` 含 range comment 且因 range 已删除变为 `state=orphaned`
   - `cursor_presence=[]` shape 稳定

### Phase B — yougen Document Morph UI

1. alice 在 UI 创建 Realm,seed bob。
2. bob 接受 invite。
3. alice 打开 `/document/:realm_id`,填写 title/body/link,点击 `save-document-button`。
4. harness 从 soland Morph projection 解析新 `morph_id`。
5. bob 打开 `/document/:realm_id/morph/:morph_id`,断言正文 hydrate 成 alice 初始内容。
6. 默认构建中 bob 看到 `document-collaboration-deferred`；启用 `experimental-document-collaboration` 时 bob 看到 `document-cursor-self` 和 `document-presence-list` presence UI shell。
7. bob 用 comment composer 提交 `6..40` range comment,harness 轮询 soland projection 确认 comment 已同步。
8. alice 把正文缩短后保存,重新打开 `/document/:realm_id/morph/:morph_id`。
9. 断言:
   - 正文 hydrate 为最新短正文
   - `document-version-row` 渲染 create/update 两个版本
   - comment thread 显示 bob 的评论
   - orphan badge 可见
   - restore button 至少输出本地 restore 状态,不验证 proof-backed restore Move

## Follow-up edge cases

- **D1 并发同位置编辑**:alice/bob 同时插入不同内容,UI 需显示冲突或合并结果。
- **D2 real-time cursor presence**:`ck.presence` ephemeral 从 alice 传播到 bob,1s 内显示 remote cursor。
- **D3 proof-backed restore**:`ck.morph.update` 带 `state_witness` + `inclusion_proof` 恢复历史版本。
- **D4 encrypted document edit**:MLS epoch 变化期间 document cells 仍可合并。
- **D5 retention purge**:被 retention GC 的历史版本恢复应失败并显示 `anchor_purged_by_retention`。
- **D6 large document performance**:10k 行同步和投影耗时受控。
