# 审核 + 封禁

## 目标

验证「举报 → moderator 决策 → 封禁 → anchored moderation_state → 后续 Move 被拒」的完整三层 gate 链路:

1. **Capability** 层:owner 的 ban 动作必须先持有 `ck.moderation.decision` capability,否则直接 `missing_capability` 拒
2. **Moderation Policy** 层:ban 决策 MUST anchored,写入 `ck.component.moderation_state.v1` cell,跨 peer 一致
3. **Personal Blocklist** 层:接收方本地 mute/block 不影响其他人的视图

不验证:跨服务器同步 (见 federation/cross-server;但 spaces/moderation-ban 的 ban anchor 应当在 federation/cross-server 拓扑下也跨 peer 一致 — 可作为 federation/cross-server+spaces/moderation-ban 组合测试,本 scenario 先在单服务器跑)、E2EE franking (spec §3.4,需要 MLS,后续单独 scenario)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §2.1 — 审核权由 Realm Owner 行使
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §2.2 — 屏蔽是本地行为
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §2.3 — 举报留痕但不公开
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §2.5.0 — Capability / Moderation / Personal Blocklist 三层判定 (流程图)
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §2.5 — Moderation 决策 MUST Anchored
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §3.1 — `POST /_cokret/self/moderation/report` 字段
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §3.2 — 举报原因枚举
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §3.3 — 举报的处理 (只有 moderator 可见、被举报人不通知)
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §4.1-§4.3 — 个人屏蔽是 Actor-Private,不进 cell
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §5.1 — `ck.message.redact` 需要 `ck.message.redact`
- `cokret-spec/spec/v1/zh/governance/content-moderation.md` §5.2 — `ck.member.state{membership="ban"}` 封禁后被封者未来 Operation 被拒

## 拓扑

- 1 × soland + 1 × coauth (与 messaging/triad-collaboration 同)

## Actors

| 名字 | DID | 角色 | 持有的 capability |
|---|---|---|---|
| alice | `did:webvh:z6mkfixture:alice-s5-<uuid>.example` | Realm owner + moderator | `ck.moderation.decision` / `ck.message.redact` |
| bob | `did:webvh:z6mkfixture:bob-s5-<uuid>.example` | 普通成员;举报人 | (默认成员 capability,无 moderate) |
| mallory | `did:webvh:z6mkfixture:mallory-s5-<uuid>.example` | 普通成员;违规者 (被封禁目标) | (默认成员 capability) |
| carol | `did:webvh:z6mkfixture:carol-s5-<uuid>.example` | 普通成员;旁观者,用于验证 personal blocklist 不广播 | (默认成员 capability) |

## Pre-conditions

- 四个 DID 都注册过、都有有效 dev session token
- alice 持有 `ck.moderation.decision` 与 `ck.message.redact` (作为 owner 默认拥有,通过 inkson 或直接事件链生成)

## Steps

### Phase A — 建 Realm + 加入所有成员

1. **alice** `/setup` 建 Realm `R`:
   - discoverability = `listed`
   - join_rule = `invite`
   - history_visibility = `shared`
   - seed_members = `[bob.did, mallory.did, carol.did]`
2. 记录 `realmId`
3. 断言:alice 的 `/realms/${realmId}/admin` 显示 4 个成员 (alice + 3 个 seed)

### Phase B — mallory 发违规消息

4. **mallory** 进 `/timeline/${realmId}` 发 `M_bad = "abusive content ${stamp}"`
5. 断言:M_bad 在 alice、bob、carol、mallory 四方 timeline 都可见

### Phase C — bob 举报 (Reporter 路径,§3.1)

6. **bob** UI 上对 `M_bad` 触发"举报" (inkson 需要有 report 入口;如缺,scenario 注明需要补 UI 或直接 API 调用)
7. 测试以 bob 的 token 调用 `POST /_cokret/self/moderation/report`,body:
   ```json
   {
     "realm_id": "<realmId>",
     "target_ref": "<M_bad event_id>",
     "report_reason_code": "harassment",
     "reporter": "<bob.did>"
   }
   ```
8. 断言:响应 200 + `report_id` + `status="submitted"`
9. 断言 §3.3 隐私要求:
   - bob 作为 reporter 只能拿到提交响应里的 `report_id`,不能通过 list endpoint 枚举 report
   - mallory 用自己的 token 调用实现私有 admin collection → **看不到** 这个 report
   - mallory 的 timeline 上 `M_bad` 没有任何"被举报"的标记
   - carol (旁观者) 同样看不到 report

### Phase D — alice 处理:capability 检查 + anchored ban

10. **alice** 调用实现私有 `GET /_soland/admin/reports` → 能看到 bob 提交的这个 report
11. **alice** 决定 ban mallory:
    - 调用 `ck.member.state` Move,membership = `ban`,subject = mallory.did
    - 该 Move 必须签名 + 引用 `ck.moderation.decision` capability grant
12. 断言 Capability 层:
    - **sub-test E5.1**:bob (没有 moderate cap) 尝试同样的 ban Move → 被拒,reason_code = `missing_capability`
    - alice 的 ban Move → 被接受
13. 断言 Anchored 层 (§2.5):
    - 查 `ck.component.moderation_state.v1` cell:有针对 mallory.did 的 ban 状态条目
    - 该 cell 的 Move 被 anchored (frontier 覆盖)
    - 跨方读取(alice、bob、carol 各自从客户端读 cell):**三方读到一致状态**

### Phase E — Post-ban 拒绝路径 (§5.2)

14. **mallory** 进 `/timeline/${realmId}` 尝试发新消息 `M_post_ban = "still here ${stamp}"`
15. 断言:soland Reducer 拒绝 mallory 的 Operation,返回 `policy_denied` / `member_banned` / 类似 reason_code
16. 断言:alice / bob / carol 三方的 timeline **不出现** `M_post_ban`

### Phase F — Tombstone redact (§5.1)

17. **alice** 用 `ck.message.redact` 把原 `M_bad` redact 掉 (需要 `ck.message.redact`,alice 持有)
18. 断言:三方 (alice、bob、carol) 视图中,`M_bad` 位置渲染为 `redacted-tombstone`,正文不再可见
19. **sub-test E5.2**:bob (没有 moderate) 尝试 redact 任意他人消息 → `missing_capability`

### Phase G — Personal Blocklist 验证 (§2.2、§4)

20. **carol** 在 UI 上对 alice 触发 personal mute / block (inkson 应当有该 UI;如缺则 spec 给 inkson 留 TODO)
21. **alice** 再发 `M_post_block = "hello after carol blocks me ${stamp}"`
22. 断言 (§4.1 屏蔽是 Actor-Private):
    - **alice 视角**:`M_post_block` 在自己 timeline 正常显示
    - **bob 视角**:`M_post_block` 正常显示
    - **carol 视角**:`M_post_block` 在 UI 上被隐藏 / 折叠 (本地过滤,服务器不广播屏蔽事实)
    - **服务器侧**:carol 的 blocklist 不应进入 `ck.component.moderation_state.v1` cell;查 cell 不应出现 carol 屏蔽 alice 的条目

## Observable assertions (合并清单)

- Phase A:成员 4 人
- Phase C 步骤 8:report 提交成功
- Phase C 步骤 9 (隐私):mallory + carol 看不到 report
- Phase D 步骤 12 (capability):bob 的 ban 被拒、alice 的 ban 被接受
- Phase D 步骤 13 (anchored):三方查 moderation_state cell 一致
- Phase E 步骤 15-16:mallory post-ban 消息被拒,其他人看不到
- Phase F 步骤 18:redact tombstone 三方一致
- Phase F 步骤 19:bob redact 被拒
- Phase G 步骤 22:personal blocklist 三方视图不一致,但 cell 不污染

## Edge cases / sub-tests

- **E5.1**:无 capability 的 ban 尝试 → `missing_capability` (在 Phase D 步骤 12)
- **E5.2**:无 capability 的 redact 尝试 → `missing_capability` (在 Phase F 步骤 19)
- **E5.3 idempotent ban**:alice 连发两次同样的 ban Move,reducer 把第二次视为 no-op (state 已 ban) 或返回幂等接受;不重复写 cell
- **E5.4 unban + 重新加入**:alice 提交 `ck.member.state{membership="leave"}` 把 mallory 移出 ban(如果协议允许;§5.2 说 ban 后"无法重新加入",所以 unban 路径可能需要明确;查 spec `event-auth-state-resolution.md` §5)。若 spec 允许 unban,验证 mallory 重新被邀后能加入并发消息
- **E5.5 hard_deny 模拟**:测 moderation policy 中 `action="deny_write"` 的语义 — alice 提交 `ck.space.moderation_policy` Move 把 mallory.did 标 `deny_write`,验证 mallory 在被正式 ban 之前就已经发不了消息 (capability 没 revoke,但 moderation policy 层 deny)

## Implementation notes

- **soland report privacy**:`POST /_cokret/self/moderation/report` 是唯一标准 reporter 写入口;v1 没有注册 `GET /_cokret/self/moderation/reports`。dev-mode `GET /_soland/admin/reports` 是实现私有调试投影,只向 realm owner、配置的 admin principal 或持有 moderation review/decision 权限的 actor 返回 report;避免 reporter、被举报人或普通成员枚举 report。
- **ban Move 权限**:`soland` 对 direct submit 的 `ck.member.state{membership="ban"}` 执行 owner/moderation gate;bob 这类非 moderator 被 `missing_capability` 拒绝,alice 作为 owner 可接受。
- **inkson owner ban UI**:`/realms/:id/admin/members` 的 `member-row[data-member-did]` + `ban-member-button` 现在作为 live 路径,owner 点击后提交 canonical `ck.member.state` direct event,并从 server projection 中移除被封禁成员。
- **idempotent ban**:重复 `ck.member.state{membership="ban"}` 通过 federation/service convergence 路径保持幂等,最终成员列表不重复、不恢复被 ban 成员。
- **remaining inkson UI 缺口**:举报入口、moderator 报告列表 — 当前 live 测试仍通过 soland HTTP API 直接驱动;后续 UI testid 可在 inkson 任务中补。
- 测试侧需要直接读 `ck.component.moderation_state.v1` cell 来验证 anchored 状态 — soland 应当暴露 `GET /_cokret/self/events?realms=${realmId}&kinds=ck.moderation.decision` 或等价 projection endpoint
- 跨 peer 一致性的 frontier 比对在单服务器场景不需要;留到 federation/cross-server+spaces/moderation-ban 组合测试

## 总耗时预估

单次跑约 60-90s (4 个 browser context、7 阶段、20+ 步)。
