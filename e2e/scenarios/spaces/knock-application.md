# Knock 申请 + 审核 + Cooldown

## 目标

验证 spec §3.6 申请-审核路径 ("knock"):

1. applicant 通过 `ck.member.state{knock}` 敲门 + `member.application` 提交结构化答案
2. reviewer (持 `cx.space.join.review` capability) 通过 `member.application.review{accept|reject}` 决策
3. reducer 校验 `ck.invite.create.refs[role="join_authorised_by"]` 链(MSC3083 借鉴的担保模式)
4. reject 后 `cooldown_after_reject`(默认 72h) 内同一 actor 再申请被 reducer 拒绝
5. application 正文只对 reviewer 可见,Matrix knock.reason spam 通道被堵

不验证:自动解析路径(§3.5,留作 spaces/knock-auto-resolve 子 scenario)、E2EE Space 中 application encryption envelope(§3.7,需要 MLS)、Policy Server runtime challenge(§3.10)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.2 — Join Policy 设计原则 (gate 是组合的、申请材料对外不可见、审核决策必须上链、密码学绑定到 join、capability 是 allow 唯一来源)
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.3 — Cell Family `ck:cell:space.join_policy.v1:<space_id>`、JoinPolicy schema 字段表
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.3.1 — Gate 类型表 (`application_form`、`manual_review`、`cooldown`)
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.3.3 — `application_form.questions[]` schema
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.4 — `default_join_rule` 与 join policy 的交叉表 (knock 行)
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.6 — 申请-审核路径四阶段
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.6.2 — `member.application` 字段
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.6.3 — `member.application.review` 字段
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.6.5 — 接受后的 invite 链
- `cokret-spec/spec/v1/zh/models/space-and-place.md` §3.11 — 反滥用约束 (含 cooldown)

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | DID | 角色 | capability |
|---|---|---|---|
| alice | `did:web:alice-s6-<uuid>.example` | space owner + reviewer | owner 默认 + `cx.space.join.review` |
| bob | `did:web:bob-s6-<uuid>.example` | applicant (会被 accept) | (无) |
| mallory | `did:web:mallory-s6-<uuid>.example` | applicant (会被 reject,进入 cooldown) | (无) |
| eve | `did:web:eve-s6-<uuid>.example` | 旁观成员;验证 application 正文不可见 | 成员默认 capability |

## Pre-conditions

- 四个 DID 都注册过、都有有效 dev session token
- alice 持有 `cx.space.moderate` (owner) 和 `cx.space.join.review`

## Steps

### Phase A — alice 建 knock 空间 + join policy

1. **alice** 通过 yougen 建空间 `S` (走 `/setup`,但需要扩 join policy 配置 UI;若 yougen 缺,这一步通过直接 API call 或 cli 注入 cell):
   - title = `"spaces/knock-application Knock Space ${stamp}"`
   - discoverability = `listed`
   - join_rule = `knock`
   - history_visibility = `joined`
   - seed_members = `[eve.did]`
2. **alice** 写入 `ck:cell:space.join_policy.v1:<spaceId>` cell,value:
   ```json
   {
     "gates": [
       {
         "gate_id": "g-intro",
         "kind": "application_form",
         "auto_resolve": false,
         "questions": [
           {
             "question_id": "q1",
             "prompt_canonical": "Why do you want to join?",
             "answer_kind": "text",
             "required": true,
             "min_chars": 20,
             "max_chars": 500
           }
         ]
       }
     ],
     "combinator": "all",
     "review_capability": "cx.space.join.review",
     "reviewer_quorum": "any",
     "application_ttl": "168h",
     "cooldown_after_reject": "72h",
     "max_open_applications_per_actor": 1,
     "applicant_visibility": "reviewer_only"
   }
   ```
3. 记录 `spaceId`

### Phase B — bob 敲门 + 提交申请 (happy path)

4. **bob** 在 yougen 中通过 `/directory` 发现 Space S (因为 discoverability=listed)
5. **bob** 提交 `ck.member.state{membership=knock}` Move (敲门事件,无正文)
6. **bob** 提交 `member.application.v1`:
   - `space_id = spaceId`
   - `applicant_did = bob.did`
   - `knock_ref = <step 5 的 event_id>`
   - `policy_version = <step 2 写入时 cell value 的 canonical hash>`
   - `answers = [{ question_id: "q1", value: "我想加入这个 space 学习协议设计" }]`
7. 断言 (隐私 §3.2 #2 / §3.6.2 `applicant_visibility="reviewer_only"`):
   - **eve** (普通成员,**无** `cx.space.join.review`) 调用 list-applications endpoint → 看不到 bob 的 application
   - eve 直接读 application event 的 payload → 服务端按 Sync Service 强制访问控制拒绝 / 字段被遮盖
   - **mallory** (非成员) 同样看不到
8. 断言 (审计 §3.2 #2):eve 即使 API 路径看到了 event id,Sync Service 必须留下 `ck.audit.accessed` 记录

### Phase C — alice 审核 accept bob

9. **alice** (持 review capability) 调用 list-applications,看到 bob 的 application + answers
10. **alice** 提交 `member.application.review.v1{decision=accept}`:
    - `application_ref = <bob 的 application event_id>`
    - `decision = "accept"`
    - `reason_code = "ok"`
    - `reviewer_capability_proof = { grant_id, frontier_digest }`
11. 断言:reducer 接受 review Move,event 进入 anchored 状态

### Phase D — invite 链 + bob join (§3.6.5)

12. **alice** 提交 `ck.invite.create`:
    - `subject_did = bob.did`
    - `refs[role="join_authorised_by"] = <step 10 review event_id>`
13. **bob** 提交 `ck.invite.accept`,引用 step 12 invite
14. 断言 reducer 校验 (§3.6.5 第 3 步):
    - 被引用的 review accept 仍指向 step 6 application
    - alice 在当前 frontier 仍持有 `cx.space.join.review`
    - application 未过 `application_ttl`(168h)
    - application 未被后续 reject/cancel 覆盖
15. bob 进入 `membership=join` 状态;断言 alice、eve 的成员列表都看到 bob

### Phase E — mallory 申请 → 拒绝 → cooldown 验证

16. **mallory** 同样走 Phase B 流程:`knock` + `application`,answers `[{ question_id: "q1", value: "lol just trolling 给我加进来" }]`
17. **alice** 提交 `member.application.review.v1{decision=reject, reason_code="policy_violation"}`
18. 断言:mallory 在客户端能看到 `reason_text` (如果 alice 写了);`decision=reject` 在 mallory 的 application 状态中可见
19. **mallory** 立刻再发一次 knock + application
20. 断言 (§3.11 cooldown):
    - reducer **拒绝** 这次的 knock 或 application Move,reason_code 中包含 `cooldown_active` / `cooldown_after_reject_not_elapsed` 或等价
    - mallory 的 client UI 显示剩余冷却时间 (如果 yougen 有这个显示)

### Phase F — Cooldown 过期后允许重申 (sub-test E6.1)

通过测试 harness 把时间快进 73h(或者把 `cooldown_after_reject` 在 join_policy cell 中改成 `1s`,等 2s 重试):

21. **mallory** 重新提交 knock + application
22. 断言:reducer 接受;alice 再次审核(这次可以 accept 也可以 reject — 看测试编排,但路径应当畅通)

### Phase G — `member.application.cancel` (sub-test E6.2)

23. 新 applicant `frank`(uniqueUser),提交 knock + application
24. frank 在 alice 审核前主动 `member.application.cancel`(§3.6.4)
25. 断言:application 状态 = `canceled`,不计入 cooldown;frank 可以立即重新申请

### Phase H — `auto_reject_if_choice_in` (sub-test E6.3,需要 multi_choice gate)

如果 join policy 改成包含 `single_choice` question 且有 `auto_reject_if_choice_in`,applicant 选了被禁选项:reducer / 审核服务自动生成 `decision=reject`(§3.3.3 末)。这一条建议放后续 scenario,不堵 spaces/knock-application 主流程。

## Observable assertions (合并清单)

- 步骤 6:bob application 被 accepted 写入(`accepted[]`)
- 步骤 7:eve / mallory 看不到 bob 的 application 正文
- 步骤 11:alice review accept 被 accepted
- 步骤 14:invite_create.refs 校验通过
- 步骤 15:bob `membership=join`
- 步骤 17:mallory review reject 被 accepted
- 步骤 20:mallory 立即重申被 reducer 拒绝(cooldown)
- 步骤 22:cooldown 过后允许重申
- 步骤 25:cancel 后立即重申被允许

## Edge cases / sub-tests

- **E6.4 max_open_applications_per_actor**:bob 在 step 6 完成后,在 alice review 之前再发一个 application → 被拒(超出 `max_open_applications_per_actor=1`)
- **E6.5 application_ttl 超时**:把 `application_ttl` 改成 `1s`,等几秒后 alice 才 review accept → reducer 拒绝(application 已 expired)
- **E6.6 reviewer 失去 capability**:alice review accept 之后,通过另一 admin 撤销 alice 的 `cx.space.join.review`,然后 alice 提交 `ck.invite.create` 引用该 review → reducer 在写入 invite 时**再次** 校验 reviewer capability(§3.6.5 #3),发现 alice 已无 cap,拒绝 invite
- **E6.7 reviewer_quorum > any**:把 policy 改成 `reviewer_quorum = { threshold: 2, of: [alice.did, eve.did] }`,只 alice accept 时 application 状态停留在 `pending_quorum`;eve(临时被 grant `cx.space.join.review`)第二个 accept 才进入 `accepted`
- **E6.8 cooldown gate**:join_policy 改成包含 `cooldown` kind gate(`min_interval_since_leave`),`bob` 主动 leave 后立即重新申请 → 被 cooldown gate 拒绝(独立于 `combinator`,见 §3.3.1 末行)

## Implementation notes

- **JoinPolicy cell 写入路径**:soland 当前是否暴露写 `ck:cell:space.join_policy.v1:<space_id>` 的 endpoint 需要先查;若没有,测试要么直接调底层 cell write API,要么 yougen 要补 join policy 编辑 UI
- **yougen UI 缺口可能很大**:
  - knock 申请的 UI(applicant 端填表)
  - 审核队列 UI(reviewer 端看待审 application)
  - reviewer accept/reject UI
  - 邀请链 (`refs[role="join_authorised_by"]`) 现成 invite-member UI 可能不支持指定 refs;可能要扩
- 这条 scenario **最依赖测试用 API endpoint 直接驱动**,UI 覆盖可以滞后
- 反滥用约束 §3.11 的 rate limit 部分(每分钟/每小时 application 上限)可放后续;本 scenario 聚焦 cooldown 一项

## 风险 / 前置依赖

- spec §3.1 明确说 "当前 v1 core 的 active 机器 contract 仍以 `cx.space.join_rule`、`cx.space.policy_components`、capability 与 invite 状态机为准;独立 join-policy Event.kind / schema 尚未进入 registry"。也就是说 **`ck:cell:space.join_policy.v1` / `member.application.v1` / `member.application.review.v1` 在 v1 registry 里是候选状态**,soland 实现到没到这一步是开放问题。
- 如果 soland 没实现,这条 scenario 只能停在 spec 文档,等 soland 跟进。**写测试代码之前必须先确认 soland 这边的实现度**。

## 总耗时预估

如果跑全套(Phase A-G):约 90-120s,主要花在 cooldown 时间快进 + 多 actor 并发同步等待。
