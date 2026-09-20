# Knock 自动解析路径(`ak.member.state{join, gate_proofs}`)

## 目标

当 `default_join_rule=knock_restricted` 且所有 gates 都 `auto_resolve=true`（claim_required + challenge_response）时，applicant 直接提交携带 `gate_proofs[]` 的 `ak.member.state{join}`，由 reducer 内联校验，不需要独立的申请资源与审核命令。这是 spec §3.5 的直接 Event 路径。

## Spec 锚点

- `governance/join-policy.md` §4 — knock_restricted 行 + auto_resolve 全 true 的 OR 合成
- `governance/join-policy.md` §6 — Auto-resolve 路径(直接 join Move)
- `governance/join-policy.md` §3.1 — Gate 类型(claim_required、challenge_response、parent_membership 都是 auto_resolve)
- `authz/constraint-schema.md` §10 — claim presentation

## 拓扑

- 1 × soland + 1 × coauth + 1 × mock claim issuer + 1 × mock challenge provider (e.g. captcha)

## Actors

| 名字 | 角色 |
|---|---|
| alice | Realm owner |
| bob | applicant,持 valid claims + 能过 captcha |
| mallory | applicant,无 claims,不能过 |
| claim-issuer | mock,签发 VC(`did:web:vc-issuer.example`)|
| captcha-provider | mock,签发 challenge proof |

## Steps

### Phase A — alice 配置 knock_restricted + 全 auto-resolve gates

1. alice createRealm `R`,`join_rule=knock_restricted`
2. alice 通过 API 写 `ak:cell:ak.component.realm.join_policy.v1:<R>`:
   ```json
   {
     "gates": [
       { "gate_id": "g-vc", "kind": "claim_required", "auto_resolve": true, "required_claims": ["acme:employee"] },
       { "gate_id": "g-captcha", "kind": "challenge_response", "auto_resolve": true, "provider_did": "did:web:captcha.example", "challenge_kinds": ["captcha"], "max_proof_age": "PT5M" }
     ],
     "combinator": "all"
   }
   ```

### Phase B — bob 自动解析 join(happy path)

3. bob 向 claim-issuer 请求 VC `acme:employee` → 拿到 signed VC
4. bob 向 captcha-provider 请求 challenge → 完成 → 拿到 signed proof
5. bob 客户端组 `ak.member.state{ membership: "join", member_id: bob.actor_id, gate_proofs: [...] }`，
   每项是封闭的 `join_gate_proof`（`event-payload.schema.json#/$defs/join_gate_proof`，裁决
   [`2026-09-05-0730`](../../../../arkret-work/tasks/spec-open/2026-09-05-0730-join-gate-proofs-have-no-closed-carrier.md)）：
   `{ gate_id, kind, realm_id, applicant_actor_id, policy_digest, created_at, (challenge_kind + challenge_id | issuer_id + claims), proofs: [detached JWS] }`。
   `policy_digest` 是当前 accepted `join_policy` component 的 canonical JSON sha256。
   裁决前 soland 读的 `claim_presentation` / `challenge_proof.*` 成员名是实现自造，spec 从未定义，现已删除。
6. 直接提交,**不**经过 application + review
7. soland reducer:
   - 加载 join policy cell
   - 按 combinator=all 校验 gates
   - 先比对绑定元组:`realm_id` / `applicant_actor_id` / `policy_digest` 必须与本次 join 一致,
     freshness 以该 Event 已签名的 `created_at` 为准(不用本地时钟)
   - 再验签(admission 面,需要 DID 解析):`g-vc` 的 `issuer_id` 落在 gate 的 `trusted_issuer_ids`
     且签名由该 issuer 控制的 key 作出;`g-captcha` 的签名由 gate `provider_did` 控制的 key 作出
   - 全过 → 接受 join Move
8. 断言:`/realms/<R>/admin` 成员列表含 bob

### Phase C — mallory 自动解析失败

9. mallory 没有 `acme:employee` VC
10. mallory 试提交同样的 Move,但 `gate_proofs[]` 缺 `g-vc` 项、`issuer_id` 不在 `trusted_issuer_ids`、
    或签名无效
11. 对外统一 `gate_check_failed`(§5 不可枚举:不得暴露是哪个 gate 失败、Realm 是否存在);
    具体原因(`claim_invalid` / `challenge_proof_invalid` / `challenge_failed` / `challenge_expired`)
    只进授权审计
12. 断言:mallory inkson UI 显示不可枚举的加入失败提示,**不得**回显具体 gate 或所需 claim 名

### Phase D — Cooldown gate(独立 deny)

13. alice 把 join policy 加一条 gate:`{ kind: "cooldown", min_interval_since_leave: "P30D" }`
14. bob 主动 leave Realm:`ak.member.state{leave}`
15. 立刻试重新 join:gate_proofs 仍正确,但 cooldown gate 命中
16. 断言:reducer 拒,reason `cooldown_gate_blocking`,独立于 combinator(spec §3.3.1)

## Edge cases

- **E6.2.1 issuer 越界**:`issuer_id` 不在 gate 的 `trusted_issuer_ids` → 拒,审计 reason `claim_invalid`
- **E6.2.2 stale challenge proof**:`max_proof_age` 5 分钟,bob 拿 6 分钟前的 proof → 拒,审计 reason `challenge_expired`
- **E6.2.4 跨 Realm / 跨 applicant / 跨 policy revision 重放**:把一份对 Realm A 有效的 proof 原样提交给
  Realm B(或换 applicant、或在 policy 改版后重放)→ 绑定元组比较即失败,对外 `gate_check_failed`
- **E6.2.3 wrong combinator**:把 combinator 改 `any` → bob 只需要满足任一个 gate;但 cooldown 仍独立

## Parent membership：同 Station durable gate

`parent_membership` 不是 Realm inheritance。它不复制 source membership，只允许 target Realm 的 current governing
Station 在接纳 target `membership=join` 的同一个 durable transaction 中读取 source authoritative current member row。

生产验收必须覆盖：

1. target 对每个 source 都有 current active `join_gate_from` link；缺任一个 link 时返回统一
   `gate_check_failed`，Event、RealmCommit 与 target `member_state` 均零写入；
2. source 与 target 的 verified current authority-tenure `service_id` 逐字相同；每个 Realm 自己的
   `governance_generation` 分别为 current，不跨 Realm 比较 generation，也不用 capability `authority_generation`；
3. 按 RealmId canonical bytes 锁 authority-tenure／handoff、target policy／links 与 source member rows；全部依赖可验证，
   且至少一个 source exact current membership 为 accepted `join` 时才通过；
4. 跨 Station、任一侧 handoff、分库不能形成单一事务 cut、authoritative lookup 不可用时统一
   `gate_check_failed` 零写入；cache、replica、history、Directory 与 caller proof 都不能替代；
5. join 若先线性化并提交，之后 source leave／ban 不级联撤销 target membership；依赖变更若先取得锁，本次 join 拒绝。

`tests/realm_link_clean_break.rs::parent_membership_contract_is_co_governed_and_caller_proof_free` 只检查 canonical
schema／registry 已表达 active link、co-governance、authoritative current lookup 与 caller-proof ban。它不是生产事务验收。

## Implementation notes

- **soland 现状(2026-09-05 傍晚)**:`gate_proofs[]` 按封闭载体解析 ✓、绑定元组与 freshness 比较 ✓、
  issuer 边界与 claims 覆盖 ✓、detached JWS 验签接在 envelope 验证链上 ✓、cooldown 时间 tracking ✓。
  soland 单元覆盖见 `crates/server/tests/realm_join_policy.rs`(24 条)。
- **仍缺**:本 joint 场景本身;验签路径的定向正负例(需要真实 Ed25519 密钥与 DID document 夹具)；以及上述
  `parent_membership` 的生产 durable transaction runner。Soland 内存 reducer 的 parent-membership 测试只说明纯求值，
  不证明 authority-tenure/link/member lock、跨 Station/handoff fail-closed 或三类零写入。
- **harness 缺口**:mock claim-issuer 和 captcha-provider 服务

## 总耗时预估

约 60s。
