# Knock 自动解析路径(`ak.member.state{join, gate_proofs}`)

## 目标

spaces/knock-application 的姊妹篇:`default_join_rule=knock_restricted` 且所有 gates 都 `auto_resolve=true`(claim_required + challenge_response)— applicant 直接提交 `ak.member.state{join}` 携带 `gate_proofs[]`,reducer 内联校验,无需 application + review。这是 spec §3.5 的快路径。

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
2. alice 通过 API 写 `ak:cell:realm.join_policy.v1:<R>`:
   ```json
   {
     "gates": [
       { "gate_id": "g-vc", "kind": "claim_required", "auto_resolve": true, "requires_claims": ["acme:employee"] },
       { "gate_id": "g-captcha", "kind": "challenge_response", "auto_resolve": true, "provider_did": "did:web:captcha.example", "challenge_kinds": ["captcha"], "max_proof_age": "PT5M" }
     ],
     "combinator": "all"
   }
   ```

### Phase B — bob 自动解析 join(happy path)

3. bob 向 claim-issuer 请求 VC `acme:employee` → 拿到 signed VC
4. bob 向 captcha-provider 请求 challenge → 完成 → 拿到 signed proof
5. bob 客户端组 `ak.member.state{ membership: "join", subject_did: bob.did, gate_proofs: [{ gate_id: "g-vc", claim_presentation: <VC> }, { gate_id: "g-captcha", challenge_proof: <proof> }] }`
6. 直接提交,**不**经过 application + review
7. soland reducer:
   - 加载 join policy cell
   - 按 combinator=all 校验 gates
   - 调用 verifier:`g-vc` 的 issuer 签名 OK + claim 匹配;`g-captcha` 的 challenge_proof 在 max_proof_age 内
   - 全过 → 接受 join Move
8. 断言:`/realms/<R>/admin` 成员列表含 bob

### Phase C — mallory 自动解析失败

9. mallory 没有 `acme:employee` VC
10. mallory 试提交同样的 Move 但 `gate_proofs[]` 缺 claim_presentation 或 issuer 签名无效
11. reducer 拒,reason `failed_precondition`,具体 gate fail = `g-vc`
12. 断言:mallory inkson UI 显示 "Missing required credential: acme:employee"

### Phase D — Cooldown gate(独立 deny)

13. alice 把 join policy 加一条 gate:`{ kind: "cooldown", min_interval_since_leave: "P30D" }`
14. bob 主动 leave Realm:`ak.member.state{leave}`
15. 立刻试重新 join:gate_proofs 仍正确,但 cooldown gate 命中
16. 断言:reducer 拒,reason `cooldown_gate_blocking`,独立于 combinator(spec §3.3.1)

## Edge cases

- **E6.2.1 expired claim**:bob 的 VC `expires_at` 过期 → 拒,reason `claim_invalid`
- **E6.2.2 stale challenge proof**:`max_proof_age` 5 分钟,bob 拿 6 分钟前的 proof → 拒,reason `challenge_failed`
- **E6.2.3 wrong combinator**:把 combinator 改 `any` → bob 只需要满足任一个 gate;但 cooldown 仍独立

## Implementation notes

- **soland 缺口**:gate verifier(VC 签名校验 + challenge provider 校验)、`gate_proofs[]` 解析、cooldown 时间 tracking — 几乎全 ✗
- **harness 缺口**:mock claim-issuer 和 captcha-provider 服务

## 总耗时预估

约 60s。
