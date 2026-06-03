# 可插拔策略决策服务(policy server check)

## 目标

验证 realm 声明的可插拔 policy server endpoint 在每次 cap-gated 操作前被 soland 调用,决策(allow / deny)生效,obligation 被执行,审计 transcript 可验签;并覆盖超时 fail-closed、多 source 优先级、cache_ttl 幂等三类边界。

不验证:capability grant/delegate/revoke 全链路(见 authz/capability-chain)、邀请的成员侧 UI(见 messaging/triad-collaboration)、policy DSL 本身的语义(见 authz/policy-language)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/authz/policy-server.md` §2 — Realm `ck.realm.policy_server` Move 形状与 endpoint 字段
- `cokret-spec/spec/v1/zh/authz/policy-server.md` §3 — `POST /_cokret/self/policy/check` request / response 契约,`{decision, reason, obligations[]}`
- `cokret-spec/spec/v1/zh/authz/policy-server.md` §4 — obligation kinds (`log_event`、`require_step_up`、`mask_field`...) 与 fail-closed 默认
- (附属) `cokret-spec/spec/v1/zh/authz/capabilities.md` §3 — 一次 cap-gated 操作的入口点(grant + policy_server 串行检查)

## 拓扑

- 1 × soland (principal server) — 假设监听 `http://127.0.0.1:<soland_port>`
- 1 × coauth (auth server) — 假设监听 `http://127.0.0.1:<coauth_port>`
- 1 × mock-policy-server (out-of-tree node mjs) — 通过 `process.env.MOCK_POLICY_SERVER_PORT` 暴露
  - `POST /_cokret/self/policy/check` — 决策入口
  - `POST /scenarios` — 注入规则(切 decision / obligations / 注入 delay)
  - `GET /inspect` — 返回 `{kinds, checks[], signed_transcript}`,测试侧用于断言

(soland + coauth 由 cotest 现有 harness 拉起;mock policy server 由并行任务的 `mock-policy-server.mjs` 提供,本测试假设它已经在跑。)

## Actors

| 名字 | DID | 角色 | 注册时机 |
|---|---|---|---|
| alice | `did:web:alice-s30-<uuid>.example` | realm admin,创建并配置 policy server endpoint | 测试开始前 |
| bob | `did:web:bob-s30-<uuid>.example` | target user,被 policy check 限制的对象 | 测试开始前 |
| policy_server | — | mock,通过 `MOCK_POLICY_SERVER_PORT` 访问;不是 DID actor,但作为外部依赖在 trace 中出现 | 测试启动前已运行 |

## Pre-conditions

- alice 和 bob 都通过 `POST /_cokret/self/account/register` 注册过(与现有 `ensureRegistered` 行为一致)
- alice 和 bob 都持有有效 dev session token(`POST /_cokret/gate/auth/dev-login`)
- alice 拥有 realm-admin capability(由 cotest harness boot 时种入)
- `process.env.MOCK_POLICY_SERVER_PORT` 已设置,且 `GET http://127.0.0.1:${MOCK_POLICY_SERVER_PORT}/inspect` 返回 200

## Steps

### Phase A — Realm 声明 policy server endpoint

1. **alice** 通过 `POST /_cokret/self/realm/state` 提交一条 `ck.realm.policy_server` Move:
   ```json
   {
     "kind": "ck.realm.policy_server",
     "endpoint": "http://127.0.0.1:${MOCK_POLICY_SERVER_PORT}/_cokret/self/policy/check",
     "fail_mode": "closed",
     "cache_ttl_ms": 5000
   }
   ```
2. 断言:realm state event 落库,`GET /_cokret/self/realm/state` 返回的 `policy_server.endpoint` 等于 mock URL
3. 调 `GET ${MOCK_POLICY_SERVER_PORT}/inspect`,记录此时 `checks.length`(后续比较增量)

### Phase B — 默认 allow:invite 触发 /policy/check

4. 通过 `POST ${MOCK_POLICY_SERVER_PORT}/scenarios` 注入规则:`{ default: { decision: "allow" } }`
5. **alice** 通过 yougen `/space/${spaceId}/admin` 邀请 **bob**(invite-member → send-invite-button)
6. soland 在执行 `ck.invite.create` 之前 `POST` mock 的 `/policy/check`,携带:
   - `actor = alice.did`
   - `action = "ck.invite.create"`
   - `resource = { kind: "space", space_id, target: bob.did }`
   - `context = { realm_id, request_id, signed: true }`
7. mock 返回 `{ decision: "allow", reason: "default_allow", obligations: [] }`
8. 邀请成功;断言 `space-admin-panel` 状态文本含 `invited ${bob.did}`
9. 调 `${MOCK_POLICY_SERVER_PORT}/inspect`,断言 `checks` 新增一条,`action = "ck.invite.create"`

### Phase C — 切换 deny:同样的邀请被拒,UI 显示 reason

10. 通过 `POST ${MOCK_POLICY_SERVER_PORT}/scenarios` 注入:
    ```json
    { "match": { "action": "ck.invite.create", "target": "${bob.did}" },
      "decision": "deny",
      "reason": "external_policy_blocks_user" }
    ```
11. **alice** 再次走 invite-member → send-invite-button(同样邀请 bob)
12. soland 调 mock,得到 `{ decision: "deny", reason: "external_policy_blocks_user", obligations: [] }`
13. soland 拒绝写入,返回 HTTP `412`,body `{ errcode: "policy_denied", reason: "external_policy_blocks_user" }`
14. 断言:yougen 在 `space-admin-panel` 渲染错误文本含 `external_policy_blocks_user`(或 testid `invite-error`)
15. `${MOCK_POLICY_SERVER_PORT}/inspect.checks` 再增一条

### Phase D — deny + obligation:soland 执行 obligation

16. 通过 `POST ${MOCK_POLICY_SERVER_PORT}/scenarios` 注入:
    ```json
    { "match": { "action": "ck.invite.create" },
      "decision": "deny",
      "reason": "external_policy_blocks_user",
      "obligations": [{ "kind": "log_event", "target": "audit_log",
                         "fields": { "category": "policy_block", "severity": "info" } }] }
    ```
17. **alice** 再次邀请(同 bob 或一个新 user 都行)
18. soland 收到 deny + obligation,**先**执行 obligation(写一条 `kind = policy.deny` 的 audit log,target_action = `ck.invite.create`),**再**返回 `412`
19. 断言:
    - `GET /_cokret/self/audit/events?actor=${alice.did}&action=policy.deny` 返回至少一条 entry
    - 该 entry 的 `target.category = "policy_block"`、`target.severity = "info"`、`target.upstream_reason = "external_policy_blocks_user"`
20. `${MOCK_POLICY_SERVER_PORT}/inspect.checks` 中本次 request 的 `obligations_executed = true`

### Phase E — Transcript 可验证

21. 调 `${MOCK_POLICY_SERVER_PORT}/inspect`,取 `signed_transcript`(一段 mock-policy-server 用私钥签名的、本测试期间所有 check 的有序记录)
22. 断言 transcript 的 `kinds` 至少包含本次测试用到的两类 (`ck.invite.create` 的 allow + deny);其 ed25519 签名通过 mock 公开的公钥验证成功
23. 断言每条 transcript entry 含 `request_id`、`action`、`actor`、`decision`、`occurred_at` 五字段非空

## Observable assertions (合并清单)

- Phase A:realm state 中 `policy_server.endpoint` 等于 mock URL,`fail_mode = "closed"`
- Phase B 步骤 8-9:allow 决策下邀请成功,mock 收到一条 `action = ck.invite.create` 的 check
- Phase C 步骤 13-14:deny 决策下 HTTP 412,errcode `policy_denied`,yougen 渲染 reason
- Phase D 步骤 19-20:obligation `log_event` 写入 audit log,且 mock inspect 标记 obligations_executed=true
- Phase E 步骤 22-23:signed_transcript 包含本次测试所有 check;签名验证成功;每条 entry 五字段齐全

## Edge cases / sub-tests

- **E3.1 policy server 超时 fail-closed**:通过 `POST ${MOCK_POLICY_SERVER_PORT}/scenarios` 注入 `{ delay_ms: 9000 }`(超过 soland 的 policy check timeout,假设默认 2s);soland 应 fail-closed(`decision = deny`,reason `policy_timeout`),邀请被拒;`/inspect.checks` 可能为空(请求未到 mock)或带 partial 标记
- **E3.2 多个 policy_source 优先级**:在 realm `ck.realm.policy_server` 之上,再给 alice 当 owner 的 org 设一条 `ck.org.policy_server`(指向同一 mock 的不同 path,如 `/_cokret/self/policy/check?source=org`);mock 让 org 路径 deny、realm 路径 allow;期望最终决策是 deny(spec §3.2 — org override realm,more specific wins)
- **E3.3 cache_ttl 幂等**:cache_ttl_ms = 5000 时,在 5 秒内对**同一** `{actor, action, resource}` 触发两次同样的操作(例如 bob 连续两次试图发 `ck.message.create`),soland 只调一次 mock;`/inspect.checks` 在第二次操作后 length 不变(或新增的那条带 `from_cache = true` 标记,取决于 mock 实现)

(E3.1/E3.2/E3.3 各自独立 `test()`,主流程的主 `test.fixme` 覆盖 A→E。)

## Implementation notes

- **soland 缺口**:`ck.realm.policy_server` state event kind 暂未实现;`POST /_cokret/self/policy/check` outbound call 在 cap-gated 路径上未挂;obligation executor (写 audit log + step-up + mask field 三个 kind);cache_ttl 缓存层;fail_mode=closed 兜底分支。统一在 soland `_todos.md` 的 "policy-server integration" backlog。
- **coauth 缺口**:无;policy server 走 soland → external HTTP,coauth 不参与。
- **yougen 缺口**:邀请失败时的 error 渲染 testid (`invite-error`) 可能需要补;policy reason 文本展示。
- **mock 缺口**:并行任务的 `mock-policy-server.mjs` 必须支持 `POST /scenarios`(规则注入)、`GET /inspect`(checks + signed_transcript)、ed25519 签名 transcript;这是本测试的硬依赖,本 spec 不重复指定,但任何字段不一致都会让本测试 fail。
- 每个 `test()` body 内统一在 `try { ... } finally { await Promise.allSettled([...close()]); }` 包起来,与现有 `tests/discovery/notifications.spec.ts` 风格一致。
- alice 用 `JointUserPage.createSpace` + `JointUserPage.gotoSpaceAdmin` 驱动 invite 流;policy 注入用 `request.post(${MOCK_POLICY_SERVER_PORT}/scenarios)` 直接调 mock。
- `MOCK_POLICY_SERVER_PORT` 在 helpers/env.ts 暂未导出,本测试目前直接读 `process.env.MOCK_POLICY_SERVER_PORT`;后续若稳定可提到 `helpers/env.ts` 的 `mockPolicyServerBaseUrl()`。

## 总耗时预估

单次跑约 45-75s(单 browser context,5 phase,3 个 edge case 各一个 sub-test)。
