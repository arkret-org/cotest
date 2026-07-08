# Account 状态机(active / soft_logged_out / locked / suspended / deactivated)

## 目标

`identity/account-lifecycle.md §3` 5 个 account state 的转换:
- `active → soft_logged_out`(用户点登出;当前 session grant 失效)
- `active → locked`(security 检测;session grant revoke,refresh MAY fail)
- `active → suspended`(governance;新 session grant 拒发)
- `active → deactivated`(用户或 admin;所有 session grant revoke,device revoked)

每个 transition 都要进 audit log,可观察的 effect 要在 client 行为 + API 响应中体现。

## Spec 锚点

- `identity/account-lifecycle.md` §3 — State machine
- `identity/account-lifecycle.md` §3.1-§3.4 — 各状态语义
- `identity/key-management.md` §5.2 — Token revocation cascade

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 主用户,各种状态转换的对象 |
| admin | governance actor(`ck.account.suspend` capability) |

## Steps

### Phase A — Active baseline

1. alice 完成 onboarding(假设 identity/onboarding 已通过),持有 session grant + holder key
2. 断言:`GET /_soland/self/account/me` 返回 `state: "active"`

### Phase B — Soft logout

3. alice inkson 点 "Log out"
4. 客户端:revoke session grant(coauth)、清 localStorage 的 session_credential
5. 断言:`/_soland/self/account/me` with old session credential → 401
6. 断言:account state 仍 `active`(soft_logged_out 是客户端语义;spec 可能也建模为 server state,要查)
7. alice 用旧 grant + DPoP holder proof 走 `/_cokret/gate/account/session-grants/refresh` → 拿新 session grant,回到正常

### Phase C — Lock(安全风险)

8. 模拟:测试 harness 调 admin endpoint `POST /_soland/admin/accounts/<alice.did>/lock { reason: "suspicious_login" }`
9. coauth revoke alice 的所有 session grant;refresh SHOULD fail closed
10. 断言:`/_soland/self/account/me` 返 401 / 403
11. 断言:account state = `locked`(若 spec 暴露)
12. alice 重新 login 触发 lock check → 客户端 UI 显示 "Account locked, contact support"
13. alice 通过 recovery 流程或 admin 解锁后 → state 回 `active`

### Phase D — Suspend(governance)

14. admin 调 `POST /_soland/admin/accounts/<alice.did>/suspend { reason: "abuse", duration: "30d" }`
15. 断言:alice 任何新 session grant request 都拒(refresh fails);老 grant 仍可用直到过期(spec §3 描述)
16. 断言:account state = `suspended`
17. alice 试发消息 → 401(grant 过期后)
18. 30 天后或 admin unsuspend → state 回 `active`

### Phase E — Deactivate(用户或 admin)

19. alice 进 `/settings/account` → "Deactivate my account"
20. 提交 `POST /_soland/self/account/deactivate`(可能需要密码)
21. coauth 把所有 session grant revoke;所有 device 标 `revoked`
22. 断言:`/_soland/self/account/me` 永久 401
23. 断言:account state = `deactivated`
24. alice 的 messages 在 spaces 中仍然可见(deactivated ≠ erasure;PII 保留,active session 没了)

## Edge cases

- **E28.1 session cascade**:lock alice → 她在 device-1 / device-2 都被踢出
- **E28.2 cross-server suspension**:alice 在 α 被 admin suspend → 这个状态如何同步给 β(spec §3 + sync/federation)
- **E28.3 reactivate**:deactivated 是否能恢复?spec 说 deactivated 通常不可逆(除非走 admin 流程)
- **E28.4 audit log**:每次状态转换写 `org.cokret.soland.account.state_change { from, to, actor, reason, timestamp }`(产品私有审计语义,不占用协议 `ck.` 前缀)
- **E28.5 in-flight write 时遇 lock**:alice 正在发消息,触发 lock → 该消息可能落或可能 abort;spec 偏好 abort(safer)

## Implementation notes

- **soland 本地状态**:`/_soland/admin/accounts/<did>/{lock,unlock,suspend,unsuspend,deactivate}`、`/_soland/admin/accounts/<did>/status`、`/_soland/self/account/deactivate`、`/account/me.state` 与 `org.cokret.soland.account.state_change` audit 已覆盖。跨服务器 suspension 同步仍单独由 federation/account-state projection 后续项处理。
- **inkson 缺口**:`/settings/account` 的 deactivate 按钮 + 确认;UI 在 locked 状态下的 fallback 屏

## 总耗时预估

约 90s。
