# 账户认证 + 设备授权完整链路

## 目标

把 identity/onboarding(账户 onboarding)+ identity/multi-device(多设备)+ session grant 串起来:用户通过 OIDC 完成账户认证;coauth 颁 `ck.session.grant`(短期);新设备加入需要现有设备签发 `ck.device.authorize`;session 过期后通过 refresh 拿新 grant。

## Spec 锚点

- `identity/account-lifecycle.md` §2 — Service account binding
- `identity/account-lifecycle.md` §3 — Account states(active / soft_logged_out / locked / suspended)
- `identity/key-management.md` §6 — Session grant 流程
- `crypto-media/device-lifecycle.md` §2-§3 — Device pairing + 注册路径
- `crypto-media/device-lifecycle.md` §10 — Device-bound session grant

## 拓扑

- 1 × soland + 1 × coauth + 1 × mock IdP

## Actors

| 名字 | 角色 |
|---|---|
| alice | 主用户;Phase A 通过 mock IdP 注册;Phase B 加新设备;Phase C session refresh |

## Steps

### Phase A — OIDC 注册 + 首 session grant

1. alice 在 device-1 `/onboarding`,选 "Sign in with OIDC"
2. 重定向 mock IdP → 自动返回 ID token
3. coauth OIDC bridge 校验 → 创建/绑定 DID → 颁 `ck.session.grant`(TTL 30 分钟)
4. yougen 拿 `{ did, session_token, refresh_token, control_space_id }`
5. 断言:`/_soland/self/account/me` 返回 alice.did

### Phase B — Device 2 via 设备授权链

6. alice device-2 进 `/onboarding`,选 "Add to existing account"
7. device-2 生成本地 device key,渲染 QR(spec §2.1)
8. device-1 扫码 → 签 `ck.device.authorize` 把 device-2 加入
9. coauth 给 device-2 颁专属 session grant
10. 断言:device-2 能调 `/_soland/self/account/me`,返回相同 DID
11. 断言:device-1 / device-2 在 `/settings/devices` 互见

### Phase C — Session refresh

12. 测试 harness 把 device-1 session_token 标过期(后端用 `Authorization: Bearer <expired>` → 401)
13. yougen 客户端捕捉 401 → 自动 `POST /_cokret/gate/auth/refresh` 用 refresh_token
14. coauth 校验 refresh_token → 颁新 session grant
15. 断言:device-1 重新可用,不需要 re-OIDC

### Phase D — Soft logout

16. alice 在 device-1 点 "Log out"
17. session_token 立刻 revoke;refresh_token 保留(soft logout, spec §3)
18. 断言:device-1 调 `/_soland/self/account/me` 返 401
19. alice 再 OIDC 一次或用 refresh_token 重新 login → 拿新 session
20. 断言:account state 仍是 `active`(soft logout 不变状态机)

## Edge cases

- **E4.1 mock IdP 拒签**:IdP 返回 invalid ID token → coauth 拒,UI 显示 "Sign-in failed"
- **E4.2 expired refresh_token**:refresh_token 也过期 → 强制重新 OIDC
- **E4.3 revoked grant**:alice 在另一设备 revoke 当前 grant → device-1 后续请求被拒
- **E4.4 hardware revocation**:device-1 hardware token 被 revoke(spec §5.2)→ 所有 grants 失效

## Implementation notes

- **coauth 缺口**:OIDC bridge 实现度未知;`/_cokret/gate/auth/refresh` 路由可能未实现;session_grant 短 TTL 机制需要验证
- **harness 缺口**:mock IdP 必须新增(本会话 harness 改动)
- **yougen 缺口**:OIDC 重定向流;自动 401 refresh interceptor

## 总耗时预估

约 60s。
