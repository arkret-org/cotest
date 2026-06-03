# 真实账户注册 (Onboarding)

## 目标

验证用户通过 passkey / OIDC / email 完成完整 onboarding:DID 生成、principal control space 创建、首设备自我授权、cross-signing 公布、首个 session grant 颁发、MLS KeyPackage 上传。**完全脱离 dev-login 短路**,exercises spec `account-lifecycle.md §2.1` 的真实流程。

不验证:多设备配对(见 identity/multi-device)、设备撤销(见 identity/multi-device)、账户恢复(见 identity/recovery)、handle 转移(见 identity/handle)。

## Spec 锚点

- `identity/account-lifecycle.md` §2.1 — 服务账户与 Principal 绑定
- `identity/account-lifecycle.md` §2.1.1 — `cx.account.create` 流程
- `identity/identity-did.md` §2 — DID 主体 + 控制密钥
- `identity/identity-did.md` §3.4 — `did:webvh` genesis entry
- `identity/key-management.md` §5.0 — Inception key + control stream genesis
- `identity/key-management.md` §5.0.1 — 4 步 bootstrap (inception key → did:webvh entry 0 → principal control space → ck.device.authorize)
- `identity/key-management.md` §5.1 — Cross-signing 三对密钥(PSK / SSK / USK)
- `identity/key-management.md` §6 — Session grant
- `crypto-media/device-lifecycle.md` §3 — 注册路径选项
- `crypto-media/device-lifecycle.md` §3.2 — passkey / WebAuthn / OIDC binding

## 拓扑

- 1 × soland (principal server) + 1 × coauth (auth server)
- coauth 必须真的做账户绑定,不能走 dev-login 旁路

## Actors

| 名字 | 注册路径 | DID 形态 | 注释 |
|---|---|---|---|
| alice | passkey/WebAuthn | `did:webvh:<scid>:<host>` | 主路径 |
| bob | OIDC (mock IdP) | `did:webvh:...` | 次路径,验证 OIDC 桥 |
| carol | email-only | `did:webvh:...` | 验证邮件验证流程(若实现) |

## Pre-conditions

- coauth 启动并完成 migration
- WebAuthn (or mock) provider 配置好
- Mock IdP 已注入到 coauth 的 OIDC bridge

## Steps

### Phase A — alice 通过 passkey 注册

1. alice 进 `/onboarding`,选择"Register with passkey"
2. yougen 调用 navigator.credentials.create(),生成 device key + WebAuthn credential
3. yougen `POST /_cokret/self/account/create` 提交 `{ method: "passkey", credential, handle: "@alice-s7" }`
4. soland → coauth 链路:
   - 生成 inception key
   - 写入 `did:webvh` entry 0 (SCID + updateKeys)
   - 创建 principal control space (`purpose="principal_control"`)
   - 写入 `ck.device.authorize` 把第一台设备授权
   - 发布 `cx.cross_signing.publish.v1` (PSK / SSK / USK)
   - coauth 颁发首个 `ck.session.grant` (短期)
5. yougen 收到 `{ did, session_token, control_space_id }`,写入 localStorage

### Phase B — alice 验证 onboarding 落地

6. alice 进 `/settings/account` 应看到:
   - DID 形如 `did:webvh:<scid>:...`
   - 当前设备列表只有这一台(显示 `ck:device:...` + cross-signing fingerprint)
   - Principal control space ID 已记录(可能不在 UI,但 yougen 客户端状态有)
7. 测试用 alice 的 session_token 调 `GET /_cokret/self/account/me`,断言返回 `did`、`handle`、device 信息一致

### Phase C — alice 的 DID Document 可被外部解析

8. 测试侧 GET `https://<webvh_host>/.well-known/did/webvh/<scid>` (或等价 endpoint) 拿 DID Document
9. 断言:
   - `id` = alice.did
   - `verificationMethod` 含 alice 的 inception key
   - `service.CokretPrincipalServer.serviceEndpoint` = soland 的 base URL
10. 验证 history chain:GET `did.jsonl`,断言至少一个 entry,SCID 一致

### Phase D — bob 通过 OIDC 注册

11. bob 进 `/onboarding`,选择"Sign in with Google"(mock IdP)
12. yougen 重定向 mock IdP,mock 直接返回 ID token
13. coauth OIDC bridge 接住 ID token,绑定到新的 DID
14. 断言 onboarding 完成,bob 拿到 session
15. 断言:bob 的 DID **不同于** alice 的,但 service endpoint 都指向同一个 soland

### Phase E — carol email + 短期 token (3PID 路径)

16. carol 进 `/onboarding`,提交邮箱 `carol@example.com`
17. (mock 邮件服务发出含 verification token 的链接)
18. carol 点链接 → yougen 把 token 提交回 coauth
19. coauth 颁发 binding proof,carol 完成 DID 绑定
20. 断言:onboarding 成功,carol DID 有效

## Observable assertions(合并)

- 三个 actor 的 DID 都形如 `did:webvh:`,SCID 各异
- 每个 DID 都有可解析的 `did.jsonl` history chain
- 三个 actor 的 service endpoint 都指向 soland alpha
- 每个 actor 都有有效 session token,能调 `/_cokret/self/account/me`
- 每个 actor 的 principal control space 已创建,device 列表只有 1 台
- 三个 actor 都已发布 cross-signing 三对密钥

## Edge cases / sub-tests

- **E7.1**:重复用同一 passkey 注册 → coauth 拒绝(`account_already_registered`)
- **E7.2**:OIDC ID token 过期 → 注册失败,UI 显示 token expired
- **E7.3**:email verification 链接已用过 → 拒绝,UI 显示 already consumed
- **E7.4**:WebVH host 不可达(DNS 故障)→ resolver 进入 `degraded_no_witness` 状态(≤24h)([identity-did.md §4.2.1](../../../cokret-spec/spec/v1/zh/identity/identity-did.md))
- **E7.5**:handle conflict (`@alice-s7` 已被占)→ coauth 拒绝 `handle_already_claimed`,客户端要求另选

## Implementation notes

- **soland 缺口**:`cx.profile.principal_control_space.v1` profile、`cx.cross_signing.publish.v1` event、`ck.device.authorize` bootstrap binding — 都是 MUST 但当前 soland 未实现。**整条 scenario 是 fixme territory**,等 control stream 落地。
- **yougen 缺口**:`/onboarding` 真路径不走 dev-login,需要补 passkey / OIDC button、verification 流程。
- **coauth 缺口**:OIDC bridge handler 完整度需要审。
- **harness 缺口**:mock IdP service、mock email service — `scripts/run-joint-e2e.ps1` 需要 `-StartMockIdp` / `-StartMockEmail` 开关。

## 总耗时预估

完整跑约 2-3 分钟(3 actors × 注册 + verification 等待 + WebVH publish 延迟)。
