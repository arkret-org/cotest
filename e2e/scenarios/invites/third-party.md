# 第三方邀请(email → token commitment → binding proof → claim)

## 目标

alice 邀请仅持有邮箱的 bob;协议用 token commitment 隐藏明文邮箱;mock 邮件服务投递 invite token;bob 注册后用 `binding_proof` + `subject_proof` 提交 `ck.invite.claim`,reducer 校验后接收为成员。

## Spec 锚点

- `sync/third-party-invites.md` §3 — invite 流程概览
- `sync/third-party-invites.md` §3.1 — `ck.invite.third_party` event(token_commitment、verification_public_key、expires_at)
- `sync/third-party-invites.md` §4 — claim 流程(token、binding_proof、subject_proof)
- `sync/third-party-invites.md` §4.1 — token commitment + binding proof 校验
- `sync/third-party-invites.md` §4.2 — invite 转 invite_create 后正常 accept
- `models/realm-and-space.md` §3.7.2 — E2EE Realm 中 invite 后才接 MLS welcome

## 拓扑

- 1 × soland + 1 × coauth + 1 × mock email/verification service

## Actors

| 名字 | 注册状态 | 角色 |
|---|---|---|
| alice | 已注册 | inviter |
| bob | Phase A 时仅有 email,Phase C 才注册 DID | invitee |

## Steps

### Phase A — alice 发起第三方邀请

1. alice createRealm `R`,`joinRule=invite`
2. alice inkson 点 "Invite by email",输入 `bob@example.com`
3. 客户端:
   - 生成 random `salt` + `token`
   - `token_commitment = sha256(salt || token)`
   - 生成临时 `verification_public_key`
   - 提交 `ck.invite.third_party { realm_id, token_commitment, verification_public_key, expires_at: +7d }`
4. inkson 调 mock email service `POST /mock/email/verification/send` 把 `token` 通过邮件投递给 bob(out-of-band)
5. 断言:`/realms/${realmId}/admin` 显示 `pending third-party invite to bob@example.com` (`pending-3pid-invite-row` testid)
6. 断言:`token_commitment` 在事件链里,**plaintext email 不在事件链**(隐私 invariant)

### Phase B — bob 注册 DID

7. bob 在 mock email 收件箱看到含 invite link 的邮件
8. bob 进 inkson `/onboarding`,通过 passkey/OIDC 注册 → 拿到 `did:webvh:bob`(参见 identity/onboarding)
9. bob 客户端把 invite token 提交给 verification service `POST /mock/email/verification/claim { token, did: bob.did }`
10. service 校验 token 新鲜性 + claim 数 → 原子消费 → 签 `binding_proof` 说"token holder 的 DID 是 bob"

### Phase C — bob 提交 `ck.invite.claim`

11. bob 客户端组 `ck.invite.claim { token_commitment, binding_proof, subject_proof (bob 签) }`
12. 提交到 soland
13. reducer:
    - 匹配 `token_commitment`
    - 校验 `binding_proof` 是 verification service 签的、audience/expiry/nonce 都对
    - 校验 `subject_proof` 是 bob 的 DID key 签的
    - 把 pending invite 转 `ck.invite.create` for bob
14. bob 客户端再提交 `ck.invite.accept` → 加入成员
15. 断言:`/realms/${realmId}/admin` 显示 bob 是 member;old pending row 消失
16. 断言:bob 进 `/timeline/${realmId}` 看得到 alice 的消息(history_visibility 之内)

### Phase D — E2EE Realm 的 MLS welcome

17. 若 `R` 是 E2EE Realm,Phase C 之后 alice 客户端构造 MLS welcome → bob 客户端接受 → 加入 MLS group

## Edge cases

- **E3.1 expired token**:`expires_at` 过期;reducer 拒 claim,reason `invite_expired`
- **E3.2 wrong DID claim**:mallory 截获 token + 用自己的 DID claim → `subject_proof` 签名是 mallory 的,但 `binding_proof` 说 token holder 是 bob;reducer 拒 `binding_mismatch`
- **E3.3 double-claim**:bob 已 claim 后,mallory 再用同 token claim → reducer 拒(token 已消费)
- **E3.4 verification service offline**:mock service 离线;bob 无法拿 binding_proof;UI 显示 "Verification pending"
- **E3.5 invite cancel by alice**:alice 在 bob claim 前撤销 invite → reducer 后续 claim 都拒

## Implementation notes

- **soland 缺口**:`ck.invite.third_party`、`ck.invite.claim` event kinds;binding_proof 校验逻辑 — 整组 ✗
- **harness 缺口**:mock email + verification service 必须新增(见本会话 mock services 改动)
- **inkson 缺口**:Invite-by-email UI、pending 3PID invite 列表、Verification 等待 UI

## 总耗时预估

约 60-90s(含 email 投递 + 模拟等待)。
