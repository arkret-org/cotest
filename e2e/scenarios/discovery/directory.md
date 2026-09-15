# Discovery(directory 搜索 / 联系人 / 组织 / profile)

## 目标

完整 discovery 面:directory 搜 spaces / actors / handles / organizations / objects 五轴;联系人请求 + 接受 + 列表;profile 更新(display name / avatar / bio);presence 状态(online/away/offline)。

## Spec 锚点

- `discovery/discovery-directory.md` §1-§3 — Directory service + 公共投影
- `discovery/profiles-presence.md` §2 — Actor profile schema
- `discovery/profiles-presence.md` §3 — Presence
- `models/relation.md` — `contact` 关系
- `identity/identity-handles.md` — Handle 与搜索

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 搜索 + 发起联系 |
| bob | 被搜 + 接受联系;profile 更新 |
| (sub-test)acme-org | 组织 DID,验证 organization 搜索 |

## Steps

### Phase A — alice 搜 bob(空结果)

1. 三人都注册
2. alice 进 `/directory`,选 `tab-actors`
3. 搜 bob.handle → 因为不是 contact 且 directory 默认隐私,显示 "No actors found"

### Phase B — alice 发联系请求

4. alice 在 `/directory` 点 `directory-contact-tools`
5. 填 `contact-target-did-input = bob.did`,点 "Request"
6. inkson 提交 `ak.relation.create { relation_kind: "contact", source: alice.did, target: bob.did, fields: { status: "pending" } }`
7. 断言:contact_state 文本含 `pending`

### Phase C — bob 接受联系

8. bob 进 `/directory`,在 contact tools 区填 `contact-requester-did-input = alice.did`,点 "Accept"
9. inkson 提交 `ak.relation.update`,status = `accepted`
10. 断言:bob 的 contact_state 含 `accepted`
11. bob 点 "List contacts" → 看到 alice.did + count 1

### Phase D — alice 搜 bob(可见)

12. alice 进 `/directory`,搜 bob.handle
13. 断言:`actor-result` 含 bob.did(联系后可见)

### Phase E — bob 更新 profile

14. bob 进 `/settings/profile`,改 display_name、bio、avatar
15. inkson 提交 `ak.profile.update`
16. alice 以共同 joined Realm 和 Bob 的完整 `ActorId` 调用
    `ak.self.actor_profile.read.resolve.v1`（`POST /_arkret/self/actor-profiles/query`），自行校验返回的最新
    signed profile Event 与该 actor 的绑定后看到新 profile；普通 profile Event 没有 covering Seal。
    该链路的独立覆盖见 [`contact-confirmed-display-name.md`](contact-confirmed-display-name.md)
17. 断言:在 directory 搜结果中显示 bob 的新 display_name

### Phase F — Presence

18. bob 关闭 inkson tab(模拟离线)
19. alice 在 directory 看 bob 的状态指示:`presence-offline`
20. bob 重新打开 → 5s 内 alice 看到 `presence-online`

### Phase G — Organization 搜索

(sub-test,若 org 实现)
21. 测试 harness 注册一个 organization DID `did:web:acme.example`
22. alice 搜 "acme" → tab-organizations → 显示 organization 列表
23. 点进去看 organization member list

## Edge cases

- **E24.1 搜索 handle 含特殊字符**:`@bob_2.0` → 编码/解码无误
- **E24.2 reject contact**：alice 请求被 bob 拒绝后，该请求永久终止；重新联系必须生成不同的 request Event 与 acceptance receipt，bob 收到新请求。依据 `identity/contact-and-direct-conversation.md` §3，不复活旧请求。
- **E24.3 隐私级别**:bob 设置 profile.privacy=private → directory 搜空,但联系人可见
- **E24.4 presence 隐私**:bob 关 presence broadcast → 显示 unknown

## Implementation notes

- 多数 testid 已存在(directory.rs:`directory-contact-tools`、`contact-target-did-input`、`request-contact-button`、`accept-contact-button`、`list-contacts-button`、`directory-search-input`、`directory-search-button`、`actor-result`、`tab-actors`)
- **soland 缺口**:`ak.profile.update`、`ak.presence` ephemeral、organization registry — 实现度未知

## 总耗时预估

约 60s。
