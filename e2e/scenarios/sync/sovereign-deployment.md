# 主权部署 + 隔离协作 Enclave

## 目标

验证组织独立运行一套主权 Cokret 网络的完整链路:`soland_main` 配置严格的 DID resolver 信任根、独立部署的 `soland_enclave` 作为「受控外部协作 Realm (enclave)」的承载节点;内部成员 `alice_internal` 在主域日常工作,外部用户 `bob_external` 仅能通过 enclave Realm 加入与内部协作,且**无法 escape 主域**(看不到主域私密资源、directory 搜索被截断);enclave 内的会话、文件、消息均落 enclave 节点,审计日志记录 bob 的全部访问范围;`soland_main ↔ soland_enclave` 出现网络中断时 enclave 走 store-and-forward 而非离线模式,链路恢复后状态收敛。

不验证:跨 realm 的 federation 协议本身(见 federation/cross-server)、E2EE 密钥分发(见 crypto/key-distribution)、DID 注册撤销(见 identity/did-revocation)、enclave 内部的冲突修复细节(见 sync/offline-conflict)。

## Spec 锚点

- `cokret-spec/spec/v1/zh/sync/sovereign-deployment.md` §2 — Sovereign client + 信任根概念
- `cokret-spec/spec/v1/zh/sync/sovereign-deployment.md` §3 — DID resolver policy (内部 method 信任白名单)
- `cokret-spec/spec/v1/zh/sync/sovereign-deployment.md` §4 — Controlled collaboration Realm / enclave 部署
- `cokret-spec/spec/v1/zh/sync/sovereign-deployment.md` §5 — Enclave 边界(外部成员无法访问主域资源)
- `cokret-spec/spec/v1/zh/sync/sovereign-deployment.md` §6 — Network outage / store-and-forward 行为 + 审计

## 拓扑

- 1 × `soland_main` (主权主节点) — 假设监听 `http://127.0.0.1:<soland_main_port>`
- 1 × `soland_enclave` (隔离 enclave 节点) — 假设监听 `http://127.0.0.1:<soland_enclave_port>`,只承载 enclave Realm,不承载主域 Realm / directory
- 1 × `coauth` (auth server) — 主域和 enclave 都信任同一个 coauth,但 DID resolver policy 分别配置
- `soland_main` ↔ `soland_enclave` 之间通过 federation pull/push 同步 enclave Realm 的事件流

(目前 cotest harness 只起单 soland;本 scenario 需要扩 `scripts/run-joint-e2e.ps1` 支持双 soland,或挂 TODO 由现有 harness 用同一 soland 的两个 Realm 模拟边界 — 见 Implementation notes。)

## Actors

| 名字 | DID | 角色 | 落地节点 |
|---|---|---|---|
| alice_internal | `did:web:alice-int-<uuid>.example` (内部 DID method) | 内部组织成员;主域 owner;创建 enclave Realm | `soland_main` |
| bob_external | `did:web:bob-ext-<uuid>.example.org` (外部 org DID method) | 外部协作者;只能通过 enclave 接入 | `soland_enclave` |

## Pre-conditions

- `soland_main` 启动时加载 DID resolver policy:仅信任 `did:web:*.example`(内部 method)作为 root principal,外部 DID 只能通过 enclave 间接绑定
- `soland_enclave` 启动时向 `soland_main` 完成可信注册(双向 trust handshake — 例如 `POST /_soland/admin/deployment/register-enclave`),并被打上 `deployment_profile = "enclave"`
- 两个 DID 都通过各自所属节点的 `POST /_soland/self/account/register` 注册;`bob_external` 的 DID 在 enclave 节点验证通过 enclave 的 trust chain(不走主域 resolver)
- 两个 actor 都持有有效 dev session token,但 token issuer 不同:alice 的 issuer = `soland_main`,bob 的 issuer = `soland_enclave`
- 两个 browser context 通过 `yougen.config.v1` localStorage 分别注入各自 server_url

## Steps

### Phase A — 主权部署启动 + DID resolver policy

1. 测试 harness 启动 `soland_main`,在 config 注入 `did_resolver.trust_roots = ["did:web:*.example"]`、`did_resolver.allow_external_via_enclave = true`
2. 启动 `soland_enclave`,config 注入 `deployment_profile = "enclave"`、`upstream_main = "<soland_main_url>"`、`did_resolver.trust_roots = ["did:web:*.example", "did:web:*.example.org"]`(enclave 的信任根更宽)
3. 断言:`GET <soland_main>/_soland/admin/deployment/info` 返回 `profile = "sovereign_main"`、`trusted_enclaves` 包含 `soland_enclave` 的 server_id
4. 断言:`GET <soland_enclave>/_soland/admin/deployment/info` 返回 `profile = "enclave"`、`upstream_main` 字段正确
5. 测试 harness 尝试用一个 `did:web:rogue-<uuid>.evil` DID 直接 register 到 `soland_main` → 拒绝,reason `did_method_not_trusted`

### Phase B — 创建 controlled collaboration Realm `E`

6. **alice_internal** 通过 `/setup` 多步向导建 Realm `R_internal`(主域私密 realm,作为后续边界验证用);记录 `internalRealmId`
   - title = `"sovereign internal ${stamp}"`,discoverability = `unlisted`,join_rule = `invite`
7. **alice_internal** 调 `POST <soland_main>/_soland/admin/deployment/realm.create` 创建 enclave Realm:
   - `realm_id = "E"`
   - `ck.realm.deployment_profile = "enclave"`
   - `ck.realm.hosted_on = "<soland_enclave server_id>"`
   - `ck.realm.external_invite_policy = "allowed"`
8. 断言:`soland_main` 返回 enclave Realm 的 `realm_id`;`soland_enclave` 上 `GET /_cokret/self/realm/E` 200,profile=enclave
9. **alice_internal** 在 enclave Realm `E` 中通过 yougen 建 space `S_enclave`(session 切到 enclave 节点上下文),记录 `enclaveSpaceId`

### Phase C — 外部用户加入 enclave

10. **alice_internal** 通过 `POST <soland_main>/_soland/admin/deployment/external-invite` 给 `bob_external` 发邀请,绑定到 enclave Realm `E`
    - 返回 `invite_token`,带 `target_realm = "E"`、`target_host = <soland_enclave>`
11. **bob_external** 用 `invite_token` 调 `POST <soland_enclave>/_soland/self/account/accept-external-invite` → enclave 节点验证 bob 的 DID 通过 enclave 的 trust chain(不走 main 的 resolver),创建 enclave 内 session
12. **bob_external** yougen browser context 配置 `server_url = <soland_enclave>`,加载后进入 `S_enclave`
13. 断言:`bob_external` 的 session metadata 显式标 `realm = "E"`、`bound_node = soland_enclave`;在 `GET <soland_main>/_cokret/self/account/<bob.did>` 返回 404 或 `external_via_enclave` 标志(bob 不是 main 的 first-class 账户)

### Phase D — Enclave 内协作

14. **alice_internal** 在 `S_enclave` 发消息 `M1 = "internal hello ${stamp}"`
15. **bob_external** 同步,timeline 包含 `M1`
16. **bob_external** 回复 `M1` 发 `M2 = "external reply ${stamp}"`,并上传一份文件 `F1`(走 enclave 节点的 blob endpoint)
17. **alice_internal** 同步,timeline 包含 `M2`、`F1` 可下载;文件 blob URL 指向 `soland_enclave`(不是 main)
18. 断言:`GET <soland_enclave>/_cokret/self/account/subscribe?catchup=true` 返回的 frontier/cursor 在 alice/bob 两侧一致

### Phase E — Enclave 边界验证

19. **bob_external** 尝试访问主域资源:
    - `GET <soland_main>/_cokret/self/realms/<internalRealmId>` → 401/403,reason `external_user_no_main_access`
    - 在 yougen UI 通过 directory 搜索 `S_internal` 的 title → 结果为空(directory 对外部 enclave 用户裁剪)
    - 尝试 `GET <soland_main>/_cokret/find/directory/spaces?q=internal` → 返回空集或 403
20. **alice_internal** 检查 `S_internal`(主域私密 realm)的成员列表 — bob 不存在;directory 也不会向 enclave 暴露 `S_internal`
21. 断言:bob 试图通过 enclave 节点 hop 到 main(`POST <soland_enclave>/_soland/self/deployment/enclave-proxy { target: <soland_main>, path: "/_cokret/self/realms/..." }` 或类似)→ 拒,reason `enclave_no_upstream_proxy_for_external`

### Phase F — Exit + audit

22. **bob_external** 主动离开 enclave Realm `E`(`POST <soland_enclave>/_cokret/self/realm/E/leave`)或被 alice 移除
23. 断言:bob 的 enclave session 失效,后续任何 enclave API 调用 401
24. **alice_internal** 调 `GET <soland_main>/_soland/admin/deployment/audit?subject=<bob.did>` 获取审计日志
25. 断言:审计日志至少包含:
    - bob 接受邀请的事件(Phase C 步骤 11)
    - bob 在 enclave 内的访问范围(Phase D 中可见的 space 列表 = `[S_enclave]`)
    - bob 下载/上传的文件清单(包含 `F1`)
    - bob 发送的消息 ID 列表(包含 `M2`)
    - 边界拒绝事件(Phase E 步骤 19/21 的拒绝记录)
    - bob 离开的事件(步骤 22)

## Observable assertions (合并清单)

- 步骤 3-4:两个节点的 `deployment.info` 各自报告正确 profile + 双向 trust
- 步骤 5:rogue DID register 主域被拒,reason `did_method_not_trusted`
- 步骤 8-9:enclave Realm `E` 同时在 main 注册 + 在 enclave 上承载
- 步骤 11:bob 通过 enclave trust chain 验证,而非 main 的 trust chain
- 步骤 13:bob 在 main 上不是 first-class 账户
- 步骤 17:enclave 内 alice/bob 互见;文件 blob 落 enclave 节点
- 步骤 19:bob 访问 main 资源全部被拒
- 步骤 20:directory 对 enclave 用户裁剪
- 步骤 21:bob 通过 enclave proxy 也无法到 main
- 步骤 25:审计日志覆盖 bob 的全部活动 + 边界拒绝

## Edge cases / sub-tests

- **E7.1 escape attempt rejected**:bob 通过各种 vector 尝试 escape 主域:
  - directory 搜索 main domain space → 返回空 / 403
  - 直接调 `GET <soland_main>/_cokret/self/realms/<internalRealmId>` → 403,reason `external_user_no_main_access`
  - 通过 enclave proxy 间接到 main → 拒,reason `enclave_no_upstream_proxy_for_external`
  - 在 enclave space 的 mention 中 `@<alice 在主域的 DID>` → 允许 mention(因为 alice 在 enclave 也是成员),但**不能**通过 mention metadata 拿到 alice 在主域其他 space 的成员关系
- **E7.2 network outage**:`soland_main ↔ soland_enclave` 链路中断(harness 用 `route.fulfill` 拦掉 federation endpoint):
  - bob 在 enclave 内继续发消息、上传文件 → 应该**成功**(不像 offline 模式 outbox 那样 pending);enclave 节点本地接受并写入
  - alice 在主域查 enclave Realm 的最新 frontier → 滞后,但**不报错**,UI 显示 "enclave sync lag" 标记
  - 链路恢复后,main 拉 federation pull,enclave 的 store-and-forward 队列推送过去,alice 看到 bob 离线期间的所有消息
  - 关键区别(对比 offline-conflict.md 的 E26.*):store-and-forward 是**节点间**而非客户端 outbox;bob 这边**不**看到 "pending sync" UI
- **E7.3 enclave DID resolver policy**:bob 的 DID 必须通过 **enclave** 的 trust chain 验证:
  - 一个属于 enclave trust roots 但**不**属于 main trust roots 的 DID(`did:web:bob-ext-<uuid>.example.org`)应能加入 enclave,被 main 上拒绝直接 register
  - 反过来一个 main trust roots 但不在 enclave trust roots 的 DID(假设有这种配置)应在 enclave 加入时被拒,reason `enclave_did_method_not_trusted`
  - bob 试图在 enclave session 内更换 DID document(替换为 `did:web:rogue.evil`)→ enclave 验证失败,session 失效

## Implementation notes

- **soland 已落地**:
  - `/_soland/admin/deployment/configure`、`/_soland/admin/deployment/info`、`/_soland/admin/deployment/register-enclave` 提供本地 sovereign main / enclave profile 与 trust chain handshake。
  - `/_soland/admin/deployment/realm.create`、`/_cokret/self/realm/:id` 记录 enclave Realm 的 `deployment_profile`、`hosted_on`、`external_invite_policy`。
  - `/_soland/admin/deployment/external-invite` + `/_soland/self/account/accept-external-invite` 验证 enclave trust roots;main 侧直接注册外部 DID 返回 `did_method_not_trusted`;enclave 侧 rogue DID 返回 `enclave_did_method_not_trusted`。
  - `/_cokret/self/realms/:id`、`/_cokret/find/directory/spaces`、`/_soland/self/deployment/enclave-proxy` 覆盖 external user 的 main-domain escape rejection 与边界审计。
  - `/_soland/admin/deployment/store-and-forward/*` 覆盖 enclave upstream outage 下本地 accepted、非客户端 pending、恢复后 drain/ingest 收敛。
- **harness 已落地**:`scripts/run-joint-e2e.ps1 -DualSoland` 提供 `soland_main` / `soland_enclave` 两节点;本 scenario 的 4 条 contract test 已全部 live。
- **yougen 后续**:enclave session metadata UI、"enclave sync lag" 标记、directory 裁剪反馈仍可在后续 UI polish 中补;P2-056 当前关闭的是 soland 侧本地开发能力。

## 总耗时预估

实现就绪后单次跑约 90-120s(双 soland 节点启动 + 两个 browser context + 6 阶段 + outage 模拟)。
