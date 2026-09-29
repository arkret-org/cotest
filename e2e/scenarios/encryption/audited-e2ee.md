# S25 — E2EE 内容的普通举报与“无审计释放”边界

## 目标

验证对 MLS 加密内容的普通治理举报只进入目标 scope 的 moderation workflow：

- Realm 仅因已接受的 `ak.mls.genesis` 而成为 E2EE scope；成员加入后由 Add Commit 覆盖 key-access revision，
  发送方用真实 MLS 状态加密消息；
- `POST /_arkret/self/moderation/report` 只接收举报人自签的 `ak.self.moderation.report` Event；
- 举报不释放任何密钥、不授予特权读取，因此不派生 `ak.audit.accessed`。v1 不存在把 MLS 历史密钥
  release 给审计方的协议流程。

## 规范映射

- `governance/content-moderation.md` §3.1 — 举报请求 `{report_event}`、`routed_to` 对普通 reporter 省略
- `governance/content-moderation.md` §3.3、§3.4、§3.4.1 — scoped moderation 路由、E2EE evidence/franking 可选、
  不存在治理密钥释放
- `crypto-media/encryption-and-audit.md` §2.4.1、§2.5.2、§2.6、§2.6.1 — membership 推进 key-access revision、
  send gate、KeyPackage claim、Welcome producer proof
- `authz/capabilities.md` §5.5 — audit action 只为已可见材料的特权读取留痕，协议不提供密钥 release 动作

## Actors

| Actor | 角色 |
|---|---|
| alice | Realm owner / scoped administrator / MLS group 创建者 |
| bob | E2EE 消息发送者 |
| reporter | 可见目标消息的普通 Realm 成员 |

## 主流程

1. alice 创建 Realm（`history_access=since_join`），邀请前以自己已授权设备 key 作 LeafNode 提交
   `ak.mls.genesis`（`createRealmApi` 的 `mls_activated`）。
2. bob 与 reporter 接受邀请；两次加入各推进一次 key-access revision。alice 授予 bob `ak.message.create`，
   创建 discussion Strand。
3. reporter、bob 依次发布设备签名的 KeyPackage；alice 以设备签名的 self claim 取得 KeyPackage，提交覆盖当前
   revision 的 inline Add Commit 与 producer-signed Welcome。bob 最后加入，因此从自己 recipient queue 读取
   Welcome、验证 producer proof 后直接处于 current epoch。
4. bob 用 SDK MLS 状态加密消息，以 current epoch 与 `group_state_ref` 提交 `ak.message.create`。
5. reporter 对该消息调用 `POST /_arkret/self/moderation/report`，不携带 franking proof（普通 reporter 只能看到
   不可验签的最小化投影，§3.4）。
6. 响应为 `{report_id,status:"submitted"}`，不含 `routed_to`。
7. reporter 从部署本地审计查询面看到自己的 `ak.self.moderation.report` 留痕。
8. 该 Realm 的审计查询中不存在 `ak.audit.accessed`。

所有 MLS 状态由 SDK 经 `cotest-wire` 的 `mls-*` 命令产生（`crates/test-support/src/mls_wire.rs`），
TS 夹具只在步骤间搬运不透明状态（`helpers/soland-api/mls.ts`）。

## 明确不覆盖

franking proof 的授权验证路径（需要 exact scope 治理 capability）与 evidence package 加密不在本场景内。

## 预算

约 45 秒。
