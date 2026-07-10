# 跨成员加密看板(另一成员解开他人加密卡片内容)

## 目标

验证 **另一个成员**(非创建者、非同账号第二设备)加入 `encryption_profile=mls_rfc9420` 的 Realm 后,能真正**解密**看板卡片的私有内容(`body`/description),而不仅仅是看到明文容器 metadata(title)。这是历史上复发最多、却唯独没有 e2e 覆盖的主链。

对照现状(都不覆盖本场景):

- `kanban/end-to-end.spec.ts` —— 只测**创建者设备本机**加密内容往返。
- `encryption/mls-group.spec.ts` "joined member decrypts E2EE timeline" —— 另一成员解密,但只测**聊天消息**,不测看板卡片。
- `encryption/mls-group.spec.ts` "fresh device ... refuses" —— **同账号第二设备**,且断言的是**拒绝写入**,不是成功解密。

不验证:密钥备份/恢复(encryption/key-backup)、加密附件、加入前历史共享(单列)、跨服务器 MLS 联邦。

## Spec 锚点

- `crypto-media/encryption-and-audit.md` §2.2-§2.4 —— Welcome/Commit、application envelope、sync+epoch
- `models/realm-and-space.md` §2.2 —— Realm `encryption_profile`
- `models/realm-and-space.md` §3.7.2 —— E2EE Realm
- `models/strand-and-message.md` §2-§3 —— Strand 私有 `body` 内容路径

## 拓扑

- 1 × soland + 1 × coauth(设备授权 KeyPackage 需要真 DPoP session-grant)

## Actors

| 名字 | 角色 |
|---|---|
| alice | Realm owner + MLS group creator,写加密卡片 |
| bob | 第二个 member,加入后**解密** alice 的卡片私有内容 |

## Pre-conditions

- 两人各持真 coauth DPoP session-grant(device-authorized KeyPackage 的前提)
- **本场景是 crown-jewel 跨成员路径**:coauth 起来时(`COTEST_REQUIRE_JOINT_STACK=1`)缺 session 必须 **fail-loud**,不得静默 `test.skip` 造假绿

## Steps

**顺序关键:内容必须在 bob 加入后创建。** 否则加入前内容对 bob 既被 history_visibility=joined 裁剪、又因 MLS 前向保密(bob 无该 epoch 密钥)解不开——皆为正确行为,不是本场景要验的协作路径。

1. alice 建**空** `encryption_profile=mls_rfc9420` 的 Realm。
2. alice 邀请 bob;断言邀请状态含 `MLS Welcome queued`(KeyPackage 被 claim)。
3. bob accept **加入**(此后内容才是 bob 可合法见+可解密的加入后内容)。
4. alice **加入后**建 board + list + card(title 明文)+ 给 card 加**加密 description**(私有 `body`);断言 `ak.strand.update` 被接受且 description **不以明文出现在 wire**。
5. **跨成员投递闸门**:以 bob 身份查 `/_arkret/self/events?realms=` 必含 board space id(隔离 soland 投递 vs inkson 投影)。
6. bob 深链进 `/kanban/{realm}/board/{boardId}`;bootstrap **backfill realm 事件并 ingest 进 raw_operations**→board Space 投影进 switcher→路由/auto-select 选中→列表卡片渲染。
7. **核心断言**:bob 打开卡片,`card-description-panel` 含 alice 的明文 description,且 `card-detail-body-locked` 计数为 0(真解密,非锁态)。
8. **假绿护栏**:目标卡不得渲染成 `kanban-card-redacted`(解密/水化失败占位)。
9. **reload 存活**:bob 刷新后卡片与解密正文仍在(防"闪现即消失"= live refresh 覆盖 bootstrap backfill)。
10. **反向投影**:bob 建自己的卡,alice 刷新后能看到(admission fork 历史上双向都断)。
11. **原始 wire**:alice 拉 `/_arkret/self/events` 原始事件,description 永不以明文出现。

## 关键前置(harness/产品修复,均为让本场景真正跑通)

- coauth debug seam 用**模型 B** 铸出的 `did:webvh:…:webvh:` principal DID 当 grant subject 并返回(designate `CokretDeviceEnrollmentAuthority`);harness 采用它当 `user.did`。
- session setup 显式 device-enroll(coauth `/device-enroll`→提交 `ak.device.authorize`)让设备可发 MLS KeyPackage。
- invitee 读加密内容前弹"Set up 24-word Recovery Key"必答模态,测试自动完成。
- inkson kanban bootstrap:backfill 在 board-View 门之前跑,并把事件 ingest 进 `raw_operations`(跨成员 board/card 投影的真修)。

## 关键 testid

- 板选择/深链:`/kanban/{realm}/board/{boardId}`(boardId 从建板后 URL `/board/ak:space:` 抽取)
- 卡片:`kanban-card`(真卡)vs `kanban-card-redacted`(失败占位)
- 解密证据:`card-description-panel`(明文正文) + `card-detail-body-locked`(锁态,须 count=0)

## 已知会红即为抓到真 bug 的类别

`invitee 见 0 卡`、`对方 board 闪现即消失`、`card 卡 Restoring`、`body locked 解不开`、`MLS policy_root 漂移`、`加入前历史`。本 spec 任一断言变红,基本就命中其中之一——这正是它存在的意义。
