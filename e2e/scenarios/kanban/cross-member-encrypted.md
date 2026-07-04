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

1. alice 建 `encryption_profile=mls_rfc9420` 的 Realm;建 board + list + card(title 明文);给 card 加**加密 description**(私有 `body`)。
2. 断言 alice 侧:`ck.strand.update` 被接受,且 description **不以明文出现在 wire**(证明确实加密,非明文 Realm 假绿)。
3. alice 邀请 bob;断言邀请状态含 `MLS Welcome queued`(KeyPackage 被 claim)。
4. bob accept 后深链进 `/kanban/{realm}/board/{boardId}`;client bootstrap 应用 pending Welcome。
5. **核心断言**:bob 打开卡片,`card-description-panel` 含 alice 的明文 description,且 `card-detail-body-locked` 计数为 0(真解密,非锁态)。
6. **假绿护栏**:目标卡不得渲染成 `kanban-card-redacted`(解密/水化失败占位)。
7. **reload 存活**:bob 刷新后卡片与解密正文仍在(防"闪现即消失"= live refresh 覆盖 bootstrap backfill)。
8. **反向投影**:bob 建自己的卡,alice 刷新后能看到(admission fork 历史上双向都断)。
9. **原始 wire**:alice 拉 `/_cokret/self/events` 原始事件,description 永不以明文出现。

## 关键 testid

- 板选择/深链:`/kanban/{realm}/board/{boardId}`(boardId 从建板后 URL `/board/ck:space:` 抽取)
- 卡片:`kanban-card`(真卡)vs `kanban-card-redacted`(失败占位)
- 解密证据:`card-description-panel`(明文正文) + `card-detail-body-locked`(锁态,须 count=0)

## 已知会红即为抓到真 bug 的类别

`invitee 见 0 卡`、`对方 board 闪现即消失`、`card 卡 Restoring`、`body locked 解不开`、`MLS policy_root 漂移`、`加入前历史`。本 spec 任一断言变红,基本就命中其中之一——这正是它存在的意义。
