# 跨成员加密看板(另一成员解开他人加密卡片内容)

## 目标

验证 **另一个成员**(非创建者、非同账号第二设备)加入已接受 MLS Genesis 的 Realm 后,能真正**解密**看板卡片的私有内容(`encrypted_content`/description),并在明确授权后双向编辑、刷新恢复。

对照现状(都不覆盖本场景):

- `kanban/end-to-end.spec.ts` —— 只测**创建者设备本机**加密内容往返。
- `encryption/mls-group.spec.ts` "joined member decrypts E2EE timeline" —— 另一成员解密,但只测**聊天消息**,不测看板卡片。
- `encryption/mls-group.spec.ts` "fresh device ... refuses" —— **同账号第二设备**,且断言的是**拒绝写入**,不是成功解密。

不验证:密钥备份/恢复(encryption/key-backup)、加密附件、加入前历史共享(单列)、跨服务器 MLS 联邦。

## Spec 锚点

- `crypto-media/encryption-and-audit.md` §2.2-§2.4 —— Welcome/Commit、application envelope、sync+epoch
- `models/realm-and-space.md` §2.2 —— accepted Genesis 与 `since_join`
- `models/realm-and-space.md` §3.7.2 —— E2EE Realm
- `models/strand-and-message.md` §2-§3 —— Strand 私有 `body` 内容路径
- `sync/invite-addressing.md` §2 / §5 / §7 —— holder 主动交付的 locator 与默认私有投递策略

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

**顺序关键:内容必须在 bob 加入后创建。** 否则加入前内容对 bob 既被 history_access=since_join 裁剪、又因 MLS 前向保密(bob 无该 epoch 密钥)解不开——皆为正确行为,不是本场景要验的协作路径。

1. alice 建**空** Realm，随后接受 MLS Genesis；history policy 为 `since_join`。
2. bob 先授权 invite consent 并通过标准接口签发 locator；alice 使用该 locator 在界面中邀请 bob。此时 Bob 尚未开启浏览器／发布 KeyPackage，邀请事实必须持久化，状态不得伪称 `MLS Welcome queued`。裸地址在缺省策略下进入 quarantine，不能用放宽默认策略替代引介证据。
3. bob 开启浏览器完成恢复策略与首个加密备份（其 PCR 已有 consent 前驱），发布真实 KeyPackage 后 accept **加入**并收到有效 Welcome。此后内容才是 bob 可合法见+可解密的加入后内容。
4. alice **加入后**建 board + list + card(title 明文)，等待卡片脱离草稿态、取得已确认的 Strand 身份后，再给 card 加**加密 description**(私有 `body`);断言 `ak.strand.update` 被接受且 description **不以明文出现在 wire**。
5. **跨成员投递闸门**:以 bob 身份使用 `POST /_arkret/self/streams/scan` 查询 Realm stream，结果必含 board space id(隔离 soland 投递 vs inkson 投影)。
6. bob 深链进 `/kanban/{realm}/board/{boardId}`;bootstrap **backfill realm 事件并 ingest 进 raw_operations**→board Space 投影进 switcher→路由/auto-select 选中→列表卡片渲染。
7. **核心断言**:bob 打开卡片,`card-description-panel` 含 alice 的明文 description,且 `card-detail-body-locked` 计数为 0(真解密,非锁态)。
8. **假绿护栏**:目标卡不得渲染成 `kanban-card-redacted`(解密/水化失败占位)。
9. **reload 存活**:bob 刷新后卡片与解密正文仍在(防"闪现即消失"= live refresh 覆盖 bootstrap backfill)。
10. alice 通过正式 `ak.capability.grant` 独立授予 bob 卡片创建/放置，以及带 `allowed_write_fields=[content,encrypted_content]` 的 Description 编辑权；membership 不替代写入授权。Bob 修改 Alice 卡片，Alice 解密修改并刷新恢复。
11. **反向解密**:bob 建自己的卡，等待已确认 Strand 身份后写入私密 description；alice 必须看到卡片、实际解密正文并编辑该卡；Bob 刷新后解出 Alice 的修改，本地存储不能泄露正文。
12. **原始 wire**:alice 使用 `POST /_arkret/self/streams/scan` 拉取原始事件，双方 description 及修改正文均不得以明文出现。

## 关键前置(harness/产品修复,均为让本场景真正跑通)

- coauth registration 以 root-anchored PCR genesis 接受的 `did:webvh:…:webvh:` principal DID 作为 grant subject；harness 采用它当 `user.did`。
- session setup 复用 genesis 中已接受的 founding device，使其可发布 MLS KeyPackage。
- invitee 读加密内容前弹"Set up 24-word Recovery Key"必答模态,测试自动完成。
- inkson kanban bootstrap:backfill 在 board-View 门之前跑,并把事件 ingest 进 `raw_operations`(跨成员 board/card 投影的真修)。

## 关键 testid

- 板选择/深链:`/kanban/{realm}/board/{boardId}`(boardId 从建板后 URL `/board/ak:space:` 抽取)
- 卡片:`kanban-card`(真卡)vs `kanban-card-redacted`(失败占位)
- 解密证据:`card-description-panel`(明文正文) + `card-detail-body-locked`(锁态,须 count=0)

## 已知会红即为抓到真 bug 的类别

`invitee 见 0 卡`、`对方 board 闪现即消失`、`card 卡 Restoring`、`body locked 解不开`、`MLS Security Frontier 漂移`、`加入前历史`。本 spec 任一断言变红,基本就命中其中之一——这正是它存在的意义。

## Outbound crash matrix

创建者另覆盖 `accepted-create response loss before epoch zero`：真实创建向导选择 MLS，首个 create 请求发出前从 encrypted IndexedDB authoring vault 读取并对照完整 closed intent／原签 unit。真实服务接受整个 ordinary Realm bootstrap 后仅丢弃客户端响应，确认尚无 Genesis 请求，再销毁页面 runtime 并深链重进原 Realm。后台必须从 durable intent 接续，create 重试保留原请求字节与唯一 EventId，原 scope 只提交一个 Genesis；随后创建加密看板、私密卡片正文并实际解密、刷新重读。此处读取本地 intent 不作为 authority evidence，也不替代完整 creator FSM／pinned governance 验收。

创建者在首个 Genesis 请求前还检查 encrypted vault 中的 `genesis_queued`，其中保留原 `governance_result_pinned` 证据：exact accepted create、独立 authority／完整签名 current cut、原 canonical proposal bytes／binding、exact Account／Device 与 generation 保存在同一正式记录；刷新后原 pin 不被替换。`Device evidence unavailable keeps acceptance before randomness` 在正式 `realm_accepted` 后让现有 self keys/query 返回合法缺席结果，要求 pin 不出现且没有 Genesis 请求；销毁 runtime、恢复查询后仅一个 Genesis、真实加密卡片解密与 reload 完成。故障结果是测试注入，self projection 不是可转交的 origin attestation；此子片不替代完整 11-state FSM、Agent／Circle 与 accepted／artifact／ready 原子发布验收。

`restores epoch-zero unit after public blob response loss` 在第一个公开 MLS blob 请求到达时检查正式记录已处于 `epoch0_state_persisted`：设备 secret 封装私有状态、原 raw GroupInfo／tree、content refs 与同一 created_at 的 unsigned Genesis core 已共同落盘。真实 blob store 写入后丢弃响应，销毁 runtime 再重进原 Realm；复用逐字相同的完整 recovery unit，不重建随机材料。Genesis 发出前，记录必须进入 `genesis_queued`，签名 Event、canonical bytes、EventId 与同一个 vault 内的 queue item 一致。实际写加密卡片并刷新后，pin、epoch-zero unit 和原签 Genesis 均保持不变。这里对 holder vault 的断言是本地持久化验收，不作为可转交的 authority attestation。

同一主链另覆盖三个发送方刷新断点；均操作完整原子 `MlsCommitSubmission`，不替换签名 Event 或服务器结果：

- `commit-response-lost`：服务器实际接收 Commit 后丢弃 HTTP 响应，刷新 Alice，再恢复传输。
- `welcome-before-durable`：完整 Commit＋Welcome 请求尚未发往服务器时断开提交，刷新 Alice，再恢复传输。
- `welcome-response-lost`：服务器实际接收完整 Commit＋Welcome 事务后丢弃响应，在发送方安装 staged state 前刷新；它与 Commit 响应丢失是同一原子事务边界。

每项都必须完成双方私密正文解密、Bob 刷新重读、本地存储与 wire 无明文检查；观察到的目标
EventId 必须保持唯一且等于断点前原 ID，完整提交字节必须逐字一致。仅重试请求或只见到 epoch/Welcome 不算通过。
此矩阵不替代多个接收端中仅部分 Welcome 已 durable 的独立验收。

## 私有安装 readiness

`private-state-blocked` 延迟 Bob 的只读 KeyPackage claim 查询，保留正式 Account current、Commit、Welcome 和所有签名输入。
已有 accepted List 仍可见时，Add Card 必须禁用，初始同步仍为 pending；恢复查询后必须完成私有安装、解密、双向编辑与 reload。
该断点用于区分公共详情 baseline 与密码学可写状态，不用伪造成功响应或修改 current 值。

## 非终局 authority outcome 与重启

`retryable-unavailable` 在原子 MLS Commit／Welcome 请求到达治理站前返回正式 `retryable_unavailable` outcome，不伪造 Commit。sender 刷新后仍由原耐久队列自动发送相同 EventId 与签名 bytes；恢复真实 transport 后完成 Welcome、双向加密卡片与 reload。该分支必须保留可诊断 authority status／reason，队列不得落为终局 rejected 或依赖交互再次 requeue。

## 连续 accepted Commit 恢复

`late-transition-tail` 在 Bob 已耐久持有 epoch 1、解密并刷新旧卡片后，再邀请真实第三成员 Carol，等待 accepted epoch 2。
Carol 按自身 Welcome 加入；Bob 不取得 Carol 的加入 secret，必须在刷新后由获准连续 Commit tail 恢复原私有组，继续双向编辑与创建加密卡片。
等待 Commit 的助手检查 `next_epoch`，不能把此前 epoch 1 的 Commit 当成第三成员已加入的证据。

## 退役的历史共享分支

现行 v1 `models/realm-and-space.md` §2.2 要求 MLS Genesis 接纳时 current history policy 为 `since_join`；
`all_history_for_current_members`＋MLS 与 exporter history-key 分支已删除，不能作为合法产品验收。
对应旧浏览器用例已移除；激活选择的拒绝门由 `views::setup::helpers::tests` 验证，不增加跳过测试。
