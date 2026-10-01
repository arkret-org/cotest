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

创建者在首个 Genesis 请求前还检查 encrypted vault 中的 `genesis_queued`，其中保留原 `governance_result_pinned` 证据：exact accepted create、独立 authority／完整签名 current cut、原 canonical proposal bytes／binding、exact Account／Device 与 generation 保存在同一正式记录；刷新后原 pin 不被替换。`Device evidence unavailable keeps acceptance before randomness` 在正式 `realm_accepted` 后让现有 self keys/query 返回合法缺席结果，要求 pin 不出现且没有 Genesis 请求；销毁 runtime、恢复查询后仅一个 Genesis、真实加密卡片解密与 reload 完成。故障结果是测试注入，self projection 不是可转交的 origin attestation；此子片不替代完整 11-state FSM、Agent／Circle 与 artifact／ready 原子发布验收。

`restores epoch-zero unit after public blob response loss` 在第一个公开 MLS blob 请求到达时检查正式记录已处于 `epoch0_state_persisted`：设备 secret 封装私有状态、原 raw GroupInfo／tree、content refs 与同一 created_at 的 unsigned Genesis core 已共同落盘。真实 blob store 写入后丢弃响应，销毁 runtime 再重进原 Realm；复用逐字相同的完整 recovery unit，不重建随机材料。Genesis 发出前，记录必须进入 `genesis_queued`，签名 Event、canonical bytes、EventId 与同一个 vault 内的 queue item 一致。实际写加密卡片并刷新后，pin、epoch-zero unit 和原签 Genesis 均保持不变。这里对 holder vault 的断言是本地持久化验收，不作为可转交的 authority attestation。

`reconciles exact accepted Genesis after response loss and unavailable query` 让真实 Station 接受原 Genesis 后丢弃响应，同时阻断后续 stream exact query，要求正式记录保持 `genesis_queued`、原 unit／原签字节不变，不能因 HTTP 接受或 exhausted queue 提前发布。销毁 runtime 并恢复查询后，从 nonce-bound authority／完整签名 snapshot cut 与连续 Commit 重放独立验证原 exact accepted Event，再进入 `genesis_accepted`，其 signed bytes／digest、covering Commit 与同 vault completed-but-retained queue 必须一致。全部 creator 场景在加密卡片写入与 reload 后核对该 acceptance 不变；原 pin 不更新，新查询使用本次验明的 current authority cut。这里的本地状态不是对端可采信的证明；Agent／Circle、终态及完整 crash 矩阵仍由 0730 承接。

`retries the whole accepted artifact install after durable write failure` 与 `publishes ready and its send-gate index atomically after durable write failure` 在真实浏览器 SubtleCrypto 加密 vault 写入时分别阻断 `artifacts_converged` 和 `ready`。前者必须保持 `genesis_accepted`、无 artifact；后者必须保持 `artifacts_converged`、无 ready receipt／索引。两者都保留原 epoch-zero unit、签名和 exact acceptance；销毁页面 runtime 后仅重试原完整安装及发布，不能再生成或再提交 Genesis。creator 成功场景在实际加密写入、解密及 reload 后核对 `ready` receipt、winning artifact 与同 vault send-gate index 完全一致，ready commit position 不超过持久 vault position。故障注入和 session setup 属于 fixture-only，不扩大为完整 UI 注册登录或跨设备证明。

`stops the losing queue after a distinct accepted Genesis wins` 在原浏览器正式进入 `genesis_queued` 后，让独立 fixture client 生成另一份真实 RFC 9420 group／签名 Genesis，并赢得真实 Station 的唯一接受位置；它不把私有材料安装到原浏览器。原浏览器必须从独立认证的 exact query 原子进入 `superseded` 并移除 loser queue，保留原 intent、epoch-zero unit、原签 Event／digest 和 winner，不发布 ready receipt／索引。看板及 List 元数据仍可操作，但 Add Card 必须禁用；刷新后终态及材料不变，不重新作者。此例仍为 fixture-only，不作为完整 UI 注册或 Welcome／迁移／恢复的成功证明。完整创建流程在目标 Genesis 故障注入前若遇到真实 unavailable snapshot，可通过页面已有 Open Realm 入口重进原接受 Realm，继续同一持久记录。

`retains a terminal rejection and explicitly opens a new verified attempt` 注入普通 Event 准入形式的 HTTP 403 Problem；生产队列保存原 Problem，并与 `rejected` 诊断在同一次 vault CAS 停止原签 Genesis。刷新后保持原 EventId／digest／reason／stage／last verified cut；点击产品重试入口时若 exact stream 查询不可用，终态与停止队列不变。恢复查询并再次明确重试后，独立认证 fresh absence 使同逻辑记录原子关闭旧尝试、保留 tombstone、移除旧队列并继承原 intent；新 epoch-zero／Genesis 可实际加密写卡片，刷新后 tombstone 仍在。拒绝结果为 fixture-only 注入，不能声称 Station 实际拒绝该 Event。

`preserves a real Station rejection before resolving its winner` 让独立 fixture client 在原浏览器 Genesis 发出前赢得真实 Station slot，然后将原请求送达 Station，要求保留实际 `mls_activation_irreversible` Problem 及 `rejected` 诊断。刷新后通过明确重试入口重新独立查询 accepted winner；真实 snapshot issuance cut 变化返回 unavailable 时，先核原 intent／诊断／停止队列不变，再至多三次通过产品按钮明确重试，不能把不可用当缺席。取得 verified winner 后原子进入 `superseded` 并移除停止队列；原私有组不得安装为 winner，实际看板门和再次刷新仍关闭。测试身份和竞争作者仍为 fixture-only，真实拒绝并不将场景改标 live product。

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

`quarantines record/private/queue/index/write_failure inconsistency` 先通过真实产品创建、加密卡片、解密和 reload，确认完整 `ready` record 与同 vault index，然后使用实际 non-extractable wrapping key 在严格 ciphertext compare 的 IndexedDB readwrite 事务中损坏本地恢复记录。分别覆盖不可解码的 private carrier、可解码但不能恢复的原 RFC private bytes、原 frozen queue 请求不一致、ready index 缺失；第五例在真实 SubtleCrypto 加密隔离提交时拒绝写入。失败写入必须保持整个原持久 record/index，不能显示已提交的隔离；重新打开后产品必须提交 `quarantined`、保留最后状态／失败 invariant／EventId／digest／queue id／已知 acceptance／检测时间／完整原记录和相关原队列，并移除 ready index。实际 Add Card 关闭、产品显示只读隔离提示、没有重试按钮，再次 reload 后诊断原样保留且不重新提交 create 或 Genesis。注入只操作认证过的本地 vault，不制造 wire authority evidence；全部仍为 fixture-only，不扩大为 UI 注册登录或跨设备证明。

`quarantines a rejected original independently proved accepted` 先注入本地 403 拒绝并保留9，再用独立 fixture HTTP caller 将完全相同的原 frozen request送达真实 Station并取得 accepted outcome。产品明确重试必须独立认证 accepted 原 Event，由9进入11，保留原拒绝、私有单元、signed coordinates及已知 accepted winner，不能把同一拒绝原件当新代或 distinct winner进入10。真实 snapshot cut不可用时只核原9原样并有界明确重试；reload后11诊断不变、无重试入口、不重新提交 create／Genesis。注入拒绝和独立 caller仍为 fixture-only；实际 Station acceptance不能将整个身份设置改标 live product。

Quarantine private／write-failure 切点保持原私有信封的合法 JSON 与字段坐标，只篡改合法 hex 密文，同时重算测试 fixture 声明的 private byte binding。因此 SDK opaque-byte 结构检查仍可通过，失败必须由持有原设备密钥的真实私有解密恢复入口发现；该切点不把 fixture vault 读写当作 portable authority proof。
