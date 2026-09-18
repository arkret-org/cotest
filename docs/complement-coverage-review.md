# Complement 测试价值与 joint-e2e 补测设计

审计日期：2026-09-08。Complement 本地 `D:/Works/complement`，commit `11ba33aee54f0e3502379e1fac38ca362b4e938f`；Cotest 起点 `eaa738dbc3fd4577d0071efa71bb6178202ddc8b`。协议依据均为本地 `arkret-spec/spec/v1/zh/`。初轮新增 21 条后，继续验收又增加 2 条账号 filter 回归，累计 23 条 Cotest 新入口；分阶段运行结果见文末。

## 范围与结论

枚举 Complement `tests/` 下全部 122 个 `*_test.go`，其中 107 个文件含业务测试，共 211 个顶层 `TestX(t *testing.T)`；不把 `TestMain`、动态 `t.Run` 展开项算作顶层测试。按测试主题筛选，并阅读下表所列重点场景的操作与断言。这里不是“211 个用例全部逐行证明等价”的声明。

对照 Cotest 的 Playwright 源码、`api-only-migration.json`、Rust `tests/`/`src/scenarios/`/`src/conformance/`，而非只搜索相似文件名。原 `complement-joint-gap-map.md` 主要覆盖三站 P0，本次补上客户端同步、账号、设备、媒体和负向授权。**代码存在、在 joint lane 中被选择、实机执行通过，是三个不同状态。** 原生 harness / fixture 证据不能直接算成 Coauth + 独立 Soland + 客户端的完整产品闭环。

最值得继续投入的是：同步窗口与当前态、断线后的 durable 重放、重启后的投递与确认、成员退出后的旧游标授权、并发 KeyPackage claim。创建/发送/接收等 happy path 已很多，再复制一份价值较低。

### 判定用语

- **已有**：找到相应断言，本轮不重复实现；不表示本轮重跑通过。
- **部分**：已有某些维度，表中明确剩余缺口。
- **新增待实测**：本轮已进入实际测试选择面，运行结论见末尾。
- **需改写**：可借鉴失效模式，必须重写为 Arkret 合同。
- **不移植**：Matrix 专属行为，当前规范没有等价操作。

## 逐域对照

表中 Complement 路径相对其 `tests/`；Cotest 路径相对本仓。

| # | Complement 来源与实际关注点 | Cotest 现有证据 | 仍有价值的补测及 Arkret 依据 | 优先级 / 判定 |
| --- | --- | --- | --- | --- |
| 01 | `csapi/sync_test.go::TestSync`：initial、incremental、重复旧 since | `e2e/tests/sync/account-stream-device-message.spec.ts` 原先仅长轮询；`src/scenarios/account_subscribe_long_poll.rs` 已有 RYW/quiet-Realm/邀请成员同步，`tests/conformance_vectors.rs` 是模型向量 | 存 cursor→停收期间写三条→两次旧 cursor 重放完整集合→用新 cursor 只收下一条；`sync/client-sync.md` §§2–3 | P0；本轮新增 |
| 02 | `TestSyncTimelineGap`：remote gap 必须 limited；`federation_sync_test.go::TestSyncOmitsStateChangeOnFilteredEvents`：过滤掉合流消息后 state 不丢 | `sync/offline-conflict.spec.ts` 有 peer backfill；`conformance/realm-state-snapshot-query-scalability.spec.ts` 有 snapshot 读取 | 小窗口限流、被过滤的控制事件、state_after/window-start 和后续完整 backfill 的同条 live 闭环；`client-sync.md` §§3、5、12–13 | P0；部分，详见 R2 |
| 03 | `csapi/room_relations_test.go::TestRelationsPagination*`：正反向、sync 边界；`room_messages_test.go`：历史读取 | `sync/service-surface-contract.spec.ts` Phase C 与 `src/scenarios/events_backfill.rs` 已验证静态向后翻页，尚未覆盖本次新增的写入交错/跨作用域组合 | 首页后插入新事件；before 继续旧历史、after 获取新事件、参数顺序规范化、scope/order 变更拒绝；`service-http-binding.md` §3.3、`client-sync.md` §11.1 | P1；部分，R3 |
| 04 | `csapi/sync_test.go` 与 `room_typing_test.go::TestLeakyTyping` 的合法接收者/旁观者对照方法 | 原账号流无 payload 范围断言；typing 自身已有 `messaging/chat-advanced.spec.ts` live rail 测试 | 账号流 initial 的 Realm filter、旁观账号不见私有 Realm；不把 typing 塞进 account delta；`client-sync.md` §2 | P0；本轮新增 |
| 05 | sync token 的恢复方法启发出的 Arkret 独有边界；不是声称 Complement 已有同名 handle 测试 | cursor conformance 与 Phase C 的损坏 token；缺少本场景的 live cross-binding 证据 | 完整 AccountId/过滤条件绑定错误→400 cursor_integrity_invalid；原持有人仍能续读；`conformance/encoding.md` §8.3.1 | P0；本轮新增 account/filter，两设备/跨 Station 仍待补 |
| 06 | `csapi/txnid_test.go::TestTxnIdempotency*`：同键重试、设备与 room 作用域、refresh 后重试 | `sync/service-surface-contract.spec.ts` D0/D 与 `src/scenarios/event_idempotency_replay.rs` 已有串行 Event/edit/redaction 重试；`sync/offline-queue-replay.spec.ts` outbox；`identity/device-key-lifecycle.spec.ts` refresh | 重试 HTTP 响应丢失、refresh/restart 后映射持久化、两个合法写者同键互不串扰；`sync/api-conventions.md` §6。Matrix“同键不同内容返回旧成功”**不能照搬**，Arkret 应 duplicate_conflict | P1；部分，R4 |
| 07 | `csapi/to_device_test.go` 多收件者；`federation_to_device_test.go` 接收端离线且发送端重启 | `src/scenarios/to_device_offline_ordering.rs` 已有三条顺序、ack 后不再投递、逻辑 ID 重试；`delivery_media.rs` 已有幂等与空队列 | 分页只是读位置；旧/重复/跨设备 ack、发送端重启后持久 outbox 与接收端 ack 闭环；`client-sync.md` §10.1、`crypto-media/device-lifecycle.md` §7。不能假设通用跨 Station device-message API 存在 | P0；部分，R5 |
| 08 | `csapi/device_lists_test.go` join/leave/rejoin；`federation_device_list_update_test.go` 远端变更 | `identity/multi-device.spec.ts`、`identity/device-key-lifecycle.spec.ts`；`tests/station_account_isolation.rs` 数据隔离 | 两远端已授权接收者 + 非共享上下文旁观者；撤销旧设备后禁止 KeyPackage/secret-share/backup 继续使用；`device-lifecycle.md`、`client-sync.md` | P0；部分，R6 |
| 09 | `csapi/upload_keys_test.go::TestKeyClaimOrdering/IdempotencyOverlap`：重复上传与一次性消耗 | `src/scenarios/delivery_media.rs::key_upload_query_and_claim_edges_are_enforced`、`protocol_payloads` | 两合法 claimant 并发 claim 同批 KeyPackage，不能重复消耗；失败重试不多消耗，补充上传后恢复；`crypto-media/device-lifecycle.md`。Matrix OTK FIFO 不是 Arkret 默认排序规则 | P0；部分，R7 |
| 10 | `federation_rooms_invite_test.go` reject 两次、空房间 reject、撤回、非当事人撤回 | `invites/invite-addressing.spec.ts` dispatch retry、first-contact 和错误证据；`src/scenarios/invite_service_fanout_live.rs` 等较强原生证据 | 跨站 reject→reinvite→withdraw→accept 旧邀请失败；同一 Station 内两 Account 不串 inbox；`sync/invite-addressing.md`、`authz/` 邀请合同 | P1；部分，R8 |
| 11 | `csapi/sync_test.go::TestCumulativeJoinLeaveJoinSync`、`sync_archive_test.go` 与 `room_messages_test.go` rejoin history | `spaces/moderation-ban.spec.ts` 已有 ban 后写拒绝；`joint/joint-inkson-smoke.spec.ts` since_join baseline | leave/rejoin 不得复用旧历史授权；旧 cursor、direct Event read、scan、Blob、live rail 同时复查；`client-sync.md`、`authz/event-auth-state-resolution.md` | P0；部分，R9 |
| 12 | `federation_room_ban_test.go::TestUnbanViaInvite`；`csapi/room_kick_test.go` 无权限/已离开成员 kick | `spaces/moderation-ban.spec.ts` 包括重复 ban 不改变 membership | 跨站 ban→unban→重新加入及旁站隔离。**邀请不能代替 Arkret unban Control Move**；按 membership `sequenced_state` transition rule 构造 | P1；需改写 |
| 13 | `federation_room_get_missing_events_test.go` 缺父、坏 JSON、巨大依赖、损坏 auth chain；`federation_unreject_rejected_test.go` B 先于 A | `federation/three-server-p0.spec.ts` P0.3 与 `sync/offline-conflict.spec.ts` 有 recovery；state-resolution conformance | 多父依赖中混入无签名/错误 scope 对象；补足依赖后的合法重试只生效一次。必须区分未决依赖与不可重裁定的 settled verdict；`sync/federation.md`、`event-auth-state-resolution.md` | P0；部分，R10 |
| 14 | `federation_room_send_test.go::TestNetworkPartitionOrdering` | 三站 P0.1/P0.3/P0.5 已比较完整 Event ID 集合，并含 restart | 延伸到有效 cell/Seal frontier 与用户可见序列，不能只看最后一条消息；先复用三站用例，不新建第四套 harness | P1；已有基础 |
| 15 | `csapi/room_typing_test.go` start/stop/leak；`federation_room_typing_test.go`、`federation_presence_test.go` | `messaging/chat-advanced.spec.ts` typing 解密与 target opacity，UI TTL；Rust signal conformance | 三站接收者/旁观者、membership 撤销后不再 fanout、旧 seq/过期 Signal 不复活；`discovery/profiles-presence.md`、Signal profile | P1；部分，R11 |
| 16 | `csapi/apidoc_room_receipts_test.go`、`thread_notifications_test.go` thread receipt | `messaging/read-receipts.spec.ts`、`models/private-read-marker.spec.ts` 已有多端内容 | Strand A read 不清 Strand B unread；倒序高水位、离线双设备合并、私有 marker 不进入公共 receipt；`discovery/read-receipts.md` | P1；部分；不移植 Matrix thread_id 枚举 |
| 17 | `csapi/ignored_users_test.go`：被忽略 Bob 的 invite 不见，但 Chris 的 invite 可见 | `governance/personal-blocklist.spec.ts` 私有偏好、CAS/account sync；`invite-addressing.spec.ts` receive policy | exact ActorId 接收策略拒 Bob，同时 Chris 成功；含已排队邀请、解除后新邀请、另一个 Station 的同 principal 不串；`sync/invite-addressing.md`。私有密文 blocklist 不能当服务端可读 ACL | P1；需改写，R8 |
| 18 | `csapi/account_data_test.go`、`msc3391` global/room data 与删除 | `personal-blocklist.spec.ts` 已有同 key CAS revision 与 sync latest；`tests/station_account_isolation.rs` | 两设备 expected_revision 冲突→读最新→重试、删除 tombstone→重启 initial/incremental 一致；`models/account-data.md` | P1；部分，不能复制 LWW 覆盖写 |
| 19 | `csapi/redact_test.go`、`federation_redaction_test.go` redaction 先于目标 | moderation-ban、`src/scenarios/event_idempotency_replay.rs` 已有 tombstone/重复 edit-redact 断言；`src/conformance/redaction.rs` | scan/单 Event/回复/搜索/Blob 引用都遵守 redacted view；晚到目标不能恢复已删正文；`sync` redaction、`conformance/encoding.md` | P1；部分；保留 Event ID/依赖证明，不能删除 DAG 节点 |
| 20 | `csapi/room_relations_test.go` edit/reaction/reply；`room_threads_test.go` | `messaging/chat-advanced.spec.ts` 与 `src/scenarios/interaction_models.rs` 已有 reaction/reply/revision | 重复 reaction remove、离线交错操作、根消息 redaction 后引用仍可验证、分页不漏 reply；CBS/OR-Set 与 Strand 语义取代 Matrix aggregation | P2；部分 |
| 21 | `federation_media_content_test.go`、`media_thumbnail_test.go` remote original/thumbnail | `encryption/file-transfer.spec.ts`；`delivery_media.rs::blob_integrity_head_range_and_missing_edges_work` | 冷缓存远端原件→range/hash 验证→owner/revoked/outsider 三方对照→清缓存/重启重读；`crypto-media/media-and-blob.md` | P1；部分，R12 |
| 22 | `media_filename_test.go` Unicode、危险 MIME、Content-Disposition；`media_nofilename_test.go` | Blob native HEAD/Range 与完整性；未发现对应完整 joint filename/MIME 矩阵 | 引号/分号/CRLF/Unicode 文件名不能成为 header 注入，active content 按 Arkret 内容安全规则处理；只对规范要求的服务端变体断言，不要求对 MLS 密文服务端缩图 | P1；需改写，R12 |
| 23 | `csapi/media_async_uploads_test.go` pending/overwrite/retry/timeout | file-transfer 与 Blob 原生基础 | 上传未完成、完成重试、digest 不匹配、越权继续、取消后残留；按 Blob 上传/内容寻址状态，不移植 MXC ID 或 M_NOT_YET_UPLOADED | P2；需改写 |
| 24 | `room_hierarchy_test.go`、restricted hierarchy、public rooms | `models/realm-links.spec.ts`、`discovery/directory.spec.ts` | 循环链接去重、分页边界、不可见 child 不泄露元数据、directory freshness/takedown；`models/realm-and-space.md` 与 Teabay discovery 合同 | P1；部分 |
| 25 | `restricted_rooms_test.go` 与 `federation_room_join_test.go` candidate failover | 三站 P0.4 只有坏 TLS candidate + 成功 peer query | 必须观测产品按签名 `join_candidates[]` 有界切换，失败候选无授权副作用；当前不能称已完成产品 fallback | P0；原 pending 保留 |
| 26 | `csapi/apidoc_profile_*`、`user_directory_display_names_test.go`、remote profile | `identity/account-profile-ui.spec.ts`、`discovery/directory.spec.ts`；signed profile request 原生合同 | 同 principal 不同 Realm 身份投影不可串用；更新/删除/旧 cursor 后仍按当前可见性；`discovery/profiles-presence.md`、`identity/identity-handles.md` | P2；部分 |
| 27 | login/logout/device management/password/deactivate/key backup | `identity/oidc-login-flow.spec.ts`、`multi-device.spec.ts`、`encryption/key-backup.spec.ts` | 撤销时活跃 long poll/refresh/backup/secret-share 联合关闭；Coauth 安全事务与 Station fresh introspection；不移植 Matrix UIA/session 规则或 Megolm backup 优选算法 | P0；部分，R6 |
| 28 | `unknown_endpoints_test.go`、request encoding、invalid JSON、capabilities | `sync/service-surface-contract.spec.ts`、`sync/transport-negotiation.spec.ts`、registry drift | 已有的 404/405/ProblemDetails/profile 声明先加强正向对照，不另起相同 suite；批量“部分合法+部分非法”的原子性值得按具体 operation 补 | P2；已有基础 |
| 29 | `room_upgrade_test.go`、`v12_test.go`、MSC room versions、owned-state/power-levels | Arkret 自有 v1 Realm/CBS/capability 规范 | 不引入 room-version、Matrix power_levels、send_join/v1/v2、ACL EDU 等概念。只抽取身份派生、防越权和冲突收敛的不变量 | 不移植 |
| 30 | MSC polls/threads/sliding sync/delayed events、URL preview、timestamp search | 产品已有 poll 与 Strand；privacy-preserving-search 是不同合同 | 仅有 Arkret 注册 operation/profile 时再立测试；不要为了对齐 Complement 增 API、全文明文索引或 MSC feature | 不移植其协议；可保留产品启发 |

## 后续可执行设计

以下是完整验收配方；本轮已实现的子项列在后文，其余仍是后续设计，均不计为新增通过。每项沿用 owning scenario 文件，API-only 场景优先 Rust；多站故障继续使用现有 runner-owned control，禁止测试自行终止其他运行的服务。

### R2：同步窗口与当前态，P0

两账号加入同一 Realm，baseline 后停收，产生超过 timeline_limit 的消息及一次合法 Realm/Strand Control Move。以 limit=2 重连，逐 frame 检查上限；若截断，必须 limited，并提供 state_at_window_start 或 preview_only。按合法 scope 的 read.scan cursor 补齐后，完整 Event ID 集合与写入集合相等，重放无重复。另加 event_kinds/not_event_kinds 过滤掉最后消息的分支，当前安全态仍必须足够验证后续写入。`state` 和 `state_after` 不是“过滤后 timeline 的顺带结果”。

### R3：边写边分页，P1

创建 6 条带唯一 ID 的消息，以 limit=2 取首尾 cursor；再接受 2 条新消息。before 继续取旧页不得重复前页，after 从原最新边界能读取 2 条新消息。改变 limit 可继续（§11.1 排除位置/分页尺寸）；改变 order/selector/filter 必须拒绝。集合等价的 selector 排序/去重不应造成 false integrity error。用两 Realm 正向读证明失败是 scope binding，而非 Realm 本身不可访问。

### R4：响应丢失与幂等映射持久化，P1

在服务端已接受、客户端未收到响应的边界中断连接，重启拥有映射的 Station 后，以同 canonical request + Idempotency-Key 重试；断言语义等价结果和仅一个 accepted Event。refresh SessionGrant 后再试，同一完整 actor 不得因 token 字符串变化重复写入。另一个合法 actor 使用同文本键应独立成功。不同 body 必须 duplicate_conflict；不要沿用 Matrix 忽略新 body 的规则。

### R5：设备确认与持久投递，P0

同账号两个已接受设备及独立发送者。发送 3 条，设备 A limit=1 分页；仅使用 after 后从头读仍有全部未 ack 消息。B 使用 A 的 ack_token 必须 invalid_ack_token，A 队列不变；A ack 第一页后只剪一条，重复旧 ack 返回 0，新消息仍在；最后累计 ack 清空。发送者/队列服务重启后重复发送相同逻辑 ID 不重新投递。跨 Station 只测试规范已登记的专用投递链（例如 Invite delivery），不得新增通用 federation-to-device 旁路。

### R6：撤销的联合收口，P0

两个 accepted device + 两个远端合法接收站；撤销前证明 grant、Signal、KeyPackage 和 secret-share/backup 可用。执行规范设备撤销/恢复安全事务后，旧 grant fresh introspection 失败，旧设备不能新发送/收取受限内容；仍有效设备和无关 Realm 的 sentinel 继续成功。历史合法 Event 的验证与当前设备授权区分开，不能把历史消息全部判为无效。

### R7：并发 KeyPackage 消耗，P0

先上传两个合法包，两个已授权 claimant 同时请求，用返回 package ref 集合和后续 claim 结果检查一次性消耗。重放相同请求按规范幂等处理；补充新包后可继续 claim；撤销设备后不允许返回旧包。只验证唯一性/授权/剩余量，不假定 FIFO，也不使用缺证据的任意公钥 fixture。

### R8：邀请生命周期与接收策略，P1

Alice/Carol 在两站，Bob 为受邀者。Bob 显式拒绝 Alice，Carol 的邀请仍正常进入 Bob inbox；验证 initial 和 incremental delivery。拒绝/撤回每个分支使用对应 accepted Invite 引用，重新邀请必须是新工作流；旧引用不可重新获得权限。邀请只是私有 workflow，不能让 `member_roster` 出现 invite 状态。所有失败后复读 inbox 与 membership，不能只断言 HTTP 4xx。

### R9：退出/重入与历史授权，P0

按 `since_join` / `all_history_for_current_members` 两个已有 profile 参数化。Bob 保存 read/stream cursor 后 leave 或 ban；新写入消息，并用旧 cursor、单 Event、Blob 与 live Signal 检查当前授权。解除 ban 与重新加入分开执行，再验证新 current baseline 足以合法双向写入。不能从 Matrix 的 joined/shared/invited/world_readable 四种 history_visibility 推导 Arkret 规则。

### R10：缺失依赖与不可重裁定，P0

合法 A/B/C 依赖图，先送依赖不齐的 C；peer1 不可用，peer2 提供部分依赖和一个错误 realm/digest/proof 对象。恢复后仅获取正确依赖、按协议 pending/retry 分支接受一次 C。另造已经 settled 的无权限事实，补其它数据也不能让其“unreject”。验证 accepted IDs、cell state、Seal basis，正向 sentinel 排除联邦完全断开。

### R11：短时 Signal 的不泄露，P1

三站，A/B 同 Realm，C 旁观；A→B 正常 typing/presence/receipt。给 B 发送倒序 seq、过期 Signal、重复 frame，不能复活旧状态。撤销 B 当前授权后，C 与 B 都不获新内容，无关 Realm 继续正常。断线期间 Signal 不补历史；不要用 account cursor/backfill 证明 Signal 已恢复。

### R12：远端媒体的授权与内容安全，P1

Alice 上传内容，Bob 在远端合法访问，Carol 不具访问权限；先验证 Bob 的 digest、HEAD/Range，再验证 Carol 与撤销后的 Bob。以普通二进制、Unicode 文件名、带参数 MIME、active content 做表驱动分支，检查规范要求的 headers；加未完成上传/取消/重启分支。MLS ciphertext 的服务器只能验证密文完整性；缩略图如需明文处理，应走规范客户端产物路径。

## 本轮实现与选择面

本轮共新增 **21 条独立测试入口**：7 条 Playwright（连同原长轮询共收集 8 条）+ 14 条 Rust。原生测试采用已有真实 HTTP harness，不是内存模型向量；但它们没有被偷换为 Playwright joint-api 的通过证据。

扩展现有 `e2e/tests/sync/account-stream-device-message.spec.ts`，没有新增另一套 API-only framework：

1. 旧游标两次重放同一组三条消息，并以新游标只读下一条。
2. Initial account sync 的 Realm 过滤，先以不带 filter 的成功响应证明两个 Realm 均存在且可读。
3. 旁观账号不能收到另一个账号私有 Realm 和 Event ID；先验证 owner 成功读取。
4. cross-account cursor 拒绝后，原持有人仍能继续。
5. cross-filter cursor 拒绝后，原 filter 仍能继续。
6. 五条消息的有限 initial timeline，逐 frame 检查 timeline_limit，截断时检查 limited 与 state boundary；允许服务器分多帧完整返回。
7. event_kinds/not_event_kinds 控制 timeline，但不抹去 Realm baseline。

扩展原生 `tests/events_backfill.rs`，新增 7 条：边写边 before/after 读取；修改 limit 与相同 cursor 重读；更换 order 拒绝；更换 Realm selector 拒绝；selector 顺序等价；同 Realm 的另一合法成员仍不能借用 cursor；barrier/stream purpose 互换拒绝。所有负例都有合法可读基线，拒绝后再次验证原请求仍有效。

扩展 `tests/to_device_offline_ordering.rs`，新增 5 条：只读分页与累计/旧 ACK；同账号另一设备 ACK 拒绝；另一账号 ACK 拒绝；并发同键投递去重且 ack 后逻辑重试不复活；同 logical ID 换 target 拒绝且另一个合法新 ID 可以投递。配对产生的 setup 通知在 seed 之前使用规范 ACK 清理，负例后同时检查两个队列。顺带修正原 helper 的 `from` 为 `after`，以及固定年末 expires_at 为当前时间加十分钟并在逻辑重试中复用同值。

扩展 `tests/event_idempotency_replay.rs`，新增 2 条：三个并发相同 Event 请求只有一个 accepted/two duplicate，后续 actor-chain 写入仍成功；两个独立合法 actor 可用同文本 Idempotency-Key，各自只产生一条 Event。读取使用规范 RYW barrier，避免只断言 HTTP 成功却未验证投影。

原生对应入口已登记到 `config/coverage-profiles.json` 的 cursor/idempotency 证据列表，保留现有 profile 状态，不因新增源码升级为实测通过。运行入口：

```powershell
cargo test --test events_backfill --test to_device_offline_ordering --test event_idempotency_replay
```

R2 已实现 limited/window-start 基础，控制状态过滤与完整长缺口补齐仍未实现；R3 上述 7 项已实现，filters/actor-selector 更多组合仍可补；R4 已实现并发 Event/actor scope，refresh/restart 仍未实现；R5 已实现读/ACK/目标冲突，进程重启和跨站专用链仍未实现。表中“部分”不能据此升级为整行完成。

原长轮询用例保留。所有用例各自注册，不使用 serial 级联依赖；任一失败不会把其余独立用例标成未执行。使用真实 Coauth onboarding + DPoP grant；共享 account-stream helper 为每次实际 GET URL 生成 DPoP headers。未增加 `test.skip`/`test.fixme` 或放宽错误集合。当前文件仍由 `api-only-migration.json.pending_migration` 纳入 `joint-api`，SDK account-stream client 可用后应迁回 Rust。

发现的源码偏差：`client-sync.md` §2/§11 的 account filter 命名是 `realms/event_kinds/not_event_kinds`；SDK `SyncFilter` 当前序列化字段为 `realm_ids/event_types/not_event_types`。Soland `account_subscribe_query` 直接反序列化该类型，snapshot 仅从 `.realm_ids` 取 Realm selector，未知 `realms` 落入 extra。旧长轮询测试使用同样的 `realm_ids`，无法发现此问题。本轮用规范 `realms`，不建立兼容 alias；该缺陷的端到端结果须以运行记录为准。

## 验证

执行命令与最终状态在本轮工作记录中同步；没有 runtime evidence 时不得将新增条目改为 covered。

静态检查已完成：TypeScript typecheck；Playwright joint-api `--list` 实际收集 8 条；API-only migration gate；coverage/evidence manifest freshness；`git diff --check`。Rust 三个受影响 target 的 `cargo check` 成功（10m03s，包含共享 target 锁等待），已执行 nightly format；14 条原生新增测试尚未实际执行。用户已明确本轮主要任务是增加测试，Docker 问题不作为本轮修复目标。

```powershell
cd D:/Works/arkret-org/cotest/e2e
npm run typecheck
npx playwright test --project joint-api --list --grep 'account stream'
cd ..
pwsh -NoProfile -File scripts/generate-e2e-coverage.ps1 -Check
pwsh -NoProfile -File scripts/generate-scenario-evidence.ps1 -Check
python scripts/check_api_only_migration.py
```

Live 使用 `run-joint-e2e.ps1 -RunProfile joint-api -StartCoauth -StartMocks -Grep 'account stream' -ForbidSkippedTests -KeepRuns 0`；Docker 未启动时改用 runner 已支持的两个隔离 local PostgreSQL 数据库，不绕过环境门禁、freshness 或标准认证链。

2026-09-08 定向 live 已完成，运行目录为 `artifacts/runs/joint-e2e/20260908-130445-joint-api-selection`，证据见其 `summary.md` / `junit.xml`。真实 Coauth + Soland provisioning 前置 7/7 通过；账号流 8 条全部执行，4 通过、4 失败，无 skip。新增 7 条中 4 通过、3 失败：

| 测试 | 实际结果 |
| --- | --- |
| 旧游标重放、完整集合与新游标续读 | 通过 |
| 私有 Realm 的账号隔离 | 通过 |
| cross-account cursor 拒绝与原持有人续读 | 通过 |
| cross-filter cursor 拒绝与原 filter 续读 | 通过 |
| initial Realm filter | 失败：请求一个 Realm，返回三个 Realm bucket；符合上文规范字段未被实现识别的源码观察 |
| initial timeline_limit | 失败：请求每帧最多 2 条，同一 Realm frame 返回 5 条；尚未执行到 truncated state boundary 的断言 |
| not_event_kinds 排除消息 | 失败：排除 `ak.message.create` 后仍返回该消息；正向允许分支已通过 |
| 原有 quiet long-poll | 失败：期望无相关数据时 `frontier`，实际得到 `delta`；用例期间创建了 filter 外 Realm，与 Realm filter 无效相符，尚未独立验证后续 wake 延迟 |

这次运行证明新测试能捕获当前实现偏差，不表示 account sync 整体通过，也不是浏览器产品链或多站联邦覆盖。未修改 SDK/Soland 来消除失败，后续修复后需按相同选择复验。

## 后续修复与复验

用户要求继续完成剩余验收后，已在 owning 仓修改以下行为：

- SDK SyncFilter 序列化与 digest 使用 `realms/event_kinds/not_event_kinds`；HTTP client 按 `filter.event_kinds/filter.not_event_kinds` 发送。增加 wire 字段读取与摘要一致性回归。
- Soland 读取点分隔 deepObject query，与 SDK HTTP client 一致。未知字段、重复 scalar、无效类型和 Realm ID 返回 `param_invalid`；不再将失败的 filter 反序列化当作无 filter。Cotest helper 同步改用规范参数编码。
- snapshot 在权限检查后应用 kind allow/deny，deny 优先；独立的当前控制基线保持。游标记录过滤前位置，防止同一批被排除事件反复重放。
- 每 Realm timeline 仅保留 limit 内最新事件；截断标记 `limited=true, preview_only=true`。当前代码没有重建首事件的 seal basis / 因果闭包，因此移除截断帧中原本取自当前 metadata 的 `state_at_window_start`，不作错误的历史状态声明。
- 新增两条 joint-api：filter 集合排序/重复项变化不改变 cursor scope；非法 filter 拒绝后正常 initial 仍可使用。原 kind 测试补充 allow 不命中与 deny 优先分支。账号流文件现有 10 条。
- 两条旧 Event 幂等测试的占位 Strand ID 改成真实 Realm default Strand，避免在到达幂等验证之前因错误目标被拒绝。

首次原生实际运行 18 条（14 新增、4 原有）为 15 通过、3 失败，进一步捕获并修复：

- `encoding.md` §8.3 规定 barrier cursor 用于 stream context 必须 `param_invalid`；Soland events-query parser 原将其归类为 `cursor_integrity_invalid`，现改为参数错误。真实 handle 查表绑定不符仍归类 integrity。
- `client-sync.md` §10.1 规定跨账号/设备 ACK 返回 `param_invalid` + reason `invalid_ack_token`。原 handler 只将其写入 detail，现附标准 reason code；token 原样匹配，拒绝空值或超过 1024 字节，不再 trim 后使用。

SDK filter 两条单元测试及 HTTP 参数编码一条单元测试、TypeScript、nightly format、10 条选择与覆盖清单检查均通过。修复后 joint-api run `artifacts/runs/joint-e2e/20260908-145306-joint-api-selection`：**10/10 通过，0 skip**，真实 Coauth + Soland provisioning **7/7 通过**，runner status success。初轮四个账号流失败均已复验通过。该结果仍只代表定向 API 合同，不扩大为完整浏览器/多站联邦通过声明。

第二轮原生结果为 Event 幂等 4/4、设备队列 6/6、backfill 7/8。用途混用测试继续揭露了反方向问题：stream cursor 放入 `X-Arkret-Wait-For` 时 header 被接受但查询忽略它。补充修复公共 header 的 barrier purpose 检查；Events QUERY 现在解析 handle、验证账号/设备绑定并等待目标投影，超时返回 `temporarily_unavailable` 和当前 frontier。该原生测试增加另一个拥有合法读取请求的账号借用 barrier 的负例，防止只做语法检查。

按用户随后要求，已 fetch 相关规范、SDK、服务与客户端仓库，并将 Soland 快进至 `c0d1b988`、Cotest 快进至 `2bc821c6` 后重放本地修改。唯一冲突为生成的 catalog，已从更新后源码重新生成，远端其它测试更新保留。上述同步前运行不替代新基线验证。

新基线最终验证（2026-09-08 15:23）：Soland 构建通过（3m30s），三个原生 target **18/18 通过**（Event 幂等 4、backfill 8、device 6），包含全部 14 条新增原生用例与强化的 cross-account barrier 断言。SDK **3/3 通过**（wire/digest 2 + HTTP 编码 1）；TypeScript、API-only gate、coverage/evidence freshness、diff 检查通过。

最新 joint-api run `artifacts/runs/joint-e2e/20260908-151819-joint-api-selection`：**10/10 通过、0 skip**，真实 Coauth + Soland provisioning **7/7 通过**；`summary.md` / `junit.xml` 为最终证据，runner exit 0。因此本次累计 23 条新增 Cotest 用例及对应 5 条旧用例已在重放远端更新后通过定向验证。原生详细输出见工作区 `.codex-logs/complement-replayed-native-tests-20260908.log`。

原生复验须设置 `SOLAND_BIN` 为共享 `.shared-target/debug/soland.exe`（以 `conformance-harness` feature 构建），并设置 `COTEST_SOLAND_DATABASE_URL` 为可创建隔离数据库的本机 PostgreSQL DSN。任务记录归档到 `arkret-work/tasks/impl-done/2026-09-08-1322-complement-test-coverage-expansion.md`；表中其它待设计场景仍不计入已通过覆盖。
