# 三站应急物资协同

三个独立 Coland／Coauth Station 的协调方、物流方、审核方，使用真实 Inkson 浏览器注册、设备入册、受限邀请与 MLS 完成同一个物资运输项目。邮件 mock 只投递注册验证码，不替代身份、签名、联邦、存储或加密。

## 规范边界

- `sync/federation.md` §4.1.1：成员 Station 持有、终止 Commit 与后续 fanout 边界。
- `sync/client-sync.md` §3、§14：耐久游标续接、本地加密状态与合法历史；退出不意味着能够抹掉成员已经获得的明文知识。
- `authz/capabilities.md` §12、§18.1／§18.2：授权在治理方实际接纳位置检查，旧 producer 缓存不授予接纳权；已接纳历史不因未来撤销重算。
- `models/realm-and-space.md`：本人退出与成员 FSM。
- `crypto-media/encryption-and-audit.md`：成员变动推进 key-access revision，必须实际 MLS transition 覆盖后才能继续发送；退出者不得获得后续 epoch 新内容。

## 场景与验收

1. 三人分别在 server1／server2／server3 通过 UI 注册；登记响应与公开 resolution 必须绑定各自 Station，三个 StationId 必须不同。
2. 协调方创建 MLS Realm 和最多两账号使用的链接。两远端账号从各自 Station 接受，并由协调方分别显式授予消息写权限。
   两种永久路径均须执行：`concurrent` 保留两个远端在线入组时的原始时序；`late-welcome` 让物流方接受后立即真实断网，协调方先完成两人成员 cut 的 MLS 覆盖，再让审核方加入并推进更晚 epoch。物流恢复后必须通过自己的 Welcome 与连续 tail 赶上，不能只碰巧在同一个 Add 批次入组。
3. 完整三人 joined cut 被 MLS 覆盖后，三人各发真实加密报告，各自跨站解密且只显示一次。私有正文不得出现在 ingress Event 明文。审核方在自身 Station 再创建独立加密审计 Realm，供退出后的活性正例使用。
4. 物流方断开真实浏览器 HTTP，同时退役已建立的所有 Arkret WebSocket；UI 排队一份物流报告。其离线期间协调方新报告在另外两端被接纳，物流方尚不可见；排队报告也不得出现在远端。
5. 重连后排队原 Event 被接纳，原 EventId 和 canonical 字节摘要在重试中保持。物流方补齐离线缺口；再次断连／重连及文档刷新仍只有一份正式消息，outbox 清空。
6. 截住物流方真实客户端已签名的下一条消息请求，仅暂缓运输、不修改 Event 或回复。协调方通过产品 UI 撤销该物流写授权并取得正式 Commit，再放行原请求。必须实际 403／`capability_denied`；不得用过期、登出、错误签名或断网替代权限拒绝。
7. 物流仍为 joined，继续解密协调方的新报告，证明写撤销没有变成成员移除或读权限丢失。被拒消息不得出现在正式共享历史；本人失败意图及明确 failed 状态须在冷恢复后仍保留，不能为了测试删除错误提示或 outbox 记录。合法 EventId 不代表已接纳；不能把表示 ID 格式的 class 当作接纳证明。
8. 审核方在自身 Station 通过 UI 自愿退出；协调方完整 current 中只剩两人，新的 key-access revision 已被更晚 MLS epoch 覆盖。协调方和只读物流方继续交换／读取后续交付结果。
9. 剩余成员刷新后通过真实虚拟列表滚动验证原已接受报告各出现一次，被拒 Event 只保留为本人失败意图。退出成员在独立审计 Realm 实际接纳加密报告，证明账号仍可工作；再次冷打开已退出项目后，要求新的 Online 状态与活跃 WebSocket，原 Realm 无可用发送入口，也看不到退出后新增正文，已观测的 WebSocket rails 不暴露该后继 EventId。不能用断线、全局 Sync stopped 或旧游标当作成功的权限隔离。

每阶段通过后才写 `relief-progress.json`。失败不记后继通过，不从不同轮次拼整体验收。故障 helper 只关闭运输，不伪造任何成功响应；不清浏览器数据库、改游标、拷贝他人 MLS 私态或重签未知写入。

## 执行

正式 `run-joint-e2e.ps1`：`-ServerCount 3 -StartCoauth -StartMockEmail -StartMockWitness -DnsSuffix localhost -RunProfile joint-full -PlaywrightProject chromium -Grep '@cross-station-relief-gate|@three-server-p0' -RequireScenario workflows/cross-station-relief -ForbidSkippedTests`，另提供独占 PostgreSQL 管理连接与数据目录。单个项目与三站 P0 各自记账，不冒称无筛选 full。
