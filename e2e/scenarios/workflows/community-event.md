# 三人社区活动交付

## 目标

在同一个真实项目内，由三个独立浏览器账号完成入组、分工、加密交付说明、讨论、海报附件与刷新恢复。每个阶段必须实际完成后才写入 `project-progress.json`；前一阶段失败不得把后续阶段记作通过。

## 规范依据

- `models/realm-and-space.md`：Realm 与 Board/List 的成员及容器边界。
- `sync/realm-invite-links.md`：受限邀请次数与入组不隐式授予写权限。
- `models/relation.md`：`assigned_to` 由独立 Relation 记录表示。
- `models/strand-and-message.md`：卡片 Strand 与讨论 Message。
- `crypto-media/encryption-and-audit.md`：MLS 私有内容与接收端解密。
- `crypto-media/media-and-blob.md`：附件引用、私有描述与密文字节载体。

执行时以当前 Spec 的上述主题实际文件与机器工件为真相源；测试不定义新的 wire 字段或权限。

## 拓扑与角色

真实 Coland、独立存储的 Coauth、Inkson、TLS 代理与邮件验证码投递夹具。邮件夹具只提供注册邮件，不替代产品注册、OAuth、设备入册、MLS、同步或存储。

| 角色 | 职责 |
| --- | --- |
| Alice | 项目经理、场地确认、建板与显式分工 |
| Bob | 海报设计、提交最终图片 |
| Carol | 志愿者招募、提交人员确认 |

## 流程与断言

1. 三人经产品 UI 注册、验证邮箱、保存确认恢复密钥并建立各自设备身份，等待真正上线及正式游标。
2. Alice 创建 MLS Realm，发布最多供两个不同账号使用的分享邀请。Bob、Carol 正式接受。Alice 分别显式授予消息创建权限。
3. 在同一完整 current cut 中确认三人的 joined ActorId 且 MLS 已覆盖当前 key-access revision；三人实际解密项目启动消息后，再由 Alice 创建交付 Board 和 List、场地／海报／志愿者三张卡片，保存各自加密说明，并通过 UI 建立对应完整 ActorId 负责人 Relation。每次重新打开选择器必须仍勾选正确负责人。
4. 所有写入要求真实 authority `committed` 回执；三人分别打开全部卡片，读到完整说明及负责人，锁定占位不得出现。卡片私有说明不得明文出现在 Event ingress。
5. 三人各自发布负责交付的报告，所有成员必须各看到且只看到一份，消息正文不得明文出现在 Event ingress。
6. Bob 用真实文件选择器发送最终海报。三人解密后的图片 SHA-256 必须与原始文件完全一致；提交须包含 Blob 引用，文件名不得明文出现在 Message Event。
7. 三人分别进行文档刷新，讨论仍只出现一份；重新进入 Board，全部卡片说明及负责人仍正确且可解密。
8. Alice 将志愿者卡片从 Carol 交接给自己，再交回 Carol。每次须取得原 Relation 的正式 tombstone 与新 Relation 的 committed 回执，确认删除的是原边、新边指向完整 ActorId 且 ID 不复用。三人逐次刷新后都只看到一位正确负责人，加密说明保持原样；重新分配给曾被移除的 Carol 必须建立有效新边。
9. 三端刷新后的 Board／List 标题须完成解密，Presence 名称不得显示内部 ActorId JSON。保存实际卡片详情、加密讨论、桌面与手机看板截图，并验证手机最后一张卡片可滚动到视口。Carol 在 390×844 窗口切换 Realms、Contacts、My agents，列表无入场动画；从账号进入 Settings，子项返回列表、列表返回账号，直接访问 Settings 同样可返回账号。截图只在恢复密钥等私密界面关闭后通过公共截图边界保存。

连续建卡须先关闭详情并回到 Board，确认标题已被编辑器接收，再观察产品同步清空原草稿的交接。仅在草稿仍原样保留、尚未交接时允许重试 UI 激活；不得重发网络 Event 或绕过写入拒绝。消息去重断言必须匹配全部实际消息，不得用固定取第一条的定位器证明唯一。

负责人筛选只准备本地查询：激活目标页面、读取当前输入框值并等待唯一候选；卡片刷新替换输入框时可有界重填同一查询。此准备函数不得选择成员、保存负责人或提交 Event；勾选、回执与三方持久状态继续独立核对。

卡片关闭须同时等待详情消失且 URL 回到原 Board，才刷新或打开下一张卡片。点击关闭按钮返回不等于路由已完成；在旧 task URL 上刷新会按正常产品路由重新打开详情。

本流程验收项目交付信息的多人持久协作，不把 List 位置或归档当作 Strand `stage` 的替代。拒绝边界、失包恢复与大附件分段由既有具名测试继续覆盖。

## 入口

`run-joint-e2e.ps1 -StartCoauth -StartMockEmail -DnsSuffix localhost -RunProfile joint-full -PlaywrightProject chromium -Grep '@community-event-gate' -RequireScenario workflows/community-event -ForbidSkippedTests`，并显式提供本轮 PostgreSQL 管理连接及数据目录。构建与二进制来源由正式 runner 记录。
