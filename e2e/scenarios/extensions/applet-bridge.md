# Applet 桥接：Service 安装、独立 Bot 与 Ghost

## 目标

以最新正式 v1 验证 Service-only 安装、独立 Bot 四 Event provision、Ghost 创建、真实 Service parent 到受管 Account 的终端授权、Service 本人入站 transaction 与撤销屏障。主流程验证创建问责闭包，以及非法 Service 代签不写入 history 和 Inkson timeline。每个 case 独立创建身份和 Realm。

本场景不声称覆盖管理审批 ledger、共享 quota、多 parent 执行、无 session Device bootstrap、设备群内容接收、MLS/附件解密回复或跨 scope 完整恢复矩阵。这些仍由 arkret-work 的 0847/1725 owner 承接；协议参考模型、组件 KAT 与历史 run 均不能替代当前 live 验收。

## Spec 锚点

- `extensions/applet-integration.md`：mandatory HTTPS 管理 base_url、Service-only install、独立 Bot/Ghost、completion、授权与 revoke。
- `applet-install-operations.schema.json`：安装只提交 package、原签 authoring basis 与 plan_digest。
- `applet-bot-operations.schema.json`：Service RFC9421 preview/provision；0..N 个 Bot 各有 Account/PCR。
- `applet-ghost-operations.schema.json`：full-scope fresh/reuse 互斥；reuse 保留原 accepted anchors，不重复创建。
- `capabilities.md` §10.1 与 `constraint-schema.md`：Service 原签 terminal child 必须来自真实 Service parent，创建授权不授予业务权。
- `managed-governance.md` §4 与 `applet-authority-material.schema.json`：Service 原签读取自己的指定 parent 原文和同快照 current，审计读取不授予业务权。
- `applet-edge-operations.schema.json` 与 `service-http-binding.md`：transport 来源签名不替代每条 Event 原签；群内容不向 base_url 推送。

## 拓扑与身份

runner 启动最新 Soland、Coauth、Inkson 与 mock-applet-registry。Applet 的公开管理 base_url 是 runner CA 认证的 HTTPS 地址，Caddy 转发至私有本地监听端口。`COTEST_MOCK_APPLET_REGISTRY_BASE_URL` 注入该公开地址，`MOCK_APPLET_REGISTRY_PUBLIC_BASE_URL` 用于签署 package。

管理员通过 canonical Coauth/Station provisioning 获得自己的 Account/session。Applet Service 无 Account session；Bot/Ghost 创建由 Service 原签 RFC9421 调 Station，业务 Event 通过 Applet→Station transaction 入站。每个 Bot/Ghost 使用独立 did:webvh inception 与 method-history evidence，ActorId 是完整 Account，不能用 DID/Core 字符串代替。

mock 的 JavaScript 只编排 HTTP 和 durable replay，原四 Event、proof、digest 与 closed carrier 由最新 `cotest-wire` 的 SDK kernel 构造及验证。Service/managed 私钥和 replay 材料以 run-scoped AES-256-GCM key 加密落盘；artifact 不保存明文私钥。

## Steps

1. 创建 Realm，管理员签署 registration 与授予 Service 的 capability grants。安装 preview 返回 plan，commit 提交原 basis 与 caller 自算 plan_digest。断言 installation 不含 Bot/PCR/Profile/accountability anchors，也没有 managed provision Event。
2. Applet Service 发起 Bot preview，把 Station 原签 authoring_request 送至管理 author endpoint，持久保存独立身份及四 Event bundle，再原样 provision。断言每个 outcome 的 managed provision/PCR/Profile/accountability anchors 完整且独立；新增 case 在同一安装创建 Bot A/B。
3. 为 Bot 建立管理员→Service 的真实 parent。fixture 的管理员 history 只定位 grant IDs；Service 通过原签 `authority/material` 取得自己指定 grant 的 accepted Event／Commit 和带 Realm／generation／真实 head 的 current。随后由 Service 原签创建 terminal child，subject 是 accepted Bot Account，authority refs 指向该 parent，ordinary role/control 与 Applet epoch/scope 约束齐全。管理员发 directed invite；Service 代签的 `ak.invite.accept` 必须拒绝且不入 history。terminal child 授给 Bot，不能授权 Service 代替本人接受 Invite。
4. 对首次外部用户执行 Ghost Service preview→author→provision。普通 Event submit 不得接纳单独 managed PCR genesis。原四 Event 中 provision/accountability 与 PCR genesis/Profile 使用其各自实际 Realm；业务授权与入场再按步骤 3 建立。
5. mock 故意构造非法 Ghost 代签：Account actor、Service executed_by、terminal child authorization_ref 与 Service proof。合法 HTTP 来源签名不能使其业务 Event 合法；transaction 必须拒绝、无 Commit refs、无 history 或 timeline 文本。直接绕过 mock 的同类 Event 同样拒绝。独立保留真实创建 Profile/accountability/registration 闭包验收。
6. 管理员以 exact full scope preview revoke，签原 capability/membership revoke Events，再提交计划 digest。断言后续入站与直接 Event 旁路受 revoke fence 拒绝，历史 creation/PCR/问责保留；不把 scoped revoke 等同于全局 Device 撤销。

## Observable assertions / sub-tests

- Service-only install 无 Bot；同一安装可产生两个独立 Bot。
- namespace 冲突、Controller/Service 身份混用、package body/proof 篡改均拒绝。
- caller-signed registration manifest 是 epoch evidence 唯一载体；旧 install bundle 无效。
- 同 key/body replay 返回字节稳定原 outcome；同安装换 key 冲突。
- 业务 child 有真实 Service parent，provision/registration/accountability 不替代普通业务授权。
- 入站 transaction 接纳真正 Service 本人的 `ak.applet.bridge_error`，引用自己的 Service parent；错误 Event proof 逐条拒绝，旧 proofs carrier 整体拒绝。
- child subject 必须匹配实际 producer；Bot/Ghost child 不能被 Service 借用，subject_only 入场不能被代签。
- 缺 RFC9421 签名、伪签名和过期窗口返回各自正式错误码。
- 撤销与入站竞争要么唯一接纳、要么不入 history；历史 resolution 保留，current authoring fence 关闭。
- 已删除的私有 Bot write route 不恢复。

## 验证入口

```powershell
$env:CARGO_BUILD_JOBS = '4'
.\scripts\run-joint-e2e.ps1 -StartCoauth -StartMockAppletRegistry -DnsSuffix localhost -RunProfile joint-full -PlaywrightProject chromium -Grep 'applet bridge|applet inbound transaction push' -RequireScenario extensions/applet-bridge -ForbidSkippedTests
```

必须使用冻结源码构建的最新 SUT、SDK kernel 与 Inkson bundle。原有 July/October 旧合同通过记录仅作历史，不作为本批证明。当前实测结果由本次子项目同步报告及 run artifact 记录。
