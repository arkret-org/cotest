# Applet 桥接：Service 安装与 Realm Bot／Ghost

## 范围

验证 Service-only 安装、独立 Realm Bot／Ghost 创建、Service parent 与受管主体 terminal child、入站 transaction 的生产者边界、精确 Service 撤销，以及 Inkson 不展示被拒绝的伪造消息。普通 Account／个人 Agent 不变；受管主体没有 AccountId 或独立 PCR。

这组浏览器联合场景不能单独证明设备入群、MLS／附件解密、独立恢复或分批更换 Service。它们由 Coland 的真实 `realm_actor_control`、`applet_admission` 及 Bridges runtime 场景验证，结果汇总到 arkret-work 唯一 0847 owner。

## 正式依据

- `extensions/realm-actors.md`：完整 ActorId.realm、独立 DID、Realm 私有控制流、设备与同身份恢复。
- `extensions/applet-integration.md`、`extensions/applet-schema.md`：Service-only 安装、独立创建、来源验证、transaction 与撤销。
- `applet-install-operations.schema.json`、`applet-bot-operations.schema.json`：精确 Service、scope、签名 CAS 和计划摘要。
- `capabilities.md` §10.1：真实 Service parent、主体 terminal child 和独立生产者证明。

## 拓扑

runner 启动冻结源码的 Coland、Coauth、Inkson 与 mock-applet-registry，公开地址通过 runner CA 的 HTTPS 反向代理访问。管理员使用真实 Account/session；Applet Service 使用 RFC9421 签名，没有用户 session。Bot／Ghost 使用独立 WebVH inception 和控制密钥，完整身份为所属 RealmId 与稳定 DID Core 组成的 RealmActorId。

mock 只编排 HTTP 与耐久重试。身份、签名、closed carrier 和摘要由 SDK 的 cotest-wire 生成／验证。私钥和重试材料在 run-scoped 加密存储中保留；原始证据不写入协调仓。

## 验收步骤

1. 管理员签署 registration 与实际 Service grants。登记签名包含精确 Realm／Applet／Service 的 expected_revision；首次登记为 null。安装 preview／commit 不隐式创建任何 Bot、Ghost、Device 或 PCR。
2. Service 按明确 service_id 与 scope 申请 Bot 候选。Applet 生成独立 DID 与持钥证明，Service 原签 realm.actor.create 经治理站接纳至 realm_control。一个安装分别创建两个不同 Bot，原创建不泄露进普通 Realm 内容流。
3. 按真实 parent 原件和同截点 current 签发 terminal child。HTTP 来源签名不代替 Realm Actor 生产者签名；Service 冒充 Bot／Ghost 的入场及业务事件必须被拒绝且不新增历史或客户端消息。
4. Ghost 按外部 tuple 独立创建。取消 Actor DID namespace 限制；Realm／portal 和 handle namespace 仍按原登记约束验证。
5. 管理员明确 service_id 和 scope，读取撤销预览，签原 capability／membership 效果，再按计划摘要提交。返回的是真实 Commit 引用或本地 fence 引用，不把主体 DID 当作撤销结果。历史创建保留，新的业务由当前 fence 拒绝。
6. 验证同 key／body 重试恢复原结果、篡改 package／proof 拒绝、缺失／伪造／过期 HTTP 签名拒绝，以及撤销与 transaction 竞争的唯一接纳或零写入。

7. Inkson 配置入口遇到 Applet 不提供配置端点时，真实治理站拒绝请求。浏览器重载仍保留原名称、请求编号、Service 和 scope；恢复与重试沿用原意图，不产生新请求或把未知结果当成功。配置成功和候选审批链路另由真实 Applet runtime／治理站 HTTPS 场景验证。

## 运行

```powershell
$env:CARGO_BUILD_JOBS = '2'
.\scripts\run-joint-e2e.ps1 -StartCoauth -StartMockAppletRegistry -DnsSuffix localhost -RunProfile joint-full -PlaywrightProject chromium -Grep 'applet bridge|applet inbound transaction push' -RequireScenario extensions/applet-bridge -ForbidSkippedTests
```

必须记录实际冻结源码、当前 SUT、命令、退出码及失败；类型检查或旧运行记录不能代替本轮联合验收。
