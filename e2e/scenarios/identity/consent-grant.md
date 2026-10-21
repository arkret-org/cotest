# 完整 peer Consent 编辑与显式清空

本场景对应 `e2e/tests/identity/consent-grant.spec.ts`，验证 Inkson 的完整集合编辑。正式定义以 `arkret-spec/spec/v1/zh/identity/consent-model.md` 及 `consent-operations.schema.json` 为准。

## 原理与规则

- Consent subject 是 holder 的实际 inception PCR 与完整 peer ActorId；Account 必须包含 Station，Realm actor 必须包含 Realm。Contact 的方向 current、成立 round 和固定私聊身份独立运行，不由 Consent 自动建立或撤销。
- 每个 peer 只有一份 permissions，最多包含 Invite、Voice、Video、Presence 四项，按正式顺序且各项唯一。没有原生 consent_id、Any、OR 集合或多个独立 grant。
- 编辑前必须取得本人认证的完整 current read；Present 提供全部条目及 exact revision，NeverWritten 是独立认证的 absence。列表摘要只展示 permission_scopes，不能作为编辑前态。
- holder root Device 原签 `ak.consent.replace`，沿统一耐久提交路径提交完整目标集合与 expected_current。CAS 失败必须重新读取并让用户确认，不自动合并或重签原提交。
- 未来、过期或带未知 constraints 的条目不授权，但编辑必须保留其窗口、约束、evidence_ref、reason 及 optional 字段的存在性。
- 显式 permissions=[] 产生真实 Present revision。清空后完整读取不能退回 NeverWritten；到期本身不产生新 Event。

## 拓扑与前置

使用真实 Coland、Coauth 与 Inkson 联合栈，两个独立 Account 经过正常注册与 DPoP SessionGrant 登录。沿现有用户/browser helper 提供的上下文调用正式 `/_arkret/...` 接口，不使用旧私有路由或伪造 session。

## 执行步骤与断言

1. holder 打开 `/settings/consent`，显式输入 peer principal 与 Station，读取完整 peer current。
2. 在四项编辑器启用 Voice，填写已过期窗口、未知 constraints 和 reason，提交完整替换；摘要仍列 Voice。
3. 再次完整读取，确认所有 inactive 字段原样保留；添加 Presence 后提交，摘要变为 Voice、Presence，revision 前进。
4. 再次完整读取，关闭全部已存 scope，提交显式空集合；摘要为空但 revision 仍存在并前进。
5. 再读完整 current，四项 checkbox 均未勾选；不把空集合视为从未写入。

## 验证边界

浏览器场景只证明完整编辑与摘要展示。真实并发 CAS、同 principal 不同 Station、MIMI 原件恢复、quarantine、Invite、Call/RTC 与 ConsentOnly Presence 由 owning Rust/PG/live suites 负责。实际执行、SUT hash、源码与未跑项见协调仓 `reports/2026-10-21-message-binding-consent-implementation.md`，不能用生成检查或 browser skip 代替真实通过。
