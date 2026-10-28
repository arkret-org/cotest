# 真实浏览器 Contact 请求与接受

## 范围

两个独立浏览器上下文分别完成普通注册、OAuth、恢复密钥确认及身份创建。发起者使用接收者真实发布的 locator，在普通 Inkson 页面完成 Contact 请求；接收者分别从联系人侧栏及重新打开的联系人页面接受。此场景保留 Inkson #32 的失败边界，不使用 API helper 代替 UI 接受。

## Spec 锚点

- `identity/contact-and-direct-conversation.md` §2：准备、原事件签名、提交和最终接纳凭据。
- `principal-operations.schema.json#/$defs/prepared_event_draft`：原 canonical 字节和固定 SHA-256 digest。
- `contact-operations.schema.json`：完整 Account、operation/idempotency/reservation 及请求／响应凭据绑定。

## 断言

1. 请求 commit 返回最终 `accepted`，不能以 prepare 或临时 admission 代替。
2. 接受的 prepare 与 commit 保留相同 operation、idempotency 和 reservation。
3. 解码 prepare 原字节并核验 canonical JSON 与 digest；commit 只能增加事件标识和 producer proof，原 digest payload 完全相同。
4. 签名 actor 是接收者完整 Account，签名方法是该浏览器注册的原 DID/Device，响应 receipt 绑定同一事件及同一原请求凭据。
5. 双方出现联系人入口；发起者刷新后仍存在。

`cold` 变体会完整重新加载联系人路由，一旦 incoming 行出现就点击，不先等待 Online 掩盖启动期；提交接纳后才核验最终 Online。它不声称覆盖所有网络调度，若后续生命周期修复需要，还应补受控的卸载／凭证刷新反例。

联系人地址文案另有独立用例，核验只宣传 locator 和完整账户地址。

事件只由普通 Inkson 客户端签署和提交；Cotest 的 SDK wire oracle 仅校验 canonical JSON 和推导原事件 ID，证据清单显式保留该参与者。
