# Account stream 与 durable 重连

规范：`sync/client-sync.md` §§2–3、§11–12；`conformance/encoding.md` §8.3.1；`sync/service-http-binding.md` 的 `ak.self.account.stream.subscribe.v1`。

来源和其余设备消息设计见 [Complement 补测复核](../../../docs/complement-coverage-review.md)。该文件名保留既有 lane 身份；当前十条测试入口验证 account stream，不能据此宣称跨站队列或浏览器持久化已覆盖。设备消息 ACK 另在 Rust `tests/to_device_offline_ordering.rs` 新增五条合同测试，不计入这十条 joint-api 用例。

| 用例 | 成功证据 | 失败边界 |
| --- | --- | --- |
| 有界 long poll | 无变化约 30 秒 frontier，下一轮有变化提前唤醒 | 其它 Realm 活动不提前结束过滤后的流 |
| 断线 + 丢失响应重试 | baseline→三条离线消息→旧 cursor 两次完整集合→新 cursor 单条 sentinel | 不漏、不重复、不重放 baseline 消息 |
| Realm filter | 无 filter 可读两个 Realm；有 filter 只返回指定一个 | 使用规范 `realms`，不使用实现私有字段名 |
| timeline_limit | 无限制时可见五条；每 frame 最多两条 | 截断必须 limited 且有 window-start state 或 preview_only；允许分多帧完整返回 |
| Event kind filter | allow list 可见新消息，deny list 不见 | timeline 过滤不应抹去 Realm 当前态 baseline |
| 旁观账号 | owner 可见私有 Realm 消息 | outsider initial 不含该 Realm 和 Event ID |
| 跨账号 cursor | 原账号有合法 baseline，负例后继续成功 | 400 cursor_integrity_invalid，无 realms payload |
| 跨 filter cursor | 原 filter 有合法 baseline，负例后继续成功 | 400 cursor_integrity_invalid，不能用新 filter 续读旧 scope |
| filter 集合规范化 | Realm/kind 排序和重复项变化后，旧 cursor 可继续读唯一 sentinel | 等价集合不能误判 scope 改变 |
| 非法 filter | 各负例拒绝后，合法 initial 仍成功 | 非法类型、重复 scalar、未知字段、无效 Realm 不得被忽略并扩大订阅 |

各测试独立创建账号和 Realm。Coauth 缺失会失败，不跳过；认证采用真实 onboarding 后的 DPoP grant。`joint-api` 从现有 migration manifest 选择本文件，完整浏览器 lane 也会收集，但这些用例本身不启动浏览器。执行是否通过看实际 JUnit，测试名和此表都不充当通过证据。
