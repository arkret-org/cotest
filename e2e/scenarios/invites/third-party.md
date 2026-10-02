# 第三方邀请：allowlist、单次提交与 claim

## 执行范围

`tests/invites/third-party.spec.ts` 包含六条服务契约或 mock 测试。它们通过 API
验证 invite 创建、claim 和不可枚举拒绝；不包含 Invite-by-email UI、最终
`ak.invite.accept`、成员消息或 MLS Welcome。这些产品验收仍由对应实现 owner 承接，
不能从本组通过推断已经完成。

## Spec 锚点

- `sync/third-party-invites.md` §2.1：当前 Realm policy 的 verification service allowlist。
- 同文 §3.1：公开 invite 只包含盲化 commitment 和验证服务绑定，不含明文 3PID/token。
- 同文 §4.2–§4.3：binding/subject transcript、确切 authority cut 与 claim 状态转换。
- 同文 §6：过期、已认领等外部 claim 失败保持不可枚举。
- `sync/authority-commit-log.md`：单次 Event 提交返回覆盖该 Event 的确切 RealmCommit。

## 拓扑与前置

- Soland 与 Coauth 提供真实注册、Standard session 和逐请求 DPoP。
- Alice 与 Bob 使用已接受 PCR 身份；Mallory 只用于 subject 不一致反例。
- 验证服务 DID、临时密钥和签名 transcript 由 fixture 构造。
- mock-email 是独立 harness 依赖；仅第二条 broker 测试在未配置它时跳过。
  官方完整全量须启动 mock，并保留 `ForbidSkippedTests`。

## 单次提交验收

所有 Realm Event 通过 `POST /_arkret/self/events` 的单次 submission 提交。
成功必须返回 `committed` 或 `duplicate`，并通过共用
`assertAuthoritySubmitOutcome` 精确核对 Commit 的 Event ID、scope 对应 stream、
整数 stream position 和 predecessor；禁止接受退休 batch `accepted[]` 或
`rejections[]` 格式。失败读取 registered Problem `type` 与 `detail`。
fixture 中的 accepted/rejected 数组仅为本地断言视图。

Claimant 不读取 membership-private frontier；它向自己的 Account Station 提交
签名 claim，由 Station 绑定新鲜 producer evidence。

## 六条完整测试

1. **创建与隐私**：verification service 未 allowlist 时创建拒绝为
   `capability_denied`；Alice 更新当前 policy 后同一邀请成功。
   durable payload 包含 commitment，不包含明文邮箱、电话、token salt。
2. **邮件 broker**：mock-email 投递 token，Bob 从 inbox 获取后 claim 成功，
   返回 binding artifact；第二次 broker claim 返回 409。这是 mock 契约测试，
   不替代正式 open present-token operation 的端到端验收。
3. **合法 claim**：验证服务签 binding proof，Bob 用当前有效身份签 subject
   proof，提交成功；通过标准 authz invite list 读回精确 Bob AccountId
   （principal 与 station）、Realm 和 `claimed` 状态。它是后续成员确认的 proposal，
   不能当作已加入或 MLS 可写。
4. **E3.1 过期**：以已过期的签名 claim 时间提交，零接受，外部返回 `not_found`。
5. **E3.2 subject 不一致**：binding proof 指向 Bob、subject proof 与提交者为
   Mallory，零接受，返回 `schema_violation`；detail 不泄露两者身份或 commitment。
6. **E3.3 重复认领**：首次 claim 必须真正接受一个 Event；新 nonce 再 claim
   已认领邀请，零接受，外部返回与不存在/过期同形态的 `not_found`。

## 尚未由本组覆盖

Invite-by-email 与 verification 等待 UI、正式 provision/activate/delivery/present
产品链、verification service 离线、Alice 撤销后 claim、最终成员接受与
E2EE Welcome/实际消息仍须独立验收。旧 scenario 的 UI 与 MLS 步骤不能作为
这六条 API/mock 测试的已执行证据。
