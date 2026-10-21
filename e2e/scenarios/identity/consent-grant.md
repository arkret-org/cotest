# 完整 peer Consent 集合编辑

正式依据：`arkret-spec/spec/v1/zh/identity/consent-model.md` 及对应机器 schema。

每个完整 peer ActorId 对应 holder PCR 内唯一完整 permissions current；同一 principal 的不同 Station 属于不同 peer。摘要列表只用于展示，编辑必须先取得同一 cut 的完整 present 或 never_written，再以其精确 revision CAS 提交单份 holder root 签名的 `ak.consent.replace`。

浏览器用例位于 `tests/identity/consent-grant.spec.ts`，覆盖：

- 完整读取、保留过期／未来窗口、未知 constraints 与 optional 成员存在性；修改单一 scope 时保留其它原始项。
- 空 permissions 仍为 present，旧 revision 和 never_written 均不能重新覆盖；完整 peer 的 Station 隔离。
- 旧签名请求精确重放返回原结果且不回滚较新的完整集合。
- 设置页先读取完整原值，再显示真实 before/after，并仅在显式确认后写入；成功或未知结果后不能重复使用旧确认。
- Contact 请求不创建 Consent，Consent 替换不接受或关闭 Contact。
- outbound request 仅允许 voice_call、video_call、presence；常量不透明响应不创建 requester 可见授权状态。
- MIMI consent_id 仅作 provider 相关性标识，Native Event 使用完整 peer/CAS/permissions；精确历史重放不能重新应用旧权限。

消息辅助代码本地生成 Event、proof 与 MLS ciphertext，并固定提交 bytes；任何传输重试复用同一请求。不存在远端普通消息准备包装。

类型由 `scripts/generate-wire-types.mjs` 从正式 schema 生成。静态类型检查与 schema 重生成检查不代替 live SUT 验收。
