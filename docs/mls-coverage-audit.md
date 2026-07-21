# MLS / E2EE 测试覆盖审计与根因记录

> 起因:新建加密 Realm → 新建 Strand → 添加 Description 报 `content_encryption_floor_violation`。
> 本文记录:(1) MLS 覆盖矩阵与缺口,(2) 本轮补的回归用例,(3) 该 bug 的根因链与修复建议。
> 日期:2026-06-01。

---

## 1. 核心结论

**"创建者 / 单设备的加密 happy-path"被系统性漏测。** 现有加密 e2e 要么走 API 协议层(`mls-group.spec.ts`),要么走"恢复后第二设备"(`key-backup.spec.ts` A1/A2),唯独**刚建完加密 Realm 的创建者本机用 UI 正常操作**这条最常见路径几乎没人覆盖——而这正是用户实际撞到的。

服务端的"拒绝明文写入"被测了(`soland/tests/http_api/lifecycle.rs:444`),错误码字符串被测了(`cotest/src/scenarios/circle/error_code_paths.rs`),但"加密 Realm 下客户端应先加密、写入应成功"的正向路径没人测。

---

## 2. 覆盖矩阵

| MLS 行为 | 状态 | 证据 |
|---|---|---|
| keypackage CAS / welcome 队列 / commit epoch | ✅ active(API) | `e2e/tests/encryption/mls-group.spec.ts`、`tests/mls_lifecycle.rs` |
| 加密消息发送/接收(timeline) | ✅ active | `key-backup.spec.ts` A1、`audited-e2ee.spec.ts` |
| 跨浏览器账户恢复 + 历史解密 | ✅ active | `key-backup.spec.ts` A1 |
| 恢复后第二设备加密 kanban 写入 | ✅ active | `key-backup.spec.ts` A2 |
| key backup 链/单调/前驱 | ✅ active | `tests/key_backup_three_class_scenarios.rs` |
| cross-signing reset 时钟偏移/重放 | ✅ active(soland 单测) | `soland/tests/http_api/events.rs` |
| e2ee relaxed window / metadata floor 收紧 | ✅ active | `scenarios/circle/metadata_encryption_floor.rs`、`e2ee_relaxed_window_negative.rs` |
| **创建者本机加密写入 strand body(description)** | ✅ active **绿(实测真加密)** | `e2e/tests/kanban/end-to-end.spec.ts` E15.7 |
| **创建者本机加密 synthesis** | ✅ active **绿(实测真加密)** | kanban E15.8 |
| **创建者本机加密 discussion comment** | ✅ active **绿(已修复,见 5.A)** | kanban E15.9 |
| **realm encryption_profile create-locked** | ✅ active **绿** | mls-group E11.6 |
| **circle encryption_profile create-locked** | 🔴→fixme **确认 gap**(soland 提交不强制,见 5.B) | mls-group E11.7 |
| **MLS 未就绪时不得静默降级明文** | ⏸️ 本轮补(fixme) | mls-group E11.8 |
| 加密附件上传/下载/缩略图分离 | ✅ active(API/blob 层) | `encrypted-attachments.spec.ts` |
| QR 配对 / MLS Remove 级联 / 设备撤销轮换 | ⏸️ 多数 fixme/ignore | `multi_device_qr_pairing.rs` 等 |
| welcome 部分失败上报 UI | ❌ 缺口(当前静默打日志) | inkson `app.rs` welcome 应用处 |
| metadata_encryption_floor **服务端强制** | ⚠️ 实现疑点(字段存了,疑似未强制) | `soland/src/reducer.rs` ~7102 — **待核实** |

---

## 3. 本轮新增用例

**P0 — 创建者本机加密三连(`e2e/tests/kanban/end-to-end.spec.ts`)**,共享 helper `recordFloorViolations` / `buildEncryptedBoardAndCard` / `setCardDetailEditorValue`,断言以**网络结果**为准(乐观 UI 会掩盖失败):
- E15.7 description(`body` → `ak.strand.update`)
- E15.8 synthesis(`synthesis` → `ak.strand.update`,独立加密+commit 代码路径)
- E15.9 discussion comment(`ak.message.create`,MLS encrypted-payload envelope)

**P1 — create-locked(`e2e/tests/encryption/mls-group.spec.ts`,API 级)**:
- E11.6 `ak.realm.update` patch `encryption_profile` → `realm_encryption_profile_create_locked`
- E11.7 `ak.circle.update` patch `encryption_profile` → `circle_encryption_profile_create_locked`

**P1 — 未就绪守卫(fixme)**:
- E11.8 未收 welcome / 未恢复的同账户新设备写私有内容 → 必须呈现可恢复的"MLS 未就绪"并拒绝,绝不静默降级明文。parked 原因:需第二设备 rig + 实跑确认未就绪 UX。

> 实测结果(见第 4 节):description / synthesis / realm-lock 三个 **active 绿**;discussion(E15.9)与 circle-lock(E11.7)实测**红 → 已转 test.fixme**,各自 `@blocking-on` 一个确认的 bug(第 5 节)。原报告的 description floor-violation bug **不复现、已解决**。

---

## 4. 实测结论(joint-e2e 全栈,2026-06-01,跑了 3 轮)

| 用例 | 结果 | 结论 |
|---|---|---|
| description 加密写入(含"提交体不得含明文"硬断言)| ✅ 真绿 | **原报告 bug 已解决**:strand body 在创建者本机真加密、服务端接受 |
| synthesis 加密写入 | ✅ 真绿 | 同上 |
| realm encryption_profile create-locked | ✅ 绿 | 服务端提交时强制生效 |
| circle encryption_profile create-locked | 🔴 → fixme | **确认 soland 提交时不强制(见 B)** |
| discussion comment 加密 | 🔴 → fixme | **确认 chat 在 wasm 上无法加密(见 A)** |

> **原报告 bug(加密 Realm 加 Description → `content_encryption_floor_violation`)在当前代码 + 干净全栈上不复现、已解决。** 先前怀疑的"客户端 `unwrap_or(false)`(kanban.rs:2686)+ sync 用 `none` 覆盖投影(sync.rs:531 / sync_engine.rs:374)"时序竞态**没有触发**——UI 向导建 realm 时投影已就位、MLS 已就绪,description/synthesis 都正确加密。那两处"未知即明文"默认仍在、是潜在隐患(见第 6 节),但不是这条 happy-path 的实际故障原因。

## 5. 实测挖出的两个确认 bug(已 park 为 test.fixme,待修)

### A. 加密 discussion/chat 消息在 inkson 端从未端到端可用 —— ✅ 已修复(2026-06-01,E15.9 实测真绿)
> 修复方案与执行记录见 `arkret-work/tasks/encrypt_fix.md` / `encrypt_fix_todos.md`。要点:
> SDK 使用唯一权威合规类型 `EncryptedEnvelope`（精确匹配 `ak.schema.encrypted_envelope.v1`，单测绿）；
> soland 移除手写 `validate_encrypted_payload_envelope` 对消息的校验、改由注册 spec schema 唯一把关
> (464+ 测试零回归);inkson 新增 `encrypt_message_with_device_snapshot`(带 aad)+ chat 用
> `encrypted_envelope_from_payload` 产出合规 envelope（key_ref 绑 commit 事件 id）+ 去 wasm 门 +
> 加密 channel 默认 Send 自动 MLS 加密(隐藏明文 Send)+ 乐观回显。E15.9 端到端真绿(提交体不含明文 +
> status<400 + 评论解密渲染)。**以下为原始诊断记录:**

尝试修复时发现是**两层**问题(2026-06-01 实跑确认):
1. **默认 Send 泄漏明文**:卡片 Discussion 默认 Send(`chat.rs` `send-chat-button`)**无条件提交明文** `ak.message.create`,不判断 scope;服务端接受(content_encryption_floor 只管 `ak.strand.*`)。加密发送 `run_local_mls_encrypt`(chat.rs:181)还是 `#[cfg(not(target_arch="wasm32"))]`、wasm 上空桩。
2. **更深:加密 envelope 不合规**(本轮新发现)。去掉 wasm 门 + 让默认 Send 走加密后,服务端改报 `ak.schema.encrypted_envelope.v1 requires field 'version'`。inkson 的消息 `encrypted_payload` 来自松散的 `core::EncryptedPayload`(`group.encrypt_payload`),**缺** `version` / `aad_visibility_event_id` / `aad.{realm_id,event_kind}` / `aad_digest`,且 `key_ref.algorithm` 应为 `"MLS"`。kanban strand 内容"能加密"只因 strand patch 值不走该 envelope schema 校验;消息走,故被拒。**inkson 全仓没有任何合规 envelope 构造**(`aad_visibility_event_id`/`aad_digest` 零出现);合规构造器在 SDK `arkret-rust-sdk/crates/sdk/src/mls.rs` 的 `MessageCrypto::encrypt_with_aad`。
- **修**(sizable):把 inkson chat 消息加密改用 SDK 的 `MessageCrypto::encrypt_with_aad` 合规路径(构造 aad、aad_digest、version、整合 commit),跨 SDK+inkson、需多轮重建。`@blocking-on: inkson#chat-encrypted-message-envelope-nonconforming`。
- 本轮已尝试"去 wasm 门 + 默认 Send 走加密"并实跑:明文泄漏被堵(不再泄漏),但暴露第 2 层后**已 `git checkout` 回退 chat.rs**,避免留下"加密频道发不出消息"的回归。

### B. circle 事件在 soland 提交时跳过全部操作校验(soland)
- `ak.circle.update` patch `encryption_profile` 在提交时被**接受**(realm 同结构却被拒)。
- 根因:`operations.rs` `operation_schema_for_kind`(soland/src/routing/events/operations.rs:897)**没有 `ak.circle.create` / `ak.circle.update` 的 arm** → `projection_operation_from_event`(event_log.rs:3549)返回 `None` → event_log.rs:1174 整段提交时校验(semantics / content_encryption_floor / operation_policy / policy_gate)被跳过。
- create-lock / below-floor 只在异步 reducer 层(reducer.rs:7173 等)兜底 → **状态安全(profile 实际改不了),但提交返回误导性 200**,且 circle 的提交时校验全是死代码。
- **修**:给 `operation_schema_for_kind` 补 circle 两条 arm。需 circle 全量回归(补后 circle 事件会新走 `validate_operation_policy` + `policy_gate`,可能拒掉合法 circle 创建)。`@blocking-on: soland#circle-submit-validation-gap`。

---

## 6. 仍开放的缺口

- **潜在隐患(未触发但应修)**:客户端 `unwrap_or(false)`(kanban.rs:2686)+ 服务端 sync `unwrap_or("none")`(sync.rs:531)两处"未知即明文"默认 + sync 全量覆盖乐观投影(sync_engine.rs:374 / app.rs:10477)。当前 happy-path 未触发,但投影滞后/竞态下仍可能误判明文。建议 fail-safe(未知不得默认明文;sync 不得用 none 覆盖已知加密 profile,该字段 create-locked 永不可变)。
- **createRealmApi 与 soland schema 漂移**:`cotest/e2e/helpers/soland-api.ts:132` 在 realm_create payload 根部放 `plaintext_visible_services`,被现行 schema 拒(波及所有用该 helper 的 e2e)。本审计 create-lock 用例已改用内联 realm 创建绕开,但 helper 本身应修。
- **metadata_encryption_floor 服务端是否真强制**(`reducer.rs` ~7102):子审计称"字段存了未强制",待核实。
- **welcome 部分失败的 UI 上报**:当前 `WelcomeApplyOutcome.first_error` 只打日志,用户可能误以为已就绪。
- **多设备**:QR 配对 / MLS Remove 级联 / 设备撤销后 account-secret 轮换持久化,多数仍 fixme/ignore,等 soland MLS 状态机。
- **commit / strand 两阶段提交原子性**(推断,未逐行核实):MLS commit 事件与业务 `ak.strand.update` 分两次提交,网络中断可能导致 epoch 推进但业务补丁丢失。
