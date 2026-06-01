# MLS / E2EE 测试覆盖审计与根因记录

> 起因:新建加密 Realm → 新建 Flow → 添加 Description 报 `content_encryption_floor_violation`。
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
| **创建者本机加密写入 flow body(description)** | ✅ 本轮补(active,当前红=复现 bug) | `e2e/tests/kanban/end-to-end.spec.ts` E15.7 |
| **创建者本机加密 synthesis** | ✅ 本轮补(active,当前红) | kanban E15.8 |
| **创建者本机加密 discussion comment** | ✅ 本轮补(active,当前红) | kanban E15.9 |
| **realm encryption_profile create-locked** | ✅ 本轮补(active,应绿) | mls-group E11.6 |
| **circle encryption_profile create-locked** | ✅ 本轮补(active,应绿) | mls-group E11.7 |
| **MLS 未就绪时不得静默降级明文** | ⏸️ 本轮补(fixme) | mls-group E11.8 |
| 加密附件上传/下载/缩略图分离 | ✅ active(API/blob 层) | `encrypted-attachments.spec.ts` |
| QR 配对 / MLS Remove 级联 / 设备撤销轮换 | ⏸️ 多数 fixme/ignore | `multi_device_qr_pairing.rs` 等 |
| welcome 部分失败上报 UI | ❌ 缺口(当前静默打日志) | yougen `app.rs` welcome 应用处 |
| metadata_encryption_floor **服务端强制** | ⚠️ 实现疑点(字段存了,疑似未强制) | `soland/src/reducer.rs` ~7102 — **待核实** |

---

## 3. 本轮新增用例

**P0 — 创建者本机加密三连(`e2e/tests/kanban/end-to-end.spec.ts`)**,共享 helper `recordFloorViolations` / `buildEncryptedBoardAndCard` / `setCardDetailEditorValue`,断言以**网络结果**为准(乐观 UI 会掩盖失败):
- E15.7 description(`body` → `cx.flow.update`)
- E15.8 synthesis(`synthesis` → `cx.flow.update`,独立加密+commit 代码路径)
- E15.9 discussion comment(`cx.message.create`,MLS encrypted-payload envelope)

**P1 — create-locked(`e2e/tests/encryption/mls-group.spec.ts`,API 级)**:
- E11.6 `cx.realm.update` patch `encryption_profile` → `realm_encryption_profile_create_locked`
- E11.7 `cx.circle.update` patch `encryption_profile` → `circle_encryption_profile_create_locked`

**P1 — 未就绪守卫(fixme)**:
- E11.8 未收 welcome / 未恢复的同账户新设备写私有内容 → 必须呈现可恢复的"MLS 未就绪"并拒绝,绝不静默降级明文。parked 原因:需第二设备 rig + 实跑确认未就绪 UX。

> 预期红绿:P0 三个当前**红**(复现客户端 bug);P1 create-locked 当前应**绿**(soland 已强制,仅补覆盖)。第一次实跑请重点确认 create-locked 真绿——若红,说明服务端强制也回归了。

---

## 4. 根因链:为什么加密 Realm 下添加描述会 412

客户端是否对私有内容加密,取决于 `selected_scope_security_encrypted`,它**纯粹**由本地 `state.space_projections[realm_id]` 经 `realm_projection_is_encrypted` 推导:

```
yougen/src/views/kanban.rs:2671-2687
  security_projection_for_scope_id(space_projections, realm_id)
    .map(realm_projection_is_encrypted)
    .unwrap_or(false)          // ← 危险默认:状态未知 = 当作明文
```

数据流与缺陷:

1. **建 Realm 时写了正确的乐观投影**(`views/setup.rs:1132`,body 带 `encryption_profile = mls_rfc9420`,顶层 + `summary` 双写)。判定函数本身没问题。
2. **account-sync 全量覆盖乐观投影**:`sync_engine.rs:374` 与 `app.rs:10477` 都是 `save_space_projection(id, body)` 直接覆盖,不 merge。
3. **服务端 sync body 在 meta 未就绪时回退 `"none"`**:`soland/src/routing/events/sync.rs:528-531` —
   ```
   let encryption_profile = meta.and_then(|r| r.encryption_profile.clone())
       .unwrap_or_else(|| "none".to_owned());   // ← 同样的危险默认
   ```
   realm 刚创建、`realm_meta` 投影尚未 settle 时,sync 发出 `encryption_profile: "none"`,**盖掉**客户端正确的乐观投影。
4. 用户随即打开看板加描述 → 客户端读到 `"none"` → 判定明文 → 跳过 MLS 加密 → 提交明文 `body`。
5. 此时服务端 `realm_meta` 已 settle(floor 检查能拒绝就证明写入时 meta 已带 profile)→ `validate_content_encryption_floor` 返回 412 `content_encryption_floor_violation`。

**两处"未知即明文"的危险默认叠加**:客户端 `unwrap_or(false)`(kanban.rs:2686)+ 服务端 `unwrap_or("none")`(sync.rs:531)。两者都把"我还不知道"误当成"明文 OK"。

## 5. 修复建议(让 P0 三个用例转绿)

按性价比排序:

1. **客户端 fail-safe(首选)**:加密状态未知/投影缺失时,**不得**默认明文。要么把写私有内容的入口置为"加载中/不可写",要么默认按加密处理并等投影确认。即移除 kanban.rs:2686 的 `unwrap_or(false)` 危险默认。
2. **sync 不要用 `"none"` 覆盖已知的加密 profile**:`save_space_projection` 在合并 realm body 时,若新 body 的 `encryption_profile` 是缺省/`"none"` 而旧投影是加密,应保留旧值(create-locked 字段本就不可变,绝不应被"降级覆盖")。
3. **服务端 sync.rs:528 不要在 meta 缺失时回退 `"none"`**:meta 未就绪时应省略该字段(让客户端走 fail-safe)或阻塞 sync 直到 meta settle,而非主动报"明文"。

> 注:realm `encryption_profile` 是 create-locked、永不可变(E11.6 守卫),因此任何把它"覆盖/降级为 none"的代码路径都是错的——这是上面 #2/#3 的硬依据。

---

## 6. 仍开放的缺口

- **metadata_encryption_floor 服务端是否真强制**(`reducer.rs` ~7102):子审计称"字段存了未强制",若属实是真实安全洞,需单独核实并补强制 + 测试。
- **welcome 部分失败的 UI 上报**:当前 `WelcomeApplyOutcome.first_error` 只打日志,用户可能误以为已就绪。
- **多设备**:QR 配对 / MLS Remove 级联 / 设备撤销后 account-secret 轮换持久化,多数仍 fixme/ignore,等 soland MLS 状态机。
- **commit / flow 两阶段提交原子性**(推断,未逐行核实):MLS commit 事件与业务 `cx.flow.update` 分两次提交,网络中断可能导致 epoch 推进但业务补丁丢失。
