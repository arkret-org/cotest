# 跨成员加密聊天消息被丢弃 —— 矛盾信号与开放问题

> Follow-up 记录。`encryption/mls-group.spec.ts` 的 "joined member decrypts E2EE
> timeline messages" 在真栈(`-StartCoauth`)下跑穿了整条 MLS 链,但最终 bob
> reload 后看不到 alice 的加密聊天消息(讨论区 "No messages yet")。
> 姊妹的**看板**跨成员测试(`kanban/cross-member-encrypted.spec.ts`)已真绿——
> 看板卡内容解密**不走**聊天的 receiver-proof 门,所以看板绿、聊天红。
>
> 本文只记录**已确认的事实**与**互相矛盾/尚未解释的信号**,给下一个接手的人。

## 已确认的事实

1. **soland 确实投递了消息。** 以 bob 身份查 `/_cokret/self/events?realms=` 含
   alice 的 `ck.message.create`（`hasAliceMsg=true`）。非投递问题、非
   history_visibility 裁剪（消息是 bob 加入后发的）。

2. **丢弃点 = 聊天 receiver-proof 门。**
   `yougen/src/views/chat/model/events.rs`：
   - `chat_message_from_event_with_sidecar` 开头 `verify_chat_envelope_proof(event)`，
     verdict==`Rejected` 直接 `return None`（消息不进列表）。
   - 插桩证明 bob 对 alice 消息 verdict=**Rejected**，reason=**`sig_verify_failed`**：
     `cached_device_signing_key(actor, device)` 是 **Hit**（key 解析到了），但
     `verify_persistent_envelope_proofs` 验签**失败**。
   - 即：**目录里 alice 设备的签名 key ≠ alice 消息 proof 的签名 key。**

3. **解密不是问题。** 即便解密失败，`events.rs:434` `None if has_encrypted_payload
   => String::new()` 仍返回一条 locked 消息（不会显示 "No messages yet"）。所以空
   讨论 = 消息被 proof 门丢弃，不是解密失败。

4. **真产品 bug（已修，不在本 gap 内）:** yougen keypackage 发布 effect
   (`app/mod.rs` ~1932) 完全不 gate 在设备授权上，且 `seen_publish_key` 在 spawn
   前就 set → 失败不重试。注入-grant 快路径下 keypackage 上传抢在设备自入册前 →
   `claim_generation_mismatch`（"accepted device authorization is required"）→
   设备永无 keypackage。已加 `if !device_authorization_check_complete() ||
   needs_device_authorization() { return }`。生产也对（不该在授权前发 keypackage）。

## 矛盾 / 尚未解释的信号

### ✅ 矛盾 A(已解决 —— spec 权威):消息 proof 由**设备 verify key**签,不是 DPoP 会话 key

**权威结论(`crypto-media/device-lifecycle.md`):**
- **§4 :114** 每个设备 MUST 有稳定 `device_id` 和**设备签名密钥**;
- **§5.2 :296** `self_signing_key (SSK) ── signs ──► device.verify_key` —— 设备的 **verify
  key**(即 `ck.device.authorize.payload.device_public_key`,per-device Ed25519)是签事件/
  消息 proof 的 key,SSK 只**交叉签名背书**这把 verify key;
- **§8.2** 该 verify key 投影进设备验签公钥目录(receiver 就是从这里解析);
- 与 **Matrix** 同构(per-device Ed25519 device/fingerprint key 签,cross-signing SSK 背书;
  会话/传输 key 从不签内容 proof)。

→ **正解 = 信号 1(signing-seed / device verify key)。信号 2 的 DPoP session key 本就
不该签 proof。** 实测 `sig_verify_failed` 的真相 = **harness 把 DPoP key 错误 enroll 进
目录**,而 proof 是设备 verify key 签的 → 目录 key ≠ proof key。

**修复裁决:** 停止 harness 的 DPoP enroll;让 yougen 用它的 device verify(signing-seed)
key 自入册(= 方向②)。残留子问 = yougen 内部到底哪条 signer 路径产出这把 verify key
签名 → **归入矛盾 B**。

<details><summary>原始两个矛盾信号(存档)</summary>

- **信号 1（signing-seed key）：** 设备自入册 `device_enrollment.rs:64`
  `device_public_key_multibase(material: &SigningSeedMaterial)` 从**持久化 signing
  seed** 派生 `device_public_key`，并自入册它。模块 doc（:8）说 proof 由
  "persisted signing seed" 签。→ 暗示 proof key = signing-seed key。
- **信号 2（DPoP key）：** secure-store 升级
  `app/mod.rs:379` `activate_device_signer_from_seed_b64url_for_device(&record.seed_b64, …)`
  用 **DPoP device key seed** 激活 event signer。→ 暗示 proof key = DPoP key。
- 当时矛盾点:harness enroll 的是 DPoP key;若升级 :379 激活的 DPoP-seed signer 真用于
  签 proof,则应验签通过——但实测 `sig_verify_failed`,说明 proof 是另一把 key 签的。
  该困惑已由上述 spec 结论消解:proof 该由设备 verify key 签,DPoP 路径无关;残留"哪条
  yougen signer 路径产出 verify 签名"归入矛盾 B。

</details>

### 矛盾 B：多条 event-signer 激活路径,哪条最终生效?

同一进程里至少四处激活/取用 event signer,未确认消息发送时哪条 active：
- `connect.rs:359` `event_signer::active_signer()`
- `connect.rs:361` / `app/mod.rs:408` `event_signer::bootstrap_default_signer("yougen")`
- `connect.rs:364` `bind_active_signer_device_id(device)`
- `app/mod.rs:379` `activate_device_signer_from_seed_b64url_for_device(<DPoP seed>)`

`active_signer()` 是全局；"最后激活/绑定者胜"未验证。**未解决:发送 `ck.message.create`
时,`active_signer()` 是 DPoP-seed 派生还是 bootstrap_default（signing-seed）派生?**

### 矛盾 C：注入的 grant "在 connect 之前" set,自入册却读到 None

- `inject_test_session_grant`（`session_boot.rs:269`）在 `use_hook`（首渲染、同步）
  里 `state_store.write().set_session_grant(Some(grant))`。`app/mod.rs:250` 注释
  明说 "Runs once, synchronously, **ahead of the bootstrap connect() below**"。
- 但自入册 `enroll_current_session_device`（`connect.rs:354`）读
  `state_store.read().session_grant()` 得 **None** → 报 "device enrollment requires
  an active session grant"（`connect.rs:458`,实测 bob console 有此 WARN）。
- **为何矛盾：** grant 声称在 connect 前已 set,自入册在 connect 内却读到 None。
  疑似异步 secure-store 升级（`app/mod.rs:324` `use_future`,reload config/state）
  在注入与自入册之间 clobber 了 `session_grant`,**但未确认**——升级 path 未见显式
  清 `session_grant`,只显式 set dpop key（:390）。也可能是 connect 实际早于/并发于
  `use_hook`,注释与实际时序不符。**未解决:确切时序 + 谁把 session_grant 清成 None。**

## 两难（当前为何 chat 无法绿）

| 路径 | keypackage | chat proof |
|---|---|---|
| harness enroll（DPoP key） | ✅ 设备被授权,可发 keypackage | ❌ 目录=DPoP key ≠ proof key → Rejected |
| 移除 harness,靠 yougen 自入册（signing key） | ❌ 自入册读不到 grant → 设备无授权 → 无 keypackage | （若能自入册,理应=对的 key） |

即:**harness enroll 错的 key(DPoP);yougen 自入册对的 key(device verify)但拿不到 grant。**
两条都不给 chat 绿。当前保留 harness enroll(看板绿)+ keypackage-gate 修复。

**矛盾 A 已裁决(见上,spec §5.2/§8.2 权威)→ 正解锁定「方向②」:让 yougen 用它的
device verify key 自入册。** 前置阻塞 = 矛盾 C(自入册拿不到 grant)。矛盾 B 是理解性子问
(哪条 signer 路径产出 verify 签名),不阻塞方向②落地。

## 建议的下一步(方向② 落地路径)

1. **解矛盾 C(阻塞项,最关键):** 定位为何 `enroll_current_session_device`(`connect.rs:354`)
   读到 `state_store.session_grant()` == None。手段:确认 `inject_test_session_grant`
   (`session_boot.rs:269`)与异步 secure-store 升级(`app/mod.rs:324`)、connect 三者的
   实际执行时序;查升级 path 是否 reload 覆盖了 `session_grant`。修:或让升级后重新注入 /
   保留 grant,或让 `enroll_current_session_device` fallback 用 connect 已持有的
   `token`(注入路径下即 grant_jwt)。keypackage-gate 修复已保证发布等授权完成,故 grant
   一到、自入册一成,keypackage 即随之发出。
2. **解矛盾 C 后移除 harness DPoP enroll:** 目录里就只剩 yougen 自入册的 device verify
   key = proof key → receiver-proof 验签通过 → 聊天绿。看板不受影响(无 proof 门)。
3. **(理解性,非阻塞)解矛盾 B:** 在 yougen 发送 `ck.message.create` 处打印
   `active_signer().public_key_multibase()`,确认它 = device verify(signing-seed)key,
   排除多路径激活把 signer 覆盖成 DPoP-seed 的隐患。
4. **兜底(若 C 短期难解):** 浏览器启动后从 localStorage(compat tier
   `allow_localstorage_secrets=1`)读 yougen 的 signing seed,以 `actor_seq+1` 再 enroll
   覆盖成对的 key。仅作应急,不如①②根治。

## 复现

```powershell
$env:COTEST_PW_WORKERS = "1"
cotest\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full `
  -StartupTimeoutSeconds 600 -Grep "joined member decrypts"
```
失败截图/`error-context.md` 在 `cotest/artifacts/runs/<ts>/joint-e2e/playwright-output/`。
`diagnostics/<session>/console.jsonl` 有 `connect.rs:458` 的 "device enrollment failed"
WARN;临时在 `events.rs` proof 门加 `tracing::warn!` 可复现 verdict/reason。
