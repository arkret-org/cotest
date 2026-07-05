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

### 🔄 矛盾 B(重大反转 —— 测试路径下 signing seed **就是** DPoP seed)

原以为"signer=signing-seed key、harness enroll 的 DPoP key 是错的"。**代码复查推翻了这个假设:**

- `event_signer.rs:480-482` `activate_device_signer_from_seed_for_device(seed, Some(store), …)`
  在 `persist_store=Some` 时 **`store_signing_seed(store, &seed)`** —— **激活即把该 seed 写成
  signing seed**。
- inject(`session_boot.rs:235`)正是用 **DPoP seed** 调
  `activate_device_signer_from_seed_b64url_for_device(&dpop_seed_b64url, Some(secure_store), …)`
  → **把 signing seed 覆盖成 DPoP seed**。
- 于是 `bootstrap_default_signer`(`event_signer.rs:771` → `ensure_signing_seed`)加载的
  signing seed = **DPoP seed** → **signer = DPoP key**。

**推论:** 测试注入路径下 signing-seed key == DPoP key,而 harness 也 enroll 的 DPoP key
→ **理应匹配**。所以 `sig_verify_failed` **不是"seed/key 不匹配"**。

**新嫌疑 = device_id 漂移(与 memory `per-account-device-seed-isolation` /
`kanban-decrypt-cursor-device-drift-roots` 同源):**
- secure-store 升级 `app/mod.rs:463` 把 `device_id` **钉成 secure-store 的稳定值**
  (`load_device_id`),可能 ≠ harness enroll 用的**注入** `device_id`(`seed.deviceId`)。
- 若漂移:harness 在 `device_A`(注入)下 enroll 了 key;yougen 消息 proof 的
  `verification_method` 绑 `#ck:device:device_B`(稳定);receiver 按 proof 的 `device_B`
  解析目录 key,拿到的**不是** harness 在 `device_A` 下 enroll 的那把 → 但实测是
  `sig_verify_failed`(Hit + 验签失败)而非 NegativeHit,说明 `device_B` 名下**确有**一把 key
  但与 proof 不匹配 → **待查:`device_B` 那把 key 从哪来、为何 ≠ proof key。**

**下一步(定 B):** 在发 `ck.message.create` 处打印 ①`active_signer().public_key_multibase()`
②proof 的 `verification_method` 里的 device_id;并在 harness 侧打印 enroll 用的
`device_id`+`device_public_key`;三者一比即真相大白。**这一步同时能证伪/证实 device_id 漂移。**

> 注意:B 与 C 相互独立——即便 B 查明是 device_id 漂移(harness/yougen 侧对齐 device_id 即可),
> C(自入册拿不到 grant)仍是让 yougen 走**自己**的授权链所必须解的。

### ⚠️ 矛盾 C(根因已确认,有 console 证据):注入的 grant 被反复 reset,自入册读到 None

- `inject_test_session_grant`（`session_boot.rs:269`）在 `use_hook`（首渲染、同步）
  `state_store.write().set_session_grant(Some(grant))`,并镜像进 config（:270）;`app/mod.rs:250`
  注释称其 "Runs once, synchronously, **ahead of connect()**"。
- 但自入册 `enroll_current_session_device`（`connect.rs:354`）读
  `state_store.read().session_grant()` 得 **None** → "device enrollment requires an active
  session grant"（`connect.rs:458`）→ 自入册失败 → 设备无授权 → keypackage 发不出。

**bob console 实测时间线(093857 run,移除 harness enroll 那次):**
```
01:41:16.573  session grant installed        ← inject 确实 set 了 grant
01:41:17.102  device enrollment requires…    ← ~0.5s 后自入册读到 None
01:41:23.052  session grant installed        ← inject 又跑(≈6s 后)
01:41:29.113  session grant installed        ← 再一次
```

**结论(推翻"疑似",坐实机制):**
1. inject **确实 set 了** grant(16.573)——不是没跑、也不是注释错时序;
2. **~0.5s 内 grant 被清掉**(17.102 自入册读到 None);
3. inject **反复重跑 3 次**(16/23/29s)——铁证:**有东西在不断 reset 内存 state**。
   最可能:注入的 grant 只在**内存 state_store**(session_boot.rs:269),没进 IndexedDB;
   异步 secure-store 升级(`app/mod.rs:324`)或 re-render 触发的**从 IndexedDB reload 覆盖**
   了内存 state（IndexedDB 里没有注入的 grant）→ grant 丢 → inject 下一轮又补 → 循环;
4. **设备授权检查只在 17.102 跑一次、失败即止**——后面 23/29s 的 re-inject 补回了 grant,
   却**没触发重检/重试自入册**。

**→ 两个可独立修的点:**
- **C1(消 reset):** 让注入的 session_grant 在 reload 中存活——inject 后把 grant 也持久化到
  升级后的 secure-store，或让升级/reload 路径**保留**而非覆盖已存在的 `session_grant`。
- **C2(补重试):** 设备授权检查/自入册在 `session_grant` 由 None→Some 时**重跑**(读该信号即订阅,
  与我给 keypackage-gate 加的重触发同构)。任一到位即可让自入册在 grant 就绪后成功。

## 两难（当前为何 chat 无法绿)

| 路径 | keypackage | chat proof |
|---|---|---|
| harness enroll（DPoP key） | ✅ 设备被授权,可发 keypackage | ❌ receiver 验签失败 `sig_verify_failed`（**mismatch 源头待定:见矛盾 B 反转——很可能是 device_id 漂移,不是 key 类型**） |
| 移除 harness,靠 yougen 自入册 | ❌ 自入册读不到 grant(矛盾 C)→ 设备无授权 → 无 keypackage | —(走不到) |

**当前保留 harness enroll(看板绿)+ keypackage-gate 修复。**

> **B 的反转改变了修复顺序:** 原以为"该改用 signing-seed key"(方向②);但既然测试路径下
> signing seed 已 == DPoP seed(矛盾 B),key 类型可能本就对齐,真凶更可能是 **device_id 漂移**。
> **所以下一步不是急着改代码,而是先跑「矛盾 B 下一步」的三方 device_id/key 打印比对**,定死
> mismatch 到底在 key 还是 device_id:
> - 若在 **device_id**:harness enroll 与 yougen 签名对齐同一个稳定 device_id 即可,**可能不必碰
>   矛盾 C**(harness 继续 enroll,只要 device_id 一致);
> - 若在 **key**:才回到"让 yougen 自入册"(必须先解矛盾 C)。

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
