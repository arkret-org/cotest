# 多设备配对 + 撤销

## 目标

验证用户在多个设备上的生命周期:Device 1 已登录;通过 QR 码 + cross-signing 绑定 Device 2;两台设备并发收发消息;Device 1 远程撤销 Device 2;撤销后 Device 2 提交的 Move 被拒绝;Device 2 的 to-device 队列消息被 drop。

不验证:首次 onboarding(identity/onboarding)、账户恢复(identity/recovery)、WebVH 密钥轮换(identity/webvh-rotation)。

## Spec 锚点

- `crypto-media/device-lifecycle.md` §2 — 多设备配对与撤销
- `crypto-media/device-lifecycle.md` §2.1 — 5 步配对流程(QR + cross-signing)
- `crypto-media/device-lifecycle.md` §2.2 — 设备撤销
- `crypto-media/device-lifecycle.md` §5.1-§5.2 — cross-signing binding schema
- `crypto-media/device-lifecycle.md` §6 — device list sync (`ak.device.list_update`)
- `crypto-media/device-lifecycle.md` §7 — to-device message 队列 + 过期
- `crypto-media/device-lifecycle.md` §9 — MLS KeyPackage 上传 + 撤销时的 MLS Remove
- `identity/key-management.md` §5.0-§5.2 — `ak.device.authorize` / `ak.device.revoke`

## 拓扑

- 1 × soland + 1 × coauth (with MLS group key server)

## Actors

| 名字 | 设备 | 注释 |
|---|---|---|
| alice | device-1 (laptop) | 已 onboard,持 PSK |
| alice | device-2 (phone) | Phase A 新加入 |
| bob | 任意设备 | 与 alice 在 E2EE Realm,验证撤销后 MLS Remove 生效 |

## Steps

### Phase A — Device 2 配对

1. alice device-1 已登录(假设 identity/onboarding 完成),持有 cross-signing PSK
2. 开新 browser context = device-2,visits `/onboarding`
3. device-2 选"Add to existing account",生成本地 device key,展示 QR(含 device-2 pubkey + 一次性 challenge)
4. device-1 进 `/settings/devices` 选 "Add device" → scan QR(测试 harness 用 `page.evaluate` 模拟相机读取,直接把 QR payload 注入 device-1)
5. device-1 验证 challenge → 用 SSK 签 `ak.device.authorize`,payload 含 device-2 pubkey + cross_signing_binding(spec §5.2)
6. device-1 把该事件 POST 到 soland 的 events API,落到 alice 的 principal control Realm
7. device-2 拉 control Realm,看到 `ak.device.authorize` 含自己的 pubkey,接受
8. device-2 拉 MLS welcome(若 alice 在 E2EE Realm)→ 加入现有 MLS group
9. 断言:device-1 和 device-2 都进 `/settings/devices`,都看到对方在列表(`ak.device.list_update` 已同步)

### Phase B — 两台设备并发收发

10. alice (device-1) 在 Realm `R_a` 发消息 `M_d1`
11. 断言:30s 内 device-2 收到 `M_d1`,timeline 出现
12. alice (device-2) 发 `M_d2`
13. 断言:device-1 收到 `M_d2`
14. **关键**:`M_d1` 和 `M_d2` 的 `actor_id` 都是 alice.did,但 `device_id` 不同 — bob 查看时显示 alice 名字下两台设备都参与了对话

### Phase C — Device 1 撤销 Device 2

15. alice (device-1) 进 `/settings/devices`,点 device-2 旁的"Revoke"
16. UI 二次确认 → device-1 用 SSK 签 `ak.device.revoke`,payload `{ revoked_device: device-2.id, revocation_time, reason: "user_initiated" }`
17. 提交到 soland events API
18. soland reducer:
    - 接受 `ak.device.revoke`
    - 把 device-2 从 alice 的 active device set 移除
    - `keys/query` 对 device-2 返回 `device_status=revoked`,并省略 `device_signing_key` / `hpke_key`
    - retire device-2 已发布但未消费的 ordinary 与 last-resort MLS KeyPackage,后续 claim 返回 `mls_keypackage_not_found`
    - 若在 E2EE Realm:触发 MLS Remove(剔除 device-2 的 leaf node)+ 新 commit + 新 epoch
19. 断言:device-1 的 `/settings/devices` 看不到 device-2 了

### Phase D — 撤销后 Device 2 提交 Move 被拒

20. device-2 继续保持登录状态,尝试发 `M_d2_post_revoke`
21. soland reducer 校验:device_id 已 revoke
22. 断言:`POST /_arkret/self/events`(或 sendMessage)返回 4xx,reason_code 含 `device_revoked` / `unauthorized`
23. device-2 inkson UI 显示 `write-status` 内含上述错误

### Phase E — To-device 队列过期

24. 在 Phase C 之前(假设 device-2 在某个时点是离线),bob 给 device-2 发了 to-device key share
25. device-2 在 revoke 之后才上线
26. 断言:to-device 队列把 device-2 的消息 **drop**(过期或 receiver 已 revoke),不送达
27. (spec §7 line 341 grace drop)

### Phase F — MLS Remove fan-out

28. bob 在 Phase A 之前已经和 alice 在 E2EE Realm 中;Phase C 触发 MLS Remove
29. bob 拉 sync → 收到新 epoch commit
30. 断言:bob 的 timeline 上,Phase C 之后的消息使用新 epoch key;device-2 没有这把新 key,理论上**不能解** 新消息(即使绕过本地 revoke 检查)

## Observable assertions(合并)

- Phase A 步骤 9:device-1/device-2 都在彼此的 device 列表
- Phase B 步骤 11/13:双向消息可见
- Phase B 步骤 14:消息携带 device_id 信息
- Phase C 步骤 19:device-2 从 device-1 视图中消失
- Phase C:撤销后 `/_arkret/self/keys/query` 不再暴露 device-2 的 `device_signing_key`,并标记 `device_status=revoked`
- Phase C:撤销后 device-2 的未消费 ordinary / last-resort KeyPackage 不再可 claim
- Phase D 步骤 22:device-2 提交被拒,错误码 device_revoked
- Phase E 步骤 26:to-device 队列 drop
- Phase F 步骤 30:MLS Remove 生效,device-2 失去新 epoch 访问

## Edge cases / sub-tests

- **E10.1 QR 过期**:device-2 显示 QR 后,alice 停留 > N 分钟才 scan → device-1 应拒绝 expired challenge
- **E10.2 QR 篡改**:测试 harness 把 QR payload 改 1 byte → device-1 challenge 验证失败,拒绝
- **E10.3 撤销中的 MLS Commit 撞车**:device-2 在 device-1 提交 revoke 的同时也提交一条消息;reducer 应当先收 revoke,后续 device-2 消息被拒
- **E10.4 自我撤销**:device-1 不能 revoke 自己(避免账户锁死);UI/reducer 都应禁止 — 必须从另一台设备 revoke
- **E10.5 Device list sync 延迟**:device-3(假设存在)收到 revoke 事件之前,如何处理 device-2 的消息 → 客户端 SHOULD 在收到 revoke 后回溯标记,事件 fingerprint 显示 "device revoked retroactively"

## Implementation notes

- **soland 已覆盖**:`ak.device.authorize` + `cross_signing_binding` 验签、`ak.device.revoke` auth gate、device-set projection、to-device grace drop、`keys/query` revoked 目录面、撤销时未消费 ordinary / last-resort MLS KeyPackage retire。
- **soland 剩余缺口**:完整 E2EE Realm MLS Remove fan-out:KeyPackage claim → Welcome → Commit Remove → epoch advance → revoked device 无法解密后续消息。该缺口保留为 `multi-device.spec.ts` 的 MLS fixme,不能用单纯 auth 拒绝替代。
- **inkson 缺口**:`/settings/devices` 的 device 列表 + revoke 按钮;QR scan UI(本测试用 evaluate 注入,UI 缺口对测试不致命)
- **harness**:模拟相机扫码用 `page.evaluate` 注入 QR payload 到 device-1 的 add-device input

## 总耗时预估

约 90s-2 分钟。
