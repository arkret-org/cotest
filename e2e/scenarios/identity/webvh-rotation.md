# WebVH DID 密钥轮换

## 目标

验证 `did:webvh` 控制密钥的定期轮换:旧密钥写入 entry N,生成新 update key,新 entry 由旧密钥签发并由 witness 见证,新 entry 落地后,客户端 resolver 能用新 key 验证新事件,**同时** 旧 key 仍能验证轮换前的历史事件;history chain 完整可审计。

不验证:首次 DID 创建(见 identity/onboarding)、设备配对(identity/multi-device)、单签到多签治理切换(后续 scenario)。

## Spec 锚点

- `identity/identity-did.md` §3 — DID 方法选择(why webvh)
- `identity/identity-did.md` §3.4 — `did:webvh` 版本链与 entry hash
- `identity/identity-did.md` §4.1 — Resolver policy 配置示例
- `identity/identity-did.md` §4.2-§4.2.1 — `degraded_no_witness` 状态机(≤24h)
- `identity/identity-did.md` §6 — 历史事件用历史 key 验证(verification rule 5)
- `identity/identity-did.md` §7 — DID 方法 operation 流程
- `identity/identity-did.md` §8.1-§8.2 — 多签治理 (governance) 与阈值轮换
- `identity/key-management.md` §3.2 — Key rotation hygiene

## 拓扑

- 1 × soland(host 着 alice 的事件)
- 1 × WebVH host(发布 `did.jsonl` history chain;可能就在 soland 同进程,也可能独立)
- N × witness service(签发 entry 见证;v1 至少 1 个)

## Actors

| 名字 | 角色 |
|---|---|
| alice | DID owner;触发轮换 |
| alice-device-1 | 持有旧 update key |
| witness-1 | 见证服务,签 entry hash |
| bob | space 内的其他用户,验证 alice 轮换前后的事件签名 |

## Pre-conditions

- alice 已完成 identity/onboarding onboarding,DID 形如 `did:webvh:<scid>:<host>`,entry 0 已存在
- witness-1 服务在 resolver policy 的 witness list 里
- alice 与 bob 在 space `S_a` 中已交换若干消息;alice 的事件都用 entry 0 的 key 签

## Steps

### Phase A — 轮换前的历史事件验证

1. bob 调 `GET https://<host>/.well-known/did/webvh/<scid>` 解析 alice 的 DID Document v0(应当 cache)
2. bob 收到的 alice 历史事件:每条用 alice entry 0 的 key 签;bob 用 v0 DID Doc 的 `verificationMethod` 验签 → 全通过
3. 断言:`/_soland/self/spaces/S_a/timeline` 上的 alice 事件签名状态都是 ✓

### Phase B — alice 触发轮换

4. alice (device-1) 进 `/settings/account` → "Rotate DID controlling key"
5. UI 提示生成新 update key(local key generation)
6. 客户端组 DID method operation:
   - `prev_entry_hash` = entry 0 hash
   - `new_update_keys` = [new pubkey]
   - `controller_proof` = 旧 update key 签 entry N+1 内容
7. 客户端 PUT 到 WebVH host 的 endpoint 把新 entry 追加到 `did.jsonl`
8. WebVH host 接收 → 拉 witness-1 签 entry hash → 写入持久化
9. 断言:`GET https://<host>/.well-known/did/webvh/<scid>` 返回的 DID Doc 现在含 **两个** `verificationMethod`(旧 + 新),或新替代旧(看 spec rotation 模型;§3.4)
10. 断言:`GET https://<host>/.well-known/did/webvh/<scid>/log` (or `did.jsonl`) 现在有 2 个 entry

### Phase C — 轮换后的新事件用新 key 签

11. alice (device-1) 在 space `S_a` 发新消息 `M_post`
12. 客户端用 **新** update key 签
13. bob 拉新 DID Doc → 验签 → 通过
14. 断言:bob timeline 上 `M_post` 签名 ✓

### Phase D — 旧 key 验证历史事件仍 OK

15. 把 bob 的 resolver cache 强清(测试 harness 调试钩子,或重启 bob 的 browser context)
16. bob 重新拉 history chain
17. bob 验 alice 在 Phase A 收到的旧消息(用 entry 0 key)→ 通过(spec §6 rule 5)
18. 断言:旧消息签名仍 ✓,新消息签名也 ✓,两条同步独立有效

### Phase E — Witness 故障下的 `degraded_no_witness` 状态

19. 测试 harness 把 witness-1 端点下掉(`route.block`)
20. alice 再次轮换;新 entry 由 alice 自己签但 witness 签不上
21. resolver 接收 → 进入 `degraded_no_witness` 状态(spec §4.2.1)
22. 断言:resolver 在 24h 时间窗内**仍接受** alice 的新签名(degraded mode),但 timeline 显示 ⚠ 标记
23. 把 witness 恢复,触发 alice 重新发起 witness signing → 状态回 healthy

## Observable assertions(合并)

- Phase A:历史事件签名验证通过
- Phase B 步骤 8-10:`did.jsonl` 增长 1 entry,witness 签名嵌入
- Phase C 步骤 14:新事件用新 key 签,bob 验证通过
- Phase D 步骤 18:旧 key 仍能验证旧事件(history chain 完整)
- Phase E 步骤 22-23:`degraded_no_witness` 状态机正确

## Edge cases / sub-tests

- **E9.1 entry hash chain broken**:测试 harness 篡改 `did.jsonl` 中某条 entry 的 prev_entry_hash → resolver MUST fail closed(`identity-did.md` §4.2.1 line 286)
- **E9.2 hosting domain DNS hijack**:模拟 WebVH host 返回完全不同的 DID Doc(SCID 不一致)→ resolver 检测 SCID 不匹配 → 拒绝(§3 line 76)
- **E9.3 governance multi-sig 轮换**:`identity-did.md` §8.2,需要 N-of-M 签名才能轮换(防止 1 把泄漏的 key 单方面改 DID Doc)。alice 是个 Organization,需要至少 2/3 governance keys。模拟单签提交 → reducer 拒绝;补齐第 2 签 → 接受
- **E9.4 24h degraded window 过期**:超过 24h witness 仍不可用 → resolver 进入 `unresolvable` 状态,新事件被拒绝直到 witness 恢复
- **E9.5 旧 key compromise + emergency rotation**:验证可以在没有 prev key signature 的情况下,凭 recovery key 强制轮换(`key-management.md §3.3` 的 recovery key)

## Implementation notes

- **soland 缺口**:`did:webvh` resolver、witness 协议、`degraded_no_witness` 状态机、24h 健康检查 timer — 整组 MUST 但未实现。整个 scenario fixme starter。
- **WebVH host**:可能由 soland 同进程提供 `/.well-known/did/webvh/<scid>` endpoint;也可能要独立部署。harness 需要确认。
- **witness 服务**:scripts/run-joint-e2e.ps1 需要 `-StartWitness` 开关或 mock service。
- **yougen 缺口**:`/settings/account` 的 "Rotate DID controlling key" 入口、DID Doc viewer。

## 总耗时预估

约 1-2 分钟,但若实测 24h degraded 窗口需 mock 时间快进(测试用 env 把 24h 改成 30s)。
