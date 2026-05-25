# GDPR 抹除 + audit log + 数据保留策略

## 目标

alice 触发 GDPR 数据导出 → 拿到完整个人数据 JSON;触发 erasure → 个人数据 pseudonymize / 删除,E2EE 密钥销毁;retention policy 设置后,过期 events 自动 prune;所有过程进 audit log。

## Spec 锚点

- `identity/account-lifecycle.md` §3 — Account states(`erasure_pending`)
- `identity/account-lifecycle.md` §8 — GDPR-compliant export + erasure
- `governance/content-moderation.md` — Audit + retention
- `models/space-and-place.md` §2.2 — Space retention policy 字段

## 拓扑

- 1 × soland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 个人用户,触发 export / erasure |
| bob | 同 space 成员,验证 alice 抹除后视图 |

## Steps

### Phase A — Setup

1. alice + bob 在 `S` 中,各自发若干消息

### Phase B — alice 导出 GDPR 数据

2. alice 进 `/settings/account` → "Export my data"
3. yougen 调 `POST /api/v1/account/export`
4. soland 异步生成 zip 包(可能 base64 inline 或返回 download URL)
5. 断言:返回 200 + `export_id` + (可选)`download_url`
6. alice 下载并解压 → 内含 JSON:`{ account: { did, handle, profile }, spaces: [...], messages: [...], devices: [...], audit_log: [...] }`
7. 断言:alice 自己的消息明文在 export 中(她有解密能力);其他用户的 E2EE 消息 ciphertext-only

### Phase C — alice 触发 erasure

8. alice 进 `/settings/account` → "Erase my account"
9. 确认对话框 → 提交 `POST /api/v1/account/erase`,可能要二次密码确认
10. soland 返回 `state="erased"`，并在响应中带 `cx.schema.erasure_receipt.v1`
11. soland 后台任务执行:
    - 删除 alice 的 PII(display_name、bio、avatar → pseudonymize)
    - 删除 alice 的 E2EE secret material(SSK / USK / device keys → 安全销毁,后续无法解密)
    - 把 alice 的消息 redact 成 tombstone(content 删除,event_id 保留以维持因果链)
    - 把 alice 的 devices 全 revoke
    - 把 alice 的 profile 改成 anonymized `did:web:erased-<hash>`(或保留 DID 但 profile 空)
12. 断言:alice 的 session token 立刻失效

### Phase D — bob 视角验证 erasure

13. bob 同步 `S` → timeline 中 alice 的消息显示 `[user erased]` tombstone
14. bob `GET /api/v1/actors/<alice.did>/profile` → 返回 anonymized / 404
15. bob 在 directory 搜 alice handle → 不再找到

### Phase E — Audit log entries

16. alice (用 admin / 测试 harness 的特殊 token) 查 `/api/v1/audit/events?actor=alice.did`
17. 断言:audit log 含 `cx.audit.exported`、`cx.audit.erasure_initiated`、`cx.audit.erasure_receipt`

### Phase F — Retention policy

18. alice 创建另一个 space `S_short`,`retention_policy: { ttl: "30d" }`
19. alice 发消息 `M_old`
20. 测试 harness 把 system time stub 到 +31 天
21. soland 后台 retention sweeper 把超过 30 天的 events 改成 tombstone(或物理删除,看 policy)
22. 断言:alice 拉 timeline → `M_old` 变 `[expired]` tombstone

## Edge cases

- **E27.1 erasure 期间 sync 进行中**:alice 写消息后立刻触发 erasure → 消息怎么处理?spec 倾向于把所有消息 tombstone
- **E27.2 erasure 不可逆**:alice "悔了" 想恢复 → 应该拒绝(spec §3 erasure_pending 是终态前奏)
- **E27.3 cross-server erasure**:alice 的 DID 在 α,在 β 上也有消息;erasure 应该 fanout 给 β 让其也 tombstone
- **E27.4 retention 与 anchor 冲突**:有 anchor 引用的老 event 不能物理删,只能 tombstone(避免破坏 anchor history chain)

## Implementation notes

- **soland 缺口**:retention sweeper；跨服务器 erasure fan-out 和历史消息 tombstone 已由 `cx.audit.erasure_receipt` live 覆盖
- **yougen 缺口**:`/settings/account` 的 export / erase 按钮、确认对话框
- **测试侧**:retention 时间快进需要 soland 暴露 admin endpoint 或测试模式

## 风险

- 整组 fixme territory;spec 写的是 MUST,但 soland 实现度低。

## 总耗时预估

约 2 分钟(含 export 异步等待 + retention sweeper 触发)。
