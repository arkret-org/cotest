# Handle 申领 / 转移 / 冲突解决

## 目标

`@alice-handle` 的端到端:alice 申领 handle、改 handle、转给 bob、handle 冲突(同时申领同名)被 reducer 拒。

## Spec 锚点

- `identity/identity-handles.md` 全篇
- `identity/identity-did.md` §6 — DID + handle 绑定

## 拓扑

- 1 × coland + 1 × coauth

## Actors

| 名字 | 角色 |
|---|---|
| alice | 申领 / 转移 handle |
| bob | 接收 handle 转移 |
| mallory | 试图 squat handle |

## Steps

### Phase A — alice 申领 handle

1. alice 完成 onboarding,初始 handle 由 `uniqueUser` 自动分配如 `@alice-s29-<uuid>`
2. alice 进 `/settings/profile` → "Change handle",新 handle = `@alice-pretty`
3. inkson 提交 `ak.handle.claim { handle: "@alice-pretty", actor: alice.did }`
4. coland reducer 校验:
   - handle 格式合法
   - handle 未被占用
   - alice 有权(自己持有)
5. 断言 handle claim viewer / handle resolve 返回 Alice 当前 primary handle `@alice-pretty`；handle 不是
   Actor Profile 的子字段，不通过 profile resolve 读取
6. 断言:directory 搜 `@alice-pretty` → 找到 alice

### Phase B — Handle 冲突

7. mallory 试 `ak.handle.claim { handle: "@alice-pretty" }`
8. coland reducer 拒,reason `handle_already_claimed`
9. 断言:mallory 的 inkson UI 显示错误；其 primary handle 未变

### Phase C — alice 转移 handle 给 bob

10. alice 进 `/settings/profile` → "Transfer handle"
11. 输入 target = bob.did
12. inkson 提交 `ak.handle.transfer { handle, from: alice.did, to: bob.did }`,alice 签
13. coland reducer:
    - 校验 alice 是当前 holder
    - 把 handle 绑定改到 bob.did
    - alice 的 primary handle 退到 fallback 或重新申领
14. 断言 Bob 的 handle claim viewer / resolve 返回 primary handle `@alice-pretty`
15. 断言:alice 不再用 `@alice-pretty`
16. 断言:directory 搜 `@alice-pretty` 现在指向 bob

### Phase D — Handle 释放后等待期

17. alice 主动释放 handle(`ak.handle.release`)
18. spec 可能规定一个 grace period(如 30 天)防止 squat
19. mallory 立刻 claim 该 handle → 拒,reason `handle_in_grace_period`
20. 时间 stub 到 +31 天 → mallory claim 成功

## Edge cases

- **E29.1 handle 格式非法**:`@a` 太短,或含特殊字符 → 拒,reason `handle_invalid_format`
- **E29.2 转移给非成员/不存在 DID**:`to` DID 未注册 → 拒
- **E29.3 转移期间 actor 离线**:bob 不在线时 alice 转给他,转移立即生效;bob 上线后看到自己有新 handle
- **E29.4 跨 server handle**:alice 在 α 的 handle `@a`,bob 在 β 也想用 `@a` → 看 handle namespace 是 server-scoped 还是 global(spec 须查)

## Implementation notes

- **coland 缺口**:`ak.handle.{claim,transfer,release}` event kinds + handle registry projection + grace period 状态
- **inkson 缺口**:`/settings/profile` 的 change handle / transfer 按钮

## 总耗时预估

约 60s。
