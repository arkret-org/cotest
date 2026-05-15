# Scenario Catalog

完整的 e2e scenario 蓝图,按 spec 自己的领域划分(`models/`、`crypto-media/`、`identity/`、`sync/`、`authz/`、`governance/`、`discovery/`),不用 `S#` 顺序号。

**31 条 scenarios,206 个 playwright tests,全部 parse 通过。**

## 按领域分组

### identity / 身份与设备
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [onboarding](identity/onboarding.md) | 真实账户注册 (passkey/OIDC/email) | 1 | 7 | ✗ |
| [recovery](identity/recovery.md) | 账户恢复 (passphrase / threshold / recovery service) | 1 | 7 | ✗ |
| [webvh-rotation](identity/webvh-rotation.md) | WebVH DID 密钥轮换 (witness + history chain) | 0 | 8 | ✗ |
| [multi-device](identity/multi-device.md) | 多设备配对 + 撤销 (QR + cross-signing + MLS Remove) | 1 | 6 | partial |
| [account-device-auth](identity/account-device-auth.md) | 真实 OIDC 注册 + 设备授权 + session refresh | 2 | 4 | ✗ |
| [account-states](identity/account-states.md) | Account 状态机 (active / locked / suspended / deactivated) | 1 | 6 | partial |
| [handle](identity/handle.md) | Handle 申领 / 转移 / 冲突解决 | 1 | 6 | partial |

### encryption / 端到端加密
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [mls-group](encryption/mls-group.md) | MLS 群组加密 (E2EE space lifecycle) | 1 | 7 | partial |
| [encrypted-attachments](encryption/encrypted-attachments.md) | 加密附件 (XChaCha20 / blob ciphertext-only / audit franking) | 1 | 6 | partial |
| [key-backup](encryption/key-backup.md) | 密钥备份 + 跨设备恢复 + MLS epoch backfill | 1 | 7 | ✗ |
| [audited-e2ee](encryption/audited-e2ee.md) | Audited E2EE (franking + moderator decryption attestation) | 1 | 5 | ✗ |

### messaging / 消息与 chat
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [triad-collaboration](messaging/triad-collaboration.md) | 单服务器三方协作 (chat / redact / history visibility) | 3 | 0 | 大部分 ✓ |
| [chat-advanced](messaging/chat-advanced.md) | reactions / replies / mentions / polls / typing / presence | 1 | 5 | partial |
| [discussion-upgrade](messaging/discussion-upgrade.md) | Flow discussion 升级为独立 child Space | 0 | 7 | partial |
| [read-receipts](messaging/read-receipts.md) | Read receipts 三层语义 (client / space policy / marker) | 0 | 8 | partial |

### spaces / 空间与成员关系
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [moderation-ban](spaces/moderation-ban.md) | 审核 + 封禁 (三层 gate / anchored moderation_state) | 2 | 0 | partial |
| [knock-application](spaces/knock-application.md) | Knock + 申请 + cooldown | 1 | 6 | 仅 step 1 |
| [knock-auto-resolve](spaces/knock-auto-resolve.md) | Knock 自动解析路径 (`gate_proofs[]`) | 0 | 5 | ✗ |
| [history-world-readable](spaces/history-world-readable.md) | `history_visibility=world_readable` 未加入也能读 | 1 | 3 | partial |

### kanban / 看板
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [end-to-end](kanban/end-to-end.md) | Board / List / Card / drag / archive / comments | 1 | 4 | partial |
| [project-simulation](kanban/project-simulation.md) | 多用户 sprint:assignees / due dates / FSM status | 1 | 6 | partial |

### documents / 文档协作
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [collaboration](documents/collaboration.md) | 协作编辑 + 光标 presence + 评论 range + 版本恢复 | 1 | 6 | partial |

### calls / 通话
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [webrtc](calls/webrtc.md) | 1:1 + group + mute + screen share + recording policy | 1 | 7 | partial |

### federation / 跨服务器
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [cross-server](federation/cross-server.md) | push/pull/frontier/RFC9421 | 3 | 6 | partial (outbound stub) |

### authz / 权能授权
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [capability-chain](authz/capability-chain.md) | grant / revoke / delegate / constraints / audit | 1 | 6 | partial |

### discovery / 搜索与通知
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [directory](discovery/directory.md) | directory 搜索 / contacts / profile / presence | 1 | 4 | partial |
| [notifications](discovery/notifications.md) | push prefs / DnD / mute / mark-all-read | 1 | 5 | partial |

### governance / 治理与合规
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [gdpr-audit-retention](governance/gdpr-audit-retention.md) | GDPR 抹除 + audit log + retention 策略 | 1 | 6 | ✗ |
| [organization-policy](governance/organization-policy.md) | 组织 directory + moderation policy 继承 | 1 | 6 | ✗ |

### sync / 同步与冲突
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [offline-conflict](sync/offline-conflict.md) | 离线编辑 / 重连同步 / 冲突修复 (bottom_cells) | 1 | 4 | partial |

### invites / 邀请扩展
| Scenario | 主题 | live | fixme | soland 就绪 |
|---|---|---|---|---|
| [third-party](invites/third-party.md) | 第三方邮件邀请 (`cx.invite.third_party` + binding proof) | 1 | 6 | ✗ |

## Soland 就绪度小结

| 状态 | 含义 | 数量 |
|---|---|---|
| 大部分 ✓ | live 测试当前应当大部分通过 | 1 (messaging/triad-collaboration) |
| partial | 一部分 live 跑得通,一部分 fixme | 15 |
| ✗ | 几乎全 fixme,等 soland 落地 | 15 |

实现度细节见各 scenario doc 的 "Implementation notes" 与 "风险" 段。

## Mock services

| 服务 | 文件 | 触发 | scenarios 受益 |
|---|---|---|---|
| OIDC IdP | [mocks/mock-idp.mjs](../mocks/mock-idp.mjs) | `-StartMockIdp` 或 `-StartMocks` | identity/onboarding, identity/account-device-auth |
| Email + 3PID | [mocks/mock-email.mjs](../mocks/mock-email.mjs) | `-StartMockEmail` 或 `-StartMocks` | invites/third-party, identity/onboarding |
| WebVH witness | [mocks/mock-witness.mjs](../mocks/mock-witness.mjs) | `-StartMockWitness` 或 `-StartMocks` | identity/webvh-rotation |

## 编排约定

- 每个 scenario 一个 `*.spec.ts` 文件,路径 `tests/<domain>/<name>.spec.ts`,对应 doc 在 `scenarios/<domain>/<name>.md`
- `test.describe.configure({ mode: "serial" })`
- 每个 scenario 用 `uniqueUser("<domain>-<short>")` 避免污染(短前缀方便日志读)
- 关键 phase 末尾 `stepShot()`
- 暂跑不通的 spec 契约用 `test.fixme()`,正文留 spec § + soland gap 说明
- 跨 scenario 引用按路径写,如 `(见 identity/multi-device)`,不用顺序号

## 运行

```pwsh
# 单服务器,无 mocks
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full

# 单服务器 + 全部 mocks(激活外部依赖)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -StartMocks -RunProfile joint-full

# 双服务器 + 全部 mocks(最大覆盖)
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -DualSoland -StartMocks -RunProfile joint-full

# 跑单个领域
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -Grep "kanban/"

# 跑单个 scenario
& "D:\Works\contrix-dev\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -Grep "messaging/triad-collaboration"
```

## 产物

`artifacts/runs/<ts>/joint-e2e/`:
- `summary.md` / `scenarios.md` — 整体 + scenario 维度
- `junit.xml` — CI 友好结构化结果
- `playwright-report/` — HTML(含 trace/video/failure screenshot)
- `services/` — soland / coauth / yougen / mock-* 进程日志
- `screenshots/` / `diagnostics/`(console + network HAR)

## 后续候选(尚未文档化)

| 主题 | 触发条件 |
|---|---|
| spaces/moderation-ban + federation/cross-server 组合 | federation outbound push 在 soland 落地 |
| 性能 / 负载基线 | 主线全绿后 |
| 跨服务器 MLS welcome | federation/cross-server + encryption/mls-group 单独通过后 |
