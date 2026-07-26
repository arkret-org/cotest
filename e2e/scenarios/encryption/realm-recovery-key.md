# Realm Recovery Key(RRK)历史持久化封存

## 目标

验证 `content_scheme=mls_exporter_aead_v1` 的 Realm 的**组织级历史持久性**:Realm 声明
`durability_policy`(`org_recovery_key` 单点 / `threshold` k-of-n)后,推进 epoch 的
`ak.mls.commit` 提交方在 eager 时序下为每个恢复方(RRK)发布 RRK-targeted
`ak.realm_key.share`,把 per-epoch `history_secret` HPKE 封装给该恢复方的离线公钥;
当全体成员设备失效 / 全员离职后,组织用 RRK 私钥 HPKE-open 还原历史;无活成员时
RRK 持有者临时上线把授权 epoch 区间 re-seal 给后加入者。

不验证:`mls_rfc9420`(PrivateMessage)Realm 的成员级 durable 备份(走
encryption/key-backup-restore),audited-e2ee 反审 release(走 encryption/audited-e2ee),
notary `mixed` profile 的 `recovery_members`(finality 轴,正交)。

## Spec 锚点

- `crypto-media/encryption-and-audit.md` §2.10 — 可共享历史内容 scheme `mls_exporter_aead_v1`
- `crypto-media/encryption-and-audit.md` §2.10.1 — `history_secret[N]` / `K_content[N]` 派生
- `crypto-media/encryption-and-audit.md` §2.10.4 — `ak.realm_key.share` 历史密钥交付
- `crypto-media/encryption-and-audit.md` §2.10.5 — 保留义务与 per-epoch FS 边界
- `crypto-media/encryption-and-audit.md` §2.10.8 — RRK 持久化封存(eager-at-commit + RYW + 兜底 re-share)
- `models/realm-and-space.md` §2.3.1 — `durability_policy`(mode / recovery_recipients / threshold)
- `identity/identity-did.md` §8.3 — `ArkretRealmHistoryRecoveryKey` service entry(RRK HPKE 公钥)
- error-code-registry:`durability_scheme_incompatible` / `durability_recovery_recipient_unverified` /
  `durability_seal_missing_before_gc`

## 拓扑

- 1 × soland + 1 × coauth
- RRK 持有者为组织 principal,发布带 active `ArkretRealmHistoryRecoveryKey` service entry 的 DID Document

## Actors

| 名字 | 角色 | 设备 |
|---|---|---|
| alice | Realm owner + group creator + epoch committer | 1 leaf |
| bob | 第二个 member,产生内容 | 1 leaf |
| org-rrk | 组织恢复方(RRK 私钥持有者),**非 MLS 成员**、离线 | 无 leaf,只有 HPKE 公钥 |
| dave | 后加入者,无活成员时经 RRK re-seal 兜底解历史 | 1 leaf(后加入) |

## Steps

### Phase A — 正向「组织恢复」

1. org-rrk 发布 DID Document,含 active `ArkretRealmHistoryRecoveryKey` service entry
   (`serviceEndpoint.verificationMethod` 指向一把 `keyAgreement` HPKE VM,`domain=mls_history`,
   独立于 `did_recovery` 域)。
2. alice 建 Realm:`encryption_profile=mls_rfc9420`、`content_scheme=mls_exporter_aead_v1`、
   `durability_policy={mode:org_recovery_key, recovery_recipients:[org-rrk RRK]}`。
3. alice 提交 `ak.mls.genesis`,推进若干 `ak.mls.commit`(epoch 1..N);每个 epoch alice+bob
   产生 `mls_exporter_aead_v1` 加密内容。
4. 每个 epoch commit accepted 后,封存方 eager 发布 RRK-targeted `ak.realm_key.share`
   (`key_scope.from_epoch=to_epoch=N`,`recipient_principal_id=org-rrk`,`ciphertext`=封给 RRK 公钥),
   且在 RYW 落盘前 MUST NOT GC `history_secret[N]`。
5. 模拟全员离开 / 设备失效(alice/bob leave + 设备 revoke)。
6. 组织取回事件日志中所有 RRK-targeted share,用 RRK 私钥 HPKE-open 得 `history_secret[1..N]`,
   按 §2.10.1 派生 `K_content[N]` 解每个 epoch 历史内容。
7. 断言:还原出的历史明文与第 3 步原内容逐 epoch 一致。

### Phase B — 后加入者经 RRK 兜底 re-share

1. 承接 Phase A(无活成员)。
2. dave 后加入,发布 KeyPackage / 设备 HPKE 公钥;无活成员可 re-share。
3. RRK 持有者临时上线,把授权 epoch 区间 `[from,to]` 的 `history_secret` 用 RRK 私钥 open 后,
   re-seal(`ak.realm_key.share`)给 dave 的设备 HPKE 公钥。
4. 断言:dave 安装 `history_secret` 后解出该区间历史,纳入 §2.3.5 late-recovery 状态机。

### Phase C — 诊断向量(负向)

- **C1 `durability_scheme_incompatible`**:在 `content_scheme=mls_rfc9420`(或缺省)的 Realm 上
  `ak.realm.policy_components` 写 `durability_policy.mode != none` → `failed_precondition`
  reason=`durability_scheme_incompatible`(§2.3.1 / §2.10.8 适用条件)。
- **C2 `durability_recovery_recipient_unverified`**:`recovery_recipients[].verification_method`
  解析不到 active `ArkretRealmHistoryRecoveryKey` service entry(已撤销 / 未被 service entry 指定 /
  指向 `did_recovery` 域 key)→ **发送客户端在 HPKE seal 前** fail closed,
  reason=`durability_recovery_recipient_unverified`,MUST NOT 回退到任意公钥，也不得发出
  `ak.realm_key.share`。仅写入 `durability_policy` 不是该诊断的触发点。
- **C3 `durability_seal_missing_before_gc`**:某 epoch 的 RRK share 尚未 accepted(RYW 未满足)即
  尝试 GC 客户端持有的 `history_secret[N]` →
  reason=`durability_seal_missing_before_gc`,MUST 保留 secret。spec 没有注册服务端
  history-secret GC operation；采用单调保留、从不 GC 的客户端通过“首次 share 未 accepted，
  后续仍可用同一 secret 重试并 accepted”证明该义务。

## 实现状态

C1 `durability_scheme_incompatible` 已 live 化；其精确回归命令为：

```powershell
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -PlaywrightProject chromium -Grep 'C1 durability_scheme_incompatible' -SkipNpmInstall -SkipBrowserInstall
```

通过证据：`artifacts/runs/20260726-035104/joint-e2e/playwright-report`。

Phase A、Phase B、C2、C3 仍为 `test.fixme`，依赖：

- `@blocking-on rrk-soland` — `content_scheme` / `durability_policy` 投影、RRK-targeted
  `ak.realm_key.share` 接受 + RYW 与恢复读取面
- `@blocking-on rrk-inkson` — `mls_exporter_aead_v1` 内容封装 / 解封、RRK HPKE seal/open、
  epoch 推进时的 eager 封存挂钩、C2 发送前 DID 验证、C3 retained-secret retry 证据和披露横幅
- `@blocking-on rrk-cotest` — C2 的可控 DID resolver/outbound capture、C3 的首次 share
  拒绝/丢弃 fault injection

着陆后逐 Phase live 化;实跑见 arkret-work jobs 的最终集成项。
