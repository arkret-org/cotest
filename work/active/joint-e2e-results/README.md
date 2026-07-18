# cotest joint-e2e 全量测试与失败分析报告

## 1. 结论摘要

- 测试日期：2026-07-19（Asia/Shanghai）
- 目标 profile：`joint-full`，Playwright project：`chrome`
- 最终完整发现 476 个测试：104 通过、58 assertion failure、3 setup/runtime error、129 显式 skipped、182 因串行 suite 的前置失败而未执行。
- Playwright 实际执行了 165 个测试（104 通过、61 失败/错误）；本次不能把 182 个 `did not run` 当作功能失败，也不能据此宣称剩余功能通过。
- 61 个失败/错误可收敛为 6 个独立根因。其中 54 个由同一个 cotest 时间戳 helper 造成；修复该根因后才有价值评估大量当前被级联阻断的测试。
- 未发现需要修改 `arkret-spec` 的规范缺陷。当前证据显示：56 个失败属于测试实现/测试预期问题，3 个错误属于 joint runner 与 coauth 本地拓扑不兼容，1 个失败属于产品 typed DTO 实现问题，另 1 个失败同时包含 Soland 实现缺陷与测试断言缺陷。
- 未修改产品代码、测试代码或 spec。本报告是唯一有意新增的工作区内容；构建缓存、测试 artifacts 和 Docker 运行态不属于源码修改。

## 2. 执行方式与完整性边界

### 2.1 标准拓扑尝试

按 cotest README 的标准联合拓扑执行：

```powershell
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full
```

环境准备完成后，标准拓扑在 Playwright 启动前被 coauth readiness 阻断：

```text
Timed out waiting for coauth describe at
http://127.0.0.1:22358/_arkret/describe. Last error: 503
```

证据目录：[`artifacts/runs/20260719-003100/joint-e2e`](../../../artifacts/runs/20260719-003100/joint-e2e)。该次运行不是测试用例失败，而是 runner 生成的本地拓扑与 coauth 出站安全策略冲突，详见 RC-2。

### 2.2 最大可运行覆盖

为在不改代码的限制下获得可分析的全量发现与最大执行覆盖，随后执行：

```powershell
.\scripts\run-joint-e2e.ps1 -RunProfile joint-full -StartMocks
```

该运行使用 `joint-full` 发现全部常规 spec，但不启动 coauth；因此 3 个明确要求 coauth DPoP session-grant 的 joint UI 用例以 fixture error 结束。权威结果目录：

- [`summary.md`](../../../artifacts/runs/20260719-003405/joint-e2e/summary.md)
- [`summary.json`](../../../artifacts/runs/20260719-003405/joint-e2e/summary.json)
- [`junit.xml`](../../../artifacts/runs/20260719-003405/joint-e2e/junit.xml)
- [`scenarios.md`](../../../artifacts/runs/20260719-003405/joint-e2e/scenarios.md)
- [`playwright-report`](../../../artifacts/runs/20260719-003405/joint-e2e/playwright-report)
- [`playwright.stdout.log`](../../../artifacts/runs/20260719-003405/joint-e2e/playwright.stdout.log)
- [`services`](../../../artifacts/runs/20260719-003405/joint-e2e/services)

运行时间为 187.21 秒，exit code 为 1，managed service failure count 为 0。`artifacts/latest/joint-e2e` 已指向/复制该次结果。

### 2.3 结果计数口径

| 口径 | 数量 | 说明 |
|---|---:|---|
| discovered | 476 | `joint-full` 全量发现 |
| passed | 104 | Playwright 通过 |
| assertion failures | 58 | JUnit `<failure>` |
| setup/runtime errors | 3 | JUnit `<error>`，均为缺少 coauth session-grant |
| explicit skipped | 129 | Playwright 输出 |
| did not run | 182 | serial suite 前置失败后的级联未执行 |
| fixme | 42 | runner 从 skipped 集合中单独归类的“pending spec implementation” |

`scenarios.md` 将 311 个 JUnit skipped node 进一步归类为 269 skipped + 42 fixme；其中 269 包含 182 个 `did not run`。因此不能用 `104 / 476` 直接衡量实现通过率。

## 3. 根因总表

| ID | 影响用例 | 归属 | 是否为 spec 问题 | 结论 |
|---|---:|---|---|---|
| RC-1 | 54 | cotest 测试实现 | 否 | `canonicalTimestamp()` 删除毫秒，生成规范明确禁止的 Event 时间戳 |
| RC-2 | 3 errors | cotest runner / coauth 集成拓扑 | 否 | runner 给 coauth 配置 loopback Soland，但 coauth 所有 build 均拒绝私网出站 |
| RC-3 | 1 | cotest 测试预期 | 否 | 测试错误假设 `update_profile` 隐式同步 Directory，并要求未保证公开的 `bio` |
| RC-4 | 1 | Soland 实现 + cotest 断言 | 否 | REST account_data 未进入 initial-sync durable Event 来源；测试又按错误的根级字段读取 Event |
| RC-5 | 1 | arkret-rust-sdk / Soland typed body | 否 | MIMI 非 Event signature 被错误建模为 Event `Proof`，拒绝 spec 正确的 `payload_digest` |
| RC-6 | 1 | cotest 测试预期 | 否 | 测试构造并要求接受 spec 明确禁止的可解码 `base64url(JSON)` locator token |

合计：54 + 3 + 1 + 1 + 1 + 1 = 61。182 个未执行用例没有作为独立根因重复计数。

## 4. 深入分析

### RC-1：cotest Event 时间戳 helper 违反 canonical wire 规范（54 个失败）

#### 现象

53 个 failure 明确返回：

```text
400 invalid_param: created_at must use canonical RFC3339 UTC millisecond form
```

另有 `invites/invite-addressing.spec.ts` 的 peer invite delivery 返回 `400 bad_json`。它的 typed request 内嵌同一 helper 生成的 Event Envelope，反序列化在 handler 业务逻辑前失败，属于同一根因。

受影响范围跨 authz、calls、conformance、encryption、extensions、governance、identity、messaging、models、spaces、sync、workflows 等目录。广泛分布不是这些产品模块同时回归，而是它们共享了同一 Event 构造 helper。

#### 直接证据

[`e2e/helpers/soland-api.ts:1631`](../../../e2e/helpers/soland-api.ts) 当前实现：

```ts
export function canonicalTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
```

它把 `2026-07-19T00:00:00.123Z` 改为 `2026-07-19T00:00:00Z`。同文件的 `signedEventEnvelope()` 将该值同时写入 Event `created_at` 和 proof binding。

规范证据一致且没有歧义：

- `arkret-spec/spec/v1/zh/conformance/encoding.md` 要求 Event Envelope 和 Event proof 固定为 `YYYY-MM-DDTHH:MM:SS.sssZ`，整秒也必须 `.000Z`；接收方必须拒绝无小数形式。
- `arkret-spec/spec/v1/zh/models/event-and-patch.md` 对 Event `created_at` 和 proof `created_at` 重复规定相同要求。
- `event-envelope.schema.json` 的 `canonical_event_timestamp` 固定三位毫秒。
- `arkret-rust-sdk` 的 `validate_timestamp_millis_canonical()` 要求长度 24，Soland 使用该 canonical validator 拒绝请求。

#### 判定

这是测试代码缺陷。spec、SDK validator 和 Soland fail-closed 行为一致，不能通过放宽 Soland 验证“修测试”。

#### 修改建议

1. 不要全局把现有 helper 简单改成一种精度。协议中同时存在两类时间戳：Event/proof 使用三位毫秒，而 cursor `t`、principal locator 等若干对象明确使用秒级无小数。
2. 拆分为语义明确的 helper，例如：
   - `canonicalEventTimestampMillis(date)`：返回 `date.toISOString()`，保证三位毫秒；
   - `canonicalTimestampSeconds(date)`：只用于规范明确要求秒级的对象。
3. `signedEventEnvelope()`、Event detached proof、Agent pairing transcript 等全部改用毫秒 helper；locator/cursor 等逐个按 schema 选择，禁止按字段名猜测。
4. 增加 helper 单测和 spec golden vector：必须保留 `.000Z`；必须拒绝无 fraction、非三位 fraction、`+00:00` 和微秒/纳秒。
5. 增加静态审计，禁止 Event 构造路径调用秒级 helper。

修复后应先只跑当前 54 个用例，再跑 `joint-full`。由于大量 suite 是 serial，RC-1 很可能还遮蔽了 182 个未执行用例中的新问题，修复后不能直接假定它们会通过。

### RC-2：`-StartCoauth` 本地拓扑与 coauth 私网出站策略互相冲突（3 个下游 error）

#### 现象

标准拓扑的生成配置把 Soland principal server 写为：

```yaml
arkret:
  principal_servers:
    - endpoint: "http://127.0.0.1:22356/"
```

coauth 日志第一组关键错误：

```text
outbound HTTP request failed service="soland" operation="principal_describe"
failed to resolve principal-server audience and no trusted cached value exists;
authentication is failing closed ...
transport error: builder error for url
(http://127.0.0.1:22356/_arkret/describe)
```

证据：[`coauth.stderr.log`](../../../artifacts/runs/20260719-003100/joint-e2e/services/coauth.stderr.log) 与 [`coauth.yaml`](../../../artifacts/runs/20260719-003100/joint-e2e/coauth.yaml)。

coauth 的 `outbound_http.rs` 对解析前 IP 和 DNS 解析后地址均应用 `OutboundPolicy::public_https()`。其 deployment hardening 文档明确说明：所有 build 均禁止私网出站，也不存在 process-wide private-network escape hatch。

#### 判定

coauth 的 fail-closed 行为符合其安全设计；错误在 joint runner 生成了必然被拒绝的 loopback 上游。它不是外部环境偶发失败，也不是 spec 应放宽的证据。

fallback 运行中以下 3 个测试的 `joint fixture requires coauth DPoP session-grant login` 只是这一启动阻断的下游表现，不应记为 Circle/Contacts/Inkson 产品功能失败：

- `joint/circle-sidecar-boundary.spec.ts`
- `joint/contact-agent-sidebar.spec.ts`
- `joint/joint-inkson-smoke.spec.ts`

#### 修改建议

1. P0 修复 runner/coauth 的集成契约；不要给 shared outbound client 添加全局 `allow_private_network=true`。
2. 首选由 runner 启动 dedicated egress proxy，并按 coauth 文档要求绑定 purpose、目标 service identity、trust domain、CIDR、port、expiry 与 audit。
3. 若本地测试必须直接 loopback，需在 coauth 引入仅限 principal discovery 的、purpose-bound 且 dev/test hard-gated 的 controlled-network allowance；规则必须精确到 `127.0.0.1/32 + 单端口 + service DID + 过期时间`，不能复用于 OIDC/JWKS 或任意 URL。
4. runner preflight 应在启动服务前验证生成 endpoint 是否会被 coauth egress policy 拒绝，给出确定性错误，避免等待 readiness 超时。
5. 修复后让 3 个 fixture 用例在缺少 coauth 时报告明确 prerequisite/skip；标准 `-StartCoauth` profile 则必须把缺失 coauth 当作 runner fail-fast。

#### 同一配置中的次要问题

coauth 日志还持续出现：

```text
webauthn_rs: rp_id is not an effective_domain of rp_origin
rp_id=127.0.0.1, rp_origin=http://127.0.0.1:22358/
```

这不是本次 503 的首要原因，但会阻断 WebAuthn 路径。runner 生成的 `public_base` 带尾部 `/`，应生成/归一化为 origin（scheme + host + port，无 path），并增加配置校验测试。

### RC-3：Directory 用例把 profile update 误当作隐式 announce（1 个失败）

#### 现象

`discovery/directory.spec.ts` 成功更新并从 account profile 读回 `display_name` 与 `profile_fields.bio`。Directory 搜索也返回更新后的 `display_name`，但测试断言 Directory row 顶层 `bio`，实际为 `undefined`。

#### 规范分析

`service-http-binding.md` 明确规定：

- `ak.self.account.command.update_profile` 写入/等价产生 `ak.profile.update`；
- 它**不隐式**触发 `ak.find.directory.command.announce` 或 `ak.account_data.set`；
- 需要可发现 profile 时，客户端/服务必须显式走 Directory announce；
- `bio` 的 ActorProfile canonical 落点是 `profile_fields.bio`，Directory 搜索结果仍受授权、隐私和 projection schema 限制。

测试注释中“profile update fans out through directory”与规范正面冲突。

#### 判定与建议

这是测试/spec mismatch，不是 Soland 必须自动公开 bio 的实现缺陷。建议把用例拆为：

1. `update_profile` 后只在 `/_arkret/self/account/viewer` 验证 canonical profile；
2. 显式调用 `ak.find.directory.command.announce` 后，再验证 Directory projection；
3. Directory 断言只覆盖对应 discovery profile 明确允许公开的字段。若要公开 bio，先在 schema/profile/privacy policy 中明确 projection 位置，再测该 profile；不要默认把私有简介泄漏到公共目录。

### RC-4：account_data initial sync 丢失 durable source，测试同时读取了错误形状（1 个失败）

#### 现象

`governance/personal-blocklist.spec.ts` 连续两次 PUT 相同 `data_type` 后：

- PUT、GET、list 均成功，list 中只有最新值；
- initial `GET /_arkret/self/account/subscribe?catchup=true` 的 `account_data.events` 中找不到该 key，收到 0 条而预期 1 条。

#### 实现证据

Soland `routing/identity/account_data.rs` 的 REST PUT 只执行：

- `account_data_application().save_entry(...)`；
- audit log；
- `fanout_actor_private_update(...)` 低延迟通知。

它没有把规范所说的 `ak.account_data.set` actor-private Event 持久化到 `events_store()`。

而 `routing/events/sync/snapshot.rs::account_data_events()` 构造 initial baseline 时只扫描 `events_store()` 中 `EventKind::ACCOUNT_DATA_SET`。因此 live/application projection 有值，重建 baseline 的 durable Event 来源却为空。

#### 测试侧问题

规范和 `account-subscribe-frame.schema.json` 定义 `account_data` 为 `event_container`，即 `account_data.events[]` 是 Event Envelope。key/value 在 `event.payload.key` 及 payload value/tombstone 中。

当前测试却按 `entry.data_type` 和 `entry.content` 的 REST DTO 形状读取 Event 根级字段。即使 Soland 补齐 canonical Event，现有 filter 仍会把它过滤掉。

#### 判定与建议

这是“实现 + 测试”双缺陷，spec 无需修改。

实现侧：REST replace/delete 应通过统一 Event acceptance 管线事务性持久化 `ak.account_data.set` actor-private Event，并更新 application projection/发送 wakeup；initial sync 从 durable Event/projection 重建最新 key。不要仅为让测试通过而在 snapshot 临时伪造非 canonical DTO。

测试侧：断言 `event.kind === "ak.account_data.set"`、`event.payload.key === dataType`，并按 canonical payload schema读取最新 value/tombstone。补充以下回归：覆盖写只保留最新值、另一设备 live fanout、服务重启后的 initial baseline、delete tombstone、敏感 key 的加密 carrier。

### RC-5：MIMI consent update 使用了错误的 proof 类型（1 个失败）

#### 现象

open consent request 成功，`POST /_arkret/open/mimi/consent/update` 对符合 schema 的 detached signature 返回 422。

测试发送的 signature 使用：

```json
{
  "kind": "detached_jws",
  "verification_method": "...",
  "alg": "EdDSA",
  "payload_digest": "sha256:...",
  "created_at": "...",
  "jws": "..."
}
```

`mimi-operations.schema.json#/$defs/signature` 引用非 Event generic proof，规范要求 `payload_digest`。但 `arkret-rust-sdk/crates/core/src/http/bodies.rs::MimiUpdateConsentRequestBody` 将 `signature` 声明为 `Proof`；wire-base 的 `Proof` 是 Event proof，要求 `event_digest` 且 `deny_unknown_fields`。Soland handler 又使用 `JsonBody<MimiUpdateConsentRequestBody>`，所以 schema 正确的 `payload_digest` 在进入业务处理前即反序列化失败。

#### 判定与建议

这是 SDK/Soland typed DTO 实现与 spec schema 不一致，不是测试应改成 `event_digest`。

建议把字段改为与 generic proof 完全同构的 `DetachedPayloadProof`（或建立专用 `MimiConsentUpdateProof`），并定义/验证 MIMI object-family signing context、payload canonical bytes、actor/consent/request/replay binding、domain/audience。SDK 增加 schema round-trip 和 unknown-field tests；Soland 增加 spec-correct `payload_digest` 成功、`event_digest` 失败、digest/binding/replay 失败的集成测试。现有测试使用占位 JWS，类型修复后还应改为真实签名，避免 bearer session 分支掩盖 proof 验证缺陷。

### RC-6：invite locator 测试要求接受规范明令禁止的 token（1 个失败）

#### 现象

测试自行构造：

```text
base64url(JSON({subject_id, nonce, expires_at}))
```

然后直接调用 open resolve 并期待 200。Soland 对 token 做 SHA-256 后在 locator store 查找，未找到即返回规范化 404 `not_found`。

#### 规范分析

`sync/invite-addressing.md` 明确要求：

- token 应是不透明 server-side handle；
- 至少 128 bit 熵，issue profile 要求 CSPRNG 至少 192 bit；
- raw token 只返回一次，服务端只保存 `sha256:` digest；
- token **MUST NOT** 是可解码的 `base64url(JSON)`，不得在明文中携带 subject、service、expiry 或策略状态。

因此让 Soland接受当前测试输入会造成安全与隐私回归。

#### 判定与建议

这是测试错误，spec 与 Soland行为正确。用例应先以认证 session 调用 `POST /_arkret/self/invite-locators` 发行 token，再把一次性 raw token 仅放在 resolve JSON body。随后验证：query/path 泄漏被拒绝、unknown token 不可枚举、rotate/revoke、TTL、one-time 并发最多一次成功、响应 `Cache-Control: private, no-store`，以及存储/audit 中不出现 raw token。

## 5. 测试前环境问题（已排除，不计入 61 个失败）

### 5.1 Dioxus wasm-bindgen tool cache 漂移

前两次准备运行分别位于：

- [`20260719-001041`](../../../artifacts/runs/20260719-001041/joint-e2e)
- [`20260719-002311`](../../../artifacts/runs/20260719-002311/joint-e2e)

Inkson 需要 `wasm-bindgen-cli 0.2.123`，Dioxus cache/runner PATH 固定到 `0.2.118`；runner 同时设置 `NO_DOWNLOADS=1`，导致 prepare 失败。通过正常 `dx build` 让 Dioxus 下载并缓存 0.2.123 后，后续 preflight 通过。未修改源码。

建议 runner 按项目 lockfile 选择精确版本的 `~/.dx/tools/wasm-bindgen-*`，并在设置 `NO_DOWNLOADS=1` 前验证版本；错误信息应给出修复命令。

### 5.2 Docker daemon 未启动

[`20260719-003012`](../../../artifacts/runs/20260719-003012/joint-e2e/preflight.md) 的 preflight 发现 Docker CLI 存在但 daemon 未运行。启动 Docker Desktop 后 server 29.6.1 可用，后续 coauth/Postgres 准备通过。该项为本机环境状态，不是代码或 spec 问题。

## 6. 版本与环境记录

| 组件 | revision / version |
|---|---|
| cotest | `ebe38aedb489d4b22be781f6321fad6ca1150bcc` |
| arkret-spec | `8e94329ec707a1e7f1aec1955e9af1672016c664` |
| arkret-rust-sdk | `1539ac7f6ae3b3d776e1abd75aa39902dd056580` |
| soland | `b84da3f0d6bcc99a3ace34c9e5fc2a0b22698307` |
| coauth | `23fad35836aec4b2e0737c04cd977a3de15b4766` |
| inkson | `385056abc1600ecc3ae2b656ced0cb11a0e3a05b` |
| Node / npm | `v24.18.0` / `11.16.0` |
| Playwright | `1.60.0` |
| rustc / cargo | `1.97.1` / `1.97.1` |
| Dioxus CLI | `0.7.9 (bfcc111)` |
| Docker client/server | `29.6.1 / 29.6.1` |

测试前相关仓库 `git status --short` 均为空；测试执行未改动这些仓库的 tracked source。

## 7. 建议实施顺序与复验门槛

### P0：先解除大面积失真

1. 拆分 cotest 秒级/毫秒级 helper，修复所有 Event producer；运行受影响 54 例。
2. 修复 `-StartCoauth` 的 purpose-bound 本地连接方案与 WebAuthn origin；标准拓扑必须通过 readiness，并运行 3 个 joint fixture 用例。
3. 再次执行完整命令，只有在 476 个用例均得到明确 pass/fail/expected skip 终态时，才把结果称为“标准联合拓扑全量执行完成”。

### P1：修复明确实现漂移

1. Soland account_data REST write 与 durable actor-private Event/initial baseline 收敛到同一事务模型，同时修正测试 Event shape。
2. SDK MIMI update signature 改为 generic payload proof，并完成真实签名/重放保护测试。

### P2：修正错误测试契约

1. Directory 测试显式 announce，并只断言 profile/policy 允许公开的字段。
2. Invite locator 测试改为 issue → resolve → rotate/revoke 的真实生命周期。

### 建议复验命令

```powershell
# P0 定向回归后，标准全量联合拓扑
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall
```

验收时至少要求：

- 不再出现 canonical Event timestamp 400；
- coauth describe ready，3 个 joint fixture 不再因 session-grant 缺失报错；
- `managed_service_failure_count = 0`；
- `did not run = 0`，或每个未执行项都有独立且可审计的 profile/fixture 原因；
- 42 个 fixme 继续作为已知 spec implementation debt 单独报告，不与回归失败混淆；
- 对修复后的剩余新失败重新按 spec 真源逐项归因，不能沿用本报告推断为已通过。
