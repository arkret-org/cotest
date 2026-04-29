# cotest 任务清单

本文件记录本轮按照 Complement 思路重构 `cotest` 后的测试计划、单机 /
多机覆盖矩阵，以及已经完成并验收的任务状态。

## Complement 实现原理映射

- [x] 保持 `cotest` 为独立测试项目，不把可复用业务/测试逻辑堆在 `tests/`
      目录里；公共 harness 和场景逻辑已移动到 `src/harness.rs` 与
      `src/scenarios/`。
- [x] 采用 “每个测试按需拉起真实服务进程” 的黑盒模型，对应 Complement 的
      deploy/runtime 思路；当前通过 `ContrixServer` / `TestServerGroup`
      管理进程生命周期。
- [x] 采用高层测试客户端抽象，对应 Complement 的 helper/client 模式；当前
      通过 `TestActorClient`、HTTP 断言工具和 `contrix-rust-sdk` 类型辅助
      复用测试动作。
- [x] 采用按协议域/业务域组织套件，对应 Complement 的 package-by-domain
      方式；当前 `tests/*.rs` 仅保留薄封装，实际场景在 `src/scenarios/*.rs`。
- [x] 保持 out-of-repo 测试定位：仅通过公开 HTTP 接口和有限 SDK smoke
      path 验证服务，不链接被测服务内部实现。

## 工程改造任务

- [x] 将旧 `tests/support/mod.rs` 的核心能力迁移为正式 harness 模块。
- [x] 将各测试文件中的可复用业务场景迁移到 `src/scenarios/`。
- [x] 调整 `Cargo.toml`，让 `src/` 中的 harness/scenario 可以直接依赖
      `contrix-rust-sdk`、`reqwest`、`tokio`、`serde_json` 等运行时库。
- [x] 将默认被测服务切换到 `E:\Works\contrix-dev\soland\Cargo.toml`，并保留
      `COTEST_SUT_MANIFEST` 可配置入口。
- [x] 删除已无价值的 ignored 占位测试，改为可执行的 extension surface gap
      检查。

## 单机测试矩阵

- [x] `service_surface`
      服务健康检查、服务描述、`sync/directory/index` describe，以及必需操作
      广告面验证。
- [x] `api_contracts_auth`
      标准错误信封、非法 JSON、账号注册/登录/登出、会话校验、联系人边界。
- [x] `collaboration_workflow`
      账号引导、空间创建、成员添加、消息发送、同步与索引投影。
- [x] `delivery_media`
      设备密钥上传/查询/领取、to-device 投递、Blob 上传/下载/Range/哈希校验。
- [x] `events_entity_backfill`
      事件写入、实体/线程投影、缺口恢复与回填相关表面。
- [x] `identity_directory_index`
      身份描述/解析/文档/日志/回执、目录搜索/解析、同步 profile、导出、审计、
      通知与 inbox 投影。
- [x] `authz_policy_presence`
      grant/check/effective-grants/revoke、presence、push device、策略检查、
      ICE 配置契约。
- [x] `interaction_models`
      消息修订/脱敏、reaction、read marker、subscribe、实体/关系/view 端点。
- [x] `schema_policy_realtime`
      schema registry、policy documents、typing ephemeral、push rules、WebRTC
      signaling 会话与参与者边界。
- [x] `extension_surface_gaps`
      对 applet / agent 当前缺失路由进行可执行探测，保证缺口可见。
- [x] `protocol_payloads`
      协议载荷、加密信封、回执、对象负载格式兼容性。
- [x] `repo_sync_index`
      repo 提交、重复提交幂等、commit/operations 读取、repo sync、参数边界、
      CAS 冲突。
- [x] `space_permissions`
      成员权限、owner-only 修改、删除后空间行为、非成员拒绝、私有明文策略。

## 多服务器测试矩阵

- [x] `federation_readiness`
      多实例拉起、远端服务发现、联邦就绪性与基本连通性。
- [x] `federation_contract`
      transaction / push / pull / verify-actor 等联邦接口的正反向契约校验。
- [x] `federation_collaboration`
      跨服务成员协作、远端消息传播、跨服同步可见性、联邦投影结果验证。

## 本轮契约对齐修正

- [x] 将 `serverx` 旧路径/旧命名收敛到当前 `soland` 运行方式。
- [x] 将重复注册、重复联系人等错误码对齐到当前 `soland` 的
      `duplicate_conflict`。
- [x] 将 repo stale-commit 冲突对齐到当前 `soland` 的 `cas_conflict`。
- [x] 将 `sync/describe` 中 `service_did` 断言调整为当前可验证的非空契约。
- [x] 对 `repo_describe`、`repo_commits`、`repo_commit`、`repo_sync` 中 SDK
      与当前 `soland` wire 不一致的部分，改用原始 HTTP 契约断言，避免客户端
      模型漂移造成假失败。

## 验收结果

- [x] 生成了独立 harness 结构，`tests/` 不再承载主要业务逻辑。
- [x] 已接入 `E:\Works\contrix-dev\contrix-rust-sdk` 作为类型与客户端辅助依赖。
- [x] 已完成 `_todos.md` 规划与状态落盘。
- [x] 已完成 `_todos.md` 中本轮所有可执行测试任务并勾选。

## 当前仍未闭合的协议缺口（细化记录，不计入本轮待办）

- 身份与组织:
  `did:uuid`、handle claim / attestation、key rotation / recovery、organization
  principal 当前没有独立 HTTP 生命周期面或 conformance vectors 注入口，现阶段
  只能停留在 `identity/*` 描述面与 resolve/log/receipt 契约测试。
- 授权与状态解析:
  grant / revoke / policy docs 已覆盖，但 approval constraint、claim
  condition、并发 membership / governance state resolution 仍缺少可注入冲突向量
  的专用 harness；这部分需要按 `state-resolution-conformance-vectors.md`
  建独立向量驱动测试。
- 同步一致性:
  repo submit、client sync、subscribe、backfill、snapshot head 已覆盖基础契约，
  但 `state_after`、snapshot chunk、cursor 过期、乱序恢复、MLS epoch
  backfill 仍需要更强的多阶段向量与快照伪造能力，当前 SUT 没有对应入口。
- Discovery / Preferences:
  presence、typing、directory、notifications、push rules 已覆盖；但 account
  data、私有标签、个人 blocklist、通知偏好合并查询等 `client-preferences`
  语义当前未暴露成独立服务面。
- 加密与设备:
  device keys、to-device、encrypted envelope、blob、ICE / WebRTC signaling
  已覆盖；MLS、cross-signing、secret storage、key backup、设备验证流程在
  当前 `soland` 中仍无完整公开面，无法做真正的黑盒正向用例。
- 扩展与第三方集成:
  applet / agent 仍以 “surface gap” 方式跟踪；等 `contrix-spec` 和服务暴露
  稳定正向接口后，再补生命周期与互操作流程测试。
- 一致性向量:
  canonical JSON / digest 的基础提交路径已间接覆盖，但 encoding、redaction、
  capability、state resolution、snapshot frontier 的官方 vector 仍应单独落成
  fixture 驱动套件，而不应混在业务场景测试里。
- SDK 契约:
  如果后续需要把 `contrix-rust-sdk` 作为更强的一致性校验面，可单独新增 SDK
  契约兼容套件，而不要让服务器黑盒测试被 SDK 当前 wire 漂移绑死。
