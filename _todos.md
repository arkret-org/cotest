# cotest Active TODO

> 更新日期: 2026-04-29
> 范围: Contrix 黑盒一致性测试套件，借鉴 Matrix Complement 的多服务部署、fixture、scenario 和报告模型。`cotest` 只通过公开接口测试 SUT，不链接被测实现内部代码。

## 0. 当前边界

- 已有本地进程和 Docker SUT 运行模式。
- 已有 `ContrixServer` / `TestServerGroup` harness、测试客户端和按领域组织的 scenarios。
- 已覆盖 soland 的基础 HTTP surface、单机协作、repo/sync/index、blob、authz、device、federation smoke。
- 当前主要缺口: 可注入冲突向量、starid/floria/coauth/chask 多项目栈、E2EE/device 深度测试、请求/响应 transcript 与 CI profile 落地。

## P0: Official Fixture Runner

目标: 从 `contrix-spec` 消费同一组 fixture，避免每个实现各写各的“通过标准”。

- [x] Encoding suite:
  - [x] canonical JSON。
  - [x] digest/hash。
  - [x] proof payload。
  - [x] HLC。
  - [x] cursor。
  - [x] rank/fractional index。
- [x] State resolution suite:
  - [x] membership conflict。
  - [x] capability grant/revoke/delegate race。
  - [x] schema/policy update race。
  - [x] deterministic tie-breaker。
- [x] Redaction suite:
  - [x] preserved fields。
  - [x] dangling redaction。
  - [x] late target event。
  - [x] audit visibility。
- [x] Capability suite:
  - [x] resource selector grammar。
  - [x] constraints fail-closed。
  - [x] approval/proposal。
  - [x] delegation cycle。
  - [x] claim revocation unavailable。
- [x] Sync suite:
  - [x] initial/incremental sync。
  - [x] `state_after`。
  - [x] limited timeline/backfill。
  - [x] expired cursor。
  - [x] filter mismatch。
  - [x] to-device ack。
  - [x] snapshot manifest/chunks。
- [x] Federation signature suite:
  - [x] canonical request hash。
  - [x] origin/destination mismatch。
  - [x] replay。
  - [x] fork quarantine。
  - [x] pull authorization。
- [x] Privacy/security suite:
  - [x] private blob HEAD/Range anti-enumeration。
  - [x] push blind wakeup。
  - [x] pairwise/private DID resolve proof。
  - [x] encrypted payload forwarding without plaintext。
  - [ ] query auth rejection。

并行性: 每个 suite 可独立实现；fixture loader 和 report format 先冻结。

## P0: SUT Matrix

目标: 不只测 soland 单体，覆盖项目实际边界。

- [ ] `soland` Principal Server:
  - [ ] memory mode。
  - [ ] PostgreSQL mode。
  - [ ] two-service federation mode。
- [ ] `starid` Identity Registry:
  - [ ] memory mode。
  - [ ] PostgreSQL mode。
  - [ ] external resolver mock。
- [ ] `floria` Push Gateway:
  - [ ] provider mock mode。
  - [ ] service auth required mode。
  - [ ] invalid-token cleanup flow。
- [ ] `coauth` Auth / Account Server:
  - [ ] OIDC discovery/JWKS/token flow。
  - [ ] admin API smoke。
  - [ ] DID binding flow with starid。
- [ ] `chask` client smoke:
  - [ ] browser E2E against local stack。
  - [ ] login/sync/message/push settings smoke。
- [ ] `sodmin` admin smoke:
  - [ ] login through coauth。
  - [ ] read soland/coauth admin pages。
  - [ ] mutation writes audit。

## P0: Harness Capabilities

- [ ] Deployment:
  - [ ] compose generator for multi-project stacks。
  - [ ] per-service env overrides。
  - [ ] deterministic ports/network names。
  - [x] health/readiness waiters。
  - [x] log capture per service。
- [ ] Fixture injection:
  - [ ] submit arbitrary operations。
  - [ ] submit conflicting branches。
  - [ ] fake remote federation transaction。
  - [ ] fake snapshot manifest/chunk。
  - [ ] fake DID document/key-log。
  - [ ] fake push provider response。
- [ ] Time/control:
  - [ ] cursor expiry。
  - [ ] token expiry。
  - [ ] grant expiry。
  - [ ] delayed backfill。
  - [ ] retry-after behavior。
- [ ] Assertions:
  - [x] error envelope matcher。
  - [ ] anti-enumeration matcher。
  - [ ] audit event matcher。
  - [ ] eventual consistency wait。
  - [ ] no-secret-in-log scan。

## P0: Principal Server Scenario Suites

- [ ] Account/session:
  - [x] register/login/logout/me。
  - [ ] locked/disabled/erased account behavior。
  - [x] token hash/revocation semantics where observable。
- [ ] Repo/write path:
  - [x] commit submit。
  - [ ] duplicate same/different body。
  - [x] expected_head CAS。
  - [ ] proof invalid cases。
  - [ ] projection rollback on failure。
- [ ] Sync:
  - [x] initial/incremental。
  - [x] state_after。
  - [x] limited/backfill。
  - [ ] wait-for。
  - [x] to-device ack。
- [ ] Authz/policy:
  - [x] grant before write accepted。
  - [x] write before grant rejected。
  - [x] revoke then write rejected。
  - [ ] policy deny/quarantine/review。
  - [ ] stale frontier rejected。
- [ ] Directory/index:
  - [ ] discoverability matrix。
  - [ ] per-result auth filtering。
  - [ ] private DID/actor search privacy。
  - [x] relation traversal。
- [ ] Blob/media:
  - [x] upload hash verification。
  - [ ] authenticated download。
  - [x] HEAD/Range。
  - [ ] invisible vs nonexistent。
  - [ ] quota/retention when available。

## P0: Identity Registry Scenario Suites

- [ ] `did:uuid` v8:
  - [ ] deterministic generation vectors。
  - [ ] invalid hash/key/method rejection。
  - [ ] uppercase rejection。
- [ ] DID document:
  - [ ] submit/resolve/document/log/receipts。
  - [ ] restart persistence in PG mode。
  - [ ] include log/receipts。
- [ ] Key-log:
  - [ ] append CAS。
  - [ ] skipped seq。
  - [ ] wrong previous hash。
  - [ ] rotate/recover/deactivate。
  - [ ] deactivated append reject。
- [ ] Proof:
  - [ ] invalid signature。
  - [ ] wrong audience。
  - [ ] stale proof。
  - [ ] private/pairwise resolve proof。
- [ ] Receipts:
  - [ ] signature verification。
  - [ ] witness threshold。
  - [ ] superseded/revoked receipt。

## P0: Push and Notification Suites

- [ ] `soland -> floria` flow:
  - [ ] register device。
  - [ ] trigger notification。
  - [ ] provider mock receives body-free payload。
  - [ ] invalid token cleanup。
- [ ] floria auth:
  - [ ] unauthenticated notify rejected。
  - [ ] bad service DID rejected。
  - [ ] expired signature rejected。
  - [ ] replay rejected。
- [ ] Privacy:
  - [ ] message body rejected。
  - [ ] encrypted payload bytes rejected。
  - [ ] SDP/ICE/TURN rejected。
  - [ ] logs do not contain full push token。

## P1: Client, Admin and E2EE Suites

- [ ] `chask`:
  - [ ] production auth smoke once coauth is ready。
  - [ ] offline queue and reconnect。
  - [ ] multi-device sync。
  - [ ] E2EE group lifecycle。
  - [ ] WebCrypto/IndexedDB storage when implemented。
- [ ] `sodmin`:
  - [ ] route smoke for all admin pages。
  - [ ] denied scope path。
  - [ ] destructive action confirmation。
  - [ ] audit event after mutation。
- [ ] E2EE/device:
  - [ ] KeyPackage publish/fetch。
  - [ ] Welcome/Commit/Proposal。
  - [ ] device verification。
  - [ ] key backup/recovery。
  - [ ] removed member fail-closed。

## P1: Reporting, CI and Release Artifacts

- [ ] Output formats:
  - [x] JSON summary。
  - [x] JUnit XML。
  - [x] human HTML/Markdown。
  - [x] per-profile coverage matrix。
  - [x] unresolved spec gap list。
- [ ] Artifacts:
  - [x] service logs。
  - [ ] request/response transcript with secrets redacted。
  - [ ] screenshots for browser tests。
  - [x] fixture version。
  - [x] SUT commit/version。
- [ ] CI:
  - [ ] fast smoke profile。
  - [ ] full nightly profile。
  - [ ] flaky quarantine label。
  - [ ] Docker cache/build strategy。
  - [ ] fail if coverage regresses for required profile。

## Definition of Done

- [x] Test only uses public API or documented fixture injection endpoint。
- [ ] Failure output includes enough request/response context with secrets redacted。
- [x] Suite maps to a spec file and profile requirement。
- [x] Multi-service tests clean up processes, containers, networks and artifacts deterministically。
- [x] Coverage report can be used by release gates in SDK/server/client repos。
