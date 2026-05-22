// Sovereign deployment + controlled external collaboration enclave
// Contract: e2e/scenarios/sync/sovereign-deployment.md
// Spec: sync/sovereign-deployment.md §2-§6

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("sovereign deployment", () => {
  // soland gap: sovereign deployment + enclave realm + cross-domain trust chain 整体架构未实现
  // 当前 harness 只起单 soland;双节点 deployment profile、DID resolver policy、
  // enclave realm 承载、external-invite 流、directory 边界裁剪、federation
  // store-and-forward、审计日志按 subject 聚合 — 均未实现。
  // 下列 fixme 锁定 spec 契约,待 soland 双节点能力 + yougen enclave UI 就绪后填实现。

  test.fixme(
    // @blocking-on: soland#sync-sovereign-deployment-gap
    // @user-promise: e2e/scenarios/sync/sovereign-deployment.md
    // @expected-live-by: 2026Q3
    "alice_internal and bob_external collaborate in enclave realm; bob cannot escape; exit triggers audit log",
    async () => {
      // Phase A: soland_main 启动并配置严格 DID resolver policy
      //   (trust_roots = ["did:web:*.example"]);soland_enclave 启动并向 main
      //   完成可信注册,deployment_profile = "enclave"。
      //   断言 GET /api/v1/deployment/info 两侧 profile + 双向 trust;rogue
      //   DID 直接 register 主域被拒,reason did_method_not_trusted。
      //
      // Phase B: alice_internal 在 main 上创建 controlled collaboration
      //   Realm `E`(cx.realm.deployment_profile = "enclave",
      //   cx.realm.hosted_on = soland_enclave,
      //   cx.realm.external_invite_policy = "allowed"),并在 enclave 内建
      //   space S_enclave;另外在主域建私密 space S_internal 作为边界对照。
      //
      // Phase C: bob_external 通过 main 颁发的 external-invite 接入,
      //   accept-external-invite 在 soland_enclave 完成(走 enclave 的 trust
      //   chain,而非 main 的),session 落 enclave 节点;bob 在 main 上不是
      //   first-class 账户。
      //
      // Phase D: alice 与 bob 在 S_enclave 内互发消息、上传/下载文件 F1;
      //   blob URL 指向 soland_enclave;sync frontier 两侧一致。
      //
      // Phase E: bob 试图访问主域资源 (S_internal、directory 搜索、federation
      //   proxy hop) → 全部被拒,reason external_user_no_main_access /
      //   enclave_no_upstream_proxy_for_external;alice 主域私密 realm 对
      //   bob 不可见。
      //
      // Phase F: bob 离开 enclave Realm,session 失效;alice 调
      //   GET /api/v1/deployment/audit?subject=<bob.did> 取得审计日志,
      //   验证日志覆盖:接受邀请、可见 space 列表 (= [S_enclave])、文件
      //   上传/下载清单 (含 F1)、消息 ID 列表、边界拒绝事件、离开事件。
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-sovereign-deployment-gap
    // @user-promise: e2e/scenarios/sync/sovereign-deployment.md
    // @expected-live-by: 2026Q3
    "E7.1 escape attempt rejected: bob cannot reach main domain via directory / direct API / enclave proxy",
    async () => {
      // soland gap: directory cross-realm 裁剪 + federation proxy 防 escape
      // 检查 + 外部用户对主域 API 的统一拒绝路径均未实现。
      //
      // Vectors to cover:
      //   - bob 在 yougen directory 搜索 main domain space title → 空集 / 403
      //   - bob 直接 GET <soland_main>/api/v1/space/<internalSpaceId>
      //     → 403,reason external_user_no_main_access
      //   - bob 通过 <soland_enclave>/api/v1/federation/proxy 间接到 main
      //     → 拒,reason enclave_no_upstream_proxy_for_external
      //   - bob 在 enclave space 内 mention alice 主域 DID:mention 本身允许
      //     (alice 在 enclave 也是成员),但 mention 解析 metadata 不会暴露
      //     alice 在主域其他 space 的成员关系 / presence
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-sovereign-deployment-gap
    // @user-promise: e2e/scenarios/sync/sovereign-deployment.md
    // @expected-live-by: 2026Q3
    "E7.2 network outage: soland_main <-> soland_enclave 失联时 enclave 走 store-and-forward,而非客户端 offline outbox",
    async () => {
      // soland gap: enclave 节点的 federation store-and-forward 队列、main
      // 侧的 "enclave sync lag" 状态暴露均未实现。
      //
      // 步骤:
      //   - harness 用 route.fulfill 拦掉 main <-> enclave 之间的 federation
      //     endpoint,模拟链路中断
      //   - bob 在 enclave 内继续发消息、上传文件 → 应该成功 (enclave 本地
      //     接受写入),UI 不显示 "pending sync"(关键区别于 sync/offline-
      //     conflict.md 的 E26.*:store-and-forward 是节点间,不是客户端
      //     outbox)
      //   - alice 在主域查 enclave Realm frontier → 滞后,UI 显示
      //     "enclave sync lag" 标记,但不报错
      //   - 取消拦截,main 拉 federation pull,store-and-forward 队列推送
      //     过去,alice 同步看到 bob 离线期间的所有消息、文件
      //   - 断言:最终状态收敛,无消息丢失,顺序与 enclave 本地一致
    },
  );

  test.fixme(
    // @blocking-on: soland#sync-sovereign-deployment-gap
    // @user-promise: e2e/scenarios/sync/sovereign-deployment.md
    // @expected-live-by: 2026Q3
    "E7.3 enclave DID resolver policy: bob 的 DID 必须通过 enclave 的 trust chain 验证(不是 main 的)",
    async () => {
      // soland gap: per-node DID resolver trust roots、per-realm DID resolver
      // policy、session 内 DID document 变更校验均未实现。
      //
      // 校验点:
      //   - did:web:bob-ext-<uuid>.example.org 属于 enclave trust roots
      //     (但不属于 main trust roots)→ 能 accept-external-invite 加入
      //     enclave;直接 register 到 main 被拒
      //   - 一个仅属于 main trust roots 而不在 enclave trust roots 的 DID
      //     → 在 enclave 加入时被拒,reason enclave_did_method_not_trusted
      //   - bob 在 enclave session 内尝试更换 DID document 为
      //     did:web:rogue.evil → enclave 重新解析 trust chain 失败,session
      //     立即失效
    },
  );
});
