// MIMI federation (Realm ↔ external MIMI network via Provider Facade)
// Contract: e2e/scenarios/extensions/mimi-federation.md
// Spec: extensions/mimi-interop.md §1-§7
//   §1 Provider Facade overview
//   §2 Realm `federation_profile = "mimi_interop"` + endpoint exposure
//   §3 Room binding: Contrix Flow ↔ MIMI room; event ↔ Message translation
//   §4 Content mapping: standard MIMI content type ↔ `cx.morph` kind; unknown → quarantine
//   §5 Policy mapping: join_rule / history_visibility ↔ MIMI room policy
//   §6 Identity bridging: MIMI handle → pairwise DID, per-Realm scoped (unlinkability)
//   §7 E2EE boundary: MLS-via-IETF profile transcript binding or explicit downgrade

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("mimi federation", () => {
  // soland gap: MIMI Provider Facade + room binding + identity bridging 未实现
  // (MIMI interop 是 extension profile,v1 core 不必需)。
  // helpers/mimi-facade.ts (mock facade + bob_mimi 预置身份) 尚未提供。
  // 所有 case 暂以 fixme 形式锚定 spec 形状,等 facade 实装后再补主体。

  test.fixme(
    "alice opens MIMI-enabled Realm; bob_mimi joins via facade; bidirectional messaging with identity bridging",
    async () => {
      // Phase A — alice 通过 /setup 创建 Realm,设
      //   cx.realm.federation_profile = "mimi_interop"
      // 断言 GET /api/v1/realm/:id/federation/mimi/endpoint 返回 mimi_endpoint_url + room_binding_id。
      //
      // Phase B — mimi_facade (mock) 模拟外部 MIMI 网络的 join request,
      //   翻译为 Contrix 的 cx.invite.request / knock,投递到 soland;
      //   alice 的 /realm/:id/admin 看到 federation-inbound-panel 含 mimi 来源标记。
      //
      // Phase C — alice approve;soland 通过 facade 验证 bob_mimi 的 MIMI identity,
      //   按 spec §6 生成 pairwise DID = did:pairwise:${realmId}/${hash(handle, realmId.salt)};
      //   POST /api/v1/realm/:id/federation/mimi/approve 返回 pairwise_did;
      //   GET /api/v1/realm/:id/members 含 source = mimi 的成员。
      //
      // Phase D — alice 在 /timeline/:realmId 发 M1;
      //   facade mock 记录到 outbound MIMI event;soland message 挂
      //   cx.morph.federation_outbound = "mimi" + mimi_event_id。
      //   facade 把 bob_mimi 在 MIMI 网络的 MM2 翻译为 Contrix Message;
      //   alice timeline 在 30s 内出现 MM2,sender 显示为 pairwise DID;
      //   消息挂 cx.morph.federation_inbound = "mimi" + mimi_origin_event_id。
      //   alice reply MM2 → M3;reply 关系在 MIMI ↔ Contrix 双向保留。
      //
      // Phase E — Phase B 的 approve 隐含 per-Realm consent;
      //   bob_mimi 的 pairwise DID 只对当前 Realm 有效,
      //   尝试在另一 Realm R2 中以同一 pairwise DID 投递应被拒。
      //   (cross-link 到 identity/consent-grant scenario)
    },
  );

  test.fixme(
    "E5.1 MIMI endpoint 不可达 → federation fallback: 消息本地保留 + outbound 状态标记 deferred,facade 恢复后重试",
    async () => {
      // facade mock 主动返回 5xx / timeout;
      // alice 发 M1 应仍然 persist 到 soland 本地、对 Contrix 成员可见;
      // message 挂 cx.morph.federation_outbound_status = "deferred";
      // facade 恢复后,soland 自动重试投递,状态转为 "delivered"。
    },
  );

  test.fixme(
    "E5.2 E2EE 在 MIMI 中的转换:transcript binding 或 explicit downgrade 标记,绝不静默泄露明文",
    async () => {
      // Contrix E2EE Flow 经 facade 进入 MIMI 时:
      //   要么有 MLS-via-IETF profile 的 transcript binding 桥(两套 group key);
      //   要么消息挂明确的 cx.morph.e2ee_downgrade = "mimi_bridge" 并在 UI 提示;
      //   任何情况下都不能把明文以未标记的方式发送给 MIMI 网络。
      // spec: extensions/mimi-interop.md §7
    },
  );

  test.fixme(
    "E5.3 content type 差异:MIMI 特有 content kind → quarantine + cx.morph.unknown_content_kind",
    async () => {
      // facade 把 bob_mimi 发的 m.location.share.live 翻译进来;
      // soland 无法映射到 Contrix content kind;
      // 消息进入 quarantine 状态,挂 cx.morph.unknown_content_kind = "<mimi.type>";
      // timeline 渲染为 "unsupported content from MIMI" 占位,而不是丢弃、也不是渲染原始 payload。
      // spec: extensions/mimi-interop.md §4
    },
  );
});
