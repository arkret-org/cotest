// MIMI federation (Realm ↔ external MIMI network via Provider Facade)
// Contract: e2e/scenarios/extensions/mimi-federation.md
// Spec: extensions/mimi-interop.md §1-§7
//   §1 Provider Facade overview
//   §2 Realm `federation_profile = "mimi_interop"` + endpoint exposure
//   §3 Room binding: Cokret Flow ↔ MIMI room; event ↔ Message translation
//   §4 Content mapping: standard MIMI content type ↔ `ck.morph` kind; unknown → quarantine
//   §5 Policy mapping: join_rule / history_visibility ↔ MIMI room policy
//   §6 Identity bridging: MIMI handle → pairwise DID, per-Realm scoped (unlinkability)
//   §7 E2EE boundary: MLS-via-IETF profile transcript binding or explicit downgrade

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  createSpaceApi,
  querySpaceEventsApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("mimi federation", () => {
  // soland/yougen gap: MIMI Provider Facade binding + room binding +
  // identity bridging 未实现(MIMI interop 是 extension profile,v1 core 不必需)。
  // cotest 已提供 helpers/mimi-facade.ts 与 mock facade;业务 case 仍以 fixme
  // 锚定服务端/客户端待实现链路。

  test.fixme(
    // @blocking-on: soland#extensions-mimi-federation-gap
    // @user-promise: e2e/scenarios/extensions/mimi-federation.md
    // @expected-live-by: 2026Q3
    "alice opens MIMI-enabled Realm; bob_mimi joins via facade; bidirectional messaging with identity bridging",
    async () => {
      // Phase A — alice 通过 /setup 创建 Realm,设
      //   ck.realm.federation_profile = "mimi_interop"
      // 断言 GET /_cokret/self/realm/:id/federation/mimi/endpoint 返回 mimi_endpoint_url + room_binding_id。
      //
      // Phase B — mimi_facade (mock) 模拟外部 MIMI 网络的 join request,
      //   翻译为 Cokret 的 ck.invite.request / knock,投递到 soland;
      //   alice 的 /realm/:id/admin 看到 federation-inbound-panel 含 mimi 来源标记。
      //
      // Phase C — alice approve;soland 通过 facade 验证 bob_mimi 的 MIMI identity,
      //   按 spec §6 生成 pairwise DID = did:pairwise:${realmId}/${hash(handle, realmId.salt)};
      //   POST /_cokret/self/realm/:id/federation/mimi/approve 返回 pairwise_did;
      //   GET /_cokret/self/realm/:id/members 含 source = mimi 的成员。
      //
      // Phase D — alice 在 /timeline/:realmId 发 M1;
      //   facade mock 记录到 outbound MIMI event;soland message 挂
      //   ck.morph.federation_outbound = "mimi" + mimi_event_id。
      //   facade 把 bob_mimi 在 MIMI 网络的 MM2 翻译为 Cokret Message;
      //   alice timeline 在 30s 内出现 MM2,sender 显示为 pairwise DID;
      //   消息挂 ck.morph.federation_inbound = "mimi" + mimi_origin_event_id。
      //   alice reply MM2 → M3;reply 关系在 MIMI ↔ Cokret 双向保留。
      //
      // Phase E — Phase B 的 approve 隐含 per-Realm consent;
      //   bob_mimi 的 pairwise DID 只对当前 Realm 有效,
      //   尝试在另一 Realm R2 中以同一 pairwise DID 投递应被拒。
      //   (cross-link 到 identity/consent-grant scenario)
    },
  );

  test.fixme(
    // @blocking-on: soland#extensions-mimi-federation-gap
    // @user-promise: e2e/scenarios/extensions/mimi-federation.md
    // @expected-live-by: 2026Q3
    "E5.1 MIMI endpoint 不可达 → federation fallback: 消息本地保留 + outbound 状态标记 deferred,facade 恢复后重试",
    async () => {
      // facade mock 主动返回 5xx / timeout;
      // alice 发 M1 应仍然 persist 到 soland 本地、对 Cokret 成员可见;
      // message 挂 ck.morph.federation_outbound_status = "deferred";
      // facade 恢复后,soland 自动重试投递,状态转为 "delivered"。
    },
  );

  test("E5.2 E2EE 在 MIMI 中的转换:transcript binding 或 explicit downgrade 标记,绝不静默泄露明文", async ({
    request,
  }) => {
    const stamp = Date.now();
    const { token, spaceId, roomId } = await createBoundMimiRoom(request, stamp, "e2ee");

    const unmarked = await request.post(mimiMessagesUrl(roomId), {
      data: {
        source_format: "application/mimi-content",
        e2ee: true,
        content: {
          kind: "ck.content.text",
          body: `silent plaintext leak ${stamp}`,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:e2ee:unmarked:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
      },
    });
    expect(unmarked.status()).toBe(400);
    expect(wireErrCode(await unmarked.json())).toBe("mimi_e2ee_boundary_unmarked");

    const downgradeText = `explicit downgrade ${stamp}`;
    const downgrade = await request.post(mimiMessagesUrl(roomId), {
      data: {
        source_format: "application/mimi-content",
        e2ee: true,
        e2ee_downgrade: "mimi_bridge",
        content: {
          kind: "ck.content.text",
          body: downgradeText,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:e2ee:downgrade:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
      },
    });
    expect(downgrade.status()).toBe(200);
    const downgradeBody = (await downgrade.json()) as Record<string, unknown>;
    expect(downgradeBody.status).toBe("mapped");
    expect(nested(downgradeBody, "receipt", "extra", "mimi_policy", "e2ee_boundary")).toBe(
      "explicit_downgrade",
    );

    const transcriptText = `transcript bound ${stamp}`;
    const transcript = await request.post(mimiMessagesUrl(roomId), {
      data: {
        source_format: "application/mimi-content",
        encrypted: true,
        transcript_binding: {
          profile: "mls-via-ietf-mimi",
          transcript_hash: `sha256:transcript-${stamp}`,
        },
        content: {
          kind: "ck.content.text",
          body: transcriptText,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:e2ee:transcript:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
      },
    });
    expect(transcript.status()).toBe(200);
    const transcriptBody = (await transcript.json()) as Record<string, unknown>;
    expect(nested(transcriptBody, "receipt", "extra", "mimi_policy", "e2ee_boundary")).toBe(
      "transcript_bound",
    );

    const events = await querySpaceEventsApi(request, token, spaceId);
    const downgradeEvent = eventById(events, String(downgradeBody.cokret_event_id));
    expect(nested(downgradeEvent, "payload", "content", "body")).toBe(downgradeText);
    expect(nested(downgradeEvent, "payload", "content", "ck.morph.e2ee_downgrade")).toBe(
      "mimi_bridge",
    );
    expect(nested(downgradeEvent, "payload", "mimi_policy", "e2ee_boundary")).toBe(
      "explicit_downgrade",
    );

    const transcriptEvent = eventById(events, String(transcriptBody.cokret_event_id));
    expect(nested(transcriptEvent, "payload", "content", "body")).toBe(transcriptText);
    expect(
      nested(transcriptEvent, "payload", "content", "transcript_binding", "transcript_hash"),
    ).toBe(`sha256:transcript-${stamp}`);
    expect(nested(transcriptEvent, "payload", "mimi_policy", "e2ee_boundary")).toBe(
      "transcript_bound",
    );
  });

  test("E5.3 content type 差异:MIMI 特有 content kind → quarantine + ck.morph.unknown_content_kind", async ({
    request,
  }) => {
    const stamp = Date.now();
    const { token, spaceId, roomId } = await createBoundMimiRoom(request, stamp, "content");
    const rawLocation = `geo:31.2304,121.4737;u=${stamp % 100}`;

    const quarantine = await request.post(mimiMessagesUrl(roomId), {
      data: {
        source_format: "application/mimi-content",
        content_kind: "m.location.share.live",
        content: {
          kind: "m.location.share.live",
          geo_uri: rawLocation,
          body: `live location ${stamp}`,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:content:unknown:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
      },
    });
    expect(quarantine.status()).toBe(200);
    const body = (await quarantine.json()) as Record<string, unknown>;
    expect(body.status).toBe("quarantined");
    expect(nested(body, "receipt", "extra", "quarantine", "unknown_content_kind")).toBe(
      "m.location.share.live",
    );

    const events = await querySpaceEventsApi(request, token, spaceId);
    const event = eventById(events, String(body.cokret_event_id));
    expect(nested(event, "payload", "content", "kind")).toBe("ck.content.unsupported");
    expect(nested(event, "payload", "content", "body")).toBe("unsupported content from MIMI");
    expect(nested(event, "payload", "content", "ck.morph.unknown_content_kind")).toBe(
      "m.location.share.live",
    );
    expect(JSON.stringify(event)).not.toContain(rawLocation);
  });
});

async function createBoundMimiRoom(
  request: APIRequestContext,
  stamp: number,
  suffix: string,
): Promise<{ token: string; spaceId: string; roomId: string }> {
  const alice = uniqueUser(`mimi-${suffix}-${stamp}`);
  await ensureRegistered(request, alice);
  const token = await issueDevSession(request, alice);
  const spaceId = await createSpaceApi(request, token, {
    title: `mimi ${suffix} ${stamp}`,
    discoverability: "listed",
    history_visibility: "joined",
    encryption_profile: "mls_rfc9420",
  });
  const roomId = `MIMI-${suffix}-${stamp}`;
  const update = await request.put(`${solandBaseUrl()}/_cokret/open/mimi/flows/${roomId}/update`, {
    data: {
      room_binding: {
        profile: "ck.profile.mimi_interop.v1",
        mimi_room_uri: `mimi://soland.local/rooms/${roomId}`,
        binding_scope: {
          space_id: spaceId,
          flow_id: null,
        },
        content_profile: "application/mimi-content",
      },
      protocol_draft: "draft-ietf-mimi-protocol-06",
    },
  });
  expect(update.status()).toBe(200);
  return { token, spaceId, roomId };
}

function mimiMessagesUrl(roomId: string): string {
  return `${solandBaseUrl()}/_cokret/open/mimi/flows/${encodeURIComponent(roomId)}/messages`;
}

function eventById(eventsBody: Record<string, unknown>, eventId: string): Record<string, unknown> {
  const events = Array.isArray(eventsBody.events) ? eventsBody.events : [];
  const event = events.find(
    (item) =>
      item &&
      typeof item === "object" &&
      (item as Record<string, unknown>).event_id === eventId,
  );
  expect(event, `event ${eventId}`).toBeTruthy();
  return event as Record<string, unknown>;
}

function nested(value: unknown, ...path: string[]): unknown {
  let current = value;
  for (const key of path) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}
