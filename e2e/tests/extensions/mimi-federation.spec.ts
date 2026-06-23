// MIMI federation (Realm ↔ external MIMI network via Provider Facade)
// Contract: e2e/scenarios/extensions/mimi-federation.md
// Spec: extensions/mimi-interop.md §1-§7
//   §1 Provider Facade overview
//   §2 Realm `federation_profile = "mimi_interop"` + endpoint exposure
//   §3 Room binding: Cokret Strand ↔ MIMI room; event ↔ Message translation
//   §4 Content mapping: standard MIMI content type ↔ `ck.morph` kind; unknown → quarantine
//   §5 Policy mapping: join_rule / history_visibility ↔ MIMI room policy
//   §6 Identity bridging: MIMI handle → pairwise DID, per-Realm scoped (unlinkability)
//   §7 E2EE boundary: MLS-via-IETF profile transcript binding or explicit downgrade

import { createHash, createPrivateKey, sign } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  canonicalJson,
  createRealmApi,
  queryRealmEventsApi,
  resolveDefaultStrandId,
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
    const { token, realmId, roomId } = await createBoundMimiRoom(request, stamp, "e2ee");
    const governanceBinding = mimiGovernanceBinding(realmId, roomId);
    const coveredSealsCell = mimiCoveredSealsCell(governanceBinding);

    const unmarked = await postSignedMimiMessage(request, roomId, {
        source_format: "application/mimi-content",
        e2ee: true,
        governance_binding: governanceBinding,
        covered_seals_cell: coveredSealsCell,
        content: {
          kind: "ck.content.text",
          body: `silent plaintext leak ${stamp}`,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:e2ee:unmarked:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
    });
    expect(unmarked.status()).toBe(400);
    expect(wireErrCode(await unmarked.json())).toBe("mimi_e2ee_boundary_unmarked");

    const downgradeText = `explicit downgrade ${stamp}`;
    const downgrade = await postSignedMimiMessage(request, roomId, {
        source_format: "application/mimi-content",
        e2ee: true,
        e2ee_downgrade: "mimi_bridge",
        governance_binding: governanceBinding,
        covered_seals_cell: coveredSealsCell,
        content: {
          kind: "ck.content.text",
          body: downgradeText,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:e2ee:downgrade:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
    });
    const downgradeResponseText = await downgrade.text();
    expect(downgrade.status(), downgradeResponseText).toBe(200);
    const downgradeBody = JSON.parse(downgradeResponseText) as Record<string, unknown>;
    expect(nested(downgradeBody, "delivery", "status")).toBe("accepted");

    const transcriptText = `transcript bound ${stamp}`;
    const transcriptHash = `sha256:${"1".repeat(64)}`;
    const transcript = await postSignedMimiMessage(request, roomId, {
        source_format: "application/mimi-content",
        e2ee: true,
        governance_binding: governanceBinding,
        covered_seals_cell: coveredSealsCell,
        transcript_binding: {
          profile: "mls-via-ietf-mimi",
          transcript_hash: transcriptHash,
        },
        content: {
          kind: "ck.content.text",
          body: transcriptText,
        },
        sender_did: "did:web:mimi.example",
        mimi_message_id: `mimi:e2ee:transcript:${stamp}`,
        protocol_draft: "draft-ietf-mimi-protocol-06",
        content_draft: "draft-ietf-mimi-content-08",
    });
    expect(transcript.status()).toBe(200);
    const transcriptBody = (await transcript.json()) as Record<string, unknown>;
    expect(nested(transcriptBody, "delivery", "status")).toBe("accepted");

    const events = await queryRealmEventsApi(request, token, realmId);
    const downgradeEvent = eventById(events, String(downgradeBody.event_ref));
    expect(nested(downgradeEvent, "payload", "content", "body")).toBe(downgradeText);
    expect(nested(downgradeEvent, "payload", "content", "ck.morph.e2ee_downgrade")).toBe(
      "mimi_bridge",
    );
    expect(nested(downgradeEvent, "payload", "mimi_policy", "e2ee_boundary")).toBe(
      "explicit_downgrade",
    );

    const transcriptEvent = eventById(events, String(transcriptBody.event_ref));
    expect(nested(transcriptEvent, "payload", "content", "body")).toBe(transcriptText);
    expect(
      nested(transcriptEvent, "payload", "content", "transcript_binding", "transcript_hash"),
    ).toBe(transcriptHash);
    expect(nested(transcriptEvent, "payload", "mimi_policy", "e2ee_boundary")).toBe(
      "transcript_bound",
    );
  });

  test("E5.3 content type 差异:MIMI 特有 content kind → quarantine + ck.morph.unknown_content_kind", async ({
    request,
  }) => {
    const stamp = Date.now();
    const { token, realmId, roomId } = await createBoundMimiRoom(request, stamp, "content");
    const rawLocation = `geo:31.2304,121.4737;u=${stamp % 100}`;

    const quarantine = await postSignedMimiMessage(request, roomId, {
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
    });
    expect(quarantine.status()).toBe(200);
    const body = (await quarantine.json()) as Record<string, unknown>;
    expect(nested(body, "delivery", "status")).toBe("accepted");

    const events = await queryRealmEventsApi(request, token, realmId);
    const event = eventById(events, String(body.event_ref));
    expect(nested(event, "payload", "content", "kind")).toBe("ck.content.unsupported");
    expect(nested(event, "payload", "content", "body")).toBe("unsupported content from MIMI");
    expect(nested(event, "payload", "content", "ck.morph.unknown_content_kind")).toBe(
      "m.location.share.live",
    );
    expect(nested(event, "payload", "quarantine", "unknown_content_kind")).toBe(
      "m.location.share.live",
    );
    expect(JSON.stringify(event)).not.toContain(rawLocation);
  });
});

async function createBoundMimiRoom(
  request: APIRequestContext,
  stamp: number,
  suffix: string,
): Promise<{ token: string; realmId: string; roomId: string }> {
  const alice = uniqueUser(`mimi-${suffix}-${stamp}`);
  await ensureRegistered(request, alice);
  const token = await issueDevSession(request, alice);
  const realmId = await createRealmApi(request, token, {
    title: `mimi ${suffix} ${stamp}`,
    discoverability: "listed",
    history_visibility: "joined",
    encryption_profile: "mls_rfc9420",
  });
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  const roomId = `MIMI-${suffix}-${stamp}`;
  const updateUrl = `${solandBaseUrl()}/_cokret/open/mimi/strands/${roomId}/update`;
  const roomBinding = {
    kind: "ck.mimi.room_binding",
    payload: {
        profile: "ck.profile.mimi_interop.v1",
        mimi_room_uri: localMimiRoomUri(roomId),
        binding_scope: {
          realm_id: realmId,
          strand_id: strandId,
        },
        hub_provider: solandServiceDid(),
        local_provider_role: "hub",
        content_profile: "application/mimi-content",
        mls_group_id: `mls:${roomId}`,
        status: "accepted",
    },
  };
  const updateBody = {
    mls_group_id: `mls:${roomId}`,
    update: {
      kind: "ck.mimi.room_binding",
      payload: opaquePayload(roomBinding, "application/vnd.cokret.mimi.room-binding+json"),
    },
    epoch: 1,
    sender_actor_id: MIMI_SOURCE_SERVICE_DID,
  };
  const update = await request.post(updateUrl, {
    headers: signedMimiHeaders({
      body: updateBody,
      targetUri: updateUrl,
      roomUri: localMimiRoomUri(roomId),
    }),
    data: canonicalJson(updateBody),
  });
  expect(update.status(), await update.text()).toBe(200);
  return { token, realmId, roomId };
}

function mimiMessagesUrl(roomId: string): string {
  return `${solandBaseUrl()}/_cokret/open/mimi/strands/${encodeURIComponent(roomId)}/messages`;
}

function mimiGovernanceBinding(realmId: string, roomId: string): Record<string, unknown> {
  const policyRoot = `sha256:${"2".repeat(64)}`;
  return {
    binding_version: 1,
    encoding_profile: "cbor-deterministic-rfc8949-v1",
    realm_id: realmId,
    effective_scope: {
      kind: "realm",
      realm_id: realmId,
    },
    mls_group_id: `mls:${roomId}`,
    previous_epoch: 0,
    next_epoch: 1,
    membership_frontier: [`ck:event:${"1".repeat(8)}-${"1".repeat(4)}-7${"1".repeat(3)}-8${"1".repeat(3)}-${"1".repeat(12)}`],
    policy_root: policyRoot,
    binding_profile: "ck.profile.mls_governance_binding.full.v1",
    reducer_profile: "ck.reducer.v1",
  };
}

function mimiCoveredSealsCell(
  governanceBinding: Record<string, unknown>,
): Record<string, unknown> {
  return {
    profile: "ck.covered_seals_cell.v1",
    governance_binding_digest: `sha256:${createHash("sha256")
      .update(canonicalJson(governanceBinding))
      .digest("hex")}`,
    frontier: ["mimi-frontier"],
  };
}

async function postSignedMimiMessage(
  request: APIRequestContext,
  roomId: string,
  message: Record<string, unknown>,
) {
  const url = mimiMessagesUrl(roomId);
  const body = {
    sender_actor_id: MIMI_SOURCE_SERVICE_DID,
    device_id: MIMI_DEVICE_ID,
    mls_group_id: `mls:${roomId}`,
    epoch: 1,
    ciphertext: ciphertextPayload(message, "application/mimi-content"),
  };
  return await request.post(url, {
    headers: signedMimiHeaders({
      body,
      targetUri: url,
      roomUri: localMimiRoomUri(roomId),
    }),
    data: canonicalJson(body),
  });
}

const MIMI_SOURCE_SERVICE_DID = "did:web:mimi.example";
const MIMI_PROVIDER_ID = "mimi://mimi.example";
const MIMI_DEVICE_ID = "ck:device:018f6f50-6a23-7abc-8def-0123456789ab";

function opaquePayload(value: unknown, contentType: string): Record<string, string> {
  const canonical = canonicalJson(value);
  return {
    content_type: contentType,
    payload_digest: sha256Prefixed(canonical),
    payload: Buffer.from(canonical, "utf8").toString("base64url"),
  };
}

function ciphertextPayload(value: unknown, contentType: string): Record<string, string> {
  const canonical = canonicalJson(value);
  return {
    content_type: contentType,
    ciphertext_digest: sha256Prefixed(canonical),
    payload: Buffer.from(canonical, "utf8").toString("base64url"),
  };
}

function signedMimiHeaders(args: {
  body: Record<string, unknown>;
  targetUri: string;
  roomUri: string;
}): Record<string, string> {
  const canonicalBody = Buffer.from(canonicalJson(args.body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(canonicalBody).digest("base64")}:`;
  const requestDigest = sha256Prefixed(canonicalBody);
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300;
  const keyid = `${MIMI_SOURCE_SERVICE_DID}#mimi-provider-key`;
  const components = [
    "@method",
    "@target-uri",
    "@authority",
    "content-digest",
    "request-canonical-digest",
    "source-service-did",
    "destination-service-did",
    "provider-id",
    "mimi-room-uri",
  ];
  const signatureParams =
    `(${components.map((component) => `"${component}"`).join(" ")});` +
    `created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const destinationServiceDid = solandServiceDid();
  const signatureBase = [
    `"@method": POST`,
    `"@target-uri": ${args.targetUri}`,
    `"@authority": ${new URL(args.targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"request-canonical-digest": ${requestDigest}`,
    `"source-service-did": ${MIMI_SOURCE_SERVICE_DID}`,
    `"destination-service-did": ${destinationServiceDid}`,
    `"provider-id": ${MIMI_PROVIDER_ID}`,
    `"mimi-room-uri": ${args.roomUri}`,
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(signatureBase, "utf8"),
    developmentMimiPrivateKey(keyid),
  );
  return {
    "content-type": "application/json",
    "content-digest": contentDigest,
    "request-canonical-digest": requestDigest,
    "source-service-did": MIMI_SOURCE_SERVICE_DID,
    "destination-service-did": destinationServiceDid,
    "provider-id": MIMI_PROVIDER_ID,
    "mimi-room-uri": args.roomUri,
    "signature-input": `sig1=${signatureParams}`,
    signature: `sig1=:${signature.toString("base64")}:`,
  };
}

function developmentMimiPrivateKey(verificationMethod: string) {
  const seed = createHash("sha256")
    .update("soland:mimi-provider-key:")
    .update(verificationMethod)
    .digest();
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function localMimiRoomUri(roomId: string): string {
  return `${localMimiProviderId()}/rooms/${roomId}`;
}

function localMimiProviderId(): string {
  const serviceDid = solandServiceDid();
  if (serviceDid.startsWith("did:web:")) {
    return `mimi://${serviceDid.slice("did:web:".length).replaceAll(":", "/")}`;
  }
  return `mimi://${serviceDid.replaceAll(":", ".")}`;
}

function sha256Prefixed(input: string | Buffer): string {
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
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
