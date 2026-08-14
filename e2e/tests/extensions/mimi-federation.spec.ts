// MIMI federation (Realm ↔ external MIMI network via Provider Facade)
// Contract: e2e/scenarios/extensions/mimi-federation.md
// Spec: extensions/mimi-interop.md §1-§7
//   §1 Provider Facade overview
//   §2 Realm `federation_profile = "mimi_interop"` + endpoint exposure
//   §3 Room binding: Arkret Strand ↔ MIMI room; event ↔ Message translation
//   §4 Content mapping: standard MIMI content type ↔ `ak.morph` kind; unknown → quarantine
//   §5 Policy mapping: join_rule / history_visibility ↔ MIMI room policy
//   §6 Identity bridging: MIMI handle → pairwise DID, per-Realm scoped (unlinkability)
//   §7 E2EE boundary: MLS-via-IETF profile transcript binding or explicit downgrade

import { createHash, createPrivateKey, sign } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl, solandServiceId } from "../../helpers/env";
import {
  advanceEnvelopeToActorFrontier,
  canonicalDidCoreId,
  canonicalJson,
  createRealmApi,
  grantCapabilityEventApi,
  grantServiceCapabilityApi,
  queryRealmEventsApi,
  readRealmSealBasis,
  resolveDefaultStrandId,
  signedEventEnvelope,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("mimi federation", () => {
  test("E5.2 E2EE translation into MIMI: transcript binding or explicit downgrade marker, never a silent plaintext leak", async ({
    request,
  }) => {
    const stamp = Date.now();
    const { token, realmId, roomId } = await createBoundMimiRoom(
      request,
      stamp,
      "e2ee",
    );
    const governanceBinding = mimiGovernanceBinding(realmId, roomId);

    const unmarked = await postSignedMimiMessage(request, roomId, {
      source_format: "application/mimi-content",
      e2ee: true,
      governance_binding: governanceBinding,
      content: {
        kind: "ak.content.text",
        body: `silent plaintext leak ${stamp}`,
      },
      sender_did: "did:web:mimi.example",
      mimi_message_id: `mimi:e2ee:unmarked:${stamp}`,
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
    });
    expect(unmarked.status()).toBe(400);
    expect(wireErrCode(await unmarked.json())).toBe(
      "mimi_e2ee_boundary_unmarked",
    );

    const downgradeText = `explicit downgrade ${stamp}`;
    const downgrade = await postSignedMimiMessage(request, roomId, {
      source_format: "application/mimi-content",
      e2ee: true,
      e2ee_downgrade: "mimi_bridge",
      governance_binding: governanceBinding,
      content: {
        kind: "ak.content.text",
        body: downgradeText,
      },
      sender_did: "did:web:mimi.example",
      mimi_message_id: `mimi:e2ee:downgrade:${stamp}`,
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
    });
    const downgradeResponseText = await downgrade.text();
    expect(downgrade.status(), downgradeResponseText).toBe(200);
    const downgradeBody = JSON.parse(downgradeResponseText) as Record<
      string,
      unknown
    >;
    expect(nested(downgradeBody, "delivery", "status")).toBe("accepted");

    const transcriptText = `transcript bound ${stamp}`;
    const transcriptHash = `sha256:${"1".repeat(64)}`;
    const transcript = await postSignedMimiMessage(request, roomId, {
      source_format: "application/mimi-content",
      e2ee: true,
      governance_binding: governanceBinding,
      transcript_binding: {
        profile: "mls-via-ietf-mimi",
        transcript_hash: transcriptHash,
      },
      content: {
        kind: "ak.content.text",
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
    expect(nested(downgradeEvent, "payload", "content", "body")).toBe(
      downgradeText,
    );
    expect(nested(downgradeEvent, "payload", "content", "e2ee_downgrade")).toBe(
      "mimi_bridge",
    );
    expect(
      nested(
        downgradeEvent,
        "payload",
        "metadata",
        "mimi_policy",
        "e2ee_boundary",
      ),
    ).toBe("explicit_downgrade");

    const transcriptEvent = eventById(events, String(transcriptBody.event_ref));
    expect(nested(transcriptEvent, "payload", "content", "body")).toBe(
      transcriptText,
    );
    expect(
      nested(
        transcriptEvent,
        "payload",
        "content",
        "transcript_binding",
        "transcript_hash",
      ),
    ).toBe(transcriptHash);
    expect(
      nested(
        transcriptEvent,
        "payload",
        "metadata",
        "mimi_policy",
        "e2ee_boundary",
      ),
    ).toBe("transcript_bound");
  });

  test("E5.3 content type mismatch: MIMI-specific content kind -> canonical fallback + quarantine metadata", async ({
    request,
  }) => {
    const stamp = Date.now();
    const { token, realmId, roomId } = await createBoundMimiRoom(
      request,
      stamp,
      "content",
    );
    const rawLocation = `geo:31.2304,121.4737;u=${stamp % 100}`;
    const governanceBinding = mimiGovernanceBinding(realmId, roomId);

    const quarantine = await postSignedMimiMessage(request, roomId, {
      source_format: "application/mimi-content",
      governance_binding: governanceBinding,
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
    const quarantineResponseText = await quarantine.text();
    expect(quarantine.status(), quarantineResponseText).toBe(200);
    const body = JSON.parse(quarantineResponseText) as Record<string, unknown>;
    expect(nested(body, "delivery", "status")).toBe("accepted");

    const events = await queryRealmEventsApi(request, token, realmId);
    const event = eventById(events, String(body.event_ref));
    expect(nested(event, "payload", "content", "kind")).toBe("ak.content.text");
    expect(nested(event, "payload", "content", "body")).toBe(
      "unsupported content from MIMI",
    );
    expect(nested(event, "payload", "content", "unknown_content_kind")).toBe(
      "m.location.share.live",
    );
    expect(
      nested(
        event,
        "payload",
        "metadata",
        "quarantine",
        "unknown_content_kind",
      ),
    ).toBe("m.location.share.live");
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
  // MIMI ingress is translated by the local Principal Server, so its service
  // DID needs a real sealed Realm capability. Membership and the room binding
  // are not authorization sources, and a canonical Realm must never be
  // modified through the conformance fixture endpoint.
  await grantServiceCapabilityApi(request, token, {
    ownerDid: alice.did,
    realmId,
    subjectServiceId: solandServiceId(),
    action: "ak.message.create",
  });
  await grantCapabilityEventApi(request, token, {
    ownerDid: alice.did,
    realmId,
    subjectDid: alice.did,
    actions: ["ak.realm.admin"],
  });
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  const roomId = `MIMI-${suffix}-${stamp}`;
  const updateUrl = `${solandBaseUrl()}/_arkret/open/mimi/strands/${roomId}/update`;
  const roomBinding = {
    kind: "ak.mimi.room_binding",
    payload: {
      profile: "ak.profile.mimi_interop.v1",
      mimi_room_uri: localMimiRoomUri(roomId),
      binding_scope: {
        realm_id: realmId,
        strand_id: strandId,
      },
      hub_provider: solandServiceId(),
      local_provider_role: "hub",
      content_profile: "application/mimi-content",
      mls_group_id: `mls:${roomId}`,
      status: "accepted",
    },
  };
  const bindingEvent = signedEventEnvelope({
    actorDid: alice.did,
    realmId,
    kind: "ak.mimi.room_binding",
    sealBasis: await readRealmSealBasis(request, token, realmId),
    payload: roomBinding.payload,
  });
  await advanceEnvelopeToActorFrontier(request, token, bindingEvent);
  const updateBody = {
    mls_group_id: `mls:${roomId}`,
    update: {
      kind: "ak.mimi.room_binding",
      payload: opaquePayload(
        roomBinding,
        "application/vnd.arkret.mimi.room-binding+json",
      ),
    },
    epoch: 1,
    sender_actor_id: canonicalDidCoreId(alice.did),
    room_binding_event: { event: bindingEvent },
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
  return `${solandBaseUrl()}/_arkret/open/mimi/strands/${encodeURIComponent(roomId)}/messages`;
}

function mimiGovernanceBinding(
  realmId: string,
  roomId: string,
): Record<string, unknown> {
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
    security_frontier_digest: `sha256:${"2".repeat(64)}`,
    binding_profile: "ak.profile.mls_governance_binding.full.v1",
    reducer_profile: "ak.reducer.core.v1",
  };
}

async function postSignedMimiMessage(
  request: APIRequestContext,
  roomId: string,
  message: Record<string, unknown>,
) {
  const url = mimiMessagesUrl(roomId);
  const body = {
    sender_actor_id: canonicalDidCoreId(MIMI_SOURCE_SERVICE_ID),
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

const MIMI_SOURCE_SERVICE_ID = "did:web:mimi.example";
const MIMI_PROVIDER_ID = "mimi://mimi.example";
const MIMI_DEVICE_ID = "ak:device:018f6f50-6a23-7abc-8def-0123456789ab";

function opaquePayload(
  value: unknown,
  contentType: string,
): Record<string, string> {
  const canonical = canonicalJson(value);
  return {
    content_type: contentType,
    payload_digest: sha256Prefixed(canonical),
    payload: Buffer.from(canonical, "utf8").toString("base64url"),
  };
}

function ciphertextPayload(
  value: unknown,
  contentType: string,
): Record<string, string> {
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
  const sourceServiceId = canonicalDidCoreId(MIMI_SOURCE_SERVICE_ID);
  const canonicalBody = Buffer.from(canonicalJson(args.body), "utf8");
  const contentDigest = `sha-256=:${createHash("sha256").update(canonicalBody).digest("base64")}:`;
  const created = Math.floor(Date.now() / 1000);
  const expires = created + 300;
  const keyid = `${MIMI_SOURCE_SERVICE_ID}#mimi-provider-key`;
  const components = [
    "@method",
    "@target-uri",
    "@authority",
    "content-digest",
    "source-service-id",
    "destination-service-id",
    "provider-id",
    "mimi-room-uri",
  ];
  const signatureParams =
    `(${components.map((component) => `"${component}"`).join(" ")});` +
    `created=${created};expires=${expires};keyid="${keyid}";alg="ed25519"`;
  const destinationServiceId = solandServiceId();
  const signatureBase = [
    `"@method": POST`,
    `"@target-uri": ${args.targetUri}`,
    `"@authority": ${new URL(args.targetUri).host}`,
    `"content-digest": ${contentDigest}`,
    `"source-service-id": ${sourceServiceId}`,
    `"destination-service-id": ${destinationServiceId}`,
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
    "source-service-id": sourceServiceId,
    "destination-service-id": destinationServiceId,
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
  const serviceId = solandServiceId();
  if (serviceId.startsWith("did:web:")) {
    return `mimi://${serviceId.slice("did:web:".length).replaceAll(":", "/")}`;
  }
  // did:webvh:<scid>:<host>[:<path>...] — the HTTP authority starts after
  // the SCID segment.
  const webvh = serviceId.match(/^did:webvh:[^:]+:(.+)$/);
  if (webvh) {
    return `mimi://${webvh[1].replaceAll(":", "/")}`;
  }
  return `mimi://${serviceId.replaceAll(":", ".")}`;
}

function sha256Prefixed(input: string | Buffer): string {
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function eventById(
  eventsBody: Record<string, unknown>,
  eventId: string,
): Record<string, unknown> {
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
