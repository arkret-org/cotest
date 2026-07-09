// MIMI federation (Realm ↔ external MIMI network via Provider Facade)
// Contract: e2e/scenarios/extensions/mimi-federation.md
// Spec: extensions/mimi-interop.md §1-§7
//   §1 Provider Facade overview
//   §2 Realm `federation_profile = "mimi_interop"` + endpoint exposure
//   §3 Room binding: Arkret Strand ↔ MIMI room; event ↔ Message translation
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
  // soland/inkson gap: the MIMI Provider Facade binding + identity-bridging
  // business chain is not implemented yet (MIMI interop is an extension
  // profile, not required for v1 core). cotest already ships
  // helpers/mimi-facade.ts plus the mock facade; the business cases below stay
  // fixme-anchored until the server/client chain lands. All acceptance
  // surfaces are spec-registered: the MIMI protocol face is exactly
  // `/_arkret/open/mimi/*` (openapi catalog); realm/member introspection goes
  // through the event plane (`ck.member.state` via `/_arkret/self/events`) or
  // the `/_soland/` product face — there is NO
  // `/_arkret/self/realm/:id/federation/mimi/*` and NO
  // `/_arkret/self/realm/:id/members` endpoint, and none may be invented
  // (SPEC-CR-020: zero new operations).

  test.fixme(
    // @blocking-on: soland#extensions-mimi-federation-gap
    // @user-promise: e2e/scenarios/extensions/mimi-federation.md
    // @expected-live-by: 2026Q3
    "alice opens MIMI-enabled Realm; bob_mimi joins via facade; bidirectional messaging with identity bridging",
    async () => {
      // Phase A — alice creates a Realm via /setup with
      //   ck.realm.federation_profile = "mimi_interop".
      // Assert MIMI interop exposure via the registered protocol face:
      //   GET /_arkret/describe advertises the mimi_interop extension, and
      //   GET /_arkret/open/mimi/provider-directory
      //   (ck.open.mimi.query.provider_directory) returns the provider
      //   feature profile. The room binding is established through
      //   POST /_arkret/open/mimi/strands/:id/update (see createBoundMimiRoom
      //   below for the already-live pattern).
      //
      // Phase B — mimi_facade (mock) simulates a join request from the
      //   external MIMI network, translated into a Arkret ck.invite.request /
      //   knock event submitted to soland; alice's /realm/:id/admin shows the
      //   federation-inbound-panel with a mimi origin marker.
      //
      // Phase C — alice approves; soland verifies bob_mimi's MIMI identity
      //   through the facade and mints the pairwise DID per spec §6
      //   (did:pairwise:${realmId}/${hash(handle, realmId.salt)}).
      //   Approval is an event-plane action: the admin approval (product
      //   face /_soland/, or inkson admin panel) results in a
      //   ck.member.state{membership=join} event for the pairwise DID.
      //   Assert membership via the event plane: query /_arkret/self/events
      //   (queryRealmEventsApi) for the ck.member.state event carrying the
      //   pairwise DID with a mimi source annotation.
      //
      // Phase D — alice posts M1 on /timeline/:realmId;
      //   the facade mock records an outbound MIMI event; the soland message
      //   carries ck.morph.federation_outbound = "mimi" + mimi_event_id.
      //   The facade translates bob_mimi's MM2 from the MIMI network into a
      //   Arkret Message; alice's timeline shows MM2 within 30s with the
      //   pairwise DID as sender; the message carries
      //   ck.morph.federation_inbound = "mimi" + mimi_origin_event_id.
      //   alice replies to MM2 with M3; the reply relation is preserved in
      //   both directions across MIMI <-> Arkret.
      //
      // Phase E — the Phase B approval implies per-Realm consent only;
      //   bob_mimi's pairwise DID is valid for the current Realm alone, and a
      //   delivery attempt in another Realm R2 with the same pairwise DID
      //   must be rejected. (Cross-link: identity/consent-grant scenario.)
    },
  );

  test.fixme(
    // @blocking-on: soland#extensions-mimi-federation-gap
    // @user-promise: e2e/scenarios/extensions/mimi-federation.md
    // @expected-live-by: 2026Q3
    "E5.1 MIMI endpoint unreachable -> federation fallback: message kept locally, outbound status marked deferred, retried once the facade recovers",
    async () => {
      // The facade mock deliberately returns 5xx / times out;
      // alice's M1 must still persist locally on soland and stay visible to
      // Arkret members; the message carries
      // ck.morph.federation_outbound_status = "deferred";
      // once the facade recovers, soland retries delivery and the status
      // transitions to "delivered".
    },
  );

  test("E5.2 E2EE translation into MIMI: transcript binding or explicit downgrade marker, never a silent plaintext leak", async ({
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

  test("E5.3 content type mismatch: MIMI-specific content kind -> quarantine + ck.morph.unknown_content_kind", async ({
    request,
  }) => {
    const stamp = Date.now();
    const { token, realmId, roomId } = await createBoundMimiRoom(request, stamp, "content");
    const rawLocation = `geo:31.2304,121.4737;u=${stamp % 100}`;
    const governanceBinding = mimiGovernanceBinding(realmId, roomId);
    const coveredSealsCell = mimiCoveredSealsCell(governanceBinding);

    const quarantine = await postSignedMimiMessage(request, roomId, {
        source_format: "application/mimi-content",
        governance_binding: governanceBinding,
        covered_seals_cell: coveredSealsCell,
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
  const updateUrl = `${solandBaseUrl()}/_arkret/open/mimi/strands/${roomId}/update`;
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
      payload: opaquePayload(roomBinding, "application/vnd.arkret.mimi.room-binding+json"),
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
  return `${solandBaseUrl()}/_arkret/open/mimi/strands/${encodeURIComponent(roomId)}/messages`;
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
const MIMI_DEVICE_ID = "ak:device:018f6f50-6a23-7abc-8def-0123456789ab";

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
  // did:webvh:<scid>:<host>[:<path>...] — the HTTP authority starts after
  // the SCID segment.
  const webvh = serviceDid.match(/^did:webvh:[^:]+:(.+)$/);
  if (webvh) {
    return `mimi://${webvh[1].replaceAll(":", "/")}`;
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
