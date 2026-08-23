// Contract: contact-and-direct-conversation.md §§5.2, 5.5, and 6.1.
// Live regression for the founder-PS immutable founding slot. The losing
// candidate is deliberately smaller by both salt and Realm id, so accepting
// the first candidate cannot be explained by a hidden min-id tie-breaker.

import { createHash, randomBytes } from "node:crypto";
import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  solandBaseUrl,
  solandServiceFullId,
} from "../../helpers/env";
import {
  base64url,
  canonicalDidCoreId,
  canonicalJson,
  canonicalTimestamp,
  cotestWire,
  expectJsonOk,
  refreshEventEnvelopeProof,
  sdkCapabilityActionRegistryDigest,
  sdkEventDerivedObjectId,
  sha256CanonicalJson,
  signedEventEnvelope,
  signedRealmGenesisEnvelope,
  singleSignerNotaryFromFullDid,
  typedId,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  createDpopUserSession,
  selfPathHeadersForDpopSession,
  type DpopUserSession,
} from "../../helpers/users";

type JsonObject = Record<string, any>;

const REALM_AUTHORITY_ROOT_CELL =
  "ak:cell:ak.component.realm.authority_root.v1:null";
const DIRECT_CONVERSATION_PROFILE = "ak.profile.direct_conversation_realm.v1";

async function sealPrincipalControlEvent(
  request: APIRequestContext,
  session: DpopUserSession,
  event: JsonObject,
): Promise<void> {
  const realmId = session.principalControlRealmId;
  if (!realmId) {
    throw new Error("session omitted its accepted event-derived PCR create");
  }
  expect(realmId, "principal control Realm id").toBeTruthy();
  const frontierUrl = `${solandBaseUrl()}/_arkret/self/events/frontier`;
  const frontierResponse = await request.fetch(frontierUrl, {
    method: "QUERY",
    headers: {
      ...selfPathHeadersForDpopSession(session, "QUERY", frontierUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({ realm_id: realmId }),
  });
  const frontierBody = await expectJsonOk<JsonObject>(
    frontierResponse,
    "read principal Seal frontier",
  );
  const predecessorFrontier = frontierBody.frontier as JsonObject;
  expect(predecessorFrontier?.kind).toBe("realm_seal");
  const leaves = (predecessorFrontier?.seal_basis as JsonObject | undefined)
    ?.leaves as string[] | undefined;
  expect(leaves, "accepted Seal frontier leaves").toHaveLength(1);
  // The frontier view carries no root hint: the successor Seal binds the
  // predecessor's own signed roots, so the single leaf is resolved first.
  const resolveUrl = `${solandBaseUrl()}/_arkret/self/seals/resolve`;
  const resolveResponse = await request.fetch(resolveUrl, {
    method: "QUERY",
    headers: {
      ...selfPathHeadersForDpopSession(session, "QUERY", resolveUrl),
      "content-type": "application/json",
    },
    data: canonicalJson({ realm_id: realmId, seal_refs: [leaves![0]] }),
  });
  const resolveBody = await expectJsonOk<JsonObject>(
    resolveResponse,
    "resolve principal predecessor Seal",
  );
  const predecessorSeal = (resolveBody.seals as JsonObject[]).find(
    (candidate) => candidate.id === leaves![0],
  );
  expect(predecessorSeal, "resolved principal predecessor Seal").toBeTruthy();
  const events = [...session.principalControlEvents, event];
  const seal = cotestWire<JsonObject>(
    "principal-successor-seal",
    {
      events,
      predecessor_seal: predecessorSeal,
      device_signing_seed_b64url: session.eventSigningSeedB64url,
    },
  );
  const sealUrl = `${solandBaseUrl()}/_arkret/self/seals`;
  const sealResponse = await request.post(sealUrl, {
    headers: {
      ...selfPathHeadersForDpopSession(session, "POST", sealUrl),
      "content-type": "application/json",
    },
    data: canonicalJson(seal),
  });
  await expectJsonOk<JsonObject>(sealResponse, "submit principal successor Seal");
  session.principalControlEvents.push(event);
}

async function prepareAndCommitContactEvent(
  request: APIRequestContext,
  session: DpopUserSession,
  path: "request" | "respond" | "scope-update",
  prepareBody: JsonObject,
): Promise<JsonObject> {
  const url = `${solandBaseUrl()}/_arkret/self/contacts/${path}`;
  const prepareResponse = await request.post(
    url,
    {
      headers: {
        ...selfPathHeadersForDpopSession(session, "POST", url),
        "content-type": "application/json",
      },
      data: canonicalJson(prepareBody),
    },
  );
  const prepared = await expectJsonOk<JsonObject>(
    prepareResponse,
    `prepare Contact ${path}`,
  );
  expect(prepared).toMatchObject({
    status: "prepared",
    operation_id: prepareBody.operation_id,
  });
  const draft = prepared.event_draft as JsonObject;
  const event = JSON.parse(
    Buffer.from(draft.unsigned_event_bytes, "base64url").toString("utf8"),
  ) as JsonObject;
  refreshEventEnvelopeProof(event);
  expect(event.event_id).toBe(draft.event_id);
  const commitResponse = await request.post(
    url,
    {
      headers: {
        ...selfPathHeadersForDpopSession(session, "POST", url),
        "content-type": "application/json",
      },
      data: canonicalJson({
        phase: "commit",
        operation_id: prepared.operation_id,
        idempotency_key: prepareBody.idempotency_key,
        reservation_handle: prepared.reservation_handle,
        signed_event: event,
      }),
    },
  );
  const committed = await expectJsonOk<JsonObject>(
    commitResponse,
    `commit Contact ${path}`,
  );
  expect(committed).toMatchObject({
    status: "accepted",
    operation_id: prepareBody.operation_id,
  });
  await sealPrincipalControlEvent(request, session, event);
  return committed;
}

async function acceptedDirectMessageEvidence(
  request: APIRequestContext,
  alice: DpopUserSession,
  bob: DpopUserSession,
): Promise<JsonObject> {
  const requestOutcome = await prepareAndCommitContactEvent(
    request,
    alice,
    "request",
    {
      phase: "prepare",
      operation_id: typedId("operation"),
      idempotency_key: typedId("contact-request"),
      peer: {
        kind: "human",
        principal_id: canonicalDidCoreId(bob.user.did),
      },
      granted_to_peer_scopes: ["direct_message"],
      introduction_evidence: { kind: "explicit_address" },
    },
  );
  const requestReceipt =
    requestOutcome.request_acceptance_receipt as JsonObject;

  const responseOutcome = await prepareAndCommitContactEvent(
    request,
    bob,
    "respond",
    {
      phase: "prepare",
      operation_id: typedId("operation"),
      idempotency_key: typedId("contact-response"),
      request_receipt: requestReceipt,
      action: "accept",
      granted_to_peer_scopes: ["direct_message"],
    },
  );
  const responseReceipt =
    responseOutcome.normal_response_acceptance_receipt as JsonObject;
  const bobCurrentProof = responseOutcome.current_proof as JsonObject;

  // The accepted response creates Bob's current proof. Advancing Alice's
  // lineage under the same contact_round produces the other current proof required by
  // the portable founder evidence bundle, without changing the pair or root
  // founder contact_round.
  const aliceScopeOutcome = await prepareAndCommitContactEvent(
    request,
    alice,
    "scope-update",
    {
      phase: "prepare",
      operation_id: typedId("operation"),
      idempotency_key: typedId("contact-scope"),
      peer: {
        kind: "human",
        principal_id: canonicalDidCoreId(bob.user.did),
      },
      contact_round_id: responseReceipt.contact_round_id,
      version: 2,
      predecessor_event_ref: requestReceipt.core.request_event_ref,
      granted_to_peer_scopes: ["direct_message"],
    },
  );
  const aliceCurrentProof = aliceScopeOutcome.current_proof as JsonObject;
  const pair = [
    canonicalDidCoreId(alice.user.did),
    canonicalDidCoreId(bob.user.did),
  ].sort();
  const contact_round = {
    kind: "normal",
    sorted_pair_members: pair,
    request_event_ref: requestReceipt.core.request_event_ref,
    request_acceptance_receipt_digest: `sha256:${sha256CanonicalJson(
      requestReceipt,
    )}`,
  };
  expect(
    `sha256:${createHash("sha256")
      .update("ak.contact.contact_round.v1\n", "utf8")
      .update(canonicalJson(contact_round), "utf8")
      .digest("hex")}`,
  ).toBe(responseReceipt.contact_round_id);
  return {
    kind: "human",
    contact_round_evidence_bundle: {
      contact_round_id: responseReceipt.contact_round_id,
      contact_round,
      request_receipts: [requestReceipt],
      normal_response_receipt: responseReceipt,
      current_proofs: [aliceCurrentProof, bobCurrentProof].sort((left, right) =>
        String(left.issuer).localeCompare(String(right.issuer)),
      ),
    },
    root_basis_continuity_chain: [],
  };
}

function foundingEvents(args: {
  founderDid: string;
  peerDid: string;
  basisRef: string;
  salt: string;
  createdAt: string;
  hlcMillis: string;
}): { events: JsonObject[]; realmId: string; mainStrandId: string } {
  const requirementsCriticalExtensions = [
    {
      id: "ak.feature.direct_conversation_realm_role.v1",
      extension_scope: "payload",
      profile_ref: DIRECT_CONVERSATION_PROFILE,
      fail_closed: true,
    },
  ];
  const { envelope: create, realmId } = signedRealmGenesisEnvelope({
    actorDid: args.founderDid,
    realmId: "",
    kind: "ak.realm.create",
    actorSeq: 0,
    createdAt: args.createdAt,
    hlc: `${args.hlcMillis}-0000-dc0fcafe`,
    refs: [
      {
        id: args.basisRef,
        role: "direct_conversation_basis",
        critical: true,
      },
    ],
    requirementsSchema: [
      "ak.schema.realm_genesis.v1",
      DIRECT_CONVERSATION_PROFILE,
    ],
    requirementsCriticalExtensions,
    preconditions: [
      {
        cell: "ak:cell:ak.component.realm.create.v1:null",
        predicate: { op: "head_eq", value: null },
      },
    ],
    payload: {
      object: {
        schema: "ak.schema.realm_genesis.v1",
        purpose: "direct_conversation",
        genesis_salt: args.salt,
        trust_domain: "ak:trust_domain:soland.local",
        schema_refs: ["ak.schema.realm.v1", DIRECT_CONVERSATION_PROFILE],
        reducer_profile: "ak.reducer.core.v1",
        encryption_profile: "mls_rfc9420",
        security_class: "standard",
        digest_algorithm: "sha256",
        notary: singleSignerNotaryFromFullDid(solandServiceFullId()),
        capability_action_registry_digest: sdkCapabilityActionRegistryDigest(),
      },
    },
  });
  const createId = String(create.event_id);
  const member = signedEventEnvelope({
    actorDid: args.founderDid,
    realmId,
    kind: "ak.member.state",
    actorSeq: 1,
    createdAt: args.createdAt,
    hlc: `${args.hlcMillis}-0001-dc0fcafe`,
    prevRefs: [createId],
    authorizationRef: REALM_AUTHORITY_ROOT_CELL,
    payload: {
      realm_id: realmId,
      actor_id: args.peerDid,
      membership: "join",
      delivery_status: "unroutable",
      reason: "direct_conversation_bootstrap",
    },
  });
  const memberId = String(member.event_id);
  const strand = signedEventEnvelope({
    actorDid: args.founderDid,
    realmId,
    kind: "ak.strand.create",
    actorSeq: 2,
    createdAt: args.createdAt,
    hlc: `${args.hlcMillis}-0002-dc0fcafe`,
    prevRefs: [memberId],
    authorizationRef: REALM_AUTHORITY_ROOT_CELL,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        metadata: { title: "Direct conversation" },
        stage: "in_progress",
        state: "active",
        tracks: { discussion: { enabled: true, is_primary: true } },
        created_by: args.founderDid,
        created_at: args.createdAt,
      },
    },
  });
  const strandId = String(strand.event_id);
  const founderMember = signedEventEnvelope({
    actorDid: args.founderDid,
    realmId,
    kind: "ak.member.state",
    actorSeq: 3,
    createdAt: args.createdAt,
    hlc: `${args.hlcMillis}-0003-dc0fcafe`,
    prevRefs: [strandId],
    authorizationRef: REALM_AUTHORITY_ROOT_CELL,
    preconditions: [
      {
        cell: `ak:cell:ak.component.member.state.v1:${args.founderDid}`,
        predicate: { op: "head_eq", value: null },
      },
    ],
    payload: {
      realm_id: realmId,
      actor_id: args.founderDid,
      membership: "join",
      delivery_status: "unroutable",
      reason: "direct_conversation_bootstrap",
    },
  });
  return {
    events: [create, member, strand, founderMember],
    realmId,
    mainStrandId: sdkEventDerivedObjectId(strand),
  };
}

function smallerFoundingCandidate(args: {
  accepted: ReturnType<typeof foundingEvents>;
  founderDid: string;
  peerDid: string;
  basisRef: string;
  acceptedSalt: string;
  createdAt: string;
  hlcMillis: string;
}): { candidate: ReturnType<typeof foundingEvents>; salt: string } {
  for (let attempt = 0; attempt < 20_000; attempt += 1) {
    const salt = base64url(randomBytes(32));
    if (salt >= args.acceptedSalt) continue;
    const candidate = foundingEvents({ ...args, salt });
    if (candidate.realmId < args.accepted.realmId) return { candidate, salt };
  }
  throw new Error("failed to find a lower salt and lower Realm-id candidate");
}

test.describe("Direct Conversation immutable founding slot @fully-implemented", () => {
  test("same slot rejects a lower-salt/lower-Realm candidate and preserves the receipt", async ({
    request,
  }) => {
    const [aliceSession, bobSession] = await Promise.all([
      createDpopUserSession(request, "dc-slot-alice"),
      createDpopUserSession(request, "dc-slot-bob"),
    ]);
    if (!aliceSession || !bobSession) {
      throw new Error("Direct Conversation live test requires canonical Coauth PCR sessions");
    }
    const alice = aliceSession.user;
    const bob = bobSession.user;

    const founderContactRoundEvidence = await acceptedDirectMessageEvidence(
      request,
      aliceSession,
      bobSession,
    );
    // Normal Contact round fixes the responder (Bob), not the requester, as
    // the only founder.
    const basisRef = String(
      founderContactRoundEvidence.contact_round_evidence_bundle.contact_round.request_event_ref,
    );
    const createdAt = canonicalTimestamp();
    const hlcMillis = Date.now().toString(16).padStart(12, "0").slice(-12);
    const acceptedSalt = base64url(randomBytes(32));
    const bobCoreId = canonicalDidCoreId(bob.did);
    const aliceCoreId = canonicalDidCoreId(alice.did);
    const accepted = foundingEvents({
      founderDid: bobCoreId,
      peerDid: aliceCoreId,
      basisRef,
      salt: acceptedSalt,
      createdAt,
      hlcMillis,
    });
    const { candidate: losing, salt: losingSalt } = smallerFoundingCandidate({
      accepted,
      founderDid: bobCoreId,
      peerDid: aliceCoreId,
      basisRef,
      acceptedSalt,
      createdAt,
      hlcMillis,
    });
    expect(losingSalt < acceptedSalt).toBe(true);
    expect(losing.realmId < accepted.realmId).toBe(true);

    const acceptedBody = {
      unit_kind: "direct_conversation_founding",
      idempotency_key: typedId("dc-founding"),
      events: accepted.events.map((event) => ({ event })),
      founder_contact_round_evidence: founderContactRoundEvidence,
    };
    const eventsUrl = `${solandBaseUrl()}/_arkret/self/events`;
    const firstResponse = await request.post(
      eventsUrl,
      {
        headers: {
          ...selfPathHeadersForDpopSession(bobSession, "POST", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson(acceptedBody),
      },
    );
    const firstText = await firstResponse.text();
    expect(
      firstResponse.status(),
      `first founding candidate returned ${firstResponse.status()}: ${firstText}`,
    ).toBe(200);
    const first = JSON.parse(firstText) as JsonObject;
    expect(first).toMatchObject({
      unit_kind: "direct_conversation_founding",
      status: "accepted",
      event_ids: accepted.events.map((event) => event.event_id),
      receipt: {
        founder_id: bobCoreId,
        realm_id: accepted.realmId,
        main_strand_id: accepted.mainStrandId,
        slot_committed: true,
      },
    });

    const retryResponse = await request.post(
      eventsUrl,
      {
        headers: {
          ...selfPathHeadersForDpopSession(bobSession, "POST", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson(acceptedBody),
      },
    );
    const retryText = await retryResponse.text();
    expect(retryResponse.status(), retryText).toBe(200);
    const retry = JSON.parse(retryText) as JsonObject;
    expect(retry.status).toBe("duplicate");
    expect(JSON.stringify(retry.receipt)).toBe(JSON.stringify(first.receipt));

    const conflictBody = {
      ...acceptedBody,
      idempotency_key: typedId("dc-founding"),
      events: losing.events.map((event) => ({ event })),
    };
    const conflictResponse = await request.post(
      eventsUrl,
      {
        headers: {
          ...selfPathHeadersForDpopSession(bobSession, "POST", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson(conflictBody),
      },
    );
    const conflictText = await conflictResponse.text();
    const conflict = JSON.parse(conflictText) as JsonObject;
    expect(conflictResponse.status(), conflictText).toBe(409);
    expect(wireErrCode(conflict)).toBe("conflict");
    expect(conflictText).toContain(
      "direct_conversation_slot_already_committed",
    );

    const acceptedHistory = await expectJsonOk<JsonObject>(
      await request.fetch(eventsUrl, {
        method: "QUERY",
        headers: {
          ...selfPathHeadersForDpopSession(bobSession, "QUERY", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({ realms: [accepted.realmId], limit: 100 }),
      }),
      `query events for accepted Direct Conversation ${accepted.realmId}`,
    );
    const acceptedEvents = (acceptedHistory.events ?? []) as JsonObject[];
    expect(acceptedEvents.map((event) => event.event_id)).toEqual(
      accepted.events.map((event) => event.event_id),
    );
    const losingHistory = await request.fetch(
      eventsUrl,
      {
        method: "QUERY",
        headers: {
          ...selfPathHeadersForDpopSession(bobSession, "QUERY", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson({ realms: [losing.realmId], limit: 100 }),
      },
    );
    const losingHistoryText = await losingHistory.text();
    expect(losingHistory.status(), losingHistoryText).toBe(404);
    expect(wireErrCode(JSON.parse(losingHistoryText) as JsonObject)).toBe(
      "not_found",
    );
    expect(losingHistoryText).not.toContain(losing.realmId);

    const postConflictRetry = await request.post(
      eventsUrl,
      {
        headers: {
          ...selfPathHeadersForDpopSession(bobSession, "POST", eventsUrl),
          "content-type": "application/json",
        },
        data: canonicalJson(acceptedBody),
      },
    );
    const postConflictText = await postConflictRetry.text();
    expect(postConflictRetry.status(), postConflictText).toBe(200);
    const postConflict = JSON.parse(postConflictText) as JsonObject;
    expect(postConflict.status).toBe("duplicate");
    expect(JSON.stringify(postConflict.receipt)).toBe(
      JSON.stringify(first.receipt),
    );
  });
});
