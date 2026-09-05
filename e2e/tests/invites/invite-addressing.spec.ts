import { createHash, randomBytes } from "node:crypto";
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";

import {
  solandBaseUrl,
  solandServiceDid,
  solandServiceId,
  type SolandKey,
} from "../../helpers/env";
import {
  countInvitesFor,
  listAuthzInvitesArkret,
} from "../../helpers/contact-api";
import type {
  InviteDeliveryCbaProofBundle,
  InviteDeliveryRequestBodyBodyBody,
} from "../../helpers/soland-api";
import {
  advanceEnvelopeToActorFrontier,
  canonicalServiceResolution,
  canonicalJson,
  canonicalTimestamp,
  authHeaders,
  createRealmApi,
  dispatchSelfInviteApi,
  inviteDeliveryCbaProofBundles,
  rawDispatchSelfInviteApi,
  rawSubmitPeerInviteDeliveryApi,
  REALM_AUTHORITY_ROOT_CELL,
  selfInviteDispatchBody,
  readRealmSealBasis,
  refreshEventEnvelopeProof,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

type InviteLocatorIssueOutcome = {
  locator_id: string;
  locator_token: string;
  expires_at: string;
  one_time_use: boolean;
};

async function errorFingerprint(response: {
  status(): number;
  headers(): Record<string, string>;
  text(): Promise<string>;
}) {
  const body = JSON.parse(await response.text()) as {
    ok: boolean;
    error: { code: string; message: string };
  };
  return {
    status: response.status(),
    contentType: response.headers()["content-type"],
    ok: body.ok,
    error: body.error,
  };
}

// The two §7 accepted-event preconditions are a closed rejection set:
// `failed_precondition` plus one of `invite_event_unaccepted` /
// `invite_event_actor_mismatch`. RFC 9457 `type` carries the top-level code;
// the registered operation-specific sub-reason is the root `reason_code`.
async function dispatchRejection(response: {
  status(): number;
  text(): Promise<string>;
}): Promise<{ status: number; code?: string; reason?: string }> {
  const text = await response.text();
  const body = JSON.parse(text) as { reason_code?: string };
  return {
    status: response.status(),
    code: wireErrCode(body),
    reason: body.reason_code,
  };
}

type AcceptedInviteFixture = {
  inviter: JointUser;
  inviterToken: string;
  invitee: JointUser;
  inviteeToken: string;
  realmId: string;
  acceptedEventId: string;
  // The accepted `ak.invite.create` envelope and the Seal basis it committed
  // to. §7 has the inviter-side Station read its own persisted canonical bytes
  // rather than rebuild them, and step 4 keys the CBA closure on exactly these
  // leaves.
  inviteEvent: Record<string, unknown>;
  sealBasis: Record<string, unknown>;
  evidence: InviteDeliveryRequestBodyBodyBody["introduction_evidence"];
  inviteAddress: InviteDeliveryRequestBodyBodyBody["invite_address"];
};

// A durable `ak.invite.create` that this Station has already accepted
// — §7's precondition for starting private delivery at all.
async function acceptedInviteFixture(
  request: APIRequestContext,
  slug: string,
): Promise<AcceptedInviteFixture> {
  const inviter = uniqueUser(`${slug}-inviter`);
  const invitee = uniqueUser(`${slug}-invitee`);
  await ensureRegistered(request, inviter);
  await ensureRegistered(request, invitee);
  const inviterToken = await issueDevSession(request, inviter);
  const inviteeToken = await issueDevSession(request, invitee);
  const realmId = await createRealmApi(request, inviterToken, {
    title: `invite dispatch ${slug} ${Date.now()}`,
    ownerId: inviter.id,
  });

  const evidence = { kind: "explicit_address" } as const;
  const inviteAddress = {
    account_id: {
      principal_id: invitee.id,
      station_id: solandServiceId(),
    },
    // The delivery address carries routing evidence outside the durable Event.
    service_resolution: canonicalServiceResolution(),
  };
  const event = signedEventEnvelope({
    actorId: inviter.id,
    realmId,
    kind: "ak.invite.create",
    payload: {
      invitee_account_id: inviteAddress.account_id,
      introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
      expires_at: canonicalTimestamp(
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ),
    },
  });
  await advanceEnvelopeToActorFrontier(request, inviterToken, event);
  const sealBasis = await readRealmSealBasis(request, inviterToken, realmId);
  event.seal_basis = sealBasis;
  refreshEventEnvelopeProof(event);
  await submitSignedEventApi(request, inviterToken, event, {
    context: `persist ${slug} invite create`,
  });

  return {
    inviter,
    inviterToken,
    invitee,
    inviteeToken,
    realmId,
    acceptedEventId: String(event.event_id),
    inviteEvent: event,
    sealBasis,
    evidence,
    inviteAddress,
  };
}

// §7 step 4 rejects before step 5 and MUST leave the holder untouched: no
// delivery, no outbox enqueue, no holder-private write. The invitee's own
// authz invite list and its `ak.account.invite_delivery` account-data cell are
// the two holder-private surfaces a delivery would have written.
async function assertNoHolderPrivateWrite(
  request: APIRequestContext,
  fixture: Pick<
    AcceptedInviteFixture,
    "inviteeToken" | "invitee" | "realmId"
  >,
  because: string,
  opts: { server?: SolandKey } = {},
) {
  expect(
    countInvitesFor(
      await listAuthzInvitesArkret(request, fixture.inviteeToken, opts),
      fixture.realmId,
      fixture.invitee.id,
    ),
    `${because}: no holder-private invite may surface`,
  ).toBe(0);

  const accountDataUrl = `${solandBaseUrl(opts.server)}/_arkret/self/account_data`;
  const listed = await request.get(accountDataUrl, {
    headers: authHeaders(fixture.inviteeToken, "GET", accountDataUrl),
  });
  expect(listed.status(), await listed.text()).toBe(200);
  const entries = ((await listed.json()) as {
    account_data_entries?: Array<{ account_data_key?: string }>;
  }).account_data_entries;
  expect(
    (entries ?? []).some(
      (entry) => entry.account_data_key === "ak.account.invite_delivery",
    ),
    `${because}: no holder-private invite_delivery cell may be written`,
  ).toBe(false);
}

// The §7 peer body for an already-accepted invite Event, with the caller's own
// choice of capability bundles so a negative case can perturb exactly one
// member.
function peerDeliveryBody(
  fixture: AcceptedInviteFixture,
  bundles: InviteDeliveryCbaProofBundle[],
  label: string,
  inviteEvent: Record<string, unknown> = fixture.inviteEvent,
): InviteDeliveryRequestBodyBodyBody {
  return {
    schema: "ak.schema.invite_delivery_request.v1",
    // `signedEventEnvelope` still returns an untyped record — wiring the Event
    // envelope itself to the generated type is the remaining B3 item.
    invite_event:
      inviteEvent as InviteDeliveryRequestBodyBodyBody["invite_event"],
    invite_address: fixture.inviteAddress,
    introduction_evidence: fixture.evidence,
    cba_proof_bundles: bundles,
    idempotency_key: `cotest-peer-invite-${label}-${Date.now()}`,
  };
}

// RFC 9457 problem body plus the registered top-level members `cba-profiles.md`
// §5 requires a `dependency_missing` to carry.
async function peerRejection(response: {
  status(): number;
  text(): Promise<string>;
}): Promise<{
  status: number;
  code?: string;
  reason_code?: unknown;
  missing_seal_refs?: unknown;
  missing_event_digests?: unknown;
}> {
  const body = JSON.parse(await response.text()) as Record<string, unknown>;
  return {
    status: response.status(),
    code: wireErrCode(body),
    reason_code: body.reason_code,
    missing_seal_refs: body.missing_seal_refs,
    missing_event_digests: body.missing_event_digests,
  };
}

// A second accepted `ak.invite.create` in the same Realm. Its Seal basis leaf
// is the Seal that sealed the first one, so the leaf has a predecessor and the
// capability closure is more than a single Seal — which is what makes an
// incomplete closure constructible at all.
async function acceptSuccessorInviteCreate(
  request: APIRequestContext,
  fixture: AcceptedInviteFixture,
): Promise<{ event: Record<string, unknown>; sealBasis: Record<string, unknown> }> {
  const event = signedEventEnvelope({
    actorId: fixture.inviter.id,
    realmId: fixture.realmId,
    kind: "ak.invite.create",
    payload: {
      invitee_account_id: fixture.inviteAddress.account_id,
      introduction_evidence_digest: `sha256:${sha256CanonicalJson(fixture.evidence)}`,
      expires_at: canonicalTimestamp(
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ),
    },
  });
  await advanceEnvelopeToActorFrontier(request, fixture.inviterToken, event);
  const sealBasis = await readRealmSealBasis(
    request,
    fixture.inviterToken,
    fixture.realmId,
  );
  event.seal_basis = sealBasis;
  refreshEventEnvelopeProof(event);
  await submitSignedEventApi(request, fixture.inviterToken, event, {
    context: "persist successor invite create",
  });
  return { event, sealBasis };
}

test.describe("invite addressing", () => {
  // Peer-layer direct coverage. `ak.peer.invites.command.submit.v1` is a
  // Station-to-Station operation, so this test exercises the
  // authenticated loopback peer path on the managed Station; it is
  // NOT the client path. A client
  // reaches the same receive pipeline through
  // `ak.self.invites.command.dispatch.v1` (§7), covered below.
  test("peer invite delivery defers explicit_address evidence", async ({ request }) => {
    // The invite Event must belong to a Realm this Station has actually
    // accepted. §7 step 4 verifies the inviter's Realm capability against the
    // closure keyed on `invite_event.seal_basis.leaves`, and a Realm that
    // exists only inside the test process has no accepted Seal to key on — the
    // request would fail step 4 before the §5 disclosure this case is about.
    const fixture = await acceptedInviteFixture(request, "peer-explicit");
    const recipientServiceId = solandServiceId();

    const outcome = await submitPeerInviteDeliveryApi(
      request,
      {
        schema: "ak.schema.invite_delivery_request.v1",
        // `signedEventEnvelope` still returns an untyped record — wiring the
        // Event envelope itself to the generated type is the remaining B3 item.
        invite_event:
          fixture.inviteEvent as InviteDeliveryRequestBodyBodyBody["invite_event"],
        invite_address: fixture.inviteAddress,
        introduction_evidence: fixture.evidence,
        cba_proof_bundles: await inviteDeliveryCbaProofBundles(
          request,
          fixture.inviterToken,
          fixture.realmId,
          fixture.sealBasis,
        ),
        idempotency_key: `cotest-peer-invite-${Date.now()}`,
      },
      {
        origin: recipientServiceId,
        destination: recipientServiceId,
      },
    );

    expect(outcome.status).toBe("deferred");
    expect(outcome.received_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
  });

  test("invite locator lifecycle uses opaque body-only secrets", async ({
    request,
  }) => {
    const user = uniqueUser(`invite-locator-${Date.now()}`);
    await ensureRegistered(request, user);
    const token = await issueDevSession(request, user);
    const selfHeaders = authHeaders(token);
    const issueUrl = `${solandBaseUrl()}/_arkret/self/invite-locators`;
    const rotateUrl = `${issueUrl}/rotate`;
    const revokeUrl = `${issueUrl}/revoke`;
    const resolveUrl = `${solandBaseUrl()}/_arkret/open/invite-locators/resolve`;

    const issueStarted = Date.now();
    const issue = await request.post(issueUrl, {
      headers: { ...selfHeaders, "content-type": "application/json" },
      data: canonicalJson({
        ttl_seconds: 60,
        one_time_use: false,
        display_hint: { display_name_hint: "Cotest locator" },
      }),
    });
    expect(issue.status(), await issue.text()).toBe(200);
    expect(issue.headers()["cache-control"]).toBe("private, no-store");
    const issued = (await issue.json()) as InviteLocatorIssueOutcome;
    expect(issued.locator_token).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(Buffer.from(issued.locator_token, "base64url")).toHaveLength(24);
    expect(() =>
      JSON.parse(Buffer.from(issued.locator_token, "base64url").toString("utf8")),
    ).toThrow();
    expect(Date.parse(issued.expires_at) - issueStarted).toBeGreaterThanOrEqual(
      55_000,
    );
    expect(Date.parse(issued.expires_at) - issueStarted).toBeLessThanOrEqual(
      65_000,
    );

    const queryLeak = await request.post(
      `${resolveUrl}?locator_token=${encodeURIComponent(issued.locator_token)}`,
      { data: { locator_token: issued.locator_token } },
    );
    expect(queryLeak.status()).toBe(400);
    const pathLeak = await request.post(
      `${resolveUrl}/${encodeURIComponent(issued.locator_token)}`,
      { data: { locator_token: issued.locator_token } },
    );
    expect(pathLeak.status()).toBe(404);

    const resolvedResponse = await request.post(resolveUrl, {
      data: { locator_token: issued.locator_token },
    });
    expect(resolvedResponse.status(), await resolvedResponse.text()).toBe(200);
    const locator = await resolvedResponse.json();
    expect(locator.schema).toBe("ak.schema.principal_locator.v1");
    expect(locator.account_id).toEqual({ principal_id: user.id, station_id: solandServiceId() });
    expect(locator).not.toHaveProperty("recipient_id");
    expect(locator.service_resolution.current_record_url).toBe(`${solandBaseUrl()}/_arkret/open/services/${encodeURIComponent(solandServiceId())}/resolution`);
    expect(locator.issued_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    expect(locator.expires_at).toBe(issued.expires_at);
    expect(locator.display_hint).toEqual({ display_name_hint: "Cotest locator" });
    expect(locator.locator_ref_digest).toBe(
      `sha256:${createHash("sha256").update(issued.locator_token).digest("hex")}`,
    );
    expect(locator.proofs?.[0]?.proof_purpose).toBe(
      "recipient_service_acceptance",
    );
    expect(locator.proofs?.[0]?.proof?.verification_method).toBe(
      `${solandServiceDid()}#notary-key`,
    );

    const rotate = await request.post(rotateUrl, {
      headers: selfHeaders,
      data: { locator_id: issued.locator_id },
    });
    expect(rotate.status(), await rotate.text()).toBe(200);
    expect(rotate.headers()["cache-control"]).toBe("private, no-store");
    const rotated = (await rotate.json()) as InviteLocatorIssueOutcome;
    expect(rotated.locator_token).not.toBe(issued.locator_token);
    expect(rotated.one_time_use).toBe(false);
    expect(
      Date.parse(rotated.expires_at) - Date.parse(locator.issued_at),
    ).toBeGreaterThanOrEqual(60_000);

    const oldAfterRotate = await request.post(resolveUrl, {
      data: { locator_token: issued.locator_token },
    });
    const unknown = await request.post(resolveUrl, {
      data: { locator_token: randomBytes(24).toString("base64url") },
    });
    expect(await errorFingerprint(oldAfterRotate)).toEqual(
      await errorFingerprint(unknown),
    );
    const rotatedResolve = await request.post(resolveUrl, {
      data: { locator_token: rotated.locator_token },
    });
    expect(rotatedResolve.status(), await rotatedResolve.text()).toBe(200);
    expect((await rotatedResolve.json()).display_hint).toEqual({
      display_name_hint: "Cotest locator",
    });

    const revoke = await request.post(revokeUrl, {
      headers: selfHeaders,
      data: { locator_id: rotated.locator_id },
    });
    expect(revoke.status(), await revoke.text()).toBe(200);
    const revoked = await revoke.json();
    const revokeRetry = await request.post(revokeUrl, {
      headers: selfHeaders,
      data: { locator_id: rotated.locator_id },
    });
    expect(revokeRetry.status(), await revokeRetry.text()).toBe(200);
    expect((await revokeRetry.json()).revoked_at).toBe(revoked.revoked_at);
    const revokedResolve = await request.post(resolveUrl, {
      data: { locator_token: rotated.locator_token },
    });
    expect(await errorFingerprint(revokedResolve)).toEqual(
      await errorFingerprint(unknown),
    );

    for (const ttl_seconds of [59, 3601]) {
      const invalidTtl = await request.post(issueUrl, {
        headers: selfHeaders,
        data: { ttl_seconds },
      });
      expect(invalidTtl.status()).toBe(400);
    }

    const oneTimeIssue = await request.post(issueUrl, {
      headers: { ...selfHeaders, "content-type": "application/json" },
      data: canonicalJson({
        ttl_seconds: 120,
        one_time_use: false,
        display_hint: { display_name_hint: "Clear me" },
      }),
    });
    expect(oneTimeIssue.status(), await oneTimeIssue.text()).toBe(200);
    const beforeOneTime =
      (await oneTimeIssue.json()) as InviteLocatorIssueOutcome;
    const oneTimeRotate = await request.post(rotateUrl, {
      headers: { ...selfHeaders, "content-type": "application/json" },
      data: canonicalJson({
        locator_id: beforeOneTime.locator_id,
        ttl_seconds: 60,
        one_time_use: true,
        display_hint: null,
      }),
    });
    expect(oneTimeRotate.status(), await oneTimeRotate.text()).toBe(200);
    const oneTime = (await oneTimeRotate.json()) as InviteLocatorIssueOutcome;
    expect(oneTime.one_time_use).toBe(true);
    const concurrent = await Promise.all([
      request.post(resolveUrl, { data: { locator_token: oneTime.locator_token } }),
      request.post(resolveUrl, { data: { locator_token: oneTime.locator_token } }),
    ]);
    expect(concurrent.map((response) => response.status()).sort()).toEqual([
      200, 404,
    ]);
    const successfulOneTime = concurrent.find(
      (response) => response.status() === 200,
    );
    expect((await successfulOneTime!.json()).display_hint).toBeUndefined();
  });

  // invite-addressing.md §7 — `ak.self.invites.command.dispatch.v1`. This is the
  // only conforming client entry point into private invite delivery: the client
  // hands raw `introduction_evidence` plus the accepted Event id to its own
  // Station and never synthesizes federation trust material.
  test("self invite dispatch delivers a same-service invite and is retry-idempotent", async ({
    request,
  }) => {
    const fixture = await acceptedInviteFixture(request, "dispatch-local");

    const body = selfInviteDispatchBody({
      eventId: fixture.acceptedEventId,
      inviteAddress: fixture.inviteAddress,
      evidence: fixture.evidence,
    });
    expect(body.invite_event_id).toBe(fixture.acceptedEventId);

    const outcome = await dispatchSelfInviteApi(
      request,
      fixture.inviterToken,
      body,
    );
    // The target is this service, so §7 runs the receive verification from step
    // 4 onward locally. The invitee published no `invite_receive_policy`, so §5
    // fails closed: `explicit_address` is low trust and is quarantined or
    // dropped. §5.1 pins that to `status="deferred"` with no
    // `disclosed_outcome`, indistinguishable from a silent drop.
    expect(outcome.status).toBe("deferred");
    expect(outcome.disclosed_outcome).toBeUndefined();

    // §7: an uncertain transport outcome MUST be retried with the same body and
    // the same `idempotency_key`, never with substituted evidence or Event.
    const retry = await dispatchSelfInviteApi(
      request,
      fixture.inviterToken,
      body,
    );
    expect(
      ["deferred", "duplicate"],
      "an exact §7 retry must stay inside the opaque low-trust equivalence class",
    ).toContain(retry.status);
    expect(retry.disclosed_outcome).toBeUndefined();

    // A quarantined low-trust invite MUST NOT surface to the invitee, and the
    // retry MUST NOT have produced a second holder-private write.
    expect(
      countInvitesFor(
        await listAuthzInvitesArkret(request, fixture.inviteeToken),
        fixture.realmId,
        fixture.invitee.id,
      ),
      "a quarantined low-trust invite must stay invisible to the invitee",
    ).toBe(0);
  });

  // §7 defines the accepted-event lookup and authenticated-actor preconditions,
  // semantics are closed. None of them may produce a delivery, an outbox
  // enqueue, or a holder-private write.
  test("self invite dispatch fails closed on accepted-event preconditions", async ({
    request,
  }) => {
    const fixture = await acceptedInviteFixture(request, "dispatch-reject");
    const accepted = selfInviteDispatchBody({
      eventId: fixture.acceptedEventId,
      inviteAddress: fixture.inviteAddress,
      evidence: fixture.evidence,
    });

    // §7: an Event this service has not accepted MUST be rejected with
    // `failed_precondition` / `invite_event_unaccepted`. The Event below is well
    // formed and correctly signed but was never submitted.
    const unsubmitted = signedEventEnvelope({
      actorId: fixture.inviter.id,
      realmId: fixture.realmId,
      kind: "ak.invite.create",
      payload: {
        invitee_account_id: fixture.inviteAddress.account_id,
        introduction_evidence_digest: `sha256:${sha256CanonicalJson(fixture.evidence)}`,
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ),
      },
    });
    const unaccepted = await rawDispatchSelfInviteApi(
      request,
      fixture.inviterToken,
      {
        ...accepted,
        invite_event_id: String(unsubmitted.event_id),
        idempotency_key: `${accepted.idempotency_key}-unaccepted`,
      },
    );
    expect(await dispatchRejection(unaccepted)).toMatchObject({
      // error-code-registry.json maps `failed_precondition` to HTTP 409.
      status: 409,
      code: "failed_precondition",
      reason: "invite_event_unaccepted",
    });

    // §7: a signer that is not the authenticated session actor MUST be
    // rejected with `failed_precondition` / `invite_event_actor_mismatch`. The
    // Event here is accepted and byte-exact — only the session belongs to
    // someone else, and the service MUST NOT co-sign or re-author for them.
    const actorMismatch = await rawDispatchSelfInviteApi(
      request,
      fixture.inviteeToken,
      accepted,
    );
    expect(await dispatchRejection(actorMismatch)).toMatchObject({
      // error-code-registry.json maps `failed_precondition` to HTTP 409.
      status: 409,
      code: "failed_precondition",
      reason: "invite_event_actor_mismatch",
    });

    // §7: neither rejection may produce a delivery, an outbox
    // enqueue, or a holder-private write.
    expect(
      countInvitesFor(
        await listAuthzInvitesArkret(request, fixture.inviteeToken),
        fixture.realmId,
        fixture.invitee.id,
      ),
      "a rejected §7 precondition must not create any holder-private invite",
    ).toBe(0);
  });

  // ── §7 step 4: the Realm capability closure carried by cba_proof_bundles ──
  //
  // The receiving Station is by definition not yet a federation peer of the
  // inviting Realm, so `ak.peer.seals.read.*` fails closed for it and the
  // closure MUST travel inside the request. Step 4 is a function of
  // `(invite_event, cba_proof_bundles)` alone and completes before step 5, so
  // every rejection below is a precise registered outcome — not a member of
  // the holder-indistinguishable class — and every one of them MUST leave the
  // holder untouched.
  //
  // The inviter's own material is what makes these constructible; the one
  // authorization verdict that needs a *narrowed* Realm authority is recorded
  // as a gap at the end of this block rather than faked here.

  test("step 4 rejects a delivery that carries no capability proof bundle", async ({
    request,
  }) => {
    const fixture = await acceptedInviteFixture(request, "step4-no-bundle");
    const bundles = await inviteDeliveryCbaProofBundles(
      request,
      fixture.inviterToken,
      fixture.realmId,
      fixture.sealBasis,
    );
    // `cba_proof_bundles` is a required top-level member, so a body without it
    // never reaches the closure evaluation: it fails the request schema.
    const { cba_proof_bundles: _omitted, ...withoutBundles } = peerDeliveryBody(
      fixture,
      bundles,
      "no-bundle",
    );
    const response = await rawSubmitPeerInviteDeliveryApi(
      request,
      withoutBundles as InviteDeliveryRequestBodyBodyBody,
      { origin: solandServiceId(), destination: solandServiceId() },
    );
    // error-code-registry.json maps `schema_violation` to HTTP 422 and defines
    // it as "parsed input does not satisfy the declared schema contract" — a
    // body missing a required member parses cleanly, so `json_invalid` ("JSON
    // body cannot be parsed", HTTP 400) is not the registered answer here.
    expect(await peerRejection(response)).toMatchObject({
      status: 422,
      code: "schema_violation",
    });
    await assertNoHolderPrivateWrite(
      request,
      fixture,
      "a delivery without a capability proof bundle",
    );
  });

  test("step 4 rejects a target_seal_ref outside invite_event.seal_basis.leaves", async ({
    request,
  }) => {
    const fixture = await acceptedInviteFixture(request, "step4-foreign-leaf");
    // A second Realm the same inviter owns. Its accepted Seal is a real,
    // independently verifiable object — the single defect is that it is not a
    // leaf of the invite Control Move's own basis, which §5 treats as an
    // unreachable object and therefore a schema violation.
    const otherRealmId = await createRealmApi(request, fixture.inviterToken, {
      title: `step4 foreign leaf ${Date.now()}`,
      ownerId: fixture.inviter.id,
    });
    const otherBasis = await readRealmSealBasis(
      request,
      fixture.inviterToken,
      otherRealmId,
    );
    expect(
      canonicalJson(otherBasis),
      "the foreign Realm must have its own Seal basis",
    ).not.toBe(canonicalJson(fixture.sealBasis));
    const foreignBundles = await inviteDeliveryCbaProofBundles(
      request,
      fixture.inviterToken,
      otherRealmId,
      otherBasis,
    );

    const response = await rawSubmitPeerInviteDeliveryApi(
      request,
      peerDeliveryBody(fixture, foreignBundles, "foreign-leaf"),
      { origin: solandServiceId(), destination: solandServiceId() },
    );
    expect(await peerRejection(response)).toMatchObject({
      status: 422,
      code: "schema_violation",
    });
    await assertNoHolderPrivateWrite(
      request,
      fixture,
      "a bundle targeting a Seal outside the invite basis",
    );
  });

  test("step 4 reports an incomplete capability closure with the exact missing Seals", async ({
    request,
  }) => {
    const fixture = await acceptedInviteFixture(request, "step4-closure");
    // The successor invite Control Move's basis leaf has a predecessor, so the
    // closure is more than one Seal and a genuine hole can be opened in it.
    const successor = await acceptSuccessorInviteCreate(request, fixture);
    const complete = await inviteDeliveryCbaProofBundles(
      request,
      fixture.inviterToken,
      fixture.realmId,
      successor.sealBasis,
    );
    expect(complete, "one bundle per basis leaf").toHaveLength(1);
    const target = complete[0]!.target_seal_ref;
    const targetSeal = complete[0]!.seals.find(
      (seal) => (seal as unknown as { id: string }).id === target,
    ) as unknown as { predecessor_refs?: string[] } | undefined;
    // Withholding the leaf's own predecessors is what the receiver can name
    // precisely: it walks the Seals it was given and reports the refs they
    // point at but that never arrived.
    const withheld = Array.from(
      new Set(targetSeal?.predecessor_refs ?? []),
    ).sort();
    expect(
      withheld.length,
      "the successor leaf must have at least one predecessor Seal to withhold",
    ).toBeGreaterThan(0);

    // cba-profiles.md §5: an incomplete closure is answered with the exact
    // Seals the sender still owes, never with an opaque authorization failure
    // and never by fetching the dependency from the inviting Realm.
    const truncated: InviteDeliveryCbaProofBundle[] = [
      {
        ...complete[0]!,
        seals: complete[0]!.seals.filter(
          (seal) => (seal as unknown as { id: string }).id === target,
        ),
      },
    ];
    const response = await rawSubmitPeerInviteDeliveryApi(
      request,
      peerDeliveryBody(fixture, truncated, "closure", successor.event),
      { origin: solandServiceId(), destination: solandServiceId() },
    );
    const rejection = await peerRejection(response);
    expect(rejection).toMatchObject({
      // error-code-registry.json maps `dependency_missing` to HTTP 409.
      status: 409,
      code: "dependency_missing",
    });
    expect(
      rejection.missing_seal_refs,
      "dependency_missing MUST name the withheld Seals exactly",
    ).toEqual(withheld);
    expect(
      Array.isArray(rejection.missing_event_digests),
      "dependency_missing MUST carry a bounded missing_event_digests list",
    ).toBe(true);
    await assertNoHolderPrivateWrite(
      request,
      fixture,
      "a delivery whose capability closure is incomplete",
    );
  });

  test("step 4 rejects an inviter that is not the authority-root controller", async ({
    request,
  }) => {
    const fixture = await acceptedInviteFixture(request, "step4-controller");
    // Registering is enough: the outsider only has to be able to sign an
    // Event envelope, never to hold a session on the inviting Realm.
    const outsider = uniqueUser(`step4-controller-outsider-${Date.now()}`);
    await ensureRegistered(request, outsider);

    // The Realm, its Seal basis and the whole capability closure are genuine;
    // the only defect is the signer. capabilities.md §3.2 closes the
    // authority-root branch on the cell's current controller and forbids any
    // fallback to `realm_state.owner`, membership or `created_by`, so this MUST
    // fail closed with the registered controller-mismatch reason rather than
    // an opaque denial.
    const foreignInvite = signedEventEnvelope({
      actorId: outsider.id,
      realmId: fixture.realmId,
      kind: "ak.invite.create",
      authorizationRef: REALM_AUTHORITY_ROOT_CELL,
      sealBasis: fixture.sealBasis,
      payload: {
        invitee_account_id: fixture.inviteAddress.account_id,
        introduction_evidence_digest: `sha256:${sha256CanonicalJson(fixture.evidence)}`,
        expires_at: canonicalTimestamp(
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ),
      },
    });
    const bundles = await inviteDeliveryCbaProofBundles(
      request,
      fixture.inviterToken,
      fixture.realmId,
      fixture.sealBasis,
    );
    const response = await rawSubmitPeerInviteDeliveryApi(
      request,
      peerDeliveryBody(fixture, bundles, "controller", foreignInvite),
      { origin: solandServiceId(), destination: solandServiceId() },
    );
    // error-code-registry.json registers `realm_authority_controller_mismatch`
    // as a reason code, not a top-level code: the closed top-level primitive
    // for an authorization denial is `capability_denied` (HTTP 403), and the
    // narrowest registered reason rides on it instead of being flattened away.
    expect(await peerRejection(response)).toMatchObject({
      status: 403,
      code: "capability_denied",
      reason_code: "realm_authority_controller_mismatch",
    });
    await assertNoHolderPrivateWrite(
      request,
      fixture,
      "a delivery whose inviter is not the authority-root controller",
    );
  });

  // GAP — "the inviter holds Realm authority but not `ak.invite.create`".
  //
  // The ruling's fifth step-4 case wants the narrowest capability reason
  // (`missing_capability`) for an inviter whose authority is a `grant_ref`
  // whose action set excludes the invite action. It is not written here
  // because the closure this suite can transport carries only the Control
  // Moves that write the authority-root cell — the one cell capabilities.md
  // §3.2 admits, and the one the Station-side builder selects. A grant cell's
  // establishing Move is therefore not in the closure, so the request would
  // fail as an incomplete or unresolvable grant rather than as an authorized
  // actor missing one action, and the assertion would be measuring the wrong
  // thing. Landing it needs the grant branch of step 4 defined against a
  // transported grant closure; the case above already pins the authority-root
  // branch, which is the branch every invite created by a Realm owner takes.
});
