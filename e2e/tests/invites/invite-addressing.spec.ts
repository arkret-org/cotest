import { createHash, randomBytes } from "node:crypto";
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";

import {
  hasServerCount,
  colandBaseUrl,
  colandServiceDid,
  colandServiceId,
  type ColandKey,
} from "../../helpers/env";
import {
  countInvitesFor,
  listAuthzInvitesArkret,
} from "../../helpers/contact-api";
import type {
  InviteDeliveryRequestBodyBodyBody,
} from "../../helpers/coland-api";
import {
  canonicalServiceResolution,
  canonicalJson,
  canonicalTimestamp,
  originalHumanSignerFactApi,
  authHeaders,
  createRealmApi,
  dispatchSelfInviteApi,
  rawDispatchSelfInviteApi,
  rawSubmitPeerInviteDeliveryApi,
  selfInviteDispatchBody,
  refreshEventEnvelopeProof,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/coland-api";
import {
  ensureRegistered,
  issueUserSession,
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

// §7 exposes only the active `failed_precondition` code. The retired
// operation-specific reason codes must not appear on the wire.
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
  // The accepted `ak.invite.create` envelope and the RealmCommit that covers
  // it. §7 has the inviter-side Station read its own persisted canonical bytes
  // rather than rebuild them.
  inviteEvent: Record<string, unknown>;
  inviteCommit: InviteDeliveryRequestBodyBodyBody["invite_commit"];
  producerSignerFact: NonNullable<InviteDeliveryRequestBodyBodyBody["producer_signer_fact"]>;
  evidence: InviteDeliveryRequestBodyBodyBody["introduction_evidence"];
  inviteAddress: InviteDeliveryRequestBodyBodyBody["invite_address"];
};

async function readAcceptedInvite(
  request: APIRequestContext,
  token: string,
  eventId: string,
): Promise<Record<string, unknown>> {
  const url = `${colandBaseUrl()}/_arkret/self/committed-events/${eventId}`;
  const response = await request.get(url, {
    headers: authHeaders(token, "GET", url),
  });
  expect(response.status(), await response.text()).toBe(200);
  const body = await response.json() as { event?: Record<string, unknown> };
  const accepted = body.event;
  if (!accepted) throw new Error("source Station did not return the accepted invite Event");
  expect(accepted.producer_proof, "portable producer proof").toBeDefined();
  return accepted;
}

// A durable `ak.invite.create` that this Station has already accepted
// — §7's precondition for starting private delivery at all.
async function acceptedInviteFixture(
  request: APIRequestContext,
  slug: string,
  recipientServer?: ColandKey,
): Promise<AcceptedInviteFixture> {
  const inviter = uniqueUser(`${slug}-inviter`);
  const invitee = uniqueUser(`${slug}-invitee`);
  await ensureRegistered(request, inviter);
  await ensureRegistered(request, invitee, { server: recipientServer });
  const inviterToken = await issueUserSession(request, inviter);
  const inviteeToken = await issueUserSession(request, invitee, { server: recipientServer });
  const realmId = await createRealmApi(request, inviterToken, {
    title: `invite dispatch ${slug} ${Date.now()}`,
    ownerId: inviter.id,
  });

  const evidence = { kind: "explicit_address" } as const;
  const inviteAddress = {
    account_id: {
      principal_id: invitee.id,
      station_id: colandServiceId(recipientServer),
    },
    // The delivery address carries routing evidence outside the durable Event.
    service_resolution: canonicalServiceResolution(recipientServer),
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
  refreshEventEnvelopeProof(event);
  const submitOutcome = await submitSignedEventApi(request, inviterToken, event, {
    context: `persist ${slug} invite create`,
  });

  const inviteEvent = await readAcceptedInvite(request, inviterToken, String(event.event_id));
  const inviteCommit = (submitOutcome as Record<string, unknown>)
    .commit as InviteDeliveryRequestBodyBodyBody["invite_commit"];
  const producerSignerFact = await originalHumanSignerFactApi(
    request, inviterToken,
    inviteEvent as InviteDeliveryRequestBodyBodyBody["invite_event"], inviteCommit,
  );
  return {
    inviter,
    inviterToken,
    invitee,
    inviteeToken,
    realmId,
    acceptedEventId: String(event.event_id),
    inviteEvent,
    inviteCommit,
    producerSignerFact,
    evidence,
    inviteAddress,
  };
}

// Authentication rejects before notification policy and leaves the holder untouched: no
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
  opts: { server?: ColandKey } = {},
) {
  expect(
    countInvitesFor(
      await listAuthzInvitesArkret(request, fixture.inviteeToken, opts),
      fixture.realmId,
      fixture.invitee.id,
    ),
    `${because}: no holder-private invite may surface`,
  ).toBe(0);

  const accountDataUrl = `${colandBaseUrl(opts.server)}/_arkret/self/account_data`;
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

// The peer notification carries the exact accepted Event and its producer proof.
function peerDeliveryBody(
  fixture: AcceptedInviteFixture,
  label: string,
  inviteEvent: Record<string, unknown> = fixture.inviteEvent,
  inviteCommit: InviteDeliveryRequestBodyBodyBody["invite_commit"] = fixture.inviteCommit,
): InviteDeliveryRequestBodyBodyBody {
  return {
    schema: "ak.schema.invite_delivery_request.v1",
    // `signedEventEnvelope` still returns an untyped record — wiring the Event
    // envelope itself to the generated type is the remaining B3 item.
    invite_event:
      inviteEvent as InviteDeliveryRequestBodyBodyBody["invite_event"],
    invite_commit: inviteCommit,
    producer_signer_fact: fixture.producerSignerFact,
    authority_locator_hints: [
      { service_kind: "station", service_id: colandServiceId(), source: "invite" },
    ],
    invite_address: fixture.inviteAddress,
    introduction_evidence: fixture.evidence,
    idempotency_key: `cotest-peer-invite-${label}-${Date.now()}`,
  };
}

// Read the registered RFC 9457 notification rejection.
async function peerRejection(response: {
  status(): number;
  text(): Promise<string>;
}): Promise<{
  status: number;
  code?: string;
  reason_code?: unknown;
}> {
  const body = JSON.parse(await response.text()) as Record<string, unknown>;
  return {
    status: response.status(),
    code: wireErrCode(body),
    reason_code: body.reason_code,
  };
}

test.describe("invite addressing", () => {
  // Peer-layer direct coverage. `ak.peer.invites.command.submit.v1` is a
  // Station-to-Station operation, so this test exercises the
  // authenticated loopback peer path on the managed Station; it is
  // NOT the client path. A client
  // reaches the same receive pipeline through
  // `ak.self.invites.command.dispatch.v1` (§7), covered below.
  test("peer invite delivery defers explicit_address evidence", async ({ request }) => {
    // Use the source Station's accepted Event with its authentic producer proof.
    const fixture = await acceptedInviteFixture(request, "peer-explicit");
    const recipientServiceId = colandServiceId();

    const outcome = await submitPeerInviteDeliveryApi(
      request,
      peerDeliveryBody(fixture, "explicit"),
      {
        origin: recipientServiceId,
        destination: recipientServiceId,
      },
    );

    expect(outcome.status).toBe("deferred");
    expect(outcome.received_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    expect(outcome.disclosed_outcome).toBeUndefined();
    await assertNoHolderPrivateWrite(request, fixture, "low-trust delivery is not a notification");
  });

  test("invite locator lifecycle uses opaque body-only secrets", async ({
    request,
  }) => {
    const user = uniqueUser(`invite-locator-${Date.now()}`);
    await ensureRegistered(request, user);
    const token = await issueUserSession(request, user);
    const issueUrl = `${colandBaseUrl()}/_arkret/self/invite-locators`;
    const rotateUrl = `${issueUrl}/rotate`;
    const revokeUrl = `${issueUrl}/revoke`;
    const resolveUrl = `${colandBaseUrl()}/_arkret/open/invite-locators/resolve`;

    const issueStarted = Date.now();
    const issue = await request.post(issueUrl, {
      headers: { ...authHeaders(token, "POST", issueUrl), "content-type": "application/json" },
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
    expect(locator.account_id).toEqual({ principal_id: user.id, station_id: colandServiceId() });
    expect(locator).not.toHaveProperty("recipient_id");
    expect(locator.service_resolution.resolution_url).toBe(`${colandBaseUrl()}/_arkret/open/services/${encodeURIComponent(colandServiceId())}/resolution`);
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
      `${colandServiceDid()}#notary-key`,
    );

    const rotate = await request.post(rotateUrl, {
      headers: authHeaders(token, "POST", rotateUrl),
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
      headers: authHeaders(token, "POST", revokeUrl),
      data: { locator_id: rotated.locator_id },
    });
    expect(revoke.status(), await revoke.text()).toBe(200);
    const revoked = await revoke.json();
    const revokeRetry = await request.post(revokeUrl, {
      headers: authHeaders(token, "POST", revokeUrl),
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
        headers: authHeaders(token, "POST", issueUrl),
        data: { ttl_seconds },
      });
      expect(invalidTtl.status()).toBe(400);
    }

    const oneTimeIssue = await request.post(issueUrl, {
      headers: { ...authHeaders(token, "POST", issueUrl), "content-type": "application/json" },
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
      headers: { ...authHeaders(token, "POST", rotateUrl), "content-type": "application/json" },
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
    // `failed_precondition`. The Event below is well
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
      reason: undefined,
    });

    // §7: a signer that is not the authenticated session actor MUST be
    // rejected with `failed_precondition`. The
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
      reason: undefined,
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

  test("first-contact Station handles a signed notification without Realm history", async ({ request }) => {
    test.skip(
      !hasServerCount(2),
      "requires two-server topology — pass -ServerCount 2 to scripts/run-joint-e2e.ps1",
    );
    const fixture = await acceptedInviteFixture(request, "foreign-notification", "server2");
    await assertNoHolderPrivateWrite(request, fixture, "before delivery", { server: "server2" });
    const delivered = await submitPeerInviteDeliveryApi(request, peerDeliveryBody(fixture, "foreign"), {
      origin: colandServiceId(), destination: colandServiceId("server2"), server: "server2",
    });
    expect(delivered.status).toBe("deferred");
    const realmUrl = `${colandBaseUrl("server2")}/_arkret/self/realms/${encodeURIComponent(fixture.realmId)}`;
    const realm = await request.get(realmUrl, { headers: authHeaders(fixture.inviteeToken, "GET", realmUrl) });
    expect(realm.status(), "notification does not grant Realm read authority").toBe(404);
  });

  // federation.md section 3 / invite-addressing.md step 4 (decision 0107
  // section 6): the invitee Station does not govern the Realm, so it never
  // resolves the inviter's foreign human device key. It checks only that the
  // producer proof is self-consistent and that invite_commit is signed by the
  // Realm's current governance Station; each defect below is one of those
  // checks failing, and each is refused before any holder-private write.
  test("notification is judged by proof self-consistency and the governance commit", async ({ request }) => {
    test.skip(
      !hasServerCount(2),
      "requires two-server topology — pass -ServerCount 2 to scripts/run-joint-e2e.ps1",
    );
    const fixture = await acceptedInviteFixture(request, "non-governance-receiver", "server2");
    const withProof = (
      mutate: (proof: Record<string, unknown>) => void,
    ): Record<string, unknown> => {
      const event = structuredClone(fixture.inviteEvent);
      const proof = event.producer_proof as Record<string, unknown>;
      expect(proof).toBeDefined();
      mutate(proof);
      return event;
    };
    const cases: Array<[string, Record<string, unknown>, InviteDeliveryRequestBodyBodyBody["invite_commit"]]> = [
      [
        "event-digest-mismatch",
        withProof((proof) => {
          proof.event_digest = `sha256:${"0".repeat(64)}`;
        }),
        fixture.inviteCommit,
      ],
      [
        "fragment-not-device-id",
        withProof((proof) => {
          const [did, fragment] = String(proof.verification_method).split("#");
          expect(fragment?.startsWith("ak:device:"), "inviter signs with a human device").toBe(true);
          proof.verification_method = `${did}#${fragment!.slice(0, "ak:device:".length + 8)}`;
        }),
        fixture.inviteCommit,
      ],
      [
        "governance-signature-invalid",
        fixture.inviteEvent,
        (() => {
          const commit = structuredClone(fixture.inviteCommit) as unknown as {
            signature: { sig: string };
          };
          const sig = commit.signature.sig;
          commit.signature.sig = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
          return commit as unknown as InviteDeliveryRequestBodyBodyBody["invite_commit"];
        })(),
      ],
    ];
    for (const [label, event, commit] of cases) {
      const response = await rawSubmitPeerInviteDeliveryApi(
        request, peerDeliveryBody(fixture, label, event, commit),
        { origin: colandServiceId(), destination: colandServiceId("server2"), server: "server2" },
      );
      expect(await peerRejection(response), label).toMatchObject({ status: 401, code: "signature_invalid" });
      await assertNoHolderPrivateWrite(request, fixture, label, { server: "server2" });
    }
  });
});
