import { createHash, randomBytes } from "node:crypto";
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";

import {
  solandBaseUrl,
  solandServiceDid,
  solandServiceId,
  solandServiceResolution,
} from "../../helpers/env";
import {
  countInvitesFor,
  listAuthzInvitesArkret,
} from "../../helpers/contact-api";
import type { InviteDeliveryRequestBodyBodyBody } from "../../helpers/soland-api";
import {
  advanceEnvelopeToActorFrontier,
  canonicalServiceResolution,
  canonicalJson,
  canonicalTimestamp,
  authHeaders,
  createRealmApi,
  dispatchSelfInviteApi,
  rawDispatchSelfInviteApi,
  selfInviteDispatchBody,
  readRealmSealBasis,
  refreshEventEnvelopeProof,
  registerEventSigner,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  submitSignedEventApi,
  typedId,
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
    // §7 step 6: this carrier and the durable
    // `invite_delivery_target.service_resolution` MUST be byte-for-byte equal.
    service_resolution: canonicalServiceResolution(),
  };
  const event = signedEventEnvelope({
    actorId: inviter.id,
    realmId,
    kind: "ak.invite.create",
    payload: {
      invitee_id: invitee.id,
      invite_delivery_target: {
        account_id: inviteAddress.account_id,
        service_resolution: inviteAddress.service_resolution,
      },
      introduction_evidence_digest: `sha256:${sha256CanonicalJson(evidence)}`,
      expires_at: canonicalTimestamp(
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ),
    },
  });
  await advanceEnvelopeToActorFrontier(request, inviterToken, event);
  event.seal_basis = await readRealmSealBasis(request, inviterToken, realmId);
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
    evidence,
    inviteAddress,
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
    const recipientServiceId = solandServiceId();
    const invitee = "ak:did_core:web:cotest-invitee.example";
    const introductionEvidence = { kind: "explicit_address" } as const;
    const inviteDeliveryTarget = {
      account_id: {
        principal_id: invitee,
        station_id: recipientServiceId,
      },
    };
    // This inviter is synthetic — it never registers through the client path,
    // so its Event proof has no signer unless one is registered here. The
    // verification method must be a real DID URL: event-envelope.schema.json
    // forbids concatenating a did_core_id into one.
    const inviter = "ak:did_core:web:cotest-inviter.example";
    const inviterDeviceId = "ak:device:01904100-0000-7000-8000-0000000000a1";
    registerEventSigner({
      actorId: inviter,
      deviceId: inviterDeviceId,
      verificationMethod: `did:web:cotest-inviter.example#${inviterDeviceId}`,
    });
    const inviteEvent = signedEventEnvelope({
      actorId: inviter,
      realmId: typedId("realm"),
      kind: "ak.invite.create",
      payload: {
        invitee_id: invitee,
        invite_delivery_target: inviteDeliveryTarget,
        introduction_evidence_digest: `sha256:${sha256CanonicalJson(introductionEvidence)}`,
        expires_at: canonicalTimestamp(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)),
      },
    });

    const outcome = await submitPeerInviteDeliveryApi(
      request,
      {
        schema: "ak.schema.invite_delivery_request.v1",
        // `signedEventEnvelope` still returns an untyped record — wiring the
        // Event envelope itself to the generated type is the remaining B3 item.
        invite_event:
          inviteEvent as InviteDeliveryRequestBodyBodyBody["invite_event"],
        invite_address: {
          account_id: inviteDeliveryTarget.account_id,
          service_resolution: solandServiceResolution(),
        },
        introduction_evidence: introductionEvidence,
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
    expect(locator.subject_id).toBe(user.id);
    expect(locator.recipient_id).toBe(solandServiceId());
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
        invitee_id: fixture.invitee.id,
        invite_delivery_target: {
          account_id: fixture.inviteAddress.account_id,
          service_resolution: fixture.inviteAddress.service_resolution,
        },
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
});
