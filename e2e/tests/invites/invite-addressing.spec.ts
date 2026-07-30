import { createHash, randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";

import { solandBaseUrl, solandServiceId } from "../../helpers/env";
import type { InviteDeliveryRequestBodyBodyBody } from "../../helpers/soland-api";
import {
  canonicalTimestamp,
  authHeaders,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  typedId,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
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

test.describe("invite addressing", () => {
  test("peer invite delivery defers explicit_address evidence", async ({ request }) => {
    const recipientServiceId = solandServiceId();
    const invitee = "did:web:cotest-invitee.example";
    const introductionEvidence = { kind: "explicit_address" } as const;
    const inviteDeliveryTarget = {
      recipient_service_id: recipientServiceId,
      recipient_service_kind: "principal_server" as const,
    };
    const inviteEvent = signedEventEnvelope({
      actorDid: "did:web:cotest-inviter.example",
      realmId: typedId("realm"),
      kind: "ak.invite.create",
      payload: {
        invite_id: typedId("invite"),
        invitee,
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
          subject_id: invitee,
          ...inviteDeliveryTarget,
        },
        introduction_evidence: introductionEvidence,
        idempotency_key: `cotest-peer-invite-${Date.now()}`,
      },
      {
        origin: "did:web:cotest-source.example",
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
      headers: selfHeaders,
      data: {
        ttl_seconds: 60,
        one_time_use: false,
        display_hint: { display_name_hint: "Cotest locator" },
      },
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
    expect(locator.subject_id).toBe(user.did);
    expect(locator.recipient_service_id).toBe(solandServiceId());
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
      `${solandServiceId()}#notary-key`,
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
      headers: selfHeaders,
      data: {
        ttl_seconds: 120,
        one_time_use: false,
        display_hint: { display_name_hint: "Clear me" },
      },
    });
    expect(oneTimeIssue.status(), await oneTimeIssue.text()).toBe(200);
    const beforeOneTime =
      (await oneTimeIssue.json()) as InviteLocatorIssueOutcome;
    const oneTimeRotate = await request.post(rotateUrl, {
      headers: selfHeaders,
      data: {
        locator_id: beforeOneTime.locator_id,
        ttl_seconds: 60,
        one_time_use: true,
        display_hint: null,
      },
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
});
