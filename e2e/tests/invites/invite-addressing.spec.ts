import { expect, test } from "@playwright/test";

import { solandBaseUrl, solandServiceDid } from "../../helpers/env";
import {
  canonicalTimestamp,
  sha256CanonicalJson,
  signedEventEnvelope,
  submitPeerInviteDeliveryApi,
  typedId,
} from "../../helpers/soland-api";

test.describe("invite addressing", () => {
  test("peer invite delivery defers explicit_address evidence", async ({ request }) => {
    const recipientServiceDid = solandServiceDid();
    const invitee = "did:web:cotest-invitee.example";
    const introductionEvidence = { kind: "explicit_address" };
    const inviteDeliveryTarget = {
      recipient_service_did: recipientServiceDid,
      recipient_service_type: "principal_server" as const,
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
        invite_event: inviteEvent,
        invite_address: {
          subject_id: invitee,
          ...inviteDeliveryTarget,
        },
        introduction_evidence: introductionEvidence,
        idempotency_key: `cotest-peer-invite-${Date.now()}`,
      },
      {
        origin: "did:web:cotest-source.example",
        destination: recipientServiceDid,
      },
    );

    expect(outcome.status).toBe("deferred");
    expect(outcome.received_at).toMatch(/Z$/);
    expect(outcome.received_at).not.toContain(".");
  });

  test("invite locator resolve is body-only", async ({ request }) => {
    const locatorToken = Buffer.from(
      JSON.stringify({
        subject_id: "did:web:locator-subject.example",
        nonce: Buffer.from(`cotest-locator-nonce-${Date.now()}`).toString("base64url"),
        expires_at: canonicalTimestamp(new Date(Date.now() + 15 * 60 * 1000)),
      }),
      "utf8",
    ).toString("base64url");

    const ok = await request.post(
      `${solandBaseUrl()}/_arkret/open/invite-locators/resolve`,
      { data: { locator_token: locatorToken } },
    );
    expect(ok.status(), await ok.text()).toBe(200);
    const locator = await ok.json();
    expect(locator.schema).toBe("ak.schema.principal_locator.v1");
    expect(locator.subject_id).toBe("did:web:locator-subject.example");
    expect(locator.recipient_service_did).toBe(solandServiceDid());
    expect(locator.issued_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(locator.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(locator.locator_ref_digest).toMatch(/^sha256:/);
    expect(locator.proofs?.[0]?.proof_purpose).toBe("recipient_service_acceptance");
    expect(locator.proofs?.[0]?.proof?.created_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
    );

    const queryLeak = await request.post(
      `${solandBaseUrl()}/_arkret/open/invite-locators/resolve?locator_token=${encodeURIComponent(locatorToken)}`,
      { data: { locator_token: locatorToken } },
    );
    expect(queryLeak.status()).toBe(400);
  });
});
