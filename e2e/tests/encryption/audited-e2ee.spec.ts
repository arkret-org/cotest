// Moderation franking and the audited-E2EE boundary.
// Contract: e2e/scenarios/encryption/audited-e2ee.md
// Spec: crypto-media/audited-e2ee.md §2/§8, governance/content-moderation.md §3.4

import { createHash } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  advanceEnvelopeToActorFrontier,
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  createRealmApi,
  grantCapabilityEventApi,
  readRealmSealBasis,
  refreshEventEnvelopeProof,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("moderation reports and audited E2EE", () => {
  test.fixme(// @blocking-on: arkret-work/spec-open/2026-08-25-1348-franking-digest-input-contract-uninhabitable
  // @user-promise: legal encrypted messages receive a verifiable local franking proof without plaintext disclosure
  // @expected-live-by: 2026-09-15
  // The moderation spec requires encrypted_content.payload_digest, while the
  // authoritative closed envelope schema forbids that member and the crypto
  // spec explicitly forbids an inline payload_digest. No legal wire Event can
  // currently inhabit the franking input contract.
  "encrypted messages receive a local franking proof without an Audit Applet binding", async ({
    request,
  }) => {
    const setup = await setupEncryptedMessage(request, "s25-frank");

    const events = await queryAuditEvents(
      request,
      setup.aliceToken,
      setup.realmId,
      "ak.moderation.franking_proof",
    );
    const proof = events.find((event) =>
      JSON.stringify(event).includes(String(setup.message.event_id)),
    );
    expect(proof, "franking proof for encrypted message").toBeTruthy();
    const proofText = JSON.stringify(proof);
    expect(proofText).toContain(setup.ciphertextDigest);
    expect(proofText).not.toContain(setup.plaintext);
    expect(proofText).not.toContain("plaintext");
    expect(proofText).not.toContain("audit_disclosure_policy");
    expect(proofText).toContain("proof_digest");

    const verify = await request.post(
      `${solandBaseUrl()}/_soland/self/audit/franking/verify`,
      {
        headers: authHeaders(setup.aliceToken),
        data: (proof as Record<string, unknown>).payload,
      },
    );
    expect(verify.ok(), await verify.text()).toBeTruthy();
  });

  test("ordinary reports stay in the scoped moderation workflow and never create audit-release events", async ({
    request,
  }) => {
    const setup = await setupEncryptedMessage(request, "s25-report");
    const report = await fileModerationReport(request, setup);

    expect(report.status).toBe("submitted");
    expect(report.routed_to).toBeUndefined();

    const localReportEvents = await queryActorAuditEvents(
      request,
      setup.reporterToken,
      "ak.self.moderation.report",
    );
    expect(JSON.stringify(localReportEvents)).toContain(
      report.report_id.replace("ak:report:", "ak:event:"),
    );

    for (const kind of [
      "org.arkret.soland.audit.report",
      "ak.audit.accessed",
      "ak.audit.session.request",
      "ak.audit.session.authorize",
      "ak.audit.release",
    ]) {
      const events = await queryAuditEvents(
        request,
        setup.aliceToken,
        setup.realmId,
        kind,
      );
      expect(
        events,
        `${kind} must not be derived from a moderation report`,
      ).toEqual([]);
    }
  });

  test("tampering with a franking proof ciphertext digest fails verification", async ({
    request,
  }) => {
    const setup = await setupEncryptedMessage(request, "s25-tamper");
    const events = await queryAuditEvents(
      request,
      setup.aliceToken,
      setup.realmId,
      "ak.moderation.franking_proof",
    );
    const proof = events[0]?.payload as Record<string, unknown>;
    expect(proof?.proof_digest).toBeTruthy();

    const verify = await request.post(
      `${solandBaseUrl()}/_soland/self/audit/franking/verify`,
      {
        headers: authHeaders(setup.aliceToken),
        data: {
          ...proof,
          ciphertext_digest:
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
      },
    );
    expect(verify.status()).toBe(409);
    expect(wireErrCode(await verify.json())).toBe("franking_tampered");
  });
});

type EncryptedMessageSetup = {
  aliceToken: string;
  reporterToken: string;
  reporterDid: string;
  realmId: string;
  message: Record<string, unknown>;
  ciphertextDigest: string;
  plaintext: string;
};

async function setupEncryptedMessage(
  request: APIRequestContext,
  label: string,
): Promise<EncryptedMessageSetup> {
  const alice = uniqueUser(`${label}-alice`);
  const bob = uniqueUser(`${label}-bob`);
  const reporter = uniqueUser(`${label}-reporter`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
    ensureRegistered(request, reporter),
  ]);
  const [aliceToken, bobToken, reporterToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
    issueDevSession(request, reporter),
  ]);

  const realmId = await createRealmApi(request, aliceToken, {
    title: `S25 moderation franking ${label} ${Date.now()}`,
    discoverability: "listed",
    history_access: "since_join",
    encryption_profile: "mls_rfc9420",
    plaintext_visible_services: [],
    ownerDid: alice.did,
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  await addRealmMemberApi(request, aliceToken, realmId, reporter.did);
  await grantCapabilityEventApi(request, aliceToken, {
    ownerDid: alice.did,
    realmId,
    subjectDid: bob.did,
    actions: ["ak.message.create"],
  });

  const strandCreatedAt = canonicalTimestamp();
  const strandEvent = signedEventEnvelope({
    actorDid: alice.did,
    realmId,
    kind: "ak.strand.create",
    createdAt: strandCreatedAt,
    payload: {
      object: {
        schema: "ak.schema.strand.v1",
        realm_id: realmId,
        tracks: {
          discussion: {
            enabled: true,
            is_primary: true,
            profile: "discussion",
          },
        },
        created_by: alice.did,
        created_at: strandCreatedAt,
      },
    },
  });
  const strandId = String(strandEvent.event_id).replace(
    /^ak:event:/,
    "ak:strand:",
  );
  await submitSignedEventApi(request, aliceToken, strandEvent, {
    context: "create encrypted moderation Strand",
  });

  const plaintext = `moderation evidence must not leak ${Date.now()}`;
  const ciphertext = Buffer.from(
    `opaque-ciphertext-${label}-${Date.now()}`,
    "utf8",
  ).toString("base64url");
  const encryptedContent = encryptedEnvelope(ciphertext, realmId);
  const message = signedEventEnvelope({
    actorDid: bob.did,
    realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      encrypted_content: encryptedContent,
    },
  });
  await submitSignedEventApi(request, bobToken, message, {
    context: "submit encrypted message with local moderation franking",
  });

  return {
    aliceToken,
    reporterToken,
    reporterDid: reporter.did,
    realmId,
    message,
    ciphertextDigest: `sha256:${createHash("sha256")
      .update(Buffer.from(ciphertext, "base64url"))
      .digest("hex")}`,
    plaintext,
  };
}

async function fileModerationReport(
  request: APIRequestContext,
  setup: EncryptedMessageSetup,
) {
  const reportEvent = signedEventEnvelope({
    actorDid: setup.reporterDid,
    realmId: setup.realmId,
    kind: "ak.self.moderation.report",
    payload: {
      realm_id: setup.realmId,
      target_ref: setup.message.event_id,
      report_reason_code: "harassment",
      reporter: setup.reporterDid,
      provenance: "self",
      description: "ordinary moderation report for scoped administrators",
      evidence_refs: [],
    },
  });
  await advanceEnvelopeToActorFrontier(
    request,
    setup.reporterToken,
    reportEvent,
  );
  const sealBasis = await readRealmSealBasis(
    request,
    setup.reporterToken,
    setup.realmId,
  );
  const sealLeaves = sealBasis.leaves;
  if (!Array.isArray(sealLeaves) || typeof sealLeaves[0] !== "string") {
    throw new Error("moderation report Realm has no accepted Seal reference");
  }
  reportEvent.seal_ref = sealLeaves[0];
  const proof = Array.isArray(reportEvent.proofs)
    ? (reportEvent.proofs[0] as Record<string, unknown> | undefined)
    : undefined;
  const verificationMethod = String(proof?.verification_method ?? "");
  // `auth_context.key_id` is an opaque local key label, not the
  // verification-method fragment itself: strip the typed-id `ak:` sigil
  // (same mapping as `eventAuthContext` in soland-api.ts).
  const keyIdFragment =
    verificationMethod.split("#").at(-1) ?? verificationMethod;
  reportEvent.auth_context = {
    actor_id: setup.reporterDid,
    key_id: keyIdFragment.startsWith("ak:")
      ? keyIdFragment.slice(3)
      : keyIdFragment,
    key_epoch: 0,
  };
  refreshEventEnvelopeProof(reportEvent, verificationMethod);
  const url = `${solandBaseUrl()}/_arkret/self/moderation/report`;
  const response = await request.post(url, {
    headers: {
      ...authHeaders(setup.reporterToken, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({ report_event: { event: reportEvent } }),
  });
  const text = await response.text();
  expect(response.ok(), text).toBeTruthy();
  return JSON.parse(text) as {
    report_id: string;
    status: string;
    routed_to?: string[];
  };
}

async function queryAuditEvents(
  request: APIRequestContext,
  token: string,
  realmId: string,
  kind: string,
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(realmId)}&kind=${encodeURIComponent(kind)}`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.ok(), text).toBeTruthy();
  return (JSON.parse(text).events ?? []) as Array<Record<string, unknown>>;
}

async function queryActorAuditEvents(
  request: APIRequestContext,
  token: string,
  kind: string,
): Promise<Array<Record<string, unknown>>> {
  const response = await request.get(
    `${solandBaseUrl()}/_soland/admin/audit/events?kind=${encodeURIComponent(kind)}`,
    { headers: authHeaders(token) },
  );
  const text = await response.text();
  expect(response.ok(), text).toBeTruthy();
  return (JSON.parse(text).events ?? []) as Array<Record<string, unknown>>;
}

function encryptedEnvelope(
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  void realmId;
  return {
    version: "1.0",
    content_type: "application/vnd.arkret.message+json",
    encryption_context: {
      epoch: 1,
      group_state_ref: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
    },
    ciphertext,
  };
}
