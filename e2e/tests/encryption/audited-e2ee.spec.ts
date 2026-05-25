// Audited E2EE (franking + moderator decryption attestation)
// Contract: e2e/scenarios/encryption/audited-e2ee.md
// Spec: crypto-media/audited-e2ee.md §2-§4, encryption-and-audit.md §3, governance/content-moderation.md §3.4

import { createHash } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";
import { mockAuditAgentBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  addSpaceMemberApi,
  authHeaders,
  createSpaceApi,
  flowIdFromRealmId,
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

test.describe("audited E2EE", () => {
  test("audit events endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s25-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const probe = await request.get(
      `${solandBaseUrl()}/api/v1/audit/events?space_id=cx:space:probe`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test(
    "alice configures audit_disclosure_policy on E2EE space; cx.moderation.franking_proof generated for each encrypted message (ciphertext_digest only, no plaintext)",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-frank");

      const audit = await request.get(
        `${solandBaseUrl()}/api/v1/audit/events?space_id=${encodeURIComponent(setup.spaceId)}&kind=cx.moderation.franking_proof`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const auditText = await audit.text();
      expect(audit.ok(), auditText).toBeTruthy();
      const events = (JSON.parse(auditText).events ?? []) as Array<Record<string, unknown>>;
      const proof = events.find((event) =>
        JSON.stringify(event).includes(String(setup.message.event_id)),
      );
      expect(proof, "franking proof for encrypted message").toBeTruthy();
      const proofText = JSON.stringify(proof);
      expect(proofText).toContain(setup.ciphertextDigest);
      expect(proofText).not.toContain(setup.plaintext);
      expect(proofText).not.toContain("plaintext");
      expect(proofText).toContain("proof_digest");

      const verify = await request.post(`${solandBaseUrl()}/api/v1/audit/franking/verify`, {
        headers: authHeaders(setup.aliceToken),
        data: (proof as Record<string, unknown>).payload,
      });
      expect(verify.ok(), await verify.text()).toBeTruthy();
    },
  );

  test(
    "report on a message triggers audit_disclosure_policy.trigger; audit-agent is invited to access via attested ceremony",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-report");
      const report = await fileModerationReport(request, setup);
      expect(report.status).toBe("queued");
      expect(report.routed_to).toContain(setup.agentDid);

      const inspect = await (await request.get(`${setup.agentBaseUrl}/inspect`)).json();
      expect(JSON.stringify(inspect)).toContain(String(report.report_id));
      expect(JSON.stringify(inspect)).toContain(setup.spaceId);

      const invite = await (await request.get(`${setup.agentBaseUrl}/api/v1/audit-agent/inbox`)).json();
      expect(JSON.stringify(invite)).toContain(String(report.report_id));
    },
  );

  test(
    "audit-agent's access writes cx.audit.accessed entry; alice in space-admin/audit sees the access record",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-accessed");
      const report = await fileModerationReport(request, setup);

      const accessed = await request.get(
        `${solandBaseUrl()}/api/v1/audit/events?space_id=${encodeURIComponent(setup.spaceId)}&kind=cx.audit.accessed`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const accessedText = await accessed.text();
      expect(accessed.ok(), accessedText).toBeTruthy();
      const events = (JSON.parse(accessedText).events ?? []) as Array<Record<string, unknown>>;
      expect(JSON.stringify(events)).toContain(setup.agentDid);
      expect(JSON.stringify(events)).toContain(String(report.report_id));
      expect(JSON.stringify(events)).toContain("e2ee_plaintext_release");
    },
  );

  test(
    "E25.1 tampered cx.moderation.franking_proof ciphertext_digest causes downstream verification to fail",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-tamper");
      const audit = await request.get(
        `${solandBaseUrl()}/api/v1/audit/events?space_id=${encodeURIComponent(setup.spaceId)}&kind=cx.moderation.franking_proof`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const auditText = await audit.text();
      expect(audit.ok(), auditText).toBeTruthy();
      const proof = (JSON.parse(auditText).events ?? [])[0]?.payload as Record<string, unknown>;
      expect(proof?.proof_digest).toBeTruthy();
      const tampered = {
        ...proof,
        ciphertext_digest:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      };
      const verify = await request.post(`${solandBaseUrl()}/api/v1/audit/franking/verify`, {
        headers: authHeaders(setup.aliceToken),
        data: tampered,
      });
      expect(verify.status()).toBe(409);
      expect(wireErrCode(await verify.json())).toBe("franking_tampered");
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-audited-e2ee-gap
    // @user-promise: e2e/scenarios/encryption/audited-e2ee.md
    // @expected-live-by: 2026Q3
    "E25.3 alice revokes audit_disclosure_policy; subsequent audit-agent requests are rejected (still leaving historical accessed records intact)",
    async () => {},
  );
});

type AuditedSetup = {
  agentBaseUrl: string;
  agentDid: string;
  aliceToken: string;
  reporterToken: string;
  reporterDid: string;
  spaceId: string;
  message: Record<string, unknown>;
  ciphertextDigest: string;
  plaintext: string;
};

async function setupAuditedMessage(request: APIRequestContext, label: string): Promise<AuditedSetup> {
  const agentBaseUrl = mockAuditAgentBaseUrl();
  test.skip(!agentBaseUrl, "mock-audit-agent not started for audited E2EE");
  await request.delete(`${agentBaseUrl}/inspect`);
  const identity = await (await request.get(`${agentBaseUrl}/api/v1/audit-agent/identity`)).json();
  const agentDid = String(identity.did);

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

  const spaceId = await createSpaceApi(request, aliceToken, {
    title: `S25 audited E2EE ${label} ${Date.now()}`,
    discoverability: "listed",
    history_visibility: "joined",
    encryption_profile: "mls_rfc9420",
    plaintext_visible_services: [],
    ownerDid: alice.did,
    audit_disclosure_policy: {
      enabled: true,
      agent_did: agentDid,
      agent_url: agentBaseUrl,
      trigger: "report_filed",
      assurance: "mock_attested",
    },
  });
  await addSpaceMemberApi(request, aliceToken, spaceId, bob.did);
  await addSpaceMemberApi(request, aliceToken, spaceId, reporter.did);

  const plaintext = `audited plaintext must not leak ${Date.now()}`;
  const ciphertext = `opaque-ciphertext-${label}-${Date.now()}`;
  const ciphertextDigest = sha256Digest(ciphertext);
  const message = signedEventEnvelope({
    actorDid: bob.did,
    realmId: spaceId,
    kind: "cx.message.create",
    payload: {
      flow_id: flowIdFromRealmId(spaceId),
      track: "discussion",
      encrypted: true,
      encrypted_payload: encryptedEnvelope("cx.message.v1", ciphertext, spaceId, ciphertextDigest),
    },
  });
  await submitSignedEventApi(request, bobToken, message, {
    context: "submit audited encrypted message",
  });

  return {
    agentBaseUrl,
    agentDid,
    aliceToken,
    reporterToken,
    reporterDid: reporter.did,
    spaceId,
    message,
    ciphertextDigest,
    plaintext,
  };
}

async function fileModerationReport(request: APIRequestContext, setup: AuditedSetup) {
  const response = await request.post(`${solandBaseUrl()}/api/v1/moderation/report`, {
    headers: authHeaders(setup.reporterToken),
    data: {
      space_id: setup.spaceId,
      target_ref: setup.message.event_id,
      reason: "harassment",
      reporter: setup.reporterDid,
      description: "moderation report should trigger audit disclosure",
      evidence_refs: [],
    },
  });
  const text = await response.text();
  expect(response.ok(), text).toBeTruthy();
  return JSON.parse(text) as {
    report_id: string;
    status: string;
    routed_to: string[];
  };
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
  ciphertextDigest: string,
): Record<string, unknown> {
  return {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.contrix.message+json",
    ciphertext,
    authentication_tag: "opaque-tag",
    aad_visibility_event_id: "hidden",
    aad: { suite: "test", content_type: contentType, realm_id: realmId, event_kind: "cx.message.create" },
    key_ref: {
      algorithm: "MLS",
      group_state_ref: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
    aad_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    payload_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    digests: {
      ciphertext: ciphertextDigest,
    },
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
