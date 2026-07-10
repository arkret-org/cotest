// Audited E2EE (franking + moderator decryption attestation)
// Contract: e2e/scenarios/encryption/audited-e2ee.md
// Spec: crypto-media/audited-e2ee.md §2-§4, encryption-and-audit.md §3, governance/content-moderation.md §3.4

import { createHash } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";
import { mockAuditAgentBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  resolveDefaultStrandId,
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
      `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=ak:realm:01904100-0000-7000-8000-000000000025`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test(
    "alice configures audit_disclosure_policy on E2EE Realm; ak.moderation.franking_proof generated for each encrypted message (ciphertext_digest only, no plaintext)",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-frank");

      const audit = await request.get(
        `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(setup.realmId)}&kind=ak.moderation.franking_proof`,
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

      const verify = await request.post(`${solandBaseUrl()}/_soland/self/audit/franking/verify`, {
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
      expect(report.status).toBe("submitted");
      expect(report.routed_to).toBeUndefined();

      const inspect = await (await request.get(`${setup.agentBaseUrl}/inspect`)).json();
      expect(JSON.stringify(inspect)).toContain(String(report.report_id));
      expect(JSON.stringify(inspect)).toContain(setup.realmId);

      const invite = await (await request.get(`${setup.agentBaseUrl}/_arkret/self/audit-agent/inbox`)).json();
      expect(JSON.stringify(invite)).toContain(String(report.report_id));
    },
  );

  test(
    "report routing records audit-agent handoff without fabricating a plaintext access release",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-accessed");
      const report = await fileModerationReport(request, setup);

      const routed = await request.get(
        `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(setup.realmId)}&kind=org.arkret.soland.audit.report`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const routedText = await routed.text();
      expect(routed.ok(), routedText).toBeTruthy();
      const routedEvents = (JSON.parse(routedText).events ?? []) as Array<Record<string, unknown>>;
      expect(JSON.stringify(routedEvents)).toContain(setup.agentDid);
      expect(JSON.stringify(routedEvents)).toContain(String(report.report_id));

      const accessed = await request.get(
        `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(setup.realmId)}&kind=ak.audit.accessed`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const accessedText = await accessed.text();
      expect(accessed.ok(), accessedText).toBeTruthy();
      const accessEvents = (JSON.parse(accessedText).events ?? []) as Array<Record<string, unknown>>;
      expect(JSON.stringify(accessEvents)).not.toContain(String(report.report_id));
    },
  );

  test(
    "E25.1 tampered ak.moderation.franking_proof ciphertext_digest causes downstream verification to fail",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-tamper");
      const audit = await request.get(
        `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(setup.realmId)}&kind=ak.moderation.franking_proof`,
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
      const verify = await request.post(`${solandBaseUrl()}/_soland/self/audit/franking/verify`, {
        headers: authHeaders(setup.aliceToken),
        data: tampered,
      });
      expect(verify.status()).toBe(409);
      expect(wireErrCode(await verify.json())).toBe("franking_tampered");
    },
  );

  test(
    "E25.3 alice revokes audit_disclosure_policy; subsequent audit-agent requests are rejected (still leaving historical accessed records intact)",
    async ({ request }) => {
      const setup = await setupAuditedMessage(request, "s25-revoke");

      // 1. With the policy active, a first report invites the audit agent.
      const firstReport = await fileModerationReport(request, setup);
      const inboxBefore = await (
        await request.get(`${setup.agentBaseUrl}/_arkret/self/audit-agent/inbox`)
      ).json();
      expect(JSON.stringify(inboxBefore)).toContain(String(firstReport.report_id));

      // The historical audit.report routing record is durable.
      const historicalRouted = await request.get(
        `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(setup.realmId)}&kind=org.arkret.soland.audit.report`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const historicalRoutedText = await historicalRouted.text();
      expect(historicalRouted.ok(), historicalRoutedText).toBeTruthy();
      expect(JSON.stringify(JSON.parse(historicalRoutedText).events ?? [])).toContain(
        String(firstReport.report_id),
      );

      // 2. Alice (the Realm owner) revokes the audit_disclosure_policy via a
      // ak.realm.update patch that flips `enabled` to false. audited-e2ee.md
      // §3.1: admins MAY suspend / revoke a binding from a new accepted policy
      // frontier onward.
      const revoke = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(setup.aliceToken),
        data: signedEventEnvelope({
          actorDid: setup.aliceDid,
          realmId: setup.realmId,
          kind: "ak.realm.update",
          payload: {
            target_ref: setup.realmId,
            patch: {
              audit_disclosure_policy: {
                $op: "set",
                value: {
                  enabled: false,
                  agent_id: setup.agentDid,
                  agent_url: setup.agentBaseUrl,
                  trigger: "report_filed",
                  assurance: "mock_attested",
                },
              },
            },
          },
        }),
      });
      const revokeText = await revoke.text();
      expect(revoke.ok(), revokeText).toBeTruthy();

      // 3. A fresh report after the revoke MUST NOT reach the audit agent.
      const secondReport = await fileModerationReportForTarget(
        request,
        setup,
        await sendAuditedMessage(request, setup, "post-revoke"),
      );
      const inboxAfter = await (
        await request.get(`${setup.agentBaseUrl}/_arkret/self/audit-agent/inbox`)
      ).json();
      expect(JSON.stringify(inboxAfter)).not.toContain(String(secondReport.report_id));
      // The post-revoke report is never routed to the audit agent DID.
      expect(secondReport.routed_to ?? []).not.toContain(setup.agentDid);

      // 4. The historical accessed / routed records from before the revoke
      // remain intact (revocation is prospective only).
      const routedAfter = await request.get(
        `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(setup.realmId)}&kind=org.arkret.soland.audit.report`,
        { headers: authHeaders(setup.aliceToken) },
      );
      const routedAfterText = await routedAfter.text();
      expect(routedAfter.ok(), routedAfterText).toBeTruthy();
      const routedAfterEvents = JSON.stringify(JSON.parse(routedAfterText).events ?? []);
      expect(routedAfterEvents).toContain(String(firstReport.report_id));
      expect(routedAfterEvents).not.toContain(String(secondReport.report_id));
    },
  );
});

type AuditedSetup = {
  agentBaseUrl: string;
  agentDid: string;
  aliceToken: string;
  aliceDid: string;
  bobToken: string;
  bobDid: string;
  reporterToken: string;
  reporterDid: string;
  realmId: string;
  message: Record<string, unknown>;
  ciphertextDigest: string;
  plaintext: string;
};

async function setupAuditedMessage(request: APIRequestContext, label: string): Promise<AuditedSetup> {
  const agentBaseUrl = mockAuditAgentBaseUrl();
  test.skip(!agentBaseUrl, "mock-audit-agent not started for audited E2EE");
  await request.delete(`${agentBaseUrl}/inspect`);
  const identity = await (await request.get(`${agentBaseUrl}/_arkret/self/audit-agent/identity`)).json();
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

  const realmId = await createRealmApi(request, aliceToken, {
    title: `S25 audited E2EE ${label} ${Date.now()}`,
    discoverability: "listed",
    history_visibility: "joined",
    encryption_profile: "mls_rfc9420",
    plaintext_visible_services: [],
    ownerDid: alice.did,
    audit_disclosure_policy: {
      enabled: true,
      agent_id: agentDid,
      agent_url: agentBaseUrl,
      trigger: "report_filed",
      assurance: "mock_attested",
    },
  });
  await addRealmMemberApi(request, aliceToken, realmId, bob.did);
  await addRealmMemberApi(request, aliceToken, realmId, reporter.did);

  const plaintext = `audited plaintext must not leak ${Date.now()}`;
  const ciphertext = Buffer.from(`opaque-ciphertext-${label}-${Date.now()}`, "utf8").toString(
    "base64url",
  );
  const strandId = await resolveDefaultStrandId(request, bobToken, realmId);
  const encryptedContent = encryptedEnvelope("ak.message.v1", ciphertext, realmId);
  const message = signedEventEnvelope({
    actorDid: bob.did,
    realmId: realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      encrypted_content: encryptedContent,
    },
  });
  await submitSignedEventApi(request, bobToken, message, {
    context: "submit audited encrypted message",
  });

  return {
    // Present by the `test.skip(!agentBaseUrl, ...)` guard above.
    agentBaseUrl: agentBaseUrl!,
    agentDid,
    aliceToken,
    aliceDid: alice.did,
    bobToken,
    bobDid: bob.did,
    reporterToken,
    reporterDid: reporter.did,
    realmId,
    message,
    ciphertextDigest: String(encryptedContent.payload_digest),
    plaintext,
  };
}

// Sends a second encrypted message into the audited Realm (e.g. after a policy
// revoke) and returns its event_id so a fresh report can target it.
async function sendAuditedMessage(
  request: APIRequestContext,
  setup: AuditedSetup,
  label: string,
): Promise<string> {
  const ciphertext = Buffer.from(
    `opaque-ciphertext-${label}-${Date.now()}`,
    "utf8",
  ).toString("base64url");
  const strandId = await resolveDefaultStrandId(
    request,
    setup.bobToken,
    setup.realmId,
  );
  const encryptedContent = encryptedEnvelope("ak.message.v1", ciphertext, setup.realmId);
  const message = signedEventEnvelope({
    actorDid: setup.bobDid,
    realmId: setup.realmId,
    kind: "ak.message.create",
    payload: {
      strand_id: strandId,
      track_name: "discussion",
      encrypted_content: encryptedContent,
    },
  });
  await submitSignedEventApi(request, setup.bobToken, message, {
    context: `submit ${label} audited encrypted message`,
  });
  return String(message.event_id);
}

// Files a moderation report against an explicit target_ref (rather than the
// setup's default message) so a test can report a post-revoke message.
async function fileModerationReportForTarget(
  request: APIRequestContext,
  setup: AuditedSetup,
  targetRef: string,
) {
  const response = await request.post(`${solandBaseUrl()}/_arkret/self/moderation/report`, {
    headers: authHeaders(setup.reporterToken),
    data: {
      realm_id: setup.realmId,
      target_ref: targetRef,
      report_reason_code: "harassment",
      reporter: setup.reporterDid,
      description: "post-revoke report must not reach the audit agent",
      evidence_refs: [],
    },
  });
  const text = await response.text();
  expect(response.ok(), text).toBeTruthy();
  return JSON.parse(text) as {
    report_id: string;
    status: string;
    routed_to?: string[];
  };
}

async function fileModerationReport(request: APIRequestContext, setup: AuditedSetup) {
  const response = await request.post(`${solandBaseUrl()}/_arkret/self/moderation/report`, {
    headers: authHeaders(setup.reporterToken),
    data: {
      realm_id: setup.realmId,
      target_ref: setup.message.event_id,
      report_reason_code: "harassment",
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
    routed_to?: string[];
  };
}

function encryptedEnvelope(
  contentType: string,
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  void contentType;
  const aad = { realm_id: realmId, event_kind: "ak.message.create" };
  const payloadMetadata = {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.arkret.message+json",
    aad_visibility_event_id: "hidden",
    aad,
    key_ref: {
      algorithm: "MLS",
      group_state_ref: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
  return {
    ...payloadMetadata,
    ciphertext,
    aad_digest: sha256Digest(canonicalJson(aad)),
    payload_digest: encryptedPayloadDigest(payloadMetadata, ciphertext),
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function encryptedPayloadDigest(metadata: Record<string, unknown>, ciphertext: string): string {
  const hash = createHash("sha256");
  hash.update(Buffer.from(canonicalJson(metadata), "utf8"));
  hash.update(Buffer.from(ciphertext, "base64url"));
  return `sha256:${hash.digest("hex")}`;
}
