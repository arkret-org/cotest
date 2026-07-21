// Encrypted attachments in E2EE Realm
// Contract: e2e/scenarios/encryption/encrypted-attachments.md
// Spec refs:
//   - crypto-media/media-and-blob.md §3 (encrypted metadata), §5 (authz + download), §5.1 (no plaintext content-type), §6 (asset privacy)
//   - crypto-media/encryption-and-audit.md §2.3.1 (key_ref MLS)
//   - crypto-media/audited-e2ee.md §3-§4 (franking, ak.audit.accessed)

import { createHash, randomUUID } from "node:crypto";

import { expect, test } from "@playwright/test";
import {
  mockAuditAgentBaseUrl,
  solandBaseUrl,
  solandServiceId,
} from "../../helpers/env";
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

test.describe("encrypted attachments", () => {
  test("blob upload endpoint exists and rejects unauthenticated downloads with opaque error", async ({
    request,
  }) => {
    const uploadResp = await request.post(`${solandBaseUrl()}/_arkret/self/blob/upload`, {
      headers: {
        "x-arkret-realm-id": "ak:realm:0196419b-0000-7000-8000-00000000prob",
        "x-arkret-content-digest":
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      multipart: {
        content: {
          name: "empty.bin",
          mimeType: "application/octet-stream",
          buffer: Buffer.alloc(0),
        },
        size_bytes: "0",
      },
    });
    expect(uploadResp.status()).toBe(401);
    expect(wireErrCode(await uploadResp.json())).toBe("unauthenticated");

    const probeBlobRef = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const getResp = await request.get(
      `${solandBaseUrl()}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(probeBlobRef)}&purpose=download`,
      {},
    );
    // Spec §5: non-existent and unauthorized must look the same — opaque 403/404.
    expect([401, 403, 404, 405]).toContain(getResp.status());
  });

  test("alice uploads encrypted attachment; members download ciphertext and non-members get opaque not_found", async ({
    request,
  }) => {
    const alice = uniqueUser("s12-alice");
    const bob = uniqueUser("s12-bob");
    const mallory = uniqueUser("s12-mallory");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, mallory),
    ]);
    const [aliceToken, bobToken, malloryToken] = await Promise.all([
      issueDevSession(request, alice),
      issueDevSession(request, bob),
      issueDevSession(request, mallory),
    ]);

    const realmId = await createRealmApi(request, aliceToken, {
      title: `S12 encrypted attachments ${Date.now()}`,
      discoverability: "listed",
      history_visibility: "joined",
      encryption_profile: "mls_rfc9420",
      plaintext_visible_services: [],
      ownerDid: alice.did,
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);

    const ciphertext = Buffer.from(`ciphertext-only-${Date.now()}`, "utf8");
    const ciphertextDigest = sha256Digest(ciphertext);
    const envelope = {
      encrypted: true,
      scheme: "ak.blob.whole_file_aead.v1",
      alg: "mls_exporter_aead_xchacha20poly1305",
      nonce: "test-nonce",
      key_ref: {
        algorithm: "MLS",
        group_state_ref: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      },
      epoch: 1,
      ciphertext_digest: ciphertextDigest,
      size_bytes: ciphertext.length,
      media_type: "application/octet-stream",
    };

    const upload = await request.post(`${solandBaseUrl()}/_arkret/self/blob/upload`, {
      headers: {
        ...authHeaders(aliceToken),
        "x-arkret-filename": "cat.png",
        "x-arkret-realm-id": realmId,
        "x-arkret-blob-encrypted": "true",
        "x-arkret-attachment-envelope": JSON.stringify(envelope),
        "x-arkret-content-digest": ciphertextDigest,
      },
      multipart: {
        content: {
          name: "cat.png",
          mimeType: "image/png",
          buffer: ciphertext,
        },
        size_bytes: String(ciphertext.length),
      },
    });
    const uploadText = await upload.text();
    expect(upload.ok(), uploadText).toBeTruthy();
    const body = JSON.parse(uploadText);
    expect(body.media_type).toBe("application/octet-stream");
    expect(body.size_bytes).toBe(ciphertext.length);
    expect(body.content_digest).toBe(ciphertextDigest);
    expect(body.upload_receipt.blob_ref).toBe(body.blob_ref);
    expect(body.upload_receipt.content_digest).toBe(ciphertextDigest);
    expect(body.upload_receipt.size_bytes).toBe(ciphertext.length);
    expect(body.upload_receipt.issuer_service_id).toMatch(/^did:/);
    expect(body.upload_receipt.signature).toBeTruthy();
    expect(JSON.stringify(body.upload_receipt)).not.toContain("cat.png");
    expect(JSON.stringify(body.upload_receipt)).not.toContain("image/png");
    expect(JSON.stringify(body.upload_receipt)).not.toContain("ciphertext_digest");

    const bobDownload = await request.get(
      `${solandBaseUrl()}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(body.blob_ref)}&purpose=message_attachment`,
      { headers: authHeaders(bobToken) },
    );
    if (!bobDownload.ok()) {
      throw new Error(`bob blob download returned ${bobDownload.status()}: ${await bobDownload.text()}`);
    }
    expect((bobDownload.headers()["content-type"] ?? "").toLowerCase()).toContain(
      "application/octet-stream",
    );
    expect((bobDownload.headers()["cache-control"] ?? "").toLowerCase()).toContain(
      "private",
    );
    const bobBytes = await bobDownload.body();
    expect(Buffer.compare(bobBytes, ciphertext)).toBe(0);
    expect(sha256Digest(bobBytes)).toBe(ciphertextDigest);

    const presign = await request.post(`${solandBaseUrl()}/_arkret/self/blob/presign`, {
      headers: authHeaders(aliceToken),
      data: { blob_ref: body.blob_ref, purpose: "message_attachment" },
    });
    expect(presign.status()).toBe(403);
    expect(wireErrCode(await presign.json())).toBe("capability_denied");

    const malloryDownload = await request.get(
      `${solandBaseUrl()}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(body.blob_ref)}&purpose=message_attachment`,
      { headers: authHeaders(malloryToken) },
    );
    expect(malloryDownload.status()).toBe(404);
    expect(malloryDownload.headers()["accept-ranges"]).toBeUndefined();
    const denied = await malloryDownload.json();
    expect(wireErrCode(denied)).toBe("not_found");
    const deniedText = JSON.stringify(denied);
    expect(deniedText).not.toContain(realmId);
    expect(deniedText).not.toContain(body.blob_ref);

    const missing = await request.get(
      `${solandBaseUrl()}/_arkret/self/blob/get?blob_ref=${encodeURIComponent(
        "ak:blob:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      )}&purpose=message_attachment`,
      { headers: authHeaders(malloryToken) },
    );
    expect(missing.status()).toBe(malloryDownload.status());
    expect(wireErrCode(await missing.json())).toBe("not_found");
  });

  test.fixme("E12.4 audited E2EE: ak.moderation.franking_proof receipt visible to audit agent without revealing plaintext", async ({
    request,
  }) => {
    // spec: audited-e2ee.md §4 / §8 — a report carries the optional
    // ak.moderation.franking_proof to the bound audit agent; the agent sees
    // the receipt (ciphertext_digest / routing metadata) but never the
    // attachment plaintext or its plaintext digest.
    const agentBaseUrl = mockAuditAgentBaseUrl();
    test.skip(!agentBaseUrl, "mock-audit-agent not started for audited E2EE");
    await request.delete(`${agentBaseUrl}/inspect`);
    const identity = await (
      await request.get(`${agentBaseUrl}/_arkret/self/audit-agent/identity`)
    ).json();
    const agentDid = String(identity.did);

    const alice = uniqueUser("s12-frank-alice");
    const bob = uniqueUser("s12-frank-bob");
    const reporter = uniqueUser("s12-frank-reporter");
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
      title: `S12 audited attachment franking ${Date.now()}`,
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

    // Bob sends an encrypted attachment message. The plaintext (filename /
    // body) is never sent to soland — only ciphertext + digests.
    const secretPlaintext = `secret-attachment-plaintext-${Date.now()}`;
    const secretFilename = `secret-${Date.now()}.bin`;
    const ciphertext = Buffer.from(
      `opaque-attachment-ciphertext-${Date.now()}`,
      "utf8",
    ).toString("base64url");
    const encryptedContent = encryptedAttachmentEnvelope(ciphertext, realmId);
    const ciphertextDigest = String(encryptedContent.payload_digest);
    const aadDigest = String(encryptedContent.aad_digest);
    const strandId = await resolveDefaultStrandId(request, bobToken, realmId);
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
      context: "submit audited encrypted attachment message",
    });
    const eventId = String(message.event_id);

    // The reporter files a report carrying a franking_proof receipt that
    // commits to the ciphertext / routing metadata — not the plaintext.
    const frankingProof = {
      kind: "ak.moderation.franking_proof",
      franking_proof_id: `ak:franking_proof:${randomUUID()}`,
      realm_id: realmId,
      event_id: eventId,
      routing_metadata_digest: sha256HexDigest(`routing-${eventId}`),
      ciphertext_digest: ciphertextDigest,
      aad_digest: aadDigest,
      sender_claim: {
        actor_id: bob.did,
        device_id: bob.deviceId,
        mls_group_id_digest: sha256HexDigest(`mls-group-${realmId}`),
      },
      received_by: solandServiceId(),
      received_at: new Date().toISOString(),
      replay_nonce: Buffer.from(randomUUID()).toString("base64url"),
      signature: "mock-attested-franking-signature",
    };

    const report = await request.post(
      `${solandBaseUrl()}/_arkret/self/moderation/report`,
      {
        headers: authHeaders(reporterToken),
        data: {
          realm_id: realmId,
          target_ref: eventId,
          report_reason_code: "harassment",
          reporter: reporter.did,
          description: "encrypted attachment report with franking proof",
          evidence_refs: [],
          franking_proof: frankingProof,
        },
      },
    );
    const reportText = await report.text();
    expect(report.ok(), reportText).toBeTruthy();
    const reportId = String(JSON.parse(reportText).report_id);

    // The bound audit agent receives the report (and its franking_proof)
    // in its inbox.
    const inbox = await (
      await request.get(`${agentBaseUrl}/_arkret/self/audit-agent/inbox`)
    ).json();
    const inboxText = JSON.stringify(inbox);
    expect(inboxText).toContain(reportId);
    // The franking receipt's commitments are visible to the audit agent.
    expect(inboxText).toContain(ciphertextDigest);
    expect(inboxText).toContain(frankingProof.franking_proof_id);
    // ...but no plaintext, filename, or plaintext digest is revealed.
    expect(inboxText).not.toContain(secretPlaintext);
    expect(inboxText).not.toContain(secretFilename);
    expect(inboxText).not.toContain("plaintext_digest");
    expect(inboxText).not.toContain(ciphertext);

    // The franking receipt is independently verifiable via the audit surface
    // without disclosing plaintext.
    const audit = await request.get(
      `${solandBaseUrl()}/_soland/admin/audit/events?realm_id=${encodeURIComponent(realmId)}&kind=org.arkret.soland.audit.report`,
      { headers: authHeaders(aliceToken) },
    );
    const auditText = await audit.text();
    expect(audit.ok(), auditText).toBeTruthy();
    const auditEvents = JSON.stringify(JSON.parse(auditText).events ?? []);
    expect(auditEvents).toContain(reportId);
    expect(auditEvents).not.toContain(secretPlaintext);
  });
});

function sha256HexDigest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function encryptedAttachmentEnvelope(
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  const aad = { realm_id: realmId, event_kind: "ak.message.create" };
  const payloadMetadata = {
    scheme: "mls-rfc9420",
    version: "1.0",
    group_id: "mls_test",
    epoch: 1,
    content_type: "application/vnd.arkret.attachment+json",
    aad_visibility_event_id: "hidden",
    aad,
    key_ref: {
      algorithm: "MLS",
      group_state_ref:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
  const aadDigest = `sha256:${createHash("sha256")
    .update(canonicalJson(aad))
    .digest("hex")}`;
  const payloadHash = createHash("sha256");
  payloadHash.update(Buffer.from(canonicalJson(payloadMetadata), "utf8"));
  payloadHash.update(Buffer.from(ciphertext, "base64url"));
  return {
    ...payloadMetadata,
    ciphertext,
    aad_digest: aadDigest,
    payload_digest: `sha256:${payloadHash.digest("hex")}`,
  };
}

function sha256Digest(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
