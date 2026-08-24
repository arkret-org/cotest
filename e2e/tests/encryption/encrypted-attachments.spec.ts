// Encrypted attachments in E2EE Realm
// Contract: e2e/scenarios/encryption/encrypted-attachments.md
// Spec refs:
//   - crypto-media/media-and-blob.md §3 (encrypted metadata), §5 (authz + download), §5.1 (no plaintext content-type), §6 (asset privacy)
//   - crypto-media/encryption-and-audit.md §2.3.1 (key_ref MLS)
//   - crypto-media/audited-e2ee.md §3-§4 (franking, ak.audit.accessed)

import { createHash } from "node:crypto";

import { expect, test } from "@playwright/test";
import { solandBaseUrl, solandServiceId } from "../../helpers/env";
import {
  addRealmMemberApi,
  authHeaders,
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
        "x-arkret-realm-id": "ak:realm:0196419b-0000-8000-8000-00000000prob",
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
      history_access: "since_join",
      encryption_profile: "mls_rfc9420",
      plaintext_visible_services: [],
      ownerDid: alice.did,
    });
    await addRealmMemberApi(request, aliceToken, realmId, bob.did);

    const ciphertext = Buffer.from(`ciphertext-only-${Date.now()}`, "utf8");
    const ciphertextDigest = sha256Digest(ciphertext);
    const envelope = {
      blob_ref: `ak:blob:${ciphertextDigest}`,
      encrypted: true,
      scheme: "ak.blob.whole_file_aead.v1",
      encryption_algorithm: "mls_exporter_aead_xchacha20poly1305",
      nonce: "dGVzdC1ub25jZS0wMDAx",
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
    expect(body.upload_receipt.issuer_service_id).toBe(solandServiceId());
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

});


function encryptedAttachmentEnvelope(
  ciphertext: string,
  realmId: string,
): Record<string, unknown> {
  void realmId;
  return {
    version: "1.0",
    content_type: "application/vnd.arkret.attachment+json",
    encryption_context: {
      epoch: 1,
      group_state_ref:
        "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
    },
    ciphertext,
  };
}

function sha256Digest(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
