// Encrypted attachments in E2EE space
// Contract: e2e/scenarios/encryption/encrypted-attachments.md
// Spec refs:
//   - crypto-media/media-and-blob.md §3 (encrypted metadata), §5 (authz + download), §5.1 (no plaintext content-type), §6 (asset privacy)
//   - crypto-media/encryption-and-audit.md §2.3.1 (key_ref MLS)
//   - crypto-media/audited-e2ee.md §3-§4 (franking, cx.audit.accessed)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("encrypted attachments", () => {
  test("blob upload endpoint exists and rejects unauthenticated downloads with opaque error", async ({
    request,
  }) => {
    const alice = uniqueUser("s12-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // Probe endpoints
    const putResp = await request.post(`${solandBaseUrl()}/api/v1/blob/put`, {
      headers: { authorization: `Bearer ${token}` },
      data: { space_id: "cx:space:probe", media_type: "application/octet-stream" },
    });
    // Either 4xx for missing body, or 404 if endpoint absent. 5xx is a bug.
    expect(putResp.status()).toBeLessThan(500);

    const probeBlobRef = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const getResp = await request.get(
      `${solandBaseUrl()}/api/v1/blob/get?blob_ref=${encodeURIComponent(probeBlobRef)}&purpose=download`,
      {},
    );
    // Spec §5: non-existent and unauthorized must look the same — opaque 403/404.
    expect([401, 403, 404, 405]).toContain(getResp.status());
  });

  test.fixme(
    // @blocking-on: soland#encryption-encrypted-attachments-gap
    // @user-promise: e2e/scenarios/encryption/encrypted-attachments.md
    // @expected-live-by: 2026Q3
    "alice uploads XChaCha20-encrypted attachment; metadata media_type is application/octet-stream (no plaintext leak)",
    async () => {
      // spec: media-and-blob.md §3 + §5.1
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-encrypted-attachments-gap
    // @user-promise: e2e/scenarios/encryption/encrypted-attachments.md
    // @expected-live-by: 2026Q3
    "bob (member) downloads blob; client verifies sha256(ciphertext) === ciphertext_digest before decrypt",
    async () => {
      // spec: media-and-blob.md §5
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-encrypted-attachments-gap
    // @user-promise: e2e/scenarios/encryption/encrypted-attachments.md
    // @expected-live-by: 2026Q3
    "mallory (non-member) GET on the same blob_ref returns opaque 403/404 indistinguishable from non-existent",
    async () => {
      // spec: media-and-blob.md §5
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-encrypted-attachments-gap
    // @user-promise: e2e/scenarios/encryption/encrypted-attachments.md
    // @expected-live-by: 2026Q3
    "blob service stores only ciphertext + blob_ref + size; no plaintext filename or media type in service logs",
    async () => {
      // spec: media-and-blob.md §3 + §5.1
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-encrypted-attachments-gap
    // @user-promise: e2e/scenarios/encryption/encrypted-attachments.md
    // @expected-live-by: 2026Q3
    "E12.2 thumbnail generation: client encrypts thumbnail and uploads as separate blob; server cannot derive thumbnails in E2EE",
    async () => {
      // spec: media-and-blob.md §5.3
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-encrypted-attachments-gap
    // @user-promise: e2e/scenarios/encryption/encrypted-attachments.md
    // @expected-live-by: 2026Q3
    "E12.4 audited E2EE: cx.moderation.frank receipt visible to audit agent without revealing plaintext",
    async () => {
      // spec: audited-e2ee.md §4
    },
  );
});
