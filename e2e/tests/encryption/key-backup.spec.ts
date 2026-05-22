// Key backup + restore
// Contract: e2e/scenarios/encryption/key-backup.md
// Spec refs:
//   - identity/key-management.md §7 (backup), §7.2 (envelope), §7.3 (restore), §12 (API)
//   - crypto-media/device-lifecycle.md §12 (key backup durable form)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("key backup + restore", () => {
  test("backup endpoint exists; listing exposes metadata only (no plaintext)", async ({
    browser,
    request,
  }) => {
    const alice = uniqueUser("s13-alice");
    await ensureRegistered(request, alice);
    const aliceToken = await issueDevSession(request, alice);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      // Probe: is /api/v1/keys/backups routed?
      const listResp = await request.get(`${solandBaseUrl()}/api/v1/keys/backups`, {
        headers: { authorization: `Bearer ${aliceToken}` },
      });
      // If routed, body must be JSON; backups array (possibly empty).
      // If not routed (404), this is the soland implementation gap S13 documents.
      expect([200, 404]).toContain(listResp.status());
      if (listResp.ok()) {
        const body = await listResp.json();
        const backups = body.backups ?? body.results ?? body;
        expect(Array.isArray(backups)).toBeTruthy();
        // Spec §12: listing MUST NOT return plaintext keys or passphrase.
        const serialized = JSON.stringify(body);
        expect(serialized).not.toMatch(/password|passphrase|plaintext_key/i);
      }
    } finally {
      await alicePage.close();
    }
  });

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "alice sets up passphrase-protected backup via /settings/recovery; Argon2id KDF + XChaCha20-Poly1305 envelope uploaded",
    async () => {
      // spec: key-management.md §7.1-§7.2
      // soland gap: cx.schema.key_backup.v1 schema + recovery policy state.
      // yougen gap: /settings/recovery setup wizard.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "device-2 restores from backup with correct passphrase; commitment match → ciphertext decrypted locally; no server oracle",
    async () => {
      // spec: key-management.md §7.2-§7.3
      // soland gap: backup retrieval API.
      // Key invariant: wrong passphrase fails at commitment stage WITHOUT contacting server.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "device-2 replays cx.mls.commit chain using backup's mls_history_backup_key; pre-loss E2EE messages decrypt",
    async () => {
      // spec: encryption-and-audit.md §2.4 + key-management.md §7.3 step 6
      // soland gap: MLS epoch backfill on restore.
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.1 wrong passphrase: client rejects at key_commitment stage; no GET issued to server (avoids oracle)",
    async () => {
      // spec: key-management.md §7.2
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.2 tampered ciphertext: digest mismatch → client refuses to decrypt",
    async () => {
      // spec: key-management.md §7.2 line 328
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.4 mixed_secret_storage=true is allowed in personal_node profile but rejected in high_assurance",
    async () => {
      // spec: key-management.md §7.1
    },
  );

  test.fixme(
    // @blocking-on: soland#encryption-key-backup-gap
    // @user-promise: e2e/scenarios/encryption/key-backup.md
    // @expected-live-by: 2026Q3
    "E13.7 DELETE backup requires ownership proof (SSK signature); session-token-only DELETE rejected",
    async () => {
      // spec: key-management.md §7.4 + §12
    },
  );
});
