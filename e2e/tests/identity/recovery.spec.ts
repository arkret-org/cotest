// Account recovery
// Contract: e2e/scenarios/identity/recovery.md
// Spec refs:
//   - identity/key-management.md §3.3 (recovery key + threshold + recovery service)
//   - §7 (key backup), §7.2 (envelope), §7.3 (restore), §8 (threshold)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("account recovery", () => {
  test("backup API surface probe (recovery and key-backup endpoints)", async ({ request }) => {
    const alice = uniqueUser("s8-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // Recovery setup / list endpoints. Either implemented (200) or absent (404).
    const recoveryListResp = await request.get(`${solandBaseUrl()}/api/v1/keys/recovery`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect([200, 401, 404]).toContain(recoveryListResp.status());
  });

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "alice (device-1) configures passphrase-protected backup; envelope uses Argon2id KDF + XChaCha20-Poly1305; key_commitment uploaded",
    async () => {
      // spec: key-management.md §7.1-§7.2
      // soland gap: cx.schema.key_backup.v1; yougen gap: /settings/recovery wizard.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "device-2 restores account using passphrase; SSK/USK recovered; new device authorized via cx.device.authorized with recovery proof",
    async () => {
      // spec: key-management.md §7.3-§7.4, §5.0.1
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "after restore, device-2 syncs E2EE history and decrypts messages sent while device-1 was offline",
    async () => {
      // spec: key-management.md §7.3 step 6, encryption-and-audit.md §2.4
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "E8.4 threshold recovery (3-of-5 shares): client reconstructs recovery key from shares; envelope decrypted; device authorized",
    async () => {
      // spec: key-management.md §8
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "E8.5 trusted recovery service: third-party signs recovery attestation; client gates backup decrypt on attestation validity",
    async () => {
      // spec: key-management.md §3.3 + §8
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "E8.6 mixed_secret_storage=true rejected in high_assurance profile but accepted in personal_node",
    async () => {
      // spec: key-management.md §7.1
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "E8.7 after device-1 revoked, restore still succeeds; historical access honors current membership (not pre-revoke)",
    async () => {
      // spec: key-management.md §12 line 724
    },
  );
});
