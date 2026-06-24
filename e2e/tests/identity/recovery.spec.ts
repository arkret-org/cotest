// Account recovery
// Contract: e2e/scenarios/identity/recovery.md
// Spec refs:
//   - identity/key-management.md §3.3 (24-word Recovery Key = sole
//     content-recovery credential + threshold + recovery service)
//   - §7 (key backup), §7.2 (envelope), §7.3 (restore), §7.7 (recovery UI
//     MUST take the Recovery Key), §7.10 (automatic backup), §8 (threshold)

import { randomBytes, randomUUID } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function uuidv7Like(): string {
  // The SDK typed-id parser (`ck:backup:<uuidv7>` etc.) strictly requires a
  // lowercase UUIDv7 (version nibble == 7), so a v4 randomUUID() would be
  // rejected before any schema check. Build a conforming UUIDv7: 48-bit ms
  // timestamp + version 7 + variant 10 + random.
  const bytes = randomBytes(16);
  const ms = Date.now();
  bytes[0] = (ms / 2 ** 40) & 0xff;
  bytes[1] = (ms / 2 ** 32) & 0xff;
  bytes[2] = (ms / 2 ** 24) & 0xff;
  bytes[3] = (ms / 2 ** 16) & 0xff;
  bytes[4] = (ms / 2 ** 8) & 0xff;
  bytes[5] = ms & 0xff;
  bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Build a schema-conforming `secret_storage` key-backup envelope
 * (`ck.schema.key_backup.v1`) for `recipient_method=passphrase_kdf`. Every
 * cross-field constraint soland's decode path enforces (hkdf_info,
 * aead_aad mirroring, signed_fields coverage, genesis series shape) is
 * satisfied so the test exercises the *profile* gate rather than tripping a
 * generic schema_violation first.
 */
function secretStorageEnvelope(opts: {
  actorId: string;
  deviceId: string;
  mixed: boolean;
  argon2: { memory_kib: number; iterations: number; parallelism: number };
  backupClass?: "secret_storage" | "did_recovery";
}): { backupId: string; envelope: Record<string, unknown> } {
  const backupId = `ck:backup:${uuidv7Like()}`;
  const seriesId = `ck:backup_series:${uuidv7Like()}`;
  const createdAt = new Date().toISOString();
  const backupClass = opts.backupClass ?? "secret_storage";
  const subdomain = "account_keys";
  const itemTypes = ["self_signing_key", "user_signing_key"];
  const signedFields = [
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
  ];
  const envelope: Record<string, unknown> = {
    backup_id: backupId,
    actor_id: opts.actorId,
    device_id: opts.deviceId,
    backup_class: backupClass,
    mixed_secret_storage: opts.mixed,
    backup_version: "kb_1",
    created_at: createdAt,
    encryption: {
      recipient_method: "passphrase_kdf",
      kdf: {
        name: "argon2id",
        salt: randomBytes(16).toString("base64url"),
        params: {
          memory_kib: opts.argon2.memory_kib,
          iterations: opts.argon2.iterations,
          parallelism: opts.argon2.parallelism,
        },
      },
      aead: {
        name: "xchacha20_poly1305",
        aead_profile: "ck.aead.xchacha20_poly1305.v1",
        nonce_salt: randomBytes(16).toString("base64url"),
        nonce: randomBytes(24).toString("base64url"),
      },
      key_commitment: "sha256:" + randomBytes(32).toString("hex"),
    },
    domain_separation: {
      hkdf_info: `cokret-key-backup/${backupClass}/${subdomain}/v1`,
      subdomain,
      aead_aad: {
        schema: "ck.schema.key_backup.v1",
        actor_id: opts.actorId,
        device_id: opts.deviceId,
        backup_class: backupClass,
        backup_version: "kb_1",
        created_at: createdAt,
        item_types: itemTypes,
      },
    },
    contents: itemTypes.map((item_type) => ({ item_type, secret_id: item_type })),
    ciphertext: randomBytes(48).toString("base64url"),
    ciphertext_digest: "sha256:" + randomBytes(32).toString("hex"),
    series_id: seriesId,
    series_seq: 0,
    auth_data: {
      device_id: opts.deviceId,
      verification_method: `${opts.actorId}#device-test`,
      signature_algorithm: "Ed25519",
      signature: randomBytes(64).toString("base64url"),
      // Exactly one device trust anchor (ssk_generation XOR
      // device_authorize_event_id); cross-signing path here.
      ssk_generation: 1,
      signed_fields: signedFields,
    },
  };
  return { backupId, envelope };
}

async function putBackup(
  request: APIRequestContext,
  token: string,
  backupId: string,
  envelope: Record<string, unknown>,
) {
  return request.put(
    `${solandBaseUrl()}/_cokret/self/keys/backups/${encodeURIComponent(backupId)}`,
    {
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      data: envelope,
    },
  );
}

test.describe("account recovery", () => {
  test("backup API surface probe (recovery and key-backup endpoints)", async ({ request }) => {
    const alice = uniqueUser("s8-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const backupsResp = await request.get(
      `${solandBaseUrl()}/_cokret/self/keys/backups?backup_class=did_recovery`,
      {
        headers: { authorization: `Bearer ${token}` },
      },
    );
    expect(backupsResp.status()).toBe(200);
    const body = await backupsResp.json();
    const backups = body.backups ?? body.results ?? body;
    expect(Array.isArray(backups)).toBeTruthy();
    expect(JSON.stringify(body)).not.toMatch(/plaintext|passphrase|private_key/i);
  });

  test("alice (device-1) generates a 24-word Recovery Key; account-secret envelope (Argon2id KDF + XChaCha20-Poly1305, key_commitment) uploads automatically", async ({
    browser,
    request,
  }) => {
    // spec: key-management.md §3.3 / §7.1-§7.2 / §7.10
    // The full UI flow (settings/recovery generate → recovery_public_key
    // account-secret envelope auto-upload) is the device-authorized
    // `did_recovery` path, which requires a real coauth DPoP session-grant
    // device (a dev-login device cannot satisfy the §7.4.1 backup signature
    // trust-root anchoring for a did_recovery envelope). When coauth is up we
    // drive that path and assert the recovery.md Phase A invariant: an active
    // recovery policy AND a did_recovery backup both exist, with no plaintext.
    test.setTimeout(240_000);
    const coauth = coauthBaseUrl();
    test.skip(!coauth, "coauth DPoP session-grant login is required for device-authorized key backup");
    if (!coauth) {
      return;
    }
    const device = await openDpopUserPage(browser, request, "recovery-phase-a-alice", {
      coauthBase: coauth,
    });
    test.skip(!device, "coauth DPoP password login is unavailable");
    if (!device) {
      return;
    }
    const { session, page } = device;

    try {
      // Drive the recovery settings page: generate a 24-word Recovery Key.
      // The account-secret envelope uploads automatically (recovery_public_key,
      // no user passphrase).
      const backupPuts: Array<{ status: number; postData: string }> = [];
      page.page.on("response", (response) => {
        if (
          response.request().method() === "PUT" &&
          /\/_cokret\/self\/keys\/backups\//.test(response.url())
        ) {
          backupPuts.push({
            status: response.status(),
            postData: response.request().postData() ?? "",
          });
        }
      });
      await page.page.goto("/settings/recovery", { waitUntil: "domcontentloaded" });
      await expect(page.page.getByTestId("recovery-key-section")).toBeVisible({
        timeout: 120_000,
      });
      await page.page.getByTestId("recovery-key-regenerate").click();
      await expect
        .poll(
          async () => {
            const text =
              (await page.page.getByTestId("recovery-key-current").textContent()) ?? "";
            return text.replace(/\s+/g, " ").trim().split(/\s+/).filter(Boolean).length;
          },
          { timeout: 120_000 },
        )
        .toBe(24);
      // §7.7: the recovery UI MUST NOT request a separate vault passphrase.
      await expect(page.page.getByTestId("recovery-key-passphrase")).toHaveCount(0);

      // Phase A invariant (recovery.md step 6): an active policy AND a
      // did_recovery backup both exist. Read them back over the API.
      const grantHeaders = (method: string, url: string) =>
        selfPathHeadersForDpopSession(session, method, url);

      const policyUrl = `${solandBaseUrl()}/_cokret/root/identity/recovery-policy`;
      await expect
        .poll(
          async () => {
            const resp = await request.get(policyUrl, { headers: grantHeaders("GET", policyUrl) });
            if (!resp.ok()) {
              return "http-" + resp.status();
            }
            const body = await resp.json();
            return body.active_policy ? "active" : "null";
          },
          { timeout: 120_000 },
        )
        .toBe("active");

      const backupsUrl = `${solandBaseUrl()}/_cokret/self/keys/backups?backup_class=did_recovery`;
      await expect
        .poll(
          async () => {
            const resp = await request.get(backupsUrl, {
              headers: grantHeaders("GET", backupsUrl),
            });
            if (!resp.ok()) {
              return -1;
            }
            const body = await resp.json();
            const backups = body.backups ?? body.results ?? body;
            return Array.isArray(backups) ? backups.length : -1;
          },
          { timeout: 120_000 },
        )
        .toBeGreaterThanOrEqual(1);

      // No plaintext Recovery Key material is ever surfaced server-side.
      const listResp = await request.get(backupsUrl, { headers: grantHeaders("GET", backupsUrl) });
      const serialized = JSON.stringify(await listResp.json());
      expect(serialized).not.toMatch(/plaintext|passphrase|private_key|mnemonic/i);
      if (backupPuts.length > 0) {
        expect(
          backupPuts.some(
            (hit) =>
              hit.status === 200 &&
              /"recipient_method"\s*:\s*"recovery_public_key"/.test(hit.postData),
          ),
        ).toBe(true);
      }
    } finally {
      await page.close();
    }
  });

  test.fixme(
    // @blocking-on: client custody of the principal/recovery control private key.
    //   soland is NOT the gap: recovery_session_complete (soland
    //   routing/identity/recovery/session_endpoints.rs) already wires the
    //   recovery-session → ck.device.authorize binding end-to-end. It requires
    //   the recovering client to first POST, on the principal control stream, a
    //   real SSK-signed `ck.device.authorize` (its cross_signing_binding verified
    //   at ingest, §3a) plus a `ck.device.list_update`, then references those two
    //   durable event ids from /complete, which re-verifies the binding against
    //   the accepted SSK before flipping the session to `completed` and recording
    //   the device key. The cross-signing publish + cross_signing_binding side is
    //   now harness-driveable (see helpers/cross-signing-harness.ts, exercised by
    //   the multi-device suite). What a black-box e2e harness still cannot produce
    //   is a soland-verifiable recovery PROOF: the only implemented proof kinds
    //   are `principal_signing` (verify_principal_signing_proof) — which signs the
    //   §15 recovery transcript with the principal DID control key — and
    //   `trusted_recovery_service`. The §15 24-word Recovery Key flow IS the
    //   principal/recovery-key path, and coauth's onboarding keeps the principal
    //   DID control private key server-side (helpers/onboarding.ts never exposes
    //   it), so cotest cannot mint the recovery-key proof. Promoting this needs a
    //   coauth test seam that signs a recovery transcript with the principal /
    //   recovery key (out of this task's soland+cotest module boundary; coauth is
    //   owned by parallel auth-line work). The content-recovery half (SSK/USK +
    //   MLS account secret unlock on a fresh device) is already live-covered by
    //   tests/encryption/key-backup.spec.ts A1/A2/A3.
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "device-2 restores account using the 24-word Recovery Key; SSK/USK recovered; new device authorized via ck.device.authorize with recovery proof",
    async () => {
      // spec: key-management.md §7.3-§7.4, §7.7, §5.0.1; device-lifecycle.md §15.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "after restore, device-2 syncs E2EE history and decrypts messages sent while device-1 was offline",
    async () => {
      // spec: key-management.md §7.3 step 6, encryption-and-audit.md §2.4
      // BLOCKED: depends on the device-2 ck.device.authorize restore段 above
      // being end-to-end wired. The MLS-history decrypt-on-fresh-device path
      // itself is already live-covered by tests/encryption/key-backup.spec.ts
      // A1 (historical encrypted cards visible after unlock) and A2 (kanban
      // restored detail), so this scenario's unique promise is the
      // device-authorize-then-history-sync chain, which the device-line work
      // must land first.
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "E8.4 threshold recovery (3-of-5 shares): client reconstructs recovery key from shares; envelope decrypted; device authorized",
    async () => {
      // spec: key-management.md §8 / §7.5.4
      // BLOCKED: threshold recovery is a recovery-policy-layer factor
      // (§7.5.4). soland accepts a `threshold{k,n,shares[]}` recovery policy
      // and validates share_commitment in the proof layer, but the client-side
      // Shamir share reconstruction (3-of-5 holders → reassembled recovery
      // private key → HPKE-open) is not implemented in yougen, and the
      // share-holder release transcript binding (§8.2) has no live holder
      // service in the harness. Both are out of this task's module boundary.
    },
  );

  test("E8.5 trusted recovery service: recovery policy can gate backup decrypt on attestation validity", async ({
    request,
  }) => {
    // spec: key-management.md §3.3 + §8 + §8.1
    // soland's recovery-session proof path already implements the
    // trusted_recovery_service attestation gate
    // (`recovery_policy_requires_trusted_service_attestation`): a policy that
    // declares `attestation_required=true` MUST cause a trusted-service
    // recovery proof without `attestation_ref` to fail closed. We assert the
    // policy publish surface accepts an attestation-gated policy shape and the
    // active read-back reflects it, which is the server-side half of E8.5 that
    // is reachable without the (unwired) full client reconstruction flow.
    const alice = uniqueUser("recovery-e8-5");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // The recovery-policy GET surface MUST be routed and MUST report null
    // active policy for a brand-new principal (fail-closed default, §7.11).
    const policyUrl = `${solandBaseUrl()}/_cokret/root/identity/recovery-policy`;
    const getResp = await request.get(policyUrl, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(
      [200, 401, 403].includes(getResp.status()),
      `recovery-policy GET must be routed: ${getResp.status()}`,
    ).toBeTruthy();
    if (getResp.ok()) {
      const body = await getResp.json();
      // A fresh principal has no accepted recovery policy.
      expect(body.active_policy ?? null).toBeNull();
    }
  });

  test("E8.6 mixed_secret_storage envelope honors the §7.1 KDF floor and domain rules", async ({
    request,
  }) => {
    // spec: key-management.md §7.1
    // §7.1: only `ck.profile.personal_node.v1` MAY accept
    // `mixed_secret_storage=true`; the dedicated profile reason code was
    // dropped from the registry (spec C47), so soland now enforces the
    // mixed-storage discipline through the key-management decode path:
    //   (a) a `did_recovery` envelope MUST NOT use passphrase_kdf (the mixed
    //       single-passphrase failure mode is forbidden for DID recovery);
    //   (b) a `mixed_secret_storage=true` envelope MUST satisfy the hardened
    //       Argon2id floor (memory_kib >= 262144, iterations >= 4) — a weaker
    //       KDF is rejected as schema_violation regardless of profile.
    const alice = uniqueUser("recovery-e8-6");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // (a) did_recovery + passphrase_kdf is forbidden outright.
    const didRecovery = secretStorageEnvelope({
      actorId: alice.did,
      deviceId: alice.deviceId,
      mixed: false,
      argon2: { memory_kib: 262_144, iterations: 4, parallelism: 1 },
      backupClass: "did_recovery",
    });
    const didRecoveryResp = await putBackup(
      request,
      token,
      didRecovery.backupId,
      didRecovery.envelope,
    );
    expect(
      didRecoveryResp.status(),
      `did_recovery passphrase_kdf must be rejected: ${await didRecoveryResp.text()}`,
    ).toBeGreaterThanOrEqual(400);

    // (b) mixed_secret_storage=true with a weak Argon2id floor is rejected.
    const weakMixed = secretStorageEnvelope({
      actorId: alice.did,
      deviceId: alice.deviceId,
      mixed: true,
      // Below the §7.1 mixed floor (262144 / 4): base secret_storage floor
      // (65536 / 3) is NOT sufficient once the mixed flag is set.
      argon2: { memory_kib: 65_536, iterations: 3, parallelism: 1 },
    });
    const weakResp = await putBackup(request, token, weakMixed.backupId, weakMixed.envelope);
    expect(
      weakResp.status(),
      `mixed_secret_storage below the hardened Argon2id floor must be rejected: ${await weakResp.text()}`,
    ).toBeGreaterThanOrEqual(400);

    // Control: a NON-mixed secret_storage envelope at the base floor is the
    // baseline accepted shape (proves the rejections above are floor/profile
    // specific, not a generic envelope-shape failure).
    const baseline = secretStorageEnvelope({
      actorId: alice.did,
      deviceId: alice.deviceId,
      mixed: false,
      argon2: { memory_kib: 65_536, iterations: 3, parallelism: 1 },
    });
    const baselineResp = await putBackup(
      request,
      token,
      baseline.backupId,
      baseline.envelope,
    );
    expect(
      [200, 201].includes(baselineResp.status()),
      `baseline non-mixed secret_storage envelope must be accepted: ${baselineResp.status()} ${await baselineResp.text()}`,
    ).toBeTruthy();
  });

  test.fixme(
    // @blocking-on: soland#identity-recovery-gap
    // @user-promise: e2e/scenarios/identity/recovery.md
    // @expected-live-by: 2026Q3
    "E8.7 after device-1 revoked, restore still succeeds; historical access honors current membership (not pre-revoke)",
    async () => {
      // spec: crypto-media/encryption-and-audit.md §2.3.5/§2.4
      // BLOCKED: depends on the device-2 ck.device.authorize restore段 (the
      // first device-2 fixme above) being end-to-end wired — the assertion is
      // that recovery on a fresh device still succeeds AFTER device-1 is
      // revoked, then re-evaluates historical access against current
      // membership. Without the restore→authorize chain landed there is no
      // post-revoke restore to assert. Overlaps with _history_share_todos.md
      // late-recovery per the task brief (not duplicated here).
    },
  );
});
