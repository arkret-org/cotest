import { authHeaders } from "../../helpers/coland-api";
// Account recovery
// Contract: e2e/scenarios/identity/recovery.md
// Spec refs:
//   - identity/key-management.md §3.3 (24-word Recovery Key = sole
//     content-recovery credential + threshold + recovery service)
//   - §7 (key backup), §7.2 (envelope), §7.3 (restore), §7.7 (recovery UI
//     MUST take the Recovery Key), §7.10 (automatic backup), §8 (threshold)

import { createHash, randomBytes, randomUUID } from "node:crypto";

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { coauthBaseUrl, colandBaseUrl } from "../../helpers/env";
import {
  accountActorId,
  canonicalJson,
  expectJsonOk,
  registeredEventSigningSeedB64url,
  registeredEventVerificationMethod,
} from "../../helpers/coland-api";
import { sdkKeyBackupAuthSignature } from "../../helpers/coland-api/wire-client";
import {
  ensureRegistered,
  issueUserSession,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function uuidv7Like(): string {
  // The SDK typed-id parser (`ak:backup:<uuidv7>` etc.) strictly requires a
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
 * (`ak.schema.key_backup.v1`) for `recipient_method=passphrase_kdf`. Every
 * cross-field constraint coland's decode path enforces (ciphertext_digest over
 * the ciphertext bytes, domain-separation subdomain, genesis series shape) is
 * satisfied so the test exercises the *profile* gate rather than tripping a
 * generic schema_violation first.
 */
type BackupDeviceSigner = {
  deviceId: string;
  // `auth_data.verification_method` is the accepted device method: the
  // holder's DID URL whose fragment is the device id (key-management.md
  // section 7.4.1).
  verificationMethod: string;
  deviceAuthorizeEventId: string;
  signingSeedB64url: string;
};

// key-management.md section 7.4.1: a receiver anchors `auth_data.signature` to
// the accepted `ak.device.authorize` of the signing device, so the envelope is
// signed by the session device over the SDK transcript and names that exact
// authorization Event.
async function sessionBackupSigner(
  request: APIRequestContext,
  token: string,
  actorId: string,
  deviceId: string,
): Promise<BackupDeviceSigner> {
  const viewerUrl = `${colandBaseUrl()}/_arkret/self/account/viewer`;
  const viewer = await expectJsonOk<{
    devices?: Array<{ device_id?: unknown; authorized_event_ref?: unknown }>;
  }>(
    await request.get(viewerUrl, {
      headers: authHeaders(token, "GET", viewerUrl),
    }),
    "read the session device authorization",
  );
  const row = (viewer.devices ?? []).find((device) => device.device_id === deviceId);
  const deviceAuthorizeEventId = row?.authorized_event_ref;
  if (typeof deviceAuthorizeEventId !== "string") {
    throw new Error(`account viewer has no accepted authorization for ${deviceId}`);
  }
  const verificationMethod = registeredEventVerificationMethod(actorId, deviceId);
  const signingSeedB64url = registeredEventSigningSeedB64url(actorId);
  if (!verificationMethod || !signingSeedB64url) {
    throw new Error(`canonical provisioning omitted the device signer of ${deviceId}`);
  }
  return { deviceId, verificationMethod, deviceAuthorizeEventId, signingSeedB64url };
}

function secretStorageEnvelope(opts: {
  actorId: string;
  signer: BackupDeviceSigner;
  mixed: boolean;
  argon2: { memory_kib: number; iterations: number; parallelism: number };
}): { backupId: string; envelope: Record<string, unknown> } {
  const backupId = `ak:backup:${uuidv7Like()}`;
  const seriesId = `ak:backup_series:${uuidv7Like()}`;
  const createdAt = new Date().toISOString();
  const backupClass = "secret_storage";
  const subdomain = "account_keys";
  const itemTypes = ["mls_group_secrets_backup_key"];
  const ciphertext = randomBytes(48);
  const envelope: Record<string, unknown> = {
    backup_id: backupId,
    actor_id: accountActorId(opts.actorId),
    device_id: opts.signer.deviceId,
    backup_kind: backupClass,
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
        aead_profile: "ak.aead.xchacha20_poly1305.v1",
        nonce_salt: randomBytes(16).toString("base64url"),
        nonce: randomBytes(24).toString("base64url"),
      },
      key_commitment: "sha256:" + randomBytes(32).toString("hex"),
    },
    // key-backup.schema.json: the HKDF info and the fixed AEAD AAD base are
    // derived from the envelope by key-management.md §7.2, so only the
    // subdomain (plus genuine `x_*` extensions) travels on the wire.
    domain_separation: {
      subdomain,
    },
    contents: itemTypes.map((item_kind) => ({
      item_kind,
      secret_id: item_kind,
    })),
    ciphertext: ciphertext.toString("base64url"),
    // coland re-derives this from the ciphertext bytes, so a random digest is
    // rejected before any KDF/domain rule is reached.
    ciphertext_digest: `sha256:${createHash("sha256").update(ciphertext).digest("hex")}`,
    series_id: seriesId,
    series_seq: 0,
    auth_data: {
      device_id: opts.signer.deviceId,
      verification_method: opts.signer.verificationMethod,
      signature_algorithm: "Ed25519",
      // The PCR accepted-device Event is the sole device trust anchor.
      device_authorize_event_id: opts.signer.deviceAuthorizeEventId,
    },
  };
  return {
    backupId,
    envelope: sdkKeyBackupAuthSignature({
      envelope,
      signingSeedB64url: opts.signer.signingSeedB64url,
    }),
  };
}

async function putBackup(
  request: APIRequestContext,
  token: string,
  backupId: string,
  envelope: Record<string, unknown>,
) {
  return request.put(
    `${colandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`,
    {
      headers: {
        ...authHeaders(token, "PUT", `${colandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`),
        "content-type": "application/json",
        "idempotency-key": `cotest-key-backup-${backupId}`,
      },
      data: canonicalJson(envelope),
    },
  );
}

test.describe("account recovery", () => {
  test("backup API surface probe (recovery and key-backup endpoints)", async ({
    request,
  }) => {
    const alice = uniqueUser("s8-probe");
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);

    const backupsResp = await request.get(
      `${colandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`,
      {
        headers: authHeaders(token, "GET", `${colandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`),
      },
    );
    expect(backupsResp.status()).toBe(200);
    const body = await backupsResp.json();
    const backups = body.backups ?? body.results ?? body;
    expect(Array.isArray(backups)).toBeTruthy();
    expect(JSON.stringify(body)).not.toMatch(
      /plaintext|passphrase|private_key/i,
    );
  });

  test("alice (device-1) generates a 24-word Recovery Key; account-secret envelope (Argon2id KDF + XChaCha20-Poly1305, key_commitment) uploads automatically", async ({
    browser,
    request,
  }) => {
    // spec: key-management.md §3.3 / §7.1-§7.2 / §7.10
    // The full UI flow (settings/recovery generate → recovery_public_key
    // account-secret envelope auto-upload) requires a real coauth DPoP
    // session-grant device. When coauth is up we assert the recovery-material
    // gate (active policy) and the separate encrypted account backup.
    test.setTimeout(240_000);
    const coauth = coauthBaseUrl();
    test.skip(
      !coauth,
      "coauth DPoP session-grant login is required for device-authorized key backup",
    );
    if (!coauth) {
      return;
    }
    const device = await openDpopUserPage(
      browser,
      request,
      "recovery-phase-a-alice",
      {
        coauthBase: coauth,
      },
    );
    test.skip(!device, "coauth DPoP password login is unavailable");
    if (!device) {
      return;
    }
    const { session, page } = device;

    try {
      // The DPoP bootstrap helper completes the first-device recovery prompt,
      // which generates the 24-word Recovery Key and uploads the
      // recovery_public_key envelope before it returns. Verify the durable
      // result rather than waiting for an already-completed browser request.
      await page.gotoAppPanel("/settings/recovery", "recovery-panel");
      await expect(page.page.getByTestId("recovery-key-section")).toBeVisible({
        timeout: 120_000,
      });
      expect(
        session.recoveryKey?.trim().split(/\s+/).filter(Boolean),
      ).toHaveLength(24);
      await expect(page.page.getByTestId("recovery-key-current")).toBeVisible();
      // §7.7: the recovery UI MUST NOT request a separate vault passphrase.
      await expect(
        page.page.getByTestId("recovery-key-passphrase"),
      ).toHaveCount(0);

      // The gate is the active policy; encrypted account material is a
      // separate secret_storage recovery path. Read both back over the API.
      const grantHeaders = (method: string, url: string) =>
        selfPathHeadersForDpopSession(session, method, url);

      const policyUrl = `${colandBaseUrl()}/_arkret/root/identity/recovery-policy`;
      await expect
        .poll(
          async () => {
            const resp = await request.get(policyUrl, {
              headers: grantHeaders("GET", policyUrl),
            });
            if (!resp.ok()) {
              return "http-" + resp.status();
            }
            const body = await resp.json();
            return body.active_policy ? "active" : "null";
          },
          { timeout: 120_000 },
        )
        .toBe("active");

      const backupsUrl = `${colandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`;
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
            return Array.isArray(backups)
              ? backups.filter(
                  (backup: any) =>
                    backup?.backup_kind === "secret_storage" &&
                    backup?.encryption?.recipient_method ===
                      "recovery_public_key",
                ).length
              : -1;
          },
          { timeout: 120_000 },
        )
        .toBeGreaterThanOrEqual(1);

      // No plaintext Recovery Key material is ever surfaced server-side.
      const listResp = await request.get(backupsUrl, {
        headers: grantHeaders("GET", backupsUrl),
      });
      const serialized = JSON.stringify(await listResp.json());
      expect(serialized).not.toMatch(
        /plaintext|passphrase|private_key|mnemonic/i,
      );
    } finally {
      await page.close();
    }
  });

  test("E8.5 recovery policy read surface is fail-closed before any policy is accepted", async ({
    request,
  }) => {
    // spec: key-management.md §7.11 + §8.1
    // The v1 recovery methods are the closed four (did_root, recovery_unlock,
    // device_quorum, trusted_recovery_service); there is no configurable
    // attestation gate. What stays observable here is the fail-closed default:
    // the routed recovery-policy read MUST report no accepted policy for a
    // brand-new principal, so the §7.11 recovery gate cannot be satisfied by an
    // absent policy.
    const alice = uniqueUser("recovery-e8-5");
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);

    // The recovery-policy GET surface MUST be routed and MUST report null
    // active policy for a brand-new principal (fail-closed default, §7.11).
    const policyUrl = `${colandBaseUrl()}/_arkret/root/identity/recovery-policy`;
    const getResp = await request.get(policyUrl, {
      headers: authHeaders(token, "GET", policyUrl),
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
    // §7.1: only `ak.profile.personal_node.v1` MAY accept
    // `mixed_secret_storage=true`; the dedicated profile reason code was
    // dropped from the registry (spec C47), so coland now enforces the
    // mixed-storage discipline through the key-management decode path:
    // A `mixed_secret_storage=true` envelope MUST satisfy the hardened
    //       Argon2id floor (memory_kib >= 262144, iterations >= 4) — a weaker
    //       KDF is rejected as schema_violation regardless of profile.
    const alice = uniqueUser("recovery-e8-6");
    await ensureRegistered(request, alice);
    const token = await issueUserSession(request, alice);
    // Both envelopes carry a genuine anchored device signature, so the only
    // difference between the rejection and the accepted baseline is the KDF
    // floor the mixed flag raises.
    const signer = await sessionBackupSigner(request, token, alice.id, alice.deviceId);

    // mixed_secret_storage=true with a weak Argon2id floor is rejected.
    const weakMixed = secretStorageEnvelope({
      actorId: alice.id,
      signer,
      mixed: true,
      // Below the §7.1 mixed floor (262144 / 4): base secret_storage floor
      // (65536 / 3) is NOT sufficient once the mixed flag is set.
      argon2: { memory_kib: 65_536, iterations: 3, parallelism: 1 },
    });
    const weakResp = await putBackup(
      request,
      token,
      weakMixed.backupId,
      weakMixed.envelope,
    );
    expect(
      weakResp.status(),
      `mixed_secret_storage below the hardened Argon2id floor must be rejected: ${await weakResp.text()}`,
    ).toBeGreaterThanOrEqual(400);

    // Control: a NON-mixed secret_storage envelope at the base floor is the
    // baseline accepted shape (proves the rejections above are floor/profile
    // specific, not a generic envelope-shape failure).
    const baseline = secretStorageEnvelope({
      actorId: alice.id,
      signer,
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
});
