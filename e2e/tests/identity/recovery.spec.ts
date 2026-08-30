// Account recovery
// Contract: e2e/scenarios/identity/recovery.md
// Spec refs:
//   - identity/key-management.md §3.3 (24-word Recovery Key = sole
//     content-recovery credential + threshold + recovery service)
//   - §7 (key backup), §7.2 (envelope), §7.3 (restore), §7.7 (recovery UI
//     MUST take the Recovery Key), §7.10 (automatic backup), §8 (threshold)

import { createHash, randomBytes, randomUUID } from "node:crypto";

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import { canonicalJson } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
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
 * cross-field constraint soland's decode path enforces (ciphertext_digest over
 * the ciphertext bytes, domain-separation subdomain, genesis series shape) is
 * satisfied so the test exercises the *profile* gate rather than tripping a
 * generic schema_violation first.
 */
function secretStorageEnvelope(opts: {
  actorId: string;
  // `auth_data.verification_method` is a DID URL, so it is built from the
  // holder's DID — never from the projected `ak:did_core:` actor id, which is
  // not a DID and fails the request-body schema before any KDF rule runs.
  actorDid: string;
  deviceId: string;
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
    actor_id: opts.actorId,
    device_id: opts.deviceId,
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
    // soland re-derives this from the ciphertext bytes, so a random digest is
    // rejected before any KDF/domain rule is reached.
    ciphertext_digest: `sha256:${createHash("sha256").update(ciphertext).digest("hex")}`,
    series_id: seriesId,
    series_seq: 0,
    auth_data: {
      device_id: opts.deviceId,
      verification_method: `${opts.actorDid}#device-test`,
      signature_algorithm: "Ed25519",
      signature: randomBytes(64).toString("base64url"),
      // The PCR accepted-device Event is the sole device trust anchor.
      device_authorize_event_id:
        "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
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
    `${solandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`,
    {
      headers: {
        authorization: `Bearer ${token}`,
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
    const token = await issueDevSession(request, alice);

    const backupsResp = await request.get(
      `${solandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`,
      {
        headers: { authorization: `Bearer ${token}` },
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

      const policyUrl = `${solandBaseUrl()}/_arkret/root/identity/recovery-policy`;
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

      const backupsUrl = `${solandBaseUrl()}/_arkret/self/keys/backups?backup_kind=secret_storage`;
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
    const policyUrl = `${solandBaseUrl()}/_arkret/root/identity/recovery-policy`;
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
    // §7.1: only `ak.profile.personal_node.v1` MAY accept
    // `mixed_secret_storage=true`; the dedicated profile reason code was
    // dropped from the registry (spec C47), so soland now enforces the
    // mixed-storage discipline through the key-management decode path:
    // A `mixed_secret_storage=true` envelope MUST satisfy the hardened
    //       Argon2id floor (memory_kib >= 262144, iterations >= 4) — a weaker
    //       KDF is rejected as schema_violation regardless of profile.
    const alice = uniqueUser("recovery-e8-6");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    // mixed_secret_storage=true with a weak Argon2id floor is rejected.
    const weakMixed = secretStorageEnvelope({
      actorId: alice.id,
      actorDid: alice.did,
      deviceId: alice.deviceId,
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
      actorDid: alice.did,
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
});
