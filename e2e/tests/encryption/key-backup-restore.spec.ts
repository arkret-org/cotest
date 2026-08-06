// Key backup restore live path
// Contract: e2e/scenarios/encryption/key-backup-restore.md

import { randomUUID, createHash } from "node:crypto";

import { expect, test, type APIRequestContext } from "@playwright/test";

import {
  authHeaders,
  canonicalJson,
  canonicalTimestamp,
  uuidV7,
} from "../../helpers/soland-api";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("key backup restore live path", () => {
  test("Device-A uploads secret_storage backup; list is metadata-only and bearer-only unlock is refused", async ({
    request,
  }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-a");
    const backupId = backupIdFor("primary");
    const backup = makeBackupBody(alice, backupId);

    const put = await putBackup(request, aliceToken, backupId, backup);
    expect(put.status(), await put.text()).toBe(200);
    // spec `keys-operations.schema.json#/$defs/keys_backups_put_outcome`:
    // { status, backup_id, ciphertext_digest } (the SDK KeysBackupsPutOutcome shape).
    expect(await put.json()).toMatchObject({
      status: "accepted",
      backup_id: backupId,
      ciphertext_digest: backup.ciphertext_digest,
    });

    const list = await request.get(`${solandBaseUrl()}/_arkret/self/keys/backups`, {
      headers: authHeaders(aliceToken),
    });
    expect(list.status()).toBe(200);
    const listBody = await list.json();
    expect((listBody.backups ?? []).map((item: { backup_id: string }) => item.backup_id)).toContain(
      backupId,
    );
    expect(JSON.stringify(listBody)).not.toMatch(/hunter2|plaintext|self-signing-secret/i);

    // key-management.md §7.7.1/§7.8 — a bearer token alone MUST NOT release
    // the full ciphertext; the proof travels in the typed
    // `POST /_arkret/self/keys/backups/{id}/unlock` body.
    const unlock = await unlockBackupWithoutProof(request, aliceToken, backupId);
    expect([400, 401, 403, 422]).toContain(unlock.status());
    const refusal = await unlock.text();
    expect(refusal).not.toContain(backup.ciphertext as string);
    expect(refusal).not.toMatch(/hunter2|plaintext|self-signing-secret/i);
  });

  test("Device-B cannot enumerate or fetch Alice backup envelope", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-owner");
    const { bob, bobToken } = await registeredSession(request, "kb-restore-device-b");
    const backupId = backupIdFor("owner-only");

    expect((await putBackup(request, aliceToken, backupId, makeBackupBody(alice, backupId))).status()).toBe(200);

    const bobList = await request.get(`${solandBaseUrl()}/_arkret/self/keys/backups`, {
      headers: authHeaders(bobToken),
    });
    expect(bobList.status()).toBe(200);
    expect(JSON.stringify(await bobList.json())).not.toContain(backupId);

    const bobLegacyGet = await legacyGetBackup(request, bobToken, backupId);
    expect([404, 405]).toContain(bobLegacyGet.status());
    void bob;
  });

  test("actor_id mismatch backup PUT is rejected before storage", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-mismatch-a");
    const { bob } = await registeredSession(request, "kb-restore-mismatch-b");
    const backupId = backupIdFor("mismatch");
    const backup = makeBackupBody(bob, backupId);

    const put = await putBackup(request, aliceToken, backupId, backup);
    expect([400, 403]).toContain(put.status());
    const list = await request.get(`${solandBaseUrl()}/_arkret/self/keys/backups`, {
      headers: authHeaders(aliceToken),
    });
    expect(JSON.stringify(await list.json())).not.toContain(backupId);
    void alice;
  });

  test("Argon2id metadata below the required floor is schema-rejected", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-weak-kdf");
    const backupId = backupIdFor("weak-kdf");
    const backup = makeBackupBody(alice, backupId, {
      encryption: {
        kdf: { params: { memory_kib: 32_768, iterations: 2, parallelism: 1 } },
      },
    });

    const put = await putBackup(request, aliceToken, backupId, backup);
    expect([400, 422]).toContain(put.status());
    expect(await put.text()).toContain("argon2id");
  });

  test("mixed_secret_storage requires the higher key-backup KDF floor", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-mixed");
    const weakId = backupIdFor("mixed-weak");
    const strongId = backupIdFor("mixed-strong");

    const weak = await putBackup(
      request,
      aliceToken,
      weakId,
      makeBackupBody(alice, weakId, { mixed_secret_storage: true }),
    );
    expect([400, 422]).toContain(weak.status());
    expect(await weak.text()).toContain("memory_kib");

    const strong = await putBackup(
      request,
      aliceToken,
      strongId,
      makeBackupBody(alice, strongId, {
        mixed_secret_storage: true,
        encryption: {
          kdf: { params: { memory_kib: 262_144, iterations: 4, parallelism: 4 } },
        },
      }),
    );
    expect(strong.status()).toBe(200);
  });

  test("DELETE requires ownership proof; proof-bound delete removes the backup", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-delete");
    const backupId = backupIdFor("delete");
    expect((await putBackup(request, aliceToken, backupId, makeBackupBody(alice, backupId))).status()).toBe(200);

    const sessionOnlyDelete = await request.delete(
      `${solandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect([400, 401, 403, 422]).toContain(sessionOnlyDelete.status());
    const afterSessionOnlyDelete = await request.get(`${solandBaseUrl()}/_arkret/self/keys/backups`, {
      headers: authHeaders(aliceToken),
    });
    expect(JSON.stringify(await afterSessionOnlyDelete.json())).toContain(backupId);

    const proofDelete = await request.delete(
      `${solandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`,
      {
        headers: authHeaders(aliceToken),
        data: {
          proof: {
            kind: "ak.key_backup.delete.development.v1",
            value: deleteProof(alice.did, backupId),
          },
          reason: "user_requested",
        },
      },
    );
    expect(proofDelete.status()).toBe(200);
    // spec `keys_backups_delete_outcome` carries only { deleted } (the SDK
    // KeysBackupsDeleteOutcome shape).
    expect(await proofDelete.json()).toMatchObject({ deleted: true });
    const list = await request.get(`${solandBaseUrl()}/_arkret/self/keys/backups`, {
      headers: authHeaders(aliceToken),
    });
    expect(JSON.stringify(await list.json())).not.toContain(backupId);
  });

});

async function registeredSession(request: APIRequestContext, prefix: string) {
  const user = uniqueUser(prefix);
  await ensureRegistered(request, user);
  const token = await issueDevSession(request, user);
  return { alice: user, aliceToken: token, bob: user, bobToken: token };
}

async function putBackup(
  request: APIRequestContext,
  token: string,
  backupId: string,
  body: Record<string, unknown>,
) {
  // Soland validates this body as a canonical JSON operation body and rejects
  // anything that is not byte-for-byte canonical. A JS object literal keeps its
  // insertion order through `JSON.stringify`, which is not key-sorted, so the
  // body has to be serialized through the SDK's canonicalizer rather than
  // handed to Playwright as an object.
  return await request.put(`${solandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`, {
    headers: {
      ...authHeaders(token),
      "content-type": "application/json",
      "idempotency-key": `cotest-key-backup-${backupId}`,
    },
    data: canonicalJson(body),
  });
}

async function unlockBackupWithoutProof(request: APIRequestContext, token: string, backupId: string) {
  return await request.post(
    `${solandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}/unlock`,
    {
      headers: authHeaders(token),
      data: {},
    },
  );
}

async function legacyGetBackup(request: APIRequestContext, token: string, backupId: string) {
  return await request.get(`${solandBaseUrl()}/_arkret/self/keys/backups/${encodeURIComponent(backupId)}`, {
    headers: authHeaders(token),
  });
}

function makeBackupBody(
  actor: JointUser,
  backupId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const createdAt = canonicalTimestamp();
  const ciphertext = `backup-ciphertext-${randomUUID()}`;
  const contents = [
    {
      item_kind: "self_signing_key",
      secret_id: "ssk",
    },
    {
      item_kind: "mls_group_secrets_backup_key",
      secret_id: "mls-history",
    },
  ];
  const base = {
    backup_id: backupId,
    actor_id: actor.did,
    device_id: actor.deviceId,
    backup_kind: "secret_storage",
    backup_version: "kb_1",
    // §7.6 series chain — every envelope is a genesis of its own series here.
    series_id: `ak:backup_series:${uuidV7()}`,
    series_seq: 0,
    supersedes: null,
    created_at: createdAt,
    encryption: {
      recipient_method: "passphrase_kdf",
      kdf: {
        name: "argon2id",
        salt: "bW9jay1zYWx0LTE2Ynl0ZXM",
        params: {
          memory_kib: 65_536,
          iterations: 3,
          parallelism: 4,
        },
      },
      // §7.2 AEAD block — passphrase_kdf envelopes MUST carry the
      // deterministic-nonce `nonce_salt` alongside the AEAD profile.
      aead: {
        name: "xchacha20_poly1305",
        aead_profile: "ak.aead.xchacha20_poly1305.v1",
        nonce: "bW9jay14Y2hhY2hhLW5vbmNlLTEyMzQ1Ng",
        nonce_salt: "bW9jay1ub25jZS1zYWx0LTE2Ynl0ZXM",
      },
      key_commitment: sha256Ref(`commitment:${backupId}`),
    },
    domain_separation: {
      hkdf_info: "arkret-key-backup/secret_storage/aead/v1",
      subdomain: "aead",
      aead_aad: {
        schema: "ak.schema.key_backup.v1",
        actor_id: actor.did,
        device_id: actor.deviceId,
        backup_kind: "secret_storage",
        backup_version: "kb_1",
        created_at: createdAt,
        item_kinds: contents.map((item) => item.item_kind),
      },
    },
    contents,
    ciphertext,
    ciphertext_digest: sha256Ref(ciphertext),
    // §7.4.1 cross-signing anchored device signature block. soland validates
    // the shape (typed device id, Ed25519 alg, base64url signature,
    // ssk_generation >= 1, signed_fields coverage) at PUT time; signature
    // *verification* happens receiver-side at restore, so a shape-valid
    // token is sufficient for these storage-contract tests.
    auth_data: {
      device_id: "ak:device:01904100-0000-7000-8000-000000000001",
      verification_method:
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
      signature_algorithm: "Ed25519",
      signature: "ZGV2LWJhY2t1cC1zaWduYXR1cmU",
      ssk_generation: 1,
      signed_fields: [
        "backup_id",
        "actor_id",
        "backup_kind",
        "backup_version",
        "series_id",
        "series_seq",
        "supersedes",
        "encryption",
        "domain_separation",
        "contents",
        "ciphertext_digest",
      ],
    },
  };
  return deepMerge(base, overrides);
}

function deepMerge<T extends Record<string, unknown>>(base: T, overrides: Record<string, unknown>): T {
  const out: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(overrides)) {
    const current = out[key];
    if (isRecord(current) && isRecord(value)) {
      out[key] = deepMerge(current, value);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function backupIdFor(label: string): string {
  void label;
  return `ak:backup:${uuidV7()}`;
}

function sha256Ref(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deleteProof(actorDid: string, backupId: string): string {
  return `dev-ssk-delete:v1:${actorDid}:${backupId}`;
}
