// Key backup restore live path
// Contract: e2e/scenarios/encryption/key-backup-restore.md

import { execFile } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

import { expect, test, type APIRequestContext } from "@playwright/test";

import { authHeaders } from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
  type JointUser,
} from "../../helpers/users";

const execFileAsync = promisify(execFile);
const CARGO_BIN = process.platform === "win32" ? "cargo.exe" : "cargo";
const YOUGEN_MANIFEST = findSiblingManifest("yougen");
const YOUGEN_CWD = path.dirname(YOUGEN_MANIFEST);
const CARGO_TEST_TIMEOUT_MS = 240_000;

test.describe.configure({ mode: "serial" });

test.describe("key backup restore live path", () => {
  test("Device-A uploads secret_storage backup; list/get expose no passphrase or plaintext", async ({
    request,
  }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-a");
    const backupId = backupIdFor("primary");
    const backup = makeBackupBody(alice, backupId);

    const put = await putBackup(request, aliceToken, backupId, backup);
    expect(put.status()).toBe(200);
    expect(await put.json()).toMatchObject({
      ok: true,
      state: "accepted",
      backup: { backup_id: backupId, ciphertext_digest: backup.ciphertext_digest },
    });

    const list = await request.get(`${solandBaseUrl()}/api/v1/keys/backups`, {
      headers: authHeaders(aliceToken),
    });
    expect(list.status()).toBe(200);
    const listBody = await list.json();
    expect((listBody.backups ?? []).map((item: { backup_id: string }) => item.backup_id)).toContain(
      backupId,
    );
    expect(JSON.stringify(listBody)).not.toMatch(/hunter2|plaintext|self-signing-secret/i);

    const get = await getBackup(request, aliceToken, backupId);
    expect(get.status()).toBe(200);
    const fetched = await get.json();
    expect(fetched.encryption.kdf.name).toBe("argon2id");
    expect(fetched.encryption.algorithm).toBe("XChaCha20-Poly1305");
    expect(fetched.ciphertext_digest).toBe(backup.ciphertext_digest);
    expect(JSON.stringify(fetched)).not.toMatch(/hunter2|plaintext|self-signing-secret/i);
  });

  test("Device-B cannot enumerate or fetch Alice backup envelope", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-owner");
    const { bob, bobToken } = await registeredSession(request, "kb-restore-device-b");
    const backupId = backupIdFor("owner-only");

    expect((await putBackup(request, aliceToken, backupId, makeBackupBody(alice, backupId))).status()).toBe(200);

    const bobList = await request.get(`${solandBaseUrl()}/api/v1/keys/backups`, {
      headers: authHeaders(bobToken),
    });
    expect(bobList.status()).toBe(200);
    expect(JSON.stringify(await bobList.json())).not.toContain(backupId);

    const bobGet = await getBackup(request, bobToken, backupId);
    expect(bobGet.status()).toBe(404);
    void bob;
  });

  test("actor_id mismatch backup PUT is rejected before storage", async ({ request }) => {
    const { alice, aliceToken } = await registeredSession(request, "kb-restore-mismatch-a");
    const { bob } = await registeredSession(request, "kb-restore-mismatch-b");
    const backupId = backupIdFor("mismatch");
    const backup = makeBackupBody(bob, backupId);

    const put = await putBackup(request, aliceToken, backupId, backup);
    expect([400, 403]).toContain(put.status());
    const list = await request.get(`${solandBaseUrl()}/api/v1/keys/backups`, {
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
      `${solandBaseUrl()}/api/v1/keys/backups/${encodeURIComponent(backupId)}`,
      { headers: authHeaders(aliceToken) },
    );
    expect(sessionOnlyDelete.status()).toBe(403);

    const proofDelete = await request.delete(
      `${solandBaseUrl()}/api/v1/keys/backups/${encodeURIComponent(backupId)}`,
      {
        headers: {
          ...authHeaders(aliceToken),
          "x-contrix-key-backup-delete-proof": deleteProof(alice.did, backupId),
        },
      },
    );
    expect(proofDelete.status()).toBe(200);
    expect(await proofDelete.json()).toMatchObject({ deleted: true, state: "deleted" });
    expect((await getBackup(request, aliceToken, backupId)).status()).toBe(404);
  });

  test("yougen crypto and late-recovery banner helpers stay live", async () => {
    await runYougenLibTest("recovery_crypto::tests::encrypt_decrypt_round_trip");
    await runYougenLibTest("recovery_crypto::tests::decrypt_rejects_wrong_passphrase");
    await runYougenLibTest("late_recovery::tests::from_audit_policy_access_carries_late_recovery_original_event_id");
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
  return await request.put(`${solandBaseUrl()}/api/v1/keys/backups/${encodeURIComponent(backupId)}`, {
    headers: authHeaders(token),
    data: body,
  });
}

async function getBackup(request: APIRequestContext, token: string, backupId: string) {
  return await request.get(`${solandBaseUrl()}/api/v1/keys/backups/${encodeURIComponent(backupId)}`, {
    headers: authHeaders(token),
  });
}

function makeBackupBody(
  actor: JointUser,
  backupId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const ciphertext = `vault-ciphertext-${randomUUID()}`;
  const base = {
    backup_id: backupId,
    actor_id: actor.did,
    backup_class: "secret_storage",
    backup_version: "kb_1",
    created_at: new Date().toISOString(),
    encryption: {
      recipient_method: "passphrase_kdf",
      algorithm: "XChaCha20-Poly1305",
      nonce: "bW9jay14Y2hhY2hhLW5vbmNlLTEyMzQ1Ng",
      key_commitment: sha256Ref(`commitment:${backupId}`),
      kdf: {
        name: "argon2id",
        params: {
          salt: "bW9jay1zYWx0LTE2Ynl0ZXM",
          memory_kib: 65_536,
          iterations: 3,
          parallelism: 4,
        },
      },
    },
    contents: [
      {
        item_type: "self_signing_key",
        secret_id: "ssk",
        encoding: "encrypted_inline",
      },
      {
        item_type: "mls_group_secrets_backup_key",
        secret_id: "mls-history",
        encoding: "encrypted_inline",
      },
    ],
    ciphertext,
    ciphertext_digest: sha256Ref(ciphertext),
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
  return `cx:backup:${label}-${randomUUID()}`;
}

function sha256Ref(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deleteProof(actorDid: string, backupId: string): string {
  return `dev-ssk-delete:v1:${actorDid}:${backupId}`;
}

async function runYougenLibTest(filter: string): Promise<void> {
  const { stdout, stderr } = await execFileAsync(
    CARGO_BIN,
    ["test", "--manifest-path", YOUGEN_MANIFEST, "--lib", filter, "--", "--nocapture"],
    {
      cwd: YOUGEN_CWD,
      timeout: CARGO_TEST_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, CARGO_TERM_COLOR: "never" },
    },
  );
  const output = `${stdout}\n${stderr}`;
  expect(output).toContain(`test ${filter} ... ok`);
  expect(output).toContain("test result: ok");
}

function findSiblingManifest(crateName: string): string {
  const candidates = [
    path.resolve(process.cwd(), "..", crateName, "Cargo.toml"),
    path.resolve(process.cwd(), "..", "..", crateName, "Cargo.toml"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(`Unable to locate sibling ${crateName}/Cargo.toml from ${process.cwd()}`);
  }
  return found;
}
