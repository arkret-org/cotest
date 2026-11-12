import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createDecipheriv, randomBytes } from "node:crypto";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { request } from "@playwright/test";
import { initializeManagerArchive } from "./manager-archive.mjs";
import { createEd25519KeyPair, encodeEd25519PubkeyMultibase, rawEd25519PublicKey } from "./keypairs.mjs";
import { canonicalJson } from "./http.mjs";

test("Service-only Applet package persists encrypted and reloads without a Bot", { timeout: 30_000 }, async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "cotest-applet-durability-"));
  const keyPath = path.join(directory, "state.key");
  const statePath = path.join(directory, "state.json");
  writeFileSync(keyPath, randomBytes(32));
  let registry;
  try {
    registry = await startRegistry(keyPath, statePath);
    const { base } = registry;
    const post = (route, body) => fetch(`${base}${route}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    for (const namespace of ["before-reload", "after-reload"]) {
      const response = await post("/sign-package", {
        namespace,
        base_url: "https://applet.fixture.localhost",
      });
      assert.equal(response.status, 200, registry.logs);
      const signed = await response.json();
      assert.match(signed.package_digest, /^sha256:[0-9a-f]{64}$/);
      assert.equal(Object.hasOwn(signed.applet_package, "bot_actor_id"), false);
      assert.equal(Object.hasOwn(signed.applet_package, "applet_actor_id"), false);
      const envelope = JSON.parse(readFileSync(statePath, "utf8"));
      assert.equal(envelope.algorithm, "A256GCM");
      assert.equal(envelope.packages, undefined);
      assert.equal(envelope.registryPrivateJwk, undefined);
      assert.equal((await post("/inspect/authoring-reload", {})).status, 200);
    }
    assert.equal(registry.child.exitCode, null);
  } finally {
    if (registry) await registry.stop();
    assert.equal(path.dirname(directory), path.resolve(tmpdir()));
    assert.ok(path.basename(directory).startsWith("cotest-applet-durability-"));
    rmSync(directory, { recursive: true });
  }
});

test("a lost durable sign-package response replays exactly after process restart", { timeout: 30_000 }, async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "cotest-applet-replay-"));
  const keyPath = path.join(directory, "state.key");
  const statePath = path.join(directory, "state.json");
  const key = randomBytes(32);
  writeFileSync(keyPath, key);
  const client = await request.newContext({ timeout: 10_000 });
  let registry;
  const readState = () => {
    const envelope = JSON.parse(readFileSync(statePath, "utf8"));
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
    decipher.setAAD(Buffer.from(envelope.schema, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
    return JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8"));
  };
  try {
    registry = await startRegistry(keyPath, statePath);
    const data = {
      namespace: "durable-replay",
      base_url: "https://applet.fixture.localhost",
    };
    const headers = {
      "Idempotency-Key": "lost-sign-package",
      "x-cotest-drop-sign-package-response": "1",
    };
    let reset = false;
    try {
      await client.post(`${registry.base}/sign-package`, { data, headers, maxRetries: 0 });
    } catch (error) {
      reset = /ECONNRESET|socket hang up/.test(error.message);
    }
    assert.equal(reset, true, registry.logs);
    const state = readState();
    assert.equal(state.packages.length, 1);
    assert.equal(Object.hasOwn(state.packages[0][1], "botActorId"), false);
    assert.equal(state.signedPackageOutcomes.length, 1);
    const original = state.signedPackageOutcomes[0][1].response;
    const durableBytes = readFileSync(statePath);
    await registry.stop();
    registry = await startRegistry(keyPath, statePath);
    const recovered = await client.post(`${registry.base}/sign-package`, { data, headers, maxRetries: 1 });
    assert.equal(recovered.status(), 200);
    assert.deepEqual(await recovered.json(), original);
    assert.equal(readFileSync(statePath).equals(durableBytes), true);

    const conflict = await client.post(`${registry.base}/sign-package`, {
      data: { ...data, namespace: "different-body" }, headers, maxRetries: 1,
    });
    assert.equal(conflict.status(), 409);
    assert.deepEqual(await conflict.json(), { error: "sign_package_idempotency_conflict" });
    assert.equal(readFileSync(statePath).equals(durableBytes), true);

    // Exercise Playwright's same-body reset retry, not only manual recovery.
    const retried = await client.post(`${registry.base}/sign-package`, {
      data: { ...data, namespace: "automatic-retry" },
      headers: { ...headers, "Idempotency-Key": "automatic-sign-package" }, maxRetries: 1,
    });
    assert.equal(retried.status(), 200);
    const retriedBody = await retried.json();
    const afterRetry = readState();
    assert.equal(afterRetry.packages.length, 2);
    assert.equal(afterRetry.signedPackageOutcomes.length, 2);
    assert.deepEqual(afterRetry.signedPackageOutcomes[1][1].response, retriedBody);
    const afterRetryBytes = readFileSync(statePath);
    assert.equal((await client.post(`${registry.base}/inspect/authoring-reload`, { data: {} })).status(), 200);
    const exact = await client.post(`${registry.base}/sign-package`, {
      data: { ...data, namespace: "automatic-retry" },
      headers: { "Idempotency-Key": "automatic-sign-package" },
    });
    assert.deepEqual(await exact.json(), retriedBody);
    assert.equal(readFileSync(statePath).equals(afterRetryBytes), true);
  } finally {
    await client.dispose();
    if (registry) await registry.stop();
    assert.equal(path.dirname(directory), path.resolve(tmpdir()));
    assert.ok(path.basename(directory).startsWith("cotest-applet-replay-"));
    rmSync(directory, { recursive: true });
  }
});

test("real SDK inception returns only after independently encrypted archive custody and survives process restart", { timeout: 30_000 }, async () => {
  assert.ok(process.env.COTEST_WIRE_BIN, "actual cotest-wire must be built for this integration");
  const root = fileURLToPath(new URL("../../../artifacts/tool-tests/", import.meta.url));
  mkdirSync(root, { recursive: true });
  const directory = mkdtempSync(path.join(root, "applet-archive-http-"));
  const authoring = path.join(directory, "authoring.key");
  const state = path.join(directory, "authoring.json");
  const archive = { file: path.join(directory, "archive.json"), key: path.join(directory, "archive.key") };
  writeFileSync(authoring, randomBytes(32), { mode: 0o600 });
  writeFileSync(archive.key, randomBytes(32), { mode: 0o600 });
  initializeManagerArchive(archive.file, archive.key, authoring);
  const history = createEd25519KeyPair("history");
  const next = createEd25519KeyPair("next");
  const control = createEd25519KeyPair("controller");
  const input = {
    base_url: "https://applet.fixture.localhost/", local_id: "archive-http",
    root_seed_b64url: history.privateKey.export({ format: "jwk" }).d,
    next_root_public_key_multibase: encodeEd25519PubkeyMultibase(rawEd25519PublicKey(next.publicKey)),
    control_seed_b64url: control.privateKey.export({ format: "jwk" }).d,
    version_created_at: new Date().toISOString(),
  };
  let registry;
  const post = (base, route, body) => fetch(`${base}${route}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  try {
    registry = await startRegistry(authoring, state, archive);
    assert.equal((await post(registry.base, "/sign-package", {
      namespace: "archive-http", base_url: "https://applet.fixture.localhost",
    })).status, 200, registry.logs);
    const response = await post(registry.base, "/inspect/realm-actor-inception", input);
    assert.equal(response.status, 200, registry.logs);
    const original = await response.json();
    const envelope = JSON.parse(readFileSync(archive.file, "utf8"));
    const decipher = createDecipheriv("aes-256-gcm", readFileSync(archive.key), Buffer.from(envelope.nonce, "base64url"));
    decipher.setAAD(Buffer.from(envelope.schema));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
    const held = JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final(),
    ]).toString()).entries[0];
    assert.ok(!canonicalJson(original).includes(held.backup_private_key_base64url));
    assert.ok(!readFileSync(archive.file, "utf8").includes(held.backup_private_key_base64url));
    const native = spawnSync(process.env.COTEST_WIRE_BIN, ["realm-actor-inception"], {
      windowsHide: true, encoding: "utf8", input: canonicalJson({ ...input, content_backup_private_key_b64url: held.backup_private_key_base64url }),
    });
    assert.equal(native.status, 0, "the physical held key must reproduce the SDK public declaration");
    assert.ok(canonicalJson(JSON.parse(native.stdout)) === canonicalJson(original));
    const before = readFileSync(archive.file);
    await registry.stop();
    registry = await startRegistry(authoring, state, archive);
    const replay = await post(registry.base, "/inspect/realm-actor-inception", input);
    assert.equal(replay.status, 200);
    assert.ok(canonicalJson(await replay.json()) === canonicalJson(original));
    assert.ok(readFileSync(archive.file).equals(before));
    unlinkSync(archive.file);
    assert.equal((await post(registry.base, "/inspect/realm-actor-inception", input)).status, 500);
    assert.equal(existsSync(archive.file), false);
  } finally {
    if (registry) await registry.stop();
    assert.equal(path.dirname(directory), path.resolve(root));
    assert.ok(path.basename(directory).startsWith("applet-archive-http-"));
    rmSync(directory, { recursive: true, force: true });
  }
});

async function startRegistry(keyPath, statePath, archive) {
  let stderr = "";
  const child = spawn(process.execPath, [fileURLToPath(new URL("../mock-applet-registry.mjs", import.meta.url))], {
    windowsHide: true,
    stdio: ["ignore", "ignore", "pipe"],
    env: {
      ...process.env,
      COTEST_COLAND_SERVICE_ID: "ak:did_core:web:station.joint-e2e.local",
      COTEST_COLAND_SERVICE_DID: "did:web:station.joint-e2e.local",
      COTEST_COLAND_SERVICE_SIGNING_KEY: Buffer.alloc(32, 53).toString("base64"),
      MOCK_APPLET_REGISTRY_PORT: "0",
      MOCK_APPLET_REGISTRY_STATE_FILE: statePath,
      MOCK_APPLET_REGISTRY_STATE_KEY_FILE: keyPath,
      MOCK_APPLET_REGISTRY_ARCHIVE_FILE: archive?.file ?? "",
      MOCK_APPLET_REGISTRY_ARCHIVE_KEY_FILE: archive?.key ?? "",
    },
  });
  const closed = once(child, "close");
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  };
  try {
    const base = await new Promise((resolve, reject) => {
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
        const match = stderr.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
        if (match) resolve(match[1]);
      });
      child.once("error", reject);
      child.once("exit", () => reject(new Error("Applet mock exited before readiness")));
    });
    return { child, base, stop, get logs() { return stderr; } };
  } catch (error) {
    await stop();
    throw error;
  }
}
