import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createDecipheriv, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { request } from "@playwright/test";

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

async function startRegistry(keyPath, statePath) {
  let stderr = "";
  const child = spawn(process.execPath, [fileURLToPath(new URL("../mock-applet-registry.mjs", import.meta.url))], {
    windowsHide: true,
    stdio: ["ignore", "ignore", "pipe"],
    env: {
      ...process.env,
      COTEST_SOLAND_SERVICE_ID: "ak:did_core:web:station.joint-e2e.local",
      COTEST_SOLAND_SERVICE_DID: "did:web:station.joint-e2e.local",
      COTEST_SOLAND_SERVICE_SIGNING_KEY: Buffer.alloc(32, 53).toString("base64"),
      MOCK_APPLET_REGISTRY_PORT: "0",
      MOCK_APPLET_REGISTRY_STATE_FILE: statePath,
      MOCK_APPLET_REGISTRY_STATE_KEY_FILE: keyPath,
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
