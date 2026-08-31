import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("Applet package without optional Bot evidence persists encrypted and reloads", { timeout: 30_000 }, async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "cotest-applet-durability-"));
  const keyPath = path.join(directory, "state.key");
  const statePath = path.join(directory, "state.json");
  writeFileSync(keyPath, randomBytes(32));
  const child = spawn(process.execPath, [fileURLToPath(new URL("../mock-applet-registry.mjs", import.meta.url))], {
    windowsHide: true,
    stdio: ["ignore", "ignore", "pipe"],
    env: {
      ...process.env,
      MOCK_APPLET_REGISTRY_PORT: "0",
      MOCK_APPLET_REGISTRY_STATE_FILE: statePath,
      MOCK_APPLET_REGISTRY_STATE_KEY_FILE: keyPath,
    },
  });
  const closed = once(child, "close");
  try {
    const base = await new Promise((resolve, reject) => {
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
        const match = stderr.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
        if (match) resolve(match[1]);
      });
      child.once("error", reject);
      child.once("exit", () => reject(new Error("Applet mock exited before readiness")));
    });
    const post = (route, body) => fetch(`${base}${route}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    for (const namespace of ["before-reload", "after-reload"]) {
      const response = await post("/sign-package", { namespace });
      assert.equal(response.status, 200);
      const signed = await response.json();
      assert.match(signed.package_digest, /^sha256:[0-9a-f]{64}$/);
      const envelope = JSON.parse(readFileSync(statePath, "utf8"));
      assert.equal(envelope.algorithm, "A256GCM");
      assert.equal(envelope.packages, undefined);
      assert.equal(envelope.registryPrivateJwk, undefined);
      assert.equal((await post("/inspect/authoring-reload", {})).status, 200);
    }
    assert.equal(child.exitCode, null);
  } finally {
    child.kill();
    await closed;
    assert.equal(path.dirname(directory), path.resolve(tmpdir()));
    assert.ok(path.basename(directory).startsWith("cotest-applet-durability-"));
    rmSync(directory, { recursive: true });
  }
});
