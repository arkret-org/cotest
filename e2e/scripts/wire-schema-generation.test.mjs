import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, mkdirSync, copyFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validateTargetNames } from "./generate-wire-types.mjs";

test("public mirrors cannot restore generic Row names", () => {
  assert.throws(() => validateTargetNames([{ typeName: "ContactRow" }]), /generic Row/);
  assert.doesNotThrow(() => validateTargetNames([{ typeName: "ContactView" }, { typeName: "CurrentMimiRoomBinding" }]));
});

test("required normative schemas cannot be silently skipped", () => {
  const tempBase = realpathSync(tmpdir());
  const root = mkdtempSync(join(tempBase, "arkret-row-schema-gate-"));
  try {
    const script = join(root, "cotest", "e2e", "scripts", "generate-wire-types.mjs");
    mkdirSync(dirname(script), { recursive: true });
    copyFileSync(fileURLToPath(new URL("./generate-wire-types.mjs", import.meta.url)), script);
    const result = spawnSync(process.execPath, [script, "--check", "--require-spec"], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /absent/);
  } finally {
    const verifiedRoot = realpathSync(root);
    assert.equal(dirname(verifiedRoot), tempBase);
    assert.match(basename(verifiedRoot), /^arkret-row-schema-gate-/);
    rmSync(verifiedRoot, { recursive: true, force: true });
  }
});
