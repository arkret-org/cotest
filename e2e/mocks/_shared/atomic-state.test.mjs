import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { replaceStateFileSync } from "./atomic-state.mjs";

test("transient Windows replacement lock preserves the previous state until success", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "cotest-atomic-state-"));
  try {
    const source = path.join(directory, "pending");
    const destination = path.join(directory, "current");
    writeFileSync(source, "new ciphertext");
    writeFileSync(destination, "previous ciphertext");
    let attempts = 0;
    const pauses = [];
    replaceStateFileSync(source, destination, {
      rename(from, to) {
        assert.equal(readFileSync(to, "utf8"), "previous ciphertext");
        if (++attempts <= 3) throw Object.assign(new Error("sharing violation"), { code: "EPERM" });
        renameSync(from, to);
      },
      pause(milliseconds) { pauses.push(milliseconds); },
    });
    assert.equal(readFileSync(destination, "utf8"), "new ciphertext");
    assert.deepEqual(pauses, [20, 40, 80]);
  } finally {
    assert.equal(path.dirname(directory), path.resolve(tmpdir()));
    assert.ok(path.basename(directory).startsWith("cotest-atomic-state-"));
    rmSync(directory, { recursive: true });
  }
});

test("permanent replacement failure is bounded and remains an error", () => {
  let attempts = 0;
  const failure = Object.assign(new Error("still locked"), { code: "EPERM" });
  assert.throws(() => replaceStateFileSync("pending", "current", {
    rename() { attempts += 1; throw failure; },
    pause() {},
  }), error => error === failure);
  assert.equal(attempts, 10);
});

test("non-transient filesystem errors fail immediately", () => {
  const failure = Object.assign(new Error("missing state"), { code: "ENOENT" });
  assert.throws(() => replaceStateFileSync("pending", "current", {
    rename() { throw failure; },
    pause() { assert.fail("must not retry"); },
  }), error => error === failure);
});
