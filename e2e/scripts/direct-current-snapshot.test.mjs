import assert from "node:assert/strict";
import test from "node:test";
import { registerHooks } from "node:module";

registerHooks({ resolve(specifier, context, next) {
  if (specifier === "./coland-api/request" && context.parentURL.endsWith("/direct-current-snapshot.ts")) {
    return next(new URL("../helpers/coland-api/request.ts", import.meta.url).href, context);
  }
  return next(specifier, context);
} });
const { readCurrentSnapshot } = await import("../helpers/direct-current-snapshot.ts");
const problem = (status, code) => ({ status, type: `https://arkret.org/problems/${code}`, signature: { jws: "must-not-appear-in-errors" } });
const response = (status, body) => ({ status: () => status, json: async () => body });

test("only registered current Snapshot503 waits, preserves the ready object and verifies it once", async () => {
  const ready = { snapshot_id: "fixture-current", marker: { original: true } };
  const replies = [response(503, problem(503, "realm_state_snapshot_unavailable")), response(200, ready)];
  let reads = 0; let verified = 0;
  const result = await readCurrentSnapshot(async () => { reads++; return replies.shift(); }, async body => {
    verified++; assert.equal(body, ready); return body;
  }, { timeoutMs: 1000, retryDelayMs: 0 });
  assert.equal(result, ready); assert.equal(reads, 2); assert.equal(verified, 1);
});

test("denial, unrelated503 and mismatched Problem status fail on their first response without verification", async () => {
  for (const [status, body] of [
    [403, problem(403, "capability_denied")], [404, problem(404, "not_found")],
    [503, problem(503, "temporarily_unavailable")], [503, problem(409, "realm_state_snapshot_unavailable")],
    [500, problem(503, "realm_state_snapshot_unavailable")],
  ]) {
    let reads = 0; let verified = 0;
    await assert.rejects(readCurrentSnapshot(async () => { reads++; return response(status, body); }, async value => {
      verified++; return value;
    }, { timeoutMs: 1000, retryDelayMs: 0 }), error => {
      assert.match(error.message, new RegExp(`HTTP ${status}`));
      assert.equal(error.message.includes("must-not-appear-in-errors"), false); return true;
    });
    assert.equal(reads, 1); assert.equal(verified, 0);
  }
});

test("an invalid200 signed Snapshot is never retried or replaced by a later response", async () => {
  let reads = 0; let verified = 0;
  await assert.rejects(readCurrentSnapshot(async () => { reads++; return response(200, {}); }, async () => {
    verified++; throw new Error("SDK signature verification refused");
  }, { timeoutMs: 1000, retryDelayMs: 0 }), /SDK signature verification refused/);
  assert.equal(reads, 1); assert.equal(verified, 1);
});

test("the readiness deadline retains a503 failure and never emits its original body", async () => {
  let reads = 0;
  await assert.rejects(readCurrentSnapshot(async () => {
    reads++; return response(503, problem(503, "realm_state_snapshot_unavailable"));
  }, async value => value, { timeoutMs: 0, retryDelayMs: 0 }), error => {
    assert.match(error.message, /HTTP 503; code=realm_state_snapshot_unavailable/);
    assert.equal(error.message.includes("must-not-appear-in-errors"), false); return true;
  });
  assert.equal(reads, 1);
});

test("malformed JSON fails before retry or Snapshot verification", async () => {
  let reads = 0; let verified = 0;
  await assert.rejects(readCurrentSnapshot(async () => {
    reads++; return { status: () => 503, json: async () => { throw new Error("malformed current JSON"); } };
  }, async value => { verified++; return value; }), /malformed current JSON/);
  assert.equal(reads, 1); assert.equal(verified, 0);
});

test("an expired readiness interval cannot send another read or replace the last503", async t => {
  let now = 0; let reads = 0;
  t.mock.method(Date, "now", () => now);
  t.mock.method(globalThis, "setTimeout", (done, delay) => { now += delay; done(); return 0; });
  await assert.rejects(readCurrentSnapshot(async () => {
    reads++; return reads === 1 ? response(503, problem(503, "realm_state_snapshot_unavailable")) : response(200, { ready: true });
  }, async value => value, { timeoutMs: 1, retryDelayMs: 500 }), /HTTP 503/);
  assert.equal(reads, 1);
});
