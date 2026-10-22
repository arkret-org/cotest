import assert from "node:assert/strict";
import test from "node:test";
import { orderedResponseObservation, assertAcceptedRealmScanAlignment } from "../helpers/session-transport-observation.ts";

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test("slow refresh headers cannot be overtaken by old401 or successor200 observations", async () => {
  const refreshHeaders = deferred();
  const oldHeaders = deferred();
  const seen = [];
  let retired = false;
  const observer = orderedResponseObservation(async response => {
    await response.headers;
    if (response.kind === "refresh200") retired = true;
    if (response.kind === "old401") assert.equal(retired, true);
    seen.push(response.kind);
  }, () => assert.fail("observation unexpectedly failed"));
  const refresh = { kind: "refresh200", headers: refreshHeaders.promise };
  const old = { kind: "old401", headers: oldHeaders.promise };
  observer.enqueue(refresh);
  observer.enqueue(old);
  observer.enqueue({ kind: "successor200", headers: Promise.resolve() });
  let inspected = false;
  const classification = observer.observed(old).then(() => { inspected = true; });
  oldHeaders.resolve();
  await Promise.resolve();
  await Promise.resolve();
  assert.deepEqual(seen, []);
  assert.equal(inspected, false);
  refreshHeaders.resolve();
  await classification;
  await observer.settled();
  assert.deepEqual(seen, ["refresh200", "old401", "successor200"]);
  assert.equal(inspected, true);
});

test("an observation failure is recorded and does not silently drop the next response", async () => {
  let failures = 0;
  const seen = [];
  const observer = orderedResponseObservation(async response => {
    if (response.failed) throw new Error("body unavailable");
    seen.push(response.id);
  }, () => { failures += 1; });
  observer.enqueue({ failed: true });
  observer.enqueue({ id: "following" });
  await observer.settled();
  assert.equal(failures, 1);
  assert.deepEqual(seen, ["following"]);
  await assert.rejects(observer.observed({}), /not registered/);
});

// These symbolic rows test observation invariants only. They do not pretend to
// be signed/accepted authority material or confer live protocol credit.
function aligned() {
  return {
    truncated: false,
    events: [{ event_id: "e0", realm_id: "realm" }, { event_id: "e1", realm_id: "realm" }],
    commits: [
      { commit_id: "c0", event_ref: "e0", realm_id: "realm", stream_ref: { realm_id: "realm", kind: "realm" }, stream_position: 0, previous_commit_ref: null },
      { commit_id: "c1", event_ref: "e1", realm_id: "realm", stream_ref: { kind: "realm", realm_id: "realm" }, stream_position: 1, previous_commit_ref: "c0" },
    ],
  };
}

test("exact Event/Commit scan accepts key-order-independent stream coordinates", () => {
  assert.doesNotThrow(() => assertAcceptedRealmScanAlignment("realm", aligned()));
});

test("same-length swapped, duplicated, foreign and noncontinuous scan pairs fail closed", () => {
  for (const corrupt of [
    scan => scan.commits.reverse(),
    scan => { scan.commits[1].event_ref = "e0"; },
    scan => { scan.commits[1].commit_id = "c0"; },
    scan => { scan.commits[1].realm_id = "foreign"; },
    scan => { scan.commits[1].stream_ref.realm_id = "foreign"; },
    scan => { scan.commits[1].stream_position = 2; },
    scan => { scan.commits[1].previous_commit_ref = "foreign"; },
    scan => { scan.truncated = true; },
    scan => { scan.commits.pop(); },
  ]) {
    const scan = aligned();
    corrupt(scan);
    assert.throws(() => assertAcceptedRealmScanAlignment("realm", scan), /accepted Realm/);
  }
});
