import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sdkEventDerivedIds } from "../helpers/coland-api/wire-client.ts";
import { orderedResponseObservation, assertAcceptedRealmScanAlignment, sessionGrantRotationObservation } from "../helpers/session-transport-observation.ts";

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
  assert.doesNotThrow(() => assertAcceptedRealmScanAlignment("realm", aligned(), unexpectedGenesis));
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
    assert.throws(() => assertAcceptedRealmScanAlignment("realm", scan, unexpectedGenesis), /accepted Realm/);
  }
});

function unexpectedGenesis() { assert.fail("ordinary rows must not invoke the genesis oracle"); }

// These are the formal constructive Event bytes, not an invented Genesis DTO.
// The SDK oracle proves content identity; this test does not claim live admission.
function constructiveGenesisScan() {
  assert.ok(process.env.COTEST_WIRE_BIN && existsSync(process.env.COTEST_WIRE_BIN),
    "COTEST_WIRE_BIN must identify an existing executable; never fall back to Cargo");
  const specRoot = process.env.COTEST_SPEC_ROOT
    ?? resolve(dirname(fileURLToPath(import.meta.url)), "../../../arkret-spec");
  const fixture = JSON.parse(readFileSync(resolve(specRoot,
    "spec/v1/artifacts/fixtures/content-bound-event-id-fixture.json"), "utf8"));
  const vector = fixture.cases.find(item => item.name ===
    "principal_control_realm_id_is_event_derived_and_nonzero_nibble_rejected");
  assert.ok(vector);
  const event = structuredClone(vector.complete_wire_event);
  const derived = sdkEventDerivedIds(event);
  assert.equal(derived.event_id, vector.derived_event_id);
  assert.equal(derived.realm_id, vector.derived_realm_id);
  return {
    realm: vector.derived_realm_id,
    scan: {
      truncated: false,
      events: [event],
      commits: [{ commit_id: "observed-c0", event_ref: event.event_id,
        realm_id: vector.derived_realm_id,
        stream_ref: { kind: "realm", realm_id: vector.derived_realm_id },
        stream_position: 0, previous_commit_ref: null }],
    },
  };
}

test("formal constructive genesis omits realm_id and matches SDK-derived identity", () => {
  const { realm, scan } = constructiveGenesisScan();
  assert.equal(Object.hasOwn(scan.events[0], "realm_id"), false);
  assert.doesNotThrow(() => assertAcceptedRealmScanAlignment(realm, scan, sdkEventDerivedIds));
});

test("forged genesis coordinates and Event refs fail without weakening ordinary alignment", () => {
  const original = constructiveGenesisScan();
  for (const corrupt of [
    ({ realm, scan }) => { scan.events[0].realm_id = realm; },
    ({ scan }) => { scan.events[0].realm_id = null; },
    ({ realm, scan }) => { scan.events[0].scope_ref = { kind: "realm", realm_id: realm }; },
    ({ scan }) => { scan.events[0].event_id = "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      scan.commits[0].event_ref = scan.events[0].event_id; },
    ({ scan }) => { scan.commits[0].event_ref = "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; },
    (fixture) => { fixture.realm = "ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      fixture.scan.commits[0].realm_id = fixture.realm;
      fixture.scan.commits[0].stream_ref.realm_id = fixture.realm; },
    ({ scan }) => { scan.commits[0].previous_commit_ref = "not-genesis"; },
    ({ scan }) => { scan.events.push(structuredClone(scan.events[0]));
      scan.commits.push({ ...scan.commits[0], commit_id: "observed-c1", stream_position: 1,
        previous_commit_ref: scan.commits[0].commit_id }); },
    ({ realm, scan }) => { scan.events.push({ event_id: "ordinary", kind: "ak.message.create" });
      scan.commits.push({ commit_id: "observed-c1", event_ref: "ordinary", realm_id: realm,
        stream_ref: { kind: "realm", realm_id: realm }, stream_position: 1,
        previous_commit_ref: scan.commits[0].commit_id }); },
  ]) {
    const changed = structuredClone(original);
    corrupt(changed);
    assert.throws(() => assertAcceptedRealmScanAlignment(changed.realm, changed.scan, sdkEventDerivedIds),
      /accepted Realm/);
  }
});

// Opaque tool-only strings exercise attribution; no JWT validation is simulated.
const holder = { principal_id: "principal", station_id: "station" };
function refreshBody(previous, successor, grant) {
  return { account_id: holder, previous_session_grant_id: previous,
    session_grant_id: successor, session_grant: grant };
}

test("concurrent refresh cannot substitute another pair's viewer denial and recovery", () => {
  const tracker = sessionGrantRotationObservation(holder);
  tracker.refresh("DPoP target-old", refreshBody("target-before", "target-after", "target-new"));
  tracker.refresh("DPoP other-old", refreshBody("other-before", "other-after", "other-new"));
  tracker.viewer(401, "DPoP other-old", "unauthenticated");
  tracker.viewer(200, "DPoP other-new");
  assert.equal(tracker.recovered("other-before", "other-after"), true);
  assert.equal(tracker.recovered("target-before", "target-after"), false);
  assert.equal(tracker.matchesPredecessor("target-before", "target-after", "DPoP other-old"), false);
  tracker.viewer(401, "DPoP target-old", "unauthenticated");
  tracker.viewer(200, "DPoP other-new");
  assert.equal(tracker.recovered("target-before", "target-after"), false);
  tracker.viewer(200, "DPoP target-new");
  assert.equal(tracker.recovered("target-before", "target-after"), true);
  assert.equal(tracker.matchesPredecessor("target-before", "target-after", "DPoP target-old"), true);
  assert.equal(tracker.matchesPredecessor("target-before", "other-after", "DPoP target-old"), false);
});

test("wrong grant, wrong problem and successor before predecessor denial do not satisfy recovery", () => {
  const tracker = sessionGrantRotationObservation(holder);
  tracker.refresh("DPoP old", refreshBody("before", "after", "new"));
  tracker.viewer(200, "DPoP new");
  tracker.viewer(401, "DPoP wrong", "unauthenticated");
  tracker.viewer(401, "DPoP old", "capability_denied");
  tracker.viewer(200, "DPoP new");
  assert.equal(tracker.recovered("before", "after"), false);
  tracker.viewer(401, "DPoP old", "unauthenticated");
  assert.equal(tracker.recovered("before", "after"), false);
  tracker.viewer(200, "DPoP wrong");
  assert.equal(tracker.recovered("before", "after"), false);
  tracker.viewer(200, "DPoP new");
  assert.equal(tracker.recovered("before", "after"), true);
});

test("refresh attribution rejects different complete holders, missing ids and changed opaque bindings", () => {
  for (const mutate of [
    body => { body.account_id = { ...holder, principal_id: "other" }; },
    body => { body.account_id = { ...holder, station_id: "other" }; },
    body => { delete body.previous_session_grant_id; },
    body => { body.session_grant_id = body.previous_session_grant_id; },
    body => { delete body.session_grant; },
  ]) {
    const tracker = sessionGrantRotationObservation(holder);
    const body = refreshBody("before", "after", "new");
    mutate(body);
    assert.throws(() => tracker.refresh("DPoP old", body), /expected holder and distinct grant pair/);
    assert.equal(tracker.recovered("before", "after"), false);
  }
  const tracker = sessionGrantRotationObservation(holder);
  tracker.refresh("DPoP old", refreshBody("before", "after", "new"));
  assert.throws(() => tracker.refresh("DPoP substituted", refreshBody("before", "after", "new")),
    /opaque authorization binding/);
  assert.throws(() => tracker.refresh("DPoP old", refreshBody("before", "after", "substituted")),
    /opaque authorization binding/);
});
