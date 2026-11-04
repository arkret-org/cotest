import assert from "node:assert/strict";
import test from "node:test";
import { waitForAcceptedDirectCut } from "../helpers/direct-accepted-cut.ts";

const accepted = { stream_ref: { kind: "realm", realm_id: "fixture-direct" },
  stream_position: 18, commit_id: "fixture-original-commit" };

test("already installed original cut returns the exact authenticated observation", async () => {
  let reads = 0;
  const observed = structuredClone(accepted);
  const result = await waitForAcceptedDirectCut(async () => { reads++; return observed; }, accepted);
  assert.equal(result, observed);
  assert.equal(reads, 1);
});

test("an online peer does not release the Signal baseline while its accepted Watch is behind", async () => {
  const lagging = { ...accepted, stream_position: 17, commit_id: "fixture-predecessor" };
  const observations = [lagging, lagging, accepted];
  const trace = [];
  let reads = 0;
  const peerOnline = true;
  assert.equal(peerOnline, true);
  const cut = await waitForAcceptedDirectCut(async () => {
    reads++;
    const current = observations.shift();
    trace.push(current.commit_id);
    return current.commit_id === accepted.commit_id ? current : undefined;
  }, accepted, { timeoutMs: 1000, retryDelayMs: 0 });
  trace.push("measure-Signal-no-write-boundary");
  assert.equal(cut, accepted);
  assert.equal(reads, 3);
  assert.deepEqual(trace, ["fixture-predecessor", "fixture-predecessor", "fixture-original-commit",
    "measure-Signal-no-write-boundary"]);
});

test("fork, wrong stream, wrong position or extra fields fail without retry or exposing the response", async () => {
  for (const observed of [
    { ...accepted, commit_id: "another-commit" },
    { ...accepted, stream_ref: { kind: "realm", realm_id: "another-direct" } },
    { ...accepted, stream_position: 19 },
    { ...accepted, jws: "must-not-be-logged" },
  ]) {
    let reads = 0;
    await assert.rejects(waitForAcceptedDirectCut(async () => {
      reads++; return observed;
    }, accepted), error => {
      assert.match(error.message, /differs from the acknowledged Commit/);
      assert.equal(error.message.includes("must-not-be-logged"), false);
      return true;
    });
    assert.equal(reads, 1);
  }
});

test("denial or transport failure is never converted into readiness retry", async () => {
  let reads = 0;
  const denial = new Error("HTTP 403");
  await assert.rejects(waitForAcceptedDirectCut(async () => {
    reads++; throw denial;
  }, accepted), error => error === denial);
  assert.equal(reads, 1);
});

test("an absent original cut at its deadline fails and never takes a later successful read", async t => {
  let now = 0;
  let reads = 0;
  t.mock.method(Date, "now", () => now);
  t.mock.method(globalThis, "setTimeout", done => { now += 10; done(); return 0; });
  await assert.rejects(waitForAcceptedDirectCut(async () => {
    reads++; return reads === 1 ? undefined : accepted;
  }, accepted, { timeoutMs: 1, retryDelayMs: 10 }), /readiness deadline/);
  assert.equal(reads, 1);
});

test("a non-Realm or invalid acknowledged position fails before any observation", async () => {
  for (const invalid of [
    { ...accepted, stream_ref: { kind: "circle", realm_id: "fixture-direct", circle_id: "circle" } },
    { ...accepted, stream_position: -1 },
  ]) {
    let reads = 0;
    await assert.rejects(waitForAcceptedDirectCut(async () => { reads++; return accepted; }, invalid), /acknowledged Realm Commit/);
    assert.equal(reads, 0);
  }
});
