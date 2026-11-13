import assert from "node:assert/strict";
import test from "node:test";
import { nativeSearchEvidence } from "../helpers/native-search-evidence.ts";

test("retained search evidence preserves source coordinates without signed or plaintext values", () => {
  const commit = { commit_id: "commit-1", stream_ref: { kind: "realm", realm_id: "realm-1" },
    stream_position: 7, signature: "synthetic-signature-stays-in-memory" };
  const original = { account_id: { principal_id: "reader", station_id: "station" }, recheck_at: null,
    view: { query: "synthetic-private-query", next_cursor: null, results: [{ event_id: "event-1",
      covering_commit: commit, source_commit: commit,
      content: { body: "synthetic-private-message" }, secret: "synthetic-future-private-field" }] } };
  const before = JSON.stringify(original);
  const evidence = nativeSearchEvidence(original);
  assert.equal(evidence.result_count, 1);
  assert.equal(evidence.results[0]!.event_id, "event-1");
  assert.deepEqual(evidence.results[0]!.covering_commit, {
    commit_id: "commit-1", stream_ref: commit.stream_ref, stream_position: 7,
  });
  assert.deepEqual(evidence.results[0]!.source_commit, evidence.results[0]!.covering_commit);
  for (const value of [commit.signature, original.view.query, original.view.results[0]!.content.body,
    original.view.results[0]!.secret]) assert.ok(!JSON.stringify(evidence).includes(value));
  assert.equal(JSON.stringify(original), before, "the original protocol result remains available to assertions");
});

test("search evidence fingerprints distinguish content without exporting it", () => {
  const observation = { account_id: { principal_id: "reader", station_id: "station" }, recheck_at: null,
    view: { query: "query", next_cursor: null, results: [{ content: { body: "first" } }] } };
  const first = nativeSearchEvidence(observation);
  observation.view.results[0]!.content.body = "second";
  const second = nativeSearchEvidence(observation);
  assert.equal(first.query_fingerprint, second.query_fingerprint);
  assert.notEqual(first.results[0]!.content_fingerprint, second.results[0]!.content_fingerprint);
});
