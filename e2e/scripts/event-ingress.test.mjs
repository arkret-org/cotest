import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeIngressEvents } from "../helpers/event-ingress.ts";

test("atomic MLS submission exposes its Commit once and no Welcome Event", () => {
  const commit = { event_id: "commit", kind: "ak.mls.commit", realm_id: "realm" };
  const body = {
    commit_event: commit,
    welcomes: [{ welcome_id: "delivery", commit_event_ref: "commit" }],
    idempotency_key: "01904100-0000-7000-8000-000000002601",
  };
  assert.deepEqual(decodeIngressEvents(JSON.stringify(body)), [commit]);
  assert.deepEqual(decodeIngressEvents(JSON.stringify({ ...body, welcomes: [] })), [commit]);
});

test("malformed MLS carrier fails instead of hiding a recovery request", () => {
  const commit_event = { kind: "ak.mls.commit" };
  for (const body of [
    { commit_event },
    { commit_event, welcomes: {}, idempotency_key: "key" },
    { commit_event: { kind: "ak.mls.welcome" }, welcomes: [], idempotency_key: "key" },
  ]) {
    assert.throws(() => decodeIngressEvents(JSON.stringify(body)), /MlsCommitSubmission/);
  }
});

test("ordinary and founding submissions retain their signed Event order", () => {
  const events = [{ event: { kind: "ak.realm.create" } }, { event: { kind: "ak.member.state" } }];
  assert.deepEqual(decodeIngressEvents(JSON.stringify(events[0])), [events[0].event]);
  assert.deepEqual(
    decodeIngressEvents(JSON.stringify({ unit_kind: "ordinary_realm_bootstrap", events })),
    events.map(({ event }) => event),
  );
  assert.throws(() => decodeIngressEvents(JSON.stringify({ events })), /unit_kind/);
});
