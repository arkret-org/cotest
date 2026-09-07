import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { forbiddenWireScanner } from "../helpers/forbidden-wire.ts";

const artifacts = fileURLToPath(new URL("../../../arkret-spec/spec/v1/artifacts", import.meta.url));
const scanner = forbiddenWireScanner(artifacts);

test("Message object and signed create payload have distinct field domains", () => {
  assert.equal(scanner.scan({ track_name: "discussion" }, "materialized_object", "message.schema.json")[0].id, "track_name");
  assert.deepEqual(scanner.scanEvent({ kind: "ak.message.create", payload: { track_name: "discussion", strand_id: "fixture", content: { kind: "ak.content.text", body: "hello" } } }), []);
  assert.deepEqual(scanner.scan({ metadata: { track_name: "custom" } }, "materialized_object", "message.schema.json"), []);
  assert.deepEqual(scanner.scanEvent({ kind: "ak.message.create", payload: { track_name: "discussion", content: { body: "ak:notif:quoted text" } } }), []);
  assert.equal(scanner.scan("ak:notif:old", "typed_id_value", "*")[0].id, "ak:notif:");
});

test("real create object wrapper and nested KDF pointer are enforced", () => {
  const hits = scanner.scanEvent({ kind: "ak.strand.create", payload: { object: { metadata: { fields: { status: "closed" } } } } });
  assert.ok(hits.some(v => v.id === "metadata.fields.status"));
  assert.equal(scanner.scan({ encryption: { kdf: { params: { hash: "SHA256" } } } }, "schema_instance", "key-backup.schema.json")[0].id, "hash#key_backup_kdf_params");
  assert.deepEqual(scanner.scan({ other: { hash: "SHA256" } }, "schema_instance", "key-backup.schema.json"), []);
});

test("patch descendants and explicit aggregate matchers are checked", () => {
  for (const patch of [
    { "metadata.fields.assignee.detail": "x" },
    { metadata: { fields: { assignee: "x" } } },
    { "metadata.fields": { $op: "set", value: { assignee: "x" } } },
  ]) assert.ok(scanner.scanEvent({ kind: "ak.strand.update", payload: { patch } }).some(v => v.id === "patch:metadata.fields.assignee"));
  assert.deepEqual(scanner.scanEvent({ kind: "ak.strand.update", payload: { patch: { metadata: { fields: { jira_status: "custom" } } } } }), []);
  assert.ok(scanner.scanEvent({ kind: "ak.strand.update", payload: { patch: { metadata: { fields: { status: "closed" } } } } }).some(v => v.id === "metadata.fields.status"));
  assert.ok(scanner.scan({ allowed_circle_refs: [] }, "schema_instance", "grant-constraint.schema.json").some(v => v.id === "grant_constraint_single_kind_refs_to_ids"));
  assert.deepEqual(scanner.scan({ type: "about:blank" }, "http_response", "http-problem-details.schema.json"), []);
});
