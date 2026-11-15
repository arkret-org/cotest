import assert from "node:assert/strict";
import test from "node:test";
import { contentHistoryProof } from "../helpers/content-history-proof.ts";

// Synthetic public bindings exercise this fixture guard, not SDK signature,
// native authorization, HPKE or AEAD validation, which stay on their real path.
function fixture() {
  const issuer = { kind: "account", id: "issuer" };
  const recipient = { kind: "account", id: "reader" };
  const source = { event_id: "source", kind: "ak.space.create", realm_id: "realm" };
  const cut = { event_id: "source", commit_id: "commit-source", stream_position: "9007199254740992",
    stream_ref: { kind: "realm", realm_id: "realm" } };
  const payload = { recipient: { actor_id: recipient, endpoint: { device_id: "device" }, authorization_event_ref: "authorization" },
    recipient_hpke_key_base64url: "synthetic-key", history_cut: cut, expires_at: "2026-11-15T01:15:00Z" };
  const request = { event_id: "request", kind: "ak.mls.history_request", realm_id: "realm",
    actor_id: recipient, created_at: "2026-11-15T01:00:00Z", payload };
  const grant = { event_id: "grant", kind: "ak.mls.history_grant", realm_id: "realm", actor_id: issuer,
    payload: { ...structuredClone(payload), recipient_key_event_ref: "request", entries: [{ selector: {
      kind: "content_key", source_event_ref: "source", content_path: "/payload/object/encrypted_metadata",
    } }] } };
  const scan = { truncated: false, events: [source, request, grant], eventSlots: [source, request, grant], commits: [
    { commit_id: "commit-source", stream_position: "9007199254740992", committed_at: "2026-11-15T00:59:59Z" },
    { commit_id: "commit-request", stream_position: "9007199254740993", committed_at: "2026-11-15T01:00:00Z" },
    { commit_id: "commit-grant", stream_position: "9007199254740994", committed_at: "2026-11-15T01:00:01Z" },
  ] };
  return { scan, source, request, grant, expected: { realmId: "realm", sourceEventId: "source", sourceKind: "ak.space.create" as const,
    issuerActor: issuer, recipientActor: recipient, recipientDeviceId: "device" } };
}

test("an exact Board grant binds its accepted source, request, endpoint and cut without losing u64 precision", () => {
  const f = fixture();
  const proof = contentHistoryProof(f.scan, f.expected)!;
  assert.equal(proof.source, f.source);
  assert.equal(proof.request, f.request);
  assert.equal(proof.grant, f.grant);
});

test("a Board metadata key does not prove disclosure of a different List or Card", () => {
  const f = fixture();
  const list = { ...f.source, event_id: "list" };
  const card = { ...f.source, event_id: "card", kind: "ak.strand.create" };
  f.scan.events.push(list, card);
  assert.equal(contentHistoryProof(f.scan, { ...f.expected, sourceEventId: "list" }), undefined);
  assert.equal(contentHistoryProof(f.scan, { ...f.expected, sourceEventId: "card", sourceKind: "ak.strand.create" }), undefined);
});

test("an absent original, wrong key selector or another recipient cannot establish the Board proof", () => {
  for (const alter of [
    f => { f.scan.events.splice(0, 1); },
    f => { f.scan.events.splice(1, 1); },
    f => { f.grant.payload.entries[0].selector.source_event_ref = "other-source"; },
    f => { f.grant.payload.entries[0].selector.content_path = "/payload/encrypted_content"; },
    f => { f.grant.payload.recipient.endpoint.device_id = "other-device"; },
  ] satisfies Array<(f: ReturnType<typeof fixture>) => void>) {
    const f = fixture(); alter(f);
    assert.equal(contentHistoryProof(f.scan, f.expected), undefined);
  }
});

test("wrong request bindings, Realm, author, cut or missing accepted Commit slots fail closed", () => {
  for (const alter of [
    f => { f.scan.truncated = true; },
    f => { f.grant.realm_id = "other-realm"; },
    f => { f.grant.actor_id = { kind: "account", id: "other-issuer" }; },
    f => { f.grant.payload.recipient.authorization_event_ref = "other-authorization"; },
    f => { f.grant.payload.recipient_hpke_key_base64url = "other-key"; },
    f => { f.grant.payload.history_cut.commit_id = "other-commit"; },
    f => { f.request.payload.history_cut.stream_ref.realm_id = "other-realm"; f.grant.payload.history_cut.stream_ref.realm_id = "other-realm"; },
    f => { f.scan.eventSlots.splice(1, 1); },
    f => { f.scan.commits[0].stream_position = "9007199254740993"; },
    f => { f.scan.commits[1].stream_position = "9007199254740992"; },
  ] satisfies Array<(f: ReturnType<typeof fixture>) => void>) {
    const f = fixture(); alter(f);
    assert.throws(() => contentHistoryProof(f.scan, f.expected));
  }
});

test("an expired or overlong original request cannot establish valid grant issuance", () => {
  for (const alter of [
    f => { f.request.payload.expires_at = f.grant.payload.expires_at = "2026-11-15T01:15:01Z"; },
    f => { f.scan.commits[2].committed_at = "2026-11-15T01:15:00Z"; },
    f => { f.scan.commits[2].committed_at = "invalid-time"; },
  ] satisfies Array<(f: ReturnType<typeof fixture>) => void>) {
    const f = fixture(); alter(f);
    assert.throws(() => contentHistoryProof(f.scan, f.expected), /original request TTL/);
  }
});
