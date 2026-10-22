import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { setImmediate } from "node:timers/promises";
import test from "node:test";
import { observeBrowserSessionRefresh } from "./browser-session-refresh.ts";

// Only fixture bookkeeping is mocked. Live scenarios still require the issuer.
const accountId = { principal_id: "alice", station_id: "station" };
const holderJwk = { kty: "OKP", crv: "Ed25519", x: "holder" };
const options = { issuerUrl: "https://issuer.test", accountId, deviceId: "device",
  audience: "station", grantedScope: ["read", "write"], holderJwk,
  initialCredential: "initial", initialGrantId: "grant-0" };
const expiry = new Date(Date.now() + 3600000).toISOString();
function setup() {
  const page = new EventEmitter(); return { page, tracker: observeBrowserSessionRefresh(page, options) };
}
function emit(page, predecessor = "initial", credential = "next", extra = {}) {
  const input = { grant_jwt: predecessor, device_id: "device", audience_id: "station", ...extra.input };
  const body = { account_id: accountId, device_id: "device", audience_id: "station",
    granted_scope: ["read", "write"], session_public_key: JSON.stringify(holderJwk),
    session_grant: credential, session_grant_id: "grant-1", previous_session_grant_id: "grant-0",
    expires_at: expiry, ...extra.outcome };
  page.emit("response", {
    request: () => ({ method: () => "POST", url: () =>
      `${extra.origin ?? options.issuerUrl}/_arkret/gate/account/session-grants/refresh`, postDataJSON: () => input }),
    status: () => extra.status ?? 200, json: () => extra.body ?? Promise.resolve(body),
  });
  return body;
}
test("real successful refresh can replace the fixture credential without another login", async () => {
  const { page, tracker } = setup(); emit(page); await setImmediate(); assert.equal(tracker.credential(), "next");
  assert.equal(tracker.refreshCount(), 1);
});
test("foreign issuer and failed refresh cannot change the credential", async () => {
  for (const extra of [{ origin: "https://other.test" }, { status: 401 }]) {
    const { page, tracker } = setup(); emit(page, "initial", "bad", extra); await setImmediate();
    assert.equal(tracker.credential(), "initial");
  }
});
test("Account, Device, audience, scope and holder changes are refused", async () => {
  for (const outcome of [{ account_id: { ...accountId, station_id: "other" } },
    { account_id: { ...accountId, principal_id: "bob" } }, { device_id: "other" },
    { audience_id: "other" }, { granted_scope: ["admin"] },
    { session_public_key: JSON.stringify({ ...holderJwk, x: "other" }) }, { expires_at: "2000-01-01T00:00:00Z" }]) {
    const { page, tracker } = setup(); emit(page, "initial", "bad", { outcome }); await setImmediate();
    assert.equal(tracker.credential(), "initial");
  }
});
test("an unrelated chain cannot replace this browser fixture", async () => {
  const { page, tracker } = setup(); emit(page, "unrelated"); await setImmediate();
  assert.equal(tracker.credential(), "initial");
});
test("out-of-order decoding still follows the original exact predecessor chain", async () => {
  const { page, tracker } = setup();
  emit(page, "next", "latest", { outcome: { previous_session_grant_id: "grant-1", session_grant_id: "grant-2" } });
  await setImmediate(); assert.equal(tracker.credential(), "initial");
  emit(page); await setImmediate(); assert.equal(tracker.credential(), "latest");
  assert.equal(tracker.refreshCount(), 2);
  emit(page); await setImmediate(); assert.equal(tracker.credential(), "latest");
});
test("a fork of the same refresh predecessor fails closed", async () => {
  const { page, tracker } = setup(); emit(page); await setImmediate(); emit(page, "initial", "fork"); await setImmediate();
  assert.throws(() => tracker.credential(), /unavailable/);
});
test("an incorrect previous grant id cannot be installed", async () => {
  const { page, tracker } = setup(); emit(page, "initial", "bad", { outcome: { previous_session_grant_id: "wrong" } });
  await setImmediate(); assert.throws(() => tracker.credential(), /unavailable/);
});
test("close discards pending credentials and stops delayed responses", async () => {
  const { page, tracker } = setup(); let release;
  const body = new Promise(resolve => { release = resolve; });
  const outcome = emit(page, "initial", "next", { body }); page.emit("close"); release(outcome); await setImmediate();
  assert.equal(page.listenerCount("response"), 0); assert.throws(() => tracker.credential(), /unavailable/);
});
