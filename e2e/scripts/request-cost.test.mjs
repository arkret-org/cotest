// Run from e2e/: node --test scripts/request-cost.test.mjs
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { observeRequestCost } from "../helpers/request-cost.ts";

function blankPage() {
  const page = new EventEmitter(); page.url = () => "about:blank"; return page;
}

function request(path, sizes) {
  return { url: () => `https://station.test${path}`, method: () => "GET",
    sizes: async () => { if (sizes instanceof Error) throw sizes; return sizes; },
    response: async () => ({ ok: () => true, headerValue: async () => "application/json",
      json: async () => ({ spaces: [{ title: "private metadata must not escape" }] }) }) };
}

test("unknown sizes remain null and evidence contains no response content", async () => {
  const page = blankPage();
  const cost = observeRequestCost(page);
  const read = request("/_arkret/self/realms/one/spaces", new Error("not available"));
  page.emit("request", read); page.emit("requestfinished", read);
  const value = await cost.snapshot();
  assert.equal(value.http[0].response_body_bytes, null);
  assert.equal(value.http[0].rows, 1);
  assert.equal(JSON.stringify(value).includes("private metadata"), false);
  const aborted = request("/_arkret/self/realms/other/spaces", {
    responseBodySize: 0, responseHeadersSize: 0, requestBodySize: 0, requestHeadersSize: 0 });
  page.emit("request", aborted); page.emit("requestfailed", aborted);
  const failed = (await cost.snapshot()).http[1];
  assert.equal(failed.failed, true);
  assert.equal(failed.response_body_bytes, null);
  assert.equal(failed.request_body_bytes, null);
  cost.dispose();
});

test("inventory concurrency belongs to each Realm and measured zero stays zero", async () => {
  const page = blankPage();
  const cost = observeRequestCost(page);
  const sizes = { responseBodySize: 0, responseHeadersSize: 80, requestBodySize: 0, requestHeadersSize: 90 };
  const one = request("/_arkret/self/realms/one/spaces", sizes);
  const two = request("/_arkret/self/realms/two/spaces", sizes);
  const duplicate = request("/_arkret/self/realms/one/spaces", sizes);
  for (const read of [one, two, duplicate]) page.emit("request", read);
  for (const read of [one, two, duplicate]) page.emit("requestfinished", read);
  const value = await cost.snapshot();
  assert.equal(value.maximum_parallel_lists["https://station.test/_arkret/self/realms/one/spaces"], 2);
  assert.equal(value.maximum_parallel_lists["https://station.test/_arkret/self/realms/two/spaces"], 1);
  assert.equal(value.http[0].response_body_bytes, 0);
  assert.equal(value.http[0].response_header_bytes, 80);
  assert.equal(value.http[0].request_header_bytes, 90);
  cost.dispose();
});

test("WebSocket byte counts retain operation coordinates but no authentication payload", async () => {
  const page = blankPage();
  const cost = observeRequestCost(page);
  const socket = new EventEmitter(); socket.url = () => "wss://station.test/_arkret/ws";
  page.emit("websocket", socket);
  const secret = JSON.stringify({ kind: "authenticate", session_grant: "private-grant" });
  socket.emit("framesent", { payload: secret });
  const open = JSON.stringify({ kind: "open", channel_id: "account-1",
    operation_id: "ak.self.account.stream.subscribe.v1" });
  socket.emit("framesent", { payload: open });
  socket.emit("framereceived", { payload: Buffer.from("opaque-content") });
  const value = await cost.snapshot();
  assert.equal(value.websocket[0].sent_bytes, Buffer.byteLength(secret) + Buffer.byteLength(open));
  assert.equal(value.websocket[0].received_bytes, 14);
  assert.equal(value.websocket[0].requested_channels.length, 1);
  assert.equal(value.websocket[0].opened_channels.length, 0);
  const opened = JSON.stringify({ kind: "opened", channel_id: "account-1",
    operation_id: "ak.self.account.stream.subscribe.v1" });
  socket.emit("framereceived", { payload: opened });
  const accepted = await cost.snapshot();
  assert.equal(accepted.websocket[0].opened_channels.length, 1);
  assert.equal(accepted.websocket[0].received_bytes, 14 + Buffer.byteLength(opened));
  assert.equal(JSON.stringify(value).includes("private-grant"), false);
  assert.equal(JSON.stringify(value).includes("opaque-content"), false);
  cost.dispose();
});

test("channel discriminator counts distinguish idle transport from delivered Account frames without payloads", async () => {
  const page = blankPage();
  const cost = observeRequestCost(page);
  const socket = new EventEmitter(); socket.url = () => "wss://station.test/_arkret/ws";
  page.emit("websocket", socket);
  const send = frame => socket.emit("framesent", { payload: JSON.stringify(frame) });
  const receive = frame => socket.emit("framereceived", { payload: JSON.stringify(frame) });
  send({ kind: "open", channel_id: "account-1", operation_id: "ak.self.account.stream.subscribe.v1" });
  receive({ kind: "opened", channel_id: "account-1", operation_id: "ak.self.account.stream.subscribe.v1" });
  receive({ kind: "data", channel_id: "account-1", payload: { kind: "delta", cursor: "private-cursor", contacts: ["private-content"] } });
  receive({ kind: "control", frame_scope: "channel", channel_id: "account-1", payload: { kind: "heartbeat" } });
  receive({ kind: "ping", nonce: "private-challenge" });
  receive({ kind: "private-kind", channel_id: "account-1", payload: { kind: "private-payload-kind" } });
  socket.emit("socketerror", "private-error-message");
  socket.emit("close");
  const value = await cost.snapshot();
  const row = value.websocket[0];
  assert.equal(row.channel_frame_kinds["account-1"]["data:delta"], 1);
  assert.equal(row.channel_frame_kinds["account-1"]["control:heartbeat"], 1);
  assert.equal(row.received_kinds.ping, 1);
  assert.equal(row.received_kinds.other, 1);
  assert.equal(row.socket_errors, 1);
  assert.equal(typeof row.closed_ms, "number");
  assert.equal(JSON.stringify(value).includes("private-"), false);
  cost.dispose();
});
