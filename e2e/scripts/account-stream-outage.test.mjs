import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { chromium } from "@playwright/test";
import { cutAccountStream, prepareAccountStreamOutage } from "../helpers/account-stream-outage.ts";

const operation = "ak.self.account.stream.subscribe.v1";
const frameSchema = JSON.parse(readFileSync(new URL("../../../arkret-spec/spec/v1/artifacts/schemas/websocket-frame.schema.json", import.meta.url), "utf8"));
const controlKind = frameSchema.$defs.channel_control.properties.kind.const;
const channelScope = frameSchema.$defs.channel_control.properties.frame_scope.const;
function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const head = Buffer.alloc(body.length < 126 ? 2 : 4);
  head[0] = 0x81;
  if (body.length < 126) head[1] = body.length;
  else { head[1] = 126; head.writeUInt16BE(body.length, 2); }
  return Buffer.concat([head, body]);
}

async function streamServer() {
  let current = 0;
  const sockets = new Set();
  const clients = new Map();
  const timer = setInterval(() => {
    current++;
    for (const send of clients.values()) {
      send({ kind: "data", channel_id: "account", body: current });
      send({ kind: controlKind, frame_scope: channelScope, channel_id: "account", payload: { kind: "checkpoint", cursor: current } });
      send({ kind: "data", channel_id: "signal", body: current });
    }
  }, 30);
  const server = createServer((_request, response) => {
    response.setHeader("content-type", "text/html");
    response.end(`<script>
localStorage.loads = String(Number(localStorage.loads || 0) + 1);
window.account = []; window.signals = []; window.cursor = 0;
function connect() {
  const ws = new WebSocket(location.origin.replace('http:', 'ws:') + '/_arkret/ws?after=' + window.cursor);
  ws.onmessage = event => {
    const frame = JSON.parse(event.data);
    if (frame.kind === ${JSON.stringify(controlKind)} && frame.frame_scope === ${JSON.stringify(channelScope)} && frame.channel_id === 'account') { window.cursor = frame.payload.cursor; return; }
    if (frame.kind !== 'data') return;
    if (frame.channel_id === 'account') { window.account.push(frame.body); window.cursor = frame.body; }
    else window.signals.push(frame.body);
  };
  ws.onclose = () => setTimeout(connect, 10);
}
connect();
</script>`);
  });
  server.on("upgrade", (request, socket) => {
    sockets.add(socket);
    const accept = createHash("sha1").update(request.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
    const send = value => { if (!socket.destroyed && !socket.writableEnded) socket.write(frame(value)); };
    send({ kind: "opened", channel_id: "account", operation_id: operation });
    send({ kind: "opened", channel_id: "signal", operation_id: "ak.self.signal.subscribe.v1" });
    const after = Number(new URL(request.url, "http://fixture.invalid").searchParams.get("after"));
    for (let value = after + 1; value <= current; value++) send({ kind: "data", channel_id: "account", body: value });
    clients.set(socket, send);
    socket.on("data", bytes => {
      if ((bytes[0] & 15) !== 8 || bytes.length < 6) return;
      const length = bytes[1] & 127;
      if (bytes.length < 6 + length) return;
      const body = Buffer.from(bytes.subarray(6, 6 + length));
      for (let index = 0; index < body.length; index++) body[index] ^= bytes[2 + index % 4];
      socket.end(Buffer.concat([Buffer.from([0x88, body.length]), body]));
    });
    socket.on("close", () => { clients.delete(socket); sockets.delete(socket); });
    socket.on("error", () => {});
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: async () => {
    clearInterval(timer);
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  } };
}

test("real WebSocket cuts preserve the page and other channels, then resume every held item from the cursor", async () => {
  const source = await streamServer();
  let browser;
  try {
    browser = await chromium.launch();
    const page = await browser.newPage();
    await prepareAccountStreamOutage(page, operation);
    await page.goto(source.url);
    await page.waitForFunction(() => window.account.length >= 2);
    for (let round = 0; round < 2; round++) {
      const before = await page.evaluate(() => ({ account: window.cursor, signals: window.signals.length }));
      const outage = cutAccountStream(page);
      assert.throws(() => cutAccountStream(page), /already active/);
      await page.waitForFunction(count => window.signals.length >= count + 3, before.signals);
      const held = await page.evaluate(() => ({ account: window.cursor, signals: window.signals.length }));
      await page.waitForFunction(count => window.signals.length >= count + 3, held.signals);
      assert.equal(await page.evaluate(() => window.cursor), held.account);
      assert.ok(outage.blockedWebSocketCount() > 0);
      await outage.restore();
      await outage.restore();
      await page.waitForFunction(cursor => window.cursor > cursor + 3, before.account);
      const result = await page.evaluate(() => ({ account: window.account, loads: Number(localStorage.loads) }));
      assert.equal(result.loads, 1, "outages must not reload or replace the application owner");
      assert.deepEqual(result.account, Array.from({ length: result.account.at(-1) }, (_, index) => index + 1));
    }
  } finally {
    try { await browser?.close(); }
    finally { await source.close(); }
  }
});

test("an unprepared page cannot silently fall back to a disruptive reload", () => {
  assert.throws(() => cutAccountStream({}), /prepared before navigation/);
});
