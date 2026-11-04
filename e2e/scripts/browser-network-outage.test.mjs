import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { test } from "node:test";
import { chromium, expect } from "@playwright/test";
import { prepareBrowserNetworkOutage } from "../helpers/browser-network-outage.ts";

test("a browser outage cuts HTTP and existing WebSockets, then resumes without reloading", async () => {
  const sockets = new Set();
  let probeRequests = 0;
  let counter = 0;
  const server = createServer((request, response) => {
    if (request.url === "/probe") { probeRequests++; response.end("online"); return; }
    response.setHeader("content-type", "text/html");
    response.end(`<script>
window.loads = 1; window.received = 0;
function connect() {
  const ws = new WebSocket(location.origin.replace('http:', 'ws:') + '/_arkret/ws');
  ws.onmessage = () => window.received++;
  ws.onclose = () => setTimeout(connect, 20);
}
connect();
</script>`);
  });
  server.on("upgrade", (request, socket) => {
    sockets.add(socket);
    const accept = createHash("sha1").update(request.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
    socket.on("data", bytes => { if ((bytes[0] & 15) === 8) socket.end(Buffer.from([0x88, 2, 3, 232])); });
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
  });
  const timer = setInterval(() => {
    const body = Buffer.from(String(++counter));
    for (const socket of sockets) if (!socket.destroyed && !socket.writableEnded) socket.write(Buffer.concat([Buffer.from([0x81, body.length]), body]));
  }, 30);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    const outage = await prepareBrowserNetworkOutage(page);
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await expect.poll(() => page.evaluate(() => window.received)).toBeGreaterThan(2);
    assert.ok(outage.stats().active_sockets > 0);
    await outage.disconnect();
    assert.ok(outage.stats().retired_sockets > 0);
    await expect.poll(() => outage.stats().active_sockets).toBe(0);
    assert.equal(await page.evaluate(() => fetch('/probe').then(() => 'online').catch(() => 'offline')), 'offline');
    assert.equal(probeRequests, 0);
    await page.waitForTimeout(100);
    const before = await page.evaluate(() => window.received);
    await page.waitForTimeout(150);
    assert.equal(await page.evaluate(() => window.received), before);
    await outage.reconnect();
    assert.equal(await page.evaluate(() => fetch('/probe').then(response => response.text())), 'online');
    await expect.poll(() => page.evaluate(() => window.received)).toBeGreaterThan(before);
    assert.ok(outage.stats().active_sockets > 0);
    assert.equal(await page.evaluate(() => window.loads), 1);
  } finally {
    clearInterval(timer);
    await browser.close();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
});
