import { expect, test } from "../../helpers/arkret-test";
import { colandBaseUrl } from "../../helpers/env";

// Exercise the configured public endpoint, including its TLS-terminating proxy.
// Native websocket_live tests cover the separate direct-TLS server fixture.
test("public HTTPS deployment delivers the same-origin WSS challenge @fully-implemented", async ({ page }) => {
  const base = colandBaseUrl();
  test.skip(new URL(base).protocol !== "https:", "WSS requires a configured HTTPS deployment");
  await page.goto(`${base}/health`, { waitUntil: "domcontentloaded" });
  const outcome = await page.evaluate(() => new Promise<string>(resolve => {
    const socket = new WebSocket(`wss://${location.host}/_arkret/ws`, "arkret.v1");
    const timer = setTimeout(() => { socket.close(); resolve("timeout"); }, 10_000);
    socket.onmessage = event => {
      clearTimeout(timer);
      try { resolve(JSON.parse(event.data).kind); } catch { resolve("invalid-json"); }
      socket.close();
    };
    socket.onerror = () => { clearTimeout(timer); resolve("upgrade-failed"); };
  }));
  expect(outcome).toBe("challenge");
});
