import { expect, test } from "../../helpers/arkret-test";
import { colandBaseUrl, configuredServerKeys } from "../../helpers/env";

// Exercise the configured public endpoint, including its TLS-terminating proxy.
// Native websocket_live tests cover the separate direct-TLS server fixture.
test("public HTTPS deployment delivers the same-origin WSS challenge @fully-implemented", async ({ page, request }) => {
  test.skip(new URL(colandBaseUrl()).protocol !== "https:", "WSS requires a configured HTTPS deployment");
  for (const station of configuredServerKeys()) {
    await test.step(station, async () => {
      const base = new URL(colandBaseUrl(station));
      expect(base.protocol).toBe("https:");
      const response = await request.get(new URL("/_arkret/describe", base).href, {
        headers: { "Arkret-Operation": "ak.server.read.describe.v1" },
      });
      expect(response.status()).toBe(200);
      const description = await response.json();
      expect(description.supported_profiles.includes("ak.profile.binding.websocket.v1")).toBe(true);
      expect(description.supported_operation_bundles.includes("ak.operation_bundle.station.websocket.v1")).toBe(true);
      const endpoint = `wss://${base.host}/_arkret/ws`;
      const bindings: Array<{ kind: string; base_url: string }> = description.transport_bindings;
      expect(bindings.some(binding => binding.kind === "http_json" && binding.base_url === `${base.origin}/`)).toBe(true);
      const advertised = bindings.find(binding => binding.kind === "websocket" && binding.base_url === endpoint);
      expect(advertised?.base_url).toBe(endpoint);

      await page.goto(new URL("/health", base).href, { waitUntil: "domcontentloaded" });
      const outcome = await page.evaluate(url => new Promise<string>(resolve => {
        const socket = new WebSocket(url, "arkret.v1");
        const timer = setTimeout(() => { socket.close(); resolve("timeout"); }, 10_000);
        socket.onmessage = event => {
          clearTimeout(timer);
          try { resolve(JSON.parse(event.data).kind); } catch { resolve("invalid-json"); }
          socket.close();
        };
        socket.onerror = () => { clearTimeout(timer); resolve("upgrade-failed"); };
      }), advertised!.base_url);
      expect(outcome).toBe("challenge");
    });
  }
});
