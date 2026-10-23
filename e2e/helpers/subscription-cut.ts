import { expect, type Page, type WebSocketRoute } from "@playwright/test";

// Forward authentic Station frames and retain one account delta in memory.
// The duplication cut replays exact already-observed bytes, never a fabricated
// snapshot, cursor, Event or Commit. No frame content is written to evidence.
export async function installSubscriptionCut(page: Page, forceHttp: boolean) {
  let lastDelta: { route: WebSocketRoute; channel: string; message: string | Buffer } | undefined;
  let rejectedConnections = 0;
  let duplicatedFrames = 0;
  const receivedRefs = new Set<string>();
  const sockets: Array<{ path: string; real_server_frames: number; real_server_bytes: number;
    client_frames: number; client_bytes: number; opened_channels: Array<{ channel_id: string; operation_id: string }> }> = [];
  const collect = (value: unknown, depth = 0) => {
    if (!value || typeof value !== "object" || depth > 32) return;
    for (const [key, child] of Object.entries(value)) {
      if (typeof child === "string" && /_(?:id|ref)$/.test(key) && /^ak:(event|realm_commit):/.test(child)) {
        if (receivedRefs.size < 20_000) receivedRefs.add(child);
      } else if (typeof child === "object") collect(child, depth + 1);
    }
  };
  if (forceHttp) await page.addInitScript(() => {
    const stats = { started: 0, successful: 0, frames: 0, decoded_body_bytes: 0, observation_errors: 0,
      refs: [] as string[] };
    (window as unknown as { __cotestSubscriptionCost: typeof stats }).__cotestSubscriptionCost = stats;
    const refs = new Set<string>();
    const collect = (value: unknown, depth = 0) => {
      if (!value || typeof value !== "object" || depth > 32) return;
      for (const [key, child] of Object.entries(value)) {
        if (typeof child === "string" && /_(?:id|ref)$/.test(key) && /^ak:(event|realm_commit):/.test(child)) {
          if (refs.size < 20_000 && !refs.has(child)) { refs.add(child); stats.refs.push(child); }
        } else if (typeof child === "object") collect(child, depth + 1);
      }
    };
    const original = window.fetch.bind(window);
    window.fetch = async (...args: Parameters<typeof fetch>) => {
      const input = args[0];
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, location.href);
      const subscription = /\/_arkret\/self\/(account|events)\/subscribe$/.test(url.pathname);
      if (subscription) stats.started += 1;
      const response = await original(...args);
      if (subscription && response.status === 200 && response.body) {
        stats.successful += 1;
        // Tee only an observation branch. The product keeps its original
        // Response and stream; no frame or credential is changed or exported.
        const reader = response.clone().body!.getReader();
        void (async () => {
          const decoder = new TextDecoder(); let pending = "";
          try {
            for (;;) {
              const chunk = await reader.read();
              if (chunk.done) break;
              stats.decoded_body_bytes += chunk.value.byteLength;
              pending += decoder.decode(chunk.value, { stream: true });
              let end: number;
              while ((end = pending.indexOf("\n")) >= 0) {
                const line = pending.slice(0, end).trim(); pending = pending.slice(end + 1);
                if (!line) continue;
                try { collect(JSON.parse(line)); stats.frames += 1; }
                catch { stats.observation_errors += 1; }
              }
              if (pending.length > 1_048_576) { stats.observation_errors += 1; break; }
            }
          } catch { stats.observation_errors += 1; }
          finally { void reader.cancel().catch(() => {}); }
        })();
      }
      return response;
    };
  });
  await page.routeWebSocket(url => url.pathname.startsWith("/_arkret/"), route => {
    const server = route.connectToServer();
    let rejected = false;
    const opened = new Set<string>();
    const cost = { path: new URL(route.url()).pathname, real_server_frames: 0, real_server_bytes: 0,
      client_frames: 0, client_bytes: 0, opened_channels: [] as Array<{ channel_id: string; operation_id: string }> };
    sockets.push(cost);
    const invalidate = () => { if (lastDelta?.route === route) lastDelta = undefined; };
    route.onClose((code, reason) => {
      invalidate();
      // The backing browser WebSocket may actively send only 1000 or 3xxx/4xxx.
      const allowed = code === 1000 || code !== undefined && code >= 3000 && code <= 4999;
      void server.close({ code: allowed ? code : 1000, reason }).catch(() => {});
    });
    server.onClose((code, reason) => { invalidate(); void route.close({ code, reason }).catch(() => {}); });
    route.onMessage(message => {
      try {
        const frame = JSON.parse(message.toString());
        if (frame.kind === "close" && typeof frame.channel_id === "string") {
          opened.delete(frame.channel_id);
          if (lastDelta?.route === route && lastDelta.channel === frame.channel_id) lastDelta = undefined;
        }
      } catch { /* Forward every client frame without changing its bytes. */ }
      cost.client_frames += 1; cost.client_bytes += Buffer.byteLength(message); server.send(message);
    });
    server.onMessage(message => {
      cost.real_server_frames += 1; cost.real_server_bytes += Buffer.byteLength(message);
      if (forceHttp) {
        if (rejected) return;
        rejected = true;
        rejectedConnections += 1;
        void route.close({ code: 1002, reason: "cotest_binding_failure" }).catch(() => {});
        void server.close({ code: 1000, reason: "cotest_binding_failure" }).catch(() => {});
        return;
      }
      route.send(message);
      try {
        const frame = JSON.parse(message.toString());
        collect(frame);
        if (frame.kind === "opened" && typeof frame.channel_id === "string" && typeof frame.operation_id === "string") {
          opened.add(frame.channel_id);
          cost.opened_channels.push({ channel_id: frame.channel_id, operation_id: frame.operation_id });
        }
        if (frame.kind === "closed" && typeof frame.channel_id === "string") {
          opened.delete(frame.channel_id);
          if (lastDelta?.route === route && lastDelta.channel === frame.channel_id) lastDelta = undefined;
        }
        if (frame.kind === "data" && frame.payload?.kind === "delta" && opened.has(frame.channel_id)) {
          lastDelta = { route, channel: frame.channel_id, message };
        }
      } catch { /* Non-data and binary frames are forwarded unchanged. */ }
    });
  });
  return {
    async repeatSameCut() {
      expect(forceHttp).toBe(false);
      await expect.poll(() => Boolean(lastDelta), { timeout: 90_000 }).toBe(true);
      const original = lastDelta!;
      for (let index = 0; index < 20; index += 1) {
        original.route.send(original.message);
        duplicatedFrames += 1;
      }
    },
    async httpProof() {
      return page.evaluate(() => {
        const value = (window as unknown as { __cotestSubscriptionCost?: {
          started: number; successful: number; frames: number; decoded_body_bytes: number; observation_errors: number } }).__cotestSubscriptionCost;
        if (!value) return null;
        return { started: value.started, successful: value.successful, frames: value.frames,
          decoded_body_bytes: value.decoded_body_bytes, observation_errors: value.observation_errors };
      });
    },
    async waitForCut(eventId: string, commitId: string) {
      await expect.poll(async () => forceHttp
        ? page.evaluate(({ eventId, commitId }) => {
          const refs = (window as unknown as { __cotestSubscriptionCost?: { refs: string[] } }).__cotestSubscriptionCost?.refs ?? [];
          return refs.includes(eventId) || refs.includes(commitId);
        }, { eventId, commitId })
        : receivedRefs.has(eventId) || receivedRefs.has(commitId), { timeout: 90_000 }).toBe(true);
      return { final_event_id: eventId, final_commit_id: commitId, real_subscription_delivered_final_cut: true };
    },
    proof: () => ({ force_http_binding_failure: forceHttp,
      rejected_real_connections: rejectedConnections, exact_duplicate_account_frames: duplicatedFrames,
      real_websocket_costs: structuredClone(sockets),
      websocket_byte_semantics: "real server application payload bytes; injected duplicate frames counted separately; excludes framing/TLS" }),
  };
}
