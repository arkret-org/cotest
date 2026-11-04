import type { Page } from "@playwright/test";

const prepared = new WeakMap<Page, { cut: () => AccountStreamOutage }>();
export type AccountStreamOutage = {
  blockedCount: () => number;
  blockedWebSocketCount: () => number;
  restore: () => Promise<void>;
};

// Register before initial navigation so later outages do not reload the app
// or change its active Realm, session, demands or UI owner.
export async function prepareAccountStreamOutage(page: Page, accountOperation: string | undefined) {
  if (!accountOperation || prepared.has(page)) throw new Error("Account cut requires one registered operation and one page owner");
  let active = false;
  let blockedHttp = 0;
  let blockedWebSocket = 0;
  const connections = new Set<{ retire: () => Promise<void> }>();
  await page.route(url => url.pathname === "/_arkret/self/account/subscribe", async route => {
    if (active) { blockedHttp++; await route.abort("connectionfailed"); }
    else await route.continue();
  });
  await page.routeWebSocket(url => url.pathname.startsWith("/_arkret/"), route => {
    const server = route.connectToServer();
    const operations = new Map<string, string>();
    let retired = false;
    const connection = { retire: () => {
      retired = true;
      // A restart reconnects with the original durable cursor. Old sockets
      // remain cut until closed; they cannot forward a post-gap frame.
      return route.close({ code: 1012, reason: "cotest Account transport restart" });
    } };
    connections.add(connection);
    server.onMessage(message => {
      let accountPayload = false;
      try {
        const frame = JSON.parse(message.toString());
        if (frame.kind === "opened" && typeof frame.channel_id === "string") operations.set(frame.channel_id, frame.operation_id);
        // Checkpoints and catchup controls carry the durable cursor too.
        // Letting them pass a dropped Delta would manufacture a resume gap.
        accountPayload = (frame.kind === "data" || (frame.kind === "control" && frame.frame_scope === "channel"))
          && operations.get(frame.channel_id) === accountOperation;
        if (frame.kind === "closed") operations.delete(frame.channel_id);
      } catch { /* Forward authentic bytes without inventing a protocol frame. */ }
      if ((active || retired) && accountPayload) { blockedWebSocket++; return; }
      route.send(message);
    });
  });
  prepared.set(page, { cut: () => {
    if (active) throw new Error("Account stream outage is already active");
    blockedHttp = 0;
    blockedWebSocket = 0;
    active = true;
    let restored = false;
    return {
      blockedCount: () => blockedHttp + blockedWebSocket,
      blockedWebSocketCount: () => blockedWebSocket,
      restore: async () => {
        if (restored) return;
        restored = true;
        const closing = [...connections].map(connection => connection.retire().catch(() => {}));
        active = false;
        await Promise.all(closing);
      },
    };
  } });
}

export function cutAccountStream(page: Page): AccountStreamOutage {
  const owner = prepared.get(page);
  if (!owner) throw new Error("Account fault routing must be prepared before navigation");
  return owner.cut();
}
