import type { Page } from "@playwright/test";

// Install before navigation. HTTP is cut by the real browser network state;
// active WebSockets are explicitly retired so no established rail bridges it.
export async function prepareBrowserNetworkOutage(page: Page) {
  let offline = false;
  let retiredSockets = 0;
  let blockedSockets = 0;
  const receivedEvents = new Set<string>();
  const observeRefs = (value: unknown, depth = 0) => {
    if (!value || typeof value !== "object" || depth > 32) return;
    for (const child of Object.values(value)) {
      if (typeof child === "string" && child.startsWith("ak:event:")) receivedEvents.add(child);
      else if (typeof child === "object") observeRefs(child, depth + 1);
    }
  };
  const connections = new Set<{ retire: () => Promise<void> }>();
  await page.routeWebSocket(url => url.pathname.startsWith("/_arkret/"), route => {
    if (offline) {
      blockedSockets++;
      void route.close({ code: 1012, reason: "cotest offline" }).catch(() => {});
      return;
    }
    const server = route.connectToServer();
    let retired = false;
    const connection = { retire: async () => {
      retired = true;
      retiredSockets++;
      await Promise.allSettled([
        route.close({ code: 1012, reason: "cotest offline" }),
        server.close({ code: 1000, reason: "cotest offline" }),
      ]);
    } };
    connections.add(connection);
    route.onMessage(message => { if (!offline && !retired) server.send(message); });
    server.onMessage(message => {
      if (offline || retired) return;
      route.send(message);
      try { observeRefs(JSON.parse(message.toString())); }
      catch { /* Keep non-JSON transport bytes unchanged. */ }
    });
    route.onClose(() => {
      connections.delete(connection);
      void server.close({ code: 1000 }).catch(() => {});
    });
    server.onClose((code, reason) => {
      connections.delete(connection);
      void route.close({ code, reason }).catch(() => {});
    });
  });
  return {
    stats: () => ({ offline, retired_sockets: retiredSockets, blocked_sockets: blockedSockets }),
    hasReceivedEvent: (eventId: string) => receivedEvents.has(eventId),
    async disconnect() {
      if (offline) throw new Error("browser is already offline");
      offline = true;
      await page.context().setOffline(true);
      await Promise.all([...connections].map(connection => connection.retire()));
    },
    async reconnect() {
      offline = false;
      await page.context().setOffline(false);
    },
  };
}
