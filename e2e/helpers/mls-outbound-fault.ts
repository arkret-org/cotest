import { expect, type Page, type Request, type Route } from "@playwright/test";
import { decodeIngressEvents } from "./event-ingress";

export type MlsOutboundFault = "commit-response-lost" | "welcome-before-durable" | "welcome-response-lost";

// Cut the real product submission; never replace its signed Event or receipt.
// The caller destroys the page runtime with reload while this cut remains in
// place, then restores transport and verifies actual encrypted communication.
export async function installMlsOutboundFault(
  page: Page,
  realmId: string,
  fault: MlsOutboundFault,
) {
  const kind = fault === "commit-response-lost" ? "ak.mls.commit" : "ak.mls.welcome";
  const isSubmit = ({ pathname }: URL) => pathname === "/_arkret/self/events";
  const observedIds = new Set<string>();
  let cutEventId: string | undefined;
  let active = true;
  const selected = (request: Request) => {
    if (request.method() !== "POST" || !isSubmit(new URL(request.url()))) return [];
    return decodeIngressEvents(request.postData(), { context: "MLS outbound fault" })
      .filter((event) => event.realm_id === realmId && event.kind === kind);
  };
  const observe = (request: Request) => {
    for (const event of selected(request)) {
      if (typeof event.event_id === "string") observedIds.add(event.event_id);
    }
  };
  page.on("request", observe);
  const handler = async (route: Route) => {
    const events = selected(route.request());
    if (!active || events.length === 0) {
      await route.continue();
      return;
    }
    expect(events).toHaveLength(1);
    const eventId = events[0].event_id;
    expect(typeof eventId).toBe("string");
    if (cutEventId === undefined && fault !== "welcome-before-durable") {
      // The server really commits its normal admission transaction. Only the
      // response is lost; the client must query/replay its original outcome.
      const response = await route.fetch();
      if (!response.ok()) {
        await route.fulfill({ response });
        return;
      }
    }
    cutEventId ??= eventId as string;
    expect(eventId, "the pending saga must retain its original Event identity").toBe(cutEventId);
    await route.abort("connectionfailed");
  };
  await page.route(isSubmit, handler);
  return {
    waitForCut: async () => {
      await expect.poll(() => cutEventId, { timeout: 120_000 }).toBeTruthy();
      return cutEventId!;
    },
    restore: async () => {
      active = false;
      await page.unroute(isSubmit, handler);
    },
    assertExactReplay: () => {
      expect(cutEventId).toBeTruthy();
      expect([...observedIds]).toEqual([cutEventId]);
    },
    dispose: async () => {
      active = false;
      await page.unroute(isSubmit, handler);
      page.off("request", observe);
    },
  };
}
