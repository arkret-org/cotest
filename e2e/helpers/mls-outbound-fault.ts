import { expect, type Page, type Request, type Route } from "@playwright/test";
import { decodeIngressEvents } from "./event-ingress";

export type MlsOutboundFault = "commit-response-lost" | "welcome-before-durable" | "welcome-response-lost" | "retryable-unavailable";

// Cut the real product submission; never replace its signed Event or receipt.
// The caller destroys the page runtime with reload while this cut remains in
// place, then restores transport and verifies actual encrypted communication.
export async function installMlsOutboundFault(
  page: Page,
  realmId: string,
  fault: MlsOutboundFault,
) {
  // Welcome deliveries and their Commit share one atomic submission. Both
  // response-loss cases cut the response of that same transaction; the
  // before-durable case cuts the complete request before it reaches authority.
  const kind = "ak.mls.commit";
  const isSubmit = ({ pathname }: URL) => pathname === "/_arkret/self/events";
  const observedIds = new Set<string>();
  let cutEventId: string | undefined;
  let frozenSubmission: string | undefined;
  let active = true;
  const selected = (request: Request) => {
    if (request.method() !== "POST" || !isSubmit(new URL(request.url()))) return [];
    const events = decodeIngressEvents(request.postData(), { context: "MLS outbound fault" })
      .filter((event) => event.realm_id === realmId && event.kind === kind);
    if (events.length > 0) {
      const submission = request.postDataJSON();
      expect(submission.commit_event).toBeTruthy();
      expect(submission.welcomes.length, "member Add must carry its atomic Welcome deliveries").toBeGreaterThan(0);
      const bytes = request.postData()!;
      frozenSubmission ??= bytes;
      const changes: string[] = [];
      const compare = (before: unknown, after: unknown, path: string) => {
        if (JSON.stringify(before) === JSON.stringify(after)) return;
        if (before && after && typeof before === "object" && typeof after === "object") {
          for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
            compare((before as Record<string, unknown>)[key], (after as Record<string, unknown>)[key], path ? `${path}.${key}` : key);
          }
        } else if (changes.length < 20) {
          changes.push(path);
        }
      };
      // Report protocol field names only, never ciphertext, signatures or keys.
      compare(JSON.parse(frozenSubmission), submission, "");
      expect(bytes === frozenSubmission, `recovery must replay the byte-identical Commit and Welcome submission; changed fields: ${changes.join(", ") || "encoding only"}`).toBe(true);
    }
    return events;
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
    if (fault === "retryable-unavailable") {
      // No request reaches the authority and no shared fact is claimed. The
      // registered nonterminal outcome must survive a real runtime restart.
      cutEventId ??= eventId as string;
      expect(eventId).toBe(cutEventId);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "retryable_unavailable", reason_code: "temporarily_unavailable" }),
      });
      return;
    }
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
