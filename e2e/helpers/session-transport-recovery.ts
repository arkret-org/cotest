import { expect, type APIRequestContext, type Page, type Response } from "@playwright/test";
import { registerRequestAuth, scanRealmStreamApi, wireErrCode } from "./coland-api";
import { selfPathHeadersForDpopSession, type DpopUserSession } from "./users";
import { assertAcceptedRealmScanAlignment, orderedResponseObservation } from "./session-transport-observation";

const hook = "__inkson_captured_transport_rotation_v1";
const retiredReads = new Set([
  "/_arkret/self/account/viewer",
  "/_arkret/self/account/subscribe",
  "/_arkret/self/streams/scan",
]);

// The hook rotates through the actual Rust provider and issuer. It neither
// substitutes a response nor exports grant tokens, holder keys or MLS leaves.
export function accountTransportRotationProbe(page: Page, request: APIRequestContext, session: DpopUserSession) {
  let armed = false;
  const retiredAuthorizations = new Set<string>();
  let latestGrant = session.grantJwt;
  let viewerDenied = false;
  let viewerRecovered = false;
  const failures: string[] = [];
  const refreshes: Array<{ previous: unknown; successor: unknown }> = [];
  const observations = orderedResponseObservation<Response>(observe, () => {
    failures.push("transport observation failed");
  });

  async function expectedRetiredRead(response: Response): Promise<boolean> {
    if (!armed || response.status() !== 401 || !retiredReads.has(new URL(response.url()).pathname)) return false;
    await observations.observed(response);
    return retiredAuthorizations.has((await response.request().allHeaders()).authorization ?? "");
  }

  page.on("response", response => {
    const path = new URL(response.url()).pathname;
    if (path.startsWith("/_arkret/self/") || path === "/_arkret/gate/account/session-grants/refresh") {
      observations.enqueue(response);
    }
  });

  async function observe(response: Response) {
    const path = new URL(response.url()).pathname;
    const authorization = (await response.request().allHeaders()).authorization;
    if (armed && path === "/_arkret/gate/account/session-grants/refresh" && response.status() === 200) {
      if (!authorization || !/^DPoP [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization)) {
        failures.push("issuer refresh did not carry a real captured grant");
        return;
      }
      retiredAuthorizations.add(authorization);
      const body = await response.json() as { previous_session_grant_id?: unknown; session_grant_id?: unknown };
      refreshes.push({ previous: body.previous_session_grant_id, successor: body.session_grant_id });
    }
    if (!path.startsWith("/_arkret/self/")) return;
    if (response.status() === 200 && authorization?.startsWith("DPoP ") && !retiredAuthorizations.has(authorization)) {
      latestGrant = authorization.slice("DPoP ".length);
      if (viewerDenied && path === "/_arkret/self/account/viewer") viewerRecovered = true;
    }
    // Do not wait on observations.observed here: this is that very job.
    if (armed && response.status() === 401 && retiredReads.has(path)
      && retiredAuthorizations.has(authorization ?? "")) {
      if (path === "/_arkret/self/account/viewer") viewerDenied = true;
      const body: unknown = await response.json();
      if (wireErrCode(body) !== "unauthenticated") failures.push("old transport denial was not issuer inactivity");
    }
  }

  async function read(realm: string) {
    await observations.settled();
    const grant = latestGrant;
    registerRequestAuth(grant, (method, url) => selfPathHeadersForDpopSession({ ...session, grantJwt: grant }, method, url));
    const result = await scanRealmStreamApi(request, grant, realm);
    assertAcceptedRealmScanAlignment(realm, result);
    return result;
  }

  return {
    expectedRetiredRead,
    read,
    async arm() {
      expect(armed).toBe(false);
      armed = true;
      await page.evaluate(name => {
        if (Object.hasOwn(window, name)) throw new Error("transport fault was already installed");
        (window as unknown as Record<string, unknown>)[name] = true;
      }, hook);
    },
    async verify() {
      await expect.poll(async () => page.evaluate(name => {
        const value = (window as unknown as Record<string, unknown>)[name];
        return typeof value === "string" ? JSON.parse(value) as Record<string, unknown> : undefined;
      }, hook), { timeout: 90_000 }).toMatchObject({ phase: "rotated_before_request" });
      const evidence = await page.evaluate(name => JSON.parse(String((window as unknown as Record<string, unknown>)[name])) as Record<string, unknown>, hook);
      expect(evidence.account_id).toEqual(session.accountId);
      expect(evidence.device_id).toBe(session.user.deviceId);
      expect(evidence.session_generation_after).toBe(evidence.session_generation_before);
      expect(evidence.successor_grant_id).not.toBe(evidence.predecessor_grant_id);
      await expect.poll(() => viewerDenied && viewerRecovered, { timeout: 90_000 }).toBe(true);
      await observations.settled();
      expect(refreshes).toContainEqual({ previous: evidence.predecessor_grant_id, successor: evidence.successor_grant_id });
      expect(failures).toEqual([]);
      return evidence;
    },
  };
}

export function assertOriginalAcceptedMlsRows(
  before: Awaited<ReturnType<typeof scanRealmStreamApi>>,
  after: Awaited<ReturnType<typeof scanRealmStreamApi>>,
) {
  const originals = before.events.flatMap((event, index) =>
    event?.kind === "ak.message.create" || event?.kind === "ak.mls.genesis"
      ? [{ event, commit: before.commits[index] }] : []);
  expect(originals.filter(row => row.event.kind === "ak.message.create")).toHaveLength(3);
  expect(originals.filter(row => row.event.kind === "ak.mls.genesis")).toHaveLength(1);
  for (const original of originals) {
    const indexes = after.events.flatMap((event, index) => event?.event_id === original.event.event_id ? [index] : []);
    expect(indexes, "a previously accepted original is neither replaced nor duplicated").toHaveLength(1);
    expect(after.events[indexes[0]!]).toEqual(original.event);
    expect(after.commits[indexes[0]!]).toEqual(original.commit);
  }
  const newAdds = after.events.filter(event => event?.kind === "ak.mls.commit"
    && !before.events.some(old => old?.event_id === event.event_id));
  expect(newAdds, "one newly paired endpoint produces one accepted Add, never a re-authored duplicate").toHaveLength(1);
  expect(newAdds[0]!.payload).toMatchObject({ previous_epoch: 0, next_epoch: 1 });
  expect(after.events.filter(event => event?.kind === "ak.message.create")).toHaveLength(5);
}
