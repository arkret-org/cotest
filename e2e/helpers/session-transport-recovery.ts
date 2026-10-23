import { expect, type APIRequestContext, type Page, type Response } from "@playwright/test";
import { registerRequestAuth, scanRealmStreamApi, sdkEventDerivedIds, wireErrCode } from "./coland-api";
import { selfPathHeadersForDpopSession, type DpopUserSession } from "./users";
import { assertAcceptedRealmScanAlignment, orderedResponseObservation, sessionGrantRotationObservation } from "./session-transport-observation";

import { colandBaseUrl, colandServiceId } from "./env";

const hook = "__inkson_captured_transport_rotation_v1";
const retiredReads = new Set([
  "/_arkret/self/account/viewer",
  "/_arkret/self/account/subscribe",
  "/_arkret/self/streams/scan",
]);

// The hook rotates through the actual Rust provider and issuer. It neither
// substitutes a response nor exports grant tokens, holder keys or MLS leaves.
export function accountTransportRotationProbe(page: Page, request: APIRequestContext, session: DpopUserSession) {
  expect(session.accountId.station_id).toBe(colandServiceId());
  const stationOrigin = new URL(colandBaseUrl()).origin;
  let armed = false;
  const rotation = sessionGrantRotationObservation(session.accountId);
  let latestGrant = session.grantJwt;
  const failures: string[] = [];
  const observations = orderedResponseObservation<Response>(observe, () => {
    failures.push("transport observation failed");
  });

  async function expectedRetiredRead(response: Response): Promise<boolean> {
    const url = new URL(response.url());
    if (!armed || url.origin !== stationOrigin || response.status() !== 401 || !retiredReads.has(url.pathname)) return false;
    await observations.observed(response);
    const evidence = await hookEvidence();
    if (evidence?.phase !== "rotated_before_request" || wireErrCode(await response.json()) !== "unauthenticated") return false;
    return rotation.matchesPredecessor(evidence.predecessor_grant_id, evidence.successor_grant_id,
      (await response.request().allHeaders()).authorization);
  }

  page.on("response", response => {
    const url = new URL(response.url());
    const path = url.pathname;
    if ((url.origin === stationOrigin && path.startsWith("/_arkret/self/")) || path === "/_arkret/gate/account/session-grants/refresh") {
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
      rotation.refresh(authorization, await response.json() as Record<string, unknown>);
    }
    if (new URL(response.url()).origin !== stationOrigin || !path.startsWith("/_arkret/self/")) return;
    if (response.status() === 200 && authorization?.startsWith("DPoP ") && !rotation.isRetiredAuthorization(authorization)) {
      latestGrant = authorization.slice("DPoP ".length);
    }
    // Do not wait on observations.observed here: this is that very job.
    if (armed && path === "/_arkret/self/account/viewer") {
      const code = response.status() === 401 ? wireErrCode(await response.json()) : undefined;
      rotation.viewer(response.status(), authorization, code);
    }
  }

  async function hookEvidence() {
    return page.evaluate(name => {
      const value = (window as unknown as Record<string, unknown>)[name];
      return typeof value === "string" ? JSON.parse(value) as Record<string, unknown> : undefined;
    }, hook);
  }

  async function read(realm: string) {
    await observations.settled();
    const grant = latestGrant;
    registerRequestAuth(grant, (method, url) => selfPathHeadersForDpopSession({ ...session, grantJwt: grant }, method, url));
    const result = await scanRealmStreamApi(request, grant, realm);
    assertAcceptedRealmScanAlignment(realm, result, sdkEventDerivedIds);
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
      await expect.poll(hookEvidence, { timeout: 90_000 }).toMatchObject({ phase: "rotated_before_request" });
      const evidence = (await hookEvidence())!;
      expect(evidence.account_id).toEqual(session.accountId);
      expect(evidence.device_id).toBe(session.user.deviceId);
      expect(evidence.session_generation_after).toBe(evidence.session_generation_before);
      expect(evidence.successor_grant_id).not.toBe(evidence.predecessor_grant_id);
      await expect.poll(() => rotation.recovered(evidence.predecessor_grant_id, evidence.successor_grant_id),
        { timeout: 90_000 }).toBe(true);
      await observations.settled();
      expect(failures).toEqual([]);
      return evidence;
    },
  };
}

export function assertOriginalAcceptedMlsRows(
  before: Awaited<ReturnType<typeof scanRealmStreamApi>>,
  after: Awaited<ReturnType<typeof scanRealmStreamApi>>,
) {
  const originals = before.events.flatMap((event) =>
    event?.kind === "ak.message.create" || event?.kind === "ak.mls.genesis"
      ? [{ event, commit: before.commits.find(commit => commit.event_ref === event.event_id) }] : []);
  expect(originals.filter(row => row.event.kind === "ak.message.create")).toHaveLength(3);
  expect(originals.filter(row => row.event.kind === "ak.mls.genesis")).toHaveLength(1);
  for (const original of originals) {
    const indexes = after.events.flatMap((event, index) => event?.event_id === original.event.event_id ? [index] : []);
    expect(indexes, "a previously accepted original is neither replaced nor duplicated").toHaveLength(1);
    expect(after.events[indexes[0]!]).toEqual(original.event);
    expect(after.commits.find(commit => commit.event_ref === original.event.event_id)).toEqual(original.commit);
  }
  const newAdds = after.events.filter(event => event?.kind === "ak.mls.commit"
    && !before.events.some(old => old?.event_id === event.event_id));
  expect(newAdds, "one newly paired endpoint produces one accepted Add, never a re-authored duplicate").toHaveLength(1);
  expect(newAdds[0]!.payload).toMatchObject({ previous_epoch: 0, next_epoch: 1 });
  expect(after.events.filter(event => event?.kind === "ak.message.create")).toHaveLength(5);
}
