// Account stream and device-message convergence.
// Spec: sync/service-http-binding.md §2.3 (account subscribe and device messages)
//       crypto-media/device-lifecycle.md §7 (durable to-device delivery)

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { sendPlaintextMessageViaApi } from "../../helpers/api";
import { solandBaseUrl } from "../../helpers/env";
import {
  accountSubscribeFramesApi,
  authHeaders,
  createRealmApi,
  resolveDefaultStrandId,
  sendMessageApi,
  wireErrCode,
} from "../../helpers/soland-api";
import { createDpopUserSession } from "../../helpers/users";

async function accountSession(request: APIRequestContext, label: string) {
  const session = await createDpopUserSession(request, label);
  if (!session) throw new Error("account stream coverage requires the joint Coauth deployment");
  return { user: session.user, token: session.grantJwt };
}

function realmBuckets(frames: Array<Record<string, unknown>>) {
  return frames.filter((frame) => frame.kind === "delta").flatMap((frame) => {
    expect(frame.realms === undefined || (frame.realms !== null && typeof frame.realms === "object")).toBe(true);
    return Object.entries((frame.realms ?? {}) as Record<string, {
      timeline?: { events?: Array<{ event_id: string; kind: string }>; limited?: boolean; preview_only?: boolean };
      state_at_window_start?: unknown;
    }>);
  });
}

function messageIds(frames: Array<Record<string, unknown>>, realmId: string): string[] {
  return realmBuckets(frames).filter(([id]) => id === realmId).flatMap(([, bucket]) => {
    if (!bucket.timeline) return [];
    expect(bucket.timeline?.limited, "small replay window must be complete").toBe(false);
    expect(Array.isArray(bucket.timeline?.events), "timeline.events is required for this delta").toBe(true);
    return bucket.timeline!.events!.filter((event) => event.kind === "ak.message.create")
      .map((event) => event.event_id);
  }).sort();
}

async function accountFramesWithMessages(
  request: APIRequestContext,
  token: string,
  realmId: string,
  expectedIds: string[],
  opts: Parameters<typeof accountSubscribeFramesApi>[2] = {},
) {
  let frames: Array<Record<string, unknown>> = [];
  await expect
    .poll(
      async () => {
        frames = await accountSubscribeFramesApi(request, token, opts);
        return messageIds(frames, realmId);
      },
      { timeout: 30_000, intervals: [250, 500, 1_000, 2_000] },
    )
    .toEqual([...expectedIds].sort());
  return frames;
}

function expectCatchup(frames: Array<Record<string, unknown>>) {
  expect(frames.some((frame) => frame.kind === "delta"), "catch-up carries a data delta").toBe(true);
  expect(frames.at(-1)?.kind, "catch-up terminates explicitly").toBe("catchup_complete");
  expect(frames.some((frame) => ["dropped", "resync_required", "unauthorized"].includes(String(frame.kind)))).toBe(false);
  latestCursor(frames);
}

function latestCursor(frames: Array<Record<string, unknown>>): string {
  const cursor = [...frames]
    .reverse()
    .map((frame) => frame.cursor)
    .find((value): value is string => typeof value === "string");
  expect(typeof cursor === "string" && /^ak:cursor:[A-Za-z0-9_-]+$/.test(cursor),
    "account frames have an opaque cursor (payload omitted from diagnostics)").toBe(true);
  return cursor!;
}

test.describe("account stream + device-message convergence", () => {
  test("quiet long-poll closes at its bound and a fresh poll wakes on the next delta", async ({
    request,
  }) => {
    test.setTimeout(75_000);
    const { user, token } = await accountSession(request, "account-long-poll");
    const realmId = await createRealmApi(request, token, {
      title: `long-poll scope ${Date.now()}`,
      ownerId: user.id,
    });
    const filter = { realm_ids: [realmId] };

    const baseline = await accountSubscribeFramesApi(request, token, { filter });
    const baselineCursor = latestCursor(baseline);

    const quietStartedAt = Date.now();
    const quietPoll = accountSubscribeFramesApi(request, token, {
      after: baselineCursor,
      filter,
      timeoutMs: 40_000,
    });
    const quiet = await quietPoll;
    const quietElapsedMs = Date.now() - quietStartedAt;
    expect(quiet[0]?.kind).toBe("frontier");
    expect(quietElapsedMs, "quiet poll respects the server-side 30s bound").toBeGreaterThanOrEqual(
      28_000,
    );
    expect(quietElapsedMs).toBeLessThan(40_000);

    // Resolve the projection before opening the measured long-poll. Otherwise
    // the helper's discovery request can queue behind the outstanding poll in
    // the shared Playwright request context and measure that client-side wait
    // instead of the server's event-driven wake latency.
    const strandId = await resolveDefaultStrandId(request, token, realmId);
    const repollStartedAt = Date.now();
    const repoll = accountSubscribeFramesApi(request, token, {
      after: latestCursor(quiet),
      filter,
      timeoutMs: 10_000,
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    await sendPlaintextMessageViaApi(request, token, realmId, `long-poll wake ${Date.now()}`, {
      actorId: user.id,
      strandId,
    });

    const woke = await repoll;
    expect(Date.now() - repollStartedAt, "fresh poll wakes well before the next bound").toBeLessThan(
      5_000,
    );
    expect(woke.some((frame) => frame.kind === "delta")).toBe(true);
  });

  // Complement: csapi/sync_test.go TestSync / TestSyncTimelineGap. Arkret
  // client-sync §§2-3: after is exclusive; reconnect replays durable deltas.
  test("Complement: reconnect and repeated old cursor replay preserve the exact message set", async ({ request }) => {
    const { user, token } = await accountSession(request, "account-replay");
    const realmId = await createRealmApi(request, token, { title: "account replay", ownerId: user.id });
    const old = await sendMessageApi(request, token, realmId, "before saved cursor");
    const filter = { realm_ids: [realmId] };
    const baseline = await accountFramesWithMessages(request, token, realmId, [old.event_id], {
      filter,
      waitFor: old.cursor,
    });
    expectCatchup(baseline);
    expect(messageIds(baseline, realmId)).toEqual([old.event_id]);
    const after = latestCursor(baseline);

    // No subscription is open while these accepted writes accumulate.
    const expected: string[] = [];
    let expectedCursor = old.cursor;
    for (let i = 0; i < 3; i++) {
      const sent = await sendMessageApi(request, token, realmId, `offline message ${i}`);
      expected.push(sent.event_id);
      expectedCursor = sent.cursor;
    }
    const resumed = await accountFramesWithMessages(request, token, realmId, expected, {
      after,
      filter,
      waitFor: expectedCursor,
    });
    expectCatchup(resumed);
    expect(messageIds(resumed, realmId)).toEqual([...expected].sort());

    // Losing the response before persisting its cursor must remain retryable.
    const replay = await accountFramesWithMessages(request, token, realmId, expected, {
      after,
      filter,
    });
    expectCatchup(replay);
    expect(messageIds(replay, realmId)).toEqual([...expected].sort());

    const sentinel = await sendMessageApi(request, token, realmId, "after persisted catch-up");
    const next = await accountFramesWithMessages(request, token, realmId, [sentinel.event_id], {
      after: latestCursor(resumed),
      filter,
      waitFor: sentinel.cursor,
    });
    expectCatchup(next);
    expect(messageIds(next, realmId)).toEqual([sentinel.event_id]);
  });

  // client-sync §2: filter.realms restricts the account Realm buckets.
  test("Complement: initial account sync filters Realm buckets", async ({ request }) => {
    const owner = await accountSession(request, "account-scope-owner");
    const first = await createRealmApi(request, owner.token, { title: "selected Realm", ownerId: owner.user.id });
    const second = await createRealmApi(request, owner.token, { title: "excluded Realm", ownerId: owner.user.id });
    const included = await sendMessageApi(request, owner.token, first, "selected private message");
    const excluded = await sendMessageApi(request, owner.token, second, "excluded private message");

    const filter = { realm_ids: [first, second] };
    const baseline = await accountFramesWithMessages(
      request,
      owner.token,
      second,
      [excluded.event_id],
      { filter, waitFor: excluded.cursor },
    );
    expectCatchup(baseline);
    await expect
      .poll(async () => messageIds(
        await accountSubscribeFramesApi(request, owner.token, { filter }),
        first,
      ))
      .toEqual([included.event_id]);
    expect(messageIds(baseline, second)).toEqual([excluded.event_id]);

    const filtered = await accountSubscribeFramesApi(request, owner.token, {
      filter: { realm_ids: [first] },
    });
    expectCatchup(filtered);
    expect(realmBuckets(filtered).map(([id]) => id)).toEqual([first]);
    expect(messageIds(filtered, first)).toEqual([included.event_id]);
  });

  // Complement: TestSyncTimelineGap. client-sync §§3/5.2 requires explicit
  // truncation plus a window-start state or a preview-only marker.
  test("Complement: limited initial timeline declares truncation and its state boundary", async ({ request }) => {
    const { user, token } = await accountSession(request, "account-limited");
    const realmId = await createRealmApi(request, token, { title: "limited initial timeline", ownerId: user.id });
    const ids: string[] = [];
    let latestMessageCursor: string | undefined;
    for (let index = 0; index < 5; index++) {
      const sent = await sendMessageApi(request, token, realmId, `limited message ${index}`);
      ids.push(sent.event_id);
      latestMessageCursor = sent.cursor;
    }
    const complete = await accountFramesWithMessages(request, token, realmId, ids, {
      filter: { realm_ids: [realmId] },
      waitFor: latestMessageCursor,
    });
    expectCatchup(complete);
    expect(messageIds(complete, realmId)).toEqual([...ids].sort());
    const limited = await accountSubscribeFramesApi(request, token, {
      filter: { realm_ids: [realmId], timeline_limit: 2 },
    });
    expectCatchup(limited);
    const buckets = realmBuckets(limited).filter(([id]) => id === realmId);
    expect(buckets.length, "the selected Realm must still be present").toBeGreaterThan(0);
    for (const [, bucket] of buckets) {
      expect(bucket.timeline?.events?.length, "per-frame timeline_limit must be enforced").toBeLessThanOrEqual(2);
      if (bucket.timeline?.limited === true) {
        expect(bucket.state_at_window_start != null || bucket.timeline?.preview_only === true,
          "a truncated timeline needs window-start state or preview_only").toBe(true);
      }
    }
    const visibleIds = buckets.flatMap(([, bucket]) => bucket.timeline!.events!.map((event) => event.event_id));
    expect(visibleIds).toContain(ids.at(-1));
    expect(new Set(visibleIds).size, "initial frames must not duplicate messages").toBe(visibleIds.length);
    expect(visibleIds.every((id) => ids.includes(id))).toBe(true);
    if (visibleIds.length < ids.length) {
      expect(buckets.some(([, bucket]) => bucket.timeline?.limited === true),
        "omitted history must not be advertised as a complete timeline").toBe(true);
    }
  });

  test("Complement: event kind filters exclude timeline messages without losing the Realm baseline", async ({ request }) => {
    const { user, token } = await accountSession(request, "account-kind-filter");
    const realmId = await createRealmApi(request, token, { title: "kind filter", ownerId: user.id });
    const sent = await sendMessageApi(request, token, realmId, "kind-filter sentinel");
    const included = await accountFramesWithMessages(request, token, realmId, [sent.event_id], {
      filter: { realm_ids: [realmId], event_kinds: ["ak.message.create"] },
      waitFor: sent.cursor,
    });
    expectCatchup(included);
    expect(messageIds(included, realmId)).toEqual([sent.event_id]);
    const excluded = await accountSubscribeFramesApi(request, token, {
      filter: { realm_ids: [realmId], not_event_kinds: ["ak.message.create"] },
    });
    expectCatchup(excluded);
    expect(realmBuckets(excluded).some(([id]) => id === realmId), "timeline filter must not erase current Realm metadata").toBe(true);
    expect(messageIds(excluded, realmId)).toEqual([]);
    const otherKind = await accountSubscribeFramesApi(request, token, {
      filter: { realm_ids: [realmId], event_kinds: ["ak.reaction.add"] },
    });
    expectCatchup(otherKind);
    expect(messageIds(otherKind, realmId)).toEqual([]);
    const deniedWins = await accountSubscribeFramesApi(request, token, {
      filter: {
        realm_ids: [realmId],
        event_kinds: ["ak.message.create"],
        not_event_kinds: ["ak.message.create"],
      },
    });
    expectCatchup(deniedWins);
    expect(messageIds(deniedWins, realmId)).toEqual([]);
  });

  test("account stream filter set order preserves cursor scope", async ({ request }) => {
    const { user, token } = await accountSession(request, "account-filter-set");
    const first = await createRealmApi(request, token, { title: "filter set first", ownerId: user.id });
    const second = await createRealmApi(request, token, { title: "filter set second", ownerId: user.id });
    const baseline = await accountSubscribeFramesApi(request, token, {
      filter: { realm_ids: [second, first], event_kinds: ["ak.reaction.add", "ak.message.create"] },
    });
    expectCatchup(baseline);
    const sent = await sendMessageApi(request, token, first, "equivalent filter sentinel");
    const resumed = await accountFramesWithMessages(request, token, first, [sent.event_id], {
      after: latestCursor(baseline),
      filter: { realm_ids: [first, second], event_kinds: ["ak.message.create", "ak.reaction.add"] },
      waitFor: sent.cursor,
    });
    expectCatchup(resumed);
    expect(messageIds(resumed, first)).toEqual([sent.event_id]);
  });

  test("account stream invalid filters fail before widening the subscription", async ({ request }) => {
    const { token } = await accountSession(request, "account-invalid-filter");
    for (const query of [
      "filter.timeline_limit=invalid", "filter.timeline_limit=-1",
      "filter.timeline_limit=1&filter.timeline_limit=2", "filter.realms=invalid",
      "filter.event_kinds=", "filter.lazy_load_members=invalid", "filter.realm_ids=invalid",
      `filter=${encodeURIComponent(JSON.stringify({ realm_ids: ["ak:realm:duplicate", "ak:realm:duplicate"] }))}`,
    ]) {
      const url = `${solandBaseUrl()}/_arkret/self/account/subscribe?catchup=true&${query}`;
      const response = await request.get(url, { headers: authHeaders(token, "GET", url), timeout: 10_000 });
      expect(response.status(), query).toBe(400);
      expect(wireErrCode(await response.json()), query).toBe("param_invalid");
    }
    expectCatchup(await accountSubscribeFramesApi(request, token));
  });

  // Complement: TestLeakyTyping supplies the positive-recipient / outsider
  // pattern; only its isolation method transfers, not Matrix ephemeral data.
  test("Complement: initial account sync does not disclose another account's private Realm", async ({ request }) => {
    const owner = await accountSession(request, "account-private-owner");
    const outsider = await accountSession(request, "account-private-outsider");
    const realmId = await createRealmApi(request, owner.token, { title: "private sync sentinel", ownerId: owner.user.id });
    const included = await sendMessageApi(request, owner.token, realmId, "private account sentinel");
    const baseline = await accountFramesWithMessages(request, owner.token, realmId, [included.event_id], {
      filter: { realm_ids: [realmId] },
      waitFor: included.cursor,
    });
    expectCatchup(baseline);
    expect(messageIds(baseline, realmId)).toEqual([included.event_id]);

    const foreign = await accountSubscribeFramesApi(request, outsider.token);
    expectCatchup(foreign);
    expect(realmBuckets(foreign).some(([id]) => id === realmId)).toBe(false);
    const leaked = JSON.stringify(foreign).includes(included.event_id);
    expect(leaked, "outsider response must not disclose private Event IDs").toBe(false);
  });

  // encoding §8.3.1: valid handles remain bound to the authenticated account
  // and filter. Negative requests must not consume or invalidate the handle.
  for (const binding of ["account", "filter"] as const) {
    test(`Complement: account cursor rejects cross-${binding} reuse and the original holder can continue`, async ({ request }) => {
      const owner = await accountSession(request, `cursor-${binding}-owner`);
      const other = binding === "account" ? await accountSession(request, "cursor-other") : owner;
      const realmId = await createRealmApi(request, owner.token, { title: `cursor ${binding}`, ownerId: owner.user.id });
      const filter = { realm_ids: [realmId], timeline_limit: 100 };
      const baseline = await accountSubscribeFramesApi(request, owner.token, { filter });
      expectCatchup(baseline);
      const after = latestCursor(baseline);
      const url = new URL(`${solandBaseUrl()}/_arkret/self/account/subscribe`);
      url.searchParams.set("catchup", "true");
      url.searchParams.set("after", after);
      url.searchParams.set(
        "filter",
        JSON.stringify({
          ...filter,
          timeline_limit: binding === "filter" ? 99 : filter.timeline_limit,
        }),
      );
      const response = await request.get(url.toString(), {
        headers: authHeaders(other.token, "GET", url.toString()),
        timeout: 10_000,
      });
      expect(response.status(), "cross-binding fails before starting an NDJSON stream").toBe(400);
      expect(response.headers()["content-type"]).toContain("application/problem+json");
      const error = await response.json();
      expect(wireErrCode(error)).toBe("cursor_integrity_invalid");
      expect(error).not.toHaveProperty("realms");

      const sentinel = await sendMessageApi(request, owner.token, realmId, "cursor still usable");
      const resumed = await accountFramesWithMessages(request, owner.token, realmId, [sentinel.event_id], {
        after,
        filter,
        waitFor: sentinel.cursor,
      });
      expectCatchup(resumed);
      expect(messageIds(resumed, realmId)).toEqual([sentinel.event_id]);
    });
  }
});
