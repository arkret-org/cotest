// Account stream and device-message convergence.
// Spec: sync/service-http-binding.md §2.3 (account subscribe and device messages)
//       crypto-media/device-lifecycle.md §7 (durable to-device delivery)

import { expect, test } from "../../helpers/arkret-test";
import { sendPlaintextMessageViaApi } from "../../helpers/api";
import {
  accountSubscribeFramesApi,
  createRealmApi,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function latestCursor(frames: Array<Record<string, unknown>>): string {
  const cursor = [...frames]
    .reverse()
    .map((frame) => frame.cursor)
    .find((value): value is string => typeof value === "string");
  expect(cursor, `account frames have a cursor: ${JSON.stringify(frames)}`).toBeTruthy();
  return cursor!;
}

test.describe("account stream + device-message convergence", () => {
  test("quiet long-poll closes at its bound and a fresh poll wakes on the next delta", async ({
    request,
  }) => {
    test.setTimeout(75_000);
    const user = uniqueUser(`account-long-poll-${Date.now()}`);
    await ensureRegistered(request, user);
    const token = await issueDevSession(request, user);
    const realmId = await createRealmApi(request, token, {
      title: `long-poll scope ${Date.now()}`,
      ownerDid: user.did,
    });
    const filter = { realms: [realmId] };

    const baseline = await accountSubscribeFramesApi(request, token, { filter });
    const baselineCursor = latestCursor(baseline);

    const quietStartedAt = Date.now();
    const quietPoll = accountSubscribeFramesApi(request, token, {
      after: baselineCursor,
      filter,
      timeoutMs: 40_000,
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    await createRealmApi(request, token, {
      title: `out-of-scope long-poll activity ${Date.now()}`,
      ownerDid: user.did,
    });
    const quiet = await quietPoll;
    const quietElapsedMs = Date.now() - quietStartedAt;
    expect(quiet[0]?.kind).toBe("frontier");
    expect(quietElapsedMs, "quiet poll respects the server-side 30s bound").toBeGreaterThanOrEqual(
      28_000,
    );
    expect(quietElapsedMs).toBeLessThan(40_000);

    const repollStartedAt = Date.now();
    const repoll = accountSubscribeFramesApi(request, token, {
      after: latestCursor(quiet),
      filter,
      timeoutMs: 10_000,
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    await sendPlaintextMessageViaApi(request, token, realmId, `long-poll wake ${Date.now()}`, {
      actorDid: user.did,
    });

    const woke = await repoll;
    expect(Date.now() - repollStartedAt, "fresh poll wakes well before the next bound").toBeLessThan(
      5_000,
    );
    expect(woke.some((frame) => frame.kind === "delta")).toBe(true);
  });
});
