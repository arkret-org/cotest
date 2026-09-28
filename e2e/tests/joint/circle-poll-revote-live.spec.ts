// Real Station Circle stream plus Inkson poll authoring and verified readback.
import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { accountSubscribeFramesApi, canonicalJson, scanRealmStreamApi, accountActorId } from "../../helpers/soland-api";
import { createDpopUserSession, openUserPage, type JointUserPage } from "../../helpers/users";
import { solandBaseUrl } from "../../helpers/env";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

test("Circle poll survives readback, replacement, a new browser process and another replacement", async ({ request, browser }) => {
  test.setTimeout(420_000);
  // Keep the Chromium profile path short on Windows: deeply nested artifact
  // paths can make IndexedDB fail to open its LevelDB backing store.
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "cp-"));
  let activePage: JointUserPage | undefined;
  let bobPage: JointUserPage | undefined;
  try {
  // Enroll Alice in the persistent Chromium profile from the first login.
  // The secure store contains a non-extractable CryptoKey, which Playwright's
  // storageState serialization cannot transfer into a different profile.
  const aliceSession = await createDpopUserSession(request, "circle-poll-alice");
  const bobSession = await createDpopUserSession(request, "circle-poll-bob");
  expect(aliceSession).toBeTruthy();
  expect(bobSession).toBeTruthy();
  const alice = aliceSession!.user;
  const bob = bobSession!.user;
  const aliceToken = aliceSession!.grantJwt;
  const stamp = Date.now();
  const circleTitle = `Poll Circle ${stamp}`;
  const strandTitle = `Poll Strand ${stamp}`;
  const question = `Circle rollout ${stamp}?`;
  const answers = [`Now ${stamp}`, `Later ${stamp}`];
  const acceptedAliceDevice = {
    grantJwt: aliceSession!.grantJwt,
    dpopSeedB64url: aliceSession!.dpopSeedB64url,
    eventSigningSeedB64url: aliceSession!.eventSigningSeedB64url,
    grantId: aliceSession!.grantId,
    accountId: aliceSession!.accountId,
    principalControlRealmId: aliceSession!.principalControlRealmId,
    grantAudience: aliceSession!.grantAudience,
    recoveryKey: aliceSession!.recoveryKey,
    recoveryMaterialEvidence: aliceSession!.recoveryMaterialEvidence,
    persistentUserDataDir: profileDir,
  };
  activePage = await openUserPage(browser, alice, acceptedAliceDevice);
  bobPage = await openUserPage(browser, bob, {
    grantJwt: bobSession!.grantJwt,
    dpopSeedB64url: bobSession!.dpopSeedB64url,
    eventSigningSeedB64url: bobSession!.eventSigningSeedB64url,
    grantId: bobSession!.grantId,
    accountId: bobSession!.accountId,
    principalControlRealmId: bobSession!.principalControlRealmId,
    grantAudience: bobSession!.grantAudience,
    recoveryKey: bobSession!.recoveryKey,
    recoveryMaterialEvidence: bobSession!.recoveryMaterialEvidence,
  });
  let page = activePage.page;
  await Promise.all([activePage.gotoHome(), bobPage.gotoHome()]);
  const realmId = await activePage.createRealm({
    title: `joint smoke ${stamp}`,
    summary: "cotest Circle poll live",
    discoverability: "public",
    joinRule: "invite",
    historyAccess: "since_join",
    mlsActivated: false,
  });
  const serviceHealth = await request.get(`${solandBaseUrl()}/health`);
  expect(serviceHealth.status(), "real governing Station is available").toBe(200);
  await Promise.all([
    activePage.completeRecoveryKeySetupIfPrompted(30_000),
    bobPage.completeRecoveryKeySetupIfPrompted(30_000),
  ]);

  await page.goto(`/realms/${encodeURIComponent(realmId)}/circles`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("circles-panel")).toBeVisible();
  await page.getByTestId("circle-create-open").click();
  await page.getByTestId("circle-create-title").fill(circleTitle);
  await page.getByTestId("circle-create-submit").click();
  await expect(page).toHaveURL(/\/realms\/[^/]+\/circles\/[^/]+$/);
  const circleId = decodeURIComponent(page.url().split("/").at(-1) ?? "");
  expect(circleId).toMatch(/^ak:circle:/);
  // Creating the first Circle can trigger the account recovery policy setup.
  // Complete the real UI flow before opening the Strand composer; the setup
  // dialog can navigate the shell and discard an already open composer.
  await activePage.completeRecoveryKeySetupIfPrompted(30_000);

  await activePage.gotoTimelineRealm(realmId);
  await activePage.completeRecoveryKeySetupIfPrompted(2_000);
  await page.getByTestId("open-channel-dialog").click();
  await expect(page.getByTestId("channel-create-modal")).toBeVisible();
  await page.getByTestId("new-channel-name").fill(strandTitle);
  const picker = page.getByTestId("new-channel-circle-scope");
  await picker.locator('button[aria-haspopup="listbox"]').click();
  await picker.locator(`[role="option"][data-value="${circleId}"]`).click();
  await expect(picker.locator('button[aria-haspopup="listbox"]')).toContainText(circleTitle);
  await expect(page.getByTestId("channel-create-modal")).toBeVisible();
  await page.getByTestId("create-channel-button").click();
  const channel = page.getByTestId("channel-item").filter({ hasText: strandTitle });
  await expect(channel).toBeVisible({ timeout: 60_000 });
  await channel.click();
  await expect(channel).toHaveClass(/active/);

  await page.getByTestId("open-poll-composer-button").click();
  await page.getByTestId("poll-question-input").fill(question);
  await page.getByTestId("poll-option-input").nth(0).fill(answers[0]!);
  await page.getByTestId("poll-option-input").nth(1).fill(answers[1]!);
  await page.getByTestId("send-poll-button").click();
  const poll = page.getByTestId("poll-card").filter({ hasText: question }).first();
  await expect(poll).toBeVisible({ timeout: 60_000 });
  await expect(poll).toHaveAttribute("data-poll-id", /^ak:message:/, { timeout: 60_000 });
  const pollRef = await poll.getAttribute("data-poll-id");
  expect(pollRef).toMatch(/^ak:message:/);
  const pollEventRef = pollRef!.replace(/^ak:message:/, "ak:event:");
  await expect(page.getByTestId("chat-message").filter({ has: poll })).toHaveAttribute(
    "data-circle-scope-id", circleId,
  );

  await expect.poll(async () => {
    const scan = await circlePollEvents(request, aliceToken, realmId, circleId);
    return scan.events.some((event) => event.event_id === pollEventRef);
  }).toBe(true);
  const initialScan = await circlePollEvents(request, aliceToken, realmId, circleId);
  const pollEvent = initialScan.events.find((event) => event.event_id === pollEventRef)!;
  expect(pollEvent.scope_ref).toEqual({ kind: "circle", realm_id: realmId, circle_id: circleId });
  expect(pollEvent.producer_proof).toBeTruthy();
  const pollContent = (pollEvent.payload as Record<string, unknown>).content as Record<string, unknown>;
  expect(pollContent.kind).toBe("ak.content.poll");
  const answerIds = ((pollContent.poll as Record<string, unknown>).answers as Array<Record<string, unknown>>)
    .map((answer) => String(answer.id));
  expect(answerIds).toHaveLength(2);

  const expectedHeads: string[][] = [[], [], []];
    for (const [index, answer] of [answers[0]!, answers[1]!, answers[0]!].entries()) {
      if (index === 2) {
        // End Alice's original client runtime. Reopen the same accepted device
        // in a newly launched Chromium OS process, then demand the poll from the
        // real Circle stream before authoring the third vote.
        const firstProcessContext = activePage.session.context;
        const beforeRestart = await firstProcessContext.storageState({ indexedDB: true }) as unknown as {
          origins: Array<{ origin: string; indexedDB?: unknown[] }>;
        };
        expect(beforeRestart.origins.some(({ origin, indexedDB }) =>
          origin === new URL(page.url()).origin && (indexedDB?.length ?? 0) > 0,
        ), "the original Chromium profile holds durable Inkson IndexedDB").toBe(true);
        await activePage.close();
        activePage = await openUserPage(browser, alice, {
          ...acceptedAliceDevice,
          resumePersistentProfile: true,
        });
        expect(activePage.session.context).not.toBe(firstProcessContext);
        page = activePage.page;
        await activePage.gotoHome();
        const afterRestart = await activePage.session.context.storageState({ indexedDB: true }) as unknown as {
          origins: Array<{ origin: string; indexedDB?: unknown[] }>;
        };
        expect(afterRestart.origins.some(({ origin, indexedDB }) =>
          origin === new URL(page.url()).origin && (indexedDB?.length ?? 0) > 0,
        ), "the relaunched Chromium process reopened the same IndexedDB profile").toBe(true);
        const acceptedAfterRestart = await circlePollEvents(request, aliceToken, realmId, circleId);
        expect(acceptedAfterRestart.events.some((event) => event.event_id === pollEventRef),
          "the governing Circle stream retains the accepted poll after process restart").toBe(true);
        const accountFrames = await accountSubscribeFramesApi(request, aliceToken, {
          filter: { realm_ids: [realmId], window_limit: 20 },
        });
        const accountCurrent = accountFrames.flatMap((frame) => {
          const realms = frame.realms as Record<string, Record<string, unknown>> | undefined;
          const current = realms?.[realmId]?.current as Record<string, unknown> | undefined;
          return current ? [current] : [];
        });
        expect(accountCurrent.length, "Account stream discloses selected Realm current").toBeGreaterThan(0);
        expect(accountCurrent.some((current) => (current.stream_heads as Array<Record<string, unknown>> ?? [])
          .some((head) => (head.stream_ref as Record<string, unknown>)?.circle_id === circleId)),
          "Account current carries the readable Circle head").toBe(true);
        expect(accountCurrent.some((current) => (current.entries as Array<Record<string, unknown>> ?? [])
          .some((entry) => (entry.selector as Record<string, unknown>)?.kind === "strand"
            && ((entry.value as Record<string, unknown>)?.metadata as Record<string, unknown>)?.title === strandTitle)),
          "Account current carries the accepted Circle Strand").toBe(true);
        await activePage.gotoTimelineRealm(realmId);
        await expect(page.getByTestId("chat-panel")).toBeVisible({ timeout: 120_000 });
        await expect(page.getByTestId("chat-panel")).toHaveAttribute(
          "data-initial-sync", "complete", { timeout: 120_000 },
        );
        await page.getByTestId("channel-item").filter({ hasText: strandTitle }).click();
        await expect(page.getByTestId("poll-card").filter({ hasText: question })).toBeVisible();
      }
      const card = page.getByTestId("poll-card").filter({ hasText: question }).first();
      await card.getByTestId("poll-option").filter({ hasText: answer }).click();
      const expectedCounts = index === 1 ? ["0", "1"] : ["1", "0"];
      for (const [optionIndex, count] of expectedCounts.entries()) {
        await expect(card.getByTestId("poll-result-row").filter({ hasText: answers[optionIndex]! })
          .getByTestId("poll-vote-count")).toHaveText(count, { timeout: 60_000 });
      }
      await expect.poll(async () => {
        const scan = await circlePollEvents(request, aliceToken, realmId, circleId);
        return responseRows(scan, pollRef!, accountActorId(alice.id));
      }, { timeout: 60_000 }).toHaveLength(index + 1);
      const scan = await circlePollEvents(request, aliceToken, realmId, circleId);
      const rows = responseRows(scan, pollRef!, accountActorId(alice.id));
      const latest = rows[index]!;
      expect(latest.event.producer_proof).toBeTruthy();
      expect(latest.event.scope_ref).toEqual({ kind: "circle", realm_id: realmId, circle_id: circleId });
      expect(latest.event.payload).toMatchObject({
        content: { kind: "ak.content.poll.response", poll_response: {
          poll_ref: pollRef, selections: [answerIds[index === 1 ? 1 : 0]],
        } },
      });
      const declared = ((latest.event.payload as Record<string, unknown>).poll_response_heads ?? []) as Array<Record<string, string>>;
      expect(declared.map((head) => head.response_event_ref)).toEqual(expectedHeads[index]);
      for (const head of declared) expect(head.poll_event_ref).toBe(pollEventRef);
      if (index < 2) expectedHeads[index + 1] = [String(latest.event.event_id)];
      expect(rows.map((row) => Number(row.commit.stream_position))).toEqual(
        [...rows.map((row) => Number(row.commit.stream_position))].sort((a, b) => a - b),
      );
      expect(String(rows.at(-1)!.event.event_id), "service stream-position winner").toBe(String(latest.event.event_id));
    }
  } finally {
    await Promise.allSettled([activePage?.close(), bobPage?.close()]);
    const parent = fs.realpathSync(os.tmpdir());
    const actual = fs.realpathSync(profileDir);
    if (path.dirname(actual) !== parent) throw new Error("persistent profile escaped the test temp root");
    fs.rmSync(actual, { recursive: true, force: true });
  }
});

async function circlePollEvents(request: APIRequestContext, token: string, realmId: string, circleId: string) {
  const scan = await scanRealmStreamApi(request, token, realmId, {
    streamRef: { kind: "circle", realm_id: realmId, circle_id: circleId }, limit: 256,
  });
  expect(scan.truncated, "Circle poll fits in a complete authenticated stream page").toBe(false);
  return scan;
}

function responseRows(
  scan: Awaited<ReturnType<typeof circlePollEvents>>,
  pollRef: string,
  actor: ReturnType<typeof accountActorId>,
) {
  return scan.events.map((event, index) => ({ event, commit: scan.commits[index]! }))
    .filter(({ event }) => event.kind === "ak.message.create"
      && canonicalJson(event.actor_id) === canonicalJson(actor)
      && ((event.payload as Record<string, unknown>)?.content as Record<string, unknown>)?.kind === "ak.content.poll.response"
      && ((((event.payload as Record<string, unknown>).content as Record<string, unknown>).poll_response as Record<string, unknown>)?.poll_ref) === pollRef)
    .sort((left, right) => Number(left.commit.stream_position) - Number(right.commit.stream_position));
}
