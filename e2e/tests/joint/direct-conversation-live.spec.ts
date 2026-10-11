import { openAndPairSecondController } from "../../helpers/paired-controller";
import { test, expect, type JointUsersFixture } from "../../helpers/joint-fixture";
import type { APIRequestContext, Browser, Page, Response } from "@playwright/test";
import { requestContactArkret, respondContactArkret } from "../../helpers/contact-api";
import { accountActorId, assertAuthoritySubmitOutcome, canonicalJson } from "../../helpers/coland-api";
import { decodeEventIngressBody, ingressEvents } from "../../helpers/event-ingress";

import { flatTopicChats } from "../../helpers/direct-structure";

function directConversationCase(mode: "normal" | "interrupted" | "offline") {
return async ({ jointUsers, request, browser }: { jointUsers: JointUsersFixture; request: APIRequestContext; browser: Browser }) => {
  test.setTimeout(mode === "normal" ? 900_000 : 480_000);
  // A Contact pair must establish its own Direct Conversation without any
  // pre-existing shared Realm. Exercise only the two account prerequisites.
  const { alicePage, bobPage, aliceSession, bobSession } = jointUsers;
  const alice = alicePage.page;
  const bob = bobPage.page;
  const interruptPreparation = mode !== "normal";
  await Promise.all([
    alicePage.completeRecoveryKeySetupIfPrompted(30_000),
    bobPage.completeRecoveryKeySetupIfPrompted(30_000),
  ]);
  const { outcome } = await requestContactArkret(request, aliceSession.grantJwt, bobSession.user.id, {
    requestedScopes: ["direct_message", "presence"],
  });
  const accepted = await respondContactArkret(request, bobSession.grantJwt, {
    requestId: outcome.request_event_ref,
    requesterId: aliceSession.user.id,
    action: "accept",
    grantedScopes: ["direct_message", "presence"],
  });
  expect(accepted.state).toBe("accepted");

  // Claim blocking fixes the pre-join boundary at epoch 0; since_join forbids
  // delivering that epoch to the future peer. Consume blocking instead tests
  // post-Add delivery before the peer's durable acknowledgement.
  const preparationPath = mode === "offline"
    ? "**/_arkret/self/keys/keypackages/claim"
    : "**/_arkret/self/keys/keypackages/consume";
  const interruptedPreparationRequests = new Map<string, number>();
  const interruptedWelcomeEpochs = new Map<string, number>();
  for (const page of interruptPreparation ? [alice, bob] : []) {
    await page.route(preparationPath, async (route) => {
      const body = route.request().postDataJSON() as {
        intended_realm_id?: string;
        recipient_durable_receipt?: { realm_id: string; mls_epoch: number };
      };
      const realm = mode === "offline" ? body.intended_realm_id : body.recipient_durable_receipt?.realm_id;
      expect(typeof realm, "interrupted request must identify its exact Realm").toBe("string");
      interruptedPreparationRequests.set(realm!, (interruptedPreparationRequests.get(realm!) ?? 0) + 1);
      if (body.recipient_durable_receipt) {
        interruptedWelcomeEpochs.set(realm!, body.recipient_durable_receipt.mls_epoch);
      }
      await route.abort("failed");
    });
  }
  await Promise.all([alice.reload(), bob.reload()]);
  let founder: Page | undefined;
  let releaseResolve!: () => void;
  const resolveDelay = new Promise<void>(resolve => { releaseResolve = resolve; });
  let acceptFounding!: (response: Response) => void;
  const foundingAccepted = new Promise<Response>(resolve => { acceptFounding = resolve; });
  const resolvePath = "**/_arkret/self/direct-conversations/resolve";
  const pendingResolveRoutes = new Set<Promise<void>>();
  if (mode === "normal") {
    for (const page of [alice, bob]) {
      page.on("request", request => {
        if (request.method() !== "POST" || new URL(request.url()).pathname !== "/_arkret/self/events") return;
        if (request.postDataJSON()?.unit_kind === "direct_conversation_founding") founder = page;
      });
      page.on("response", response => {
        if (response.request().method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return;
        if (response.request().postDataJSON()?.unit_kind === "direct_conversation_founding") acceptFounding(response);
      });
      await page.route(resolvePath, async route => {
        const handling = (async () => {
          if (founder === page) await resolveDelay;
          await route.continue();
        })();
        pendingResolveRoutes.add(handling);
        try {
          await handling;
        } finally {
          pendingResolveRoutes.delete(handling);
        }
      });
    }
  }
  try {
  for (const [page, peer] of [[alice, bobSession.user.id], [bob, aliceSession.user.id]] as const) {
    await page.getByTestId("realm-sidebar-tab-direct").click();
    await page.locator(`[data-testid="direct-conversation-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(peer)))}]`).click();
  }
  if (mode === "normal") {
    const acceptedResponse = await foundingAccepted;
    expect(acceptedResponse.ok(), await acceptedResponse.text()).toBeTruthy();
    const acceptedAt = Date.now();
    expect(founder).toBeDefined();
    await expect(founder!).toHaveURL(/\/direct\/ak:realm:.*\/ak:strand:/, { timeout: 15_000 });
    await expect(founder!.getByTestId("chat-panel")).toBeVisible();
    await expect(founder!.getByTestId("chat-panel")).toHaveAttribute("data-chat-mode", "direct");
    test.info().annotations.push({ type: "founding-navigation-ms", description: String(Date.now() - acceptedAt) });
  }
  } finally {
    releaseResolve();
    await Promise.all([...pendingResolveRoutes]);
    if (mode === "normal") await Promise.all([alice.unroute(resolvePath), bob.unroute(resolvePath)]);
  }
  // The first click may belong to the non-founder. Once the selected founder
  // creates the pair, opening the same sidebar row must resolve its coordinates.
  for (const [page, peer] of [[alice, bobSession.user.id], [bob, aliceSession.user.id]] as const) {
    await expect(async () => {
      if (!new URL(page.url()).pathname.startsWith("/direct/")) {
        await page.locator(`[data-testid="direct-conversation-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(peer)))}]`).click();
      }
      await expect(page).toHaveURL(/\/direct\/ak:realm:.*\/ak:strand:/, { timeout: 5_000 });
    }).toPass({ timeout: 180_000, intervals: [2_000] });
  }
  const path = new URL(alice.url()).pathname;
  expect(new URL(bob.url()).pathname).toBe(path);
  const messages: string[] = [];
  let preJoinMessage: string | undefined;
  if (interruptPreparation) {
    const directRealm = decodeURIComponent(path.split("/")[2]);
    await expect.poll(() => interruptedPreparationRequests.get(directRealm) ?? 0, { timeout: 120_000 }).toBeGreaterThan(0);
    if (mode === "interrupted") {
      await expect.poll(() => interruptedWelcomeEpochs.get(directRealm) ?? 0, { timeout: 120_000 }).toBeGreaterThan(0);
      // The peer can observe Welcome before the founder has replayed the
      // covering MLS Commit. Reopen the founder while consume stays blocked;
      // its durable admission must restore the post-Add sending state.
      await bob.reload();
      await expect.poll(async () => Number(await bob.getByTestId("chat-panel").getAttribute("data-mls-epoch")), { timeout: 180_000 }).toBeGreaterThan(0);
    }
    await alice.getByTestId("chat-input").fill("preparation probe");
    await expect(alice.getByTestId("send-chat-button")).toBeDisabled();
    // The responder is the founder. Spec §7.2 permits real exporter messages
    // before the peer's durable Welcome, including when that device is offline.
    if (mode === "offline") await alice.context().setOffline(true);
    const provisional = `direct-provisional-${Date.now()}`;
    await bob.getByTestId("chat-input").fill(provisional);
    await expect(bob.getByTestId("send-chat-button")).toBeEnabled({ timeout: 120_000 });
    const submitted = bob.waitForResponse(response => {
      const observed = response.request();
      if (observed.method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return false;
      return ingressEvents(decodeEventIngressBody(observed.postDataJSON()))
        .some(event => event.kind === "ak.message.create");
    }, { timeout: 90_000 });
    await bob.getByTestId("send-chat-button").click();
    const response = await submitted;
    expect(response.ok(), await response.text()).toBeTruthy();
    const sentEvent = ingressEvents(decodeEventIngressBody(response.request().postDataJSON()))
      .find(event => event.kind === "ak.message.create");
    const submission = await response.json() as Record<string, unknown>;
    expect(sentEvent, "the provisional submission carries its message").toBeTruthy();
    expect(submission.status, `provisional outcome reason: ${String(submission.reason_code ?? "none")}`).toBe("committed");
    assertAuthoritySubmitOutcome(submission, sentEvent!, "provisional Direct message");
    const envelope = sentEvent?.payload?.encrypted_content as { encryption_context?: { epoch?: number } } | undefined;
    if (mode === "offline") {
      expect(envelope?.encryption_context?.epoch).toBe(0);
      preJoinMessage = provisional;
    } else {
      expect(envelope?.encryption_context?.epoch).toBeGreaterThan(0);
      messages.push(provisional);
    }
    if (mode === "offline") await alice.context().setOffline(false);
    await Promise.all([alice.unroute(preparationPath), bob.unroute(preparationPath)]);
    await Promise.all([alice.reload(), bob.reload()]);
  }
  for (const page of [alice, bob]) {
    await page.getByTestId("chat-input").fill("preparation probe");
    await expect(page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 180_000 });
    expect(new URL(page.url()).pathname).toBe(path);
  }
  if (mode === "offline") {
    // Enabled alone also describes the founder's legitimate epoch-0 phase.
    // A post-join offline test needs both local snapshots at the joined epoch.
    await expect.poll(async () => {
      const epochs = await Promise.all([alice, bob].map(async page =>
        Number(await page.getByTestId("chat-panel").getAttribute("data-mls-epoch"))));
      return epochs[0] > 0 && epochs[0] === epochs[1];
    }, { timeout: 180_000 }).toBe(true);
    await alice.context().setOffline(true);
    const offlineMessage = `direct-offline-after-join-${Date.now()}`;
    await bob.getByTestId("chat-input").fill(offlineMessage);
    const offlineSubmission = bob.waitForResponse(response =>
      response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/events"
      && ingressEvents(decodeEventIngressBody(response.request().postDataJSON()))
        .some(event => event.kind === "ak.message.create"), { timeout: 90_000 });
    await bob.getByTestId("send-chat-button").click();
    const offlineResponse = await offlineSubmission;
    expect(offlineResponse.ok(), await offlineResponse.text()).toBeTruthy();
    const offlineEvent = ingressEvents(decodeEventIngressBody(offlineResponse.request().postDataJSON()))
      .find(event => event.kind === "ak.message.create");
    const offlineOutcome = await offlineResponse.json() as Record<string, unknown>;
    expect(offlineEvent, "the offline submission carries its message").toBeTruthy();
    expect(offlineOutcome.status, `post-join outcome reason: ${String(offlineOutcome.reason_code ?? "none")}`).toBe("committed");
    assertAuthoritySubmitOutcome(offlineOutcome, offlineEvent!, "post-join offline Direct message");
    const offlineEnvelope = offlineEvent?.payload?.encrypted_content as { encryption_context?: { epoch?: number } } | undefined;
    expect(offlineEnvelope?.encryption_context?.epoch).toBeGreaterThan(0);
    await expect(bob.getByTestId("chat-message").filter({ hasText: offlineMessage })).toBeVisible();
    await alice.context().setOffline(false);
    await alice.reload();
    await expect(alice.getByTestId("chat-message").filter({ hasText: offlineMessage })).toBeVisible({ timeout: 90_000 });
    messages.push(offlineMessage);
  }

  const exchange = [`direct-alice-${Date.now()}`, `direct-bob-${Date.now()}`];
  messages.push(...exchange);
  for (const [sender, recipient, message] of [[alice, bob, exchange[0]], [bob, alice, exchange[1]]] as const) {
    await sender.getByTestId("chat-input").fill(message);
    await sender.getByTestId("send-chat-button").click();
    await expect(recipient.getByTestId("chat-message").filter({ hasText: message })).toBeVisible({ timeout: 90_000 });
  }
  await Promise.all([alice.reload(), bob.reload()]);
  for (const page of [alice, bob]) {
    for (const message of messages) {
      await expect(page.getByTestId("chat-message").filter({ hasText: message })).toBeVisible({ timeout: 90_000 });
    }
  }
  if (preJoinMessage) {
    await expect(bob.getByTestId("chat-message").filter({ hasText: preJoinMessage })).toBeVisible({ timeout: 90_000 });
    await expect(alice.getByTestId("chat-message").filter({ hasText: preJoinMessage })).toHaveCount(0);
  }
  const afterReload = `direct-after-reload-${Date.now()}`;
  await bob.getByTestId("chat-input").fill(afterReload);
  await bob.getByTestId("send-chat-button").click();
  await expect(alice.getByTestId("chat-message").filter({ hasText: afterReload })).toBeVisible({ timeout: 90_000 });
  if (mode === "normal") {
    const paired = await openAndPairSecondController(browser, request, jointUsers);
    try {
      await alice.goto(path, { waitUntil: "domcontentloaded" });
      await paired.page.page.goto(path, { waitUntil: "domcontentloaded" });
      expect(jointUsers.aliceSession.recoveryKey).toBeTruthy();
      await paired.page.unlockMlsAccountSecret(jointUsers.aliceSession.recoveryKey!);
      await expect(paired.page.page.getByTestId("send-chat-button")).toBeEnabled({ timeout: 180_000 });
      await flatTopicChats(alice, bob, [...messages, afterReload], [paired.page.page]);
    } finally {
      await paired.page.close();
    }
  }
  for (const [page, peer] of [[alice, bobSession.user.id], [bob, aliceSession.user.id]] as const) {
    const presence = page.locator(`[data-testid="presence-row"][data-actor-id=${JSON.stringify(canonicalJson(accountActorId(peer)))}]`);
    await expect.soft(presence).toHaveAttribute("data-presence-state", "online", { timeout: 90_000 });
  }
};
}

test("same-server Direct Conversation exchanges encrypted messages and retains them after reload", directConversationCase("normal"));
test("same-server Direct Conversation resumes interrupted preparation and exchanges messages after reload", directConversationCase("interrupted"));
test("same-server Direct Conversation founder sends while the peer device is offline and the peer decrypts after reconnect", directConversationCase("offline"));
