import { uint64Decimal, uint64Value } from "../../helpers/uint64-decimal";
import { submitOrdinaryComposerDraft } from "../../helpers/composer-handoff";
import { readCreatorRecords } from "../../helpers/creator-bootstrap";
import { accountRow } from "../../helpers/product-locators";
import { openAndPairSecondController } from "../../helpers/paired-controller";
import { test, expect, type JointUsersFixture } from "../../helpers/joint-fixture";
import type { APIRequestContext, Browser, Page, Response } from "@playwright/test";
import type { AccountId } from "../../helpers/generated/spec-wire-objects";
import { requestContactArkret, respondContactArkret, resolvePrincipalLocator, tombstoneContactArkret } from "../../helpers/contact-api";
import { accountActorId, assertAuthoritySubmitOutcome, canonicalJson, createRealmApi, resolveDefaultStrandId, scanRealmStreamApi, sdkEventDerivedObjectId, signedEventEnvelope, submitSignedEventApi } from "../../helpers/coland-api";
import { decodeEventIngressBody, ingressEvents } from "../../helpers/event-ingress";
import { readScopeMlsGroupCurrentApi } from "../../helpers/coland-api/mls";

import { approvePairingLinkOnAuthorizedDevice, createDpopUserSession, openDpopUserPageFromSession, selfPathHeadersForDpopSession } from "../../helpers/users";
import { serverLoginViaCoauth, submitCoauthPasswordCredentials } from "../../helpers/real-oidc-login";
import { colandBaseUrl } from "../../helpers/env";

import { createDirectBoundaryCircleStrand, directStructureLifecycleGate, flatTopicChats, rejectDirectStructureEvent } from "../../helpers/direct-structure";

async function openContactConversation(page: Page, account: AccountId): Promise<void> {
  await page.locator(".rail-contacts").click();
  const people = page.locator(".contact-list-item:not(.contact-agent-list-item)");
  // These fresh two-account fixtures have exactly one human Contact. Verify
  // its complete identity in the detail before activating Message.
  await expect(people).toHaveCount(1, { timeout: 90_000 });
  await people.click();
  const detail = accountRow(page, ".contact-row", account);
  await expect(detail).toBeVisible({ timeout: 90_000 });
  // Message is available only for an accepted Contact with direct_message.
  const message = detail.locator(".contact-message");
  await expect(message).toBeEnabled({ timeout: 90_000 });
  await message.click();
}

function directConversationCase(mode: "normal" | "interrupted" | "offline" | "lost" | "logout" | "account" | "withdrawal" | "leave", remoteBob = false) {
return async ({ jointUsers, request, browser }: { jointUsers: JointUsersFixture; request: APIRequestContext; browser: Browser }) => {
  // The normal case includes the full structure lifecycle and physical cache
  // recovery, matching the dedicated cross-Station case's total budget.
  test.setTimeout(mode === "normal" ? 1_200_000 : 480_000);
  // A Contact pair must establish its own Direct Conversation without any
  // pre-existing shared Realm. Exercise only the two account prerequisites.
  const { alicePage, bobPage, aliceSession, bobSession } = jointUsers;
  const alice = alicePage.page;
  const bob = bobPage.page;
  const interruptPreparation = mode === "interrupted" || mode === "offline";
  const holdSecondResolve = mode === "normal" || mode === "logout" || mode === "account";
  const phase = (stage: string) => {
    if (remoteBob) console.info("Cross-station Direct preparation", JSON.stringify({ stage, mode }));
  };
  const recoveryKeys = new Map<Page, string>();
  const resolveObservations = new Map<Page, string>();
  phase("recovery_start");
  await Promise.all([
    alicePage.completeRecoveryKeySetupIfPrompted(30_000).then(key => {
      if (key) recoveryKeys.set(alice, key);
      phase("alice_recovery_finished");
    }),
    bobPage.completeRecoveryKeySetupIfPrompted(30_000).then(key => {
      if (key) recoveryKeys.set(bob, key);
      phase("bob_recovery_finished");
    }),
  ]);

  // Claim blocking fixes the pre-join boundary at epoch 0; since_join forbids
  // delivering that epoch to the future peer. Consume blocking instead tests
  // post-Add delivery before the peer's durable acknowledgement.
  const preparationPath = mode === "offline"
    ? "**/_arkret/self/keys/keypackages/claim"
    : "**/_arkret/self/keys/keypackages/consume";
  const interruptedPreparationRequests = new Map<string, number>();
  const interruptedWelcomeEpochs = new Map<string, string>();
  for (const page of interruptPreparation ? [alice, bob] : []) {
    await page.route(preparationPath, async (route) => {
      const body = route.request().postDataJSON() as {
        intended_realm_id?: string;
        recipient_durable_receipt?: { realm_id: string; mls_epoch: string };
      };
      const realm = mode === "offline" ? body.intended_realm_id : body.recipient_durable_receipt?.realm_id;
      expect(typeof realm, "interrupted request must identify its exact Realm").toBe("string");
      interruptedPreparationRequests.set(realm!, (interruptedPreparationRequests.get(realm!) ?? 0) + 1);
      if (body.recipient_durable_receipt) {
        interruptedWelcomeEpochs.set(realm!, uint64Decimal(body.recipient_durable_receipt.mls_epoch));
      }
      await route.abort("failed");
    });
  }
  let founder: Page | undefined;
  let foundingAcceptedAt: number | undefined;
  let releaseResolve!: () => void;
  const resolveDelay = new Promise<void>(resolve => { releaseResolve = resolve; });
  let acceptFounding!: (response: Response) => void;
  const foundingAccepted = new Promise<Response>(resolve => { acceptFounding = resolve; });
  let foundingRequestCount = 0;
  let foundingResponseCount = 0;
  const waitForFoundingAcceptance = async () => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        foundingAccepted,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("Direct founding acceptance was not observed within180s")), 180_000);
        }),
      ]);
    } catch (error) {
      const diagnostic = { mode, cross_station: remoteBob, founding_requests: foundingRequestCount,
        founding_responses: foundingResponseCount, committed_response_observed: foundingAcceptedAt !== undefined,
        resolver_observations: [...resolveObservations.values()].map(value => JSON.parse(value)) };
      console.warn("Direct founding observation timeout", JSON.stringify(diagnostic));
      await test.info().attach("direct-founding-observation-timeout", {
        body: JSON.stringify(diagnostic), contentType: "application/json",
      });
      throw error;
    } finally { if (timer) clearTimeout(timer); }
  };
  const resolvePath = "**/_arkret/self/direct-conversations/resolve";
  const pendingResolveRoutes = new Set<Promise<void>>();
  let browserCancelledOldResolves = 0;
  let heldResolvedCoordinates: { realm_id: string; main_strand_id: string } | undefined;
  let oldResolutionReady!: () => void;
  const actualOldResolution = new Promise<void>(resolve => { oldResolutionReady = resolve; });
  let lostAccepted!: () => void;
  const lostAcceptance = new Promise<void>(resolve => { lostAccepted = resolve; });
  let originalUnit: string | undefined;
  const foundingIds: string[][] = [];
  let observedUnitRaw: string | undefined;
  let unchangedUnit = true;
  const observeUnit = (request: import("@playwright/test").Request) => {
    if (request.method() !== "POST" || new URL(request.url()).pathname !== "/_arkret/self/events"
      || request.postDataJSON()?.unit_kind !== "direct_conversation_founding") return;
    const raw = request.postData()!;
    if (observedUnitRaw === undefined) observedUnitRaw = raw;
    else unchangedUnit = unchangedUnit && observedUnitRaw === raw;
    foundingIds.push(ingressEvents(decodeEventIngressBody(request.postDataJSON())).map(event => event.event_id!));
  };
  const originalCommits: string[] = [];
  const lossRoutes: Array<{ page: Page; handler: (route: import("@playwright/test").Route) => Promise<void> }> = [];
  if (mode === "lost") {
    for (const page of [alice, bob]) {
      page.on("request", observeUnit);
      const handler = async (route: import("@playwright/test").Route) => {
        if (route.request().postDataJSON()?.unit_kind !== "direct_conversation_founding") { await route.continue(); return; }
        const raw = route.request().postData()!;
        const events = ingressEvents(decodeEventIngressBody(route.request().postDataJSON()));
        if (originalUnit !== undefined) {
          expect(raw, "lost acceptance must replay the exact signed four-Event unit").toBe(originalUnit);
          await route.continue();
          return;
        }
        originalUnit = raw;
        founder = page;
        const create = route.request().postDataJSON().events[0].event;
        const realm = sdkEventDerivedObjectId(create);
        const records = (await readCreatorRecords(page)).filter(record =>
          record.intent.effective_scope.kind === "realm" && record.intent.effective_scope.realm_id === realm);
        expect(records.length, "the original Direct creator intent must precede its first network write").toBe(1);
        expect(records[0].state).toBe("genesis_intent_persisted");
        expect(canonicalJson(records[0].intent.signed_scope_create_unit) === canonicalJson(route.request().postDataJSON()),
          "the durable intent retains the exact four-Event unit").toBe(true);
        expect(records[0].intent.creator_device_id === (page === alice ? aliceSession : bobSession).user.deviceId,
          "the original accepted Device owns the creator intent").toBe(true);
        expect(Boolean(records[0].epoch_zero), "founding admission precedes epoch-zero material").toBe(false);
        const response = await route.fetch();
        expect(response.ok(), await response.text()).toBe(true);
        const outcome = await response.json() as { unit_kind: string; status: string; commits: Array<Record<string, unknown>> };
        expect(outcome.unit_kind).toBe("direct_conversation_founding");
        expect(outcome.status).toBe("committed");
        expect(outcome.commits).toHaveLength(4);
        for (let i = 0; i < 4; i += 1) {
          expect(outcome.commits[i].event_ref).toBe(events[i].event_id);
          expect(outcome.commits[i].stream_position).toBe(i);
          expect(outcome.commits[i].previous_commit_ref ?? null).toBe(i ? outcome.commits[i - 1].commit_id : null);
          originalCommits.push(outcome.commits[i].commit_id as string);
        }
        // The Station really commits; only the browser's receipt is lost.
        await route.abort("failed");
        lostAccepted();
      };
      lossRoutes.push({ page, handler });
      await page.route("**/_arkret/self/events", handler);
    }
  }

  if (holdSecondResolve) {
    for (const page of [alice, bob]) {
      page.on("request", request => {
        if (request.method() !== "POST" || new URL(request.url()).pathname !== "/_arkret/self/events") return;
        if (request.postDataJSON()?.unit_kind === "direct_conversation_founding") {
          foundingRequestCount += 1;
          founder = page;
        }
      });
      page.on("response", async response => {
        if (response.request().method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return;
        if (response.request().postDataJSON()?.unit_kind !== "direct_conversation_founding") return;
        foundingResponseCount += 1;
        const outcome = await response.json().catch(() => null);
        const committed = response.ok() && outcome?.unit_kind === "direct_conversation_founding"
          && outcome.status === "committed" && Array.isArray(outcome.commits) && outcome.commits.length === 4;
        console.info("Direct founding submit observation", JSON.stringify({
          side: page === alice ? "alice" : "bob", http_status: response.status(),
          committed, commit_count: Array.isArray(outcome?.commits) ? outcome.commits.length : 0,
        }));
        if (!response.ok()) return;
        if (committed) {
          founder = page;
          foundingAcceptedAt ??= Date.now();
        }
        acceptFounding(response);
      });
      await page.route(resolvePath, async route => {
        const handling = (async () => {
          // A submit request does not establish acceptance. A failed first
          // attempt must retain the real resolver path needed for recovery.
          const holdAcceptedResolve = founder === page && foundingAcceptedAt !== undefined;
          const heldResponse = mode === "account" && holdAcceptedResolve ? await route.fetch() : undefined;
          const observedResponse = remoteBob && !holdAcceptedResolve ? await route.fetch() : undefined;
          if (observedResponse) {
            const resolved = await observedResponse.json();
            const state = ["creation_required", "creation_blocked", "awaiting_founder", "provisional", "found", "suspended", "temporarily_unavailable"].includes(resolved.state)
              ? resolved.state : "unexpected_state";
            const observation = JSON.stringify({ side: page === alice ? "alice" : "bob",
              http_status: observedResponse.status(), state,
              blockers: Array.isArray(resolved.blockers) ? resolved.blockers
                .filter((value: unknown) => typeof value === "string" && /^[a-z_]{1,80}$/.test(value)) : [],
              founding_input_present: resolved.next_founding_input !== undefined });
            if (resolveObservations.get(page) !== observation) {
              console.info("Cross-station Direct real resolver observation", observation);
              resolveObservations.set(page, observation);
            }
          }
          if (heldResponse) {
            expect(heldResponse.ok(), "the old Account's actual resolver must answer before identity replacement").toBe(true);
            const resolved = await heldResponse.json();
            expect(["found", "provisional", "suspended"]).toContain(resolved.state);
            expect(resolved.coordinates?.realm_id).toMatch(/^ak:realm:/);
            expect(resolved.coordinates?.main_strand_id).toMatch(/^ak:strand:/);
            heldResolvedCoordinates = resolved.coordinates;
            oldResolutionReady();
          }
          if (holdAcceptedResolve) await resolveDelay;
          try {
            if (heldResponse) await route.fulfill({ response: heldResponse });
            else if (observedResponse) await route.fulfill({ response: observedResponse });
            else await route.continue();
          } catch (error) {
            if (mode !== "account") throw error;
            // Complete OIDC navigation may cancel the original document's
            // fetch. Only actual browser cancellation is an accepted fence.
            const failure = route.request().failure();
            if (!failure || !/abort|cancel/i.test(failure.errorText)) throw error;
            browserCancelledOldResolves += 1;
          }
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
  phase("contact_request_start");
  const remoteLocator = remoteBob ? await resolvePrincipalLocator(request, bobSession.user.id, "server2", bobSession.grantJwt) : undefined;
  const { outcome } = await requestContactArkret(request, aliceSession.grantJwt, bobSession.user.id, {
    requestedScopes: ["direct_message", "presence"],
    ...(remoteLocator ? { recipientServiceId: bobSession.accountId.station_id,
      introductionEvidence: { kind: "locator_ref", principal_locator: remoteLocator } } : {}),
  });
  const accepted = await respondContactArkret(request, bobSession.grantJwt, {
    requestId: outcome.request_event_ref,
    requesterId: aliceSession.user.id,
    action: "accept",
    grantedScopes: ["direct_message", "presence"],
    ...(remoteBob ? { server: "server2" as const, requesterServiceId: aliceSession.accountId.station_id } : {}),
  });
  expect(accepted.state).toBe("accepted");
  phase("contact_accepted");
  phase("participant_reload_start");
  await Promise.all([alice.reload(), bob.reload()]);
  phase("participant_reload_finished");
  for (const [page, peer] of [[alice, bobSession.user.id], [bob, aliceSession.user.id]] as const) {
    phase(page === alice ? "alice_direct_open_start" : "bob_direct_open_start");
    await openContactConversation(page, accountActorId(peer, peer === bobSession.user.id && remoteBob ? "server2" : "default").account_id);
    phase(page === alice ? "alice_direct_open_finished" : "bob_direct_open_finished");
  }
  if (remoteBob) {
    await Promise.all([
      alicePage.completeRecoveryKeySetupIfPrompted(2_000).then(key => {
        if (key) recoveryKeys.set(alice, key);
        phase("alice_direct_recovery_finished");
      }),
      bobPage.completeRecoveryKeySetupIfPrompted(2_000).then(key => {
        if (key) recoveryKeys.set(bob, key);
        phase("bob_direct_recovery_finished");
      }),
    ]);
  }
  if (mode === "lost") {
    await lostAcceptance;
    expect(founder).toBeDefined();
    await founder!.reload();
  }
  if (holdSecondResolve) {
    const acceptedResponse = await waitForFoundingAcceptance();
    phase("founding_accepted");
    expect(acceptedResponse.ok(), await acceptedResponse.text()).toBeTruthy();
    const unit = ingressEvents(decodeEventIngressBody(acceptedResponse.request().postDataJSON()));
    const acceptedBody = await acceptedResponse.json() as { unit_kind: string; status: string; commits: Array<Record<string, unknown>> };
    expect(acceptedBody.unit_kind).toBe("direct_conversation_founding");
    expect(acceptedBody.status).toBe("committed");
    expect(unit).toHaveLength(4);
    expect(acceptedBody.commits).toHaveLength(4);
    for (let i = 0; i < 4; i += 1) {
      expect(acceptedBody.commits[i].event_ref).toBe(unit[i].event_id);
      expect(acceptedBody.commits[i].stream_position).toBe(i);
      expect(acceptedBody.commits[i].previous_commit_ref ?? null).toBe(i ? acceptedBody.commits[i - 1].commit_id : null);
    }
    expect(foundingAcceptedAt).toBeDefined();
    const acceptedAt = foundingAcceptedAt!;
    expect(founder).toBeDefined();
    await expect(founder!).toHaveURL(/\/direct\/ak:realm:.*\/ak:strand:/, { timeout: 15_000 });
    await expect(founder!.locator(".chat-panel")).toBeVisible();
    await expect(founder!.locator(".chat-panel")).toHaveClass(/\bdirect-mode\b/);
    const acceptedToVisibleMs = Date.now() - acceptedAt;
    test.info().annotations.push({ type: "founding-navigation-ms", description: String(acceptedToVisibleMs) });
    await founder!.locator(".chat-input").fill("held-second-resolve-send-probe");
    await expect(founder!.locator(".send-chat-button")).toBeDisabled();
    await expect(founder!.locator(".chat-panel")).not.toContainText("Strand not found");
    const firstPath = new URL(founder!.url()).pathname;
    if (mode === "logout" || mode === "account") {
      const previousIdentity = mode === "account" ? await founder!.evaluate(() => {
        const config = JSON.parse(window.localStorage.getItem("inkson.config.v1") ?? "{}");
        return { accountId: config.active_account?.authority, deviceId: config.active_account?.device_id };
      }) : undefined;
      if (previousIdentity) {
        expect(previousIdentity.accountId).toEqual(founder === alice ? aliceSession.accountId : bobSession.accountId);
        expect(previousIdentity.deviceId).toMatch(/^ak:device:/);
        await actualOldResolution;
      }
      await founder!.locator(".rail-account").click();
      await founder!.getByRole("button", { name: "Sign out of this account", exact: true }).click();
      await expect(founder!.locator(".auth-panel")).toBeVisible({ timeout: 60_000 });
      await expect(founder!.locator(".shell.app")).toHaveCount(0);
      if (mode === "account") {
        expect(heldResolvedCoordinates, "hold a real old resolution response, not an unissued request").toBeDefined();
        const acceptedPathParts = firstPath.split("/").map(decodeURIComponent);
        expect(heldResolvedCoordinates!.realm_id).toBe(acceptedPathParts[2]);
        expect(heldResolvedCoordinates!.main_strand_id).toBe(acceptedPathParts[3]);
        const replacement = founder === alice ? bobSession : aliceSession;
        const authorized = founder === alice ? bobPage : alicePage;
        expect(previousIdentity!.accountId).not.toEqual(replacement.accountId);
        await founder!.locator(".auth-station-field input").fill(colandBaseUrl());
        await founder!.locator(".auth-primary").click();
        await submitCoauthPasswordCredentials(founder!, replacement.account);
        const consent = founder!.locator(".login-container").getByRole("button", { name: "Allow", exact: true });
        if (await consent.waitFor({ state: "visible", timeout: 20_000 }).then(() => true).catch(() => false)) {
          await consent.click();
        }
        await expect(founder!.locator(".device-setup-required")).toBeVisible({ timeout: 120_000 });
        await expect(founder!.locator(".shell.app")).toHaveCount(0);
        await founder!.locator(".device-setup-pairing-start").click();
        const pairingCode = founder!.locator(".device-setup-pairing-code");
        await expect(pairingCode).toBeVisible({ timeout: 30_000 });
        const code = (await pairingCode.textContent())?.trim() ?? "";
        expect(code).not.toBe("");
        const pairingLink = await founder!.locator(".device-setup-pairing-link").inputValue();
        await approvePairingLinkOnAuthorizedDevice(authorized, pairingLink, code);
        await founder!.locator(".device-setup-pairing-status").click();
        await expect(founder!.locator(".device-setup-status")).toContainText("Device authorization is accepted", { timeout: 90_000 });
        await founder!.getByRole("button", { name: "Sign in again after approval", exact: true }).click();
        await expect(founder!.locator(".auth-panel")).toBeVisible({ timeout: 30_000 });
        await serverLoginViaCoauth(founder!, replacement.account);
        const currentIdentity = await founder!.evaluate(() => {
          const config = JSON.parse(window.localStorage.getItem("inkson.config.v1") ?? "{}");
          return { accountId: config.active_account?.authority, deviceId: config.active_account?.device_id };
        });
        expect(currentIdentity.accountId).toEqual(replacement.accountId);
        expect(currentIdentity.deviceId).toMatch(/^ak:device:/);
        expect(currentIdentity.deviceId).not.toBe(previousIdentity!.deviceId);
        const viewerUrl = `${colandBaseUrl()}/_arkret/self/account/viewer`;
        await expect.poll(async () => {
          const response = await request.get(viewerUrl, {
            headers: selfPathHeadersForDpopSession(replacement, "GET", viewerUrl),
          });
          expect(response.ok(), "the replacement Account must confirm its actual accepted Device").toBe(true);
          const body = await response.json();
          return body.devices?.find((device: { device_id?: string; status?: string }) => device.device_id === currentIdentity.deviceId)?.status;
        }, { timeout: 90_000 }).toBe("active");
        await expect(founder!.locator(".chat-panel")).toHaveCount(0);
        const replacementPath = new URL(founder!.url()).pathname;
        expect(replacementPath).not.toBe(firstPath);
        releaseResolve();
        await Promise.all([...pendingResolveRoutes]);
        await expect(founder!).toHaveURL(url => url.pathname === replacementPath);
        await expect(founder!.locator(".shell.app")).toBeVisible();
        await expect(founder!.locator(".chat-panel")).toHaveCount(0);
        await expect(founder!.locator(".chat-input")).toHaveCount(0);
        await test.info().attach("founding-held-resolve-real-account-device-reentry", {
          body: Buffer.from(JSON.stringify({ original_account: previousIdentity!.accountId,
            original_device: previousIdentity!.deviceId, accepted_account: currentIdentity.accountId,
            accepted_device: currentIdentity.deviceId, actual_hard_logout: true,
            actual_oidc_and_authorized_device_pairing: true, accepted_device_status: "active",
            actual_old_resolver_response_fetched_before_identity_replacement: true,
            actual_old_resolver_coordinates: heldResolvedCoordinates,
            old_resolve_released_after_new_account_device_acceptance: true,
            browser_cancelled_old_requests: browserCancelledOldResolves,
            old_chat_and_draft_not_installed: true, same_document_account_switch_claimed: false })),
          contentType: "application/json",
        });
        return;
      }
      releaseResolve();
      await Promise.all([...pendingResolveRoutes]);
      await expect(founder!.locator(".auth-panel")).toBeVisible();
      await expect(founder!.locator(".chat-panel")).toHaveCount(0);
      await expect(founder!.locator(".shell.app")).toHaveCount(0);
      await test.info().attach("founding-held-resolve-session-terminated", {
        body: Buffer.from(JSON.stringify({ accepted_path: firstPath, actual_hard_logout: true,
          old_resolve_released_after_shell_unmount: true, old_chat_not_installed: true })),
        contentType: "application/json",
      });
      return;
    }
    await founder!.locator(".rail-settings").click();
    await expect(founder!.locator(".settings-content-column")).toBeVisible();
    await founder!.goBack();
    await expect(founder!).toHaveURL(url => url.pathname === firstPath);
    await expect(founder!.locator(".chat-panel")).toBeVisible();
    await expect(founder!.locator(".send-chat-button")).toBeDisabled();
    await test.info().attach("founding-held-resolve-page-navigation", {
      body: Buffer.from(JSON.stringify({ accepted_to_visible_ms: acceptedToVisibleMs,
        accepted_path: firstPath, second_resolve_released: false, strict_send_gate: true, shell_survived_page_navigation: true })),
      contentType: "application/json",
    });
  }
  } finally {
    releaseResolve();
    await Promise.all([...pendingResolveRoutes]);
    if (holdSecondResolve) await Promise.all([alice.unroute(resolvePath), bob.unroute(resolvePath)]);
  }
  // The first click may belong to the non-founder. Once the selected founder
  // creates the pair, opening the same sidebar row must resolve its coordinates.
  for (const [page, peer] of [[alice, bobSession.user.id], [bob, aliceSession.user.id]] as const) {
    await expect(async () => {
      if (!new URL(page.url()).pathname.startsWith("/direct/")) {
        await openContactConversation(page, accountActorId(peer, peer === bobSession.user.id && remoteBob ? "server2" : "default").account_id);
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
      await expect.poll(() => uint64Value(interruptedWelcomeEpochs.get(directRealm) ?? "0"), { timeout: 120_000 }).toBeGreaterThan(0n);
      // The peer can observe Welcome before the founder has replayed the
      // covering MLS Commit. Reopen the founder while consume stays blocked;
      // its durable admission must restore the post-Add sending state.
      await bob.reload();
      await expect.poll(async () => uint64Value((await readScopeMlsGroupCurrentApi(
        request, bobSession.grantJwt, directRealm, { kind: "realm", realm_id: directRealm },
        remoteBob ? "server2" : "default",
      ))?.epoch ?? "0"), { timeout: 180_000 }).toBeGreaterThan(0n);
    }
    await alice.locator(".chat-input").fill("preparation probe");
    await expect(alice.locator(".send-chat-button")).toBeDisabled();
    // The responder is the founder. Spec §7.2 permits real exporter messages
    // before the peer's durable Welcome, including when that device is offline.
    if (mode === "offline") await alice.context().setOffline(true);
    const provisional = `direct-provisional-${Date.now()}`;
    await bob.locator(".chat-input").fill(provisional);
    await expect(bob.locator(".send-chat-button")).toBeEnabled({ timeout: 120_000 });
    const submitted = bob.waitForResponse(response => {
      const observed = response.request();
      if (observed.method() !== "POST" || new URL(response.url()).pathname !== "/_arkret/self/events") return false;
      return ingressEvents(decodeEventIngressBody(observed.postDataJSON()))
        .some(event => event.kind === "ak.message.create");
    }, { timeout: 90_000 });
    await submitOrdinaryComposerDraft(bob, provisional);
    const response = await submitted;
    expect(response.ok(), await response.text()).toBeTruthy();
    const sentEvent = ingressEvents(decodeEventIngressBody(response.request().postDataJSON()))
      .find(event => event.kind === "ak.message.create");
    const submission = await response.json() as Record<string, unknown>;
    expect(sentEvent, "the provisional submission carries its message").toBeTruthy();
    expect(submission.status, `provisional outcome reason: ${String(submission.reason_code ?? "none")}`).toBe("committed");
    assertAuthoritySubmitOutcome(submission, sentEvent!, "provisional Direct message");
    const founding = await scanRealmStreamApi(request, bobSession.grantJwt, directRealm, { limit: 1000 });
    expect(founding.truncated).toBe(false);
    const mainCreate = founding.events.find(event => event.kind === "ak.strand.create");
    expect(mainCreate).toBeDefined();
    await rejectDirectStructureEvent({ request, token: bobSession.grantJwt }, sentEvent!,
      `provisional-${mode}-structure`, "ak.strand.create", { object: (mainCreate!.payload as Record<string, unknown>).object },
      "direct_conversation_participant_authority_denied");
    const envelope = sentEvent?.payload?.encrypted_content as { encryption_context?: { epoch?: string } } | undefined;
    if (mode === "offline") {
      expect(uint64Value(envelope?.encryption_context?.epoch)).toBe(0n);
      preJoinMessage = provisional;
    } else {
      expect(uint64Value(envelope?.encryption_context?.epoch)).toBeGreaterThan(0n);
      messages.push(provisional);
    }
    if (mode === "offline") await alice.context().setOffline(false);
    await Promise.all([alice.unroute(preparationPath), bob.unroute(preparationPath)]);
    await Promise.all([alice.reload(), bob.reload()]);
  }
  for (const [user, session, server] of [[alicePage, aliceSession, "default"],
    [bobPage, bobSession, remoteBob ? "server2" : "default"]] as const) {
    const page = user.page;
    await page.bringToFront();
    const restore = page.getByRole("dialog", { name: "Restore encryption keys", exact: true });
    const recoveryKey = recoveryKeys.get(page) ?? session.recoveryKey;
    if (await restore.waitFor({ state: "visible", timeout: 2_000 }).then(() => true).catch(() => false)) {
      if (!recoveryKey) throw new Error("Direct readiness requires this holder's actual accepted Recovery Key");
      await user.unlockMlsAccountSecret(recoveryKey);
    }
    await user.fillWithPassivePromptRetry(page.locator(".chat-input"), "preparation probe");
    await expect(page.locator(".chat-input")).toHaveValue("preparation probe");
    await expect(page.locator(".chat-input-hint")).toHaveCount(0);
    await expect(page.locator(".send-chat-button")).toBeEnabled({ timeout: 180_000 }).catch(async error => {
      const realm = decodeURIComponent(new URL(page.url()).pathname.split("/")[2] ?? "");
      let currentReadFailed = false;
      const current = await readScopeMlsGroupCurrentApi(request, session.grantJwt, realm,
        { kind: "realm", realm_id: realm }, server).catch(() => { currentReadFailed = true; return undefined; });
      let creatorProbeFailed = false;
      const creatorRecords = await readCreatorRecords(page, true).catch(() => { creatorProbeFailed = true; return []; });
      await test.info().attach("safe-direct-preparation-readiness", {
        contentType: "application/json",
        body: JSON.stringify({ mode, server,
          draftMatches: await page.locator(".chat-input").inputValue().then(value => value === "preparation probe").catch(() => false),
          checking: await page.locator(".send-chat-button").getAttribute("aria-busy").catch(() => null),
          restoreVisible: await restore.isVisible().catch(() => false),
          backupVisible: await page.getByRole("dialog", { name: "Back up encrypted history", exact: true }).isVisible().catch(() => false),
          actualRecoveryKeyKnown: Boolean(recoveryKey), currentEpoch: current?.epoch ?? null, currentReadFailed,
          creatorProbeFailed, creatorRecords: creatorRecords.map(record => ({ state: record.state,
            scope: record.intent.effective_scope, acceptedGenesis: Boolean(record.accepted_genesis),
            invariant: record.diagnostic?.invariant, lastState: record.diagnostic?.last_state })) }),
      });
      throw error;
    });
    expect(new URL(page.url()).pathname).toBe(path);
  }
  if (mode === "offline") {
    // Verify the joined public state, then prove both local private snapshots
    // by accepting and decrypting real ordinary encrypted messages at that epoch.
    const directRealm = decodeURIComponent(path.split("/")[2]);
    await expect.poll(async () => {
      const currents = await Promise.all([
        readScopeMlsGroupCurrentApi(request, aliceSession.grantJwt, directRealm),
        readScopeMlsGroupCurrentApi(request, bobSession.grantJwt, directRealm, undefined,
          remoteBob ? "server2" : "default"),
      ]);
      const epochs = currents.map(current => uint64Value(current?.epoch ?? "0"));
      return epochs[0] > 0n && epochs[0] === epochs[1];
    }, { timeout: 180_000 }).toBe(true);
    const privateEpochs: bigint[] = [];
    for (const [sender, recipient, name] of [[alice, bob, "alice"], [bob, alice, "bob"]] as const) {
      const probe = `direct-joined-readiness-${name}-${Date.now()}`;
      await sender.locator(".chat-input").fill(probe);
      const [response] = await Promise.all([
        sender.waitForResponse(response => response.request().method() === "POST"
          && new URL(response.url()).pathname === "/_arkret/self/events"
          && ingressEvents(decodeEventIngressBody(response.request().postDataJSON()))
            .some(event => event.kind === "ak.message.create"), { timeout: 90_000 }),
        submitOrdinaryComposerDraft(sender, probe),
      ]);
      expect(response.ok(), "the ordinary readiness probe must reach authority admission").toBe(true);
      const original = ingressEvents(decodeEventIngressBody(response.request().postDataJSON()))
        .find(event => event.kind === "ak.message.create")!;
      const outcome = await response.json() as Record<string, unknown>;
      expect(outcome.status).toBe("committed");
      assertAuthoritySubmitOutcome(outcome, original, "joined Direct private-state readiness");
      expect(original.scope_ref).toEqual({ kind: "realm", realm_id: directRealm });
      const envelope = original.payload?.encrypted_content as { encryption_context?: { epoch?: string } } | undefined;
      const epoch = uint64Value(envelope?.encryption_context?.epoch);
      expect(epoch).toBeGreaterThan(0n);
      privateEpochs.push(epoch);
      await expect(recipient.locator(".chat-message").filter({ hasText: probe })).toBeVisible({ timeout: 90_000 });
      messages.push(probe);
    }
    expect(privateEpochs[0]).toBe(privateEpochs[1]);
    await alice.context().setOffline(true);
    const offlineMessage = `direct-offline-after-join-${Date.now()}`;
    await bob.locator(".chat-input").fill(offlineMessage);
    const offlineSubmission = bob.waitForResponse(response =>
      response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/self/events"
      && ingressEvents(decodeEventIngressBody(response.request().postDataJSON()))
        .some(event => event.kind === "ak.message.create"), { timeout: 90_000 });
    await submitOrdinaryComposerDraft(bob, offlineMessage);
    const offlineResponse = await offlineSubmission;
    expect(offlineResponse.ok(), await offlineResponse.text()).toBeTruthy();
    const offlineEvent = ingressEvents(decodeEventIngressBody(offlineResponse.request().postDataJSON()))
      .find(event => event.kind === "ak.message.create");
    const offlineOutcome = await offlineResponse.json() as Record<string, unknown>;
    expect(offlineEvent, "the offline submission carries its message").toBeTruthy();
    expect(offlineOutcome.status, `post-join outcome reason: ${String(offlineOutcome.reason_code ?? "none")}`).toBe("committed");
    assertAuthoritySubmitOutcome(offlineOutcome, offlineEvent!, "post-join offline Direct message");
    const offlineEnvelope = offlineEvent?.payload?.encrypted_content as { encryption_context?: { epoch?: string } } | undefined;
    expect(uint64Value(offlineEnvelope?.encryption_context?.epoch)).toBeGreaterThan(0n);
    await expect(bob.locator(".chat-message").filter({ hasText: offlineMessage })).toBeVisible();
    await alice.context().setOffline(false);
    await alice.reload();
    await expect(alice.locator(".chat-message").filter({ hasText: offlineMessage })).toBeVisible({ timeout: 90_000 });
    messages.push(offlineMessage);
  }

  const exchange = [`direct-alice-${Date.now()}`, `direct-bob-${Date.now()}`];
  messages.push(...exchange);
  for (const [sender, recipient, message] of [[alice, bob, exchange[0]], [bob, alice, exchange[1]]] as const) {
    await sender.locator(".chat-input").fill(message);
    await submitOrdinaryComposerDraft(sender, message);
    await expect(recipient.locator(".chat-message").filter({ hasText: message })).toBeVisible({ timeout: 90_000 });
  }
  await Promise.all([alice.reload(), bob.reload()]);
  for (const page of [alice, bob]) {
    for (const message of messages) {
      await expect(page.locator(".chat-message").filter({ hasText: message })).toBeVisible({ timeout: 90_000 });
    }
  }
  if (preJoinMessage) {
    await expect(bob.locator(".chat-message").filter({ hasText: preJoinMessage })).toBeVisible({ timeout: 90_000 });
    await expect(alice.locator(".chat-message").filter({ hasText: preJoinMessage })).toHaveCount(0);
  }
  const afterReload = `direct-after-reload-${Date.now()}`;
  await bob.locator(".chat-input").fill(afterReload);
  await submitOrdinaryComposerDraft(bob, afterReload);
  await expect(alice.locator(".chat-message").filter({ hasText: afterReload })).toBeVisible({ timeout: 90_000 });
  if (mode === "withdrawal" || mode === "leave") {
    await directStructureLifecycleGate(alice, bob, { request, token: aliceSession.grantJwt,
      peer: { token: bobSession.grantJwt, server: "default" } }, mode, async author => {
      if (mode === "withdrawal") {
        const withdrawn = await tombstoneContactArkret(request, aliceSession.grantJwt, bobSession.user.id);
        expect(withdrawn.state).toBe("tombstoned");
      } else {
        const event = signedEventEnvelope({ actorId: author.actor_id as ReturnType<typeof accountActorId>,
          realmId: author.realm_id!, kind: "ak.member.state",
          authorizationRef: author.authorization_ref as string, semanticRefs: author.semantic_refs as Array<Record<string, unknown>>,
          proofVerificationMethod: (author.producer_proof as { verification_method: string }).verification_method,
          payload: { member_id: author.actor_id, membership: "leave", reason: "self_leave" },
        });
        await submitSignedEventApi(request, bobSession.grantJwt, event, { context: "Direct participant self leave", controlObserverToken: aliceSession.grantJwt });
      }
    });
    return;
  }
  if (mode === "normal") {
    const paired = await openAndPairSecondController(browser, request, jointUsers);
    try {
      await alice.goto(path, { waitUntil: "domcontentloaded" });
      await paired.page.page.goto(path, { waitUntil: "domcontentloaded" });
      const actualRecoveryKey = recoveryKeys.get(alice) ?? jointUsers.aliceSession.recoveryKey;
      expect(Boolean(actualRecoveryKey), "the paired holder retains its actual accepted recovery material").toBe(true);
      await paired.page.unlockMlsAccountSecret(actualRecoveryKey!);
      await expect(paired.page.page.locator(".send-chat-button")).toBeEnabled({ timeout: 180_000 });
      const outsideRealm = await createRealmApi(request, aliceSession.grantJwt, {
        title: `DM boundary outside ${Date.now()}`, mls_activated: false,
      });
      const outsideStrand = await resolveDefaultStrandId(request, aliceSession.grantJwt, outsideRealm);
      const control = paired.page.page;
      const circleStrand = await createDirectBoundaryCircleStrand(paired.page, request,
        aliceSession.grantJwt, outsideRealm, `DM boundary Circle ${Date.now()}`);
      const third = await createDpopUserSession(request, "direct-outsider", {});
      expect(third, "negative author must be a real registered principal/device").toBeDefined();
      await control.goto(path, { waitUntil: "domcontentloaded" });
      await flatTopicChats(alice, bob, [...messages, afterReload], [paired.page.page], { request, token: aliceSession.grantJwt,
        peer: { token: bobSession.grantJwt, server: remoteBob ? "server2" : "default" }, boundaryTargets: {
          realmStrand: outsideStrand, circleStrand: circleStrand!, thirdActor: accountActorId(third!.user.id), thirdToken: third!.grantJwt,
        } });
    } finally {
      await paired.page.close();
    }
  }
  for (const [page, peer] of [[alice, bobSession.user.id], [bob, aliceSession.user.id]] as const) {
    const identity = canonicalJson(accountActorId(peer, peer === bobSession.user.id && remoteBob ? "server2" : "default"));
    const presence = page.locator(".presence-row").filter({ has: page.getByLabel(identity, { exact: true }) });
    await expect.soft(presence).toHaveClass(/\bpresence-row-online\b/, { timeout: 90_000 });
  }
  if (mode === "lost") {
    expect(unchangedUnit, "all founding submissions after restart preserve the original signed bytes").toBe(true);
    expect(new Set(foundingIds.map(ids => canonicalJson(ids))).size).toBe(1);
    const realm = decodeURIComponent(path.split("/")[2]);
    const records = (await readCreatorRecords(founder!)).filter(record =>
      record.intent.effective_scope.kind === "realm" && record.intent.effective_scope.realm_id === realm);
    expect(records.length, "cold recovery retains one original Direct creator transaction").toBe(1);
    expect(records[0].state).toBe("ready");
    expect(canonicalJson(records[0].intent.signed_scope_create_unit) === canonicalJson(JSON.parse(originalUnit!)),
      "the ready transaction retains the original founding bytes").toBe(true);
    expect(records[0].ready_receipt.accepted_genesis_event_id).toBe(records[0].accepted_genesis.accepted.event.event_id);
    await test.info().attach("founding-acceptance-lost-cold-resume", {
      body: Buffer.from(JSON.stringify({ submitted_event_ids: foundingIds, original_commit_ids: originalCommits,
        first_response_lost_after_actual_commit: true, process_restarted: true, unique_founding_unit: true })),
      contentType: "application/json",
    });
  }
  for (const { page, handler } of lossRoutes) {
    await page.unroute("**/_arkret/self/events", handler);
    page.off("request", observeUnit);
  }
};
}

test("same-server Direct Conversation exchanges encrypted messages and retains them after reload", directConversationCase("normal"));
test("same-server Direct Conversation resumes interrupted preparation and exchanges messages after reload", directConversationCase("interrupted"));
test("same-server Direct Conversation founder sends while the peer device is offline and the peer decrypts after reconnect", directConversationCase("offline"));


test("cross-station Direct Conversation preserves encrypted Chat and Topic state across participants and reload", async ({ jointUsers, request, browser }) => {
  test.setTimeout(1_200_000);
  const session = await createDpopUserSession(request, "direct-cross-bob", { server: "server2" });
  expect(session, "the official two-Station runner must supply a real second Station").toBeDefined();
  const remoteFlow = await openDpopUserPageFromSession(browser, session, { server: "server2" });
  expect(remoteFlow, "the remote participant must complete canonical browser session initialization").toBeDefined();
  const remote = remoteFlow!.page;
  try {
    await directConversationCase("normal", true)({ browser, request, jointUsers: {
      ...jointUsers, bob: session!.user, bobSession: session!, bobToken: session!.grantJwt, bobPage: remote,
    } });
  } finally {
    await remote.close();
  }
});

test("Direct Conversation resumes a genuinely lost founding acceptance after cold reload without creating another pair", directConversationCase("lost"));

test("Direct Conversation rejects a delayed founding resolve after actual hard logout and shell termination", directConversationCase("logout"));

test("Direct Conversation rejects its old delayed resolve after real OIDC Account and paired Device replacement", directConversationCase("account"));

test("Direct Conversation rejects Chat Topic and own watch writes after known Contact withdrawal", directConversationCase("withdrawal"));
test("Direct Conversation rejects Chat Topic and own watch writes after participant self leave", directConversationCase("leave"));
