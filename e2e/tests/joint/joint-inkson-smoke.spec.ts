// T-P0-05 joint harness smoke.
// Contract: true inkson UI + true coland process create a realm and render messages.

import type { APIRequestContext } from "../../helpers/arkret-test";
import { test, expect } from "../../helpers/joint-fixture";
import {
  accountActorId,
  canonicalJson,
  grantCapabilityEventApi,
  retypeEventDerivedId,
  signedEventEnvelope,
} from "../../helpers/coland-api";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  type DpopUserSession,
  openDpopUserPage,
  openDpopUserPageFromSession,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";
import { coauthBaseUrl } from "../../helpers/env";
import {
  deliverInviteWithConsentGrant,
  grantInviteConsentArkret,
} from "../../helpers/contact-api";

test.describe.configure({ mode: "serial" });

test.describe("joint-inkson smoke @fully-implemented", () => {
  // Inkson consumes the accepted default-Strand projection. The Realm token
  // is never retyped into a Strand token; this smoke test resolves the exact
  // projected coordinate before submitting the message.
  test("creates a public realm and renders a coland message in inkson", async ({
    jointRealm,
  }) => {
    // Regression: the Coauth service-account hint belongs to the Account
    // Authority namespace. Public principal identity must instead use the
    // Coland-signed handle consistently across every shell/chat surface.
    const stamp = Date.now();
    const aliceMessage = `joint smoke from Alice ${stamp}`;
    const principalHandle = canonicalHandle(
      jointRealm.alice.handle,
      jointRealm.alicePage.serverUrl,
    );
    const accountAuthority = coauthBaseUrl();
    const accountAuthorityHandle = accountAuthority
      ? canonicalHandle(jointRealm.alice.handle, accountAuthority)
      : undefined;

    await jointRealm.alicePage.sendTimelineMessage(
      jointRealm.realmId,
      aliceMessage,
    );
    const message = jointRealm.alicePage.timelineEvent(aliceMessage);
    await expect(message).toBeVisible({
      timeout: 30_000,
    });
    await expect(message.locator(".msg-head .name")).toHaveText(
      principalHandle,
    );

    const selfParticipant = jointRealm.alicePage.page
      .getByTestId("discussion-user-row")
      .filter({
        has: jointRealm.alicePage.page.getByTestId("participant-self-badge"),
      });
    await expect(selfParticipant).toContainText(principalHandle);

    await jointRealm.alicePage.page.getByTestId("account-menu-button").click();
    await expect(
      jointRealm.alicePage.page.getByTestId("account-menu-handles"),
    ).toHaveText(principalHandle);
    if (accountAuthorityHandle && accountAuthorityHandle !== principalHandle) {
      for (const identitySurface of [
        message,
        selfParticipant,
        jointRealm.alicePage.page.getByTestId("account-menu-handles"),
      ]) {
        await expect(identitySurface).not.toContainText(accountAuthorityHandle);
      }
    }
  });

  test("does not promote mention audit metadata to Agent identity", async ({
    browser,
    jointRealm,
    request,
  }) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const slug = `summary${stamp.toString(36)}`;
    const forgedDisplayName = `Forged Summary Agent ${stamp}`;
    const controllerHandle = canonicalHandle(
      jointRealm.alice.handle,
      jointRealm.alicePage.serverUrl,
    );
    const participantSession = await createDpopUserSession(
      request,
      `joint-participant-${stamp}`,
    );
    expect(participantSession, "joint participant DPoP session").toBeTruthy();
    const participantId = participantSession!.user.id;
    const participantFlow = await openDpopUserPageFromSession(
      browser,
      participantSession,
      { prepareMlsDevice: false },
    );
    expect(
      participantFlow,
      "joint participant browser enrollment flow",
    ).toBeTruthy();
    await participantFlow!.page.gotoHome();

    try {
      const strandId = await resolveDefaultStrandId(
        request,
        jointRealm.aliceSession,
        jointRealm.alicePage.serverUrl,
        jointRealm.realmId,
      );
      await grantCapabilityEventApi(request, jointRealm.aliceToken, {
        ownerId: jointRealm.alice.id,
        realmId: jointRealm.realmId,
        subjectId: jointRealm.alice.id,
        actions: ["ak.message.create"],
      });
      const consent = await grantInviteConsentArkret(
        request,
        participantSession!.grantJwt,
        participantSession!.user,
        jointRealm.alice.id,
      );
      const delivery = await deliverInviteWithConsentGrant(request, {
        inviterId: jointRealm.alice.id,
        inviterToken: jointRealm.aliceToken,
        realmId: jointRealm.realmId,
        inviteeId: participantId,
        consentGrantRef: consent.eventRef,
        originServer: "server1",
        recipientServer: "server1",
      });
      expect(delivery.outcome.disclosed_outcome).toBe("delivered");
      await participantFlow!.page.acceptInvite(jointRealm.realmId);
      // Membership does not confer the action capability needed by the reply.
      await grantCapabilityEventApi(request, jointRealm.aliceToken, {
        ownerId: jointRealm.alice.id,
        realmId: jointRealm.realmId,
        subjectId: participantId,
        actions: ["ak.message.create"],
      });
      const controllerMessageId = await submitSignedEvent(
        request,
        jointRealm.aliceSession,
        jointRealm.alice.id,
        jointRealm.alicePage.serverUrl,
        jointRealm.realmId,
        "ak.message.create",
        {
          strand_id: strandId,
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: `mention ${forgedDisplayName}`,
            mentions: [
              {
                kind: "mention",
                subject_account_id: accountActorId(participantId).account_id,
                controller_subject_account_id: accountActorId(jointRealm.alice.id)
                  .account_id,
                controller_handle_at_time: controllerHandle,
                agent_slug_at_time: slug,
                display_name_at_time: forgedDisplayName,
                mention_text_original: `@${controllerHandle}/${slug}`,
              },
            ],
          },
        },
      );
      const replyBody = `${participantSession!.user.displayName} visible reply`;
      await submitSignedEvent(
        request,
        participantSession!,
        participantId,
        jointRealm.alicePage.serverUrl,
        jointRealm.realmId,
        "ak.message.create",
        {
          strand_id: strandId,
          track_name: "discussion",
          reply_to_id: retypeEventDerivedId(controllerMessageId, "message"),
          content: {
            kind: "ak.content.text",
            body: replyBody,
          },
        },
      );

      await jointRealm.alicePage.page.goto(`/chat/${jointRealm.realmId}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(
        jointRealm.alicePage.page.getByTestId("chat-panel"),
      ).toBeVisible({
        timeout: 120_000,
      });
      await expect(jointRealm.alicePage.timelineEvent(replyBody)).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        jointRealm.alicePage.page.locator(
          `[data-testid="participant-agent-group"][data-controller-principal-id="${jointRealm.alice.id}"]`,
        ),
      ).toHaveCount(0);

      const participantRow = jointRealm.alicePage.page
        .getByTestId("discussion-user-row")
        .filter({
          // A dev-login display name is not an authoritative profile label.
          // Select the human row by the canonical full Account ActorId kept
          // in the identity label's title; visible copy may be a handle.
          has: jointRealm.alicePage.page.locator(
            `xpath=.//*[@data-testid='participant-identity' and @title='${canonicalJson(accountActorId(participantId))}']`,
          ),
        });
      await expect(participantRow).toBeVisible({ timeout: 60_000 });
      await expect(participantRow).not.toContainText(forgedDisplayName);
      await expect(
        participantRow.getByTestId("member-badge-agent"),
      ).toHaveCount(0);
      await expect(
        participantRow.getByTestId("participant-agent-selector"),
      ).toHaveCount(0);

      const input = jointRealm.alicePage.page.getByTestId("chat-input");
      await input.fill(`@me/${slug}`);
      await expect(
        jointRealm.alicePage.page
          .getByTestId("mention-suggestion")
          .filter({ hasText: `@me/${slug}` }),
      ).toHaveCount(0);
    } finally {
      await participantFlow!.page.close();
    }
  });

  // inviteFromAdmin drives the current modal flow: gotoRealmAdminSection
  // navigates to /realms/:id/members (realm-members-panel), opens the invite
  // modal via open-invite-modal-button, fills invite-target-input, and submits
  // send-invite-button, asserting the "invited ..." realm-members-status. The
  // inkson route + testids (routes.rs RealmMembersPage, realm_admin/
  // members_panel.rs) match the helper, so the cursor-poisoning regression this
  // test guards runs end-to-end.
  test("admin invite preserves since-join history and a writable current baseline without poisoning the account cursor", async ({
    browser,
    request,
  }) => {
    test.setTimeout(360_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow] = await Promise.all([
      openDpopUserPage(browser, request, "joint-invite-alice"),
      openDpopUserPage(browser, request, "joint-invite-bob"),
    ]);
    if (!aliceFlow || !bobFlow) {
      assertJointStackNotRequired("joint-inkson smoke invite browser login");
      test.skip(
        true,
        "coauth DPoP session-grant login is required for joint UI",
      );
      return;
    }
    const alice = aliceFlow.user;
    const bob = bobFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const subscribeFailures: string[] = [];
    // Count every account-subscribe response (success or failure) so the
    // assertion below can wait for at least one FRESH re-poll after the join
    // instead of sleeping a fixed margin — that re-poll is exactly the request
    // that would carry the poisoned cursor if the regression reappeared.
    let subscribeResponses = 0;

    for (const observedPage of [alicePage.page, bobPage.page]) {
      observedPage.on("response", async (response) => {
        if (!response.url().includes("/_arkret/self/account/subscribe")) {
          return;
        }
        subscribeResponses += 1;
        if (response.status() < 400) {
          return;
        }
        const body = await response.text().catch(() => "");
        subscribeFailures.push(
          `${response.status()} ${response.url()} ${body}`,
        );
      });
    }

    try {
      const realmId = await alicePage.createRealm({
        title: `joint invite ${stamp}`,
        summary: "regression for write sync_token cursor poisoning",
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        mlsActivated: false,
      });
      await grantInviteConsentArkret(
        request,
        bobFlow.session.grantJwt,
        bob,
        alice.id,
      );
      const beforeJoin = `before Bob joined ${stamp}`;
      await alicePage.sendTimelineMessage(realmId, beforeJoin);
      await alicePage.inviteFromAdmin(realmId, bob.id);

      await expect
        .poll(
          async () => {
            const invites = await listInvitesForDpop(
              request,
              bobFlow.session,
              bobPage.serverUrl,
              bob.id,
            );
            return invites.some(
              (invite) =>
                invite.realm_id === realmId && canonicalJson(invite.invitee_account_id) === canonicalJson(accountActorId(bob.id).account_id),
            );
          },
          { timeout: 30_000 },
        )
        .toBe(true);

      await bobPage.page.goto("/notifications", {
        waitUntil: "domcontentloaded",
      });
      const inviteCard = bobPage.page.getByTestId("notification-item").filter({
        has: bobPage.page.locator(`[title="${realmId}"]`),
      });
      await expect(inviteCard).toHaveCount(1, { timeout: 30_000 });
      await expect(inviteCard).toContainText("Realm invite");
      await expect(inviteCard).toContainText("You were invited to join");
      // The recovery-key setup dialog can pop asynchronously once the MLS
      // device state loads and its backdrop swallows every click; complete or
      // dismiss it before accepting the invite.
      await bobPage.clickWithPassivePromptRetry(
        inviteCard.getByTestId("notification-action"),
      );

      await expect(
        bobPage.page.getByTestId("notifications-status"),
      ).toContainText(/Joined Realm/, { timeout: 30_000 });
      await expect(inviteCard).toHaveCount(0, { timeout: 30_000 });
      await expect(bobPage.page.getByTestId("realm-tree-list")).toContainText(
        `joint invite ${stamp}`,
        { timeout: 30_000 },
      );

      // Membership is not an authorization source (capabilities.md §3.2).
      // Give Bob exactly the post-join action exercised below.
      await alicePage.grantRealmCapability(
        realmId,
        bobFlow.session.accountId,
        "ak.message.create",
      );

      // `since_join` is an authorization boundary, not a presentation hint:
      // the joiner receives the current baseline needed to author successors,
      // but no pre-join timeline contents.
      await bobPage.gotoTimelineRealm(realmId);
      await expect(bobPage.timelineEvent(beforeJoin)).toHaveCount(0);

      const bobAfterJoin = `Bob writes after joining ${stamp}`;
      await bobPage.sendTimelineMessage(realmId, bobAfterJoin);
      await expect(bobPage.timelineEvent(beforeJoin)).toHaveCount(0);
      await alicePage.gotoTimelineRealm(realmId);
      await alicePage.expectTimelineEventVisible(bobAfterJoin, 30_000);

      const aliceAfterJoin = `Alice replies after Bob joined ${stamp}`;
      await alicePage.sendTimelineMessage(realmId, aliceAfterJoin);
      await bobPage.expectTimelineEventVisible(aliceAfterJoin, 30_000);
      await expect(bobPage.timelineEvent(beforeJoin)).toHaveCount(0);

      // Force alice's page to re-establish its account-subscribe stream after
      // the invite/join settled, then wait (bounded) for that fresh re-poll to
      // land. If the write path poisoned the cursor, this is the request that
      // would return cursor_integrity_invalid.
      const baselineResponses = subscribeResponses;
      await alicePage.page.reload({ waitUntil: "domcontentloaded" });
      await expect
        .poll(() => subscribeResponses, {
          timeout: 30_000,
          intervals: [250, 500, 1_000],
        })
        .toBeGreaterThan(baselineResponses);

      expect(
        subscribeFailures.filter(
          (failure) =>
            failure.includes("cursor_integrity_invalid") ||
            failure.includes("cursor principal does not match request actor"),
        ),
        subscribeFailures.join("\n"),
      ).toEqual([]);
    } finally {
      await Promise.allSettled([bobPage.close(), alicePage.close()]);
    }
  });
});

async function submitSignedEvent(
  request: APIRequestContext,
  session: DpopUserSession,
  actorId: string,
  serverUrl: string,
  realmId: string,
  kind: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const url = `${serverUrl}/_arkret/self/events`;
  const envelope = signedEventEnvelope({
    actorId,
    realmId,
    kind,
    payload,
  });
  const response = await request.post(url, {
    headers: {
      ...selfPathHeadersForDpopSession(session, "POST", url),
      "content-type": "application/json",
    },
    data: canonicalJson({ event: envelope }),
  });
  const text = await response.text();
  expect(
    [200, 201],
    `submit ${kind} returned ${response.status()}: ${text}`,
  ).toContain(response.status());
  const eventId = envelope.event_id;
  if (typeof eventId !== "string") {
    throw new Error(`derived ${kind} Event is missing event_id`);
  }
  return eventId;
}

function canonicalHandle(handle: string, serverUrl: string): string {
  const localpart = handle.trim().replace(/^@/, "").split(":", 1)[0];
  return `${localpart}:${new URL(serverUrl).hostname.toLowerCase()}`;
}

async function listInvitesForDpop(
  request: APIRequestContext,
  session: DpopUserSession,
  serverUrl: string,
  subjectId: string,
): Promise<Array<{ id: string; realm_id: string; invitee_account_id?: import("../../helpers/generated/spec-wire-objects").AccountId }>> {
  const url = new URL("/_arkret/self/authz/invites", serverUrl);
  url.searchParams.set("subject", subjectId);
  url.searchParams.set("subject_station_id", session.accountId.station_id);
  const href = url.toString();
  const response = await request.get(href, {
    headers: {
      ...selfPathHeadersForDpopSession(session, "GET", href),
      "Arkret-Operation": "ak.self.authz.invites.read.list.v1",
    },
  });
  const text = await response.text();
  expect(
    response.ok(),
    `list invites returned ${response.status()}: ${text}`,
  ).toBeTruthy();
  const body = JSON.parse(text) as {
    invites?: Array<{ id: string; realm_id: string; invitee_account_id?: import("../../helpers/generated/spec-wire-objects").AccountId }>;
  };
  return body.invites ?? [];
}

// COT-06-004: discover the default Strand via projection rather than deriving it
// from the Realm identity token. This joint harness submits against an explicit serverUrl
// (true coland process), so it cannot reuse the shared colandBaseUrl-bound
// helper; the discovery logic mirrors it: authoritative Realm `default_strand_id`
// first, Strand projection `is_default` marker as fallback.
async function resolveDefaultStrandId(
  request: APIRequestContext,
  session: DpopUserSession,
  serverUrl: string,
  realmId: string,
): Promise<string> {
  const realmUrl = `${serverUrl}/_arkret/self/realms/${encodeURIComponent(realmId)}`;
  const realmResp = await request.get(realmUrl, {
    headers: selfPathHeadersForDpopSession(session, "GET", realmUrl),
  });
  if (realmResp.ok()) {
    const realm = (await realmResp.json()) as { default_strand_id?: unknown };
    if (
      typeof realm.default_strand_id === "string" &&
      realm.default_strand_id
    ) {
      return realm.default_strand_id;
    }
  }
  const flowsUrl = `${serverUrl}/_arkret/self/realms/${encodeURIComponent(realmId)}/strands`;
  const flowsResp = await request.get(flowsUrl, {
    headers: selfPathHeadersForDpopSession(session, "GET", flowsUrl),
  });
  expect(
    flowsResp.ok(),
    `resolveDefaultStrandId: strand projection for ${realmId} returned ${flowsResp.status()}`,
  ).toBeTruthy();
  const body = (await flowsResp.json()) as {
    strands?: Array<{ strand_id?: string; is_default?: boolean }>;
  };
  const strands = body.strands ?? [];
  const def = strands.find((strand) => strand.is_default === true);
  if (def?.strand_id) {
    return def.strand_id;
  }
  throw new Error(
    `resolveDefaultStrandId: accepted projections for ${realmId} expose no default Strand`,
  );
}
