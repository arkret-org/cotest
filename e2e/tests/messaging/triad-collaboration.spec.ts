// Single-server triad collaboration
// Contract: e2e/scenarios/messaging/triad-collaboration.md
// Spec refs:
//   - models/realm-and-space.md §2-§3
//   - models/strand-and-message.md §8, §8.4, §8.5

import { expect, test } from "../../helpers/arkret-test";
import {
  createRealmViaApi,
  createSharedRealmViaApi,
  listRealmEventsViaApi,
  sendPlaintextMessageViaApi,
} from "../../helpers/api";
import { colandBaseUrl, colandServiceId } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  accountActorId,
  authHeaders,
  canonicalJson,
  joinRealmMemberByInviteApi,
  listInvitesApi,
  resolveDefaultStrandId,
  scanRealmStreamApi,
  signedEventEnvelope,
  submitSignedEventApi,
} from "../../helpers/coland-api";
import { grantInviteConsentArkret } from "../../helpers/contact-api";
import {
  assertJointStackNotRequired,
  ensureRegistered,
  issueInviteLocatorToken,
  issueUserSession,
  openDpopUserPage,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

function eventKind(event: Record<string, unknown>): string {
  return String(event.kind ?? event.event_kind ?? "");
}

function eventPayload(event: Record<string, unknown> | undefined): Record<string, unknown> {
  const payload = event?.payload;
  return payload && typeof payload === "object"
    ? (payload as Record<string, unknown>)
    : {};
}

function visibleMemberIds(realm: Record<string, unknown>): string[] {
  const members = realm.member_ids;
  if (!Array.isArray(members)) {
    return [];
  }
  return members.flatMap((member) => {
    if (typeof member === "string") {
      return [member];
    }
    if (!member || typeof member !== "object") {
      return [];
    }
    const record = member as Record<string, unknown>;
    const id = [record.actor_id, record.id].find(
      (candidate): candidate is string => typeof candidate === "string",
    );
    return id ? [id] : [];
  });
}

test.describe("single-server triad collaboration", () => {
  test("API create → revise → redact updates projection visibility", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("triad-api-alice");
    const bob = uniqueUser("triad-api-bob");
    await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
    const [aliceToken, bobToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
    ]);
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
      title: `triad audit ${stamp}`,
      historyAccess: "all_history_for_current_members",
    });
    const createBody = `triad create ${stamp}`;
    const created = await sendPlaintextMessageViaApi(
      request,
      aliceToken,
      realmId,
      createBody,
      { actorId: alice.id },
    );

    const revisedBody = `triad revised ${stamp}`;
    const messageRef = created.event_id.replace(/^ak:event:/, "ak:message:");
    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.message.revise",
        payload: {
          message_id: messageRef,
          content: { kind: "ak.content.text", body: revisedBody },
        },
      }),
      { context: "revise message" },
    );

    const beforeRedact = await listRealmEventsViaApi(request, bobToken, realmId);
    expect(beforeRedact.map(eventKind)).toEqual(
      expect.arrayContaining(["ak.message.create", "ak.message.revise"]),
    );
    expect(eventPayload(beforeRedact.find((event) => eventKind(event) === "ak.message.revise")))
      .toMatchObject({ message_id: messageRef });

    await submitSignedEventApi(
      request,
      aliceToken,
      signedEventEnvelope({
        actorId: alice.id,
        realmId: realmId,
        kind: "ak.message.redact",
        payload: {
          message_id: messageRef,
          reason: "author_redaction",
        },
      }),
      { context: "redact message" },
    );

    // The Commit chain keeps every slot and the redaction fact stays disclosed
    // (strand-and-message.md section 9.5.1). The signed create and revise
    // bytes cannot be rewritten into a stub, so their slots use the closed
    // withheld `CommittedEventView` branch (service-http-binding.md); no
    // third redacted form exists and the original bodies never leak.
    const scan = await scanRealmStreamApi(request, bobToken, realmId);
    const revise = beforeRedact.find((event) => eventKind(event) === "ak.message.revise");
    const reviseEventId = String(revise?.event_id ?? "");
    expect(reviseEventId).toMatch(/^ak:event:/);
    const slot = (eventId: string) => {
      const index = scan.commits.findIndex((commit) => commit.event_ref === eventId);
      expect(index, `Commit slot for ${eventId}`).toBeGreaterThanOrEqual(0);
      return scan.events[index];
    };
    expect(slot(created.event_id), "redacted create is withheld").toBeUndefined();
    expect(slot(reviseEventId), "redacted revise is withheld").toBeUndefined();
    const events = scan.events.filter(
      (event): event is Record<string, unknown> => event !== undefined,
    );
    expect(events.map(eventKind)).toContain("ak.message.redact");
    expect(JSON.stringify(scan)).not.toContain(createBody);
    expect(JSON.stringify(scan)).not.toContain(revisedBody);
  });

  test("API late-join triad member sees only post-join messages in joined history", async ({
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("triad-joined-alice");
    const bob = uniqueUser("triad-joined-bob");
    const carol = uniqueUser("triad-joined-carol");
    await Promise.all([
      ensureRegistered(request, alice),
      ensureRegistered(request, bob),
      ensureRegistered(request, carol),
    ]);
    const [aliceToken, bobToken, carolToken] = await Promise.all([
      issueUserSession(request, alice),
      issueUserSession(request, bob),
      issueUserSession(request, carol),
    ]);
    const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
      title: `triad joined ${stamp}`,
      historyAccess: "since_join",
    });
    const defaultStrandId = await resolveDefaultStrandId(request, aliceToken, realmId);
    const pre = signedEventEnvelope({
      actorId: alice.id,
      realmId: realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: { kind: "ak.content.text", body: `triad pre ${stamp}` },
      },
    });
    await submitSignedEventApi(request, aliceToken, pre, {
      context: "pre-join triad message",
    });
    // common-fields.md section 4.5: only the target itself, or its accepted
    // directed invite, writes its `leave -> join` edge. history-visibility.md
    // section 3 anchors the `since_join` floor at that join Commit's stream
    // position, so submission order alone separates pre from post.
    await joinRealmMemberByInviteApi(request, aliceToken, realmId, {
      id: carol.id,
      token: carolToken,
    });
    const post = signedEventEnvelope({
      actorId: alice.id,
      realmId: realmId,
      kind: "ak.message.create",
      payload: {
        strand_id: defaultStrandId,
        track_name: "discussion",
        content: { kind: "ak.content.text", body: `triad post ${stamp}` },
      },
    });
    await submitSignedEventApi(request, aliceToken, post, {
      context: "post-join triad message",
    });

    const carolEvents = await listRealmEventsViaApi(request, carolToken, realmId);
    const ids = carolEvents.map((event) => event.event_id);
    expect(ids).not.toContain(pre.event_id);
    expect(ids).toContain(post.event_id);
  });

  // The history_access=since_join server gap is now covered live by the
  // API late-join case above plus spaces/history-joined-enforcement.spec.ts.
  // Phases A-D (space lifecycle, invite, mutual messaging, reply, edit) are
  // fully wired in inkson (chat-* reply/edit testids + the realm-members invite
  // modal). Phase E's *receive-side* redaction tombstone is now wired end-to-end:
  // coland folds a redacted ak.message.create into a per-message tombstone on the
  // sync timeline (projection/timeline.rs + sync/snapshot.rs call
  // apply_message_redaction_timeline_projection, which uses the SDK
  // redaction_tombstone_message_value shape: event_id preserved, body stripped,
  // redacted/state/redacted_at/redaction_ref markers added), and inkson's receive
  // path folds the tombstone onto the existing message (chat_message_from_event
  // sets redacted=true → chat-redacted-tombstone) so alice renders the tombstone
  // on reload, not just bob's optimistic local redact.
  test(
    "alice + bob + carol drive space lifecycle, mutual messaging, late-join history visibility, and redact tombstone",
    async ({
    browser,
    request,
  }, testInfo) => {
    // Three real logins, four sealed grants, three navigations per member,
    // and the complete edit/redact flow share this budget. Each convergence
    // assertion retains its own shorter bound.
    test.setTimeout(540_000);
    const stamp = Date.now();
    const [aliceFlow, bobFlow, carolFlow] = await Promise.all([
      openDpopUserPage(browser, request, "s1-alice"),
      openDpopUserPage(browser, request, "s1-bob"),
      openDpopUserPage(browser, request, "s1-carol"),
    ]);
    if (!aliceFlow || !bobFlow || !carolFlow) {
      assertJointStackNotRequired("triad collaboration browser login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const bob = bobFlow.user;
    const carol = carolFlow.user;
    const alicePage = aliceFlow.page;
    const bobPage = bobFlow.page;
    const carolPage = carolFlow.page;

    const m1 = `M1 alice hello ${stamp}`;
    const m2 = `M2 bob reply ${stamp}`;
    const m2Edited = `${m2} (edited)`;
    const m3 = `M3 welcome carol ${stamp}`;

    try {
      // Phase A — alice creates space, seed-invites bob; bob accepts.
      const realmId = await alicePage.createRealm({
        title: `S1 Triad ${stamp}`,
        summary: "triad collaboration coverage",
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "since_join",
        mlsActivated: false,
        seedMembers: [bob.id],
      });
      await stepShot(alicePage.page, testInfo, "A-alice-space-created");

      await bobPage.acceptInvite(realmId);
      await alicePage.grantRealmCapability(
        realmId,
        bobFlow.session.accountId,
        "ak.message.create",
      );
      await alicePage.grantRealmCapability(
        realmId,
        bobFlow.session.accountId,
        "ak.message.revise",
      );
      await alicePage.grantRealmCapability(
        realmId,
        bobFlow.session.accountId,
        "ak.message.redact",
      );
      await stepShot(bobPage.page, testInfo, "A-bob-accepted-invite");

      // Phase B — alice and bob exchange messages with reply chain + edit.
      await alicePage.sendTimelineMessage(realmId, m1);
      await stepShot(alicePage.page, testInfo, "B-m1-sent");

      await bobPage.gotoTimelineRealm(realmId);
      await expect(bobPage.page.getByTestId("message-list")).toContainText(m1, {
        timeout: 30_000,
      });
      await stepShot(bobPage.page, testInfo, "B-bob-received-m1");

      // Reply to M1, then edit. Chat view's reply testids use the `chat-*` prefix.
      await bobPage.clickTimelineReply(m1);
      await expect(bobPage.page.getByTestId("chat-reply-banner")).toBeVisible();
      await bobPage.sendTimelineMessage(realmId, m2);
      const m2EventOnBob = bobPage.timelineEvent(m2);
      await expect(m2EventOnBob.getByTestId("chat-reply-indicator")).toBeVisible();
      await stepShot(bobPage.page, testInfo, "B-bob-replied");

      await bobPage.clickTimelineEdit(m2);
      await bobPage.page.getByTestId("chat-edit-composer").locator("textarea").fill(m2Edited);
      await bobPage.page.getByTestId("chat-save-edit-button").click();
      await bobPage.waitForTimelineEventSettled(m2Edited);
      await expect(bobPage.page.getByTestId("chat-status")).toContainText(/Message updated/i);
      await stepShot(bobPage.page, testInfo, "B-bob-edited-m2");

      // Alice sees the edited reply.
      await alicePage.gotoTimelineRealm(realmId);
      await expect(alicePage.timelineEvent(m2Edited)).toBeVisible({ timeout: 30_000 });

      // Phase C — alice invites carol, carol accepts, carol has restricted history.
      await alicePage.inviteFromAdmin(realmId, carol.id);
      await stepShot(alicePage.page, testInfo, "C-alice-invited-carol");

      await carolPage.acceptInvite(realmId);
      await alicePage.grantRealmCapability(
        realmId,
        carolFlow.session.accountId,
        "ak.message.create",
      );
      await stepShot(carolPage.page, testInfo, "C-carol-accepted-invite");

      await carolPage.gotoTimelineRealm(realmId);
      // Spec models/realm-and-space.md §3.4: history_access=since_join →
      // carol sees nothing posted before she became a member.
      await expect(carolPage.timelineEvent(m1)).toHaveCount(0);
      await expect(carolPage.timelineEvent(m2Edited)).toHaveCount(0);
      await stepShot(carolPage.page, testInfo, "C-carol-pre-join-hidden");

      // Phase D — post-join message reaches all three.
      await alicePage.sendTimelineMessage(realmId, m3);
      await carolPage.expectTimelineEventVisible(m3, 30_000);
      await bobPage.expectTimelineEventVisible(m3, 30_000);
      await stepShot(carolPage.page, testInfo, "D-carol-sees-m3");

      // Phase E — bob redacts his own M2; alice sees tombstone; carol unaffected
      // (she never saw M2 anyway because of history_access).
      await bobPage.gotoTimelineRealm(realmId);
      await bobPage.clickTimelineRedact(m2Edited);
      await bobPage.page.getByTestId("chat-confirm-redact-button").click();
      await expect(bobPage.page.getByTestId("chat-redacted-tombstone")).toBeVisible({ timeout: 30_000 });
      await expect(bobPage.page.getByTestId("chat-status")).toContainText(/Message removed/i);
      await stepShot(bobPage.page, testInfo, "E-bob-redacted");

      await expect
        .poll(
          () => alicePage.page.getByTestId("chat-redacted-tombstone").count(),
          { timeout: 60_000, intervals: [500, 1_000, 2_000, 5_000] },
        )
        .toBeGreaterThan(0);
      // The redacted body should not be visible in plain form anymore.
      await expect(alicePage.page.getByTestId("message-list")).not.toContainText(m2Edited);
      await stepShot(alicePage.page, testInfo, "E-alice-sees-tombstone");

      await carolPage.gotoTimelineRealm(realmId);
      // Carol only sees M3 (and possibly the tombstone marker for M2, but never
      // its original text).
      await carolPage.expectTimelineEventVisible(m3, 30_000);
      await expect(carolPage.page.getByTestId("message-list")).not.toContainText(m1);
      await expect(carolPage.page.getByTestId("message-list")).not.toContainText(m2Edited);
    } finally {
      await Promise.allSettled([carolPage.close(), bobPage.close(), alicePage.close()]);
    }
  },
  );

  test.describe("E1 sub-cases", () => {
    // E1.1 — governance-objects.md section 5.3: one live directed Invite per
    // (realm_id, invitee_account_id), carried by the registered
    // `ak.component.invite.live_target.v1` slot. A second create for the same
    // account contends on that one cell and is refused with
    // `failed_precondition` / `invite_live_target_occupied`, so it never enters
    // canonical history and derives no cell write.
    //
    // Both halves of the proof matter and neither substitutes for the other:
    // the Realm log shows exactly one accepted create (authoritative state),
    // and Bob's private delivery list shows exactly one credential. The list is
    // only evidence because Alice presents Bob's issued principal locator —
    // a grant stored only at Bob's holder does not turn an explicit address
    // into consent_grant evidence. Without presented high-trust material,
    // both deliveries are correctly quarantined
    // (sync/invite-addressing.md section 7) and a count of zero would say
    // nothing about the reducer.
    test("E1.1 live-target slot — a second directed invite for the same account is refused", async ({
      browser,
      request,
    }, testInfo) => {
      const stamp = Date.now();
      const bob = uniqueUser("s1e11-bob");
      await ensureRegistered(request, bob);
      const bobToken = await issueUserSession(request, bob);
      const locator = { token: await issueInviteLocatorToken(request, bobToken) };
      const aliceFlow = await openDpopUserPage(
        browser,
        request,
        `s1e11-alice-${stamp}`,
      );
      if (!aliceFlow) {
        assertJointStackNotRequired("triad invite browser login");
        test.skip(true, "coauth DPoP session-grant login is unavailable");
        return;
      }
      const alicePage = aliceFlow.page;
      const aliceToken = aliceFlow.session.grantJwt;

      try {
        await grantInviteConsentArkret(
          request,
          bobToken,
          bob,
          aliceFlow.user.id,
        );

        const realmId = await alicePage.createRealm({
          title: `S1 Live Target Invite ${stamp}`,
          discoverability: "listed",
          joinRule: "invite",
        });

        // First invite claims the slot. inviteFromAdmin internally calls
        // gotoRealmAdminSection (Members) and opens the invite modal before
        // submitting — that already defeats the RealmAdminPanel hydration race
        // that historically caused fresh-nav fails (see
        // scenarios/spaces/admin-section-route.md).
        const firstDelivery = alicePage.page.waitForResponse((response) =>
          new URL(response.url()).pathname === "/_arkret/self/invites/dispatch" &&
          response.request().method() === "POST",
        );
        await alicePage.inviteFromAdmin(realmId, bob.id, undefined, locator);
        const firstDeliveryBody = await (await firstDelivery).json();

        // Second issue for the same account. The client MUST NOT re-sign the
        // create under a fresh event_id — that only collides with the same
        // cell again — so it acts on the occupant instead and says so.
        const repeatedDelivery = alicePage.page.waitForResponse((response) =>
          new URL(response.url()).pathname === "/_arkret/self/invites/dispatch" &&
          response.request().method() === "POST",
        );
        await alicePage.inviteFromAdmin(
          realmId,
          bob.id,
          undefined,
          locator,
          /already has a live invite/,
        );
        const repeatedDeliveryBody = await (await repeatedDelivery).json();
        await testInfo.attach("invite-delivery-outcomes", {
          body: JSON.stringify([firstDeliveryBody, repeatedDeliveryBody].map((body) => ({
            status: body.status,
            disclosed_outcome: body.disclosed_outcome,
            retry_after_ms: body.retry_after_ms,
          }))),
          contentType: "application/json",
        });

        // Realm authoritative state: exactly one accepted ak.invite.create.
        // The refused Event enters no canonical history at all, so a second
        // one appearing here would mean the slot did not hold.
        await expect
          .poll(
            async () => {
              const events = await listRealmEventsViaApi(
                request,
                aliceToken,
                realmId,
                { limit: 200 },
              );
              return events.filter(
                (event) => eventKind(event) === "ak.invite.create",
              ).length;
            },
            { timeout: 30_000 },
          )
          .toBe(1);

        // Holder-private delivery under an active consent: one credential.
        await expect
          .poll(
            async () => {
              const visible = await listInvitesApi(request, bobToken);
              return visible.filter((invite) =>
                invite.realm_id === realmId &&
                invite.invitee_account_id?.principal_id === bob.id &&
                invite.invitee_account_id.station_id === colandServiceId() &&
                invite.state === "pending"
              ).length;
            },
            { timeout: 30_000 },
          )
          .toBe(1);
      } finally {
        await alicePage.close();
      }
    });

    // E1.2 — pre-join message is sent BEFORE carol is invited. With
    // history_access=all_history_for_current_members (spec §3.4), late joiners must see the
    // pre-join timeline. coland's default sync path currently exposes the
    // full timeline regardless of visibility (see main test's coland gap
    // comment), so this positive assertion passes today; once coland adds
    // history_access filtering, this test will still be the canonical
    // "shared visibility lets carol read history" coverage.
    test("E1.2 history_access=all_history_for_current_members exposes pre-join messages to late joiner", async ({
      request,
    }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s1e12-alice");
      const carol = uniqueUser("s1e12-carol");
      await ensureRegistered(request, alice);
      await ensureRegistered(request, carol);
      const aliceToken = await issueUserSession(request, alice);
      const carolToken = await issueUserSession(request, carol);

      const preMessage = `pre-join shared message ${stamp}`;
      const realmId = await createRealmViaApi(request, aliceToken, {
        title: `S1.2 Shared History ${stamp}`,
        historyAccess: "all_history_for_current_members",
        ownerId: alice.id,
      });
      const pre = await sendPlaintextMessageViaApi(
        request,
        aliceToken,
        realmId,
        preMessage,
        { actorId: alice.id },
      );
      await joinRealmMemberByInviteApi(request, aliceToken, realmId, {
        id: carol.id,
        token: carolToken,
      });

      const carolEvents = await listRealmEventsViaApi(request, carolToken, realmId);
      expect(carolEvents.map((event) => event.event_id)).toContain(pre.event_id);
      expect(JSON.stringify(carolEvents)).toContain(preMessage);
    });

    test("E1.4 membership leave gates writes; owner re-add restores membership", async ({
      request,
    }) => {
      const stamp = Date.now();
      const alice = uniqueUser("s1e14-alice");
      const bob = uniqueUser("s1e14-bob");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const [aliceToken, bobToken] = await Promise.all([
        issueUserSession(request, alice),
        issueUserSession(request, bob),
      ]);
      const realmId = await createSharedRealmViaApi(request, alice, aliceToken, bob, {
        title: `S1.4 Leave Rejoin ${stamp}`,
        historyAccess: "all_history_for_current_members",
      });
      const strandId = await resolveDefaultStrandId(request, aliceToken, realmId);
      const beforeLeave = await sendPlaintextMessageViaApi(
        request,
        bobToken,
        realmId,
        `before leave ${stamp}`,
        { actorId: bob.id },
      );

      await submitSignedEventApi(
        request,
        bobToken,
        signedEventEnvelope({
          actorId: bob.id,
          realmId,
          kind: "ak.member.state",
          payload: {
            realm_id: realmId,
            member_id: accountActorId(bob.id),
            membership: "leave",
            reason: "self_leave",
          },
        }),
        {
          context: "bob leaves realm",
          controlObserverToken: aliceToken,
        },
      );

      const realmAfterLeave = await request.get(
        `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`,
        { headers: authHeaders(aliceToken, "GET", `${colandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}`) },
      );
      expect(realmAfterLeave.status()).toBe(200);
      expect(visibleMemberIds(await realmAfterLeave.json())).not.toContain(bob.id);

      const afterLeaveBody = `after leave rejected ${stamp}`;
      const rejected = await request.post(`${colandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(bobToken, "POST", `${colandBaseUrl()}/_arkret/self/events`),
        data: { event: signedEventEnvelope({
          actorId: bob.id,
          realmId,
          kind: "ak.message.create",
          payload: {
            strand_id: strandId,
            track_name: "discussion",
            content: { kind: "ak.content.text", body: afterLeaveBody },
          },
        }) },
      });
      expect(
        rejected.status(),
        "left member cannot write ordinary messages",
      ).toBeGreaterThanOrEqual(400);

      const eventsAfterLeave = await listRealmEventsViaApi(request, aliceToken, realmId);
      const bobMemberEvents = eventsAfterLeave.filter(
        (event) =>
          eventKind(event) === "ak.member.state" &&
          canonicalJson(eventPayload(event).member_id) ===
            canonicalJson(accountActorId(bob.id)),
      );
      expect(eventPayload(bobMemberEvents[bobMemberEvents.length - 1])).toMatchObject({
        membership: "leave",
      });
      expect(JSON.stringify(eventsAfterLeave)).not.toContain(afterLeaveBody);

      // common-fields.md section 4.5: an administrator never writes the
      // `leave -> join` edge for somebody else; the owner re-adds bob with a
      // fresh directed invite that bob accepts himself.
      await joinRealmMemberByInviteApi(request, aliceToken, realmId, {
        id: bob.id,
        token: bobToken,
      });
      const afterRejoin = await sendPlaintextMessageViaApi(
        request,
        bobToken,
        realmId,
        `after rejoin ${stamp}`,
        { actorId: bob.id },
      );
      const finalEvents = await listRealmEventsViaApi(request, aliceToken, realmId);
      expect(finalEvents.map((event) => event.event_id)).toEqual(
        expect.arrayContaining([beforeLeave.event_id, afterRejoin.event_id]),
      );
      expect(JSON.stringify(finalEvents)).not.toContain(afterLeaveBody);
    });
  });
});
