// T-P0-05 joint harness smoke.
// Contract: true inkson UI + true soland process create a realm and render messages.

import { randomBytes } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "../../helpers/joint-fixture";
import { canonicalJson, signedEventEnvelope } from "../../helpers/soland-api";
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
  decodeEventIngressBody,
  ingressEvents,
  type IngressEvent,
} from "../../helpers/event-ingress";

test.describe.configure({ mode: "serial" });

test.describe("joint-inkson smoke @fully-implemented", () => {
  test("creates a Realm without probing its nonexistent actor frontier", async ({
    browser,
    request,
  }) => {
    test.setTimeout(360_000);
    const flow = await openDpopUserPage(
      browser,
      request,
      `joint-realm-genesis-${Date.now()}`,
      { prepareMlsDevice: false },
    );
    if (!flow) {
      assertJointStackNotRequired("joint-inkson Realm genesis browser login");
      test.skip(
        true,
        "coauth DPoP session-grant login is required for joint UI",
      );
      return;
    }

    const frontierRequests: Array<{
      body: Record<string, unknown>;
      ordinal: number;
    }> = [];
    const eventBatches: Array<{
      body: Record<string, unknown>;
      ordinal: number;
    }> = [];
    let requestOrdinal = 0;
    flow.page.page.on("request", (observed) => {
      const ordinal = requestOrdinal++;
      const url = new URL(observed.url());
      if (
        observed.method() === "QUERY" &&
        url.pathname === "/_arkret/self/events/frontier"
      ) {
        try {
          frontierRequests.push({
            body: observed.postDataJSON() as Record<string, unknown>,
            ordinal,
          });
        } catch {
          // A malformed request is not a valid registered frontier preflight.
        }
      }
      if (
        observed.method() === "POST" &&
        url.pathname === "/_arkret/self/events"
      ) {
        try {
          const body = observed.postDataJSON() as Record<string, unknown>;
          eventBatches.push({ body, ordinal });
        } catch {
          // Non-JSON traffic is irrelevant to the Event batch contract.
        }
      }
    });

    try {
      const realmId = await flow.page.createRealm({
        title: `joint Realm genesis ${Date.now()}`,
        summary: "regression for local Realm genesis authoring",
        discoverability: "listed",
        joinRule: "invite",
        historyAccess: "all_history_for_current_members",
        encryptionProfile: "none",
      });
      const batchEvents = (body: Record<string, unknown>): IngressEvent[] =>
        ingressEvents(
          decodeEventIngressBody(body, { context: "Realm bootstrap ingress" }),
        );
      const bootstrapBatch = eventBatches.find(({ body }) => {
        const events = batchEvents(body);
        return events[0]?.kind === "ak.realm.create";
      });
      const bootstrap = bootstrapBatch && batchEvents(bootstrapBatch.body);
      expect(bootstrap, "Inkson Realm bootstrap POST batch").toBeTruthy();
      expect(bootstrap![0].realm_id).toBeUndefined();
      expect(bootstrap![0].event_id?.replace(/^ak:event:/, "ak:realm:")).toBe(
        realmId,
      );
      expect(bootstrap![0].actor_seq).toBe(0);
      expect(bootstrap![0].prev_refs).toEqual([]);
      // realm-and-space.md section 2.5: create is followed only by the closed
      // bootstrap facet whitelist. v1 has no founding `ak.capability.grant`;
      // the creator's root authority is the authority-root cell the create
      // Event's registered reducer contract writes.
      expect(
        bootstrap!.some((event) => event.kind === "ak.capability.grant"),
        "genesis batch carries no capability grant",
      ).toBe(false);
      // `artifacts/registry/contract-registry.json`
      // `realm_bootstrap_registry.ordinary_collaboration.ordered_slots`: the
      // slot after `ak.realm.create` is `ak.realm.profile` (join_rule is slot
      // 3, after policy_bundle).
      expect(bootstrap![1].kind).toBe("ak.realm.profile");
      expect(bootstrap![1].actor_seq).toBe(1);
      expect(bootstrap![1].prev_refs).toEqual([bootstrap![0].event_id]);

      // realm-and-space.md section 2.7: the creator's membership comes only
      // from the unit's LAST standalone `ak.member.state{membership="join"}`,
      // which is the genesis write of that member cell and MUST carry
      // `head_eq null`. `ak.realm.create` never writes membership implicitly.
      const creatorMembership = bootstrap!.at(-1)!;
      const creatorDid = bootstrap![0].actor_id;
      expect(creatorMembership.kind).toBe("ak.member.state");
      expect(creatorMembership.actor_id).toBe(creatorDid);
      expect(creatorMembership.payload).toMatchObject({
        realm_id: realmId,
        actor_id: creatorDid,
        membership: "join",
      });
      expect(creatorMembership.preconditions).toEqual([
        {
          cell: `ak:cell:ak.component.member.state.v1:${creatorDid}`,
          predicate: { op: "head_eq", value: null },
        },
      ]);
      expect(
        bootstrap!.filter((event) => event.kind === "ak.member.state"),
        "genesis carries exactly one membership write",
      ).toHaveLength(1);

      const preflightForNewRealm = frontierRequests.filter(
        (observed) =>
          observed.ordinal < bootstrapBatch!.ordinal &&
          observed.body.realm_id === realmId &&
          typeof observed.body.actor_id === "string",
      );
      expect(
        preflightForNewRealm,
        "registered Realm genesis must be authored locally before submit",
      ).toEqual([]);
    } finally {
      await flow.page.page.context().close();
    }
  });

  // Inkson consumes the accepted default-Strand projection. The Realm token
  // is never retyped into a Strand token; this smoke test resolves the exact
  // projected coordinate before submitting the message.
  test("creates a public realm and renders a soland message in inkson", async ({
    jointRealm,
  }) => {
    // Regression: the Coauth service-account hint belongs to the Account
    // Authority namespace. Public principal identity must instead use the
    // Soland-signed handle consistently across every shell/chat surface.
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
    ).toHaveText(`@${principalHandle}`);
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
    const participantId = participantSession!.user.did;
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
      await submitSignedEvent(
        request,
        jointRealm.aliceSession,
        jointRealm.alice.did,
        jointRealm.alicePage.serverUrl,
        jointRealm.realmId,
        "ak.member.state",
        {
          realm_id: jointRealm.realmId,
          actor_id: participantId,
          membership: "join",
          delivery_status: "unroutable",
        },
      );
      const controllerMessageId = `ak:message:${uuidV7()}`;
      await submitSignedEvent(
        request,
        jointRealm.aliceSession,
        jointRealm.alice.did,
        jointRealm.alicePage.serverUrl,
        jointRealm.realmId,
        "ak.message.create",
        {
          message_id: controllerMessageId,
          strand_id: strandId,
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: `mention ${forgedDisplayName}`,
            mentions: [
              {
                kind: "mention",
                subject_id: participantId,
                controller_subject_id: jointRealm.alice.did,
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
          reply_to: controllerMessageId,
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
          `[data-testid="participant-agent-group"][data-controller-id="${jointRealm.alice.did}"]`,
        ),
      ).toHaveCount(0);

      const participantRow = jointRealm.alicePage.page
        .getByTestId("discussion-user-row")
        .filter({
          has: jointRealm.alicePage.page.getByTitle(participantId, {
            exact: true,
          }),
        });
      await expect(participantRow).toBeVisible();
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
  test("admin invite remains visible to invitee without poisoning account subscribe cursor", async ({
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
        encryptionProfile: "none",
      });
      await alicePage.inviteFromAdmin(realmId, bob.did);

      await expect
        .poll(
          async () => {
            const invites = await listInvitesForDpop(
              request,
              bobFlow.session,
              bobPage.serverUrl,
              bob.did,
            );
            return invites.some(
              (invite) =>
                invite.realm_id === realmId && invite.invitee === bob.did,
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
  actorDid: string,
  serverUrl: string,
  realmId: string,
  kind: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const url = `${serverUrl}/_arkret/self/events`;
  const frontier = await readRealmActorFrontier(
    request,
    session,
    actorDid,
    serverUrl,
    realmId,
  );
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    kind,
    actorSeq: frontier.nextActorSeq,
    prevRefs: frontier.frontierEventIds,
    payload,
  });
  const response = await request.post(url, {
    headers: selfPathHeadersForDpopSession(session, "POST", url),
    data: envelope,
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

async function readRealmActorFrontier(
  request: APIRequestContext,
  session: DpopUserSession,
  actorDid: string,
  serverUrl: string,
  realmId: string,
): Promise<{ nextActorSeq: number; frontierEventIds: string[] }> {
  const href = new URL("/_arkret/self/events/frontier", serverUrl).toString();
  const response = await request.fetch(href, {
    method: "QUERY",
    headers: {
      ...selfPathHeadersForDpopSession(session, "QUERY", href),
      "content-type": "application/json",
    },
    data: canonicalJson({ actor_id: actorDid, realm_id: realmId }),
  });
  const text = await response.text();
  expect(
    response.ok(),
    `read actor frontier returned ${response.status()}: ${text}`,
  ).toBeTruthy();
  const body = JSON.parse(text) as {
    frontier?: {
      actor_id?: unknown;
      next_actor_seq?: unknown;
      frontier_event_ids?: unknown;
    };
  };
  const frontier = body.frontier;
  expect(frontier?.actor_id, "actor frontier identity").toBe(actorDid);
  const nextActorSeq = frontier?.next_actor_seq;
  expect(
    typeof nextActorSeq === "number" &&
      Number.isSafeInteger(nextActorSeq) &&
      nextActorSeq >= 0,
    `actor frontier sequence is invalid: ${text}`,
  ).toBeTruthy();
  if (
    typeof nextActorSeq !== "number" ||
    !Number.isSafeInteger(nextActorSeq) ||
    nextActorSeq < 0
  ) {
    throw new Error(`actor frontier sequence is invalid: ${text}`);
  }
  const frontierEventIds = frontier?.frontier_event_ids;
  expect(Array.isArray(frontierEventIds), "actor frontier event ids").toBe(
    true,
  );
  if (!Array.isArray(frontierEventIds)) {
    throw new Error(`actor frontier event ids are invalid: ${text}`);
  }
  expect(frontierEventIds.every((eventId) => typeof eventId === "string")).toBe(
    true,
  );
  expect([...frontierEventIds].sort()).toEqual(frontierEventIds);
  expect(new Set(frontierEventIds).size).toBe(frontierEventIds.length);
  expect(frontierEventIds.length === 0).toBe(nextActorSeq === 0);
  return {
    nextActorSeq,
    frontierEventIds: frontierEventIds as string[],
  };
}

function canonicalHandle(handle: string, serverUrl: string): string {
  const localpart = handle.trim().replace(/^@/, "").split(":", 1)[0];
  return `${localpart}:${new URL(serverUrl).hostname.toLowerCase()}`;
}

async function listInvitesForDpop(
  request: APIRequestContext,
  session: DpopUserSession,
  serverUrl: string,
  subjectDid: string,
): Promise<Array<{ id: string; realm_id: string; invitee?: string }>> {
  const url = new URL("/_arkret/self/authz/invites", serverUrl);
  url.searchParams.set("subject", subjectDid);
  const href = url.toString();
  const response = await request.get(href, {
    headers: selfPathHeadersForDpopSession(session, "GET", href),
  });
  const text = await response.text();
  expect(
    response.ok(),
    `list invites returned ${response.status()}: ${text}`,
  ).toBeTruthy();
  const body = JSON.parse(text) as {
    invites?: Array<{ id: string; realm_id: string; invitee?: string }>;
  };
  return body.invites ?? [];
}

// COT-06-004: discover the default Strand via projection rather than deriving it
// from the Realm identity token. This joint harness submits against an explicit serverUrl
// (true soland process), so it cannot reuse the shared solandBaseUrl-bound
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
    items?: Array<{ strand_id?: string; is_default?: boolean }>;
  };
  const strands = Array.isArray(body.strands)
    ? body.strands
    : Array.isArray(body.items)
      ? body.items
      : [];
  const def = strands.find((strand) => strand.is_default === true);
  if (def?.strand_id) {
    return def.strand_id;
  }
  throw new Error(
    `resolveDefaultStrandId: accepted projections for ${realmId} expose no default Strand`,
  );
}

function uuidV7(): string {
  const time = Date.now().toString(16).padStart(12, "0").slice(-12);
  const random = randomBytes(9).toString("hex");
  const variant = (8 + (randomBytes(1)[0] & 0x03)).toString(16);
  return [
    time.slice(0, 8),
    time.slice(8, 12),
    `7${random.slice(0, 3)}`,
    `${variant}${random.slice(3, 6)}`,
    random.slice(6, 18),
  ].join("-");
}
