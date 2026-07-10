// T-P0-05 joint harness smoke.
// Contract: true inkson UI + true soland process create a realm and render messages.

import { randomBytes } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";
import { test, expect } from "../../helpers/joint-fixture";
import { signedEventEnvelope } from "../../helpers/soland-api";
import {
  assertJointStackNotRequired,
  type DpopUserSession,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("joint-inkson smoke @fully-implemented", () => {
  // The inkson chat view synthesizes a default discussion channel from the
  // realm id (views/chat/model/strands.rs default_discussion_strand_id /
  // default_discussion_channel) even when soland has not marked any Strand
  // is_default, so the message-list renders without an explicit
  // ak.realm.set_default_strand. The submitted message addresses the same
  // derived ak:strand:<uuid> the channel selects, so it lands on the rendered
  // strand.
  test("creates a public realm and renders a soland message in inkson", async ({
    jointRealm,
    request,
  }) => {
    const stamp = Date.now();
    const aliceMessage = `joint smoke from Alice ${stamp}`;

    await submitMessageEvent(
      request,
      jointRealm.aliceSession,
      jointRealm.alice.did,
      jointRealm.alicePage.serverUrl,
      jointRealm.realmId,
      aliceMessage,
    );
    await jointRealm.alicePage.gotoTimelineRealm(jointRealm.realmId);
    await expect(jointRealm.alicePage.timelineEvent(aliceMessage)).toBeVisible({
      timeout: 30_000,
    });
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
        subscribeFailures.push(`${response.status()} ${response.url()} ${body}`);
      });
    }

    try {
      const realmId = await alicePage.createRealm({
        title: `joint invite ${stamp}`,
        summary: "regression for write sync_token cursor poisoning",
        discoverability: "listed",
        joinRule: "invite",
        historyVisibility: "joined",
        encryptionProfile: "none",
      });
      await alicePage.inviteFromAdmin(realmId, bob.did);

      await expect
        .poll(async () => {
          const invites = await listInvitesForDpop(
            request,
            bobFlow.session,
            bobPage.serverUrl,
            bob.did,
          );
          return invites.some(
            (invite) => invite.realm_id === realmId && invite.invitee === bob.did,
          );
        }, { timeout: 30_000 })
        .toBe(true);

      await bobPage.page.goto("/notifications", { waitUntil: "domcontentloaded" });
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

      await expect(bobPage.page.getByTestId("notifications-status")).toContainText(
        /Joined Realm/,
        { timeout: 30_000 },
      );
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
        .poll(() => subscribeResponses, { timeout: 30_000, intervals: [250, 500, 1_000] })
        .toBeGreaterThan(baselineResponses);

      expect(
        subscribeFailures.filter((failure) =>
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

async function submitMessageEvent(
  request: APIRequestContext,
  session: DpopUserSession,
  actorDid: string,
  serverUrl: string,
  realmId: string,
  body: string,
) {
  const eventId = `ak:event:${uuidV7()}`;
  const strandId = await resolveDefaultStrandId(request, session, serverUrl, realmId);
  const payload = {
    strand_id: strandId,
    track_name: "discussion",
    content: {
      kind: "ak.content.text",
      body,
    },
  };
  const envelope = signedEventEnvelope({
    actorDid,
    realmId,
    eventId,
    kind: "ak.message.create",
    actorSeq: 9_000_000_000_000_000,
    payload,
  });

  const url = `${serverUrl}/_arkret/self/events`;
  const response = await request.post(url, {
    headers: selfPathHeadersForDpopSession(session, "POST", url),
    data: envelope,
  });
  const text = await response.text();
  expect([200, 201], `submit ak.message.create: ${text}`).toContain(response.status());
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
  expect(response.ok(), `list invites returned ${response.status()}: ${text}`).toBeTruthy();
  const body = JSON.parse(text) as {
    invites?: Array<{ id: string; realm_id: string; invitee?: string }>;
  };
  return body.invites ?? [];
}

// COT-06-004: discover the default Strand via projection rather than deriving it
// from the Realm UUID. This joint harness submits against an explicit serverUrl
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
    if (typeof realm.default_strand_id === "string" && realm.default_strand_id) {
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
  // The inkson UI realm-create flow does not emit an explicit
  // ak.realm.set_default_strand, so soland never marks a strand is_default for
  // it. inkson addresses the default strand by the deterministic
  // default_strand_id_for_realm convention (ak:realm:<uuid> -> ak:strand:<uuid>);
  // derive the same id so the message lands on the strand inkson renders.
  const suffix = realmId.startsWith("ak:realm:")
    ? realmId.slice("ak:realm:".length)
    : realmId;
  return `ak:strand:${suffix}`;
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
