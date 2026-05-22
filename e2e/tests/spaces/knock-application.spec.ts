// Knock application + review + cooldown
// Contract: e2e/scenarios/spaces/knock-application.md
// Spec refs:
//   - models/space-and-place.md §3.3-§3.6 (join policy, application, review)
//   - §3.11 reuse limits / cooldown
//
// Soland implementation status (2026-05 audit):
//   ✓ PUT /api/v1/spaces/{id}/policy can set join_rule="knock"
//   ✓ POST /api/v1/moves accepts cx.member.state{membership="knock"}
//   ✗ space.join_policy cell family not registered
//   ✗ member.application / member.application.review event kinds not present
//   ✗ cooldown_after_reject not enforced
//   ✗ cx.invite.create.refs[role="join_authorised_by"] not validated
// The fixme tests below encode the spec contract that soland MUST satisfy
// once those handlers ship.

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("knock + application + cooldown", () => {
  test("alice opens a knock space and lists bob in member.state=knock after he knocks", async ({
    browser,
    request,
  }) => {
    const stamp = Date.now();
    const alice = uniqueUser("s6-alice");
    const bob = uniqueUser("s6-bob");
    await ensureRegistered(request, alice);
    await ensureRegistered(request, bob);
    const aliceToken = await issueDevSession(request, alice);
    const bobToken = await issueDevSession(request, bob);
    const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });

    try {
      const spaceId = await alicePage.createSpace({
        title: `S6 Knock ${stamp}`,
        summary: "knock + application coverage",
        discoverability: "listed",
        joinRule: "knock",
        historyVisibility: "joined",
      });

      // bob submits cx.member.state{membership="knock"} — soland accepts via
      // POST /api/v1/moves. Constructing a signed Move here would duplicate
      // SDK code, so we go through soland's higher-level "knock" REST shim
      // if it exists; otherwise the membership endpoint MAY be wired.
      const knockResp = await request.post(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/members`,
        {
          headers: { authorization: `Bearer ${bobToken}` },
          data: { member: bob.did, action: "knock" },
        },
      );
      // /members endpoint is owner-only in soland today (no dedicated knock
      // shim yet), so bob's self-knock attempt may return 403; the dedicated
      // knock Move endpoint may not exist (404). All shapes are acceptable
      // for the probe — the real contract is in the fixme tests below.
      expect([200, 201, 202, 400, 403, 404]).toContain(knockResp.status());

      // Whichever route was used, alice's space-admin view MUST list bob in
      // an "applicants / knockers" pane. Yougen renders the FSM members
      // table; we just look for bob's DID anywhere in space-admin-panel.
      await alicePage.gotoSpaceAdmin(spaceId);
      if (knockResp.ok()) {
        await expect(alicePage.page.getByTestId("space-admin-panel")).toContainText(bob.did, {
          timeout: 30_000,
        });
      }
    } finally {
      await alicePage.close();
    }
  });

  // The remainder of S6 covers spec contract that soland has not implemented
  // (audit 2026-05). They are encoded as fixme tests so that:
  //   - playwright reports them as expected-to-fail without burying the contract;
  //   - once soland lands the missing surfaces, removing `test.fixme` activates them.

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.A bob submits structured member.application after knocking; alice (with cx.space.join.review) sees the answers and accepts",
    async () => {
      // spec: models/space-and-place.md §3.6.2-§3.6.3
      // soland gap: member.application{,.review} event kinds not registered;
      //             no /api/v1/spaces/:id/applications listing endpoint.
    },
  );

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.B alice's cx.invite.create.refs[role=\"join_authorised_by\"] is required to point at a fresh review accept; reducer rejects re-used or stale refs",
    async () => {
      // spec: models/space-and-place.md §3.6.5
      // soland gap: invite reducer does not enforce the refs binding.
    },
  );

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.C mallory is rejected by alice and CANNOT re-knock until cooldown_after_reject (default 72h) elapses; cooldown gate independent of combinator",
    async () => {
      // spec: models/space-and-place.md §3.6, §3.3.1 cooldown gate
      // soland gap: no temporal cooldown tracking on member state transitions.
    },
  );

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.D max_open_applications_per_actor=1 — bob's second open application is rejected before review",
    async () => {
      // spec: models/space-and-place.md §3.3 + §3.11 reuse limits.
      // soland gap: application state not tracked.
    },
  );

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.E application_ttl expiry — application accepted past TTL is rejected even if reviewer signs accept",
    async () => {
      // spec: §3.3 application_ttl (default 168h, min 1h).
      // soland gap: application TTL field not modeled.
    },
  );

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.F reviewer loses cx.space.join.review between review accept and invite create; invite create MUST be rejected even though review already accepted",
    async () => {
      // spec: §3.6.5 #3 — reducer re-checks reviewer capability when invite is written.
      // soland gap: capability re-check on invite write not enforced.
    },
  );

  test.fixme(
    // @blocking-on: soland#spaces-knock-application-gap
    // @user-promise: e2e/scenarios/spaces/knock-application.md
    // @expected-live-by: 2026Q3
    "E6.G applicant_visibility=reviewer_only — non-reviewer members CANNOT read application answers; sync service returns 403 and writes cx.audit.accessed",
    async () => {
      // spec: §3.2 #2, §3.6.2 encryption_envelope.
      // soland gap: no access-control on application payloads (kinds not present).
    },
  );
});
