// Contact identity confirmation: authorized profile resolve → first explicit
// confirmation → rename notice with the old confirmed value → explicit refresh.
// Contract: e2e/scenarios/discovery/contact-confirmed-display-name.md
// Spec: discovery/client-preferences.md §3.6, discovery/profiles-presence.md §2.3
//
// Everything before the first browser assertion runs through the API on purpose.
// This chain used to sit behind the serial Contact UI test, so a Contact failure
// skipped every profile and petname assertion with it.

import { expect, test } from "../../helpers/arkret-test";
import type { APIRequestContext, APIResponse } from "@playwright/test";
import {
  contactRow,
  requestContactArkret,
  respondContactArkret,
} from "../../helpers/contact-api";
import { colandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  openDpopUserPage,
  openDpopUserPageFromSession,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";
import {
  accountActorId,
  canonicalJson,
  prepareSignedEventSubmissionApi,
  principalControlRealmForId,
  retypeEventDerivedId,
  signedEventEnvelope,
} from "../../helpers/coland-api";

/// The prepared submission carries the envelope after CBS plane, frontier
/// binding and re-signing, so its Event id is the only one the service sees.
function preparedEventId(submission: Record<string, unknown>): string {
  const event = submission.event as Record<string, unknown>;
  return String(event.event_id);
}

// Lose the caller's first successful commit response after the real Station
// has persisted it. Exact replay must recover its original durable outcome.
function loseFirstContactCommitResponse(request: APIRequestContext) {
  let originalOutcome: string | undefined;
  let lostAt: number | undefined;
  let replayAt: number | undefined;
  const commitBytes: string[] = [];
  const replayingRequest = new Proxy(request, {
    get(target, property) {
      if (property !== "post") {
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      }
      return async (...args: Parameters<APIRequestContext["post"]>) => {
        const [url, options] = args;
        const isCommit = url.endsWith("/_arkret/self/contacts/request") &&
          typeof options?.data === "string" &&
          JSON.parse(options.data).phase === "commit";
        if (isCommit) {
          commitBytes.push(options!.data as string);
          if (lostAt !== undefined && replayAt === undefined) replayAt = Date.now();
        }
        const response = await target.post(...args);
        if (!isCommit || !response.ok() || originalOutcome !== undefined) {
          return response;
        }
        originalOutcome = await response.text();
        lostAt = Date.now();
        const problem = {
          type: "https://arkret.org/problems/temporarily_unavailable",
          title: "Temporary contact response loss",
          status: 503,
          detail: "The committed Contact outcome is temporarily unavailable to this caller.",
        };
        return new Proxy(response, {
          get(saved, member) {
            if (member === "status") return () => 503;
            if (member === "ok") return () => false;
            if (member === "json") return async () => problem;
            if (member === "text") return async () => JSON.stringify(problem);
            if (member === "headers") return () => ({
              "content-type": "application/problem+json",
              "retry-after": "0",
            });
            const value = Reflect.get(saved, member);
            return typeof value === "function" ? value.bind(saved) : value;
          },
        });
      };
    },
  });
  return {
    request: replayingRequest,
    async assertExactRecovery(response: APIResponse) {
      expect(originalOutcome !== undefined, "a real Contact commit was accepted before response loss").toBe(true);
      expect(commitBytes.length, "the lost response causes an exact commit replay").toBeGreaterThanOrEqual(2);
      expect(new Set(commitBytes).size, "all commit retries preserve the complete signed request bytes").toBe(1);
      expect(replayAt! - lostAt!, "Retry-After zero does not shorten the first one-second backoff").toBeGreaterThanOrEqual(1_000);
      expect(await response.text() === originalOutcome, "replay returns the original durable outcome bytes").toBe(true);
    },
  };
}

test.describe("contact confirmed display name", () => {
  test("a holder confirms an identity once, is warned when the peer renames, and keeps its petname", async ({
    browser,
    request,
  }, testInfo) => {
    test.setTimeout(420_000);
    const stamp = Date.now();
    const aliceSession = await openDpopUserPage(
      browser,
      request,
      `confirmed-name-alice-${stamp}`,
    );
    const bobSession = await createDpopUserSession(
      request,
      `confirmed-name-bob-${stamp}`,
    );
    if (!aliceSession || !bobSession) {
      assertJointStackNotRequired("contact confirmed display name login");
      test.skip(true, "coauth DPoP session-grant login is unavailable");
      return;
    }
    const alice = aliceSession.user;
    const alicePage = aliceSession.page;
    const aliceToken = aliceSession.session.grantJwt;
    const bob = bobSession.user;
    const bobToken = bobSession.grantJwt;

    try {
      // A shared Collaboration Realm is what authorizes reading Bob's global
      // Profile at all (profiles-presence.md §2.3). Accepting the Contact does
      // not create one: only the pair's founder authors the Direct
      // Conversation founding unit, and in the normal branch that founder is
      // the responder (contact-and-direct-conversation.md §5.2 / §5.5).
      const lostContactResponse = loseFirstContactCommitResponse(request);
      const { outcome, response: contactResponse } = await requestContactArkret(
        lostContactResponse.request,
        aliceToken,
        bob.id,
        { requestedScopes: ["direct_message"] },
      );
      await lostContactResponse.assertExactRecovery(contactResponse);
      await respondContactArkret(request, bobToken, {
        requestId: outcome.request_event_ref,
        requesterId: alice.id,
        action: "accept",
        grantedScopes: ["direct_message"],
      });
      const bobFlow = await openDpopUserPageFromSession(browser, bobSession);
      expect(bobFlow, "Bob's founder device opens").toBeTruthy();
      const bobPage = bobFlow!.page;
      try {
        await Promise.all([
          alicePage.completeRecoveryKeySetupIfPrompted(30_000),
          bobPage.completeRecoveryKeySetupIfPrompted(30_000),
        ]);
        await bobPage.page.getByTestId("realm-sidebar-tab-direct").click();
        const aliceRow = bobPage.page.locator(
          `[data-testid="direct-conversation-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(alice.id)))}]`,
        );
        await expect(async () => {
          if (!new URL(bobPage.page.url()).pathname.startsWith("/direct/")) {
            await aliceRow.click();
          }
          await expect(bobPage.page).toHaveURL(/\/direct\/ak:realm:.*\/ak:strand:/, {
            timeout: 5_000,
          });
        }).toPass({ timeout: 180_000, intervals: [2_000] });
        const [, , encodedRealmId, encodedStrandId] = new URL(bobPage.page.url()).pathname.split("/");
        // The recipient opens the same conversation to demand its verified
        // scope current before installing and acknowledging the Welcome.
        await alicePage.page.getByTestId("realm-sidebar-tab-direct").click();
        const bobRow = alicePage.page.locator(
          `[data-testid="direct-conversation-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(bob.id)))}]`,
        );
        await bobRow.click();
        await expect(alicePage.page).toHaveURL(/\/direct\/ak:realm:.*\/ak:strand:/, { timeout: 180_000 });
        expect(new URL(alicePage.page.url()).pathname).toBe(new URL(bobPage.page.url()).pathname);
        await expect.poll(async () =>
          (await contactRow(request, aliceToken, bob.id))?.direct_conversation,
        { timeout: 90_000, intervals: [500, 1_000, 2_000] }).toMatchObject({
          realm_id: decodeURIComponent(encodedRealmId),
          main_strand_id: decodeURIComponent(encodedStrandId),
        });
      } finally {
        await bobPage.close();
      }

      const bobRealmId = principalControlRealmForId(bob.id);
      const profileUrl = `${colandBaseUrl()}/_arkret/self/account/profile`;
      const postProfile = async (
        submission: Record<string, unknown>,
        envelope: Record<string, unknown>,
      ) => {
        const send = () =>
          request.post(profileUrl, {
            headers: {
              ...selfPathHeadersForDpopSession(bobSession, "POST", profileUrl),
              "content-type": "application/json",
            },
            data: canonicalJson({ profile_event: submission }),
          });
        let response = await send();
        if (response.status() === 503) {
          for (let attempt = 0; attempt < 120; attempt += 1) {
            response = await send();
            if (response.status() !== 503) break;
            await new Promise((resolve) => setTimeout(resolve, 250));
          }
        }
        const text = await response.text();
        expect(response.status(), text).toBe(200);
        return JSON.parse(text);
      };

      const firstDisplay = `Bob Before ${stamp}`;
      const renamedDisplay = `Bob After ${stamp}`;
      const createEnvelope = signedEventEnvelope({
        kind: "ak.profile.create",
        realmId: bobRealmId,
        actorId: bob.id,
        payload: {
          object: {
            principal_id: bob.id,
            actor_kind: "user",
            display_name: firstDisplay,
          },
        },
      });
      const createSubmission = await prepareSignedEventSubmissionApi(
        request,
        bobToken,
        createEnvelope,
        { context: "prepare contact peer profile create" },
      );
      const created = await postProfile(createSubmission, createEnvelope);
      expect(created.profile?.display_name).toBe(firstDisplay);
      const profileId = retypeEventDerivedId(
        preparedEventId(createSubmission),
        "actor_profile",
      );

      // The petname editor lives on the advanced Contacts settings surface.
      await alicePage.gotoAppPanel("/settings/contacts", "settings-panel");
      const peerSelector = `[data-testid="contact-row"][data-peer=${JSON.stringify(canonicalJson(accountActorId(bob.id)))}]`;
      const row = alicePage.page.locator(peerSelector);
      await expect(row).toBeVisible({ timeout: 60_000 });
      // The live verified Profile display arrives through the authorized
      // resolve, not through the Contact row itself.
      await expect(row).toContainText(firstDisplay, { timeout: 60_000 });
      await stepShot(alicePage.page, testInfo, "profile-resolved");

      // First explicit confirmation. Accept could not have made one: the pair
      // had no shared Realm when Alice sent the request.
      const confirm = row.getByTestId(/^contact-confirm-name-/);
      await expect(confirm).toBeVisible({ timeout: 60_000 });
      await confirm.click();
      await expect(row.getByTestId(/^contact-confirm-identity-/)).toBeHidden({
        timeout: 60_000,
      });

      // A petname is holder-authored and must survive everything below.
      const petname = `Bee ${stamp}`;
      await row.getByTestId(/^contact-petname-/).first().fill(petname);
      await row.getByTestId(/^contact-petname-save-/).click();
      await expect(row).toContainText(petname, { timeout: 60_000 });

      const updateEnvelope = signedEventEnvelope({
        kind: "ak.profile.update",
        realmId: bobRealmId,
        actorId: bob.id,
        payload: {
          target_ref: profileId,
          patch: { display_name: { $op: "set", value: renamedDisplay } },
        },
      });
      const updateSubmission = await prepareSignedEventSubmissionApi(
        request,
        bobToken,
        updateEnvelope,
        { context: "prepare contact peer profile update" },
      );
      const updated = await postProfile(updateSubmission, updateEnvelope);
      expect(updated.profile?.display_name).toBe(renamedDisplay);

      // The cached row is only refreshed on its own freshness window, so the
      // notice is asserted after a fresh page load rather than in place.
      await alicePage.gotoAppPanel("/settings/contacts", "settings-panel");
      await alicePage.page.reload();
      await expect(alicePage.page.getByTestId("settings-panel")).toBeVisible({ timeout: 60_000 });
      const renamedRow = alicePage.page.locator(peerSelector);
      const notice = renamedRow.getByTestId(/^contact-display-name-changed-/);
      await expect(notice).toBeVisible({ timeout: 120_000 });
      await expect(notice).toContainText(firstDisplay);
      await expect(notice).toContainText(renamedDisplay);
      await expect(renamedRow).toContainText(petname);
      await stepShot(alicePage.page, testInfo, "rename-warned");

      // Only an explicit confirmation refreshes the baseline, and it leaves the
      // petname exactly as the holder wrote it.
      await notice.getByTestId(/^contact-confirm-name-/).click();
      await expect(notice).toBeHidden({ timeout: 60_000 });
      await expect(renamedRow).toContainText(petname);
      await expect(
        renamedRow.getByTestId(/^contact-petname-/).first(),
      ).toHaveValue(petname);
    } finally {
      await alicePage.close();
    }
  });
});
