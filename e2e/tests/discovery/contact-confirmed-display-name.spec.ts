// Contact identity confirmation: authorized profile resolve → first explicit
// confirmation → rename notice with the old confirmed value → explicit refresh.
// Contract: e2e/scenarios/discovery/contact-confirmed-display-name.md
// Spec: discovery/client-preferences.md §3.6, discovery/profiles-presence.md §2.3
//
// Everything before the first browser assertion runs through the API on purpose.
// This chain used to sit behind the serial Contact UI test, so a Contact failure
// skipped every profile and petname assertion with it.

import { expect, test } from "../../helpers/arkret-test";
import {
  requestContactArkret,
  respondContactArkret,
} from "../../helpers/contact-api";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  assertJointStackNotRequired,
  createDpopUserSession,
  openDpopUserPage,
  selfPathHeadersForDpopSession,
} from "../../helpers/users";
import {
  canonicalJson,
  prepareSignedEventSubmissionApi,
  principalControlRealmForId,
  retypeEventDerivedId,
  signedEventEnvelope,
} from "../../helpers/soland-api";

/// The prepared submission carries the envelope after CBS plane, frontier
/// binding and re-signing, so its Event id is the only one the service sees.
function preparedEventId(submission: Record<string, unknown>): string {
  const event = submission.event as Record<string, unknown>;
  return String(event.event_id);
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
      // The shared Direct Conversation Realm created by an accepted Contact is
      // what authorizes reading Bob's global Profile at all.
      const { outcome } = await requestContactArkret(
        request,
        aliceToken,
        bob.id,
        { requestedScopes: ["direct_message"] },
      );
      await respondContactArkret(request, bobToken, {
        requestId: outcome.request_event_ref,
        requesterId: alice.id,
        action: "accept",
        grantedScopes: ["direct_message"],
      });

      const bobRealmId = principalControlRealmForId(bob.id);
      const profileUrl = `${solandBaseUrl()}/_arkret/self/account/profile`;
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
            schema: "ak.schema.actor_profile.v1",
            realm_id: bobRealmId,
            principal_id: bob.id,
            actor_kind: "user",
            display_name: firstDisplay,
            created_at: new Date().toISOString(),
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
      const row = alicePage.page
        .getByTestId("contact-row")
        .filter({ hasText: bob.id });
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
      const renamedRow = alicePage.page
        .getByTestId("contact-row")
        .filter({ hasText: bob.id });
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
