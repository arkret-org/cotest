import { test as base, type APIRequestContext, type Browser } from "@playwright/test";
import {
  ensureRegistered,
  issueDevSession,
  type JointUser,
  type JointUserPage,
  openUserPage,
  uniqueUser,
} from "./users";

export type JointRealmFixture = {
  alice: JointUser;
  bob: JointUser;
  /// Real `ck.session.grant` JWT (the bearer presented on `/_cokret/self/*`).
  aliceToken: string;
  bobToken: string;
  alicePage: JointUserPage;
  bobPage: JointUserPage;
  realmId: string;
};

export const test = base.extend<{ jointRealm: JointRealmFixture }>({
  jointRealm: async ({ browser, request }, use) => {
    const jointRealm = await createJointTwoUserRealm(browser, request);
    try {
      await use(jointRealm);
    } finally {
      await Promise.allSettled([jointRealm.bobPage.close(), jointRealm.alicePage.close()]);
    }
  },
});

export { expect } from "@playwright/test";

// NOTE: this fixture authenticates via soland dev-login (a dev-mode bearer).
// Migrating the joint browser fixture to a real ck.session.grant (so the full
// coauth enrollment + recovery path is exercised) is a tracked follow-up: it
// requires registering real coauth users (did:webvh) via coauth-register — the
// coauth debug grant-mint seam rejects fabricated did:web actors. The grant
// injection plumbing is already in place (openUserPage grantJwt/dpopSeedB64url
// + yougen dev boot injection + run-joint-e2e COAUTH_ENABLE_TEST_ENDPOINTS); it
// activates once this fixture passes real grant material.
async function createJointTwoUserRealm(
  browser: Browser,
  request: APIRequestContext,
): Promise<JointRealmFixture> {
  const stamp = Date.now();
  const alice = uniqueUser("joint-alice");
  const bob = uniqueUser("joint-bob");

  await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
  const [aliceToken, bobToken] = await Promise.all([
    issueDevSession(request, alice),
    issueDevSession(request, bob),
  ]);
  const [alicePage, bobPage] = await Promise.all([
    openUserPage(browser, alice, { sessionToken: aliceToken }),
    openUserPage(browser, bob, { sessionToken: bobToken }),
  ]);

  const realmId = await alicePage.createRealm({
    title: `joint smoke ${stamp}`,
    summary: "cotest joint harness smoke",
    discoverability: "public",
    joinRule: "invite",
    historyVisibility: "joined",
    encryptionProfile: "none",
  });

  return {
    alice,
    bob,
    aliceToken,
    bobToken,
    alicePage,
    bobPage,
    realmId,
  };
}
