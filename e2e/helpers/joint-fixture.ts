import { test as base, type APIRequestContext, type Browser } from "@playwright/test";
import {
  createDpopUserSession,
  type DpopUserSession,
  type JointUser,
  type JointUserPage,
  openUserPage,
} from "./users";

export type JointRealmFixture = {
  alice: JointUser;
  bob: JointUser;
  /// Real `ak.session.grant` JWT (the bearer presented on `/_arkret/self/*`).
  aliceToken: string;
  bobToken: string;
  aliceSession: DpopUserSession;
  bobSession: DpopUserSession;
  alicePage: JointUserPage;
  bobPage: JointUserPage;
  realmId: string;
};

export const test = base.extend<{ jointRealm: JointRealmFixture }>({
  jointRealm: async ({ browser, request }, use, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 360_000));
    const jointRealm = await createJointTwoUserRealm(browser, request);
    try {
      await use(jointRealm);
    } finally {
      await Promise.allSettled([jointRealm.bobPage.close(), jointRealm.alicePage.close()]);
    }
  },
});

export { expect } from "@playwright/test";

// The joint browser fixture uses real coauth-minted ak.session.grant material
// and registers the same principal/device at soland before opening inkson.
async function createJointTwoUserRealm(
  browser: Browser,
  request: APIRequestContext,
): Promise<JointRealmFixture> {
  const stamp = Date.now();
  const [aliceSession, bobSession] = await Promise.all([
    createDpopUserSession(request, "joint-alice", { skipDeviceEnrollment: true }),
    createDpopUserSession(request, "joint-bob", { skipDeviceEnrollment: true }),
  ]);
  if (!aliceSession || !bobSession) {
    throw new Error("joint fixture requires coauth DPoP session-grant login");
  }
  const alice = aliceSession.user;
  const bob = bobSession.user;
  const [alicePage, bobPage] = await Promise.all([
    openUserPage(browser, alice, {
      grantJwt: aliceSession.grantJwt,
      dpopSeedB64url: aliceSession.dpopSeedB64url,
      eventSigningSeedB64url: aliceSession.eventSigningSeedB64url,
      grantId: aliceSession.grantId,
      grantAudience: aliceSession.grantAudience,
    }),
    openUserPage(browser, bob, {
      grantJwt: bobSession.grantJwt,
      dpopSeedB64url: bobSession.dpopSeedB64url,
      eventSigningSeedB64url: bobSession.eventSigningSeedB64url,
      grantId: bobSession.grantId,
      grantAudience: bobSession.grantAudience,
    }),
  ]);
  await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);

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
    aliceToken: aliceSession.grantJwt,
    bobToken: bobSession.grantJwt,
    aliceSession,
    bobSession,
    alicePage,
    bobPage,
    realmId,
  };
}
