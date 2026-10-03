import {
  test as base,
  type APIRequestContext,
  type Browser,
} from "./arkret-test";
import {
  createDpopUserSession,
  type DpopUserSession,
  type JointUser,
  type JointUserPage,
  openUserPage,
} from "./users";

export type JointUsersFixture = {
  alice: JointUser;
  bob: JointUser;
  /// Real `ak.session.grant` JWT (the bearer presented on `/_arkret/self/*`).
  aliceToken: string;
  bobToken: string;
  aliceSession: DpopUserSession;
  bobSession: DpopUserSession;
  alicePage: JointUserPage;
  bobPage: JointUserPage;
};

export type JointRealmFixture = JointUsersFixture & { realmId: string };

export const test = base.extend<{
  jointUsers: JointUsersFixture;
  jointRealm: JointRealmFixture;
}>({
  jointUsers: async ({ browser, request }, use, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 360_000));
    const users = await createJointTwoUsers(browser, request);
    try {
      await use(users);
    } finally {
      await Promise.allSettled([users.bobPage.close(), users.alicePage.close()]);
    }
  },
  jointRealm: async ({ jointUsers }, use) => {
    const realmId = await jointUsers.alicePage.createRealm({
      title: `joint smoke ${Date.now()}`,
      summary: "cotest joint harness smoke",
      discoverability: "public",
      joinRule: "invite",
      historyAccess: "since_join",
      mlsActivated: false,
    });
    await use({ ...jointUsers, realmId });
  },
});

export { expect } from "./arkret-test";

// The joint browser fixture uses real coauth-minted ak.session.grant material
// and registers the same principal/device at soland before opening inkson.
async function createJointTwoUsers(
  browser: Browser,
  request: APIRequestContext,
): Promise<JointUsersFixture> {
  // Principal inception is lease-fenced by the local Coauth/Soland pair.
  // Starting two independent DID inception/handoff chains concurrently can
  // make each wait on the other's global identity-binding lease until the
  // caller timeout. Keep user creation sequential; browser bootstrap below is
  // still parallel once both durable principals exist.
  const aliceSession = await createDpopUserSession(request, "joint-alice", {});
  const bobSession = await createDpopUserSession(request, "joint-bob", {});
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
      accountId: aliceSession.accountId,
      principalControlRealmId: aliceSession.principalControlRealmId,
      grantAudience: aliceSession.grantAudience,
      recoveryKey: aliceSession.recoveryKey,
      recoveryMaterialEvidence: aliceSession.recoveryMaterialEvidence,
      onRecoveryKeyConfigured: (key) => {
        aliceSession.recoveryKey = key;
      },
    }),
    openUserPage(browser, bob, {
      grantJwt: bobSession.grantJwt,
      dpopSeedB64url: bobSession.dpopSeedB64url,
      eventSigningSeedB64url: bobSession.eventSigningSeedB64url,
      grantId: bobSession.grantId,
      accountId: bobSession.accountId,
      principalControlRealmId: bobSession.principalControlRealmId,
      grantAudience: bobSession.grantAudience,
      recoveryKey: bobSession.recoveryKey,
      recoveryMaterialEvidence: bobSession.recoveryMaterialEvidence,
      onRecoveryKeyConfigured: (key) => {
        bobSession.recoveryKey = key;
      },
    }),
  ]);
  await Promise.all([alicePage.gotoHome(), bobPage.gotoHome()]);


  return {
    alice,
    bob,
    aliceToken: aliceSession.grantJwt,
    bobToken: bobSession.grantJwt,
    aliceSession,
    bobSession,
    alicePage,
    bobPage,
  };
}
