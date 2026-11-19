import {
  test as base,
  type APIRequestContext,
  type Browser,
  type Page,
} from "./arkret-test";
import type { ColandKey } from "./env";
import {
  canonicalSessionOptions,
  createDpopUserSession,
  type DpopUserSession,
  type JointUser,
  type JointUserPage,
  openUserPage,
} from "./users";

export type JointUsersFixture = {
  alice: JointUser;
  bob: JointUser;
  /// Real opaque SessionGrant presented with DPoP on `/_arkret/self/*`.
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
  jointBobServer: ColandKey;
  prepareJointAlicePage: ((page: Page) => Promise<void>) | undefined;
}>({
  prepareJointAlicePage: [undefined, { option: true }],
  jointBobServer: ["default", { option: true }],
  jointUsers: async ({ browser, request, jointBobServer, prepareJointAlicePage }, use, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 360_000));
    const users = await createJointTwoUsers(browser, request, jointBobServer, prepareJointAlicePage);
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
// and registers the same principal/device at coland before opening inkson.
async function createJointTwoUsers(
  browser: Browser,
  request: APIRequestContext,
  bobServer: ColandKey,
  beforeAliceNavigate?: (page: Page) => Promise<void>,
): Promise<JointUsersFixture> {
  // Principal inception is lease-fenced by the local Coauth/Coland pair.
  // Starting two independent DID inception/handoff chains concurrently can
  // make each wait on the other's global identity-binding lease until the
  // caller timeout. Keep user creation sequential; browser bootstrap below is
  // still parallel once both durable principals exist.
  const aliceSession = await createDpopUserSession(request, "joint-alice", {});
  const bobSession = await createDpopUserSession(request, "joint-bob", { server: bobServer });
  if (!aliceSession || !bobSession) {
    throw new Error("joint fixture requires coauth DPoP session-grant login");
  }
  const alice = aliceSession.user;
  const bob = bobSession.user;
  const [alicePage, bobPage] = await Promise.all([
    openUserPage(browser, alice, {
      ...canonicalSessionOptions(aliceSession),
      beforeNavigate: beforeAliceNavigate,
    }),
    openUserPage(browser, bob, {
      ...canonicalSessionOptions(bobSession),
      server: bobServer,
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
