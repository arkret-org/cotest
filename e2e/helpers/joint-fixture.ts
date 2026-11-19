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
  jointAliceUserDataDir: string | undefined;
  prepareJointAlicePage: ((page: Page) => Promise<void>) | undefined;
}>({
  prepareJointAlicePage: [undefined, { option: true }],
  jointBobServer: ["default", { option: true }],
  jointAliceUserDataDir: [undefined, { option: true }],
  jointUsers: async ({ browser, request, jointBobServer, prepareJointAlicePage, jointAliceUserDataDir }, use, testInfo) => {
    testInfo.setTimeout(Math.max(testInfo.timeout, 360_000));
    const users = await createJointTwoUsers(browser, request, jointBobServer, prepareJointAlicePage, jointAliceUserDataDir);
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
  aliceUserDataDir?: string,
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
  const [first, second] = await Promise.allSettled([
    openUserPage(browser, alice, {
      ...canonicalSessionOptions(aliceSession),
      beforeNavigate: beforeAliceNavigate,
      persistentUserDataDir: aliceUserDataDir,
    }),
    openUserPage(browser, bob, {
      ...canonicalSessionOptions(bobSession),
      server: bobServer,
    }),
  ]);
  try {
    if (first.status === "rejected") throw first.reason;
    if (second.status === "rejected") throw second.reason;
    const alicePage = first.value;
    const bobPage = second.value;
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
  } catch (error) {
    await Promise.allSettled([first, second].flatMap(result =>
      result.status === "fulfilled" ? [result.value.close()] : []));
    throw error;
  }
}
