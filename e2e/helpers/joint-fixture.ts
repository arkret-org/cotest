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
  aliceToken: string;
  bobToken: string;
  alicePage: JointUserPage;
  bobPage: JointUserPage;
  spaceId: string;
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

  const spaceId = await alicePage.createRealm({
    title: `joint smoke ${stamp}`,
    summary: "cotest joint harness smoke",
    discoverability: "public",
    joinRule: "invite",
    historyVisibility: "joined",
    encryptionProfile: "none",
  });

  return { alice, bob, aliceToken, bobToken, alicePage, bobPage, spaceId };
}
