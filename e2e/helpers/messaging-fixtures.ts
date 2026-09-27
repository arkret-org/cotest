import type { APIRequestContext } from "@playwright/test";
import {
  createSharedRealmViaApi,
  type ApiRealmOpts,
} from "./api";
import {
  ensureRegistered,
  issueUserSession,
  type JointUser,
  uniqueUser,
} from "./users";

export type TwoUserMessagingRealmFixture = {
  alice: JointUser;
  bob: JointUser;
  aliceToken: string;
  bobToken: string;
  realmId: string;
};

export async function createTwoUserMessagingRealm(
  request: APIRequestContext,
  opts: {
    label: string;
    title: string;
    owner?: "alice" | "bob";
    realm?: Omit<ApiRealmOpts, "invitees" | "ownerId" | "title">;
  },
): Promise<TwoUserMessagingRealmFixture> {
  const alice = uniqueUser(`${opts.label}-alice`);
  const bob = uniqueUser(`${opts.label}-bob`);
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, bob),
  ]);
  const [aliceToken, bobToken] = await Promise.all([
    issueUserSession(request, alice),
    issueUserSession(request, bob),
  ]);

  const owner = opts.owner ?? "alice";
  const [ownerUser, ownerToken, memberUser, memberToken]: [
    JointUser,
    string,
    JointUser,
    string,
  ] =
    owner === "alice"
      ? [alice, aliceToken, bob, bobToken]
      : [bob, bobToken, alice, aliceToken];
  const realmId = await createSharedRealmViaApi(
    request,
    ownerUser,
    ownerToken,
    memberUser,
    {
      ...opts.realm,
      title: opts.title,
    },
  );
  return { alice, bob, aliceToken, bobToken, realmId };
}
