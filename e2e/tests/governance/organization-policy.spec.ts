// Organization directory + moderation policy inheritance
// Contract: e2e/scenarios/governance/organization-policy.md
// Spec: governance/content-moderation.md §7, identity/identity-did.md §6, models/governance-objects.md §3

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  addSpaceMemberApi,
  authHeaders,
  createSpaceApi,
  signedEventEnvelope,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("organization policy inheritance", () => {
  test("organization policy endpoint surface probe", async ({ request }) => {
    const alice = uniqueUser("s30-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const probe = await request.get(`${solandBaseUrl()}/_cokret/self/organizations`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test(
    "acme-org publishes ck.organization.moderation_policy with deny_join targets; spaces under acme inherit the policy automatically",
    async ({ request }) => {
      const { alice, mallory, aliceToken, orgDid } = await setupAcmeOrg(request, "s30-inherit");
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S30 inherited policy ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const policy = await request.get(
        `${solandBaseUrl()}/_cokret/self/organizations/${encodeURIComponent(orgDid)}/policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(policy.ok()).toBeTruthy();
      const policyBody = await policy.json();
      expect(policyBody.policy.targets[0].did).toBe(mallory.did);
      expect(policyBody.applies_to_spaces).toContain(spaceId);

      const effective = await request.get(
        `${solandBaseUrl()}/_cokret/self/spaces/${encodeURIComponent(spaceId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(effective.ok()).toBeTruthy();
      const effectiveText = JSON.stringify(await effective.json());
      expect(effectiveText).toContain(orgDid);
      expect(effectiveText).toContain("deny_join");
      expect(effectiveText).toContain(mallory.did);
    },
  );

  test(
    "mallory's join attempt on an Acme space is rejected with organization_policy_denied; space-level override requires organization approval",
    async ({ request }) => {
      const { alice, mallory, aliceToken, orgDid } = await setupAcmeOrg(request, "s30-deny");
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S30 deny join ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const deniedJoin = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: authHeaders(aliceToken),
        data: signedEventEnvelope({
          actorDid: alice.did,
          realmId: spaceId,
          kind: "ck.member.state",
          payload: {
            actor_id: mallory.did,
            member: mallory.did,
            membership: "join",
            delivery_status: "unroutable",
          },
        }),
      });
      expect(deniedJoin.status()).toBe(403);
      expect(JSON.stringify(await deniedJoin.json())).toContain("organization_policy_denied");

      const noApproval = await request.post(
        `${solandBaseUrl()}/_cokret/self/spaces/${encodeURIComponent(spaceId)}/moderation-policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            allow_override: [{ target: mallory.did, action: "allow_join" }],
          },
        },
      );
      expect(noApproval.status()).toBe(403);
      expect(wireErrCode(await noApproval.json())).toBe("requires_organization_approval");

      const withApproval = await request.post(
        `${solandBaseUrl()}/_cokret/self/spaces/${encodeURIComponent(spaceId)}/moderation-policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            allow_override: [{ target: mallory.did, action: "allow_join" }],
            organization_approval: {
              organization_id: orgDid,
              approved: true,
              decision_id: `ck:org-approval:${Date.now()}`,
            },
          },
        },
      );
      expect(withApproval.ok()).toBeTruthy();

      await addSpaceMemberApi(request, aliceToken, spaceId, mallory.did);
      const space = await request.get(
        `${solandBaseUrl()}/_cokret/self/spaces/${encodeURIComponent(spaceId)}`,
        { headers: authHeaders(aliceToken) },
      );
      expect(space.ok()).toBeTruthy();
      expect((await space.json()).members ?? []).toContain(mallory.did);
    },
  );

  test(
    "policy update at organization level fans out to all member spaces without per-space rewrites",
    async ({ request }) => {
      const { aliceToken, orgDid } = await setupAcmeOrg(request, "s30-fanout");
      const first = await createSpaceApi(request, aliceToken, {
        title: `S30 fanout one ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });
      const second = await createSpaceApi(request, aliceToken, {
        title: `S30 fanout two ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const update = await request.post(
        `${solandBaseUrl()}/_cokret/self/organizations/${encodeURIComponent(orgDid)}/policy`,
        {
          headers: authHeaders(aliceToken),
          data: {
            policy_id: `ck:org-policy:fanout-${Date.now()}`,
            targets: [
              {
                kind: "actor",
                did: "did:web:later-denied.example",
                action: "deny_join",
              },
            ],
          },
        },
      );
      expect(update.ok()).toBeTruthy();

      for (const spaceId of [first, second]) {
        const effective = await request.get(
          `${solandBaseUrl()}/_cokret/self/spaces/${encodeURIComponent(spaceId)}/effective-policy`,
          { headers: authHeaders(aliceToken) },
        );
        expect(effective.ok()).toBeTruthy();
        const body = await effective.json();
        expect(JSON.stringify(body)).toContain("did:web:later-denied.example");
        expect(body.organization_policy_layers?.[0]?.version).toBe(2);
        expect(body.organization_policy_layers?.[0]?.applies_to_spaces).toEqual(
          expect.arrayContaining([first, second]),
        );
        expect(body.fanout?.rewrites_space_policy).toBe(false);
      }
    },
  );

  test(
    "tab-organizations search returns acme-org with member count and verified badge",
    async ({ browser, request }) => {
      // spec: discovery-directory.md §2
      const label = `s30-dir-${Date.now()}`;
      const { alice, aliceToken, orgDid } = await setupAcmeOrg(request, label);
      const spaceId = await createSpaceApi(request, aliceToken, {
        title: `S30 org directory ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const apiSearch = await request.post(`${solandBaseUrl()}/_cokret/find/directory/search-organizations`, {
        headers: authHeaders(aliceToken),
        data: { query: orgDid },
      });
      expect(apiSearch.ok()).toBeTruthy();
      const searchBody = await apiSearch.json();
      const apiRow = searchBody.results?.find(
        (row: { organization_id?: string; organization_did?: string }) =>
          row.organization_id === orgDid || row.organization_did === orgDid,
      );
      expect(apiRow, "search-organizations should return the runtime Acme organization").toBeTruthy();
      expect(apiRow.verified_badge ?? apiRow.verified).toBe(true);
      expect(apiRow.member_count).toBe(2);
      expect(apiRow.spaces).toEqual(expect.arrayContaining([spaceId]));
      expect(apiRow.space_count).toBeGreaterThanOrEqual(1);

      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      try {
        await alicePage.gotoDirectory();
        await alicePage.page.getByTestId("tab-organizations").click();
        await alicePage.page.getByTestId("directory-search-input").fill(orgDid);
        await alicePage.page.getByTestId("directory-search-button").click();

        const row = alicePage.page.getByTestId("org-result").filter({ hasText: `Acme ${label}` }).first();
        await expect(row).toBeVisible({ timeout: 30_000 });
        await expect(row.getByTestId("organization-verified-badge")).toBeVisible();
        await expect(row.getByTestId("organization-member-count")).toContainText("2 member");
        await expect(row.getByTestId("organization-policy-hint")).toContainText("Policy inheritance: active");
        await expect(row.getByTestId("organization-policy-hint")).toContainText("1 realm");
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "E30.1 cross-org space joining most-restrictive of the two organizations' policies",
    async () => {},
  );

  test.fixme(
    // @blocking-on: soland#governance-organization-policy-gap
    // @user-promise: e2e/scenarios/governance/organization-policy.md
    // @expected-live-by: 2026Q3
    "appeal flow: mallory submits appeal via policy.appeal.endpoint; moderator reviews; possible override",
    async () => {},
  );
});

async function setupAcmeOrg(request: APIRequestContext, label: string) {
  const stamp = Date.now();
  const alice = uniqueUser(`${label}-alice`);
  const mallory = uniqueUser(`${label}-mallory`);
  const bob = uniqueUser(`${label}-bob`);
  const orgDid = `did:web:acme-${label}-${stamp}.example`;
  await Promise.all([
    ensureRegistered(request, alice),
    ensureRegistered(request, mallory),
    ensureRegistered(request, bob),
  ]);
  const aliceToken = await issueDevSession(request, alice);

  const org = await request.post(`${solandBaseUrl()}/_cokret/self/organizations`, {
    headers: authHeaders(aliceToken),
    data: {
      organization_did: orgDid,
      display_name: `Acme ${label}`,
      handle: `@acme-${label}`,
      verified: true,
      members: [alice.did, bob.did],
      member_count: 2,
    },
  });
  expect(org.ok()).toBeTruthy();

  const policy = await request.post(
    `${solandBaseUrl()}/_cokret/self/organizations/${encodeURIComponent(orgDid)}/policy`,
    {
      headers: authHeaders(aliceToken),
      data: {
        policy_id: `ck:org-policy:${label}-${stamp}`,
        targets: [{ kind: "actor", did: mallory.did, action: "deny_join" }],
        appeal: { enabled: true, endpoint: "/_cokret/self/moderation/appeals" },
      },
    },
  );
  expect(policy.ok()).toBeTruthy();

  return { alice, mallory, bob, aliceToken, orgDid };
}
