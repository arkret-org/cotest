// Directory / teabay verified organization badge
// Contract: e2e/scenarios/discovery/organization-verified-badge.md
// Spec: discovery/discovery-directory.md §2, governance/content-moderation.md §7,
//       event-payload.schema.json#/$defs/realm_organization_payload
//
// COT-ORG-04 — the directory / teabay verified-organization badge must derive
// from the SAME active-verified `ak.realm.organization` relationship that drives
// protocol governance (see governance/organization-policy.spec.ts), never from
// create-payload hints or the `_soland/self/organizations` local mirror. These
// are `test.fixme` until SOL-ORG-06 / TBY-ORG-01..03 land
// the verified-relationship-backed badge projection.

import { expect, test, type APIRequestContext } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  projectDidToCoreId,
  signedEventEnvelope,
  uuidV7,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

async function submitOrganizationStatement(
  request: APIRequestContext,
  token: string,
  actorId: string,
  realmId: string,
  organizationDid: string,
  relationship: "owner" | "directory_certifier",
  controlScopes: string[],
  status: "active" | "revoked",
  revokesStatementId?: string,
) {
  const statement: Record<string, unknown> = {
    statement_id: `org-stmt-${uuidV7()}`,
    realm_id: realmId,
    organization_id: projectDidToCoreId(organizationDid),
    relationship,
    status,
    control_scopes: controlScopes,
    issued_at: canonicalTimestamp(),
  };
  if (revokesStatementId) statement.revokes_statement_id = revokesStatementId;
  statement.authorization = {
    issuer_id: projectDidToCoreId(organizationDid),
    issuer_role: "organization",
    verification_method: `${organizationDid}#k1`,
    signed_at: canonicalTimestamp(),
    proof: "c2ln",
  };
  return request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: { event: signedEventEnvelope({
      actorId,
      realmId,
      kind: "ak.realm.organization",
      payload: statement,
    }) },
  });
}

async function searchOrganization(
  request: APIRequestContext,
  token: string,
  query: string,
) {
  const resp = await request.post(
    `${solandBaseUrl()}/_arkret/find/directory/search-organizations`,
    { headers: authHeaders(token), data: { query } },
  );
  expect(resp.ok()).toBeTruthy();
  const body = await resp.json();
  return (body.organizations ?? []) as Array<Record<string, any>>;
}

function rowFor(rows: Array<Record<string, any>>, organizationId: string) {
  const envelope = rows.find(
    (row) =>
      row.organization_id === organizationId ||
      row.preview?.organization_id === organizationId,
  );
  return envelope?.preview ?? envelope;
}

test.describe("directory verified organization badge", () => {
  test.fixme(
    // @blocking-on: SOL-ORG-06 — directory verified_badge must be false for a
    //   Realm with no active verified ak.realm.organization relationship.
    //   Today the directory derives the
    //   badge from the local organizations registry, so declared-only realms can
    //   still show as verified — the regression this case must catch.
    // @user-promise: e2e/scenarios/discovery/organization-verified-badge.md (Case A)
    // @expected-live-by: 2026Q3
    "Case A: Realm without a relationship does not show a verified organization badge",
    async ({ request }) => {
      const alice = uniqueUser("s30-badge-A");
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const orgDid = `did:web:acme-badgeA-${Date.now()}.example`;

      await createRealmApi(request, token, {
        title: `S30 badge A ${Date.now()}`,
        public: true,
      });

      const organizationId = projectDidToCoreId(orgDid);
      const rows = await searchOrganization(request, token, organizationId);
      const row = rowFor(rows, organizationId);
      // Either the org is not surfaced at all, or it is surfaced unverified.
      if (row) {
        expect(row.verified_badge ?? row.verified ?? false).toBe(false);
      }
    },
  );

  test.fixme(
    // @blocking-on: SOL-ORG-06 / TBY-ORG-01..03 — verified_badge projection from
    //   an active verified ak.realm.organization (owner|directory_certifier)
    //   relationship, read identically by inkson + teabay.
    // @user-promise: e2e/scenarios/discovery/organization-verified-badge.md (Case B)
    // @expected-live-by: 2026Q3
    "Case B: active owner / directory_certifier relationship shows the badge",
    async ({ browser, request }) => {
      const label = `s30-badgeB-${Date.now()}`;
      const alice = uniqueUser(`${label}-alice`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const orgDid = `did:web:acme-${label}.example`;

      const realmId = await createRealmApi(request, token, {
        title: `Acme ${label}`,
        public: true,
      });
      const accepted = await submitOrganizationStatement(
        request,
        token,
        alice.id,
        realmId,
        orgDid,
        "directory_certifier",
        ["directory_listing", "official_badge"],
        "active",
      );
      expect(accepted.ok()).toBeTruthy();

      const organizationId = projectDidToCoreId(orgDid);
      const rows = await searchOrganization(request, token, organizationId);
      const row = rowFor(rows, organizationId);
      expect(row, "verified relationship must surface the organization").toBeTruthy();
      expect(row.verified_badge ?? row.verified).toBe(true);

      const alicePage = await openUserPage(browser, alice, { sessionCredential: token });
      try {
        await alicePage.gotoDirectory();
        await alicePage.page.getByTestId("tab-organizations").click();
        await alicePage.page.getByTestId("directory-search-input").fill(orgDid);
        await alicePage.page.getByTestId("directory-search-button").click();
        const uiRow = alicePage.page.getByTestId("org-result").first();
        await expect(uiRow).toBeVisible({ timeout: 30_000 });
        await expect(uiRow.getByTestId("organization-verified-badge")).toBeVisible();
      } finally {
        await alicePage.close();
      }
    },
  );

  test.fixme(
    // @blocking-on: SOL-ORG-06 — badge must clear when the backing relationship
    //   is revoked / expired / stale, matching the effective-policy revocation
    //   behaviour in governance/organization-policy.spec.ts (Case C).
    // @user-promise: e2e/scenarios/discovery/organization-verified-badge.md (Case C)
    // @expected-live-by: 2026Q3
    "Case C: revoked / expired relationship clears the badge",
    async ({ request }) => {
      const label = `s30-badgeC-${Date.now()}`;
      const alice = uniqueUser(`${label}-alice`);
      await ensureRegistered(request, alice);
      const token = await issueDevSession(request, alice);
      const orgDid = `did:web:acme-${label}.example`;

      const realmId = await createRealmApi(request, token, {
        title: `Acme ${label}`,
        public: true,
      });
      const activeStatementId = `org-stmt-${uuidV7()}`;
      const active = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(token),
        data: { event: signedEventEnvelope({
          actorId: alice.id,
          realmId,
          kind: "ak.realm.organization",
          payload: {
            statement_id: activeStatementId,
            realm_id: realmId,
            organization_id: projectDidToCoreId(orgDid),
            relationship: "owner",
            status: "active",
            control_scopes: ["official_badge"],
            issued_at: canonicalTimestamp(),
            authorization: {
              issuer_id: projectDidToCoreId(orgDid),
              issuer_role: "organization",
              verification_method: `${orgDid}#k1`,
              signed_at: canonicalTimestamp(),
              proof: "c2ln",
            },
          },
        }) },
      });
      expect(active.ok()).toBeTruthy();

      const revoke = await submitOrganizationStatement(
        request,
        token,
        alice.id,
        realmId,
        orgDid,
        "owner",
        ["official_badge"],
        "revoked",
        activeStatementId,
      );
      expect(revoke.ok()).toBeTruthy();

      const organizationId = projectDidToCoreId(orgDid);
      const rows = await searchOrganization(request, token, organizationId);
      const row = rowFor(rows, organizationId);
      if (row) {
        expect(row.verified_badge ?? row.verified ?? false).toBe(false);
      }
    },
  );
});
