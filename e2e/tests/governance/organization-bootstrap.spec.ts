// Organization principal bootstrap / delegation
// Contract: e2e/scenarios/governance/organization-bootstrap.md
// Spec: identity/identity-did.md §6, governance/content-moderation.md §7,
//       event-payload.schema.json#/$defs/realm_organization_payload
//
// COT-ORG-05 — "who controls the organization principal when there is no shared
// account?" An organization is a DID principal, not a human's account. Issuing a
// ck.realm.organization statement requires the organization DID controller, or
// an explicit delegation (governance_service / account_authority); a logged-in
// human admin does NOT become the organization principal.
//
// These are `test.fixme` until the coauth organization surface
// (COA-ORG-02/03/04) and soland delegation acceptance (SOL-ORG-03) land. The
// issuer-role / delegation coupling invariants themselves are already enforced
// statically by tests/realm_organization_statement_negative.rs against the
// arkret-rust-sdk verifier.

import { expect, test } from "@playwright/test";
import { coauthBaseUrl, solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  signedEventEnvelope,
  uuidV7,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("organization principal bootstrap / delegation", () => {
  test.fixme(
    // @blocking-on: COA-ORG-03 — coauth must refuse to issue a
    //   ck.realm.organization authorization for an actor that holds no
    //   organization delegation. There is no coauth organization-authorization
    //   endpoint yet, so the "human admin cannot self-issue" gate cannot be
    //   exercised live.
    // @user-promise: e2e/scenarios/governance/organization-bootstrap.md (Case A)
    "Case A: human admin without delegation cannot issue an organization statement",
    async ({ request }) => {
      const coauthBase = coauthBaseUrl();
      expect(coauthBase, "coauth deployment required").toBeTruthy();

      const human = uniqueUser("s30-orgboot-human");
      await ensureRegistered(request, human);
      const token = await issueDevSession(request, human);
      const orgDid = `did:web:acme-boot-${Date.now()}.example`;

      // Attempt to mint an organization authorization with no delegation.
      const attempt = await request.post(
        `${coauthBase}/_coauth/self/organizations/${encodeURIComponent(orgDid)}/authorization`,
        {
          headers: authHeaders(token),
          data: {
            relationship: "owner",
            control_scopes: ["official_badge"],
          },
        },
      );
      // The human is not the organization principal: coauth must refuse.
      expect(attempt.status()).toBeGreaterThanOrEqual(400);
      expect(attempt.status()).toBeLessThan(500);
    },
  );

  test.fixme(
    // @blocking-on: COA-ORG-02/03 + SOL-ORG-03 — coauth issues a delegation
    //   whose purpose covers ck.realm.organization, then signs the statement as
    //   governance_service/account_authority (or the DID controller signs
    //   directly), and soland accepts it after resolving the live delegation.
    // @user-promise: e2e/scenarios/governance/organization-bootstrap.md (Case B)
    "Case B: DID controller / governance service / account authority delegation issues successfully",
    async ({ request }) => {
      const coauthBase = coauthBaseUrl();
      expect(coauthBase, "coauth deployment required").toBeTruthy();

      const admin = uniqueUser("s30-orgboot-admin");
      await ensureRegistered(request, admin);
      const token = await issueDevSession(request, admin);
      const orgDid = `did:web:acme-boot-${Date.now()}.example`;

      // coauth issues an organization delegation covering ck.realm.organization.
      const delegation = await request.post(
        `${coauthBase}/_coauth/self/organizations/${encodeURIComponent(orgDid)}/delegations`,
        {
          headers: authHeaders(token),
          data: {
            purpose: "ak.realm.organization",
            covered_relationships: ["owner"],
            covered_control_scopes: ["official_badge", "realm_admin"],
          },
        },
      );
      expect(delegation.ok()).toBeTruthy();
      const delegationRef = (await delegation.json()).delegation_ref as string;
      expect(delegationRef).toBeTruthy();

      const realmId = await createRealmApi(request, token, {
        title: `S30 org boot ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      // Statement signed under the delegation (governance_service issuer).
      const submit = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(token),
        data: signedEventEnvelope({
          actorDid: admin.did,
          realmId,
          kind: "ak.realm.organization",
          schemaId: "ak.schema.event_payload.v1",
          payload: {
            statement_id: `org-stmt-${uuidV7()}`,
            realm_id: realmId,
            organization_id: orgDid,
            relationship: "owner",
            status: "active",
            control_scopes: ["official_badge", "realm_admin"],
            issued_at: canonicalTimestamp(),
            authorization: {
              issuer: orgDid,
              issuer_role: "governance_service",
              verification_method: `${orgDid}#k1`,
              delegation_ref: delegationRef,
              signed_at: canonicalTimestamp(),
              proof: "c2ln",
            },
          },
        }),
      });
      expect(submit.ok()).toBeTruthy();
    },
  );

  test.fixme(
    // @blocking-on: COA-ORG-03 + SOL-ORG-03 — an expired / revoked delegation
    //   must neither continue to sign nor be accepted by soland; the verifier
    //   maps it to grant_revoked_upstream (see realm_organization_statement
    //   _negative.rs: delegated_role_not_live_delegation).
    // @user-promise: e2e/scenarios/governance/organization-bootstrap.md (Case C)
    "Case C: expired / revoked delegation cannot issue nor be accepted",
    async ({ request }) => {
      const coauthBase = coauthBaseUrl();
      expect(coauthBase, "coauth deployment required").toBeTruthy();

      const admin = uniqueUser("s30-orgboot-revoked");
      await ensureRegistered(request, admin);
      const token = await issueDevSession(request, admin);
      const orgDid = `did:web:acme-boot-${Date.now()}.example`;

      const delegation = await request.post(
        `${coauthBase}/_coauth/self/organizations/${encodeURIComponent(orgDid)}/delegations`,
        {
          headers: authHeaders(token),
          data: {
            purpose: "ak.realm.organization",
            covered_relationships: ["owner"],
            covered_control_scopes: ["official_badge"],
          },
        },
      );
      expect(delegation.ok()).toBeTruthy();
      const delegationRef = (await delegation.json()).delegation_ref as string;

      const revoke = await request.delete(
        `${coauthBase}/_coauth/self/organizations/${encodeURIComponent(orgDid)}/delegations/${encodeURIComponent(delegationRef)}`,
        { headers: authHeaders(token) },
      );
      expect(revoke.ok()).toBeTruthy();

      const realmId = await createRealmApi(request, token, {
        title: `S30 org boot revoked ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      // soland must reject a statement that still references the revoked
      // delegation — fail closed.
      const submit = await request.post(`${solandBaseUrl()}/_arkret/self/events`, {
        headers: authHeaders(token),
        data: signedEventEnvelope({
          actorDid: admin.did,
          realmId,
          kind: "ak.realm.organization",
          schemaId: "ak.schema.event_payload.v1",
          payload: {
            statement_id: `org-stmt-${uuidV7()}`,
            realm_id: realmId,
            organization_id: orgDid,
            relationship: "owner",
            status: "active",
            control_scopes: ["official_badge"],
            issued_at: canonicalTimestamp(),
            authorization: {
              issuer: orgDid,
              issuer_role: "governance_service",
              verification_method: `${orgDid}#k1`,
              delegation_ref: delegationRef,
              signed_at: canonicalTimestamp(),
              proof: "c2ln",
            },
          },
        }),
      });
      expect(submit.status()).toBe(403);
      expect(JSON.stringify(await submit.json())).toContain("grant_revoked_upstream");
    },
  );
});
