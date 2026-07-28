// Organization governance: verified relationship vs declared owning_organizations
// Contract: e2e/scenarios/governance/organization-policy.md
// Spec: governance/content-moderation.md §7, identity/identity-did.md §6,
//       models/governance-objects.md §3,
//       event-payload.schema.json#/$defs/realm_organization_payload
//
// cotest is the "declared owning organization != verified governance
// relationship" regression gate. Protocol governance semantics derive ONLY from
// an active, verified `ak.realm.organization` relationship statement
// (RealmOrganizationPayload) — never from `realm.create.owning_organizations[]`
// alone, and never from the `_soland/self/organizations` local-deployment
// surface.
//
// The payload + protocol-semantic invariants are already exercised statically
// by tests/realm_organization_statement_negative.rs against the arkret-rust-sdk
// validator + verifier. The cases below are the live soland projection of the
// same semantics; they are `test.fixme` until the soland organization surface
// (SOL-ORG-02/03/05) lands, at which point they become the red-on-regression
// gate the scenario promises.

import { expect, test, type APIRequestContext } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import {
  authHeaders,
  canonicalTimestamp,
  createRealmApi,
  signedEventEnvelope,
  uuidV7,
} from "../../helpers/soland-api";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

type RelationshipKind = "owner" | "governance" | "sponsor" | "directory_certifier";
type ControlScope =
  | "official_badge"
  | "realm_admin"
  | "moderation_policy"
  | "directory_listing";

/**
 * Build a `ak.realm.organization` relationship statement payload
 * (RealmOrganizationPayload). Field order mirrors
 * event-payload.schema.json#/$defs/realm_organization_payload. The
 * organization-side `authorization` proof here is a fixture; soland verifies it
 * against the organization DID control state (SOL-ORG-02/03).
 */
function realmOrganizationStatement(args: {
  realmId: string;
  organizationDid: string;
  relationship: RelationshipKind;
  status: "active" | "revoked";
  controlScopes: ControlScope[];
  statementId?: string;
  notBefore?: string;
  expiresAt?: string;
  revokesStatementId?: string;
}): Record<string, unknown> {
  const statement: Record<string, unknown> = {
    statement_id: args.statementId ?? `org-stmt-${uuidV7()}`,
    realm_id: args.realmId,
    organization_id: args.organizationDid,
    relationship: args.relationship,
    status: args.status,
    control_scopes: args.controlScopes,
    issued_at: canonicalTimestamp(),
  };
  if (args.notBefore) statement.not_before = args.notBefore;
  if (args.expiresAt) statement.expires_at = args.expiresAt;
  if (args.revokesStatementId) statement.revokes_statement_id = args.revokesStatementId;
  statement.authorization = {
    issuer: args.organizationDid,
    issuer_role: "organization_did",
    verification_method: `${args.organizationDid}#k1`,
    signed_at: canonicalTimestamp(),
    proof: "c2ln",
  };
  return statement;
}

/** Submit a `ak.realm.organization` statement into Realm history (writer must
 * hold ak.realm.admin). Returns the raw response for assertion. */
async function submitOrganizationStatement(
  request: APIRequestContext,
  token: string,
  actorDid: string,
  realmId: string,
  payload: Record<string, unknown>,
) {
  return request.post(`${solandBaseUrl()}/_arkret/self/events`, {
    headers: authHeaders(token),
    data: signedEventEnvelope({
      actorDid,
      realmId,
      kind: "ak.realm.organization",
      schemaId: "ak.schema.event_payload.v1",
      payload,
    }),
  });
}

test.describe("organization governance — verified relationship semantics", () => {
  // Non-blocking guard: the local deployment surface, if present, must not be
  // the way callers learn protocol governance semantics. We only assert the
  // probe does not 5xx; the verified-relationship cases below own the semantics.
  test("legacy local organizations surface is not the governance truth source", async ({
    request,
  }) => {
    const alice = uniqueUser("s30-probe");
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);

    const probe = await request.get(`${solandBaseUrl()}/_soland/self/organizations`, {
      headers: authHeaders(token),
    });
    expect([200, 401, 403, 404]).toContain(probe.status());
    expect(probe.status()).toBeLessThan(500);
  });

  test.fixme(
    // @blocking-on: SOL-ORG-05 — effective-policy must derive organization
    //   layers ONLY from active verified ak.realm.organization statements, and
    //   must NOT inherit from realm.create.owning_organizations[] alone. Until
    //   that lands soland still treats owning_organizations[] as the inheritance
    //   chain, which is exactly the behaviour this case is meant to fail on.
    // @user-promise: e2e/scenarios/governance/organization-policy.md (Case A)
    // @expected-live-by: 2026Q3
    "Case A: owning_organizations[] alone does not inherit organization policy or badge",
    async ({ request }) => {
      const alice = uniqueUser("s30-caseA-alice");
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const orgDid = `did:web:acme-caseA-${Date.now()}.example`;

      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 case A ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      // No ak.realm.organization statement is written — only the declaration.
      const effective = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(effective.ok()).toBeTruthy();
      const body = await effective.json();
      const layers = body.effective_policy?.organization_policy_layers ?? [];
      expect(layers, "declared-only realm must not inherit any organization layer").toEqual([]);
      expect(body.effective_policy?.inheritance_mode ?? "none").toBe("none");
      expect(JSON.stringify(body)).not.toContain(orgDid);
    },
  );

  test.fixme(
    // @blocking-on: SOL-ORG-02 (statement reducer + verification) and SOL-ORG-05
    //   (effective-policy derivation + official badge projection). No self-API
    //   yet accepts a ak.realm.organization statement or projects the resulting
    //   organization layer / badge.
    // @user-promise: e2e/scenarios/governance/organization-policy.md (Case B)
    // @expected-live-by: 2026Q3
    "Case B: active verified statement with covering scope inherits policy + badge",
    async ({ request }) => {
      const alice = uniqueUser("s30-caseB-alice");
      const mallory = uniqueUser("s30-caseB-mallory");
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, mallory)]);
      const aliceToken = await issueDevSession(request, alice);
      const orgDid = `did:web:acme-caseB-${Date.now()}.example`;

      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 case B ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      // Active owner statement covering moderation_policy + official_badge.
      const accepted = await submitOrganizationStatement(
        request,
        aliceToken,
        alice.did,
        realmId,
        realmOrganizationStatement({
          realmId,
          organizationDid: orgDid,
          relationship: "owner",
          status: "active",
          controlScopes: ["moderation_policy", "official_badge"],
        }),
      );
      expect(accepted.ok()).toBeTruthy();

      const effective = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      expect(effective.ok()).toBeTruthy();
      const body = await effective.json();
      const layers = body.effective_policy?.organization_policy_layers ?? [];
      expect(
        layers.map((layer: { organization_id?: string }) => layer.organization_id),
      ).toContain(orgDid);
      expect(body.effective_policy?.inheritance_mode).toBe("organization");
      expect(body.effective_policy?.official_badge).toBe(true);

      // Scope-not-covered variant: a statement that only carries realm_admin
      // must NOT inherit moderation policy nor light the badge.
      const narrowRealmId = await createRealmApi(request, aliceToken, {
        title: `S30 case B narrow ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });
      const narrowAccepted = await submitOrganizationStatement(
        request,
        aliceToken,
        alice.did,
        narrowRealmId,
        realmOrganizationStatement({
          realmId: narrowRealmId,
          organizationDid: orgDid,
          relationship: "owner",
          status: "active",
          controlScopes: ["realm_admin"],
        }),
      );
      expect(narrowAccepted.ok()).toBeTruthy();
      const narrow = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(narrowRealmId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      const narrowBody = await narrow.json();
      expect(narrowBody.effective_policy?.official_badge ?? false).toBe(false);
      expect(
        (narrowBody.effective_policy?.organization_effective_rules ?? []).length,
        "realm_admin-only scope must not inherit moderation rules",
      ).toBe(0);
    },
  );

  test.fixme(
    // @blocking-on: SOL-ORG-02/05 — revocation handling. soland must drop the
    //   organization layer + badge as soon as a revoking statement
    //   (revokes_statement_id) is accepted, and must treat expired / not-before
    //   statements identically (not effective).
    // @user-promise: e2e/scenarios/governance/organization-policy.md (Case C)
    // @expected-live-by: 2026Q3
    "Case C: revoke (and expiry) immediately drops inheritance + badge",
    async ({ request }) => {
      const alice = uniqueUser("s30-caseC-alice");
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const orgDid = `did:web:acme-caseC-${Date.now()}.example`;

      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 case C ${Date.now()}`,
        public: true,
        owning_organizations: [orgDid],
      });

      const activeStatementId = `org-stmt-${uuidV7()}`;
      const active = await submitOrganizationStatement(
        request,
        aliceToken,
        alice.did,
        realmId,
        realmOrganizationStatement({
          realmId,
          organizationDid: orgDid,
          relationship: "owner",
          status: "active",
          controlScopes: ["moderation_policy", "official_badge"],
          statementId: activeStatementId,
        }),
      );
      expect(active.ok()).toBeTruthy();

      const revoke = await submitOrganizationStatement(
        request,
        aliceToken,
        alice.did,
        realmId,
        realmOrganizationStatement({
          realmId,
          organizationDid: orgDid,
          relationship: "owner",
          status: "revoked",
          controlScopes: ["moderation_policy", "official_badge"],
          revokesStatementId: activeStatementId,
        }),
      );
      expect(revoke.ok()).toBeTruthy();

      const effective = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      const body = await effective.json();
      const layers = body.effective_policy?.organization_policy_layers ?? [];
      expect(
        layers.map((layer: { organization_id?: string }) => layer.organization_id),
      ).not.toContain(orgDid);
      expect(body.effective_policy?.official_badge ?? false).toBe(false);
      expect(body.effective_policy?.inheritance_mode ?? "none").toBe("none");
    },
  );

  test.fixme(
    // @blocking-on: SOL-ORG-05 — relationship-kind discrimination. soland must
    //   not treat a `sponsor` relationship as an owner / governance source: a
    //   sponsor statement carries no inheritable moderation control and must not
    //   light the official badge.
    // @user-promise: e2e/scenarios/governance/organization-policy.md (Case D)
    // @expected-live-by: 2026Q3
    "Case D: sponsor relationship is not owner/governance — no inheritance",
    async ({ request }) => {
      const alice = uniqueUser("s30-caseD-alice");
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const sponsorDid = `did:web:sponsor-caseD-${Date.now()}.example`;

      const realmId = await createRealmApi(request, aliceToken, {
        title: `S30 case D ${Date.now()}`,
        public: true,
        owning_organizations: [sponsorDid],
      });

      const accepted = await submitOrganizationStatement(
        request,
        aliceToken,
        alice.did,
        realmId,
        realmOrganizationStatement({
          realmId,
          organizationDid: sponsorDid,
          relationship: "sponsor",
          status: "active",
          // Even if a sponsor over-claims moderation_policy, the sponsor
          // relationship must not be honoured as a governance source.
          controlScopes: ["moderation_policy"],
        }),
      );
      expect(accepted.ok()).toBeTruthy();

      const effective = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(realmId)}/effective-policy`,
        { headers: authHeaders(aliceToken) },
      );
      const body = await effective.json();
      const governanceLayers = (body.effective_policy?.organization_policy_layers ?? []).filter(
        (layer: { relationship?: string; organization_id?: string }) =>
          layer.organization_id === sponsorDid &&
          (layer.relationship === "owner" || layer.relationship === "governance"),
      );
      expect(governanceLayers, "sponsor must not become an owner/governance layer").toEqual([]);
      expect(body.effective_policy?.official_badge ?? false).toBe(false);
    },
  );
});
