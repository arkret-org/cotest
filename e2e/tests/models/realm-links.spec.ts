// Realm links (governed_by / inherits_policy_from / link reject / cycle / narrow-only / cap non-propagation)
// Contract: e2e/scenarios/models/realm-links.md
// Spec: models/realm-links.md §2 (design principles), §3 (standard link kinds),
//       §4 (status: active/rejected/tombstoned), §5 (no implicit cascade),
//       §6 (explicit inheritance, narrow-only, local deny overrides, max_depth=1)

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import { authHeaders, createRealmApi, wireErrCode } from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("realm links", () => {
  test.fixme(
    // @blocking-on: soland#models-realm-links-gap
    // @user-promise: e2e/scenarios/models/realm-links.md
    // @expected-live-by: 2026Q3
    "alice declares governed_by link from team realm to governance realm; bob's violations get filtered via inherited policy; link rejection restores independence",
    async ({ browser, request }, testInfo) => {
      // soland gap: realm-link projection logic + inherited policy merge 未实现
      //   - ck.realm.link Move endpoint
      //   - ck.realm.inheritance_policy opt-in
      //   - /_cokret/self/realms/:id/policy/effective (link-aware merge)
      //   - moderation decision source attribution (derived_via_link)
      // yougen gap: realm-link-list / realm-overview-panel / policy-hold-marker testids
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-alice-${stamp}`);
      const bob = uniqueUser(`s-rl-bob-${stamp}`);
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const bobPage = await openUserPage(browser, bob, { sessionToken: bobToken });
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };
      const bobAuth = { authorization: `Bearer ${bobToken}` };
      const bannedKeyword = `forbidden-word-${stamp}`;

      try {
        // Phase A — alice creates governance Realm G + moderation policy with inheritable=true.
        // (Direct soland API; yougen has no governance-realm wizard yet.)
        const govRes = await request.post(`${solandBaseUrl()}/_cokret/self/realms`, {
          headers: aliceAuth,
          data: {
            title: `models/realm-links Gov Realm ${stamp}`,
            realm_kind: "governance",
          },
        });
        expect(govRes.status()).toBe(201);
        const govBody = await govRes.json();
        const govRealmId: string = govBody.realm_id;
        expect(govRealmId).toMatch(/^ck:realm:/);

        await request.post(`${solandBaseUrl()}/_cokret/self/realms/${govRealmId}/events`, {
          headers: aliceAuth,
          data: {
            kind: "ck.policy.moderation",
            payload: { banned_keywords: [bannedKeyword], inheritable: true },
          },
        });
        await request.post(`${solandBaseUrl()}/_cokret/self/realms/${govRealmId}/events`, {
          headers: aliceAuth,
          data: {
            kind: "ck.realm.inheritance_policy",
            payload: {
              allow_downstream_link_kinds: ["governed_by"],
              allow_rule_ids: ["moderation.banned_keywords"],
            },
          },
        });

        // Phase B — alice creates team Realm T, then signs ck.realm.link governed_by → G,
        // and explicitly opts into inheritance on T's side.
        const teamRes = await request.post(`${solandBaseUrl()}/_cokret/self/realms`, {
          headers: aliceAuth,
          data: {
            title: `models/realm-links Team Realm ${stamp}`,
            seed_members: [bob.did],
          },
        });
        expect(teamRes.status()).toBe(201);
        const teamRealmId: string = (await teamRes.json()).realm_id;

        const linkRes = await request.post(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/events`,
          {
            headers: aliceAuth,
            data: {
              kind: "ck.realm.link",
              payload: {
                target_realm_id: govRealmId,
                link_kind: "governed_by",
                status: "active",
                label: `Gov realm ${stamp}`,
              },
            },
          },
        );
        expect(linkRes.status()).toBe(201);

        await request.post(`${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/events`, {
          headers: aliceAuth,
          data: {
            kind: "ck.realm.inheritance_policy",
            payload: {
              from_realm_id: govRealmId,
              inherit_rule_ids: ["moderation.banned_keywords"],
            },
          },
        });

        // Phase C — T's effective policy now includes G's banned_keywords via derivation.
        const eff1 = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/policy/effective`,
          { headers: aliceAuth },
        );
        expect(eff1.status()).toBe(200);
        const eff1Body = await eff1.json();
        expect(eff1Body.moderation.banned_keywords).toContain(bannedKeyword);
        const derivedRule = eff1Body.derived_rules?.find(
          (r: { source_realm_id?: string }) => r.source_realm_id === govRealmId,
        );
        expect(derivedRule).toBeTruthy();

        // T's local (non-inherited) policy does NOT contain the keyword — verifies that
        // inherited is a merge artifact, not a copy.
        const local = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/policy/local`,
          { headers: aliceAuth },
        );
        const localBody = await local.json();
        expect(localBody.moderation?.banned_keywords ?? []).not.toContain(bannedKeyword);

        // Phase D — bob posts a violating message in T's default space.
        // (We rely on the seed-members default-space helper that other scenarios use;
        //  the assertion here is at the API layer to stay independent of yougen testids.)
        const defaultSpaceRes = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/spaces/default`,
          { headers: bobAuth },
        );
        const defaultSpaceId: string = (await defaultSpaceRes.json()).space_id;
        const violatingText = `this contains ${bannedKeyword} test`;
        const sendRes = await request.post(
          `${solandBaseUrl()}/_soland/self/spaces/${defaultSpaceId}/messages`,
          { headers: bobAuth, data: { body: violatingText } },
        );
        // moderation_hold or rejected — both are spec-acceptable for an inherited deny.
        const sendBody = await sendRes.json();
        expect(["moderation_hold", "rejected"]).toContain(sendBody.status);

        // Phase E — moderation decision attributes the rule back to G via the link.
        const decisions = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/moderation/decisions?message_id=${sendBody.message_id}`,
          { headers: aliceAuth },
        );
        const decisionsBody = await decisions.json();
        expect(decisionsBody.items.length).toBeGreaterThanOrEqual(1);
        const decision = decisionsBody.items[0];
        expect(decision.applied_rule.source_realm_id).toBe(govRealmId);
        expect(decision.derived_via_link).toBe("governed_by");

        await stepShot(alicePage.page, testInfo, "alice-effective-policy");
        await stepShot(bobPage.page, testInfo, "bob-moderation-hold");

        // Phase F — alice rejects the link; effective policy reverts; bob can resend.
        const rejectRes = await request.post(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/events`,
          {
            headers: aliceAuth,
            data: {
              kind: "ck.realm.link",
              payload: {
                target_realm_id: govRealmId,
                link_kind: "governed_by",
                status: "rejected",
              },
            },
          },
        );
        expect(rejectRes.status()).toBe(201);

        const eff2 = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${teamRealmId}/policy/effective`,
          { headers: aliceAuth },
        );
        const eff2Body = await eff2.json();
        expect(eff2Body.moderation.banned_keywords ?? []).not.toContain(bannedKeyword);

        const resend = await request.post(
          `${solandBaseUrl()}/_soland/self/spaces/${defaultSpaceId}/messages`,
          { headers: bobAuth, data: { body: violatingText } },
        );
        const resendBody = await resend.json();
        expect(resendBody.status).toBe("persisted");
      } finally {
        await Promise.allSettled([bobPage.close(), alicePage.close()]);
      }
    },
  );

  test(
    "E6.1 cycle detection: link graph A→B→C→A is rejected with link_cycle_detected (spec §5)",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-cycle-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const auth = authHeaders(aliceToken);

      const mk = async (label: string) => {
        return await createRealmApi(request, aliceToken, {
          title: `realm-link-cycle-${label}-${stamp}`,
          public: true,
          discoverability: "public",
          history_visibility: "shared",
        });
      };
      const A = await mk("A");
      const B = await mk("B");
      const C = await mk("C");

      const link = async (src: string, dst: string) =>
        request.post(`${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(src)}/links`, {
          headers: auth,
          data: {
            target_realm_id: dst,
            link_kind: "governed_by",
            status: "active",
          },
        });

      const ab = await link(A, B);
      expect(ab.ok()).toBeTruthy();
      const bc = await link(B, C);
      expect(bc.ok()).toBeTruthy();

      const outboundA = await request.get(
        `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(A)}/links?direction=outbound`,
        { headers: auth },
      );
      expect(outboundA.ok()).toBeTruthy();
      const outboundABody = await outboundA.json();
      expect(outboundABody.links).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ realm_id: A, target_realm_id: B, link_kind: "governed_by", status: "active" }),
        ]),
      );

      // The Move that would close the cycle must be rejected.
      const ca = await link(C, A);
      expect(ca.status()).toBe(422);
      const caBody = await ca.json();
      expect(wireErrCode(caBody)).toBe("realm_link_cycle");
    },
  );

  test.fixme(
    // @blocking-on: soland#models-realm-links-gap
    // @user-promise: e2e/scenarios/models/realm-links.md
    // @expected-live-by: 2026Q3
    "E6.2 multi-target narrowing: T governed_by G1 + G2 takes narrow (intersection) of inherited rules (spec §6.2 narrow-only)",
    async ({ request }) => {
      // soland gap: realm-link projection logic + multi-source narrow-only merge 未实现
      //   When T inherits the same rule from multiple sources, the derived
      //   grant/deny set must not be wider than ANY single source. For deny-
      //   style rules (banned_keywords), the practical interpretation is
      //   intersection. Test only asserts: effective ⊆ each source.
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-multi-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const auth = { authorization: `Bearer ${aliceToken}` };

      const mk = async (label: string, banned: string[]) => {
        const res = await request.post(`${solandBaseUrl()}/_cokret/self/realms`, {
          headers: auth,
          data: { title: `multi-${label}-${stamp}`, realm_kind: "governance" },
        });
        const id = (await res.json()).realm_id as string;
        await request.post(`${solandBaseUrl()}/_cokret/self/realms/${id}/events`, {
          headers: auth,
          data: {
            kind: "ck.policy.moderation",
            payload: { banned_keywords: banned, inheritable: true },
          },
        });
        return id;
      };
      const G1 = await mk("G1", [`w1-${stamp}`, `w2-${stamp}`]);
      const G2 = await mk("G2", [`w2-${stamp}`, `w3-${stamp}`]);

      const teamRes = await request.post(`${solandBaseUrl()}/_cokret/self/realms`, {
        headers: auth,
        data: { title: `multi-T-${stamp}` },
      });
      const T = (await teamRes.json()).realm_id as string;
      for (const G of [G1, G2]) {
        await request.post(`${solandBaseUrl()}/_cokret/self/realms/${T}/events`, {
          headers: auth,
          data: {
            kind: "ck.realm.link",
            payload: { target_realm_id: G, link_kind: "governed_by", status: "active" },
          },
        });
        await request.post(`${solandBaseUrl()}/_cokret/self/realms/${T}/events`, {
          headers: auth,
          data: {
            kind: "ck.realm.inheritance_policy",
            payload: { from_realm_id: G, inherit_rule_ids: ["moderation.banned_keywords"] },
          },
        });
      }

      const eff = await request.get(`${solandBaseUrl()}/_cokret/self/realms/${T}/policy/effective`, {
        headers: auth,
      });
      const effBody = await eff.json();
      const merged: string[] = effBody.moderation.banned_keywords ?? [];
      const g1Set = new Set([`w1-${stamp}`, `w2-${stamp}`]);
      const g2Set = new Set([`w2-${stamp}`, `w3-${stamp}`]);
      // Narrow-only: every word in the merged set must appear in EVERY source.
      for (const w of merged) {
        expect(g1Set.has(w) && g2Set.has(w)).toBe(true);
      }
      // And the obvious intersection element survives.
      expect(merged).toContain(`w2-${stamp}`);
    },
  );

  test.fixme(
    // @blocking-on: soland#models-realm-links-gap
    // @user-promise: e2e/scenarios/models/realm-links.md
    // @expected-live-by: 2026Q3
    "E6.3 capability non-propagation: alice has realm.admin in G; the governed_by link does NOT grant her admin in T (spec §5)",
    async ({ request }) => {
      // soland gap: realm-link projection logic + capability isolation enforcement 未实现
      //   Per spec §5, capability grants MUST NOT cascade via realm link. Even
      //   though alice is admin of G and T --governed_by--> G, alice has no
      //   admin capability in T unless T explicitly declares a derived grant
      //   policy (which this test does NOT set up). Endpoint must reject 403
      //   with reason="capability_not_propagated_via_link".
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-cap-${stamp}`);
      const bob = uniqueUser(`s-rl-cap-bob-${stamp}`);
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };
      const bobAuth = { authorization: `Bearer ${bobToken}` };

      // alice owns G (admin).
      const gRes = await request.post(`${solandBaseUrl()}/_cokret/self/realms`, {
        headers: aliceAuth,
        data: { title: `cap-G-${stamp}`, realm_kind: "governance" },
      });
      const G = (await gRes.json()).realm_id as string;

      // bob owns T (admin); alice is NOT a member of T.
      const tRes = await request.post(`${solandBaseUrl()}/_cokret/self/realms`, {
        headers: bobAuth,
        data: { title: `cap-T-${stamp}` },
      });
      const T = (await tRes.json()).realm_id as string;

      // bob links T --governed_by--> G.
      const linkRes = await request.post(`${solandBaseUrl()}/_cokret/self/realms/${T}/events`, {
        headers: bobAuth,
        data: {
          kind: "ck.realm.link",
          payload: { target_realm_id: G, link_kind: "governed_by", status: "active" },
        },
      });
      expect(linkRes.status()).toBe(201);

      // alice tries to use her G-admin rights against T — must fail.
      const attempt = await request.post(`${solandBaseUrl()}/_cokret/self/realms/${T}/admin/members`, {
        headers: aliceAuth,
        data: { action: "ban", target_did: bob.did },
      });
      expect(attempt.status()).toBe(403);
      const attemptBody = await attempt.json();
      expect(attemptBody.reason).toBe("capability_not_propagated_via_link");
    },
  );
});
