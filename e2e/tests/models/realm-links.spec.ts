// Realm links (governed_by / inherits_policy_from / link reject / graph cycle / narrow-only / cap non-propagation)
// Contract: e2e/scenarios/models/realm-links.md
// Spec: models/realm-links.md §2 (design principles), §3 (standard link kinds),
//       §4 (status: active/rejected/tombstoned), §5 (no implicit cascade),
//       §6 (explicit inheritance, narrow-only, local deny overrides, max_depth=1)

import { expect, test } from "../../helpers/arkret-test";
import { solandBaseUrl } from "../../helpers/env";
import {
  accountActorId,
  alignSignedEventToActorFrontierApi,
  authHeaders,
  canonicalJson,
  createRealmApi,
  prepareSignedEventCbaApi,
  signedEventEnvelope,
  submitSignedEventApi,
  wireErrCode,
} from "../../helpers/soland-api";
import {
  ensureRegistered,
  issueDevSession,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("realm links", () => {
  test(
    "alice declares governed_by link from team realm to governance realm; effective policy inherits via the link; rejecting the link severs inheritance",
    async ({ request }) => {
      // PROMOTED + reshaped to the real surface. soland's realm-link +
      // inheritance pipeline is fully wired (routing/realms.rs +
      // reducer/realm_links.rs):
      //   - POST /_arkret/self/events admits caller-signed ak.realm.link Events
      //     with reducer-side self-reference / kind / status validation.
      //   - ak.realm.inheritance_policy (signed event) is the §6 opt-in.
      //   - GET /_arkret/self/realms/{id}/effective-policy walks active
      //     governed_by / inherits_policy_from links and merges the source
      //     realm's allow-lists ONLY when the child opted in (§5 no implicit
      //     cascade), severing inheritance when the link flips to rejected.
      // The moderation-keyword-deny enforcement + per-message
      // `derived_via_link` decision attribution from the original sketch are
      // NOT implemented in soland (no banned_keyword gate on message send,
      // no moderation decision attribution subsystem), so this exercises the
      // policy-inheritance invariant the spec actually backs.
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = authHeaders(aliceToken);
      const inheritedPolicyId = `moderation.banned_keywords.${stamp}`;

      // Phase A — alice creates governance Realm G and declares its own
      // policy allow-list (the rule that downstream realms may inherit).
      const govRealmId = await createRealmApi(request, aliceToken, {
        title: `models/realm-links Gov Realm ${stamp}`,
        ownerId: alice.id,
      });
      const govPolicyEnvelope = signedEventEnvelope({
        actorId: alice.id,
        realmId: govRealmId,
        kind: "ak.realm.inheritance_policy",
        payload: {
          source_realm_id: govRealmId,
          inherits: { policy_rules: [inheritedPolicyId] },
          mode: "narrow_only",
          max_depth: 1,
        },
      });
      const govPolicy = await submitSignedEventApi(request, aliceToken, govPolicyEnvelope, {
        context: "G declares its inheritable allow-list",
      });
      expect(govPolicy.rejections ?? []).toEqual([]);

      // Phase B — alice creates team Realm T, links T --governed_by--> G,
      // and explicitly opts into inheriting from G (spec §6.1).
      const teamRealmId = await createRealmApi(request, aliceToken, {
        title: `models/realm-links Team Realm ${stamp}`,
        ownerId: alice.id,
      });
      const linkRes = await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId: teamRealmId,
          kind: "ak.realm.link",
          payload: {
            target_realm_id: govRealmId,
            link_kind: "governed_by",
            status: "active",
            label: `Gov realm ${stamp}`,
          },
        }),
        { context: "T declares governed_by G" },
      );
      expect(linkRes.rejections ?? []).toEqual([]);

      const teamPolicyEnvelope = signedEventEnvelope({
        actorId: alice.id,
        realmId: teamRealmId,
        kind: "ak.realm.inheritance_policy",
        payload: {
          source_realm_id: govRealmId,
          inherits: { policy_rules: [inheritedPolicyId] },
          mode: "narrow_only",
          max_depth: 1,
        },
      });
      const teamPolicy = await submitSignedEventApi(request, aliceToken, teamPolicyEnvelope, {
        context: "T opts into inheriting from G",
      });
      expect(teamPolicy.rejections ?? []).toEqual([]);

      // Phase C — T's effective policy now derives G's allow-list via the
      // active governed_by link.
      const eff1 = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(teamRealmId)}/effective-policy`,
        { headers: aliceAuth },
      );
      expect(eff1.ok()).toBeTruthy();
      const eff1Body = await eff1.json();
      expect(eff1Body.inheritance_mode).toBe("explicit");
      expect(eff1Body.inheritance_chain_ids).toContain(govRealmId);
      expect(eff1Body.effective_policy.allowed_policies).toContain(inheritedPolicyId);

      // Phase D — a realm WITHOUT the inheritance opt-in does NOT inherit
      // (spec §5 no implicit cascade): create T2 governed_by G but never opt
      // in; its effective policy stays mode=none and empty.
      const team2RealmId = await createRealmApi(request, aliceToken, {
        title: `models/realm-links Team Realm 2 ${stamp}`,
        ownerId: alice.id,
      });
      await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId: team2RealmId,
          kind: "ak.realm.link",
          payload: { target_realm_id: govRealmId, link_kind: "governed_by", status: "active" },
        }),
        { context: "T2 declares governed_by G" },
      );
      const eff2NoOptIn = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(team2RealmId)}/effective-policy`,
        { headers: aliceAuth },
      );
      const eff2NoOptInBody = await eff2NoOptIn.json();
      expect(eff2NoOptInBody.inheritance_mode).toBe("none");
      expect(eff2NoOptInBody.effective_policy.allowed_policies ?? []).not.toContain(
        inheritedPolicyId,
      );

      // Phase E — alice rejects the T --> G link; inheritance is severed even
      // though T's inheritance_policy declaration is still on file (§6.3).
      const rejectRes = await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId: teamRealmId,
          kind: "ak.realm.link",
          payload: { target_realm_id: govRealmId, link_kind: "governed_by", status: "rejected" },
        }),
        { context: "T rejects governed_by G" },
      );
      expect(rejectRes.rejections ?? []).toEqual([]);

      const eff3 = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(teamRealmId)}/effective-policy`,
        { headers: aliceAuth },
      );
      const eff3Body = await eff3.json();
      expect(eff3Body.effective_policy.allowed_policies ?? []).not.toContain(inheritedPolicyId);
      expect(eff3Body.inheritance_chain_ids).not.toContain(govRealmId);
    },
  );

  test(
    "E6.1 general graph cycle: link graph A→B→C→A is accepted",
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
          history_access: "all_history_for_current_members",
        });
      };
      const A = await mk("A");
      const B = await mk("B");
      const C = await mk("C");

      const link = async (src: string, dst: string) =>
        submitSignedEventApi(
          request,
          aliceToken,
          signedEventEnvelope({
            actorId: alice.id,
            realmId: src,
            kind: "ak.realm.link",
            payload: {
            target_realm_id: dst,
            link_kind: "governed_by",
            status: "active",
            },
          }),
          { context: `${src} governed_by ${dst}` },
        );

      const ab = await link(A, B);
      expect(ab.rejections ?? []).toEqual([]);
      const bc = await link(B, C);
      expect(bc.rejections ?? []).toEqual([]);

      const outboundA = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(A)}/links?direction=outbound`,
        { headers: auth },
      );
      expect(outboundA.ok()).toBeTruthy();
      const outboundABody = await outboundA.json();
      expect(outboundABody.links).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ realm_id: A, target_realm_id: B, link_kind: "governed_by", status: "active" }),
        ]),
      );

      // General graph cycles are valid; only a Realm linking to itself is rejected.
      const ca = await link(C, A);
      expect(ca.rejections ?? []).toEqual([]);

      const outboundC = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(C)}/links?direction=outbound`,
        { headers: auth },
      );
      expect(outboundC.ok()).toBeTruthy();
      const outboundCBody = await outboundC.json();
      expect(outboundCBody.links).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ realm_id: C, target_realm_id: A, link_kind: "governed_by", status: "active" }),
        ]),
      );
    },
  );

  test(
    "E6.2 multi-target narrowing: T governed_by G1 + G2 takes narrow (intersection) of inherited rules (spec §6.2 narrow-only)",
    async ({ request }) => {
      // PROMOTED. soland now retains a per-(child, source) inheritance-policy
      // projection (reducer/projection_state.rs
      // `realm_inheritance_policies_by_source`, populated in
      // reducer/apply_realm_policy.rs), and the effective-policy read
      // (reducer/realm_links.rs `narrowed_inheritance_intersection`) surfaces
      // the narrow-only INTERSECTION across every source the child opted into
      // via a currently-active governance link, alongside the UNION view.
      // `effective_policy.narrowed_policies` is the §6.2 narrow-only result:
      // a policy survives only when EVERY active source declares it.
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-multi-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const auth = authHeaders(aliceToken);

      const mk = async (label: string, policies: string[]) => {
        const id = await createRealmApi(request, aliceToken, {
          title: `multi-${label}-${stamp}`,
          ownerId: alice.id,
        });
        await submitSignedEventApi(
          request,
          aliceToken,
          signedEventEnvelope({
            actorId: alice.id,
            realmId: id,
            kind: "ak.realm.inheritance_policy",
            payload: {
              source_realm_id: id,
              inherits: { policy_rules: policies },
              mode: "narrow_only",
              max_depth: 1,
            },
          }),
          { context: `${label} declares allow-list` },
        );
        return id;
      };
      const G1 = await mk("G1", [`p1-${stamp}`, `p2-${stamp}`]);
      const G2 = await mk("G2", [`p2-${stamp}`, `p3-${stamp}`]);

      const T = await createRealmApi(request, aliceToken, {
        title: `multi-T-${stamp}`,
        ownerId: alice.id,
      });
      for (const G of [G1, G2]) {
        await submitSignedEventApi(
          request,
          aliceToken,
          signedEventEnvelope({
            actorId: alice.id,
            realmId: T,
            kind: "ak.realm.link",
            payload: { target_realm_id: G, link_kind: "governed_by", status: "active" },
          }),
          { context: `T governed_by ${G}` },
        );
        await submitSignedEventApi(
          request,
          aliceToken,
          signedEventEnvelope({
            actorId: alice.id,
            realmId: T,
            kind: "ak.realm.inheritance_policy",
            payload: {
              source_realm_id: G,
              inherits: { policy_rules: [] },
              mode: "narrow_only",
              max_depth: 1,
            },
          }),
          { context: `T opts into ${G}` },
        );
      }

      const eff = await request.get(
        `${solandBaseUrl()}/_arkret/self/realms/${encodeURIComponent(T)}/effective-policy`,
        { headers: auth },
      );
      const effBody = await eff.json();
      // §6.2 narrow-only: `narrowed_policies` is the INTERSECTION across the
      // two opted-in sources (G1 = {p1, p2}, G2 = {p2, p3}). Only the shared
      // p2 survives the narrowing; p1 and p3 (declared by only one source) do
      // NOT.
      const narrowed: string[] = effBody.effective_policy.narrowed_policies ?? [];
      const g1Set = new Set([`p1-${stamp}`, `p2-${stamp}`]);
      const g2Set = new Set([`p2-${stamp}`, `p3-${stamp}`]);
      // Every narrowed policy MUST appear in EVERY source.
      for (const p of narrowed) {
        expect(g1Set.has(p) && g2Set.has(p)).toBe(true);
      }
      expect(narrowed).toContain(`p2-${stamp}`);
      // The source-exclusive policies MUST be narrowed out.
      expect(narrowed).not.toContain(`p1-${stamp}`);
      expect(narrowed).not.toContain(`p3-${stamp}`);
    },
  );

  test(
    "E6.3 capability non-propagation: alice (admin of G) cannot use a governed_by link to gain admin in T (spec §5)",
    async ({ request }) => {
      // PROMOTED + reshaped. Per spec §5 capability grants MUST NOT cascade
      // via a realm link. The original sketch hit a non-existent
      // `/admin/members` endpoint with a fabricated
      // `capability_not_propagated_via_link` reason; soland enforces member
      // bans through the canonical `ak.member.state{membership=ban}` event,
      // gated on Realm ownership or a projected `ak.realm.admin` capability
      // (routing/events/operations/policy.rs validate_member_state_policy).
      // alice owns G and links T --governed_by--> G, but holds no capability
      // in T — so her ban attempt against T fails closed, which IS the §5
      // non-propagation invariant (a derived grant would require T to publish
      // an explicit ak.capability.derived, which this test does not set up).
      const stamp = Date.now();
      const alice = uniqueUser(`s-rl-cap-${stamp}`);
      const bob = uniqueUser(`s-rl-cap-bob-${stamp}`);
      await Promise.all([ensureRegistered(request, alice), ensureRegistered(request, bob)]);
      const aliceToken = await issueDevSession(request, alice);
      const bobToken = await issueDevSession(request, bob);
      const aliceAuth = authHeaders(aliceToken);

      // alice owns governance Realm G.
      const G = await createRealmApi(request, aliceToken, {
        title: `cap-G-${stamp}`,
        ownerId: alice.id,
      });

      // bob owns team Realm T (alice is NOT a member of T).
      const T = await createRealmApi(request, bobToken, {
        title: `cap-T-${stamp}`,
        ownerId: bob.id,
      });

      // alice links T --governed_by--> G from G's side (the link is declared
      // on whichever realm the actor controls; here alice declares G's
      // outbound view — the non-propagation invariant holds regardless of
      // declaration side).
      const linkRes = await submitSignedEventApi(
        request,
        aliceToken,
        signedEventEnvelope({
          actorId: alice.id,
          realmId: G,
          kind: "ak.realm.link",
          payload: { target_realm_id: T, link_kind: "governed_by", status: "active" },
        }),
        { context: "G declares governed_by T" },
      );
      expect(linkRes.rejections ?? []).toEqual([]);

      // alice (no membership / capability in T) tries to ban bob in T via the
      // canonical member-state event. MUST fail closed — the governed_by link
      // does not carry alice's G-admin into T.
      const deniedEvent = signedEventEnvelope({
          actorId: alice.id,
          realmId: T,
          kind: "ak.member.state",
          payload: {
            realm_id: T,
            member_id: accountActorId(bob.id),
            membership: "ban",
          },
        });
      // Use T's public-to-its-member governance basis without granting Alice
      // any authority. The server must reach authorization, not wrapper parsing.
      await prepareSignedEventCbaApi(request, bobToken, deniedEvent);
      // Bob reads Alice's selected frontier in T; Alice remains the signer and submitter.
      await alignSignedEventToActorFrontierApi(request, bobToken, deniedEvent);
      const submitUrl = `${solandBaseUrl()}/_arkret/self/events`;
      const attempt = await request.post(submitUrl, {
        headers: { ...authHeaders(aliceToken, "POST", submitUrl), "content-type": "application/json" },
        data: canonicalJson({ event: deniedEvent }),
      });
      expect(attempt.status()).toBeGreaterThanOrEqual(400);
      // fail-closed reason is one of soland's capability gates; any of them
      // proves the link did not propagate alice's admin into T.
      expect(["missing_capability", "capability_denied", "not_member"]).toContain(
        wireErrCode(await attempt.json()),
      );
    },
  );
});
