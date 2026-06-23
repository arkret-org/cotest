// Core object invariants — common fields, patch precondition CAS, lifecycle
// cascade, relation cardinality, view projection fallback.
//
// Contract: e2e/scenarios/models/core-object-invariants.md
// Spec refs:
//   - models/common-fields.md §3 (Common Object Fields), §5 / §5.1 (lifecycle
//     state machine + canonical reason codes)
//   - models/event-and-patch.md §2.2 (Event Envelope required fields),
//     §4.2.4 / §4.2.5 (redactable / reducer-managed field protection)
//   - models/realm-and-space.md §2.5 / §2.5.1 (Realm tombstone / destroy
//     cascade), §3.4 (Space lifecycle, space_has_live_dependents)
//   - models/relation.md §3.2 (cardinality table, dedup rule), §4.4
//     (cross-Realm structural constraint)
//   - models/views.md §2.2 (kind is response family), §6 / §6.3 (Board
//     projection derived from query → contains → strand)
//
// Phase A is live (Space create + read-back of 4 spec-equivalent common
// fields). Phases B–E are test.fixme — they sketch the API call and
// assertion so a future live-ification PR only needs to remove the fixme
// once the soland endpoints land.

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { stepShot } from "../../helpers/screenshots";
import {
  ensureRegistered,
  issueDevSession,
  openUserPage,
  uniqueUser,
} from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("core object invariants", () => {
  test(
    "Phase A — newly created Realm exposes spec §3 common fields (id, created_at, actor, lifecycle_state equivalents) on the read-back wire",
    async ({ browser, request }, testInfo) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const alicePage = await openUserPage(browser, alice, { sessionCredential: aliceToken });
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      try {
        // ── Step 1-2: alice creates Realm R via the standard setup wizard
        // (same path messaging/triad-collaboration uses).
        const realmId = await alicePage.createRealm({
          title: `models/core-object-invariants Realm ${stamp}`,
          summary: "core object invariants coverage",
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "joined",
        });
        expect(realmId).toMatch(/^ck:realm:/);
        await stepShot(alicePage.page, testInfo, "A-alice-realm-created");

        // ── Step 3: read back the Realm via the soland API and verify the
        // spec §3 common-field equivalents on the RealmLifecycleResponse
        // serializer. Current wire shape (soland/src/wire.rs
        // RealmLifecycleResponse): { ok, realm_id, owner, members, deleted }.
        //   - realm_id  ↔ spec `id`              (typed ck:realm: prefix)
        //   - owner     ↔ spec `created_by`      (DID, actor reference)
        //   - members   ↔ membership invariant   (must contain owner)
        //   - deleted   ↔ spec `lifecycle_state` (false ⇒ active)
        const realmRes = await request.get(
          `${solandBaseUrl()}/_cokret/self/realms/${encodeURIComponent(realmId)}`,
          { headers: aliceAuth },
        );
        expect(realmRes.status()).toBe(200);
        const realmBody = (await realmRes.json()) as {
          ok?: boolean;
          realm_id?: string;
          owner?: string;
          members?: string[];
          deleted?: boolean;
        };
        // Common-field 1: `id` (typed ck:realm: prefix).
        expect(realmBody.realm_id).toBe(realmId);
        expect(realmBody.realm_id).toMatch(/^ck:realm:/);
        // Common-field 2: actor reference (`created_by` equivalent → `owner`).
        expect(realmBody.owner).toBe(alice.did);
        // Membership invariant: owner must always appear in members.
        expect(Array.isArray(realmBody.members)).toBe(true);
        expect(realmBody.members ?? []).toContain(alice.did);
        // Common-field 3: `lifecycle_state` equivalent (deleted=false ⇒ active).
        expect(realmBody.deleted).toBe(false);

        // ── Step 4: read the event log for this Realm to recover the
        // `created_at` + `event_id` + `actor_id` + `kind` fields that
        // RealmLifecycleResponse does not currently surface. The events
        // query response item shape follows the Event Envelope projection:
        // { event_id, realm_id, kind, actor_id, payload, created_at, ... }.
        const eventsRes = await request.get(
          `${solandBaseUrl()}/_cokret/self/events?realms=${encodeURIComponent(realmId)}&limit=20`,
          { headers: aliceAuth },
        );
        expect(eventsRes.status()).toBe(200);
        const eventsBody = (await eventsRes.json()) as {
          events?: Array<{
            event_id?: string;
            kind?: string;
            actor_id?: string;
            created_at?: string;
            realm_id?: string;
          }>;
        };
        const events = eventsBody.events ?? [];
        expect(events.length).toBeGreaterThan(0);

        // Find the Realm lifecycle / create event — soland writes lifecycle
        // ops via record_space_lifecycle_operation, so the kind is in the
        // ck.realm.* family. We accept any ck.realm.* kind to stay
        // resilient to soland's exact lifecycle op naming.
        const lifecycleEvent =
          events.find((event) => event.kind?.startsWith("ck.realm.")) ?? events[0];
        expect(lifecycleEvent).toBeTruthy();
        // Common-field (Event Envelope §2.2): event_id.
        expect(lifecycleEvent.event_id).toMatch(/^ck:event:/);
        // Common-field (§2.2 / §3): created_at (RFC 3339, MUST end with Z).
        expect(lifecycleEvent.created_at).toMatch(
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/,
        );
        // Common-field (§2.2): actor_id.
        expect(lifecycleEvent.actor_id).toBe(alice.did);
        // Common-field: kind (§2.2 — Event Envelope `kind`).
        expect(typeof lifecycleEvent.kind).toBe("string");
        expect(lifecycleEvent.kind?.length ?? 0).toBeGreaterThan(0);
        // Realm scoping: event must reference the Realm we just created.
        expect(lifecycleEvent.realm_id).toBe(realmId);

        await stepShot(alicePage.page, testInfo, "A-alice-common-fields-verified");
      } finally {
        await alicePage.close();
      }
    },
  );

  // ── Phase B — Patch precondition CAS fail.
  // soland gap: there is no unified Move/patch endpoint exposing
  // preconditions[].head_eq on the wire today; ck.strand.update precondition
  // checks exist in the reducer but no HTTP path drives them with a stale
  // expected_revision. Live this once soland adds:
  //   POST /_cokret/self/events  with { kind: "ck.strand.update", preconditions: [...],
  //                                effects: [...], payload: { target_ref, patch } }
  // and returns { error_code: "failed_precondition", reason: "..." } on
  // head_eq mismatch (spec models/event-and-patch.md §4.2.4 / §4.2.5).
  test.fixme(
    // @blocking-on: soland#models-core-object-invariants-gap
    // @user-promise: e2e/scenarios/models/core-object-invariants.md
    // @expected-live-by: 2026Q3
    "Phase B — stale precondition head_eq is rejected with failed_precondition and effects[] are NOT applied",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-b-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      // 1. Create a Strand with fields.status = "open".
      const strandRes = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.strand.create",
          payload: {
            object: {
              kind: "ck.schema.strand.v1",
              title: `core-invariants strand ${stamp}`,
              fields: { status: "open" },
            },
          },
        },
      });
      expect(strandRes.status()).toBe(201);
      const strandId = (await strandRes.json()).strand_id as string;
      expect(strandId).toMatch(/^ck:strand:/);

      // 2. Submit an update with a STALE precondition (claims status == "closed"
      //    when it's actually "open"). Expect 4xx + failed_precondition.
      const staleMove = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.strand.update",
          preconditions: [
            {
              cell: `ck:cell:ck.component.strand.fields.v1:${strandId}`,
              predicate: { op: "head_eq", value: { "fields.status": "closed" } },
            },
          ],
          effects: [
            {
              cell: `ck:cell:ck.component.strand.fields.v1:${strandId}`,
              op: { kind: "set", value: { "fields.status": "done" } },
            },
          ],
          payload: { target_ref: strandId, patch: { "fields.status": "done" } },
        },
      });
      expect(staleMove.status()).toBeGreaterThanOrEqual(400);
      const staleBody = await staleMove.json();
      expect(staleBody.error_code).toBe("failed_precondition");

      // 3. Verify the cell head is UNCHANGED — failed precondition MUST NOT
      //    apply any effect (spec §2.2: preconditions + effects are atomic).
      const readBack = await request.get(
        `${solandBaseUrl()}/_cokret/self/strands/${encodeURIComponent(strandId)}`,
        { headers: aliceAuth },
      );
      const strandBody = await readBack.json();
      expect(strandBody.fields?.status).toBe("open");
    },
  );

  // ── Phase C — Cascade / archive / delete.
  // soland gap: soland has archive/delete paths on Space but the
  // child-cascade error code (`space_has_live_dependents`) and the
  // post-tombstone write-rejection (`realm_terminal_state` /
  // `space_already_terminal`) are not stably exposed on the wire. Once they
  // are, drop the fixme.
  test.fixme(
    // @blocking-on: soland#models-core-object-invariants-gap
    // @user-promise: e2e/scenarios/models/core-object-invariants.md
    // @expected-live-by: 2026Q3
    "Phase C — ck.space.archive does NOT cascade; tombstone with live dependents fails; post-tombstone writes are rejected",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-c-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      // Create parent space + a child Strand as a live dependent.
      const parentRes = await request.post(`${solandBaseUrl()}/_soland/self/spaces`, {
        headers: aliceAuth,
        data: { title: `core-invariants parent ${stamp}` },
      });
      const parentSpaceId = (await parentRes.json()).space_id as string;

      const childStrandRes = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.strand.create",
          space_id: parentSpaceId,
          payload: { object: { title: `child ${stamp}` } },
        },
      });
      expect(childStrandRes.status()).toBe(201);

      // Step 11 — archive parent; verify child is still active.
      const archiveRes = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: { kind: "ck.space.archive", payload: { space_id: parentSpaceId } },
      });
      expect(archiveRes.status()).toBe(200);

      // Step 12 — tombstone with live child must fail (space §3.4).
      const tombFail = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: { kind: "ck.space.tombstone", payload: { space_id: parentSpaceId } },
      });
      expect(tombFail.status()).toBeGreaterThanOrEqual(400);
      const tombFailBody = await tombFail.json();
      expect(tombFailBody.error_code).toBe("failed_precondition");
      expect(tombFailBody.reason).toBe("space_has_live_dependents");

      // Step 13–14 — remove child, then tombstone OK; further writes blocked.
      // (Sketch only; exact endpoint TBD.)
    },
  );

  // ── Phase D — Relation cardinality.
  // soland gap: ck.relation.create reducer + cardinality enforcement on
  // has_default_view (many_to_one), idempotent dedup on
  // (realm_id, relation_kind, from_ref, to_ref), and cross-Realm contains
  // refusal are not stably wired today.
  test.fixme(
    // @blocking-on: soland#models-core-object-invariants-gap
    // @user-promise: e2e/scenarios/models/core-object-invariants.md
    // @expected-live-by: 2026Q3
    "Phase D — has_default_view enforces many_to_one; duplicate Relation create is idempotent; cross-Realm contains rejected",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-d-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      const spaceRes = await request.post(`${solandBaseUrl()}/_soland/self/spaces`, {
        headers: aliceAuth,
        data: { title: `core-invariants D ${stamp}` },
      });
      const spaceId = (await spaceRes.json()).space_id as string;

      // Two Views in the same space.
      const mkView = async (label: string) => {
        const res = await request.post(`${solandBaseUrl()}/_cokret/self/views`, {
          headers: aliceAuth,
          data: {
            kind: "collection",
            renderer: "board",
            title: `${label} ${stamp}`,
            source_space_id: spaceId,
          },
        });
        return (await res.json()).view_id as string;
      };
      const v1 = await mkView("V1");
      const v2 = await mkView("V2");

      // Step 16 — first has_default_view edge succeeds.
      const e1 = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.relation.create",
          payload: {
            relation_kind: "has_default_view",
            from_ref: spaceId,
            to_ref: v1,
          },
        },
      });
      expect(e1.status()).toBe(201);

      // Step 17 — second has_default_view edge MUST NOT coexist as active.
      // Acceptable outcomes:
      //  (a) 200/201 + v1 edge auto-tombstoned (reducer closes old winner)
      //  (b) 4xx + relation_cardinality_violation (early reducer fail-closed)
      const e2 = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.relation.create",
          payload: {
            relation_kind: "has_default_view",
            from_ref: spaceId,
            to_ref: v2,
          },
        },
      });
      const activeEdges = await request.get(
        `${solandBaseUrl()}/_cokret/self/relations?from_ref=${encodeURIComponent(spaceId)}&relation_kind=has_default_view&state=active`,
        { headers: aliceAuth },
      );
      const edgesBody = await activeEdges.json();
      expect((edgesBody.items ?? []).length).toBeLessThanOrEqual(1);
      if (e2.status() >= 400) {
        expect((await e2.json()).reason).toBe("relation_cardinality_violation");
      }

      // Step 18 — completely duplicate edge create is idempotent.
      const dup = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.relation.create",
          payload: {
            relation_kind: "has_default_view",
            from_ref: spaceId,
            to_ref: v2,
          },
        },
      });
      expect([200, 201, 409]).toContain(dup.status());

      // Step 19 — cross-Realm contains MUST fail (spec §4.4).
      const otherSpace = (
        await (
          await request.post(`${solandBaseUrl()}/_soland/self/spaces`, {
            headers: aliceAuth,
            data: { title: `other-realm ${stamp}` },
          })
        ).json()
      ).space_id as string;
      const otherStrand = (
        await (
          await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
            headers: aliceAuth,
            data: { kind: "ck.strand.create", space_id: otherSpace, payload: { object: {} } },
          })
        ).json()
      ).strand_id as string;
      const crossRealm = await request.post(`${solandBaseUrl()}/_cokret/self/events`, {
        headers: aliceAuth,
        data: {
          kind: "ck.relation.create",
          space_id: spaceId,
          payload: {
            relation_kind: "contains",
            from_ref: spaceId,
            to_ref: otherStrand,
          },
        },
      });
      expect(crossRealm.status()).toBeGreaterThanOrEqual(400);
      expect((await crossRealm.json()).reason).toBe("cross_space_structural_relation");
    },
  );

  // ── Phase E — View projection fallback.
  // soland gap: /_soland/self/spaces/{id}/views/projection endpoint for the
  // derived board response family does not exist. Once soland exposes it
  // (returning a CollectionProjectionResponse even when no user-defined
  // View has been registered), drop the fixme.
  test.fixme(
    // @blocking-on: soland#models-core-object-invariants-gap
    // @user-promise: e2e/scenarios/models/core-object-invariants.md
    // @expected-live-by: 2026Q3
    "Phase E — Board projection on a fresh Space with no registered View returns the derived default (NOT 404); unknown renderer fails closed",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-e-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      const spaceRes = await request.post(`${solandBaseUrl()}/_soland/self/spaces`, {
        headers: aliceAuth,
        data: { title: `core-invariants E ${stamp}` },
      });
      const spaceId = (await spaceRes.json()).space_id as string;

      // Step 20-21 — request a board projection on a Space that has never
      // had ck.view.create called on it. Spec views.md §6: response MUST be
      // derived (kind=collection, renderer=board) from query → contains →
      // strand, not 404.
      const proj = await request.get(
        `${solandBaseUrl()}/_soland/self/spaces/${encodeURIComponent(spaceId)}/views/projection?renderer=board`,
        { headers: aliceAuth },
      );
      expect(proj.status()).toBe(200);
      const projBody = await proj.json();
      expect(projBody.kind).toBe("collection");
      expect(projBody.renderer).toBe("board");
      expect(projBody.view_id).toMatch(/^ck:view:/);
      expect(Array.isArray(projBody.frontier)).toBe(true);
      expect(Array.isArray(projBody.groups)).toBe(true);

      // Step 22 — unknown renderer MUST fail-closed (spec §2.2 — only the
      // 5 canonical View.kind / known renderers are valid response families).
      const bogus = await request.get(
        `${solandBaseUrl()}/_soland/self/spaces/${encodeURIComponent(spaceId)}/views/projection?renderer=bogus_renderer_${stamp}`,
        { headers: aliceAuth },
      );
      expect(bogus.status()).toBeGreaterThanOrEqual(400);
      const bogusBody = await bogus.json();
      expect(bogusBody.error_code).toMatch(/unknown_renderer|unsupported_renderer/);
    },
  );
});
