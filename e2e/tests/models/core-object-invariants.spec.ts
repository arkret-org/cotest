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
//     projection derived from query → contains → flow)
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
    "Phase A — newly created Space exposes spec §3 common fields (id, created_at, actor, lifecycle_state equivalents) on the read-back wire",
    async ({ browser, request }, testInfo) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-alice-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const alicePage = await openUserPage(browser, alice, { sessionToken: aliceToken });
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      try {
        // ── Step 1-2: alice creates Space S via the standard setup wizard
        // (same path messaging/triad-collaboration uses).
        const spaceId = await alicePage.createSpace({
          title: `models/core-object-invariants Space ${stamp}`,
          summary: "core object invariants coverage",
          discoverability: "listed",
          joinRule: "invite",
          historyVisibility: "joined",
        });
        expect(spaceId).toMatch(/^cx:space:/);
        await stepShot(alicePage.page, testInfo, "A-alice-space-created");

        // ── Step 3: read back the Space via the soland API and verify the
        // spec §3 common-field equivalents on the SpaceLifecycleResponse
        // serializer. Current wire shape (soland/src/wire.rs
        // SpaceLifecycleResponse): { ok, space_id, owner, members, deleted }.
        //   - space_id  ↔ spec `id`              (typed cx:space: prefix)
        //   - owner     ↔ spec `created_by`      (DID, actor reference)
        //   - members   ↔ membership invariant   (must contain owner)
        //   - deleted   ↔ spec `lifecycle_state` (false ⇒ active)
        const spaceRes = await request.get(
          `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}`,
          { headers: aliceAuth },
        );
        expect(spaceRes.status()).toBe(200);
        const spaceBody = (await spaceRes.json()) as {
          ok?: boolean;
          space_id?: string;
          owner?: string;
          members?: string[];
          deleted?: boolean;
        };
        // Common-field 1: `id` (typed cx:space: prefix).
        expect(spaceBody.space_id).toBe(spaceId);
        expect(spaceBody.space_id).toMatch(/^cx:space:/);
        // Common-field 2: actor reference (`created_by` equivalent → `owner`).
        expect(spaceBody.owner).toBe(alice.did);
        // Membership invariant: owner must always appear in members.
        expect(Array.isArray(spaceBody.members)).toBe(true);
        expect(spaceBody.members ?? []).toContain(alice.did);
        // Common-field 3: `lifecycle_state` equivalent (deleted=false ⇒ active).
        expect(spaceBody.deleted).toBe(false);

        // ── Step 4: read the event log for this Space to recover the
        // `created_at` + `event_id` + `actor_id` + `kind` fields that
        // SpaceLifecycleResponse does not currently surface. The events
        // query response item shape (soland/src/routing/events/projection.rs
        // projection_event_json) is { event_id, space_id, event_kind,
        // sender, payload, created_at, ... }.
        const eventsRes = await request.get(
          `${solandBaseUrl()}/api/v1/events?spaces=${encodeURIComponent(spaceId)}&limit=20`,
          { headers: aliceAuth },
        );
        expect(eventsRes.status()).toBe(200);
        const eventsBody = (await eventsRes.json()) as {
          events?: Array<{
            event_id?: string;
            event_kind?: string;
            sender?: string;
            created_at?: string;
            space_id?: string;
          }>;
        };
        const events = eventsBody.events ?? [];
        expect(events.length).toBeGreaterThan(0);

        // Find the Space lifecycle / create event — soland writes lifecycle
        // ops via record_space_lifecycle_operation, so the kind is in the
        // cx.space.* family. We accept any cx.space.* event_kind to stay
        // resilient to soland's exact lifecycle op naming.
        const lifecycleEvent =
          events.find((event) => event.event_kind?.startsWith("cx.space.")) ?? events[0];
        expect(lifecycleEvent).toBeTruthy();
        // Common-field (Event Envelope §2.2): event_id.
        expect(lifecycleEvent.event_id).toMatch(/^cx:event:/);
        // Common-field (§2.2 / §3): created_at (RFC 3339, MUST end with Z).
        expect(lifecycleEvent.created_at).toMatch(
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/,
        );
        // Common-field (§2.2): actor_id — soland projects this as `sender`.
        expect(lifecycleEvent.sender).toBe(alice.did);
        // Common-field: kind (§2.2 — Event Envelope `kind`).
        expect(typeof lifecycleEvent.event_kind).toBe("string");
        expect(lifecycleEvent.event_kind?.length ?? 0).toBeGreaterThan(0);
        // Space scoping: event must reference the Space we just created.
        expect(lifecycleEvent.space_id).toBe(spaceId);

        await stepShot(alicePage.page, testInfo, "A-alice-common-fields-verified");
      } finally {
        await alicePage.close();
      }
    },
  );

  // ── Phase B — Patch precondition CAS fail.
  // soland gap: there is no unified Move/patch endpoint exposing
  // preconditions[].head_eq on the wire today; cx.flow.update precondition
  // checks exist in the reducer but no HTTP path drives them with a stale
  // expected_revision. Live this once soland adds:
  //   POST /api/v1/events  with { kind: "cx.flow.update", preconditions: [...],
  //                                effects: [...], payload: { flow_id, patch } }
  // and returns { error_code: "failed_precondition", reason: "..." } on
  // head_eq mismatch (spec models/event-and-patch.md §4.2.4 / §4.2.5).
  test.fixme(
    "Phase B — stale precondition head_eq is rejected with failed_precondition and effects[] are NOT applied",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-b-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      // 1. Create a Flow with fields.status = "open".
      const flowRes = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.flow.create",
          payload: {
            object: {
              kind: "cx.schema.flow.v1",
              title: `core-invariants flow ${stamp}`,
              fields: { status: "open" },
            },
          },
        },
      });
      expect(flowRes.status()).toBe(201);
      const flowId = (await flowRes.json()).flow_id as string;
      expect(flowId).toMatch(/^cx:flow:/);

      // 2. Submit an update with a STALE precondition (claims status == "closed"
      //    when it's actually "open"). Expect 4xx + failed_precondition.
      const staleMove = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.flow.update",
          preconditions: [
            {
              cell: `cx:cell:cx.component.flow.fields.v1:${flowId}`,
              predicate: { op: "head_eq", value: { "fields.status": "closed" } },
            },
          ],
          effects: [
            {
              cell: `cx:cell:cx.component.flow.fields.v1:${flowId}`,
              op: { kind: "set", value: { "fields.status": "done" } },
            },
          ],
          payload: { flow_id: flowId, patch: { "fields.status": "done" } },
        },
      });
      expect(staleMove.status()).toBeGreaterThanOrEqual(400);
      const staleBody = await staleMove.json();
      expect(staleBody.error_code).toBe("failed_precondition");

      // 3. Verify the cell head is UNCHANGED — failed precondition MUST NOT
      //    apply any effect (spec §2.2: preconditions + effects are atomic).
      const readBack = await request.get(
        `${solandBaseUrl()}/api/v1/flows/${encodeURIComponent(flowId)}`,
        { headers: aliceAuth },
      );
      const flowBody = await readBack.json();
      expect(flowBody.fields?.status).toBe("open");
    },
  );

  // ── Phase C — Cascade / archive / delete.
  // soland gap: soland has archive/delete paths on Space but the
  // child-cascade error code (`space_has_live_dependents`) and the
  // post-tombstone write-rejection (`realm_terminal_state` /
  // `space_already_terminal`) are not stably exposed on the wire. Once they
  // are, drop the fixme.
  test.fixme(
    "Phase C — cx.space.archive does NOT cascade; tombstone with live dependents fails; post-tombstone writes are rejected",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-c-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      // Create parent space + a child Flow as a live dependent.
      const parentRes = await request.post(`${solandBaseUrl()}/api/v1/spaces`, {
        headers: aliceAuth,
        data: { title: `core-invariants parent ${stamp}` },
      });
      const parentSpaceId = (await parentRes.json()).space_id as string;

      const childFlowRes = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.flow.create",
          space_id: parentSpaceId,
          payload: { object: { title: `child ${stamp}` } },
        },
      });
      expect(childFlowRes.status()).toBe(201);

      // Step 11 — archive parent; verify child is still active.
      const archiveRes = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: { kind: "cx.space.archive", payload: { space_id: parentSpaceId } },
      });
      expect(archiveRes.status()).toBe(200);

      // Step 12 — tombstone with live child must fail (space §3.4).
      const tombFail = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: { kind: "cx.space.tombstone", payload: { space_id: parentSpaceId } },
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
  // soland gap: cx.relation.create reducer + cardinality enforcement on
  // has_default_view (many_to_one), idempotent dedup on
  // (realm_id, relation_kind, from_ref, to_ref), and cross-Realm contains
  // refusal are not stably wired today.
  test.fixme(
    "Phase D — has_default_view enforces many_to_one; duplicate Relation create is idempotent; cross-Realm contains rejected",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-d-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      const spaceRes = await request.post(`${solandBaseUrl()}/api/v1/spaces`, {
        headers: aliceAuth,
        data: { title: `core-invariants D ${stamp}` },
      });
      const spaceId = (await spaceRes.json()).space_id as string;

      // Two Views in the same space.
      const mkView = async (label: string) => {
        const res = await request.post(`${solandBaseUrl()}/api/v1/views`, {
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
      const e1 = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.relation.create",
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
      const e2 = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.relation.create",
          payload: {
            relation_kind: "has_default_view",
            from_ref: spaceId,
            to_ref: v2,
          },
        },
      });
      const activeEdges = await request.get(
        `${solandBaseUrl()}/api/v1/relations?from_ref=${encodeURIComponent(spaceId)}&relation_kind=has_default_view&state=active`,
        { headers: aliceAuth },
      );
      const edgesBody = await activeEdges.json();
      expect((edgesBody.items ?? []).length).toBeLessThanOrEqual(1);
      if (e2.status() >= 400) {
        expect((await e2.json()).reason).toBe("relation_cardinality_violation");
      }

      // Step 18 — completely duplicate edge create is idempotent.
      const dup = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.relation.create",
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
          await request.post(`${solandBaseUrl()}/api/v1/spaces`, {
            headers: aliceAuth,
            data: { title: `other-realm ${stamp}` },
          })
        ).json()
      ).space_id as string;
      const otherFlow = (
        await (
          await request.post(`${solandBaseUrl()}/api/v1/events`, {
            headers: aliceAuth,
            data: { kind: "cx.flow.create", space_id: otherSpace, payload: { object: {} } },
          })
        ).json()
      ).flow_id as string;
      const crossRealm = await request.post(`${solandBaseUrl()}/api/v1/events`, {
        headers: aliceAuth,
        data: {
          kind: "cx.relation.create",
          space_id: spaceId,
          payload: {
            relation_kind: "contains",
            from_ref: spaceId,
            to_ref: otherFlow,
          },
        },
      });
      expect(crossRealm.status()).toBeGreaterThanOrEqual(400);
      expect((await crossRealm.json()).reason).toBe("cross_space_structural_relation");
    },
  );

  // ── Phase E — View projection fallback.
  // soland gap: /api/v1/spaces/{id}/views/projection endpoint for the
  // derived board response family does not exist. Once soland exposes it
  // (returning a CollectionProjectionResponse even when no user-defined
  // View has been registered), drop the fixme.
  test.fixme(
    "Phase E — Board projection on a fresh Space with no registered View returns the derived default (NOT 404); unknown renderer fails closed",
    async ({ request }) => {
      const stamp = Date.now();
      const alice = uniqueUser(`s-coinv-e-${stamp}`);
      await ensureRegistered(request, alice);
      const aliceToken = await issueDevSession(request, alice);
      const aliceAuth = { authorization: `Bearer ${aliceToken}` };

      const spaceRes = await request.post(`${solandBaseUrl()}/api/v1/spaces`, {
        headers: aliceAuth,
        data: { title: `core-invariants E ${stamp}` },
      });
      const spaceId = (await spaceRes.json()).space_id as string;

      // Step 20-21 — request a board projection on a Space that has never
      // had cx.view.create called on it. Spec views.md §6: response MUST be
      // derived (kind=collection, renderer=board) from query → contains →
      // flow, not 404.
      const proj = await request.get(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/views/projection?renderer=board`,
        { headers: aliceAuth },
      );
      expect(proj.status()).toBe(200);
      const projBody = await proj.json();
      expect(projBody.kind).toBe("collection");
      expect(projBody.renderer).toBe("board");
      expect(projBody.view_id).toMatch(/^cx:view:/);
      expect(Array.isArray(projBody.frontier)).toBe(true);
      expect(Array.isArray(projBody.groups)).toBe(true);

      // Step 22 — unknown renderer MUST fail-closed (spec §2.2 — only the
      // 5 canonical View.kind / known renderers are valid response families).
      const bogus = await request.get(
        `${solandBaseUrl()}/api/v1/spaces/${encodeURIComponent(spaceId)}/views/projection?renderer=bogus_renderer_${stamp}`,
        { headers: aliceAuth },
      );
      expect(bogus.status()).toBeGreaterThanOrEqual(400);
      const bogusBody = await bogus.json();
      expect(bogusBody.error_code).toMatch(/unknown_renderer|unsupported_renderer/);
    },
  );
});
