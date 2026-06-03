// TSP relationship bootstrap and Cokret-over-TSP envelope
// Contract: e2e/scenarios/identity/tsp-bootstrap.md
// Spec refs:
//   - identity/tsp-integration.md §2 (TSP applicability), §3 (VID/Endpoint/Relationship mapping)
//   - §4 (cx.service.tsp endpoint declaration), §5 (Cokret over TSP rules)
//   - §8 (Security requirements: VID verification, audit log fields)

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("tsp bootstrap", () => {
  test.fixme(
    // @blocking-on: soland#identity-tsp-bootstrap-gap
    // @user-promise: e2e/scenarios/identity/tsp-bootstrap.md
    // @expected-live-by: 2026Q3
    "alice and bob_extern bootstrap TSP relationship; alice sends Cokret invite via TSP; bob_extern verifies + ACKs",
    async () => {
      // Main flow covers tsp-bootstrap.md Phase A-E:
      //   A — both VIDs' DID Documents declare `cx.service.tsp` endpoint
      //       (spec §4); yougen feature-discovery shows TSP capability badge
      //       (spec §3: DID method adapter SHOULD expose TSP support).
      //   B — alice POSTs TSP bootstrap message to bob_extern's endpoint
      //       (= mock-tsp-endpoint.mjs on MOCK_TSP_ENDPOINT_PORT, declaring
      //       MOCK_TSP_ENDPOINT_VID); mock returns relationship_id + remote
      //       pubkey; alice's /settings/connections shows the new relationship
      //       with trust_level="verified" (spec §8).
      //   C — alice wraps `cx.invite.create` (with inner Cokret event
      //       signature) as a TSP application payload using nested mode
      //       (content_type="application/cokret+json"; outer envelope
      //       carries only pairwise VID, real `vid_local` hidden inside;
      //       spec §4 metadata_privacy.nested_messages, §5).
      //   D — mock (as bob_extern) decrypts outer, validates Cokret
      //       signature against alice's webvh key, ACKs with both
      //       `tsp_authenticity = "ok"` AND `contrix_signature = "ok"`
      //       (spec §5: both SHOULD be verified, and independently).
      //       soland audit log gets `tsp.message.send` with
      //       relationship_id / payload_digest / payload_type /
      //       verification_result (spec §8).
      //   E — reverse channel: mock sends bob_extern's
      //       `cx.member.state{join}` via the same relationship; alice's
      //       TSP listener decrypts, verifies bob_extern's did:web
      //       signature, and the space-admin-panel reflects the join.
      //
      // soland gap: cx.service.tsp endpoint declaration + TSP envelope verification 未实现 (TSP 是 extension profile,v1 core 不必需)
      // yougen gap: establish-tsp-button on /directory, /settings/connections
      //   TSP relationship list, trust_level badge.
      // harness gap: mock-tsp-endpoint.mjs is delivered by a parallel task;
      //   this test reads MOCK_TSP_ENDPOINT_PORT / MOCK_TSP_ENDPOINT_VID
      //   from process.env. If either is unset, the spec should skip rather
      //   than fail (TSP is opt-in / profile-extension).
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-tsp-bootstrap-gap
    // @user-promise: e2e/scenarios/identity/tsp-bootstrap.md
    // @expected-live-by: 2026Q3
    "E2.1 TSP endpoint unreachable → client falls back to HTTPS JWE; invite still delivers; audit logs transport.fallback{from:tsp,to:https-jwe}",
    async () => {
      // spec: tsp-integration.md status header (v1 core default = HTTPS JWE /
      // MLS DM; TSP is opt-in). Drop the mock TSP endpoint (kill the process
      // bound to MOCK_TSP_ENDPOINT_PORT or use route.block) before alice
      // sends the second `cx.invite.create`; the client MUST degrade to the
      // default Cokret v1 core transport rather than fail-closed.
      //
      // soland gap: cx.service.tsp endpoint declaration + TSP envelope verification 未实现 (TSP 是 extension profile,v1 core 不必需)
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-tsp-bootstrap-gap
    // @user-promise: e2e/scenarios/identity/tsp-bootstrap.md
    // @expected-live-by: 2026Q3
    "E2.2 VID resolver degraded (no witness) → TSP relationship's trust_level downgrades to 'degraded_no_witness'; signature still validates but trust drops",
    async () => {
      // spec: tsp-integration.md §8 (record support system + trust
      // assessment result). Reuse the webvh-rotation `degraded_no_witness`
      // machinery: bring the witness offline so bob_extern's resolver
      // returns a degraded view of alice's VID. The TSP message itself
      // still verifies (signature is computable), but the relationship
      // metadata's trust_level transitions verified → degraded, and the
      // ACK from D step 18 must carry verification.vid_trust =
      // "degraded_no_witness" alongside tsp_authenticity = "ok".
      //
      // soland gap: cx.service.tsp endpoint declaration + TSP envelope verification 未实现 (TSP 是 extension profile,v1 core 不必需)
    },
  );

  test.fixme(
    // @blocking-on: soland#identity-tsp-bootstrap-gap
    // @user-promise: e2e/scenarios/identity/tsp-bootstrap.md
    // @expected-live-by: 2026Q3
    "E2.3 metadata privacy via nested message: an intermediary relay sees pairwise VID + payload_digest only — no vid_local, no inner operation, no plaintext payload",
    async () => {
      // spec: tsp-integration.md §4 (metadata_privacy.nested_messages),
      // §5 (nested mode hides inner VID; intermediary MUST NOT be treated
      // as a trusted authorization party). Configure the mock to also
      // expose a `relay-view` endpoint that records exactly what an
      // intermediary observes; assert the inner VID + inner operation
      // name + inner payload bytes are all absent from that view, while
      // bob_extern (the terminus) still successfully decrypts and
      // executes the inner Cokret payload.
      //
      // soland gap: cx.service.tsp endpoint declaration + TSP envelope verification 未实现 (TSP 是 extension profile,v1 core 不必需)
    },
  );
});
