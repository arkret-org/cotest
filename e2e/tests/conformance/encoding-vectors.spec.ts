// Conformance — Encoding & Crypto / Redaction Vectors
// Contract: e2e/scenarios/conformance/encoding-vectors.md
// Spec: conformance/conformance-vectors.md §1 (encoding/crypto), §3 (redaction)
// Fixtures: contrix-spec/spec/v1/artifacts/fixtures/cx.vector.encoding.*.json,
//           contrix-spec/spec/v1/artifacts/fixtures/cx.vector.redaction.*.json
// Rust parity: cotest/src/conformance/{encoding,envelope,redaction}.rs already
// drive these vectors against in-process traits; this suite re-runs the same
// vectors over the HTTP surface to catch wire-level canonicalizer drift.
//
// soland gap: /api/v1/conformance/{encode,sign,hlc-merge,cursor,envelope,redact}
// endpoints 未实现 (当前仅有 Rust integration tests)。在 endpoints 落地前,主流程
// + 每个 phase 子测试以 test.fixme 钉住 spec 合约,仅保留一个 smoke 测试断言
// fixture loader 与 harness 自身可用。

import { expect, test } from "@playwright/test";
import { solandBaseUrl } from "../../helpers/env";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

test.describe.configure({ mode: "serial" });

test.describe("conformance encoding vectors", () => {
  test.fixme(
    "load canonical JSON / signature / HLC / cursor vectors and assert soland outputs match",
    async ({ request }, testInfo) => {
      // Top-level orchestration: walks every §1 + §3 vector through soland's
      // conformance endpoints and accumulates a coverage report. Pinned as
      // fixme until /api/v1/conformance/* lands on soland.
      const stamp = Date.now();
      const alice = uniqueUser(`conf-alice-${stamp}`);
      const guest = uniqueUser(`conf-guest-${stamp}`);
      await Promise.all([
        ensureRegistered(request, alice),
        ensureRegistered(request, guest),
      ]);
      const aliceToken = await issueDevSession(request, alice);
      const auth = { authorization: `Bearer ${aliceToken}` };

      // pseudo: vectors = await loadSpecFixtures("encoding", "redaction");
      // for each vector: POST to the matching endpoint, diff actual vs expected.
      const probe = await request.post(`${solandBaseUrl()}/api/v1/conformance/encode`, {
        headers: auth,
        data: {
          vector_id: "cx.vector.encoding.canonical_json.basic.v1",
          input: { b: 2, a: 1 },
        },
      });
      expect(probe.status()).toBe(200);
      const body = await probe.json();
      expect(body.canonical_json).toBe('{"a":1,"b":2}');
      expect(body.digest).toBe(
        "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
      );
      void guest; // used by the §3 fixme below
      void testInfo;
    },
  );

  test.fixme(
    "§1.1 canonical JSON encoding parity with spec vectors",
    async () => {
      // spec: conformance-vectors.md §1.3 basic, §1.4 nested, §1.5 reject
      // non-canonical numbers, §1.5.1 reject malformed JSON.
      //
      // POST /api/v1/conformance/encode { vector_id, input } →
      //   accept-path: response.canonical_json byte-equals expected_canonical_json,
      //                response.digest === expected_digest (sha256:<lowercase_hex>)
      //   reject-path: HTTP 4xx with error.code ∈
      //                {schema_violation, invalid_canonical_json, invalid_encoding}
      //                and NO partial canonical bytes / digest leak.
    },
  );

  test.fixme(
    "§1.2 signature binding deterministic across runs",
    async () => {
      // spec: conformance-vectors.md §1.6 event_digest, §1.7 batch_receipt_digest,
      //       §1.8 signature_binding.
      //
      // POST /api/v1/conformance/sign { event, signing_key_ref: alice.dev_key } →
      //   - canonical_bytes byte-equals vector expected_canonical_bytes
      //   - signature verifies under (canonical_bytes, alice.public_key)
      //   - Ed25519 schemes: two calls with same input produce identical signature
      //   - ECDSA schemes: r/s may differ but verify still passes
      //
      // alice.public_key pulled from coauth via GET /api/v1/account/keys.
    },
  );

  test.fixme(
    "§1.3 HLC ordering converges under concurrent clocks",
    async () => {
      // spec: conformance-vectors.md §1.9 hlc_order, §1.10 hlc_logical_overflow.
      //
      // POST /api/v1/conformance/hlc-merge { clocks: [...] } →
      //   - response.ordered === vector expected_order (incl. actor_id tie-break)
      //   - overflow vector: HTTP 4xx with error.code === "hlc_logical_overflow"
      //     (no silent wrap-around).
    },
  );

  test.fixme(
    "§1.4 sync cursor stable across re-reduce",
    async () => {
      // spec: conformance-vectors.md §1.11 cursor_opaqueness.
      //
      // POST /api/v1/conformance/cursor { events, reduce_round: 1 } → cursor_A
      // POST /api/v1/conformance/cursor { events_shuffled, reduce_round: 2 } → cursor_B
      // assert:
      //   - cursor_A === cursor_B (reduce order invariant)
      //   - Buffer.from(cursor, "base64url").toString() does NOT contain any
      //     event_id substring (cursor is opaque to clients)
      //   - base64url decode does not throw
    },
  );

  test.fixme(
    "§1.5 encrypted envelope round-trips canonical hash",
    async () => {
      // spec: conformance-vectors.md §1.12 encrypted_envelope_digest.
      //
      // POST /api/v1/conformance/envelope { envelope: { mls_ciphertext, header, ... } } →
      //   - response.canonical_bytes matches vector (header keys sorted)
      //   - response.digest === expected_digest
      //   - re-posting same envelope produces identical digest (no randomness
      //     in canonical form)
    },
  );

  test.fixme(
    "§3 redaction visibility matrix matches projection",
    async () => {
      // spec: conformance-vectors.md §3.2 field retention, §3.2.1 space target
      //       redaction schema, §3.3 redaction × policy scope, §3.4 hard
      //       erasure receipt, §3.5 snapshot pruning verification stub.
      //
      // For each (original_event, redaction_event) vector:
      //   POST /api/v1/conformance/redact { event, redaction, viewer_did: alice.did }
      //     → projected_event keys === vector.expected_retained_fields_owner
      //       (stripped fields MUST be absent, not null)
      //   POST .../redact { ..., viewer_did: guest.did }
      //     → projected_event keys === vector.expected_retained_fields_guest
      //       (typical: payload.content hidden; event_id / redacted_because /
      //       tombstone marker still visible)
      //
      // Then assert §3.4 hard-erasure receipt schema and §3.5 snapshot stub
      // (snapshot keeps a verification stub even after content erasure).
    },
  );

  test("conformance endpoint surface probe (smoke)", async ({ request }, testInfo) => {
    // While the §1/§3 fixme tests above pin the spec contract, this smoke test
    // gives the suite something to run today: it confirms the harness can
    // reach soland and that the conformance namespace responds in a predictable
    // way (either 200 once endpoints land, or 404 / 501 today). This makes the
    // gap visible in CI without the suite being entirely red.
    const probe = await request.post(`${solandBaseUrl()}/api/v1/conformance/encode`, {
      data: {
        vector_id: "cx.vector.encoding.canonical_json.basic.v1",
        input: { b: 2, a: 1 },
      },
    });
    // Today: 404 (route absent), 405 (route present but verb not wired) or
    // 501 (route stubbed) are all acceptable; 200 is the eventual target.
    // Anything else (5xx other than 501) signals the conformance namespace
    // is half-wired and worth investigating.
    expect([200, 404, 405, 501]).toContain(probe.status());
    await testInfo.attach("conformance-endpoint-probe-status", {
      body: String(probe.status()),
      contentType: "text/plain",
    });
  });
});
