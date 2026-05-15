// Knock auto-resolve path (cx.member.state{join, gate_proofs})
// Contract: e2e/scenarios/spaces/knock-auto-resolve.md
// Spec: models/space-and-place.md §3.4 + §3.5, §3.3.1 gate types

import { test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test.describe("knock auto-resolve path", () => {
  test.fixme(
    "alice sets join_rule=knock_restricted with gates=[claim_required(auto), challenge_response(auto)]; bob submits cx.member.state{join, gate_proofs[]} and joins directly",
    async () => {
      // spec: space-and-place.md §3.5
      // soland gap: join_policy cell + gate verifier; harness gap: mock claim issuer + challenge provider.
    },
  );

  test.fixme(
    "mallory without the required VC: gate_proofs[].g-vc invalid; reducer rejects with failed_precondition + g-vc gate id",
    async () => {},
  );

  test.fixme(
    "E6.2.2 challenge_proof older than max_proof_age=5min: rejected with challenge_failed",
    async () => {},
  );

  test.fixme(
    "cooldown gate independent of combinator: bob leaves then immediately re-applies → rejected with cooldown_gate_blocking",
    async () => {
      // spec: space-and-place.md §3.3.1 cooldown gate semantics
    },
  );

  test.fixme(
    "combinator=any: bob satisfies only g-vc → still accepted; mallory satisfies only g-captcha → also accepted (typical knock_restricted hybrid)",
    async () => {},
  );
});
