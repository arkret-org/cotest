import assert from "node:assert/strict";
import { test } from "node:test";
import { publicOrdinaryHistoryDiagnostic } from "../helpers/ordinary-history-diagnostics.ts";

test("ordinary history diagnostics keep public carrier facts and discard content and credentials", () => {
  const result = publicOrdinaryHistoryDiagnostic({ raw_message_count: 1, verified_message_count: 1, exact_committed_count: 1,
    checkpoint_readable: true, checkpoint_position: "18446744073709551615", session_grant: "fixture-sensitive-grant",
    exact_records: [{ top_level_signed: false, nested_signed: true, proof_verdict: "verified", strand_id: `ak:strand:${"A".repeat(44)}`, body: "fixture-sensitive-content" }],
    private_material: "fixture-sensitive-private-material" });
  assert.equal(result.raw_message_count, 1);
  assert.equal(result.exact_records[0].proof_verdict, "verified");
  assert.equal(result.checkpoint_position, "18446744073709551615");
  assert.ok(!JSON.stringify(result).includes("fixture-sensitive"));
});

test("ordinary history diagnostics reject unknown errors and malformed facts and bound carrier lists", () => {
  const result = publicOrdinaryHistoryDiagnostic({ error: "fixture-sensitive-grant", raw_message_count: -1,
    verified_message_count: Infinity, checkpoint_position: "private-material", checkpoint_readable: "true",
    exact_records: Array.from({ length: 20 }, () => ({ top_level_signed: "yes", proof_verdict: "private-material", strand_id: "private-material" })) });
  assert.deepEqual(result, { exact_records: Array.from({ length: 8 }, () => ({})) });
  assert.deepEqual(publicOrdinaryHistoryDiagnostic({ error: "account_mismatch" }), { error: "account_mismatch" });
});
