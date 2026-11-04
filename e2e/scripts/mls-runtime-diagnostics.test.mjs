import assert from "node:assert/strict";
import { test } from "node:test";
import { publicMlsRuntimeDiagnostic } from "../helpers/mls-runtime-diagnostics.ts";

test("MLS diagnostics retain public mismatch flags without raw credentials or errors", () => {
  const result = publicMlsRuntimeDiagnostic(
    "MLS reconciliation current result does not match local checkpoint scope_matches=true epoch_matches=false commit_matches=false key_access_covered=true Authorization=Bearer fixture-sensitive-grant private_material=fixture-private-material",
  );
  assert.deepEqual(result, {
    code: "MLS reconciliation current result does not match local checkpoint",
    fields: { scope_matches: true, epoch_matches: false, commit_matches: false, key_access_covered: true },
    categories: ["epoch"],
  });
  assert.ok(!JSON.stringify(result).includes("fixture-sensitive-grant"));
  assert.ok(!JSON.stringify(result).includes("fixture-private-material"));
});

test("MLS diagnostics preserve distinct current and payload epochs as decimal strings", () => {
  const result = publicMlsRuntimeDiagnostic(
    'MLS application payload remains decryption-pending payload_epoch=9007199254740991 snapshot_epoch=Some(2) error="session changed; ratchet unavailable" fixture-private-material',
  );
  assert.deepEqual(result.fields, { payload_epoch: "9007199254740991", snapshot_epoch: "2" });
  assert.deepEqual(result.categories, ["unavailable", "session", "ratchet", "epoch"]);
  assert.ok(!JSON.stringify(result).includes("fixture-private-material"));
});

test("MLS diagnostics discard unknown messages and malformed public values", () => {
  assert.equal(publicMlsRuntimeDiagnostic("Authorization=Bearer fixture-sensitive-grant"), undefined);
  const result = publicMlsRuntimeDiagnostic(
    "MLS send readiness dependencies observed checkpoint_present=trueSuffix private_root_available=opaque payload_epoch=-1 snapshot_epoch=18446744073709551615",
  );
  assert.deepEqual(result.fields, {});
  assert.equal(result.code, "MLS send readiness dependencies observed");
});
