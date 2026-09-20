import assert from "node:assert/strict";
import test from "node:test";
import { publicRequestFailure } from "../helpers/secret-safe.ts";

test("disposed request diagnostics do not retain credential-bearing Call logs", () => {
  const secret = "synthetic-proof-never-report-this-value";
  const source = new Error(`apiRequestContext.call: Request context disposed.\nCall log:\n  - DPoP: ${secret}`);
  const safe = publicRequestFailure(
    source,
    "POST",
    "ak.self.committed_event.read.scan.v1",
  );
  assert.equal(
    safe.message,
    "POST ak.self.committed_event.read.scan.v1 failed: request context disposed",
  );
  assert.equal(safe.cause, undefined);
  assert.ok(!safe.stack?.includes(secret));
  assert.ok(!JSON.stringify(safe).includes(secret));
});

test("unstructured request exceptions cannot inject raw credentials into diagnostics", () => {
  const secret = "synthetic-credential-should-stay-in-memory";
  const safe = publicRequestFailure(new Error(secret), "POST");
  assert.equal(safe.message, "POST HTTP request failed: transport error");
  assert.ok(!safe.stack?.includes(secret));
});
