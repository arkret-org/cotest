import assert from "node:assert/strict";
import test from "node:test";
import type { TestCase, TestError, TestResult, TestStep } from "@playwright/test/reporter";
import PrivateCaptureReporter from "../reporters/private-capture.ts";

test("a caught route transport error cannot export its signed headers in Playwright reports", () => {
  const reporter = new PrivateCaptureReporter({ outputFolder: "unused" });
  const credentials = { grant: "synthetic-grant-not-for-reporting", proof: "synthetic-proof-not-for-reporting" };
  const callLog = `route.fetch: Target page, context or browser has been closed\r\nCall log:\r\n\x1b[2m  - authorization: DPoP ${credentials.grant}\x1b[22m\r\n  - dpop: ${credentials.proof}`;
  const location = { file: "agent-avatar-live.spec.ts", line: 1, column: 1 };
  const stepError: TestError = { message: callLog, stack: `${callLog}\r\n  at Agent provisioning`, location };
  const testError: TestError = { message: "Agent provisioning failed", cause: { value: callLog } };
  const testcase = {} as TestCase;
  const result = { attachments: [], errors: [testError] } as unknown as TestResult;

  reporter.onStepEnd(testcase, result, { error: stepError } as TestStep);
  reporter.onTestEnd(testcase, result);

  for (const value of [stepError.message, stepError.stack, testError.cause?.value]) {
    assert.match(value!, /route\.fetch: Target page/);
    assert.match(value!, /\[Authorization header omitted\]/);
    assert.match(value!, /\[DPoP header omitted\]/);
    assert.ok(!value!.includes(credentials.grant) && !value!.includes(credentials.proof));
  }
  assert.equal(stepError.location, location);
  assert.equal(testError.message, "Agent provisioning failed");
});

test("successful matcher descriptions cannot export signed protocol objects into native HTML step titles", () => {
  const reporter = new PrivateCaptureReporter({ outputFolder: "unused" });
  const location = { file: "capture.spec.ts", line: 1, column: 1 };
  const step = { category: "expect", title: JSON.stringify({ jws: "synthetic-private-step-jws" }), location } as TestStep;
  reporter.onStepBegin({} as TestCase, {} as TestResult, step);
  assert.equal(step.title, "expect step [private parameters omitted]");
  assert.equal(step.location, location);
});

test("failing matcher values retain failure locations without signature or private scalar bytes", () => {
  const reporter = new PrivateCaptureReporter({ outputFolder: "unused" });
  const location = { file: "capture.spec.ts", line: 2, column: 1 };
  const error = { message: 'expect(received).toEqual(expected)\n+ "signature": "synthetic-private-error-signature"\n+ "seed": [1, 2, 3]', location };
  reporter.onError(error);
  assert.match(error.message, /expect\(received\)\.toEqual\(expected\)/);
  assert.match(error.message, /"signature": "\[redacted\]"/);
  assert.match(error.message, /"seed": "\[redacted\]"/);
  assert.equal(error.location, location);
});

test("archive private fixture inputs cannot enter step titles or error diagnostics", () => {
  const reporter = new PrivateCaptureReporter({ outputFolder: "unused" });
  const location = { file: "applet-bridge.spec.ts", line: 1, column: 1 };
  for (const field of ["content_backup_private_key_b64url", "privateKeyB64url", "private_key_base64url"]) {
    const secret = "synthetic-archive-private-key-not-for-reporting";
    const payload = JSON.stringify({ [field]: secret });
    const step = { category: "expect", title: payload, location } as TestStep;
    const error = { message: `native fixture failed: ${payload}`, stack: payload, location };
    reporter.onStepBegin({} as TestCase, {} as TestResult, step);
    reporter.onError(error);
    assert.equal(step.title, "expect step [private parameters omitted]");
    assert.match(error.message, /native fixture failed/);
    assert.match(error.message, /\[redacted\]/);
    assert.ok(!error.message.includes(secret) && !error.stack.includes(secret));
    assert.equal(step.location, location);
    assert.equal(error.location, location);
  }
});
