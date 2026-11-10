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
