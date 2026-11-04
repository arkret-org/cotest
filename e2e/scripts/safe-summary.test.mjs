import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import SafeSummaryReporter, { safeCase, renderSummary } from "../reporters/safe-summary.ts";

const secret = "synthetic-private-API-argument-AAABBBCCC";
const makeTest = (id = "fixture-id") => ({ id, title: "recovery journey", location: { file: "/private/source/e2e/tests/recovery.spec.ts", line: 12 }, parent: { project: () => ({ name: "chromium" }) } });
const makeResult = (status = "passed", retry = 0) => ({ status, retry, duration: 42,
  steps: [{ title: `Fill "${secret}"`, snippet: secret, attachments: [{ body: Buffer.from(secret) }] }],
  stdout: [secret], stderr: [secret], errors: [{ message: secret, stack: secret }],
  annotations: [{ description: secret }],
  attachments: [{ name: secret, contentType: "application/json", body: Buffer.from(secret) },
    { name: secret, contentType: secret, path: `/private/${secret}` }],
});

test("private API arguments, errors, output and arbitrary attachment contents never enter the record", () => {
  const record = safeCase(makeTest(), makeResult(), "/private/source/e2e");
  assert.equal(JSON.stringify(record).includes(secret), false);
  assert.equal(record.attachments[0].sha256, createHash("sha256").update(secret).digest("hex"));
  assert.equal(record.attachments[0].bytes, Buffer.byteLength(secret));
  assert.equal(record.attachments[1].file_attachment_omitted, true);
  assert.equal(record.attachments[1].content_type, "application/octet-stream");
});

test("source identity is relative and never publishes an unrelated absolute root", () => {
  assert.equal(safeCase(makeTest(), makeResult(), "/private/source/e2e").file, "tests/recovery.spec.ts");
  assert.equal(safeCase(makeTest(), makeResult(), "/different/root").file, "recovery.spec.ts");
  const windows = makeTest(); windows.location.file = "C:\\private\\e2e\\tests\\recovery.spec.ts";
  assert.equal(safeCase(windows, makeResult(), "C:\\private\\e2e").file, "tests/recovery.spec.ts");
});

test("source metadata is escaped in HTML and no embedded archive is produced", () => {
  const fixture = makeTest(); fixture.title = `<script>alert("source")</script>&`;
  const html = renderSummary("passed", [safeCase(fixture, makeResult(), "/private/source/e2e")], 0);
  assert.equal(html.includes('<script>alert'), false);
  assert.ok(html.includes("&lt;script&gt;"));
  assert.equal(html.includes(secret), false);
  assert.equal(html.includes("data:application/zip;base64,"), false);
});

test("the public reporter writes only final retry outcomes and byte receipts", () => {
  const outputFolder = mkdtempSync(path.join(os.tmpdir(), "cotest-safe-report-"));
  try {
    const reporter = new SafeSummaryReporter({ outputFolder, sourceRoot: "/private/source/e2e" });
    reporter.onBegin({}, {});
    reporter.onTestEnd(makeTest(), makeResult("failed", 0));
    reporter.onTestEnd(makeTest(), makeResult("passed", 1));
    reporter.onTestEnd(makeTest("skipped-id"), makeResult("skipped", 0));
    reporter.onError({ message: secret });
    reporter.onEnd({ status: "passed" });
    const raw = readFileSync(path.join(outputFolder, "safe-summary.json"), "utf8");
    const summary = JSON.parse(raw);
    assert.equal(summary.cases.length, 2);
    assert.equal(summary.cases[0].status, "passed");
    assert.equal(summary.cases[0].retry, 1);
    assert.equal(summary.cases[1].status, "skipped");
    assert.equal(summary.global_error_count, 1);
    assert.equal(raw.includes(secret), false);
    assert.equal(readFileSync(path.join(outputFolder, "index.html"), "utf8").includes(secret), false);
  } finally { rmSync(outputFolder, { recursive: true, force: true }); }
});
