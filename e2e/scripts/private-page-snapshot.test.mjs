import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import PrivateCaptureReporter from "../reporters/private-capture.ts";
import { fileURLToPath } from "node:url";

const e2e = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("a real failing browser run preserves failure without retaining its private page", { timeout: 45_000 }, () => {
  const root = path.join(e2e, "..", "artifacts", "tool-tests");
  mkdirSync(root, { recursive: true });
  const fixture = mkdtempSync(path.join(root, "private-page-snapshot-"));
  const output = path.join(fixture, "output");
  writeFileSync(path.join(fixture, "package.json"), JSON.stringify({ type: "module" }));
  const canary = `arkret://agent-pair#token=snapshot-canary-${randomUUID()}`;
  const runtime = path.join(e2e, "node_modules", "@playwright", "test", "index.mjs");
  const baseConfig = path.join(e2e, "playwright.config.ts");
  writeFileSync(path.join(fixture, "capture.spec.ts"), `
import { test, expect } from ${JSON.stringify(runtime)};
test("retains the actual missing approval failure", async ({ page }) => {
  await page.setContent('<h1>Approval pending</h1><input aria-label="Private pairing URL" readonly>');
  await page.getByLabel("Private pairing URL").evaluate((input, value) => { input.value = value; }, process.env.COTEST_PRIVATE_PAGE_CANARY);
  await expect(page.getByRole("heading", { name: "Missing approval", exact: true })).toBeVisible({ timeout: 100 });
});
`);
  writeFileSync(path.join(fixture, "playwright.config.ts"), `
import base from ${JSON.stringify(baseConfig)};
export default { ...base, testDir: ${JSON.stringify(fixture)}, testMatch: /capture\\.spec\\.ts/,
  outputDir: ${JSON.stringify(path.join(output, "results"))}, retries: 0, workers: 1,
  projects: [{ name: "private-page-capture" }],
  use: { ...base.use, trace: "off", video: "off", screenshot: "off" },
  reporter: base.reporter.map(entry => {
    const [name, options] = typeof entry === "string" ? [entry] : entry;
    const resolved = name.startsWith(".") ? ${JSON.stringify(e2e)} + "/" + name : name;
    return options === undefined ? [resolved] : [resolved, options];
  }),
};
`);
  const environment = { ...process.env, COTEST_JOINT_RUN_DIR: output, COTEST_PRIVATE_PAGE_CANARY: canary };
  // Exercise the production config, never a caller's inherited snapshot opt-out.
  delete environment.PLAYWRIGHT_NO_COPY_PROMPT;
  const child = spawnSync(process.execPath, [path.join(e2e, "node_modules", "playwright", "cli.js"),
    "test", "--config", path.join(fixture, "playwright.config.ts")], {
    cwd: e2e, env: environment, encoding: "utf8", timeout: 30_000, maxBuffer: 2_000_000,
  });
  writeFileSync(path.join(fixture, "child.log"), child.stdout + child.stderr);
  writeFileSync(path.join(fixture, "execution.json"), JSON.stringify({
    exit_code: child.status, signal: child.signal,
    canary_sha256: createHash("sha256").update(canary).digest("hex"),
  }, null, 2));
  assert.equal(child.error, undefined, "the real browser child must terminate normally");
  assert.equal(child.status, 1, "the actual missing approval failure must remain CLI 1");
  const summary = JSON.parse(readFileSync(path.join(output, "playwright-report", "safe-summary.json"), "utf8"));
  assert.equal(summary.status, "failed");
  assert.equal(summary.global_error_count, 0);
  assert.equal(summary.cases.length, 1);
  assert.equal(summary.cases[0].status, "failed");
  const files = readdirSync(output, { recursive: true, withFileTypes: true })
    .filter(entry => entry.isFile()).map(entry => path.join(entry.parentPath, entry.name));
  const persisted = files.map(file => readFileSync(file).toString("utf8")).join("\n") + child.stdout + child.stderr;
  assert.equal(persisted.includes(canary), false, "private page values must be absent from retained diagnostics");
  assert.equal(persisted.includes("snapshot-canary-"), false, "even a partial private value must be absent");
});


function guardFixture() {
  const base = path.join(e2e, "..", "artifacts", "tool-tests");
  mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(path.join(base, "private-capture-guard-"));
  const root = path.join(directory, "results");
  const report = path.join(directory, "report");
  mkdirSync(root);
  const guard = new PrivateCaptureReporter({ outputFolder: report });
  guard.onBegin({ projects: [{ outputDir: root }] });
  return { directory, root, report, guard };
}

test("automatic context is replaced whole and keeps its exact original receipt", async () => {
  const { root, report, guard } = guardFixture();
  const body = "synthetic private page value";
  const file = path.join(root, "error-context.md");
  writeFileSync(file, body);
  const result = { status: "failed", attachments: [{ name: "error-context", path: file }] };
  guard.onTestEnd({ id: "actual-failed-case" }, result);
  assert.equal(await guard.onEnd(), undefined);
  assert.equal(result.status, "failed");
  const expected = createHash("sha256").update(body).digest("hex");
  const receipt = JSON.parse(readFileSync(path.join(report, "private-capture-receipts.json"), "utf8"));
  assert.deepEqual(receipt.disposed, [{ test_id: "actual-failed-case", bytes: Buffer.byteLength(body), sha256: expected }]);
  assert.equal(receipt.rejected_attachments, 0);
  const retained = readFileSync(file, "utf8");
  assert.equal(retained.includes(body), false);
  assert.equal(retained.includes(expected), true);
});

test("an arbitrary attachment path fails closed without changing or exporting its bytes", async () => {
  const { directory, report, guard } = guardFixture();
  const outside = path.join(directory, "error-context.md");
  const bytes = "external attachment must remain untouched";
  writeFileSync(outside, bytes);
  guard.onTestEnd({ id: "outside-path" }, { attachments: [{ name: "error-context", path: outside }] });
  assert.deepEqual(await guard.onEnd(), { status: "failed" });
  assert.equal(readFileSync(outside, "utf8"), bytes);
  const receipt = readFileSync(path.join(report, "private-capture-receipts.json"), "utf8");
  assert.equal(receipt.includes(bytes), false);
  assert.equal(JSON.parse(receipt).disposed.length, 0);
});

test("a link below the owned output cannot redirect disposal outside that output", async () => {
  const { directory, root, report, guard } = guardFixture();
  const external = path.join(directory, "external");
  mkdirSync(external);
  const file = path.join(external, "error-context.md");
  writeFileSync(file, "external linked bytes");
  const link = path.join(root, "case");
  symlinkSync(external, link, process.platform === "win32" ? "junction" : "dir");
  guard.onTestEnd({ id: "linked-path" }, { attachments: [{ name: "error-context", path: path.join(link, "error-context.md") }] });
  assert.deepEqual(await guard.onEnd(), { status: "failed" });
  assert.equal(readFileSync(file, "utf8"), "external linked bytes");
  assert.equal(JSON.parse(readFileSync(path.join(report, "private-capture-receipts.json"), "utf8")).disposed.length, 0);
});
