import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { FullConfig, FullResult, Reporter, Suite, TestCase, TestResult } from "@playwright/test/reporter";

type Options = { outputFolder: string; sourceRoot: string };
type SafeCase = ReturnType<typeof safeCase>;

// Source-authored case names are metadata. Never traverse API steps, parameters,
// arbitrary attachment bodies, error messages, annotations or captured stdio.
export function safeCase(test: TestCase, result: TestResult, sourceRoot: string) {
  const file = test.location.file.replaceAll("\\", "/");
  const root = sourceRoot.replaceAll("\\", "/").replace(/\/$/, "");
  return {
    test_id: test.id,
    title: test.title,
    file: file.startsWith(root + "/") ? file.slice(root.length + 1) : path.posix.basename(file),
    line: test.location.line,
    project: test.parent.project()?.name ?? "",
    status: result.status,
    retry: result.retry,
    duration_ms: result.duration,
    attachments: result.attachments.map((attachment, index) => ({
      index,
      content_type: /^[a-z0-9.+_-]+\/[a-z0-9.+_-]+$/i.test(attachment.contentType)
        ? attachment.contentType : "application/octet-stream",
      ...(attachment.body ? {
        bytes: attachment.body.length,
        sha256: createHash("sha256").update(attachment.body).digest("hex"),
      } : { file_attachment_omitted: true }),
    })),
  };
}

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]!);
}

export function renderSummary(status: string, cases: SafeCase[], globalErrors: number): string {
  const rows = cases.map(row => `<tr><td>${escapeHtml(row.status)}</td><td>${escapeHtml(row.project)}</td><td>${escapeHtml(row.title)}</td><td>${escapeHtml(row.file)}:${row.line}</td><td>${row.duration_ms}</td></tr>`).join("\n");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Arkret test summary</title><style>body{font:15px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}th,td{padding:.5rem;border-bottom:1px solid #ddd;text-align:left}</style><h1>Arkret test summary</h1><p>Status: ${escapeHtml(status)}. Final cases: ${cases.length}. Global errors: ${globalErrors}.</p><p>Source-authored test names and result metadata only. API steps, inputs, error bodies, captured output and attachment bodies are omitted. See the scanned CLI and JUnit diagnostics.</p><table><thead><tr><th>Status</th><th>Project</th><th>Case</th><th>Source</th><th>Milliseconds</th></tr></thead><tbody>${rows}</tbody></table></html>`;
}

export default class SafeSummaryReporter implements Reporter {
  private readonly options: Options;
  private readonly cases = new Map<string, SafeCase>();
  private globalErrors = 0;

  constructor(options: Options) { this.options = options; }
  onBegin(_config: FullConfig, _suite: Suite) {
    this.cases.clear();
    this.globalErrors = 0;
  }
  onTestEnd(test: TestCase, result: TestResult) {
    const previous = this.cases.get(test.id);
    if (!previous || result.retry >= previous.retry) {
      this.cases.set(test.id, safeCase(test, result, this.options.sourceRoot));
    }
  }
  onError() { this.globalErrors++; }
  onEnd(result: FullResult) {
    const cases = [...this.cases.values()];
    mkdirSync(this.options.outputFolder, { recursive: true });
    writeFileSync(path.join(this.options.outputFolder, "index.html"), renderSummary(result.status, cases, this.globalErrors));
    writeFileSync(path.join(this.options.outputFolder, "safe-summary.json"), JSON.stringify({
      status: result.status, global_error_count: this.globalErrors, cases,
      boundary: "Result metadata and exact attachment byte receipts; no API steps, parameters, arbitrary error or attachment bodies, source snippets or captured stdio.",
    }, null, 2) + "\n");
  }
}
