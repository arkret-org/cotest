import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { FullConfig, Reporter, TestCase, TestResult } from "@playwright/test/reporter";

// Playwright writes matcher page snapshots before reporter callbacks. Dispose
// of the whole automatic context before any retained report is exported.
export default class PrivateCaptureReporter implements Reporter {
  private roots: string[] = [];
  private failures = 0;
  private readonly receipts: Array<{ test_id: string; bytes: number; sha256: string }> = [];
  private readonly options: { outputFolder: string };
  constructor(options: { outputFolder: string }) { this.options = options; }

  onBegin(config: FullConfig) {
    this.roots = [...new Set(config.projects.map(project => path.resolve(project.outputDir)))];
    this.failures = 0;
    this.receipts.length = 0;
  }
  onTestEnd(test: TestCase, result: TestResult) {
    for (const attachment of result.attachments) {
      if (attachment.name !== "error-context") continue;
      try {
        if (!attachment.path || path.basename(attachment.path) !== "error-context.md") throw new Error();
        const file = path.resolve(attachment.path);
        const root = this.roots.find(candidate => file.startsWith(candidate + path.sep));
        if (!root) throw new Error();
        // Reject links below the owned project output, including the root.
        let current = root;
        const rootInfo = lstatSync(root);
        if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error();
        for (const part of path.relative(root, file).split(path.sep)) {
          current = path.join(current, part);
          if (lstatSync(current).isSymbolicLink()) throw new Error();
        }
        if (!lstatSync(file).isFile() || !realpathSync(file).startsWith(realpathSync(root) + path.sep)) throw new Error();
        const bytes = readFileSync(file);
        const receipt = { test_id: test.id, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
        writeFileSync(file, `# Automatic capture discarded\n\nOriginal bytes: ${receipt.bytes}\nSHA-256: ${receipt.sha256}\n\nPlaywright page/error context can contain private DOM values. See the original assertion and scanned CLI/JUnit diagnostics.\n`);
        this.receipts.push(receipt);
      } catch {
        // Static diagnostic only: an attachment can supply an arbitrary path.
        this.failures++;
      }
    }
  }
  async onEnd() {
    mkdirSync(this.options.outputFolder, { recursive: true });
    writeFileSync(path.join(this.options.outputFolder, "private-capture-receipts.json"), JSON.stringify({
      disposed: this.receipts, rejected_attachments: this.failures,
      boundary: "Whole automatic error-context disposal after Playwright writes it, before retained report export. Assertions and original failures remain unchanged.",
    }, null, 2) + "\n");
    if (this.failures) return { status: "failed" as const };
  }
}
