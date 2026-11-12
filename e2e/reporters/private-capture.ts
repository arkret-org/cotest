import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { FullConfig, Reporter, TestCase, TestError, TestResult, TestStep } from "@playwright/test/reporter";

// A caught Playwright transport failure is still recorded as an API step.
// Strip signed request header values before list, JUnit or HTML can copy them.
const signedHeaderLine = /^((?:[ \t]|\x1b\[[0-9;]*m)*(?:[-+][ \t]+)?)(?:(authorization)[ \t]*:[ \t]*(?:bearer|dpop)[ \t]+|dpop[ \t]*:[ \t]*)[^\s\x1b]+/gim;

// Matcher descriptions can become HTML step titles even when they pass.
// Never export a full signed protocol response used as a custom description.
const privateJsonFields = "authorization|access_token|token|push_key|invite_token|oob_code|token_salt|code_salt|pepper|signing_seed|signed_link|jws|signature|password|secret|secret_base64url|private_key|seed|mnemonic|recovery_key|recovery_phrase|recovery_secret|root_seed|root_private_key|hkdf_prk|prk|credential|plaintext_keybag|keybag_secret|mls_secret|epoch_secret|application_secret|confirmation_key|membership_key|init_secret|joiner_secret|welcome_secret|private_state";
const privateJsonField = new RegExp(`"(?:${privateJsonFields})"\\s*:`, "i");
const privateJsonValue = new RegExp(`("(?:${privateJsonFields})"\\s*:\\s*)(?:"(?:\\\\.|[^"\\\\])*"|\\[(?:\\s*\\d+\\s*,?)*\\])`, "gi");

function protectDiagnosticText(value: string): string {
  return value.replace(signedHeaderLine, (_header, prefix, authorization) =>
    `${prefix}[${authorization ? "Authorization" : "DPoP"} header omitted]`)
    .replace(privateJsonValue, '$1"[redacted]"');
}

function protectTransportError(error: TestError | undefined) {
  const seen = new Set<TestError>();
  for (let entry = error; entry && !seen.has(entry); entry = entry.cause) {
    seen.add(entry);
    for (const key of ["message", "stack", "value", "snippet"] as const) {
      const value = entry[key];
      if (value !== undefined) {
        entry[key] = protectDiagnosticText(value);
      }
    }
  }
}

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
  onStepBegin(_test: TestCase, _result: TestResult, step: TestStep) {
    // The native HTML reporter copies titles at step begin. Input values can
    // contain recovery material even when the later DOM snapshot is discarded.
    // Keep the action and source location without exporting its entered value.
    if (privateJsonField.test(step.title)) {
      step.title = `${step.category} step [private parameters omitted]`;
      return;
    }
    if (step.category !== "pw:api") return;
    const input = /^(Fill|Type|Insert) "/.exec(step.title);
    if (input) step.title = `${input[1]} input [value omitted]`;
  }
  onStepEnd(_test: TestCase, _result: TestResult, step: TestStep) {
    protectTransportError(step.error);
  }
  onError(error: TestError) {
    protectTransportError(error);
  }
  onTestEnd(test: TestCase, result: TestResult) {
    for (const error of result.errors) protectTransportError(error);
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
      boundary: "Discard automatic page context and omit private step parameters, signed header values and secret JSON values before retained report export. Preserve assertion outcomes and source locations.",
    }, null, 2) + "\n");
    if (this.failures) return { status: "failed" as const };
  }
}
