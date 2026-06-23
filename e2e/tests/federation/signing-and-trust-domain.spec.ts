// Federation outbound signing and trust_domain
// Contract: e2e/scenarios/federation/signing-and-trust-domain.md
//
// These Playwright tests wrap soland's real integration suite so cotest
// coverage tracks the live federation security contract without mocking the
// transport or lowering this to a TODO/fixme.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

import { expect, test } from "@playwright/test";

const execFileAsync = promisify(execFile);

const CARGO_TEST_TIMEOUT_MS = 180_000;
const SOLAND_MANIFEST = findSolandManifest();
const SOLAND_CWD = path.dirname(SOLAND_MANIFEST);
const CARGO_TARGET_DIR = path.join(SOLAND_CWD, "target", "cotest-federation-outbox");
const CARGO_BIN = process.platform === "win32" ? "cargo.exe" : "cargo";

test.describe.configure({ mode: "serial" });

test.describe("federation outbound signing and trust_domain", () => {
  test("A→B outbound invite push carries RFC 9421 signature headers verified by A service public key", async () => {
    await runSolandOutboxTest("enqueue_then_dispatch_delivers_payload_with_spec_headers");
  });

  test("tampered body digest invalidates the signed outbound transcript", async () => {
    await runSolandOutboxTest("outbound_signature_rejects_body_digest_tamper");
  });

  test("missing trust_domain component is rejected as untrusted", async () => {
    await runSolandOutboxTest("outbound_signature_rejects_missing_trust_domain_component");
  });

  test("trust_domain mismatch is rejected", async () => {
    await runSolandOutboxTest("outbound_signature_rejects_trust_domain_mismatch");
  });

  test("replayed nonce/idempotency key reuses the existing outbox row", async () => {
    await runSolandOutboxTest("outbound_enqueue_is_idempotent_for_same_peer_and_key");
  });

  test("service key revoke or rotation invalidates idempotent replay of old signed request", async () => {
    await runSolandOutboxTest("outbound_signature_fails_after_service_key_rotation");
  });
});

async function runSolandOutboxTest(filter: string): Promise<void> {
  await expectSolandOutboxTestListed(filter);
  const { stdout, stderr } = await execFileAsync(
    CARGO_BIN,
    [
      "test",
      "--message-format=json",
      "--manifest-path",
      SOLAND_MANIFEST,
      "--test",
      "federation_outbox",
      filter,
      "--",
      "--exact",
      "--nocapture",
    ],
    {
      cwd: SOLAND_CWD,
      timeout: CARGO_TEST_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        ...process.env,
        CARGO_TERM_COLOR: "never",
        CARGO_TARGET_DIR,
      },
    },
  );
  const output = `${stdout}\n${stderr}`;
  expect(hasCargoBuildFinishedJson(output)).toBeTruthy();
  const summary = output.match(
    /test result: ok\. (?<passed>\d+) passed; (?<failed>\d+) failed; (?<ignored>\d+) ignored; (?<measured>\d+) measured; (?<filtered>\d+) filtered out/,
  );
  expect(summary, output).toBeTruthy();
  expect(summary?.groups?.passed).toBe("1");
  expect(summary?.groups?.failed).toBe("0");
}

async function expectSolandOutboxTestListed(filter: string): Promise<void> {
  const { stdout, stderr } = await execFileAsync(
    CARGO_BIN,
    [
      "test",
      "--manifest-path",
      SOLAND_MANIFEST,
      "--test",
      "federation_outbox",
      "--",
      "--list",
    ],
    {
      cwd: SOLAND_CWD,
      timeout: CARGO_TEST_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        ...process.env,
        CARGO_TERM_COLOR: "never",
        CARGO_TARGET_DIR,
      },
    },
  );
  const output = `${stdout}\n${stderr}`;
  const matches = output
    .split(/\r?\n/)
    .filter((line) => line.trim() === `${filter}: test`);
  expect(matches, `soland federation_outbox should list exactly one ${filter}`).toHaveLength(1);
}

function hasCargoBuildFinishedJson(output: string): boolean {
  return output.split(/\r?\n/).some((line) => {
    try {
      const value = JSON.parse(line) as { reason?: string };
      return value.reason === "build-finished";
    } catch {
      return false;
    }
  });
}

function findSolandManifest(): string {
  const candidates = [
    path.resolve(process.cwd(), "..", "soland", "Cargo.toml"),
    path.resolve(process.cwd(), "..", "..", "soland", "Cargo.toml"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(`Unable to locate sibling soland/Cargo.toml from ${process.cwd()}`);
  }
  return found;
}
