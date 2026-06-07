#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const trackedFiles = new Set([
  path.normalize("e2e/helpers/soland-api.ts"),
  path.normalize("tests/yougen_mock_parity.rs"),
]);
const scannedRoots = ["e2e/helpers", "e2e/tests"];
const scannedFiles = ["tests/yougen_mock_parity.rs"];
const requiredSwitchMarkers = [
  "COTEST_EVENT_PROOF_MODE",
  "COTEST_FORBID_DEV_PROOF",
  "detached-jws",
  "cotest.detached_jws.fixture.v1",
];

const hits = [];
for (const root of scannedRoots) {
  for (const file of walk(path.join(repoRoot, root))) {
    if (!/\.(rs|ts)$/.test(file)) {
      continue;
    }
    const text = fs.readFileSync(file, "utf8");
    if (!text.includes("dev-proof")) {
      continue;
    }
    hits.push({
      file,
      rel: path.normalize(path.relative(repoRoot, file)),
      count: text.split("dev-proof").length - 1,
    });
  }
}
for (const rel of scannedFiles) {
  const file = path.join(repoRoot, rel);
  if (!fs.existsSync(file)) {
    continue;
  }
  const text = fs.readFileSync(file, "utf8");
  if (!text.includes("dev-proof")) {
    continue;
  }
  hits.push({
    file,
    rel: path.normalize(rel),
    count: text.split("dev-proof").length - 1,
  });
}

const untracked = hits.filter((hit) => !trackedFiles.has(hit.rel));
if (untracked.length > 0) {
  fail(
    [
      "dev-proof appeared outside the tracked fixture/switch points:",
      ...untracked.map((hit) => `  ${hit.rel} (${hit.count})`),
      "Use e2e/helpers/soland-api.ts::eventProof() or add an explicit tracked exception.",
    ].join("\n"),
  );
}

const helperPath = path.join(repoRoot, "e2e/helpers/soland-api.ts");
const helper = fs.readFileSync(helperPath, "utf8");
const missingMarkers = requiredSwitchMarkers.filter(
  (marker) => !helper.includes(marker),
);
if (missingMarkers.length > 0) {
  fail(`dev-proof switch is missing markers: ${missingMarkers.join(", ")}`);
}
if (!helper.includes('process.env.COTEST_EVENT_PROOF_MODE ?? "detached-jws"')) {
  fail("COTEST_EVENT_PROOF_MODE must default to detached-jws, not dev-proof");
}

const total = hits.reduce((sum, hit) => sum + hit.count, 0);
console.log(
  `dev-proof gate: ${total} tracked occurrence(s) in ${hits.length} file(s)`,
);

function* walk(dir) {
  if (!fs.existsSync(dir)) {
    return;
  }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else {
      yield full;
    }
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
