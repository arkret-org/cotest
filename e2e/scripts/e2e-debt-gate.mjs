#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const testsRoot = path.join(root, "tests");

const thresholds = {
  minRunRatio: numberEnv("COTEST_E2E_MIN_RUN_RATIO", 0.55),
  maxFixmeRatio: numberEnv("COTEST_E2E_MAX_FIXME_RATIO", 0.35),
  maxSkipRatio: numberEnv("COTEST_E2E_MAX_SKIP_RATIO", 0.08),
};

const counts = {
  run: 0,
  fixme: 0,
  skip: 0,
};

for (const file of walk(testsRoot)) {
  if (!file.endsWith(".spec.ts")) {
    continue;
  }
  const text = fs.readFileSync(file, "utf8");
  counts.fixme += countMatches(text, /\btest\.fixme\s*\(/g);
  counts.skip += countMatches(text, /\btest\.skip\s*\(/g);
  counts.run += countMatches(text, /\btest\s*\(/g);
}

const total = counts.run + counts.fixme + counts.skip;
if (total === 0) {
  fail("no Playwright tests were counted under e2e/tests");
}

const ratios = {
  run: counts.run / total,
  fixme: counts.fixme / total,
  skip: counts.skip / total,
};

console.log(
  [
    "e2e debt gate:",
    `run=${counts.run} (${pct(ratios.run)})`,
    `fixme=${counts.fixme} (${pct(ratios.fixme)})`,
    `skip=${counts.skip} (${pct(ratios.skip)})`,
  ].join(" "),
);

const failures = [];
if (ratios.run < thresholds.minRunRatio) {
  failures.push(
    `run ratio ${pct(ratios.run)} < ${pct(thresholds.minRunRatio)}`,
  );
}
if (ratios.fixme > thresholds.maxFixmeRatio) {
  failures.push(
    `fixme ratio ${pct(ratios.fixme)} > ${pct(thresholds.maxFixmeRatio)}`,
  );
}
if (ratios.skip > thresholds.maxSkipRatio) {
  failures.push(
    `skip ratio ${pct(ratios.skip)} > ${pct(thresholds.maxSkipRatio)}`,
  );
}

if (failures.length > 0) {
  fail(`Playwright run/skip/fixme debt gate failed: ${failures.join("; ")}`);
}

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else {
      yield full;
    }
  }
}

function countMatches(text, pattern) {
  return [...text.matchAll(pattern)].length;
}

function numberEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    fail(`${name} must be a number between 0 and 1, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

function pct(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
