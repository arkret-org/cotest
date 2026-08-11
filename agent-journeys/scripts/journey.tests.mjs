import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const journeyRoot = path.resolve(scriptDir, "..");
const scenarioDir = path.join(journeyRoot, "scenarios");
const journeyScript = path.join(scriptDir, "journey.mjs");

function scenarioFiles() {
  return fs
    .readdirSync(scenarioDir)
    .filter((file) => file.endsWith(".json"))
    .sort();
}

function runJourney(args, options = {}) {
  return spawnSync(process.execPath, [journeyScript, ...args], {
    encoding: "utf8",
    ...options,
  });
}

test("the scenario catalog satisfies the journey contract", () => {
  const output = execFileSync(
    process.execPath,
    [journeyScript, "validate-scenarios", "--scenario-dir", scenarioDir],
    { encoding: "utf8" },
  );
  const catalog = JSON.parse(output);
  assert.equal(catalog.count, scenarioFiles().length);
  assert.deepEqual(
    catalog.scenarios.map((scenario) => scenario.id),
    [...catalog.scenarios.map((scenario) => scenario.id)].sort(),
  );
});

test("the catalog covers the executable flow families", () => {
  const covered = new Set();
  for (const file of scenarioFiles()) {
    const scenario = JSON.parse(fs.readFileSync(path.join(scenarioDir, file), "utf8"));
    for (const sourceFlow of scenario.source_flows) covered.add(sourceFlow);
  }
  const expected = [
    "contact-direct-conversation-lifecycle",
    "contact-lineage-model",
    "device-pairing-and-recovery",
    "message-authoring-seal-sync",
    "ordinary-realm-creation",
    "realm-event-server-fanout",
    "realm-invitation-history-bootstrap",
    "registration-pcr-genesis",
    "service-route-authentication-and-relocation",
    "service-route-discovery-handover-and-repair",
  ];
  assert.deepEqual([...covered].sort(), expected);
});

test("every scenario initializes a result with the declared checkpoints", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cotest-agent-journey-"));
  try {
    for (const file of scenarioFiles()) {
      const scenarioFile = path.join(scenarioDir, file);
      const scenario = JSON.parse(fs.readFileSync(scenarioFile, "utf8"));
      const runDir = path.join(tempRoot, scenario.id);
      const outcome = runJourney([
        "init",
        "--scenario",
        scenarioFile,
        "--run-dir",
        runDir,
        "--run-id",
        `test-${scenario.id}`,
      ]);
      assert.equal(outcome.status, 0, outcome.stderr);
      const result = JSON.parse(fs.readFileSync(path.join(runDir, "result.json"), "utf8"));
      assert.equal(result.scenario_id, scenario.id);
      assert.equal(result.topology, scenario.required_topology);
      assert.equal(result.checkpoints.length, scenario.checkpoints.length);
      assert.ok(result.checkpoints.every((checkpoint) => checkpoint.status === "PENDING"));
    }
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("scenario validation rejects an unknown checkpoint actor", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cotest-agent-journey-invalid-"));
  try {
    const source = JSON.parse(
      fs.readFileSync(path.join(scenarioDir, "first-realm-continuity.json"), "utf8"),
    );
    source.id = "invalid-actor-scenario";
    source.checkpoints[0].actor = "missing-actor";
    const scenarioFile = path.join(tempRoot, `${source.id}.json`);
    fs.writeFileSync(scenarioFile, `${JSON.stringify(source, null, 2)}\n`, "utf8");
    const outcome = runJourney([
      "init",
      "--scenario",
      scenarioFile,
      "--run-dir",
      path.join(tempRoot, "run"),
      "--run-id",
      "invalid-actor",
    ]);
    assert.notEqual(outcome.status, 0);
    assert.match(outcome.stderr, /unknown actor/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("scenario validation rejects duplicate hard checks", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cotest-agent-journey-invalid-"));
  try {
    const source = JSON.parse(
      fs.readFileSync(path.join(scenarioDir, "first-realm-continuity.json"), "utf8"),
    );
    source.id = "duplicate-hard-check-scenario";
    source.checkpoints[0].hard_checks.push(source.checkpoints[0].hard_checks[0]);
    const scenarioFile = path.join(tempRoot, `${source.id}.json`);
    fs.writeFileSync(scenarioFile, `${JSON.stringify(source, null, 2)}\n`, "utf8");
    const outcome = runJourney([
      "init",
      "--scenario",
      scenarioFile,
      "--run-dir",
      path.join(tempRoot, "run"),
      "--run-id",
      "duplicate-hard-check",
    ]);
    assert.notEqual(outcome.status, 0);
    assert.match(outcome.stderr, /duplicate or invalid hard check/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
