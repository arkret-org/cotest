import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const FINAL_STATUSES = new Set([
  "PASS",
  "PRODUCT_FAIL",
  "AGENT_FAIL",
  "HARNESS_FAIL",
  "INCONCLUSIVE",
]);
const CHECKPOINT_STATUSES = new Set(["PENDING", ...FINAL_STATUSES]);
const RESULT_STATUSES = new Set(["RUNNING", ...FINAL_STATUSES]);

function parseArgs(values) {
  const parsed = { _: [] };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) {
      parsed._.push(value);
      continue;
    }
    const key = value.slice(2);
    const next = values[index + 1];
    const parsedValue = next && !next.startsWith("--") ? values[++index] : true;
    if (Object.hasOwn(parsed, key)) {
      parsed[key] = Array.isArray(parsed[key])
        ? [...parsed[key], parsedValue]
        : [parsed[key], parsedValue];
    } else {
      parsed[key] = parsedValue;
    }
  }
  return parsed;
}

function required(args, key) {
  const value = args[key];
  if (value === undefined || value === true || value === "") {
    throw new Error(`missing --${key}`);
  }
  return String(value);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function resultPath(runDir) {
  return path.join(runDir, "result.json");
}

function resolveEvidence(runDir, evidence) {
  return path.isAbsolute(evidence) ? evidence : path.join(runDir, evidence);
}

function normalizeMany(value) {
  if (value === undefined) return [];
  return (Array.isArray(value) ? value : [value]).map(String);
}

function hardCheck(value) {
  const separator = value.lastIndexOf("=");
  if (separator <= 0) {
    throw new Error(`hard check must be name=STATUS: ${value}`);
  }
  const status = value.slice(separator + 1).toUpperCase();
  if (!FINAL_STATUSES.has(status)) {
    throw new Error(`invalid hard-check status: ${status}`);
  }
  return { name: value.slice(0, separator), status };
}

function validateScenario(scenario) {
  if (scenario.schema_version !== "v1") throw new Error("scenario schema_version must be v1");
  if (typeof scenario.id !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(scenario.id)) {
    throw new Error("scenario id must be a lowercase kebab-case string");
  }
  if (typeof scenario.title !== "string" || scenario.title.trim() === "") {
    throw new Error("scenario title is required");
  }
  if (typeof scenario.intent !== "string" || scenario.intent.trim() === "") {
    throw new Error("scenario intent is required");
  }
  if (!["single", "federated"].includes(scenario.required_topology)) {
    throw new Error("scenario required_topology must be single or federated");
  }
  if (!Array.isArray(scenario.source_flows) || scenario.source_flows.length === 0) {
    throw new Error("scenario source_flows are required");
  }
  const sourceFlows = new Set();
  for (const sourceFlow of scenario.source_flows) {
    if (
      typeof sourceFlow !== "string" ||
      !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(sourceFlow) ||
      sourceFlows.has(sourceFlow)
    ) {
      throw new Error(`duplicate or invalid source flow: ${sourceFlow}`);
    }
    sourceFlows.add(sourceFlow);
  }
  if (!Array.isArray(scenario.actors) || scenario.actors.length === 0) {
    throw new Error("scenario actors are required");
  }
  const actorIds = new Set();
  for (const actor of scenario.actors) {
    if (!actor || typeof actor !== "object" || Array.isArray(actor)) {
      throw new Error("scenario actors must be objects");
    }
    if (typeof actor.id !== "string" || actor.id.trim() === "" || actorIds.has(actor.id)) {
      throw new Error(`duplicate or missing actor id: ${actor.id}`);
    }
    if (typeof actor.site !== "string" || actor.site.trim() === "") {
      throw new Error(`actor ${actor.id} site is required`);
    }
    if (typeof actor.role !== "string" || actor.role.trim() === "") {
      throw new Error(`actor ${actor.id} role is required`);
    }
    if (scenario.required_topology === "single" && actor.site !== "alpha") {
      throw new Error(`single-topology actor ${actor.id} must use site alpha`);
    }
    if (scenario.required_topology === "federated" && !["alpha", "beta"].includes(actor.site)) {
      throw new Error(`federated actor ${actor.id} site must be alpha or beta`);
    }
    actorIds.add(actor.id);
  }
  const constraints = scenario.agent_constraints;
  if (!constraints || constraints.mutation_surface !== "visible-ui-only") {
    throw new Error("scenario mutation_surface must be visible-ui-only");
  }
  if (!Number.isInteger(constraints.max_attempts_per_checkpoint) || constraints.max_attempts_per_checkpoint < 1) {
    throw new Error("scenario max_attempts_per_checkpoint must be a positive integer");
  }
  for (const key of [
    "read_only_oracles_allowed",
    "allow_testid_locators",
    "allow_dom_eval_for_actions",
    "require_semantic_snapshot_before_action",
  ]) {
    if (typeof constraints[key] !== "boolean") {
      throw new Error(`scenario agent constraint ${key} must be boolean`);
    }
  }
  if (!Array.isArray(scenario.checkpoints) || scenario.checkpoints.length === 0) {
    throw new Error("scenario checkpoints are required");
  }
  const ids = new Set();
  for (const checkpoint of scenario.checkpoints) {
    if (!checkpoint || typeof checkpoint !== "object" || Array.isArray(checkpoint)) {
      throw new Error("scenario checkpoints must be objects");
    }
    if (
      typeof checkpoint.id !== "string" ||
      checkpoint.id.trim() === "" ||
      ids.has(checkpoint.id)
    ) {
      throw new Error(`duplicate or missing checkpoint id: ${checkpoint.id}`);
    }
    ids.add(checkpoint.id);
    if (checkpoint.actor !== "harness" && !actorIds.has(checkpoint.actor)) {
      throw new Error(`checkpoint ${checkpoint.id} uses unknown actor: ${checkpoint.actor}`);
    }
    if (typeof checkpoint.phase !== "string" || checkpoint.phase.trim() === "") {
      throw new Error(`checkpoint ${checkpoint.id} phase is required`);
    }
    if (typeof checkpoint.goal !== "string" || checkpoint.goal.trim() === "") {
      throw new Error(`checkpoint ${checkpoint.id} goal is required`);
    }
    if (typeof checkpoint.required !== "boolean") {
      throw new Error(`checkpoint ${checkpoint.id} required must be boolean`);
    }
    if (!Array.isArray(checkpoint.hard_checks) || checkpoint.hard_checks.length === 0) {
      throw new Error(`checkpoint ${checkpoint.id} hard_checks are required`);
    }
    const hardChecks = new Set();
    for (const check of checkpoint.hard_checks) {
      if (typeof check !== "string" || check.trim() === "" || hardChecks.has(check)) {
        throw new Error(`checkpoint ${checkpoint.id} has duplicate or invalid hard check: ${check}`);
      }
      hardChecks.add(check);
    }
  }
}

function commandValidateScenarios(args) {
  const scenarioDir = path.resolve(required(args, "scenario-dir"));
  const files = fs
    .readdirSync(scenarioDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => entry.name)
    .sort();
  if (files.length === 0) throw new Error(`no scenarios found in ${scenarioDir}`);
  const ids = new Set();
  const scenarios = [];
  for (const file of files) {
    const scenario = readJson(path.join(scenarioDir, file));
    validateScenario(scenario);
    if (ids.has(scenario.id)) throw new Error(`duplicate scenario id: ${scenario.id}`);
    if (file !== `${scenario.id}.json`) {
      throw new Error(`scenario filename ${file} must match id ${scenario.id}`);
    }
    ids.add(scenario.id);
    scenarios.push({
      id: scenario.id,
      topology: scenario.required_topology,
      checkpoints: scenario.checkpoints.length,
      source_flows: scenario.source_flows,
    });
  }
  printJson({ count: scenarios.length, scenarios });
}

function commandInit(args) {
  const scenarioFile = path.resolve(required(args, "scenario"));
  const runDir = path.resolve(required(args, "run-dir"));
  const runId = required(args, "run-id");
  const scenario = readJson(scenarioFile);
  validateScenario(scenario);
  fs.mkdirSync(path.join(runDir, "screenshots"), { recursive: true });
  fs.mkdirSync(path.join(runDir, "profiles"), { recursive: true });
  fs.mkdirSync(path.join(runDir, "diagnostics"), { recursive: true });
  const result = {
    schema_version: "v1",
    run_id: runId,
    scenario_id: scenario.id,
    scenario_title: scenario.title,
    topology: scenario.required_topology,
    status: "RUNNING",
    started_at: new Date().toISOString(),
    finished_at: null,
    runtime_manifest: null,
    actors: scenario.actors,
    checkpoints: scenario.checkpoints.map((checkpoint) => ({
      id: checkpoint.id,
      actor: checkpoint.actor,
      phase: checkpoint.phase,
      goal: checkpoint.goal,
      required: checkpoint.required !== false,
      expected_hard_checks: checkpoint.hard_checks ?? [],
      status: "PENDING",
      attempts: 0,
      hard_checks: [],
      screenshot: null,
      notes: [],
      friction: [],
      completed_at: null,
    })),
  };
  writeJson(resultPath(runDir), result);
  fs.copyFileSync(scenarioFile, path.join(runDir, "scenario.json"));
  fs.writeFileSync(path.join(runDir, "actions.ndjson"), "", "utf8");
  printJson({ run_dir: runDir, result: resultPath(runDir) });
}

function commandBindRuntime(args) {
  const runDir = path.resolve(required(args, "run-dir"));
  const manifestFile = path.resolve(required(args, "runtime-manifest"));
  const result = readJson(resultPath(runDir));
  const runtime = readJson(manifestFile);
  if (runtime.schema_version !== "v1") throw new Error("runtime manifest schema_version must be v1");
  if (runtime.topology !== result.topology) {
    throw new Error(`runtime topology ${runtime.topology} does not satisfy ${result.topology}`);
  }
  if (result.topology === "federated") {
    const requiredIsolation = [
      "distinct_principal_server_processes",
      "distinct_service_identities",
      "distinct_state_roots",
      "distinct_object_roots",
      "distinct_browser_origins",
      "explicit_federation_peer_links",
    ];
    for (const key of requiredIsolation) {
      if (runtime.isolation?.[key] !== true) {
        throw new Error(`federated runtime isolation check failed: ${key}`);
      }
    }
  }
  result.runtime_manifest = path.relative(runDir, manifestFile).replaceAll("\\", "/");
  writeJson(resultPath(runDir), result);
  printJson({ topology: runtime.topology, isolation: runtime.isolation });
}

function commandCheckpoint(args) {
  const runDir = path.resolve(required(args, "run-dir"));
  const id = required(args, "id");
  const actor = required(args, "actor");
  const status = required(args, "status").toUpperCase();
  if (!FINAL_STATUSES.has(status)) throw new Error(`invalid checkpoint status: ${status}`);
  const result = readJson(resultPath(runDir));
  if (result.status !== "RUNNING") throw new Error(`journey is not running: ${result.status}`);
  const checkpoint = result.checkpoints.find((candidate) => candidate.id === id);
  if (!checkpoint) throw new Error(`unknown checkpoint: ${id}`);
  if (checkpoint.actor !== actor) {
    throw new Error(`checkpoint ${id} belongs to ${checkpoint.actor}, not ${actor}`);
  }
  const screenshot = required(args, "screenshot");
  const screenshotFile = resolveEvidence(runDir, screenshot);
  if (!fs.existsSync(screenshotFile) || !fs.statSync(screenshotFile).isFile()) {
    throw new Error(`checkpoint screenshot not found: ${screenshotFile}`);
  }
  const checks = normalizeMany(args["hard-check"]).map(hardCheck);
  if (checks.length === 0) throw new Error("at least one --hard-check is required");
  checkpoint.status = status;
  checkpoint.attempts = Number(args.attempts ?? 1);
  checkpoint.hard_checks = checks;
  checkpoint.screenshot = path.relative(runDir, screenshotFile).replaceAll("\\", "/");
  checkpoint.notes = normalizeMany(args.note);
  checkpoint.friction = normalizeMany(args.friction);
  checkpoint.completed_at = new Date().toISOString();
  writeJson(resultPath(runDir), result);
  printJson({ id, actor, status, screenshot: checkpoint.screenshot });
}

function overallStatus(checkpoints) {
  const statuses = new Set(checkpoints.map((checkpoint) => checkpoint.status));
  for (const candidate of ["HARNESS_FAIL", "PRODUCT_FAIL", "AGENT_FAIL", "INCONCLUSIVE"]) {
    if (statuses.has(candidate)) return candidate;
  }
  return "PASS";
}

function validateResult(runDir, { requireFinished = false, gate = false } = {}) {
  const result = readJson(resultPath(runDir));
  if (result.schema_version !== "v1") throw new Error("result schema_version must be v1");
  if (!RESULT_STATUSES.has(result.status)) throw new Error(`invalid result status: ${result.status}`);
  const missing = [];
  for (const checkpoint of result.checkpoints) {
    if (checkpoint.required && checkpoint.status === "PENDING") missing.push(checkpoint.id);
    if (checkpoint.status !== "PENDING") {
      if (!Array.isArray(checkpoint.hard_checks) || checkpoint.hard_checks.length === 0) {
        throw new Error(`checkpoint ${checkpoint.id} has no hard checks`);
      }
      const hardCheckByName = new Map(
        checkpoint.hard_checks.map((check) => [check.name, check.status]),
      );
      for (const expected of checkpoint.expected_hard_checks ?? []) {
        if (!hardCheckByName.has(expected)) {
          throw new Error(
            `checkpoint ${checkpoint.id} is missing expected hard check: ${expected}`,
          );
        }
      }
      if (
        checkpoint.status === "PASS" &&
        checkpoint.hard_checks.some((check) => check.status !== "PASS")
      ) {
        throw new Error(
          `checkpoint ${checkpoint.id} cannot PASS with a failing hard check`,
        );
      }
      if (!checkpoint.screenshot) throw new Error(`checkpoint ${checkpoint.id} has no screenshot`);
      const screenshotFile = resolveEvidence(runDir, checkpoint.screenshot);
      if (!fs.existsSync(screenshotFile)) {
        throw new Error(`checkpoint ${checkpoint.id} screenshot is missing: ${screenshotFile}`);
      }
    }
  }
  if (requireFinished && missing.length > 0) {
    throw new Error(`required checkpoints are pending: ${missing.join(", ")}`);
  }
  if (requireFinished && result.status === "RUNNING" && gate) {
    throw new Error("result is still RUNNING");
  }
  if (gate && result.status !== "PASS") {
    throw new Error(`journey gate failed with status ${result.status}`);
  }
  return result;
}

function writeSummary(runDir, result) {
  const lines = [
    "# agent journey summary",
    "",
    `- run: ${result.run_id}`,
    `- scenario: ${result.scenario_id}`,
    `- topology: ${result.topology}`,
    `- status: ${result.status}`,
    `- started_at: ${result.started_at}`,
    `- finished_at: ${result.finished_at ?? "-"}`,
    "",
    "## checkpoints",
    "",
    "| id | actor | phase | status | attempts | screenshot |",
    "|---|---|---|---|---:|---|",
  ];
  for (const checkpoint of result.checkpoints) {
    const screenshot = checkpoint.screenshot
      ? `[evidence](${checkpoint.screenshot.replaceAll("\\", "/")})`
      : "-";
    lines.push(
      `| ${checkpoint.id} | ${checkpoint.actor} | ${checkpoint.phase} | ${checkpoint.status} | ${checkpoint.attempts} | ${screenshot} |`,
    );
  }
  const friction = result.checkpoints.flatMap((checkpoint) =>
    checkpoint.friction.map((item) => ({ id: checkpoint.id, item })),
  );
  lines.push("", "## UX friction", "");
  if (friction.length === 0) {
    lines.push("- none recorded");
  } else {
    for (const item of friction) lines.push(`- ${item.id}: ${item.item}`);
  }
  fs.writeFileSync(path.join(runDir, "summary.md"), `${lines.join("\n")}\n`, "utf8");
}

function commandFinish(args) {
  const runDir = path.resolve(required(args, "run-dir"));
  const result = validateResult(runDir, { requireFinished: true });
  result.status = overallStatus(result.checkpoints);
  result.finished_at = new Date().toISOString();
  writeJson(resultPath(runDir), result);
  writeSummary(runDir, result);
  printJson({ status: result.status, summary: path.join(runDir, "summary.md") });
}

function commandAbort(args) {
  const runDir = path.resolve(required(args, "run-dir"));
  const result = readJson(resultPath(runDir));
  result.status = "HARNESS_FAIL";
  result.finished_at = new Date().toISOString();
  result.abort_reason = required(args, "reason");
  writeJson(resultPath(runDir), result);
  writeSummary(runDir, result);
  printJson({ status: result.status, reason: result.abort_reason });
}

function commandValidate(args) {
  const runDir = path.resolve(required(args, "run-dir"));
  const result = validateResult(runDir, {
    requireFinished: args.finished === true,
    gate: args.gate === true,
  });
  printJson({ status: result.status, checkpoints: result.checkpoints.length });
}

function printJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

try {
  const [command, ...values] = process.argv.slice(2);
  const args = parseArgs(values);
  switch (command) {
    case "init":
      commandInit(args);
      break;
    case "bind-runtime":
      commandBindRuntime(args);
      break;
    case "checkpoint":
      commandCheckpoint(args);
      break;
    case "finish":
      commandFinish(args);
      break;
    case "abort":
      commandAbort(args);
      break;
    case "validate":
      commandValidate(args);
      break;
    case "validate-scenarios":
      commandValidateScenarios(args);
      break;
    default:
      throw new Error(`unknown command: ${command ?? "<missing>"}`);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
