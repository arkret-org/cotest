import assert from "node:assert/strict";
import test from "node:test";
import { SessionDiagnostics, sessionDiagnosticPriority } from "../helpers/session-diagnostics.ts";

test("small diagnostics retain all lines in arrival order", () => {
  const log = new SessionDiagnostics();
  assert.deepEqual(log.lines(), []);
  for (let i = 0; i < 3999; i++) log.push(String(i));
  assert.deepEqual(log.lines(), Array.from({ length: 3999 }, (_, i) => String(i)));
});

test("overflow retains startup and latest failures with exact omission accounting", () => {
  const log = new SessionDiagnostics();
  for (let i = 0; i < 14000; i++) log.push(String(i));
  const lines = log.lines();
  assert.equal(lines.length, 4000);
  assert.deepEqual(lines.slice(0, 1000), Array.from({ length: 1000 }, (_, i) => String(i)));
  assert.deepEqual(JSON.parse(lines[1000]), {
    type: "diagnostic_truncated", retained_lines: 3999, omitted_lines: 10001,
  });
  assert.deepEqual(lines.slice(1001), Array.from({ length: 2999 }, (_, i) => String(11001 + i)));
  assert.equal(log.join("\n"), lines.join("\n"));
  log.push("late Sidecar failure");
  assert.equal(log.lines().at(-1), "late Sidecar failure");
  assert.equal(JSON.parse(log.lines()[1000]).omitted_lines, 10002);
  assert.equal(lines.at(-1), "13999", "snapshots must not mutate after later writes");
});

test("routine floods cannot evict sparse critical errors or preparation phases", () => {
  const log = new SessionDiagnostics();
  for (let i = 0; i < 1000; i++) log.push(`head-${i}`);
  log.push("Genesis accepted", "phase");
  log.push("signed current read failed", "critical");
  for (let i = 0; i < 10000; i++) log.push(`render-${i}`);
  const lines = log.lines();
  assert.equal(lines.length, 4002);
  assert.deepEqual(lines.slice(1001, 1003), ["Genesis accepted", "signed current read failed"]);
  assert.equal(lines.at(-1), "render-9999");
  assert.equal(JSON.parse(lines[1000]).omitted_lines, 7001);
});

test("all shares remain bounded and snapshots retain arrival order", () => {
  const log = new SessionDiagnostics();
  for (let i = 0; i < 1000; i++) log.push(`head-${i}`);
  for (let i = 0; i < 6000; i++) {
    log.push(`normal-${i}`, "normal");
    log.push(`critical-${i}`, "critical");
    log.push(`phase-${i}`, "phase");
  }
  const lines = log.lines();
  assert.equal(lines.length, 5000);
  const marker = JSON.parse(lines[1000]);
  assert.equal(marker.retained_lines, 4999);
  assert.equal(marker.omitted_lines + marker.retained_lines, 19000);
  assert.deepEqual(lines.slice(-3), ["normal-5999", "critical-5999", "phase-5999"]);
  assert.equal(lines.filter((line) => line.startsWith("critical-")).length, 500);
  assert.equal(lines.filter((line) => line.startsWith("phase-")).length, 500);
});

test("structured diagnostic classification keeps sparse errors apart from render noise", () => {
  const classify = (row) => sessionDiagnosticPriority(JSON.stringify(row));
  assert.equal(classify({ type: "log", text: "joint Sidecar preparation stage stage = genesis_accepted" }), "phase");
  assert.equal(classify({ type: "log", text: "Sidecar access preparation will resume" }), "critical");
  assert.equal(classify({ type: "log", text: "joint card member current eligibility" }), "normal");
  assert.equal(classify({ type: "pageerror", text: "failure" }), "critical");
  assert.equal(classify({ type: "http-error", status: 503 }), "critical");
  assert.equal(classify({ type: "log", text: { unexpected: true } }), "normal");
  assert.equal(classify(null), "normal");
  assert.equal(sessionDiagnosticPriority("not JSON"), "normal");
});

test("line size remains bounded independently of the ring", () => {
  const log = new SessionDiagnostics();
  log.push("a".repeat(4000));
  log.push("b".repeat(4001));
  assert.equal(log.lines()[0], "a".repeat(4000));
  assert.equal(log.lines()[1], `${"b".repeat(4000)}... [truncated]`);
});
