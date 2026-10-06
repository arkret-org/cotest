import assert from "node:assert/strict";
import test from "node:test";
import { SessionDiagnostics } from "../helpers/session-diagnostics.ts";

test("small diagnostics retain all lines in arrival order", () => {
  const log = new SessionDiagnostics();
  assert.deepEqual(log.lines(), []);
  for (let i = 0; i < 4999; i++) log.push(String(i));
  assert.deepEqual(log.lines(), Array.from({ length: 4999 }, (_, i) => String(i)));
});

test("overflow retains startup and latest failures with exact omission accounting", () => {
  const log = new SessionDiagnostics();
  for (let i = 0; i < 14000; i++) log.push(String(i));
  const lines = log.lines();
  assert.equal(lines.length, 5000);
  assert.deepEqual(lines.slice(0, 1000), Array.from({ length: 1000 }, (_, i) => String(i)));
  assert.deepEqual(JSON.parse(lines[1000]), {
    type: "diagnostic_truncated", retained_lines: 4999, omitted_lines: 9001,
  });
  assert.deepEqual(lines.slice(1001), Array.from({ length: 3999 }, (_, i) => String(10001 + i)));
  assert.equal(log.join("\n"), lines.join("\n"));
  log.push("late Sidecar failure");
  assert.equal(log.lines().at(-1), "late Sidecar failure");
  assert.equal(JSON.parse(log.lines()[1000]).omitted_lines, 9002);
  assert.equal(lines.at(-1), "13999", "snapshots must not mutate after later writes");
});

test("line size remains bounded independently of the ring", () => {
  const log = new SessionDiagnostics();
  log.push("a".repeat(4000));
  log.push("b".repeat(4001));
  assert.equal(log.lines()[0], "a".repeat(4000));
  assert.equal(log.lines()[1], `${"b".repeat(4000)}... [truncated]`);
});
