import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { orderByCanonicalKey } from "../helpers/direct-structure-order.ts";
import { canonicalJson } from "../helpers/coland-api/wire-client.ts";

test("precomputed SDK canonical keys preserve the original comparator and all full rows", () => {
  assert.ok(process.env.COTEST_WIRE_BIN && existsSync(process.env.COTEST_WIRE_BIN),
    "COTEST_WIRE_BIN must identify an existing executable; never fall back to Cargo");
  // Public selectors exercise the real SDK canonical oracle, not local JCS.
  const rows = [
    { selector: { kind: "realm_history_access" }, current: { value: 1 } },
    { selector: { kind: "realm_genesis" }, current: { value: 2 } },
    { selector: { kind: "realm_authority_root" }, current: { value: 3 } },
  ];
  const expected = [...rows].sort((a, b) => canonicalJson(a.selector).localeCompare(canonicalJson(b.selector)));
  let calls = 0;
  const actual = orderByCanonicalKey(rows, row => { calls++; return canonicalJson(row.selector); });
  assert.equal(calls, rows.length);
  assert.deepEqual(actual, expected);
  for (const row of actual) assert.equal(rows.includes(row), true);
});

test("equal canonical keys retain duplicate rows and their original stable order", () => {
  const rows = [
    { selector: "b", value: "later-key" },
    { selector: "a", value: "first-duplicate" },
    { selector: "a", value: "second-duplicate" },
  ];
  const actual = orderByCanonicalKey(rows, row => row.selector);
  assert.deepEqual(actual, [rows[1], rows[2], rows[0]]);
  assert.equal(actual.length, rows.length);
  assert.deepEqual(rows.map(row => row.value), ["later-key", "first-duplicate", "second-duplicate"]);
});

test("same selectors never hide a full-row mutation or cache keys across snapshots", () => {
  let calls = 0;
  const key = row => { calls++; return row.selector; };
  const before = [{ selector: "b", revision: 2, value: { name: "original" } }, { selector: "a", revision: 1 }];
  const original = orderByCanonicalKey(before, key);
  const same = orderByCanonicalKey(structuredClone(before).reverse(), key);
  assert.deepEqual(same, original);
  assert.equal(calls, before.length * 2);
  const changed = structuredClone(before);
  changed[0].value.name = "changed";
  const after = orderByCanonicalKey(changed, key);
  assert.notDeepEqual(after, original);
  assert.equal(calls, before.length * 3);
  assert.equal(original[1].value.name, "original");
});

test("empty snapshots invoke no oracle and canonical failures propagate", () => {
  assert.deepEqual(orderByCanonicalKey([], () => assert.fail("unexpected oracle call")), []);
  assert.throws(() => orderByCanonicalKey([{ selector: "a" }], () => { throw new Error("oracle failed"); }),
    /oracle failed/);
});
