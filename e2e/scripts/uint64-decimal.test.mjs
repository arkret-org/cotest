// Canonical unsigned-decimal tests for the existing wire-type gate.
import assert from "node:assert/strict";
import { test } from "node:test";
import { uint64Decimal, uint64Value } from "../helpers/uint64-decimal.ts";

test("canonical u64 strings retain full precision and remain strings on the wire", () => {
  for (const value of ["0", "1", "9007199254740991", "9007199254740992", "9007199254740993", "18446744073709551615"]) {
    assert.equal(uint64Decimal(value), value);
    assert.equal(uint64Value(value).toString(), value);
  }
  assert.equal(uint64Value("9007199254740992") + 1n, uint64Value("9007199254740993"));
});

test("JSON numbers, bigint values and other nonstring alternatives are rejected", () => {
  for (const value of [0, 1, 1n, 9007199254740992, NaN, Infinity, null, undefined, true, {}, []]) {
    assert.throws(() => uint64Decimal(value), /canonical uint64/);
  }
});

test("noncanonical spellings, Unicode digits and whitespace are rejected", () => {
  for (const value of ["", "00", "01", "+0", "-0", "-1", "1.0", "1e0", " 1", "1 ", "\n1", "1\n", "１", "١"]) {
    assert.throws(() => uint64Decimal(value), /canonical uint64/);
  }
});

test("overflow is rejected rather than wrapped or rounded", () => {
  for (const value of ["18446744073709551616", "99999999999999999999", "100000000000000000000"]) {
    assert.throws(() => uint64Value(value), /canonical uint64/);
  }
});

test("saved epoch evidence stays a JSON string while comparisons are lossless", () => {
  const oldEpoch = uint64Decimal("9007199254740993");
  const encoded = JSON.stringify({ historical_epoch_advanced_from: oldEpoch });
  assert.equal(encoded, '{"historical_epoch_advanced_from":"9007199254740993"}');
  assert.equal(JSON.parse(encoded).historical_epoch_advanced_from, oldEpoch);
  assert.equal(uint64Value(oldEpoch), 9007199254740993n);
  assert.throws(() => JSON.stringify({ historical_epoch_advanced_from: uint64Value(oldEpoch) }), TypeError);
});
