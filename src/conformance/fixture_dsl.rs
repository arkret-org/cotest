//! Shared accessor layer for fixture-backed conformance suites.
//!
//! Every conformance suite reads its vectors out of a JSON fixture, so each
//! suite used to carry a private copy of the same "read one field or fail"
//! helpers (`required_str`, `required_u64`, `expected_str`, `string_set`, …).
//! Those copies were byte-identical apart from the wording of the error
//! message, which meant a fixture-shape change had to be chased through two
//! dozen files.
//!
//! This module is the single definition. It is deliberately limited to
//! *accessors*: reading a field out of a `serde_json::Value` and turning a
//! missing or wrongly-typed field into an `anyhow::Error`. It carries no
//! protocol judgement of its own — every assertion about what a fixture value
//! must *say* stays in the suite that owns the vector, because that assertion
//! is the conformance evidence.
//!
//! Two families exist:
//!
//! * `required_*` — read `value[field]` (the case object itself).
//! * `expected_*` — read `value["expected"][field]` (the case's expectation block), which fixtures
//!   model as a nested object.
//!
//! Suites whose accessors carry an *extra* check (rejecting empty strings,
//! requiring a `sha256:` digest, forbidding duplicates) keep their own
//! definition on purpose: that check is part of the vector's judgement, not
//! boilerplate.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

// ── Raw field access ────────────────────────────────────────────────────────

/// Read a field as an untyped `Value`, failing when the field is absent.
///
/// Note this reads through `Value::get`, so a non-object `value` is reported
/// as a missing field rather than panicking.
pub(crate) fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

pub(crate) fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

pub(crate) fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing u64 field {field}"))
}

pub(crate) fn required_i64(value: &Value, field: &str) -> Result<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("missing i64 field {field}"))
}

pub(crate) fn required_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("missing bool field {field}"))
}

pub(crate) fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

pub(crate) fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing array field {field}"))
}

// ── Field access on an already-destructured object ──────────────────────────

pub(crate) fn required_str_obj<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

// ── The `expected` block ────────────────────────────────────────────────────

/// Borrow a case's `expected` block.
pub(crate) fn expected(value: &Value) -> Result<&Value> {
    value
        .get("expected")
        .ok_or_else(|| anyhow!("missing expected object"))
}

pub(crate) fn expected_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing expected.{field}"))
}

pub(crate) fn expected_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("case missing bool expected.{field}"))
}

pub(crate) fn expected_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("case missing u64 expected.{field}"))
}

/// Optional variants: an absent `expected.<field>` is `None`, but a present
/// field of the wrong type is still an error. Fixtures use this where the
/// expectation only applies to some cases.
pub(crate) fn expected_str_opt<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>> {
    match value.pointer(&format!("/expected/{field}")) {
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => bail!("expected.{field} must be a string"),
        None => Ok(None),
    }
}

pub(crate) fn expected_u64_opt(value: &Value, field: &str) -> Result<Option<u64>> {
    match value.pointer(&format!("/expected/{field}")) {
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("expected.{field} must be u64")),
        Some(_) => bail!("expected.{field} must be u64"),
        None => Ok(None),
    }
}

// ── String collections ──────────────────────────────────────────────────────

/// Borrowed string set from a required array field.
pub(crate) fn string_set<'a>(value: &'a Value, field: &str) -> Result<BTreeSet<&'a str>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect()
}

/// Owned string set where `value` *is* the array (no field indirection).
pub(crate) fn string_set_of(value: &Value) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("expected string array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("expected string array item"))
        })
        .collect()
}

/// Owned string vector from a required array field.
pub(crate) fn string_vec(value: &Value, field: &str) -> Result<Vec<String>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect()
}

/// Borrowed string vector from an *optional* array field: an absent field
/// yields an empty vector. Retained separately from [`string_vec`] because a
/// handful of suites treat "field absent" and "field empty" alike.
pub(crate) fn string_array_field<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| anyhow!("{field} entry must be a string"))
        })
        .collect()
}

// ── Fixture envelope shape ──────────────────────────────────────────────────

/// The `runner` block every spec fixture carries.
///
/// `deny_unknown_fields` matches the fixtures that already declared it; suites
/// that intentionally read `runner` as a free-form `Value` keep doing so.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixtureRunner {
    pub(crate) kind: String,
    pub(crate) entrypoint: String,
}
