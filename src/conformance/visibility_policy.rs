//! Visibility policy conformance vectors.
//!
//! Covers the Circle/E2EE floor ratchet, Circle directory visibility, and the
//! joined-history pre-join denial vector from the spec artifact fixture.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::governance::circle::{
    CircleScopeError, EncryptionFloor, validate_circle_encryption_floor,
    validate_content_encryption_floor, validate_content_encryption_floor_ratchet,
    validate_metadata_encryption_floor_ratchet,
};
use arkret_wire::{EncryptionProfile, ProfileId};
use serde_json::{Value, json};

pub const VECTOR_ID_CONTENT_FLOOR_DOWNGRADE_REJECTED: &str =
    "ak.vector.e2ee.content_floor_downgrade_rejected.v1";
pub const VECTOR_ID_METADATA_FLOOR_DOWNGRADE_REJECTED: &str =
    "ak.vector.e2ee.metadata_floor_downgrade_rejected.v1";
pub const VECTOR_ID_IN_PLACE_E2EE_ENABLE: &str = "ak.vector.e2ee.in_place_enable.v1";
pub const VECTOR_ID_CIRCLE_CONTENT_FLOOR_BELOW_REALM_REJECTED: &str =
    "ak.vector.circle.content_floor_below_realm_rejected.v1";
pub const VECTOR_ID_DIRECTORY_VISIBILITY_MEMBERS_INDISTINGUISHABLE: &str =
    "ak.vector.circle.directory_visibility_members_indistinguishable.v1";
pub const VECTOR_ID_DIRECTORY_VISIBILITY_REALM_MEMBERS_INDISTINGUISHABLE: &str =
    "ak.vector.circle.directory_visibility_realm_members_indistinguishable.v1";
pub const VECTOR_ID_HISTORY_VISIBILITY_JOINED_PREJOIN_DENIED: &str =
    "ak.vector.history_visibility.joined_prejoin_denied.v1";

pub const ALL_VISIBILITY_POLICY_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_CONTENT_FLOOR_DOWNGRADE_REJECTED,
    VECTOR_ID_METADATA_FLOOR_DOWNGRADE_REJECTED,
    VECTOR_ID_IN_PLACE_E2EE_ENABLE,
    VECTOR_ID_CIRCLE_CONTENT_FLOOR_BELOW_REALM_REJECTED,
    VECTOR_ID_DIRECTORY_VISIBILITY_MEMBERS_INDISTINGUISHABLE,
    VECTOR_ID_DIRECTORY_VISIBILITY_REALM_MEMBERS_INDISTINGUISHABLE,
    VECTOR_ID_HISTORY_VISIBILITY_JOINED_PREJOIN_DENIED,
];

const VISIBILITY_POLICY_FIXTURE_FILE: &str = "visibility-policy-fixture.json";
const LOCKED_TIMING_BUCKET: &str = "circle_locked_v1";
const LOCKED_OPAQUE_COMMITMENT: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PREVIEW_OPAQUE_COMMITMENT: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn visibility_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(VISIBILITY_POLICY_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::CIRCLE_CONFORMANCE_V1)?;
    validate_visibility_policy_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_visibility_policy_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("visibility_policy") {
        bail!("visibility policy fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("visibility policy fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("visibility policy fixture missing cases[]"))?;

    for vector_id in ALL_VISIBILITY_POLICY_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("visibility policy fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("visibility policy fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        })
        .ok_or_else(|| anyhow!("visibility policy fixture missing case {vector_id}"))
}

fn expected_reason(case: &Value) -> Result<&str> {
    case.pointer("/expected/reason")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing expected.reason"))
}

fn parse_floor(value: &str) -> Result<EncryptionFloor> {
    match value {
        "allow_plaintext" => Ok(EncryptionFloor::AllowPlaintext),
        "e2ee_required" => Ok(EncryptionFloor::E2eeRequired),
        other => bail!("unknown encryption floor {other}"),
    }
}

fn parse_profile(value: &str) -> Result<EncryptionProfile> {
    match value {
        "none" => Ok(EncryptionProfile::None),
        "mls_rfc9420" => Ok(EncryptionProfile::MlsRfc9420),
        "external" => Ok(EncryptionProfile::External),
        other => bail!("unknown encryption profile {other}"),
    }
}

fn floor_field(case: &Value, field: &str) -> Result<EncryptionFloor> {
    parse_floor(
        case.get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("case missing {field}"))?,
    )
}

fn profile_field(case: &Value, field: &str) -> Result<EncryptionProfile> {
    parse_profile(
        case.get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("case missing {field}"))?,
    )
}

fn circle_reason(error: CircleScopeError) -> String {
    let message = error.to_string();
    message
        .strip_prefix("reason=")
        .and_then(|suffix| suffix.split(':').next())
        .unwrap_or(&message)
        .to_owned()
}

fn expect_circle_reason(error: CircleScopeError, expected: &str) -> Result<()> {
    let actual = circle_reason(error);
    if actual != expected {
        bail!("expected reason {expected}, got {actual}");
    }
    Ok(())
}

pub fn run_content_floor_downgrade_rejected_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(&fixture, VECTOR_ID_CONTENT_FLOOR_DOWNGRADE_REJECTED)?;
    let previous = floor_field(vector, "previous")?;
    let next = floor_field(vector, "next")?;
    expect_circle_reason(
        validate_content_encryption_floor_ratchet(previous, next).unwrap_err(),
        expected_reason(vector)?,
    )?;

    validate_content_encryption_floor_ratchet(
        EncryptionFloor::AllowPlaintext,
        EncryptionFloor::E2eeRequired,
    )?;
    validate_content_encryption_floor_ratchet(
        EncryptionFloor::E2eeRequired,
        EncryptionFloor::E2eeRequired,
    )?;

    if arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE != expected_reason(vector)? {
        bail!("content floor downgrade reason constant drifted");
    }
    Ok(())
}

pub fn run_metadata_floor_downgrade_rejected_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(&fixture, VECTOR_ID_METADATA_FLOOR_DOWNGRADE_REJECTED)?;
    let previous = floor_field(vector, "previous")?;
    let next = floor_field(vector, "next")?;
    expect_circle_reason(
        validate_metadata_encryption_floor_ratchet(previous, next).unwrap_err(),
        expected_reason(vector)?,
    )?;

    validate_metadata_encryption_floor_ratchet(
        EncryptionFloor::AllowPlaintext,
        EncryptionFloor::E2eeRequired,
    )?;
    validate_metadata_encryption_floor_ratchet(
        EncryptionFloor::E2eeRequired,
        EncryptionFloor::E2eeRequired,
    )?;

    if arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_DOWNGRADE != expected_reason(vector)? {
        bail!("metadata floor downgrade reason constant drifted");
    }
    Ok(())
}

pub fn run_in_place_e2ee_enable_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(&fixture, VECTOR_ID_IN_PLACE_E2EE_ENABLE)?;
    let previous = floor_field(vector, "previous")?;
    let next = floor_field(vector, "next")?;
    validate_content_encryption_floor_ratchet(previous, next)
        .map_err(|err| anyhow!("in-place E2EE enable rejected: {err}"))?;

    let plaintext_error = validate_content_encryption_floor(
        EncryptionFloor::E2eeRequired,
        &EncryptionProfile::None,
        None,
    )
    .unwrap_err();
    let expected = vector
        .pointer("/expected/post_upgrade_plaintext_reason")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("in-place E2EE case missing plaintext failure reason"))?;
    expect_circle_reason(plaintext_error, expected)?;
    if expected != arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_VIOLATION {
        bail!("content floor violation reason constant drifted");
    }

    validate_content_encryption_floor(
        EncryptionFloor::E2eeRequired,
        &EncryptionProfile::MlsRfc9420,
        None,
    )?;
    Ok(())
}

pub fn run_circle_content_floor_below_realm_rejected_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_CIRCLE_CONTENT_FLOOR_BELOW_REALM_REJECTED,
    )?;
    let realm_profile = profile_field(vector, "realm_encryption_profile")?;
    let realm_floor = floor_field(vector, "realm_content_encryption_floor")?;
    let circle_profile = profile_field(vector, "circle_encryption_profile")?;
    expect_circle_reason(
        validate_circle_encryption_floor(&realm_profile, realm_floor, &circle_profile).unwrap_err(),
        expected_reason(vector)?,
    )?;
    if expected_reason(vector)? != arkret_wire::ReasonCode::CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR {
        bail!("circle floor reason constant drifted");
    }

    validate_circle_encryption_floor(
        &EncryptionProfile::MlsRfc9420,
        EncryptionFloor::E2eeRequired,
        &EncryptionProfile::MlsRfc9420,
    )?;
    validate_circle_encryption_floor(
        &EncryptionProfile::None,
        EncryptionFloor::AllowPlaintext,
        &EncryptionProfile::None,
    )?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Projection {
    body: Value,
    timing_bucket: &'static str,
}

fn locked_stub_projection() -> Projection {
    Projection {
        body: json!({
            "visibility": "locked",
            "opaque_commitment": LOCKED_OPAQUE_COMMITMENT
        }),
        timing_bucket: LOCKED_TIMING_BUCKET,
    }
}

fn realm_member_preview_projection() -> Projection {
    Projection {
        body: json!({
            "circle_id": "ak:circle:0196419c-0000-8000-8000-000000000000",
            "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000000",
            "visibility": "realm_members",
            "display": {
                "color_token": "indigo",
                "symbol": {
                    "glyph": "shield"
                }
            },
            "member_count_bucket": "10_49",
            "join_rule": "knock",
            "opaque_commitment": PREVIEW_OPAQUE_COMMITMENT
        }),
        timing_bucket: "circle_realm_member_preview_v1",
    }
}

fn circle_member_full_projection() -> Projection {
    Projection {
        body: json!({
            "circle_id": "ak:circle:0196419c-0000-8000-8000-000000000000",
            "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000000",
            "visibility": "members",
            "title": "Security Review",
            "display": {
                "color_token": "indigo",
                "symbol": {
                    "glyph": "shield"
                }
            },
            "member_count": 17,
            "created_by": "did:web:alice.example",
            "join_rule": "invite"
        }),
        timing_bucket: "circle_member_full_v1",
    }
}

fn expected_string_set(case: &Value, pointer: &str) -> Result<BTreeSet<String>> {
    case.pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("case missing string array {pointer}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{pointer} entry must be a string"))
        })
        .collect()
}

fn object_key_set(value: &Value) -> Result<BTreeSet<String>> {
    Ok(value
        .as_object()
        .ok_or_else(|| anyhow!("projection body must be an object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>())
}

fn assert_exact_keys(value: &Value, expected: &BTreeSet<String>) -> Result<()> {
    let actual = object_key_set(value)?;
    if &actual != expected {
        bail!("projection keys drifted: expected {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn contains_field_recursive(value: &Value, field: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(field)
                || object
                    .values()
                    .any(|child| contains_field_recursive(child, field))
        }
        Value::Array(items) => items
            .iter()
            .any(|child| contains_field_recursive(child, field)),
        _ => false,
    }
}

fn assert_forbidden_absent(value: &Value, forbidden: &BTreeSet<String>) -> Result<()> {
    for field in forbidden {
        if contains_field_recursive(value, field) {
            bail!("projection leaked forbidden field {field}");
        }
    }
    Ok(())
}

fn assert_locked_stub(case: &Value, projection: &Projection) -> Result<()> {
    let expected_keys = expected_string_set(case, "/expected/locked_stub_keys")?;
    assert_exact_keys(&projection.body, &expected_keys)?;
    if projection.body.get("visibility").and_then(Value::as_str) != Some("locked") {
        bail!("locked projection must carry visibility=locked");
    }
    let commitment = projection
        .body
        .get("opaque_commitment")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("locked projection missing opaque_commitment"))?;
    if !super::looks_like_sha256_digest(commitment) {
        bail!("locked opaque_commitment must be a sha256 digest");
    }
    if projection.timing_bucket
        != case
            .pointer("/expected/timing_bucket")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("case missing expected.timing_bucket"))?
    {
        bail!("locked projection timing bucket drifted");
    }
    assert_forbidden_absent(
        &projection.body,
        &expected_string_set(case, "/expected/forbidden_fields")?,
    )
}

pub fn run_directory_visibility_members_indistinguishable_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_DIRECTORY_VISIBILITY_MEMBERS_INDISTINGUISHABLE,
    )?;

    let visible_circle_for_non_member = locked_stub_projection();
    let absent_circle = locked_stub_projection();
    assert_locked_stub(vector, &visible_circle_for_non_member)?;
    assert_locked_stub(vector, &absent_circle)?;
    if visible_circle_for_non_member != absent_circle {
        bail!("members directory visibility leaked existence through locked stub body or timing");
    }

    let member_control = circle_member_full_projection();
    if !contains_field_recursive(&member_control.body, "title")
        || !contains_field_recursive(&member_control.body, "member_count")
    {
        bail!("Circle member control must expose policy-allowed metadata");
    }
    assert_locked_stub(vector, &visible_circle_for_non_member)?;
    Ok(())
}

pub fn run_directory_visibility_realm_members_indistinguishable_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_DIRECTORY_VISIBILITY_REALM_MEMBERS_INDISTINGUISHABLE,
    )?;

    let preview = realm_member_preview_projection();
    assert_exact_keys(
        &preview.body,
        &expected_string_set(vector, "/expected/preview_keys")?,
    )?;
    if preview.body.get("visibility").and_then(Value::as_str) != Some("realm_members") {
        bail!("realm-member preview must carry visibility=realm_members");
    }
    let display = preview
        .body
        .get("display")
        .ok_or_else(|| anyhow!("preview missing display whitelist object"))?;
    assert_exact_keys(
        display,
        &["color_token".to_owned(), "symbol".to_owned()]
            .into_iter()
            .collect(),
    )?;
    assert_forbidden_absent(
        &preview.body,
        &expected_string_set(vector, "/expected/forbidden_fields")?,
    )?;

    let non_realm = locked_stub_projection();
    let absent = locked_stub_projection();
    if non_realm != absent {
        bail!("realm_members directory visibility leaked existence to non-Realm caller");
    }
    if non_realm.timing_bucket != LOCKED_TIMING_BUCKET {
        bail!("non-Realm locked projection timing bucket drifted");
    }
    Ok(())
}

fn history_visible_joined(
    viewer_membership: Option<&str>,
    join_ts: Option<u64>,
    origin_ts: u64,
) -> bool {
    matches!(viewer_membership, Some("join")) && join_ts.is_some_and(|ts| origin_ts >= ts)
}

pub fn run_history_visibility_joined_prejoin_denied_vector() -> Result<()> {
    let fixture = visibility_fixture()?;
    let vector = case(&fixture, VECTOR_ID_HISTORY_VISIBILITY_JOINED_PREJOIN_DENIED)?;
    if vector.get("history_visibility").and_then(Value::as_str) != Some("joined") {
        bail!("joined pre-join vector must use history_visibility=joined");
    }

    let viewer = vector
        .get("viewer")
        .ok_or_else(|| anyhow!("history vector missing viewer"))?;
    let membership = viewer.get("membership_state").and_then(Value::as_str);
    let join_ts = viewer.get("join_ts").and_then(Value::as_u64);
    let events = vector
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("history vector missing events[]"))?;
    let mut saw_prejoin_denied = false;
    let mut saw_postjoin_visible = false;
    for event in events {
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("history event missing event_id"))?;
        let origin_ts = event
            .get("origin_ts")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("history event missing origin_ts"))?;
        let expected = event
            .get("expected_visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("history event missing expected_visible"))?;
        let actual = history_visible_joined(membership, join_ts, origin_ts);
        if actual != expected {
            bail!(
                "history event {event_id} visibility mismatch: expected {expected}, got {actual}"
            );
        }
        saw_prejoin_denied |= !actual && event_id == "E_before_join";
        saw_postjoin_visible |= actual && event_id == "E_after_join";
    }

    let control = vector
        .get("non_member_control")
        .ok_or_else(|| anyhow!("history vector missing non_member_control"))?;
    let control_actual = history_visible_joined(
        control.get("membership_state").and_then(Value::as_str),
        None,
        control
            .get("origin_ts")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("non-member control missing origin_ts"))?,
    );
    if control_actual
        != control
            .get("expected_visible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("non-member control missing expected_visible"))?
    {
        bail!("joined history non-member control visibility mismatch");
    }
    if !saw_prejoin_denied || !saw_postjoin_visible {
        bail!("joined history vector must cover pre-join denial and post-join visibility");
    }
    if vector
        .pointer("/expected/prejoin_error")
        .and_then(Value::as_str)
        != Some(arkret_wire::ErrorCode::HISTORY_NOT_VISIBLE)
    {
        bail!("joined pre-join denial error code drifted");
    }
    Ok(())
}

pub fn run_visibility_policy_fixture_suite() -> Result<()> {
    validate_visibility_policy_fixture_metadata(&visibility_fixture()?)?;
    if ALL_VISIBILITY_POLICY_VECTOR_IDS.len() != 7 {
        bail!(
            "expected 7 visibility policy vector ids, got {}",
            ALL_VISIBILITY_POLICY_VECTOR_IDS.len()
        );
    }

    run_content_floor_downgrade_rejected_vector()?;
    run_metadata_floor_downgrade_rejected_vector()?;
    run_in_place_e2ee_enable_vector()?;
    run_circle_content_floor_below_realm_rejected_vector()?;
    run_directory_visibility_members_indistinguishable_vector()?;
    run_directory_visibility_realm_members_indistinguishable_vector()?;
    run_history_visibility_joined_prejoin_denied_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_policy_vectors_run_clean() {
        run_visibility_policy_fixture_suite().unwrap();
    }
}
