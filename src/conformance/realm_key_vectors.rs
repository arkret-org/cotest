//! `ak.realm_key.*` payload conformance vectors.
//!
//! Vector-level (offline) coverage for the direct history-key delivery pair
//! `ak.realm_key.request` / `ak.realm_key.share` (device-lifecycle.md §13):
//!
//! * schema conformance of the request content against
//!   `device-message.schema.json#/$defs/realm_key_request_content` and of the share payload against
//!   `event-payload.schema.json#/$defs/realm_key_share_payload`, driven through the SDK strong
//!   types so wire shape and Rust shape are pinned to each other;
//! * the registered `ak.vector.realm_key.share_sender_signature.v1` vector: byte-exact sender-proof
//!   transcript KAT (canonical JSON, unselected branch/material/optional fields omitted, `context =
//!   ak.realm-key-share-sender-proof-v1`), a real Ed25519 sign/verify positive, and the fixture's
//!   negative mutations failing closed.
//!
//! The reducer-side `ak.vector.realm_key.withheld_policy_basis.v1` (policy
//! root resolution at the Event CBA/T0 basis) needs accepted-log state and
//! stays out of scope here; only the withheld payload's wire shape is pinned.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_models_collaboration::events_payloads::{
    RealmKeyRequestPayload, RealmKeySharePayload, RealmKeyWithheldPayload,
};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde_json::{Value, json};

use super::schema_validation_fixture::SchemaEnv;

pub const VECTOR_ID_REALM_KEY_SHARE_SENDER_SIGNATURE: &str =
    "ak.vector.realm_key.share_sender_signature.v1";

const REALM_KEY_REQUEST_CONTENT_SCHEMA: &str =
    "schemas/device-message.schema.json#/$defs/realm_key_request_content";
const REALM_KEY_SHARE_PAYLOAD_SCHEMA: &str =
    "schemas/event-payload.schema.json#/$defs/realm_key_share_payload";
const REALM_KEY_WITHHELD_PAYLOAD_SCHEMA: &str =
    "schemas/event-payload.schema.json#/$defs/realm_key_withheld_payload";

const FIXTURE_FILE: &str = "state-reducer-hardening-fixture.json";

const RECIPIENT_PRINCIPAL: &str = "ak:did_core:webvh:z6mkfixture";
const RECIPIENT_DEVICE: &str = "ak:device:019f9000-0000-7000-8000-000000000003";
const SENDER_DEVICE: &str = "ak:device:019f9000-0000-7000-8000-000000000004";
const SOURCE_AUTHORIZATION_REF: &str = "ak:event:Adl8EVE0XuYmtOeRAa0WJVGy5DWansCGrXuwPONweuzs";
const REALM_ID: &str = "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy";
const POLICY_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CREATED_AT: &str = "2026-07-26T00:00:00.000Z";

/// The sender-proof transcript negative mutations this suite implements.
/// Checked against the spec fixture so a fixture-side extension fails loudly
/// here instead of silently going uncovered.
const IMPLEMENTED_SHARE_MUTATIONS: &[&str] = &[
    "unselected_target_written_as_null",
    "cross_variant_target_present",
    "ciphertext_and_encrypted_key_ref_both_present",
    "material_missing",
    "expires_at_tampered",
    "source_authorization_ref_tampered",
    "key_scope_tampered",
    "signature_kid_sender_device_mismatch",
];

pub fn run_realm_key_payload_vector_suite() -> Result<()> {
    let env = SchemaEnv::load()?;
    validate_share_sender_signature_fixture_case()?;
    run_request_content_schema_cases(&env)?;
    run_share_payload_schema_cases(&env)?;
    run_withheld_payload_schema_case(&env)?;
    run_share_sender_signature_vector()?;
    eprintln!("[cotest realm_key_vectors] request/share/withheld schema + sender-signature KAT ok");
    Ok(())
}

/// Pin this suite to the spec fixture's registered case so mutation-list or
/// variant drift in `state-reducer-hardening-fixture.json` is caught.
fn validate_share_sender_signature_fixture_case() -> Result<()> {
    let fixture = super::load_fixture_value(FIXTURE_FILE)?;
    let case = fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str)
                    == Some(VECTOR_ID_REALM_KEY_SHARE_SENDER_SIGNATURE)
            })
        })
        .ok_or_else(|| {
            anyhow!("{FIXTURE_FILE} lost its {VECTOR_ID_REALM_KEY_SHARE_SENDER_SIGNATURE} case")
        })?;
    if case.get("context").and_then(Value::as_str) != Some("ak.realm-key-share-sender-proof-v1") {
        bail!("share sender-signature vector proof context drifted");
    }
    let variants: BTreeSet<&str> = case
        .get("positive_variants")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if variants != BTreeSet::from(["member_device", "realm_recovery_key"]) {
        bail!("share sender-signature vector positive variants drifted: {variants:?}");
    }
    let fixture_mutations: BTreeSet<&str> = case
        .get("negative_mutations")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let implemented: BTreeSet<&str> = IMPLEMENTED_SHARE_MUTATIONS.iter().copied().collect();
    if fixture_mutations != implemented {
        bail!(
            "share sender-signature negative mutations drifted from this suite: fixture {fixture_mutations:?} vs implemented {implemented:?}"
        );
    }
    Ok(())
}

// ── ak.realm_key.request content ────────────────────────────────────────────

fn request_content_wire() -> Value {
    json!({
        "key_scope": {
            "effective_scope": { "kind": "realm", "realm_id": REALM_ID },
            "from_epoch": 0,
            "to_epoch": 4
        },
        "recipient_principal_id": RECIPIENT_PRINCIPAL,
        "recipient_device_id": RECIPIENT_DEVICE,
        "recipient_hpke_public_key": "cHVia2V5",
        "requested_source_kind": "verified_member_device",
        "target_source_ref": SENDER_DEVICE,
        "target_principal_id": RECIPIENT_PRINCIPAL,
        "created_at": CREATED_AT
    })
}

fn run_request_content_schema_cases(env: &SchemaEnv) -> Result<()> {
    let validator = env.compile(REALM_KEY_REQUEST_CONTENT_SCHEMA)?;

    // Positive: schema-valid, strong-type parse, byte-identical round trip.
    let positive = request_content_wire();
    if !validator.is_valid(&positive) {
        bail!("positive ak.realm_key.request content rejected by schema");
    }
    let parsed: RealmKeyRequestPayload =
        serde_json::from_value(positive.clone()).context("SDK parse of realm_key request")?;
    parsed
        .validate()
        .map_err(|error| anyhow!("SDK validate of realm_key request: {error}"))?;
    if serde_json::to_value(&parsed)? != positive {
        bail!("realm_key request round trip is not byte-identical");
    }

    // key_backup is intentionally excluded from the direct request path:
    // both the closed schema enum and the SDK validator refuse it.
    let mut key_backup = positive.clone();
    key_backup["requested_source_kind"] = json!("key_backup");
    if validator.is_valid(&key_backup) {
        bail!("schema admitted requested_source_kind=key_backup");
    }

    // Unknown fields: schema `additionalProperties: false` and the SDK's
    // `deny_unknown_fields` must agree.
    let mut unknown = positive.clone();
    unknown["surprise"] = json!(1);
    if validator.is_valid(&unknown) {
        bail!("schema admitted an unknown realm_key request field");
    }
    if serde_json::from_value::<RealmKeyRequestPayload>(unknown).is_ok() {
        bail!("SDK admitted an unknown realm_key request field");
    }

    // Blank (whitespace-only) HPKE key passes the schema's minLength but must
    // fail the SDK semantic validator before the request ships.
    let mut blank_key = positive;
    blank_key["recipient_hpke_public_key"] = json!("   ");
    let parsed: RealmKeyRequestPayload = serde_json::from_value(blank_key)?;
    if parsed.validate().is_ok() {
        bail!("SDK admitted a blank recipient_hpke_public_key");
    }

    Ok(())
}

// ── ak.realm_key.share payload ──────────────────────────────────────────────

fn share_wire_base(share_kind: &str) -> Value {
    json!({
        "share_kind": share_kind,
        "recipient_principal_id": RECIPIENT_PRINCIPAL,
        "sender_device_id": SENDER_DEVICE,
        "source_authorization_ref": SOURCE_AUTHORIZATION_REF,
        "sender_device_signature": {
            "kid": "k",
            "signature_algorithm": "Ed25519",
            "sig": "AAAA"
        },
        "key_scope": {
            "effective_scope": { "kind": "realm", "realm_id": REALM_ID },
            "policy_digest": POLICY_DIGEST
        },
        "created_at": CREATED_AT
    })
}

fn member_share_wire() -> Value {
    let mut value = share_wire_base("member_device");
    let object = value.as_object_mut().expect("share wire is an object");
    object.insert("recipient_device_id".to_owned(), json!(RECIPIENT_DEVICE));
    object.insert("ciphertext".to_owned(), json!("Y2lwaGVy"));
    value
}

fn recovery_share_wire() -> Value {
    let mut value = share_wire_base("realm_recovery_key");
    let object = value.as_object_mut().expect("share wire is an object");
    object.insert(
        "recipient_verification_method".to_owned(),
        json!("did:webvh:z6mkfixture:acme.example#realm-history-recovery-1"),
    );
    object.insert("recovery_recipient_id".to_owned(), json!("rr-1"));
    object.insert(
        "encrypted_key_ref".to_owned(),
        json!("ak:blob:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    );
    value
}

fn run_share_payload_schema_cases(env: &SchemaEnv) -> Result<()> {
    let validator = env.compile(REALM_KEY_SHARE_PAYLOAD_SCHEMA)?;

    // Positives: both registered variants, schema-valid and byte-identical
    // through the SDK strong type.
    for (name, wire) in [
        ("member_device", member_share_wire()),
        ("realm_recovery_key", recovery_share_wire()),
    ] {
        if !validator.is_valid(&wire) {
            bail!("positive {name} share payload rejected by schema");
        }
        let parsed: RealmKeySharePayload =
            serde_json::from_value(wire.clone()).with_context(|| format!("SDK parse {name}"))?;
        if serde_json::to_value(&parsed)? != wire {
            bail!("{name} share round trip is not byte-identical");
        }
    }

    // Structural negative mutations: closed schema and SDK strict wire
    // mirror must both fail them.
    let cross_variant = {
        let mut value = member_share_wire();
        value["recovery_recipient_id"] = json!("rr-1");
        value
    };
    let both_material = {
        let mut value = member_share_wire();
        value["encrypted_key_ref"] = json!(
            "ak:blob:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        value
    };
    let material_missing = {
        let mut value = member_share_wire();
        value.as_object_mut().unwrap().remove("ciphertext");
        value
    };
    for (mutation, value) in [
        ("cross_variant_target_present", cross_variant),
        (
            "ciphertext_and_encrypted_key_ref_both_present",
            both_material,
        ),
        ("material_missing", material_missing),
    ] {
        if validator.is_valid(&value) {
            bail!("schema admitted share mutation {mutation}");
        }
        if serde_json::from_value::<RealmKeySharePayload>(value).is_ok() {
            bail!("SDK admitted share mutation {mutation}");
        }
    }

    // `unselected_target_written_as_null`: a null-padded wire form is not the
    // registered shape — the schema rejects it, and the SDK serializer can
    // never emit it (absent options are omitted, proven by the byte-identical
    // round trips above).
    let mut null_padded = member_share_wire();
    null_padded["recipient_verification_method"] = Value::Null;
    if validator.is_valid(&null_padded) {
        bail!("schema admitted a null-padded unselected target field");
    }

    Ok(())
}

fn run_withheld_payload_schema_case(env: &SchemaEnv) -> Result<()> {
    let validator = env.compile(REALM_KEY_WITHHELD_PAYLOAD_SCHEMA)?;
    let wire = json!({
        "share_kind": "member_device",
        "recipient_principal_id": RECIPIENT_PRINCIPAL,
        "recipient_device_id": RECIPIENT_DEVICE,
        "sender_device_id": SENDER_DEVICE,
        "source_authorization_ref": SOURCE_AUTHORIZATION_REF,
        "key_scope": {
            "effective_scope": { "kind": "realm", "realm_id": REALM_ID },
            "policy_digest": POLICY_DIGEST
        },
        "withheld_reason_code": "policy_denied",
        "created_at": CREATED_AT
    });
    if !validator.is_valid(&wire) {
        bail!("positive realm_key withheld payload rejected by schema");
    }
    let parsed: RealmKeyWithheldPayload =
        serde_json::from_value(wire.clone()).context("SDK parse of realm_key withheld")?;
    if serde_json::to_value(&parsed)? != wire {
        bail!("realm_key withheld round trip is not byte-identical");
    }

    // The refusal basis is mandatory: a withheld without its policy_digest or
    // source_authorization_ref has no policy root to bind to and must be
    // rejected at the wire layer already.
    for missing in ["source_authorization_ref", "key_scope"] {
        let mut value = wire.clone();
        value.as_object_mut().unwrap().remove(missing);
        if validator.is_valid(&value) {
            bail!("schema admitted a realm_key withheld payload missing {missing}");
        }
        if serde_json::from_value::<RealmKeyWithheldPayload>(value).is_ok() {
            bail!("SDK admitted a realm_key withheld payload missing {missing}");
        }
    }
    let mut no_policy_digest = wire;
    no_policy_digest["key_scope"]
        .as_object_mut()
        .unwrap()
        .remove("policy_digest");
    if validator.is_valid(&no_policy_digest) {
        bail!("schema admitted a realm_key withheld key_scope without policy_digest");
    }
    if serde_json::from_value::<RealmKeyWithheldPayload>(no_policy_digest).is_ok() {
        bail!("SDK admitted a realm_key withheld key_scope without policy_digest");
    }
    Ok(())
}

// ── ak.vector.realm_key.share_sender_signature.v1 ───────────────────────────

/// Byte-exact member-device sender-proof transcript (canonical JSON, sorted
/// keys, unselected branch/material and absent optional fields omitted,
/// `context` inserted, `sender_device_signature` excluded).
const MEMBER_DEVICE_TRANSCRIPT_KAT: &str = concat!(
    "{\"ciphertext\":\"Y2lwaGVy\",",
    "\"context\":\"ak.realm-key-share-sender-proof-v1\",",
    "\"created_at\":\"2026-07-26T00:00:00.000Z\",",
    "\"key_scope\":{\"effective_scope\":{\"kind\":\"realm\",",
    "\"realm_id\":\"ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy\"},",
    "\"policy_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},",
    "\"recipient_device_id\":\"ak:device:019f9000-0000-7000-8000-000000000003\",",
    "\"recipient_principal_id\":\"ak:did_core:webvh:z6mkfixture\",",
    "\"sender_device_id\":\"ak:device:019f9000-0000-7000-8000-000000000004\",",
    "\"share_kind\":\"member_device\",",
    "\"source_authorization_ref\":\"ak:event:Adl8EVE0XuYmtOeRAa0WJVGy5DWansCGrXuwPONweuzs\"}",
);

fn run_share_sender_signature_vector() -> Result<()> {
    let member: RealmKeySharePayload = serde_json::from_value(member_share_wire())?;
    let transcript = member
        .sender_signing_input()
        .map_err(|error| anyhow!("member transcript: {error}"))?;

    // KAT: the transcript bytes are pinned, not merely self-consistent.
    if transcript != MEMBER_DEVICE_TRANSCRIPT_KAT.as_bytes() {
        bail!(
            "member-device sender transcript drifted from the KAT:\n  got: {}\n  want: {}",
            String::from_utf8_lossy(&transcript),
            MEMBER_DEVICE_TRANSCRIPT_KAT
        );
    }

    // The RRK variant carries exactly its own branch and material fields.
    let recovery: RealmKeySharePayload = serde_json::from_value(recovery_share_wire())?;
    let recovery_transcript: Value = serde_json::from_slice(
        &recovery
            .sender_signing_input()
            .map_err(|error| anyhow!("recovery transcript: {error}"))?,
    )?;
    let recovery_object = recovery_transcript
        .as_object()
        .ok_or_else(|| anyhow!("recovery transcript is not an object"))?;
    for present in [
        "recipient_verification_method",
        "recovery_recipient_id",
        "encrypted_key_ref",
        "context",
    ] {
        if !recovery_object.contains_key(present) {
            bail!("recovery transcript lost {present}");
        }
    }
    for absent in [
        "recipient_device_id",
        "ciphertext",
        "sender_device_signature",
    ] {
        if recovery_object.contains_key(absent) {
            bail!("recovery transcript must omit {absent}");
        }
    }

    // Positive: a real Ed25519 signature over the pinned transcript verifies.
    let sender_key = SigningKey::from_bytes(&[7u8; 32]);
    let signature = sender_key.sign(&transcript);
    sender_key
        .verifying_key()
        .verify(&transcript, &signature)
        .map_err(|error| anyhow!("positive sender signature must verify: {error}"))?;

    // `signature_kid_sender_device_mismatch`: another device's key must not
    // verify the same transcript.
    let other_device_key = SigningKey::from_bytes(&[8u8; 32]);
    if other_device_key
        .verifying_key()
        .verify(&transcript, &signature)
        .is_ok()
    {
        bail!("another device's key verified the sender transcript");
    }

    // Field tampering: each mutated payload re-canonicalizes to different
    // bytes, so the original signature fails closed.
    let tampered_expires_at = {
        let mut value = member_share_wire();
        value["expires_at"] = json!("2026-07-27T00:00:00.000Z");
        value
    };
    let tampered_source_ref = {
        let mut value = member_share_wire();
        value["source_authorization_ref"] =
            json!("ak:event:AY2gmtVpH4CNWqvZ25JTuYdzI56aAbxr3k-TrqvZfsKv");
        value
    };
    let tampered_key_scope = {
        let mut value = member_share_wire();
        value["key_scope"]["policy_digest"] =
            json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        value
    };
    for (mutation, wire) in [
        ("expires_at_tampered", tampered_expires_at),
        ("source_authorization_ref_tampered", tampered_source_ref),
        ("key_scope_tampered", tampered_key_scope),
    ] {
        let tampered: RealmKeySharePayload = serde_json::from_value(wire)
            .with_context(|| format!("tampered payload {mutation} must still parse"))?;
        let tampered_transcript = tampered
            .sender_signing_input()
            .map_err(|error| anyhow!("{mutation} transcript: {error}"))?;
        if tampered_transcript == transcript {
            bail!("{mutation} did not change the sender transcript");
        }
        if sender_key
            .verifying_key()
            .verify(&tampered_transcript, &signature)
            .is_ok()
        {
            bail!("{mutation} transcript still verified under the original signature");
        }
    }

    // `unselected_target_written_as_null` at the transcript level: a
    // null-padded transcript is a second, unregistered signing shape — its
    // bytes differ, so the registered-shape signature fails against it.
    let mut null_padded: Value = serde_json::from_slice(&transcript)?;
    null_padded
        .as_object_mut()
        .unwrap()
        .insert("recipient_verification_method".to_owned(), Value::Null);
    let null_padded_bytes = arkret_canonical::canonical_json_bytes(&null_padded)?;
    if null_padded_bytes == transcript {
        bail!("null-padding the transcript must change its bytes");
    }
    if sender_key
        .verifying_key()
        .verify(&null_padded_bytes, &signature)
        .is_ok()
    {
        bail!("null-padded transcript verified under the registered-shape signature");
    }

    Ok(())
}
