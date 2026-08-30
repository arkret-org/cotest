//! Handle-claim rejection conformance vectors (VECT-COT-6 / VECT-COT-7).
//!
//! Spec source: `artifacts/schemas/handle-claim.schema.json` +
//! `identity/identity-handles.md §3.2 / §17`.
//!
//! Wire-breaking cleanup:
//!   * `claim_kind` enum lost `service_handle` — only `handle_binding` / `organization_handle`
//!     remain. A `claim_kind=service_handle` envelope MUST schema-reject (VECT-COT-6).
//!   * `subject_account_id.principal_id` MUST be a holder/principal did_core_id. A DID, account
//!     id, or generic resource id MUST reject (VECT-COT-7), enforced by
//!     [`arkret_models_identity::validate_handle_claim_subject`] and by the AccountId schema.
//!
//! VECT-COT-6 also pins that the SDK `HandleClaimKind` enum no longer carries a
//! `ServiceHandle` variant, so any attempt to parse `service_handle` into
//! the typed `claim_kind` field fails.

use std::ffi::OsStr;
use std::fs;

use anyhow::{Result, anyhow, bail};
use arkret_identifiers::DidCoreId;
use arkret_models_identity::{HandleClaimKind, validate_handle_claim_subject};
use jsonschema::{Registry, Resource};
use serde_json::{Value, json};

use super::{looks_like_sha256_digest, spec_artifacts_root};

pub const VECTOR_ID_HC_SERVICE_HANDLE_REJECTED: &str =
    "ak.cotest_vector.handle_claim.service_handle_rejected.v1";
pub const VECTOR_ID_HC_SUBJECT_NOT_PRINCIPAL_REJECTED: &str =
    "ak.cotest_vector.handle_claim.subject_not_principal_did_rejected.v1";

pub const ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_HC_SERVICE_HANDLE_REJECTED,
    VECTOR_ID_HC_SUBJECT_NOT_PRINCIPAL_REJECTED,
];

const SCHEMA_DIR: &str = "schemas";
const SCHEMA_ID_PREFIX: &str = "https://arkret.org/v1/";
const HANDLE_CLAIM_SCHEMA_FILE: &str = "schemas/handle-claim.schema.json";

/// Compile the `handle-claim.schema.json` artifact with the full schema
/// registry so `$ref` / `$defs` resolve.
fn compile_handle_claim_schema() -> Result<jsonschema::Validator> {
    let root = spec_artifacts_root();
    let schemas_dir = root.join(SCHEMA_DIR);
    let mut resources: Vec<(String, Value)> = Vec::new();
    for entry in fs::read_dir(&schemas_dir)
        .map_err(|e| anyhow!("read schemas dir {}: {e}", schemas_dir.display()))?
    {
        let path = entry?.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|err| anyhow!("schema file {} invalid JSON: {err}", path.display()))?;
        if let Some(id) = value.get("$id").and_then(Value::as_str)
            && id.starts_with(SCHEMA_ID_PREFIX)
        {
            resources.push((id.to_owned(), value));
        }
    }
    let mut builder = Registry::new();
    for (id, value) in &resources {
        builder = builder
            .add(id.as_str(), Resource::from_contents(value.clone()))
            .map_err(|err| anyhow!("registry add {id} failed: {err}"))?;
    }
    let registry = builder
        .prepare()
        .map_err(|err| anyhow!("registry prepare failed: {err}"))?;

    let schema_value: Value = serde_json::from_str(
        &fs::read_to_string(root.join(HANDLE_CLAIM_SCHEMA_FILE))
            .map_err(|e| anyhow!("read handle-claim schema: {e}"))?,
    )?;
    jsonschema::options()
        .with_registry(&registry)
        .build(&schema_value)
        .map_err(|err| anyhow!("compile handle-claim schema failed: {err}"))
}

/// A schema-valid `ak.schema.handle_claim.v1` instance to mutate per case.
fn base_claim() -> Value {
    json!({
        "schema": "ak.schema.handle_claim.v1",
        "handle": "alice:acme.example",
        "subject_account_id": {
            "principal_id": "ak:did_core:web:alice.principal.example",
            "station_id": "ak:did_core:web:station.acme.example"
        },
        "issuer_id": "ak:did_core:web:coauth.acme.example",
        "binding_state": "verified",
        "claim_kind": "handle_binding",
        "created_at": "2026-05-20T00:00:00.000Z",
        "expires_at": "2026-06-20T00:00:00.000Z",
        "proofs": [
            {
                "kind": "detached_jws",
                "verification_method": "did:web:coauth.acme.example#key-1",
                "payload_digest":
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": "2026-05-20T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZDI1NTE5In0..signature"
            },
            // binding_state=verified claims MUST also carry a
            // holder_acceptance proof (handle-claim.schema.json allOf[0]).
            {
                "kind": "detached_jws",
                "verification_method": "did:web:alice.principal.example#key-1",
                "proof_purpose": "holder_acceptance",
                "payload_digest":
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": "2026-05-20T00:00:00.000Z",
                "jws": "eyJhbGciOiJFZDI1NTE5In0..signature"
            }
        ]
    })
}

// ── VECT-COT-6 — claim_kind=service_handle rejected ─────────────────────────

pub fn run_service_handle_rejected_vector() -> Result<()> {
    let validator = compile_handle_claim_schema()?;

    // Control: the canonical handle_binding claim MUST validate.
    let ok = base_claim();
    if !validator.is_valid(&ok) {
        bail!(
            "VECT-COT-6 control: a canonical handle_binding claim MUST validate; \
             errors: {:?}",
            validator
                .iter_errors(&ok)
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }
    // Sanity: the proof digest in the fixture is well-formed.
    if !looks_like_sha256_digest(
        ok["proofs"][0]["payload_digest"]
            .as_str()
            .unwrap_or_default(),
    ) {
        bail!("VECT-COT-6 control: proof payload_digest must be a sha256 digest");
    }

    // The retired `service_handle` value MUST schema-reject.
    let mut service = base_claim();
    service["claim_kind"] = json!("service_handle");
    if validator.is_valid(&service) {
        bail!(
            "VECT-COT-6: claim_kind=service_handle MUST schema-reject (enum is \
             [handle_binding, organization_handle])"
        );
    }

    // The SDK typed `HandleClaimKind` enum MUST NOT deserialise `service_handle`.
    let parsed: std::result::Result<HandleClaimKind, _> =
        serde_json::from_value(json!("service_handle"));
    if parsed.is_ok() {
        bail!("VECT-COT-6: HandleClaimKind MUST NOT accept the retired `service_handle` variant");
    }
    // It MUST still accept the two surviving values.
    for ok_value in ["handle_binding", "organization_handle"] {
        if serde_json::from_value::<HandleClaimKind>(json!(ok_value)).is_err() {
            bail!("VECT-COT-6: HandleClaimKind MUST accept `{ok_value}`");
        }
    }
    Ok(())
}

// ── VECT-COT-7 — subject not a principal core id rejected ──────────────────

pub fn run_subject_not_principal_did_rejected_vector() -> Result<()> {
    let validator = compile_handle_claim_schema()?;

    for invalid in [
        "did:web:alice.principal.example",
        "ak:account:01904100-0000-7000-8000-000000000002",
    ] {
        let principal_id = DidCoreId::new(invalid.to_owned());
        if let Ok(principal_id) = principal_id
            && validate_handle_claim_subject(&principal_id).is_ok()
        {
            bail!(
                "VECT-COT-7: validate_handle_claim_subject MUST reject `{invalid}` \
                     (reason handle_claim_subject_not_principal_did)"
            );
        }
    }

    let holder = DidCoreId::new("ak:did_core:web:alice.principal.example".to_owned())?;
    validate_handle_claim_subject(&holder)
        .map_err(|e| anyhow!("VECT-COT-7: a principal core id MUST pass: {e}"))?;

    for bad_subject in [
        "did:web:alice.principal.example",
        "ak:account:01904100-0000-7000-8000-000000000002",
        "resource-handle-7",
    ] {
        let mut claim = base_claim();
        claim["subject_account_id"]["principal_id"] = json!(bad_subject);
        if validator.is_valid(&claim) {
            bail!(
                "VECT-COT-7: handle claim with non-principal account component `{bad_subject}` \
                 MUST schema-reject (principal_id requires ak:did_core:<method>:...)"
            );
        }
    }

    if !validator.is_valid(&base_claim()) {
        bail!("VECT-COT-7 control: an exact Station account MUST validate");
    }
    Ok(())
}

// ── Suite entry-point ──────────────────────────────────────────────────────

pub fn run_handle_claim_rejection_vector_suite() -> Result<()> {
    if ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS.len() != 2 {
        bail!(
            "expected 2 handle-claim rejection vector ids, got {}",
            ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS.len()
        );
    }
    run_service_handle_rejected_vector()?;
    run_subject_not_principal_did_rejected_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_claim_rejection_vector_suite_runs_clean() {
        run_handle_claim_rejection_vector_suite().unwrap();
    }
}
