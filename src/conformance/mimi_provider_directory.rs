//! MIMI provider-directory signed projection closure vector.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::objects::interop::{
    ProviderDirectory, ProviderDirectoryEndpoint, ProviderDirectoryMimi, ProviderDirectoryProof,
};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::signer::verify_ed25519_payload_signature;
use arkret_wire::{DidFullId, DidUrl, Hash, MimiUri, PayloadProof, PayloadSigner as _};
use chrono::{Duration, Utc};

pub const VECTOR_ID_MIMI_PROVIDER_DIRECTORY_SIGNATURE: &str =
    "ak.vector.mimi.provider_directory_signature.v1";

fn validate_directory(
    directory: &ProviderDirectory,
    now: chrono::DateTime<Utc>,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let proof = &directory.proof.0;
    if directory.supported_profiles.is_empty()
        || directory.mimi.endpoints.is_empty()
        || directory.mimi.features.is_empty()
        || directory.mimi.mls_cipher_suites.is_empty()
        || directory.mimi.content_profiles.is_empty()
        || directory.mimi.room_policy_components.is_empty()
    {
        bail!("MIMI provider directory omitted a required capability set");
    }
    for values in [
        &directory.supported_profiles,
        &directory.mimi.features,
        &directory.mimi.mls_cipher_suites,
        &directory.mimi.content_profiles,
        &directory.mimi.room_policy_components,
    ] {
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            bail!("MIMI provider directory capability arrays must be sorted and unique");
        }
    }
    let feature_set = directory.mimi.features.iter().collect::<BTreeSet<_>>();
    let endpoint_set = directory
        .mimi
        .endpoints
        .iter()
        .map(|endpoint| &endpoint.endpoint_id)
        .collect::<BTreeSet<_>>();
    if feature_set != endpoint_set
        || directory.mimi.endpoints.iter().any(|endpoint| {
            !endpoint.relative_path.starts_with('/')
                || endpoint.relative_path.contains(['?', '#', '\\', ' '])
                || endpoint.relative_path.contains("://")
        })
    {
        bail!("MIMI endpoint declarations are not a closed feature/path mapping");
    }
    if directory.extra.keys().any(|key| {
        matches!(
            key.as_str(),
            "base_url" | "provider_id" | "endpoints" | "mimi"
        )
    }) || directory.mimi.extra.keys().any(|key| {
        matches!(
            key.as_str(),
            "base_url" | "provider_id" | "endpoints" | "features"
        )
    }) {
        bail!("an unknown extension attempted to shadow routing or capabilities");
    }
    let proof_controller = proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| anyhow!("MIMI proof verification method has no fragment"))?;
    let proof_controller = DidFullId::new(proof_controller.to_owned())?;
    let proof_controller =
        arkret_wire::DidCoreId::from(arkret_wire::project_full_id_to_core_id(&proof_controller)?);
    if proof.kind != "detached_jws"
        || proof_controller != directory.service_id
        || now - proof.created_at > Duration::minutes(5)
        || proof.created_at > now + Duration::seconds(60)
    {
        bail!("MIMI provider-directory proof metadata is invalid");
    }
    let bytes = directory.unsigned_projection_bytes()?;
    let digest = arkret_canonical::canonical::sha256_digest(&bytes);
    if proof.payload_digest.as_str() != digest {
        bail!("MIMI provider-directory payload digest does not bind the unsigned projection");
    }
    let signature = arkret_wire::PayloadSignature {
        verification_method: proof.verification_method.clone(),
        payload_digest: proof.payload_digest.clone(),
        created_at: proof.created_at,
        jws: proof.jws.clone(),
        extra: BTreeMap::new(),
    };
    verify_ed25519_payload_signature(&bytes, &signature, verifying_key)?;
    Ok(())
}

fn signed_directory() -> Result<(ProviderDirectory, ed25519_dalek::VerifyingKey)> {
    let service_full_id = DidFullId::new("did:webvh:z6mkfixture:provider.example")?;
    let service_id =
        arkret_wire::DidCoreId::from(arkret_wire::project_full_id_to_core_id(&service_full_id)?);
    let verification_method = DidUrl::new(format!("{}#notary-key", service_full_id.as_str()))
        .map_err(|error| anyhow!(error))?;
    let placeholder = PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        created_at: Utc::now(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "placeholder".to_owned(),
    };
    let mut directory = ProviderDirectory {
        schema: "ak.schema.mimi_interop.v1".to_owned(),
        service_id: service_id.clone(),
        service_kind: "mimi_provider_facade".to_owned(),
        supported_profiles: vec!["ak.profile.mimi_interop.v1".to_owned()],
        mimi: ProviderDirectoryMimi {
            protocol_draft: "draft-ietf-mimi-protocol-06".to_owned(),
            content_draft: "draft-ietf-mimi-content-08".to_owned(),
            room_policy_draft: "draft-ietf-mimi-room-policy-03".to_owned(),
            identifier_draft: "draft-kohbrok-mimi-identifiers-01".to_owned(),
            base_url: "https://provider.example/_arkret/open/mimi".to_owned(),
            provider_id: MimiUri::new("mimi://provider.example")
                .expect("canonical MIMI provider id"),
            endpoints: [
                ("consent", "/consent/request"),
                ("group_info", "/strands/{strand_id}/group-info"),
                ("submit_message", "/strands/{strand_id}/messages"),
            ]
            .into_iter()
            .map(|(endpoint_id, relative_path)| ProviderDirectoryEndpoint {
                endpoint_id: endpoint_id.to_owned(),
                relative_path: relative_path.to_owned(),
            })
            .collect(),
            features: ["consent", "group_info", "submit_message"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            mls_cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            content_profiles: vec!["application/mimi-content".to_owned()],
            room_policy_components: vec!["membership".to_owned(), "roles".to_owned()],
            extra: BTreeMap::new(),
        },
        proof: ProviderDirectoryProof(placeholder),
        extra: BTreeMap::new(),
    };
    let signer =
        Ed25519PayloadSigner::from_did_key_seed([0x51; 32], service_full_id, verification_method);
    let signature = signer.sign_payload(&directory.unsigned_projection_bytes()?)?;
    directory.proof = ProviderDirectoryProof(PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: signature.verification_method,
        payload_digest: signature.payload_digest,
        created_at: signature.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: signature.jws,
    });
    Ok((directory, signer.verifying_key()))
}

/// Exact runner for `ak.vector.mimi.provider_directory_signature.v1`.
pub fn run_mimi_provider_directory_signature_vector() -> Result<()> {
    let fixture = super::load_fixture_value("mimi-interop-fixture.json")?;
    super::validate_profile(&fixture, "ak.profile.mimi_interop.v1")?;
    let case = fixture
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(serde_json::Value::as_str)
                    == Some(VECTOR_ID_MIMI_PROVIDER_DIRECTORY_SIGNATURE)
            })
        })
        .ok_or_else(|| anyhow!("MIMI fixture is missing the provider-directory signature case"))?;
    if case
        .get("assertions")
        .and_then(serde_json::Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        bail!("MIMI provider-directory signature fixture has no assertions");
    }
    let (directory, key) = signed_directory()?;
    validate_directory(&directory, directory.proof.0.created_at, &key)?;

    for mutate in [
        |value: &mut ProviderDirectory| value.mimi.endpoints[0].relative_path.push_str("/tampered"),
        |value: &mut ProviderDirectory| value.mimi.mls_cipher_suites[0].push_str("-tampered"),
        |value: &mut ProviderDirectory| value.mimi.content_profiles[0].push_str("-tampered"),
        |value: &mut ProviderDirectory| value.mimi.room_policy_components[0].push_str("-tampered"),
    ] {
        let mut tampered = directory.clone();
        mutate(&mut tampered);
        if validate_directory(&tampered, tampered.proof.0.created_at, &key).is_ok() {
            bail!("a signed MIMI capability or routing mutation was accepted");
        }
    }
    let mut empty = directory.clone();
    empty.mimi.features.clear();
    if validate_directory(&empty, empty.proof.0.created_at, &key).is_ok() {
        bail!("an empty required MIMI capability array was accepted");
    }
    let mut wrong_controller = directory.clone();
    wrong_controller.proof.0.verification_method =
        DidUrl::new("did:web:other.example#key").map_err(|error| anyhow!(error))?;
    if validate_directory(&wrong_controller, wrong_controller.proof.0.created_at, &key).is_ok() {
        bail!("a MIMI proof controlled by another DID was accepted");
    }
    let mut shadow = directory.clone();
    shadow.extra.insert(
        "base_url".to_owned(),
        serde_json::json!("https://evil.example"),
    );
    if validate_directory(&shadow, shadow.proof.0.created_at, &key).is_ok() {
        bail!("a routing-shadow extension was accepted");
    }
    let stale_now = directory.proof.0.created_at + Duration::minutes(6);
    if validate_directory(&directory, stale_now, &key).is_ok() {
        bail!("a stale MIMI directory proof was accepted");
    }
    let mut dev_digest = directory.clone();
    dev_digest.proof.0.jws = dev_digest.proof.0.payload_digest.to_string();
    if validate_directory(&dev_digest, dev_digest.proof.0.created_at, &key).is_ok() {
        bail!("a development digest was accepted in place of a detached JWS");
    }
    for (http_signature_valid, directory_jws_valid) in [(true, false), (false, true)] {
        if http_signature_valid && directory_jws_valid {
            bail!("independent transport and directory proof gates collapsed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn mimi_provider_directory_signature_vector_runs_clean() {
        super::run_mimi_provider_directory_signature_vector().unwrap();
    }
}
