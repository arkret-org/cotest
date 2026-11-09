//! Independent source-binding primitives, not native storage or issuer qualification.

use anyhow::{Context as _, Result, ensure};
use arkret_canonical::{
    DigestSuite, base64url_decode, base64url_encode, canonical_json_bytes, canonical_sha256,
};
use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::{
    ContentContext, ContentEncryptionAlgorithm, ContentEndpoint, ContentPurpose,
    ContentRootContext, ContentRootSecret, EncryptedEnvelopeEncryptionContext,
    EventContentMaterial, EventContentPreEncryptionHeader, EventContentRoutingContext,
};
use arkret_wire::Event;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};

pub const CONTENT_BACKUP_SOURCE_ENTRYPOINT: &str = "ak.suite.crypto.content_backup_source.v1";
pub const FIXTURE: &str = "content-backup-source-fixture.json";
const DOMAIN: &[u8] = b"ak.content.backup_source.v1\n";

pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

pub struct SuiteExecutionResult {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

fn bytes(value: &Value) -> Result<Vec<u8>> {
    let encoded = value.as_str().context("expected base64url bytes")?;
    let decoded = base64url_decode(encoded)?;
    ensure!(
        base64url_encode(&decoded) == encoded,
        "noncanonical base64url"
    );
    Ok(decoded)
}

fn transcript(source: &Value) -> Result<Vec<u8>> {
    let mut unsigned = source.as_object().context("source object")?.clone();
    unsigned.remove("signature");
    let mut result = DOMAIN.to_vec();
    result.extend(canonical_json_bytes(&unsigned)?);
    Ok(result)
}

fn original_protections(event: &Event) -> Result<Value> {
    let mut slots = event.event_content_envelopes()?;
    ensure!(
        !slots.is_empty(),
        "source requires actual registered encrypted slots"
    );
    slots.sort_by(|a, b| a.content_path.as_bytes().cmp(b.content_path.as_bytes()));
    let rows: Result<Vec<_>> = slots
        .into_iter()
        .map(|slot| {
            let context = serde_json::to_value(slot.envelope.encryption_context)?;
            Ok(json!({"content_path":slot.content_path,"protection":context["protection"]}))
        })
        .collect();
    Ok(Value::Array(rows?))
}

fn verify_source(
    source: &Value,
    event: &Event,
    producer: &ContentEndpoint,
    origin: &Value,
    now: DateTime<Utc>,
) -> Result<()> {
    producer.validate()?;
    let account = producer
        .actor_id
        .as_account_id()
        .context("actual producer Account")?;
    ensure!(
        origin["station_id"] == serde_json::to_value(&account.station_id)?,
        "wrong owning Station"
    );
    ensure!(
        source["verification_method"] == origin["verification_method"]
            && source["signature"]["kid"] == origin["verification_method"],
        "wrong service method"
    );
    ensure!(
        source["signature"]
            .get("signature_algorithm")
            .is_none_or(|a| a == "Ed25519"),
        "wrong signature algorithm"
    );
    let public: [u8; 32] = bytes(&origin["public_key_base64url"])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("service key width"))?;
    VerifyingKey::from_bytes(&public)?.verify_strict(
        &transcript(source)?,
        &Signature::from_slice(&bytes(&source["signature"]["signature"])?)?,
    )?;
    ensure!(
        source["event_ref"] == serde_json::to_value(&event.event_id)?,
        "wrong original Event id"
    );
    ensure!(
        source["event_original_digest"] == canonical_sha256(event)?,
        "changed complete original Event"
    );
    ensure!(
        source["producer"] == serde_json::to_value(producer)?,
        "wrong actual endpoint"
    );
    ensure!(
        &producer.actor_id == event.executed_by.as_ref().unwrap_or(&event.actor_id),
        "wrong actual Actor"
    );
    ensure!(
        source["effective_scope"] == serde_json::to_value(&event.scope_ref)?,
        "wrong scope"
    );
    ensure!(
        source["destination_service_id"] == "ak:did_core:web:governor.example",
        "wrong destination"
    );
    ensure!(
        source["protections_digest"] == canonical_sha256(&original_protections(event)?)?,
        "missing or changed registered protections"
    );
    let issued =
        DateTime::parse_from_rfc3339(source["attested_at"].as_str().context("attested time")?)?
            .with_timezone(&Utc);
    let expires =
        DateTime::parse_from_rfc3339(source["expires_at"].as_str().context("expiry time")?)?
            .with_timezone(&Utc);
    ensure!(
        expires > issued
            && expires - issued <= Duration::seconds(300)
            && issued <= now
            && now < expires,
        "source observation window"
    );
    Ok(())
}

fn execute_case(case: &Value, fixture: &Value) -> Result<usize> {
    let event: Event = serde_json::from_value(case["event"].clone())?;
    let producer: ContentEndpoint = serde_json::from_value(case["producer"].clone())?;
    event.verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)?;
    event.verify_producer_proof_self_consistency(DigestSuite::Sha256)?;
    let proof = event
        .producer_proof
        .as_ref()
        .context("real producer proof")?;
    let binding = proof.canonical_binding_bytes(&event.actor_id)?;
    ensure!(
        hex::encode(&binding) == case["producer_binding_hex"],
        "independent producer transcript"
    );
    let public: [u8; 32] = bytes(&case["producer"]["signature_key_base64url"])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("producer key width"))?;
    let signature = proof
        .jws
        .split_once("..")
        .context("detached producer JWS")?
        .1;
    VerifyingKey::from_bytes(&public)?.verify_strict(
        &binding,
        &Signature::from_slice(&base64url_decode(signature)?)?,
    )?;
    let source = &case["attestation"];
    ensure!(
        hex::encode(transcript(source)?) == case["signing_hex"],
        "independent service transcript"
    );
    let now = DateTime::parse_from_rfc3339("2026-11-08T00:00:02.000Z")?.with_timezone(&Utc);
    verify_source(source, &event, &producer, &case["origin_key"], now)?;

    let root_context: ContentRootContext = serde_json::from_value(fixture["root_context"].clone())?;
    let root = ContentRootSecret::new(
        hex::decode(fixture["root_hex"].as_str().context("root hex")?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("root width"))?,
    );
    let slots = event.event_content_envelopes()?;
    ensure!(slots.len() == 2, "body and metadata must both execute");
    let mut assertions = 16;
    for slot in slots {
        let envelope = slot.envelope;
        let EncryptedEnvelopeEncryptionContext::EpochContent {
            content_key_salt,
            root_ref,
            key_commitment,
            protection,
            ..
        } = &envelope.encryption_context;
        let context = ContentContext {
            root_context: root_context.clone(),
            root_ref: root_ref.clone(),
            purpose: ContentPurpose::EventBody,
            encryption_scheme: envelope.encryption_scheme.clone(),
            encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
            producer: producer.clone(),
            content_key_salt: content_key_salt.clone(),
        };
        let header = EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            &envelope.content_type,
            envelope.encryption_scheme,
            event.scope_ref.clone(),
            event.kind.as_str(),
            envelope.encryption_context.epoch(),
            envelope.encryption_context.group_state_ref().clone(),
            arkret_canonical::canonical_json_string(&producer.actor_id)?,
            EventContentRoutingContext::None,
            EventContentMaterial {
                content_context: context,
                outer_event: EventContentMaterial::outer_event_for(&event)?,
                protection: protection.clone(),
                key_commitment: key_commitment.clone(),
            },
        )?;
        let opened =
            arkret_crypto::content_history::open_content(&root, &header, &envelope.ciphertext)?;
        let field = slot
            .content_path
            .strip_prefix("/payload/")
            .context("registered field")?;
        ensure!(
            hex::encode(opened) == case["plaintexts_hex"][field],
            "original typed plaintext"
        );
        assertions += 1;
    }
    let private: [u8; 32] = hex::decode(
        case["service_signing_seed_hex"]
            .as_str()
            .context("fixture service seed")?,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("fixture seed width"))?;
    let signer = SigningKey::from_bytes(&private);
    for field in [
        "event_ref",
        "event_original_digest",
        "effective_scope",
        "producer",
        "destination_service_id",
        "protections_digest",
    ] {
        let mut changed = source.clone();
        changed[field] = match field {
            "producer" => {
                let mut p = changed[field].clone();
                p["authorization_event_ref"] =
                    json!("ak:event:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir");
                p
            }
            "effective_scope" => {
                json!({"kind":"realm","realm_id":"ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir"})
            }
            "event_ref" => json!("ak:event:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir"),
            "destination_service_id" => json!("ak:did_core:web:another.example"),
            _ => json!(format!("sha256:{}", "0".repeat(64))),
        };
        use ed25519_dalek::Signer as _;
        changed["signature"]["signature"] = json!(base64url_encode(
            signer.sign(&transcript(&changed)?).to_bytes()
        ));
        ensure!(
            verify_source(&changed, &event, &producer, &case["origin_key"], now).is_err(),
            "valid service signature cannot rebind {field}"
        );
        assertions += 1;
    }
    let mut missing_metadata = source.clone();
    let mut projections = original_protections(&event)?;
    projections
        .as_array_mut()
        .context("registered slots")?
        .truncate(1);
    missing_metadata["protections_digest"] = json!(canonical_sha256(&projections)?);
    use ed25519_dalek::Signer as _;
    missing_metadata["signature"]["signature"] = json!(base64url_encode(
        signer.sign(&transcript(&missing_metadata)?).to_bytes()
    ));
    ensure!(
        verify_source(
            &missing_metadata,
            &event,
            &producer,
            &case["origin_key"],
            now
        )
        .is_err(),
        "metadata omission"
    );
    let expired = DateTime::parse_from_rfc3339(source["expires_at"].as_str().context("expiry")?)?
        .with_timezone(&Utc);
    ensure!(
        verify_source(source, &event, &producer, &case["origin_key"], expired).is_err(),
        "expired source"
    );
    let mut wrong_origin = case["origin_key"].clone();
    wrong_origin["station_id"] = json!("ak:did_core:web:foreign.example");
    ensure!(
        verify_source(source, &event, &producer, &wrong_origin, now).is_err(),
        "foreign keeper"
    );
    Ok(assertions + 3)
}

pub fn run_content_backup_source_suite() -> Result<SuiteExecutionResult> {
    let fixture = arkret_schema_conformance::spec_json_artifact(&format!("fixtures/{FIXTURE}"))?;
    ensure!(
        fixture["runner"]["entrypoint"] == CONTENT_BACKUP_SOURCE_ENTRYPOINT,
        "wrong runner"
    );
    let mut cases = Vec::new();
    for case in fixture["cases"]
        .as_array()
        .context("declared source cases")?
    {
        let id = case["name"].as_str().context("case id")?;
        let assertions =
            execute_case(case, &fixture).with_context(|| format!("source case {id}"))?;
        cases.push(CaseExecutionResult {
            case_id: id.to_owned(),
            assertions,
        });
    }
    ensure!(
        cases.len() == 2 && cases[0].case_id == "human" && cases[1].case_id == "agent",
        "complete Human/Agent cases"
    );
    Ok(SuiteExecutionResult {
        entrypoint: CONTENT_BACKUP_SOURCE_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn independent_source_vectors_execute_every_declared_case() {
        let result = super::run_content_backup_source_suite().unwrap();
        assert_eq!(result.cases.len(), 2);
        assert!(result.cases.iter().all(|case| case.assertions >= 27));
    }
}
