use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use arkret_canonical as canonical;
use arkret_crypto::DeviceTrustBinding;
use arkret_identifiers::{ConsentId, DeviceId, Did, Hash};
use arkret_models_collaboration::http_bodies::{MimiConsentDecision, MimiUpdateConsentRequestBody};
use arkret_models_identity::artifacts_device_identity::CrossSigningPublish;
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_wire::{Audience, Event, PayloadProof, Proof, proof_kind};
use base64::Engine as _;
use chrono::{Timelike as _, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

#[derive(Debug, Deserialize)]
struct EventProofInput {
    actor_did: String,
    verification_method: String,
    created_at: String,
    event: Value,
    signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MimiConsentProofInput {
    request: Value,
    verification_method: String,
    created_at: String,
    domain: String,
    audience: String,
    signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrincipalControlRealmInput {
    principal_id: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalRegistrationFixtureInput {
    principal_server_url: String,
    gate_account_base: String,
    handoff_request_id: String,
    identity_creation_lease: Value,
    device_id: String,
    enrollment_authority_did: String,
    trust_domain: String,
}

#[derive(Debug, Deserialize)]
struct AccountHandoffRequestFixtureInput {
    request_id: String,
    audience: String,
    issuer: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    authorization_code: String,
    code_verifier: String,
    dpop_seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct IdentityCreationRegisterFixtureInput {
    challenge: Value,
    did_operation: Value,
    recovery_key: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PreRegistrationSessionFixtureInput {
    principal_id: String,
    device_id: String,
    requested_scope: Vec<String>,
    account_handoff_grant: String,
    audience: String,
    expires_at: String,
    dpop_seed_b64url: String,
}

/// 05-2 — flat inputs for the SSK→device `ak.device-trust-bind-v1` canonical
/// signing input. Mirrors the args the TS `deviceTrustBindingInput` byte-mirror
/// helper takes, but the bytes are produced by the SDK.
#[derive(Debug, Deserialize)]
struct DeviceTrustBindingInputArgs {
    principal_id: String,
    device_id: String,
    device_public_key: String,
    hpke_key: String,
    algorithms: Vec<String>,
    ssk_generation: u64,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "capability-action-registry-digest" => capability_action_registry_digest()?,
        "event-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "event-envelope-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "mimi-consent-proof" => mimi_consent_proof(input)?,
        "principal-control-realm-id" => principal_control_realm(input)?,
        "account-handoff-request" => account_handoff_request(input)?,
        "principal-registration-fixture" => principal_registration_fixture(input)?,
        "identity-creation-register-request" => identity_creation_register_request(input)?,
        "pre-registration-session-request" => pre_registration_session_request(input)?,
        "cross-signing-binding-input" => cross_signing_binding_input(input)?,
        "device-trust-binding-input" => device_trust_binding_input(input)?,
        _ => bail!("unknown cotest-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn capability_action_registry_digest() -> Result<Value> {
    let digest = arkret::current_capability_action_registry_digest()
        .context("load SDK capability-action registry digest")?;
    Ok(json!({ "digest": digest.as_str() }))
}

fn principal_registration_fixture(input: Value) -> Result<Value> {
    let input: PrincipalRegistrationFixtureInput =
        serde_json::from_value(input).context("parse principal-registration fixture input")?;
    let endpoint =
        url::Url::parse(&input.principal_server_url).context("parse principal server URL")?;
    let created_at = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);

    // Cotest fixture entropy is unique to this registration and never leaves
    // the local test process except as the user-facing mnemonic. Production
    // recovery-key generation remains OS-CSPRNG backed in Inkson.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos();
    let mut entropy_hasher = Sha256::new();
    entropy_hasher.update(b"cotest-principal-registration-v1");
    entropy_hasher.update(input.handoff_request_id.as_bytes());
    entropy_hasher.update(input.device_id.as_bytes());
    entropy_hasher.update(nonce.to_le_bytes());
    let entropy: [u8; 32] = entropy_hasher.finalize().into();
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .context("build 24-word principal recovery mnemonic")?;
    let recovery_key = mnemonic.words().collect::<Vec<_>>().join(" ");
    let key_material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &recovery_key,
        "",
        0,
    )
    .context("derive principal recovery key material")?;
    let draft =
        arkret::webvh::prepare_principal_inception(&arkret::webvh::PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &input
                .handoff_request_id
                .trim_start_matches("ak:request:")
                .to_ascii_lowercase(),
            also_known_as: &[],
            version_time: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
            enrollment: arkret::webvh::PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: &input.enrollment_authority_did,
            },
        })
        .context("prepare principal inception")?;
    let principal = Did::new(draft.did.clone()).context("parse prepared principal DID")?;
    let control_realm = principal_control_realm_id(&principal);
    let mut hlc = arkret::hlc::HlcGenerator::new(
        &control_realm,
        &input.device_id,
        input.handoff_request_id.as_bytes(),
    );
    let recovery_key_fingerprint = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(recovery_key.as_bytes()))
    );
    let did_operation = serde_json::to_value(&draft.submit_body)
        .context("serialize prepared principal DID operation")?;
    let lease: arkret::IdentityCreationLease =
        serde_json::from_value(input.identity_creation_lease)
            .context("parse identity-creation lease")?;
    let challenge_request = garth::identity_binding_challenge_request(
        arkret::RequestId::new(arkret_identifiers::new_prefixed_uuid7("ak:request:"))
            .context("build identity-binding challenge request id")?,
        &lease,
        draft.submit_body,
    )
    .context("build identity-binding challenge request")?;
    let checkpoint = json!({
        "principal_server_url": input.principal_server_url,
        "gate_account_base": input.gate_account_base,
        "handoff_request_id": input.handoff_request_id,
        "lease_id": lease.lease_id,
        "lease_fence": lease.fence,
        "device_id": input.device_id,
        "enrollment_authority_did": input.enrollment_authority_did,
        "trust_domain": input.trust_domain,
        "did": draft.did,
        "version_id": draft.version_id,
        "root_public_key_multibase": draft.root_public_key_multibase,
        "root_verification_method": draft.root_verification_method,
        "next_root_public_key_multibase": draft.next_root_public_key_multibase,
        "next_root_key_hash": draft.next_root_key_hash,
        "recovery_proof_public_key_multibase": key_material.recovery_proof_public_key_multikey,
        "backup_hpke_public_key_multibase": key_material.backup_hpke_public_key_multikey,
        "recovery_key_fingerprint": recovery_key_fingerprint,
        "did_operation": did_operation,
        "bootstrap_create_event_id": arkret_identifiers::new_prefixed_uuid7("ak:event:"),
        "bootstrap_created_at": arkret_canonical::format_timestamp_canonical(created_at),
        "bootstrap_hlc": hlc.generate().to_string(),
        "binding_receipt": null,
        "stage": "custody_confirmed",
    });
    Ok(json!({
        "did_operation": checkpoint["did_operation"],
        "recovery_key": recovery_key,
        "checkpoint": checkpoint,
        "challenge_request": challenge_request,
    }))
}

fn account_handoff_request(input: Value) -> Result<Value> {
    let input: AccountHandoffRequestFixtureInput =
        serde_json::from_value(input).context("parse account-handoff request input")?;
    let signing_key = signing_key_from_seed(&input.dpop_seed_b64url)?;
    let request = garth::oidc_account_handoff_request(
        garth::OidcAccountHandoffInput {
            request_id: arkret::RequestId::new(input.request_id)
                .context("parse account-handoff request id")?,
            audience: Did::new(input.audience).context("parse handoff audience")?,
            issuer: input.issuer,
            client_id: input.client_id,
            redirect_uri: input.redirect_uri,
            state: input.state,
            nonce: input.nonce,
            authorization_code: input.authorization_code,
            code_verifier: input.code_verifier,
        },
        |bytes| {
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.sign(bytes).to_bytes()))
        },
    )
    .context("build account-handoff request")?;
    serde_json::to_value(request).context("serialize account-handoff request")
}

fn identity_creation_register_request(input: Value) -> Result<Value> {
    let input: IdentityCreationRegisterFixtureInput =
        serde_json::from_value(input).context("parse identity-creation register input")?;
    let challenge: arkret::IdentityBindingChallengeOutcome =
        serde_json::from_value(input.challenge).context("parse identity-binding challenge")?;
    let did_operation: arkret::DidOperationSubmitRequestBody =
        serde_json::from_value(input.did_operation).context("parse DID operation")?;
    let key_material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &input.recovery_key,
        "",
        0,
    )
    .context("derive identity root for control proof")?;
    let request = garth::identity_creation_register_request(
        &challenge,
        did_operation,
        &key_material.root_seed,
        input.display_name,
    )
    .context("build identity-creation register request")?;
    serde_json::to_value(request).context("serialize identity-creation register request")
}

fn pre_registration_session_request(input: Value) -> Result<Value> {
    let input: PreRegistrationSessionFixtureInput =
        serde_json::from_value(input).context("parse pre-registration session input")?;
    let signing_key = signing_key_from_seed(&input.dpop_seed_b64url)?;
    let expires_at = canonical::parse_timestamp_canonical(&input.expires_at)
        .context("parse pre-registration proof expiry")?;
    let request = garth::pre_registration_session_grant_request(
        Did::new(input.principal_id).context("parse session principal")?,
        Some(DeviceId::new(input.device_id).context("parse session device id")?),
        input.requested_scope,
        &input.account_handoff_grant,
        Did::new(input.audience).context("parse session audience")?,
        expires_at,
        |bytes| {
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.sign(bytes).to_bytes()))
        },
    )
    .context("build pre-registration session request")?;
    serde_json::to_value(request).context("serialize pre-registration session request")
}

fn signing_key_from_seed(seed_b64url: &str) -> Result<SigningKey> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seed_b64url)
        .context("decode Ed25519 seed")?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("Ed25519 seed must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn read_stdin_json() -> Result<Value> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("read stdin")?;
    serde_json::from_str(&stdin).context("parse stdin JSON")
}

fn canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse canonical input")?;
    let bytes = canonical::canonical_json_bytes(&input.value).context("canonical JSON encode")?;
    let canonical = String::from_utf8(bytes).context("canonical JSON was not UTF-8")?;
    Ok(json!({ "canonical": canonical }))
}

fn sha256_canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse digest input")?;
    let digest = canonical::canonical_sha256(&input.value).context("canonical JSON digest")?;
    Ok(json!({
        "digest": digest,
        "digest_hex": digest.strip_prefix("sha256:").unwrap_or(digest.as_str()),
    }))
}

fn principal_control_realm(input: Value) -> Result<Value> {
    let input: PrincipalControlRealmInput =
        serde_json::from_value(input).context("parse principal-control realm input")?;
    let principal = Did::new(input.principal_id).context("parse principal DID")?;
    Ok(json!({
        "realm_id": principal_control_realm_id(&principal),
    }))
}

/// 05-2 — deserialize a full `ak.cross_signing.publish` payload (the shape the
/// TypeScript conformance builder emits) into the SDK's
/// `CrossSigningPublish` and return the SDK-authoritative PSK→SSK and
/// PSK→USK `ak.cross-signing-bind-v1` canonical signing inputs. The TS
/// `crossSigningBindingInput` byte-mirror is regression-checked against these
/// bytes so a drift in the prefix / body field-set / canonical-JSON encoding
/// is caught cross-language.
fn cross_signing_binding_input(input: Value) -> Result<Value> {
    let content: CrossSigningPublish =
        serde_json::from_value(input).context("parse cross_signing.publish content")?;
    let self_signing = content
        .self_signing_binding_input()
        .map_err(|err| anyhow::anyhow!("self_signing binding input: {err}"))?;
    let user_signing = content
        .user_signing_binding_input()
        .map_err(|err| anyhow::anyhow!("user_signing binding input: {err}"))?;
    Ok(json!({
        "self_signing_input_b64": base64::engine::general_purpose::STANDARD.encode(&self_signing),
        "user_signing_input_b64": base64::engine::general_purpose::STANDARD.encode(&user_signing),
    }))
}

/// 05-2 — SDK-authoritative `ak.device-trust-bind-v1` canonical signing input
/// (SSK→device) for the TS `deviceTrustBindingInput` byte-mirror to regress
/// against.
fn device_trust_binding_input(input: Value) -> Result<Value> {
    let args: DeviceTrustBindingInputArgs =
        serde_json::from_value(input).context("parse device-trust binding input args")?;
    let principal = Did::new(args.principal_id).context("parse principal DID")?;
    let device_id = DeviceId::new(args.device_id).context("parse device id")?;
    let bytes = DeviceTrustBinding::canonical_input(
        &principal,
        &device_id,
        &args.device_public_key,
        &args.hpke_key,
        &args.algorithms,
        args.ssk_generation,
    )
    .map_err(|err| anyhow::anyhow!("device-trust binding input: {err}"))?;
    Ok(json!({
        "input_b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
    }))
}

#[derive(Clone, Copy)]
enum EventDigestMode {
    RawCanonicalJson,
}

fn event_proof(input: Value, digest_mode: EventDigestMode) -> Result<Value> {
    let input: EventProofInput =
        serde_json::from_value(input).context("parse event proof input")?;
    let actor = Did::new(input.actor_did.clone()).context("parse actor DID")?;
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let event_digest =
        Hash::new(event_digest(&input.event, digest_mode)?).context("parse event digest")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse event signing seed")?,
        None => development_event_signing_key(&input.verification_method),
    };

    let mut proof = Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: input.verification_method,
        event_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding_bytes = proof
        .canonical_binding_bytes(&actor)
        .context("encode event proof binding")?;
    proof.jws = arkret_signatures::proof::sign_eddsa_detached_jws(&signing_key, &binding_bytes)
        .map_err(|err| anyhow::anyhow!("sign event proof: {err}"))?;

    serde_json::to_value(proof).context("serialize event proof")
}

fn mimi_consent_proof(input: Value) -> Result<Value> {
    let input: MimiConsentProofInput =
        serde_json::from_value(input).context("parse MIMI consent proof input")?;
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let consent_id = input
        .request
        .get("consent_id")
        .and_then(Value::as_str)
        .context("MIMI consent request requires consent_id")?;
    let decision = input
        .request
        .get("decision")
        .cloned()
        .context("MIMI consent request requires decision")?;
    let actor_id = input
        .request
        .get("actor_id")
        .and_then(Value::as_str)
        .context("MIMI consent request requires actor_id")?;
    let reason = input
        .request
        .get("reason")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let expires_at = input
        .request
        .get("expires_at")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .context("parse MIMI consent expires_at")?;
    let mut request = MimiUpdateConsentRequestBody {
        consent_id: ConsentId::new(consent_id.to_owned()).context("parse consent id")?,
        decision: serde_json::from_value::<MimiConsentDecision>(decision)
            .context("parse consent decision")?,
        actor_id: Did::new(actor_id.to_owned()).context("parse consent actor DID")?,
        signature: PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: input.verification_method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .context("build placeholder payload digest")?,
            created_at,
            domain: Some(input.domain),
            audience: Some(Audience::Single(input.audience)),
            proof_purpose: None,
            jws: "pending".to_owned(),
        },
        reason,
        expires_at,
    };
    request.signature.payload_digest =
        request.payload_digest().context("digest consent request")?;
    let binding = request
        .signature_binding_bytes()
        .context("encode MIMI consent proof binding")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse MIMI consent signing seed")?,
        None => development_event_signing_key(&input.verification_method),
    };
    request.signature.jws =
        arkret_signatures::proof::sign_eddsa_detached_jws(&signing_key, &binding)
            .map_err(|error| anyhow::anyhow!("sign MIMI consent proof: {error}"))?;
    serde_json::to_value(request.signature).context("serialize MIMI consent proof")
}

fn event_digest(event: &Value, _mode: EventDigestMode) -> Result<String> {
    // Use the SDK projection that every verifier uses. Deserializing before
    // hashing is significant: wire defaults such as EventRef.critical=true
    // are part of Event::digest_payload even when the producer omitted them.
    let mut event = event.clone();
    if let Value::Object(object) = &mut event {
        object
            .entry("proofs")
            .or_insert_with(|| Value::Array(Vec::new()));
    }
    let event: Event = serde_json::from_value(event).context("parse SDK Event digest payload")?;
    let payload = event
        .digest_payload()
        .context("build SDK Event digest payload")?;
    canonical::canonical_sha256(&payload).context("hash event digest payload")
}

fn development_event_signing_key(verification_method: &str) -> SigningKey {
    arkret_signatures::development_signing_key(verification_method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_digest_uses_producer_envelope_canonical_bytes() {
        let event = json!({
            "event_id": "ak:event:019f3b1c-784d-7fc0-965f-0550baae7184",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02"},
            "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "schema": ["ak.schema.event_payload.v1"],
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
                "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
                "membership": "join",
                "reason": "invite_accept"
            },
            "unsigned": {"trace": "local"},
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02"
            },
            "actor_kind": "native",
            "proofs": []
        });

        let digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let producer_event: Event = serde_json::from_value(event).unwrap();
        let producer_event = producer_event.digest_payload().unwrap();

        assert_eq!(
            digest,
            canonical::canonical_sha256(&producer_event).unwrap()
        );
    }

    #[test]
    fn event_digest_materializes_sdk_ref_defaults() {
        let event = json!({
            "event_id": "ak:event:019f3b1c-784d-7fc0-965f-0550baae7184",
            "kind": "ak.morph.schema_migrate",
            "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02"},
            "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [{
                "role": "authorized_by",
                "id": "ak:event:019f3b1c-784d-7fc0-965f-0550baae7185"
            }],
            "requirements": {"schema": ["ak.schema.event_payload.v1"]},
            "payload": {
                "morph_id": "ak:morph:019f3b1c-784d-7fc0-965f-0550baae7186",
                "from_schema_refs": ["ak.schema.morph.customer_risk.v1"],
                "to_schema_refs": ["ak.schema.morph.customer_risk.ext.v1"],
                "compatibility_class": "transformation"
            }
        });
        let raw_digest = canonical::canonical_sha256(&event).unwrap();
        let sdk_digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let mut event_with_proofs = event;
        event_with_proofs["proofs"] = json!([]);
        let sdk_event: Event = serde_json::from_value(event_with_proofs).unwrap();
        let sdk_payload = sdk_event.digest_payload().unwrap();

        assert_eq!(sdk_payload["refs"][0]["critical"], json!(true));
        assert_ne!(sdk_digest, raw_digest);
        assert_eq!(
            sdk_digest,
            canonical::canonical_sha256(&sdk_payload).unwrap()
        );
    }

    #[test]
    fn fallback_event_signer_uses_sdk_method_bound_development_key() {
        let method = "did:webvh:z6mkfixture:alice.example#device";

        assert_eq!(
            development_event_signing_key(method).verifying_key(),
            arkret_signatures::development_verifying_key(method)
        );
        assert_ne!(
            development_event_signing_key(method).verifying_key(),
            arkret_signatures::development_verifying_key(
                "did:webvh:z6mkfixture:alice.example#other-device"
            )
        );
    }

    #[test]
    fn capability_registry_digest_is_sdk_authoritative() {
        let output = capability_action_registry_digest().unwrap();
        let expected = arkret::current_capability_action_registry_digest().unwrap();

        assert_eq!(output["digest"], expected.as_str());
    }

    #[test]
    fn event_proof_with_registered_seed_verifies_through_sdk() {
        let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let verification_method = format!("{actor}#principal-signing-key");
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let event = json!({
            "event_id": "ak:event:019f3b1c-784d-7fc0-965f-0550baae7184",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02"},
            "actor_id": actor,
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "schema": ["ak.schema.event_payload.v1"],
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02",
                "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f3b1c-6fc8-7f20-9715-66c42a93ad02"},
                "actor_id": actor,
                "membership": "join"
            }
        });
        let proof_value = event_proof(
            json!({
                "actor_did": actor,
                "verification_method": verification_method,
                "created_at": "2026-07-07T05:45:49.000Z",
                "event": event,
                "signing_seed_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(seed)
            }),
            EventDigestMode::RawCanonicalJson,
        )
        .unwrap();
        let proof: Proof = serde_json::from_value(proof_value).unwrap();

        let mut event_with_proofs = event;
        event_with_proofs["proofs"] = json!([]);
        let sdk_event: Event = serde_json::from_value(event_with_proofs).unwrap();
        let canonical_bytes =
            canonical::canonical_json_bytes(&sdk_event.digest_payload().unwrap()).unwrap();
        let public_key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };

        assert_eq!(proof.verification_method, verification_method);
        arkret_signatures::proof::verify_eddsa_detached_jws_proof(
            &proof,
            &canonical_bytes,
            &actor,
            &public_key,
        )
        .unwrap();
    }
}
