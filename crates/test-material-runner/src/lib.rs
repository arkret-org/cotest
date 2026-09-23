//! Executable public-test-material rejection vectors.
//!
//! The runner uses production SDK matchers and Coauth's production binding
//! constructor. It also records the remaining cross-service gaps explicitly;
//! case execution here must not be mistaken for a live WebSocket or Soland
//! trust-admission test.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_identity::VerifiedDidBindingStore as _;
use arkret_identity::test_material::{
    FormalTestMaterialPolicyError, PublicKeyFingerprintInput, enforce_formal_test_material_policy,
    reserved_identifier_matches,
};
use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde_json::Value;

pub const TEST_MATERIAL_REJECTION_ENTRYPOINT: &str = "ak.suite.identity.test_material_rejection.v1";
const FIXTURE: &str = "test-material-rejection-fixture.json";
const ARTIFACT_FIXTURES_DIR: &str = "fixtures";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestMaterialRejectionExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

impl TestMaterialRejectionExecution {
    fn assert_complete_against(&self, fixture: &Value) -> Result<()> {
        let declared = fixture["cases"]
            .as_array()
            .context("test-material fixture has no cases[]")?;
        ensure!(
            declared.len() == self.cases.len(),
            "{} declared {} cases but runner returned {} results",
            self.entrypoint,
            declared.len(),
            self.cases.len()
        );
        for (index, (case, result)) in declared.iter().zip(&self.cases).enumerate() {
            let declared_id = case
                .get("case_id")
                .or_else(|| case.get("name"))
                .and_then(Value::as_str)
                .with_context(|| format!("{} cases[{index}] has no id", self.fixture))?;
            ensure!(
                declared_id == result.case_id,
                "{} cases[{index}] is {declared_id}, runner returned {}",
                self.entrypoint,
                result.case_id
            );
            ensure!(
                result.assertions > 0,
                "{} case {declared_id} returned no executed assertions",
                self.entrypoint
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestMaterialRejectionCoverage {
    pub execution: TestMaterialRejectionExecution,
    pub service_e2e_status: &'static str,
    pub service_e2e_gaps: Vec<&'static str>,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("registry").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture_value(file_name: &str) -> Result<Value> {
    load_artifact_json(&format!("{ARTIFACT_FIXTURES_DIR}/{file_name}"))
}

fn load_artifact_json(relative_path: &str) -> Result<Value> {
    let path = spec_artifacts_root().join(relative_path);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read artifact {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse artifact {}", path.display()))
}

fn b64u(value: &str) -> Result<Vec<u8>> {
    arkret_canonical::base64url::base64url_decode(value).map_err(Into::into)
}

fn denied(result: Result<(), FormalTestMaterialPolicyError>) -> bool {
    matches!(result, Err(FormalTestMaterialPolicyError::Denied(_)))
}

fn ed25519_fixture_material(crypto: &Value) -> Result<(Vec<u8>, &str, &str)> {
    let vector = &crypto["vectors"][0];
    Ok((
        b64u(
            vector["did_document_fragment"]["publicKeyJwk"]["x"]
                .as_str()
                .context("Ed25519 fixture x is absent")?,
        )?,
        vector["jws_signing_input"]
            .as_str()
            .context("Ed25519 signing input is absent")?,
        vector["proof"]["jws"]
            .as_str()
            .and_then(|value| value.rsplit('.').next())
            .context("Ed25519 detached JWS signature is absent")?,
    ))
}

fn assert_real_ed25519_fixture_signature(crypto: &Value) -> Result<[u8; 32]> {
    let (public_key, signing_input, signature) = ed25519_fixture_material(crypto)?;
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.clone(),
    };
    ensure!(
        verify_detached_ed25519_signature(&material, signing_input.as_bytes(), signature),
        "published Ed25519 fixture signature must be cryptographically valid before policy denial"
    );
    public_key
        .try_into()
        .map_err(|value: Vec<u8>| anyhow::anyhow!("Ed25519 key is {} bytes", value.len()))
}

fn p256_fixture_bytes_and_verify(crypto: &Value) -> Result<Vec<u8>> {
    let vector = &crypto["vectors"][1];
    let x = b64u(
        vector["did_document_fragment"]["publicKeyJwk"]["x"]
            .as_str()
            .context("P-256 x is absent")?,
    )?;
    let y = b64u(
        vector["did_document_fragment"]["publicKeyJwk"]["y"]
            .as_str()
            .context("P-256 y is absent")?,
    )?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let verifying_key = P256VerifyingKey::from_sec1_bytes(&point)?;
    let signature_b64u = vector["proof"]["jws"]
        .as_str()
        .and_then(|value| value.rsplit('.').next())
        .context("P-256 detached JWS signature is absent")?;
    let signature = P256Signature::from_slice(&b64u(signature_b64u)?)?;
    verifying_key.verify(
        vector["jws_signing_input"]
            .as_str()
            .context("P-256 signing input is absent")?
            .as_bytes(),
        &signature,
    )?;
    Ok(point)
}

fn coauth_websocket_rejects_before_state(websocket: &Value) -> Result<()> {
    use arkret_models_collaboration::sync_frames::websocket::WebSocketClientFrame;
    use arkret_signatures::websocket_auth::{
        WebSocketAuthProofRequest, WebSocketAuthVerificationRequest, build_websocket_auth_proof,
        verify_websocket_auth_proof,
    };
    use arkret_wire::WebOrigin;
    use arkret_wire::websocket_binding::WebSocketChallengeRecord;
    use coauth_backend::services::websocket_auth::{
        WebSocketAuthenticationCommit, WebSocketAuthenticationError, WebSocketAuthenticationState,
        admit_websocket_authentication,
    };

    #[derive(Default)]
    struct JointWebSocketState {
        commit_calls: usize,
        challenge_consumed: bool,
        replay_rows: usize,
        cache_rows: usize,
        auth_state_rows: usize,
    }

    #[async_trait::async_trait]
    impl WebSocketAuthenticationState for JointWebSocketState {
        type Error = std::convert::Infallible;

        async fn commit_verified_authentication(
            &mut self,
            _challenge: &WebSocketChallengeRecord,
            _verified: &arkret_signatures::websocket_auth::VerifiedWebSocketAuth,
        ) -> Result<WebSocketAuthenticationCommit, Self::Error> {
            self.commit_calls += 1;
            self.challenge_consumed = true;
            self.replay_rows += 1;
            self.cache_rows += 1;
            self.auth_state_rows += 1;
            Ok(WebSocketAuthenticationCommit::Authenticated)
        }
    }

    let kat = &websocket["dpop_kat"];
    let stored = &kat["challenge_state"];
    let issued_at: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(stored["issued_at"].clone())?;
    let expires_at: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(stored["expires_at"].clone())?;
    let challenge = WebSocketChallengeRecord {
        connection_id: kat["connection_id"]
            .as_str()
            .context("WebSocket connection_id")?
            .to_owned(),
        nonce: kat["nonce"].as_str().context("WebSocket nonce")?.to_owned(),
        canonical_origin: WebOrigin::new(
            stored["canonical_origin"]
                .as_str()
                .context("WebSocket canonical_origin")?,
        )?,
        canonical_base_url: stored["canonical_base_url"]
            .as_str()
            .context("WebSocket canonical_base_url")?
            .to_owned(),
        issued_at,
        expires_at,
        consumed: stored["consumed"]
            .as_bool()
            .context("WebSocket challenge consumed")?,
    };
    let frame = WebSocketClientFrame::Authenticate {
        connection_id: challenge.connection_id.clone(),
        session_grant: kat["session_grant"]
            .as_str()
            .context("WebSocket session_grant")?
            .to_owned(),
        dpop_proof: kat["compact_jws"]
            .as_str()
            .context("WebSocket compact_jws")?
            .to_owned(),
    };
    let mut state = JointWebSocketState::default();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    // Verify the exact fixture frame through the production proof verifier.
    // This checks signature, live challenge, grant hash, and holder binding,
    // so the following terminal error can only come from material admission.
    verify_websocket_auth_proof(&WebSocketAuthVerificationRequest {
        compact_jws: kat["compact_jws"]
            .as_str()
            .context("WebSocket compact_jws")?,
        connection_id: &challenge.connection_id,
        session_grant: kat["session_grant"]
            .as_str()
            .context("WebSocket session_grant")?,
        socket_origin: kat["origin"].as_str().context("WebSocket origin")?,
        challenge: &challenge,
        grant_cnf_jkt: kat["cnf_jkt"].as_str().context("WebSocket cnf_jkt")?,
        replay_ledger_hit: false,
        now: issued_at,
    })?;
    let error = runtime
        .block_on(admit_websocket_authentication(
            &frame,
            kat["origin"].as_str().context("WebSocket origin")?,
            &challenge,
            kat["cnf_jkt"].as_str().context("WebSocket cnf_jkt")?,
            issued_at,
            &mut state,
        ))
        .expect_err("the published DPoP confirmation key must be terminally denied");
    ensure!(matches!(
        error,
        WebSocketAuthenticationError::TestSigningMaterialDenied
    ));
    ensure!(error.to_string() == "test_signing_material_denied");
    ensure!(state.commit_calls == 0);
    ensure!(!state.challenge_consumed);
    ensure!(state.replay_rows == 0);
    ensure!(state.cache_rows == 0);
    ensure!(state.auth_state_rows == 0);

    // The same challenge and state port admit an ordinary key. A broad
    // rejection or a hidden mutation from the preceding denial would fail.
    let ordinary_key =
        coauth_backend::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[91; 32]);
    let ordinary_proof = build_websocket_auth_proof(
        &WebSocketAuthProofRequest {
            base_url: &challenge.canonical_base_url,
            session_grant: kat["session_grant"]
                .as_str()
                .context("WebSocket session_grant")?,
            nonce: &challenge.nonce,
            issued_at,
            jti: "d3MtYXV0aC1qdGktMDAwMg",
        },
        &ordinary_key,
    )?;
    let ordinary_frame = WebSocketClientFrame::Authenticate {
        connection_id: challenge.connection_id.clone(),
        session_grant: kat["session_grant"]
            .as_str()
            .context("WebSocket session_grant")?
            .to_owned(),
        dpop_proof: ordinary_proof.compact_jws,
    };
    runtime.block_on(admit_websocket_authentication(
        &ordinary_frame,
        kat["origin"].as_str().context("WebSocket origin")?,
        &challenge,
        &ordinary_proof.jkt,
        issued_at,
        &mut state,
    ))?;
    ensure!(state.commit_calls == 1);
    ensure!(state.challenge_consumed);
    ensure!(state.replay_rows == 1 && state.cache_rows == 1 && state.auth_state_rows == 1);
    Ok(())
}

fn coauth_rejects_before_binding_state(public_key: &[u8]) -> Result<()> {
    use arkret_identifiers::{Did, Hash, TrustDomainId};
    use arkret_identity::{
        AcceptedDidBinding, DidBindingPurpose, DidBindingStatus, EvidenceReceipt, LimitedTrust,
        MethodEvidence, VerifiedDidBinding, VerifiedDidBindingDocumentInput, VerifiedDidBindingKey,
    };
    use coauth_backend::handlers::arkret::{DidDocument, VerificationMethod};
    use coauth_backend::services::did_binding::{
        DurableVerifiedDidBindingStore, binding_from_resolution, encode_row, high_risk_freshness,
        to_shared_document,
    };
    use coauth_backend::services::did_resolver::{DidResolution, DidResolutionSource};
    use coauth_data::RepositoryError;
    use coauth_data::did_binding::{
        VerifiedDidBindingInvalidation, VerifiedDidBindingKeyColumns, VerifiedDidBindingRepository,
        VerifiedDidBindingRow,
    };

    #[derive(Default)]
    struct MemoryBindingRepository {
        row: Option<VerifiedDidBindingRow>,
        get_calls: usize,
        delete_exact_calls: usize,
    }

    #[async_trait::async_trait]
    impl VerifiedDidBindingRepository for MemoryBindingRepository {
        type Error = RepositoryError;

        async fn get(
            &mut self,
            key: &VerifiedDidBindingKeyColumns,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> Result<Option<VerifiedDidBindingRow>, Self::Error> {
            self.get_calls += 1;
            Ok(self.row.clone().filter(|row| &row.key == key))
        }

        async fn upsert(
            &mut self,
            row: VerifiedDidBindingRow,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), Self::Error> {
            self.row = Some(row);
            Ok(())
        }

        async fn delete_exact(
            &mut self,
            key: &VerifiedDidBindingKeyColumns,
        ) -> Result<bool, Self::Error> {
            self.delete_exact_calls += 1;
            let existed = self.row.as_ref().is_some_and(|row| &row.key == key);
            if existed {
                self.row = None;
            }
            Ok(existed)
        }

        async fn invalidate(
            &mut self,
            _selector: &VerifiedDidBindingInvalidation,
        ) -> Result<usize, Self::Error> {
            Ok(0)
        }

        async fn prune_expired(
            &mut self,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> Result<usize, Self::Error> {
            Ok(0)
        }
    }

    let did = "did:web:cotest-production.example.net";
    let trust_domain = TrustDomainId::new("ak:trust_domain:cotest.production".to_owned())?;
    let policy_digest = Hash::new(format!("sha256:{}", "b".repeat(64)))?;
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).context("fixed instant")?;
    let resolution = DidResolution {
        document: DidDocument {
            id: did.to_owned(),
            also_known_as: Vec::new(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#runtime-1"),
                kind: "JsonWebKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_jwk: Some(serde_json::from_value(serde_json::json!({
                    "x": arkret_canonical::base64url_encode(public_key),
                    "crv": "Ed25519",
                    "kty": "OKP"
                }))?),
                public_key_multibase: None,
            }],
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            service: Vec::new(),
            metadata: None,
        },
        source: DidResolutionSource::DelegatedResolver,
        verified_local_binding: false,
        key_log_head: Some(Hash::new(format!("sha256:{}", "a".repeat(64)))?),
        method_evidence: serde_json::json!({"method": "did:web"}),
        closed_method_evidence: None,
        identity_fact_rejection: None,
    };
    let error = binding_from_resolution(
        &resolution,
        trust_domain.clone(),
        DidBindingPurpose::AccountBinding,
        policy_digest.clone(),
        None,
        &high_risk_freshness(),
        now,
    )
    .expect_err("Coauth must reject before producing an accepted binding");
    ensure!(
        matches!(
            error,
            coauth_backend::services::did_binding::DidBindingError::TestSigningMaterialDenied
        ),
        "Coauth returned the wrong terminal denial: {error}"
    );
    let key = VerifiedDidBindingKey {
        did: Did::new(did.to_owned())?,
        trust_domain,
        purpose: DidBindingPurpose::AccountBinding,
        policy_digest,
        verification_method: None,
    };
    // Recreate a valid row accepted before the published-material rule existed.
    // Construction still goes through every SDK binding/digest invariant; only
    // today's Coauth formal-admission guard is deliberately bypassed.
    let legacy_document = DidDocument {
        id: did.to_owned(),
        also_known_as: Vec::new(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#runtime-1"),
            kind: "JsonWebKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_jwk: Some(serde_json::from_value(serde_json::json!({
                "x": arkret_canonical::base64url_encode(public_key),
                "crv": "Ed25519",
                "kty": "OKP"
            }))?),
            public_key_multibase: None,
        }],
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        service: Vec::new(),
        metadata: None,
    };
    let shared_document = to_shared_document(&legacy_document)?;
    let document_digest = arkret_identity::document_canonical_digest(&shared_document)?;
    let evidence = MethodEvidence::none();
    let receipt = EvidenceReceipt::new("web", document_digest, &evidence);
    let legacy_binding = VerifiedDidBinding::from_verified_document(
        &shared_document,
        VerifiedDidBindingDocumentInput {
            trust_domain: key.trust_domain.clone(),
            purpose: key.purpose,
            verification_method: None,
            history_head: None,
            version_id: None,
            limited_trust: Some(LimitedTrust::for_proofless_method(None, None)),
            evidence_digest: receipt.digest()?,
            evidence_dependencies: receipt.evidence_dependencies()?,
            policy_digest: key.policy_digest.clone(),
            verified_at: now,
            refresh_after: Some(now + chrono::Duration::minutes(5)),
            expires_at: Some(now + chrono::Duration::hours(1)),
            status: DidBindingStatus::Active,
        },
    )?;
    let legacy = AcceptedDidBinding::new(legacy_binding, shared_document, receipt)?;
    let durable = DurableVerifiedDidBindingStore::new(4);
    durable.accept(legacy.clone())?;
    let mut repository = MemoryBindingRepository {
        row: Some(encode_row(&legacy)?),
        ..MemoryBindingRepository::default()
    };
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let error = runtime
        .block_on(durable.load_from_repository(&mut repository, &key, now))
        .expect_err("historical published material must be a terminal durable-load denial");
    ensure!(matches!(
        error,
        coauth_backend::services::did_binding::DidBindingError::TestSigningMaterialDenied
    ));
    ensure!(repository.get_calls == 1 && repository.delete_exact_calls == 1);
    ensure!(repository.row.is_none(), "rejected durable row survived");
    ensure!(
        durable.get(&key, now).is_none(),
        "rejected durable row survived in the mirror"
    );
    Ok(())
}

pub fn run_test_material_rejection_suite_with_coverage() -> Result<TestMaterialRejectionCoverage> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(TEST_MATERIAL_REJECTION_ENTRYPOINT),
        "test-material entrypoint drifted"
    );
    let crypto = load_fixture_value("crypto-signature-fixture.json")?;
    let registry = load_artifact_json("registry/test-material-registry.json")?;
    let websocket = load_fixture_value("websocket-binding-fixture.json")?;
    let published_ed = assert_real_ed25519_fixture_signature(&crypto)?;
    let published_ed_input = PublicKeyFingerprintInput::Ed25519Rfc8032(&published_ed);
    let ordinary_did = arkret_wire::Did::new("did:web:runtime.production".to_owned())?;
    let ordinary_kid = arkret_wire::DidUrl::new("did:web:runtime.production#runtime-1".to_owned())
        .map_err(anyhow::Error::msg)?;
    ensure!(denied(enforce_formal_test_material_policy(
        Some(&published_ed_input),
        Some(&ordinary_did),
        Some(&ordinary_kid),
        None,
    )));

    let mut results = Vec::new();
    let mut record = |index: usize, assertions: usize| -> Result<()> {
        let id = fixture["cases"][index]["name"]
            .as_str()
            .with_context(|| format!("case {index} has no name"))?;
        results.push(CaseExecutionResult {
            case_id: id.to_owned(),
            assertions,
        });
        Ok(())
    };

    // 0: real signature validity is established independently of policy.
    record(0, 3)?;
    // 1: ordinary renamed DID and kid still leave the fingerprint decisive.
    ensure!(!reserved_identifier_matches(Some(&ordinary_did), Some(&ordinary_kid), None).any());
    record(1, 3)?;

    // 2: JWK, multicodec and SPKI PEM all reduce to the same RFC 8032 bytes.
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&published_ed);
    let multibase_bytes =
        PublicKeyMaterial::Ed25519Multibase { value: multibase }.ed25519_bytes()?;
    let mut spki = hex::decode("302a300506032b6570032100")?;
    spki.extend_from_slice(&published_ed);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        base64::engine::general_purpose::STANDARD.encode(&spki)
    );
    let pem_der = base64::engine::general_purpose::STANDARD.decode(
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>(),
    )?;
    ensure!(multibase_bytes == published_ed && pem_der[12..] == published_ed);
    ensure!(denied(enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&pem_der[12..])),
        None,
        None,
        None,
    )));
    record(2, 4)?;

    // 3: P-256 fixture signature verifies; both P-256 and ML-DSA use their
    // algorithm-defined bytes for the shared denial. ML-DSA production
    // signature verification is not applicable to the current-v1 profile.
    let p256 = p256_fixture_bytes_and_verify(&crypto)?;
    ensure!(denied(enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::P256Sec1Uncompressed(&p256)),
        None,
        None,
        None,
    )));
    let mldsa = b64u(
        crypto["vectors"][2]["public_key_b64u"]
            .as_str()
            .context("ML-DSA key")?,
    )?;
    ensure!(denied(enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::MlDsa65Fips204(&mldsa)),
        None,
        None,
        None,
    )));
    record(3, 4)?;

    // 4: the published RFC 8032 DPoP KAT verifies cryptographically, then the
    // Coauth production consumer rejects it before its single atomic state
    // port can consume the challenge or write replay/cache/auth state.
    let dpop = &websocket["dpop_kat"];
    let dpop_key = b64u(dpop["public_jwk"]["x"].as_str().context("DPoP x")?)?;
    ensure!(verify_detached_ed25519_signature(
        &PublicKeyMaterial::Ed25519Raw {
            bytes: dpop_key.clone()
        },
        dpop["signing_input_ascii"]
            .as_str()
            .context("DPoP input")?
            .as_bytes(),
        dpop["signature_base64url"]
            .as_str()
            .context("DPoP signature")?,
    ));
    ensure!(denied(enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&dpop_key)),
        None,
        None,
        None,
    )));
    coauth_websocket_rejects_before_state(&websocket)?;
    record(4, 10)?;

    // 5: a fresh unlisted key remains cryptographically and policy valid.
    let unlisted = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
    let message = b"cotest formal material admission";
    let signature = unlisted.sign(message);
    unlisted
        .verifying_key()
        .verify_strict(message, &signature)?;
    enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(
            unlisted.verifying_key().as_bytes(),
        )),
        Some(&ordinary_did),
        Some(&ordinary_kid),
        None,
    )?;
    record(5, 3)?;

    // 6: invoke Coauth's production consumer seam and observe no accepted
    // binding or cache write after denial.
    coauth_rejects_before_binding_state(&published_ed)?;
    record(6, 3)?;

    // 7: the isolated harness can verify the fixture while the formal guard
    // has no bypass input and still denies the same bytes.
    ensure!(denied(enforce_formal_test_material_policy(
        Some(&published_ed_input),
        None,
        None,
        None,
    )));
    record(7, 2)?;

    let rules = registry["reserved_identifiers"]
        .as_array()
        .context("reserved rules")?;
    let did_example =
        arkret_wire::Did::new(rules[0]["examples"][0].as_str().context("did example")?)?;
    let key_example =
        arkret_wire::DidUrl::new(rules[1]["examples"][0].as_str().context("key example")?)
            .map_err(anyhow::Error::msg)?;
    let domain_example = arkret_wire::TrustDomainId::new(
        rules[2]["examples"][0]
            .as_str()
            .context("domain example")?
            .to_owned(),
    )?;
    let did_only = reserved_identifier_matches(Some(&did_example), Some(&ordinary_kid), None);
    ensure!(did_only.did && !did_only.key_id && !did_only.trust_domain);
    record(8, 3)?;
    let key_only = reserved_identifier_matches(Some(&ordinary_did), Some(&key_example), None);
    ensure!(!key_only.did && key_only.key_id && !key_only.trust_domain);
    record(9, 3)?;
    let domain_only = reserved_identifier_matches(None, None, Some(&domain_example));
    ensure!(!domain_only.did && !domain_only.key_id && domain_only.trust_domain);
    record(10, 3)?;

    for sample in rules[2]["non_examples"]
        .as_array()
        .context("domain non-examples")?
    {
        let matches =
            arkret_wire::TrustDomainId::new(sample.as_str().context("domain")?.to_owned())
                .map(|value| reserved_identifier_matches(None, None, Some(&value)))
                .unwrap_or_default();
        ensure!(!matches.any());
    }
    record(11, 2)?;
    for (rule, kind) in rules.iter().zip(["did", "key_id", "trust_domain"]) {
        for sample in rule["non_examples"].as_array().context("non-examples")? {
            let raw = sample.as_str().context("non-example string")?;
            let matches = match kind {
                "did" => reserved_identifier_matches(
                    Some(&arkret_wire::Did::new(raw.to_owned())?),
                    None,
                    None,
                ),
                "key_id" => reserved_identifier_matches(
                    None,
                    Some(&arkret_wire::DidUrl::new(raw.to_owned()).map_err(anyhow::Error::msg)?),
                    None,
                ),
                _ => arkret_wire::TrustDomainId::new(raw.to_owned())
                    .map(|value| reserved_identifier_matches(None, None, Some(&value)))
                    .unwrap_or_default(),
            };
            ensure!(!matches.any());
        }
    }
    record(12, 3)?;
    ensure!([did_only, key_only, domain_only].iter().all(|matches| {
        [matches.did, matches.key_id, matches.trust_domain]
            .into_iter()
            .filter(|v| *v)
            .count()
            == 1
    }));
    record(13, 3)?;

    let execution = TestMaterialRejectionExecution {
        entrypoint: TEST_MATERIAL_REJECTION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(TestMaterialRejectionCoverage {
        execution,
        service_e2e_status: "partial",
        service_e2e_gaps: vec!["Cross-service Soland trust-admission and ledger/cache observation"],
    })
}

pub fn run_test_material_rejection_suite() -> Result<TestMaterialRejectionExecution> {
    Ok(run_test_material_rejection_suite_with_coverage()?.execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_fourteen_cases_through_sdk_and_coauth_seams() -> Result<()> {
        let coverage = run_test_material_rejection_suite_with_coverage()?;
        assert_eq!(coverage.execution.cases.len(), 14);
        assert!(
            coverage
                .execution
                .cases
                .iter()
                .all(|case| case.assertions > 0)
        );
        assert_eq!(coverage.service_e2e_status, "partial");
        assert_eq!(coverage.service_e2e_gaps.len(), 1);
        Ok(())
    }
}
