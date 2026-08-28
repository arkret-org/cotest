//! `ak.suite.binding.websocket.v1` — the executable runner for
//! `websocket-binding-fixture.json` (`zh/sync/websocket-binding.md` §10).
//!
//! §10 requires the suite to *execute*, not merely load, the fixture: exact
//! UTF-8 frame bytes, direction schemas, the DPoP known answer and its
//! mutations, the challenge replay ledger, the three-channel trace, reauth,
//! drain, close codes and the HTTP fallback decisions all have to be produced
//! by the implementation under test.
//!
//! The implementation under test here is the SDK: the frame codec, the closed
//! frame types, the `challenge_dpop_session_v1` builder / verifier, the
//! connection state machine and the transport-selection table. soland and the
//! client engine drive those same types, so a green run of this suite is what
//! gates advertising the profile — it is not a second, parallel model of the
//! binding.

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketClientFrame, WebSocketConnectionControlPayload, WebSocketConnectionLimits,
    WebSocketOpenParameters, WebSocketServerFrame,
};
use arkret_models_collaboration::sync_frames::websocket_session::{
    WebSocketConnectionPhase, WebSocketConnectionState, WebSocketConsumerHandoff,
    WebSocketConsumerOwner, WebSocketFallbackPolicy, WebSocketFrameCodec,
    WebSocketHandshakeFailure, WebSocketOpenAdmission, WebSocketServerEvent,
    WebSocketTransportDecision,
};
use arkret_models_discovery::websocket_binding::{
    select_websocket_binding, validate_websocket_transport,
};
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
use arkret_signatures::websocket_auth::{
    WebSocketAuthProofRequest, WebSocketAuthVerificationRequest, build_websocket_auth_proof,
    verify_websocket_auth_proof, websocket_holder_thumbprint,
};
use arkret_wire::websocket_binding::{
    WEBSOCKET_AUTH_REPLAY_CONTEXT, WEBSOCKET_AUTHENTICATION_DEADLINE_MS,
    WEBSOCKET_HARD_MAX_FRAME_BYTES, WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS,
    WebSocketChallengeRecord, WebSocketCloseCode, WebSocketDpopProof, WebSocketOperationId,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::schema_validation_fixture::SchemaEnv;
use super::{fixture_runner_entrypoint, load_fixture_value, required_str, validate_profile};

const FIXTURE: &str = "websocket-binding-fixture.json";
const PROFILE: &str = "ak.profile.binding.websocket.v1";
const VECTOR_ID: &str = "ak.vector.binding.websocket.v1";
const ENTRYPOINT: &str = "ak.suite.binding.websocket.v1";
const SUITE: &str = "websocket_binding";

/// The multiplex trace steps this runner executes, in order. Pinned so a
/// fixture revision that adds or reorders a step cannot pass while the runner
/// silently keeps executing the old sequence.
const MULTIPLEX_STEPS: &[&str] = &[
    "authenticate accepted",
    "welcome",
    "open account-1",
    "opened account-1",
    "open events-1",
    "opened events-1",
    "open signal-1",
    "opened signal-1",
    "account-1 data delta advances only account durable cursor",
    "events-1 data event advances only events durable cursor",
    "events-1 control heartbeat advances no cursor",
    "signal-1 control heartbeat creates no cursor or catch-up state",
    "events-1 channel error and closed leave account-1 and signal-1 open",
    "reusing events-1 returns conflict and never reopens it",
];

pub fn run_websocket_binding_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    let limits = validate_metadata(&fixture)?;
    let env = SchemaEnv::load()?;

    let discovery = run_discovery_cases(&fixture, &env)?;
    let bundle_closure = run_bundle_closure_cases(&fixture, &env)?;
    let kat = run_dpop_kat(&fixture, &env)?;
    let negatives = run_dpop_negative_cases(&fixture, &kat)?;
    let frames = run_frame_schema_cases(&fixture, &env)?;
    let wire_negatives = run_wire_negative_cases(&fixture, &env, &limits)?;
    run_multiplex_trace(&fixture, &frames, &limits)?;
    run_reauth_trace(&fixture, &kat)?;
    run_drain_and_close_traces(&fixture, &limits)?;
    run_fallback_cases(&fixture)?;

    eprintln!(
        "[cotest {SUITE}] discovery={discovery} dpop_kat=1 dpop_negative={negatives} \
         frame_schema={frames_len} wire_negative={wire_negatives} multiplex=1 reauth=2 \
         drain_and_close=6 fallback=2 bundle_closure={bundle_closure}",
        frames_len = frames.len()
    );
    Ok(())
}

// ── Fixture metadata ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Deserialize)]
struct FixtureLimits {
    hard_max_frame_bytes: usize,
    fixture_advertised_max_frame_bytes: u32,
    max_channels: u32,
    authentication_deadline_ms: u64,
    replay_ledger_retention_seconds: u64,
}

fn validate_metadata(fixture: &Value) -> Result<FixtureLimits> {
    validate_profile(fixture, PROFILE)?;
    if required_str(fixture, "suite")? != SUITE {
        bail!("{FIXTURE} suite drifted from {SUITE}");
    }
    if fixture
        .get("runner")
        .and_then(|runner| runner.get("kind"))
        .and_then(Value::as_str)
        != Some("named_suite")
    {
        bail!("{FIXTURE} runner kind must be named_suite");
    }
    if fixture_runner_entrypoint(fixture)? != ENTRYPOINT {
        bail!("{FIXTURE} runner entrypoint must be {ENTRYPOINT}");
    }
    if super::string_array_field(fixture, "covers_vectors")? != [VECTOR_ID] {
        bail!("{FIXTURE} must cover exactly {VECTOR_ID}");
    }

    let limits: FixtureLimits =
        serde_json::from_value(super::required_field(fixture, "limits")?.clone())?;
    if limits.hard_max_frame_bytes != WEBSOCKET_HARD_MAX_FRAME_BYTES {
        bail!("{FIXTURE} hard_max_frame_bytes drifted from the SDK ceiling");
    }
    if limits.authentication_deadline_ms != WEBSOCKET_AUTHENTICATION_DEADLINE_MS {
        bail!("{FIXTURE} authentication_deadline_ms drifted from the SDK deadline");
    }
    if limits.replay_ledger_retention_seconds != WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS {
        bail!("{FIXTURE} replay_ledger_retention_seconds drifted from the SDK retention");
    }
    Ok(limits)
}

fn cases<'a>(fixture: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    super::value_array(super::required_field(fixture, field)?, field)
}

fn case_name(case: &Value) -> Result<&str> {
    required_str(case, "name")
}

// ── §2 Discovery ────────────────────────────────────────────────────────────

fn run_discovery_cases(fixture: &Value, env: &SchemaEnv) -> Result<usize> {
    let cases = cases(fixture, "discovery_cases")?;
    if cases.len() != 3 {
        bail!("{FIXTURE} discovery_cases must cover the closed descriptor and two rejections");
    }
    let schema_ref = required_str(&cases[0], "schema_ref")?;
    let validator = env.compile(schema_ref)?;
    let base = super::required_field(&cases[0], "instance")?.clone();

    for case in cases {
        let name = case_name(case)?;
        let expect_valid = case
            .get("expect_valid")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("discovery case {name} must state expect_valid"))?;
        let expected_transport = required_str(case, "expected_transport")?;
        let instances = discovery_case_instances(name, case, &base)?;
        if instances.is_empty() {
            bail!("discovery case {name} produced no instance to execute");
        }
        for instance in instances {
            let schema_valid = validator.is_valid(&instance);
            if schema_valid != expect_valid {
                bail!(
                    "discovery case {name} schema validity {schema_valid} != expected {expect_valid}"
                );
            }
            let selected = select_descriptor(&instance);
            match (expect_valid, expected_transport) {
                (true, "websocket") => {
                    let descriptor = selected.ok_or_else(|| {
                        anyhow!("discovery case {name} must yield a usable websocket binding")
                    })?;
                    if descriptor.kind() != arkret_wire::BindingKind::Websocket {
                        bail!("discovery case {name} must select websocket transport");
                    }
                }
                (false, "http_json") => {
                    if selected.is_some() {
                        bail!("discovery case {name} must fall back to the mandatory HTTP binding");
                    }
                }
                _ => bail!("discovery case {name} has an unsupported expectation"),
            }
        }
    }
    Ok(cases.len())
}

/// Materialise every instance one declarative discovery case stands for.
fn discovery_case_instances(name: &str, case: &Value, base: &Value) -> Result<Vec<Value>> {
    if let Some(instance) = case.get("instance") {
        return Ok(vec![instance.clone()]);
    }
    if let Some(base_urls) = case.get("base_urls").and_then(Value::as_array) {
        return base_urls
            .iter()
            .map(|base_url| {
                let mut instance = base.clone();
                instance
                    .as_object_mut()
                    .ok_or_else(|| anyhow!("discovery base must be an object"))?
                    .insert("base_url".to_owned(), base_url.clone());
                Ok(instance)
            })
            .collect();
    }
    if let Some(remove_each) = case.get("remove_each").and_then(Value::as_array) {
        return remove_each
            .iter()
            .map(|field| {
                let field = field
                    .as_str()
                    .ok_or_else(|| anyhow!("remove_each entries must be strings"))?;
                let mut instance = base.clone();
                instance
                    .as_object_mut()
                    .ok_or_else(|| anyhow!("discovery base must be an object"))?
                    .remove(field)
                    .ok_or_else(|| anyhow!("discovery base has no {field} to remove"))?;
                Ok(instance)
            })
            .collect();
    }
    bail!("discovery case {name} declares no executable mutation")
}

/// Execute the ServiceDescribe-level operation reachability cases.
///
/// The transport descriptor is a closed object without `operations[]`, so
/// "does this service actually expose the three streaming operations over
/// WebSocket" is answered by expanding `supported_operation_bundles`
/// (`websocket-binding.md` 2). Each declared mutation must name a carrier the
/// base instance really has; a mutation that cannot be materialised fails the
/// suite instead of being skipped.
fn run_bundle_closure_cases(fixture: &Value, env: &SchemaEnv) -> Result<usize> {
    let cases = cases(fixture, "bundle_closure_cases")?;
    if cases.len() != 3 {
        bail!("{FIXTURE} bundle_closure_cases must cover the advertised closure and two fallbacks");
    }
    let base_case = &cases[0];
    if case_name(base_case)? != "advertised_bundle_closure_selects_websocket" {
        bail!("{FIXTURE} bundle_closure_cases must start with the advertised closure case");
    }
    let schema_ref = required_str(base_case, "schema_ref")?;
    let validator = env.compile(schema_ref)?;
    let base = super::required_field(base_case, "instance")?.clone();

    for case in cases {
        let name = case_name(case)?;
        let expected_transport = required_str(case, "expected_transport")?;
        let instance = bundle_closure_case_instance(name, case, &base)?;
        if !validator.is_valid(&instance) {
            bail!("bundle closure case {name} instance is not a valid ServiceDescribe");
        }
        let describe: ServiceDescribe = serde_json::from_value(instance)?;
        let selected = select_websocket_binding(&describe, u32::MAX);
        match expected_transport {
            "websocket" => {
                let binding = selected.ok_or_else(|| {
                    anyhow!("bundle closure case {name} must select the websocket transport")
                })?;
                if binding.kind() != arkret_wire::BindingKind::Websocket {
                    bail!("bundle closure case {name} selected a non-websocket transport");
                }
            }
            "http_json" => {
                if selected.is_some() {
                    bail!(
                        "bundle closure case {name} must fall back to the mandatory HTTP binding"
                    );
                }
            }
            other => bail!("bundle closure case {name} has an unsupported expectation: {other}"),
        }
    }
    Ok(cases.len())
}

fn bundle_closure_case_instance(name: &str, case: &Value, base: &Value) -> Result<Value> {
    if let Some(instance) = case.get("instance") {
        return Ok(instance.clone());
    }
    if let Some(bundle) = case.get("remove_bundle").and_then(Value::as_str) {
        let mut instance = base.clone();
        let bundles = instance
            .get_mut("supported_operation_bundles")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("bundle closure base has no supported_operation_bundles"))?;
        let before = bundles.len();
        bundles.retain(|value| value.as_str() != Some(bundle));
        if bundles.len() == before {
            bail!("bundle closure case {name} names a bundle the base does not advertise");
        }
        return Ok(instance);
    }
    if let Some(kind) = case.get("remove_transport_kind").and_then(Value::as_str) {
        let mut instance = base.clone();
        let bindings = instance
            .get_mut("transport_bindings")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("bundle closure base has no transport_bindings"))?;
        let before = bindings.len();
        bindings.retain(|value| value.get("kind").and_then(Value::as_str) != Some(kind));
        if bindings.len() == before {
            bail!("bundle closure case {name} names a transport the base does not advertise");
        }
        if bindings.is_empty() {
            bail!("bundle closure case {name} removed the mandatory HTTP binding");
        }
        return Ok(instance);
    }
    bail!("bundle closure case {name} declares no executable mutation")
}

fn select_descriptor(instance: &Value) -> Option<TransportBinding> {
    let binding: TransportBinding = serde_json::from_value(instance.clone()).ok()?;
    validate_websocket_transport(&binding).ok()?;
    Some(binding)
}

// ── §3.1 DPoP known answer ──────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct DpopKat {
    proof_schema_ref: String,
    /// Namespace of the DPoP replay ledger key. It is a replay-cache namespace,
    /// not a registered proof context: the WebSocket DPoP proof is a compact
    /// JWS over its own claims, not an `ak.*-proof-v1` binding transcript.
    replay_cache_namespace: String,
    base_url: String,
    origin: String,
    connection_id: String,
    nonce: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    session_grant: String,
    private_seed_hex: String,
    public_jwk: PublicJwk,
    cnf_jkt: String,
    protected_json_utf8: String,
    claims_json_utf8: String,
    decoded: Value,
    protected_base64url: String,
    claims_base64url: String,
    signing_input_ascii: String,
    signature_base64url: String,
    compact_jws: String,
    challenge_state: ChallengeState,
    expected_replay_ledger_key: Vec<String>,
    expected: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PublicJwk {
    crv: String,
    kty: String,
    x: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ChallengeState {
    key: Vec<String>,
    canonical_origin: String,
    canonical_base_url: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    consumed: bool,
}

impl DpopKat {
    fn signing_key(&self) -> Result<SigningKey> {
        let seed: [u8; 32] = hex::decode(&self.private_seed_hex)?
            .try_into()
            .map_err(|_| anyhow!("the KAT private seed must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    fn challenge(&self) -> WebSocketChallengeRecord {
        WebSocketChallengeRecord {
            connection_id: self.connection_id.clone(),
            nonce: self.nonce.clone(),
            canonical_origin: self.challenge_state.canonical_origin.clone(),
            canonical_base_url: self.challenge_state.canonical_base_url.clone(),
            issued_at: self.challenge_state.issued_at,
            expires_at: self.challenge_state.expires_at,
            consumed: self.challenge_state.consumed,
        }
    }

    fn verification<'a>(
        &'a self,
        compact_jws: &'a str,
        challenge: &'a WebSocketChallengeRecord,
    ) -> WebSocketAuthVerificationRequest<'a> {
        WebSocketAuthVerificationRequest {
            compact_jws,
            connection_id: &self.connection_id,
            session_grant: &self.session_grant,
            socket_origin: &self.origin,
            challenge,
            grant_cnf_jkt: &self.cnf_jkt,
            replay_ledger_hit: false,
            now: self.issued_at,
        }
    }
}

fn run_dpop_kat(fixture: &Value, env: &SchemaEnv) -> Result<DpopKat> {
    let kat: DpopKat = serde_json::from_value(super::required_field(fixture, "dpop_kat")?.clone())?;
    if kat.expected != "accepted" {
        bail!("{FIXTURE} dpop_kat must be the accepted known answer");
    }
    if kat.replay_cache_namespace != WEBSOCKET_AUTH_REPLAY_CONTEXT {
        bail!("{FIXTURE} dpop_kat replay_cache_namespace drifted from the SDK replay namespace");
    }
    if arkret_wire::ProofContextId::from_wire(&kat.replay_cache_namespace).is_some() {
        bail!(
            "{FIXTURE} dpop_kat replay namespace `{}` is a registered proof context; the replay \
             ledger namespace must not be confusable with a proof binding context",
            kat.replay_cache_namespace
        );
    }
    if kat.challenge_state.key != [kat.connection_id.clone(), kat.nonce.clone()] {
        bail!("{FIXTURE} challenge_state key must be (connection_id, nonce)");
    }
    if kat.issued_at != kat.challenge_state.issued_at
        || kat.expires_at != kat.challenge_state.expires_at
    {
        bail!("{FIXTURE} dpop_kat and challenge_state disagree about the challenge window");
    }
    if kat.public_jwk.kty != "OKP" || kat.public_jwk.crv != "Ed25519" {
        bail!("{FIXTURE} dpop_kat holder key must be an Ed25519 OKP key");
    }

    // The decoded proof is the registered schema instance.
    env.compile(&kat.proof_schema_ref)?
        .validate(&kat.decoded)
        .map_err(|error| anyhow!("dpop_kat decoded proof failed its schema: {error}"))?;
    let decoded: WebSocketDpopProof = serde_json::from_value(kat.decoded.clone())?;
    decoded
        .validate()
        .map_err(|error| anyhow!("dpop_kat decoded proof is not the closed shape: {error}"))?;

    // Rebuild every intermediate from the seed. Copying the expected compact
    // string without re-deriving it is explicitly not a pass (§3.1).
    let built = build_websocket_auth_proof(
        &WebSocketAuthProofRequest {
            base_url: &kat.base_url,
            session_grant: &kat.session_grant,
            nonce: &kat.nonce,
            issued_at: kat.issued_at,
            jti: &decoded.claims.jti,
        },
        &kat.signing_key()?,
    )?;
    let protected_bytes = arkret_canonical::canonical::canonical_json_bytes(
        &serde_json::to_value(&built.protected)?,
    )?;
    let claims_bytes =
        arkret_canonical::canonical::canonical_json_bytes(&serde_json::to_value(&built.claims)?)?;
    let protected_json = String::from_utf8(protected_bytes.clone())?;
    let claims_json = String::from_utf8(claims_bytes.clone())?;
    let protected_b64 = arkret_canonical::base64url_encode(protected_bytes);
    let claims_b64 = arkret_canonical::base64url_encode(claims_bytes);
    let signing_input = format!("{protected_b64}.{claims_b64}");
    let signature_b64 = built
        .compact_jws
        .rsplit('.')
        .next()
        .ok_or_else(|| anyhow!("a compact JWS always has a signature segment"))?
        .to_owned();

    for (field, actual, expected) in [
        (
            "protected_json_utf8",
            protected_json,
            &kat.protected_json_utf8,
        ),
        ("claims_json_utf8", claims_json, &kat.claims_json_utf8),
        (
            "protected_base64url",
            protected_b64,
            &kat.protected_base64url,
        ),
        ("claims_base64url", claims_b64, &kat.claims_base64url),
        (
            "signing_input_ascii",
            signing_input,
            &kat.signing_input_ascii,
        ),
        (
            "signature_base64url",
            signature_b64,
            &kat.signature_base64url,
        ),
        ("compact_jws", built.compact_jws.clone(), &kat.compact_jws),
        ("cnf_jkt", built.jkt.clone(), &kat.cnf_jkt),
    ] {
        if &actual != expected {
            bail!("dpop_kat {field} mismatch: derived {actual}, fixture {expected}");
        }
    }
    if built.protected.jwk.x != kat.public_jwk.x {
        bail!("dpop_kat holder key does not derive from the fixture seed");
    }
    if websocket_holder_thumbprint(&built.protected.jwk)? != kat.cnf_jkt {
        bail!("dpop_kat cnf_jkt does not equal the holder key thumbprint");
    }

    // Verify the KAT against its own stored challenge and pin the ledger key.
    let challenge = kat.challenge();
    let verified = verify_websocket_auth_proof(&kat.verification(&kat.compact_jws, &challenge))
        .map_err(|error| anyhow!("dpop_kat must verify against its challenge: {error}"))?;
    if verified.replay_ledger_key.as_triple().as_slice() != kat.expected_replay_ledger_key {
        bail!("dpop_kat replay ledger key drifted from the fixture");
    }
    Ok(kat)
}

// ── §3.1 DPoP negatives ─────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct DpopNegativeCase {
    name: String,
    expected: String,
    #[serde(default)]
    validator_context: Option<String>,
    #[serde(default)]
    replace_claim: Option<Map<String, Value>>,
    #[serde(default)]
    add_claim: Option<Map<String, Value>>,
    #[serde(default)]
    resign: bool,
    #[serde(default)]
    authenticate_connection_id: Option<String>,
    #[serde(default)]
    socket_origin: Option<String>,
    #[serde(default)]
    verification_time: Option<DateTime<Utc>>,
    #[serde(default)]
    challenge_consumed: bool,
    #[serde(default)]
    replay_ledger_key_present: bool,
    #[serde(default)]
    grant_cnf_jkt: Option<String>,
}

fn run_dpop_negative_cases(fixture: &Value, kat: &DpopKat) -> Result<usize> {
    let cases: Vec<DpopNegativeCase> =
        serde_json::from_value(super::required_field(fixture, "dpop_negative_cases")?.clone())?;
    if cases.len() != 11 {
        bail!("{FIXTURE} must execute all eleven DPoP negative cases");
    }
    let key = kat.signing_key()?;
    for case in &cases {
        if case.expected != "rejected" {
            bail!("dpop negative case {} must expect rejection", case.name);
        }
        if case.validator_context.as_deref() == Some("http_request_dpop") {
            // The generic HTTP DPoP validator must never accept a `wss` htu or
            // the application method token.
            let rejected = arkret_signatures::dpop::verify_dpop_proof(
                &arkret_signatures::dpop::DpopVerificationRequest {
                    proof_jwt: &kat.compact_jws,
                    method: arkret_wire::websocket_binding::WEBSOCKET_AUTH_METHOD_TOKEN,
                    htu: &kat.base_url,
                    access_token: Some(&kat.session_grant),
                    now: kat.issued_at,
                    max_age: chrono::Duration::seconds(300),
                    max_future_skew: chrono::Duration::seconds(30),
                    expected_nonce: None,
                },
            )
            .is_err();
            if !rejected {
                bail!("the HTTP DPoP validator accepted the WebSocket application context");
            }
            continue;
        }

        let compact_jws = match (&case.replace_claim, &case.add_claim) {
            (None, None) => kat.compact_jws.clone(),
            (replace, add) => {
                if !case.resign {
                    bail!(
                        "dpop negative case {} mutates claims without resigning",
                        case.name
                    );
                }
                resign_with_claims(kat, &key, replace.as_ref(), add.as_ref())?
            }
        };
        let mut challenge = kat.challenge();
        challenge.consumed = case.challenge_consumed;
        let mut request = kat.verification(&compact_jws, &challenge);
        if let Some(connection_id) = &case.authenticate_connection_id {
            request.connection_id = connection_id;
        }
        if let Some(origin) = &case.socket_origin {
            request.socket_origin = origin;
        }
        if let Some(now) = case.verification_time {
            request.now = now;
        }
        if let Some(cnf_jkt) = &case.grant_cnf_jkt {
            request.grant_cnf_jkt = cnf_jkt;
        }
        request.replay_ledger_hit = case.replay_ledger_key_present;

        if verify_websocket_auth_proof(&request).is_ok() {
            bail!("dpop negative case {} was accepted", case.name);
        }
    }
    Ok(cases.len())
}

/// Re-sign the known answer with mutated claims, so a negative case exercises
/// the semantic check rather than a signature failure.
fn resign_with_claims(
    kat: &DpopKat,
    key: &SigningKey,
    replace: Option<&Map<String, Value>>,
    add: Option<&Map<String, Value>>,
) -> Result<String> {
    let mut claims: Value = serde_json::from_str(&kat.claims_json_utf8)?;
    let object = claims
        .as_object_mut()
        .ok_or_else(|| anyhow!("the KAT claims are an object"))?;
    for (name, value) in replace
        .into_iter()
        .flatten()
        .chain(add.into_iter().flatten())
    {
        object.insert(name.clone(), value.clone());
    }
    let protected: Value = serde_json::from_str(&kat.protected_json_utf8)?;
    let protected_b64 = arkret_canonical::base64url_encode(
        arkret_canonical::canonical::canonical_json_bytes(&protected)?,
    );
    let claims_b64 = arkret_canonical::base64url_encode(
        arkret_canonical::canonical::canonical_json_bytes(&claims)?,
    );
    let signing_input = format!("{protected_b64}.{claims_b64}");
    let signature = ed25519_dalek::Signer::sign(key, signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        arkret_canonical::base64url_encode(signature.to_bytes())
    ))
}

// ── §4 Frame schema ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct FrameSchemaCase {
    name: String,
    direction_schema_ref: String,
    wire_utf8: String,
    expect_valid: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Server,
    Client,
}

fn direction_of(schema_ref: &str) -> Result<Direction> {
    if schema_ref.ends_with("#/$defs/server_frame") {
        return Ok(Direction::Server);
    }
    if schema_ref.ends_with("#/$defs/client_frame") {
        return Ok(Direction::Client);
    }
    bail!("{schema_ref} is not one of the two registered direction schemas")
}

fn run_frame_schema_cases(fixture: &Value, env: &SchemaEnv) -> Result<Vec<FrameSchemaCase>> {
    let frames: Vec<FrameSchemaCase> =
        serde_json::from_value(super::required_field(fixture, "frame_schema_cases")?.clone())?;
    if frames.len() != 22 {
        bail!("{FIXTURE} must execute all twenty-two frame schema cases");
    }
    // The fixture advertises 2048; the schema cases are validated at the hard
    // ceiling so an over-2048 positive case is a schema question, not a byte
    // gate question.
    let codec = WebSocketFrameCodec::new(WEBSOCKET_HARD_MAX_FRAME_BYTES as u32, None);
    for case in &frames {
        let direction = direction_of(&case.direction_schema_ref)?;
        let validator = env.compile(&case.direction_schema_ref)?;
        let instance: Value = serde_json::from_str(&case.wire_utf8)
            .map_err(|error| anyhow!("frame case {} wire_utf8 is not JSON: {error}", case.name))?;
        let schema_valid = validator.is_valid(&instance);
        if schema_valid != case.expect_valid {
            bail!(
                "frame case {} schema validity {schema_valid} != expected {}",
                case.name,
                case.expect_valid
            );
        }
        if !case.expect_valid {
            continue;
        }

        // The SDK must accept the exact bytes, and what it re-emits must still
        // satisfy the same direction schema.
        let reencoded = match direction {
            Direction::Server => {
                let frame = codec
                    .decode_server_frame(case.wire_utf8.as_bytes())
                    .map_err(|rejection| {
                        anyhow!(
                            "frame case {} was refused by the SDK codec: {}",
                            case.name,
                            rejection.error.message
                        )
                    })?;
                frame.validate().map_err(|error| {
                    anyhow!("frame case {} failed SDK validation: {error}", case.name)
                })?;
                codec.encode(&frame)?
            }
            Direction::Client => {
                let frame = codec
                    .decode_client_frame(case.wire_utf8.as_bytes())
                    .map_err(|rejection| {
                        anyhow!(
                            "frame case {} was refused by the SDK codec: {}",
                            case.name,
                            rejection.error.message
                        )
                    })?;
                frame.validate().map_err(|error| {
                    anyhow!("frame case {} failed SDK validation: {error}", case.name)
                })?;
                codec.encode(&frame)?
            }
        };
        let reencoded_value: Value = serde_json::from_str(&reencoded)?;
        if reencoded_value != instance {
            bail!(
                "frame case {} does not round-trip through the SDK types",
                case.name
            );
        }
        if !validator.is_valid(&reencoded_value) {
            bail!(
                "frame case {} re-emitted bytes fail the direction schema",
                case.name
            );
        }
    }
    Ok(frames)
}

fn frame_case<'a>(frames: &'a [FrameSchemaCase], name: &str) -> Result<&'a FrameSchemaCase> {
    frames
        .iter()
        .find(|case| case.name == name)
        .ok_or_else(|| anyhow!("{FIXTURE} frame_schema_cases has no case named {name}"))
}

// ── §4 wire negatives ───────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct WireNegativeCase {
    name: String,
    rejection_stage: String,
    #[serde(default)]
    direction_schema_ref: Option<String>,
    #[serde(default)]
    wire_utf8: Option<String>,
    #[serde(default)]
    wire_hex: Option<String>,
    #[serde(default)]
    opcode: Option<String>,
    #[serde(default)]
    generator: Option<OversizeGenerator>,
    #[serde(default)]
    advertised_max_frame_bytes: Option<u32>,
    #[serde(default)]
    json_parser_called: Option<bool>,
    #[serde(default)]
    expected_close_code: Option<u16>,
    #[serde(default)]
    channel_operation: Option<WebSocketOperationId>,
    #[serde(default)]
    expected_channel_result: Option<String>,
    #[serde(default)]
    connection_remains_open: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
struct OversizeGenerator {
    prefix_utf8: String,
    repeat_utf8: String,
    total_message_bytes: usize,
    suffix_utf8: String,
}

impl OversizeGenerator {
    fn materialise(&self) -> Result<String> {
        let fixed = self.prefix_utf8.len() + self.suffix_utf8.len();
        if self.repeat_utf8.len() != 1 || self.total_message_bytes < fixed {
            bail!("the oversize generator must pad a single-byte filler up to the total length");
        }
        let padding = self.repeat_utf8.repeat(self.total_message_bytes - fixed);
        Ok(format!("{}{padding}{}", self.prefix_utf8, self.suffix_utf8))
    }
}

fn run_wire_negative_cases(
    fixture: &Value,
    env: &SchemaEnv,
    limits: &FixtureLimits,
) -> Result<usize> {
    let cases: Vec<WireNegativeCase> =
        serde_json::from_value(super::required_field(fixture, "wire_negative_cases")?.clone())?;
    if cases.len() != 8 {
        bail!("{FIXTURE} must execute all eight wire negative cases");
    }
    let codec = WebSocketFrameCodec::new(limits.fixture_advertised_max_frame_bytes, None);

    for case in &cases {
        match case.rejection_stage.as_str() {
            "json_duplicate_scan" | "schema" | "direction_schema" => {
                let wire = case
                    .wire_utf8
                    .as_deref()
                    .ok_or_else(|| anyhow!("wire negative {} needs wire_utf8", case.name))?;
                // A declared direction defaults to the client frame: every
                // fixture case at these stages is client-originated.
                let direction = match &case.direction_schema_ref {
                    Some(schema_ref) => direction_of(schema_ref)?,
                    None => Direction::Client,
                };
                let rejected = match direction {
                    Direction::Client => codec
                        .decode_client_frame(wire.as_bytes())
                        .map_err(|rejection| rejection.close_code)
                        .and_then(|frame| {
                            frame
                                .validate()
                                .map_err(|_| Some(WebSocketCloseCode::ProtocolError))
                        }),
                    Direction::Server => codec
                        .decode_server_frame(wire.as_bytes())
                        .map_err(|rejection| rejection.close_code)
                        .and_then(|frame| {
                            frame
                                .validate()
                                .map_err(|_| Some(WebSocketCloseCode::ProtocolError))
                        }),
                };
                let close_code = match rejected {
                    Ok(()) => bail!("wire negative {} was accepted by the SDK", case.name),
                    Err(close_code) => close_code,
                };
                expect_close_code(&case.name, close_code, case.expected_close_code)?;
                if let Some(schema_ref) = &case.direction_schema_ref {
                    let instance: Value = serde_json::from_str(wire)?;
                    if env.compile(schema_ref)?.is_valid(&instance) {
                        bail!("wire negative {} passed its direction schema", case.name);
                    }
                }
            }
            "opcode" => {
                if case.opcode.as_deref() != Some("binary") {
                    bail!("wire negative {} must declare the binary opcode", case.name);
                }
                let bytes = hex::decode(
                    case.wire_hex
                        .as_deref()
                        .ok_or_else(|| anyhow!("wire negative {} needs wire_hex", case.name))?,
                )?;
                // The payload would be legal as text; only the opcode makes it
                // a protocol error.
                if serde_json::from_slice::<Value>(&bytes).is_err() {
                    bail!("wire negative {} must isolate the opcode rule", case.name);
                }
                expect_close_code(
                    &case.name,
                    codec.reject_binary_message().close_code,
                    case.expected_close_code,
                )?;
            }
            "byte_gate" => {
                let generator = case
                    .generator
                    .as_ref()
                    .ok_or_else(|| anyhow!("wire negative {} needs a generator", case.name))?;
                let advertised = case.advertised_max_frame_bytes.ok_or_else(|| {
                    anyhow!(
                        "wire negative {} needs advertised_max_frame_bytes",
                        case.name
                    )
                })?;
                if advertised != limits.fixture_advertised_max_frame_bytes {
                    bail!(
                        "wire negative {} disagrees with the fixture limits",
                        case.name
                    );
                }
                let message = generator.materialise()?;
                if message.len() != generator.total_message_bytes {
                    bail!(
                        "wire negative {} generator produced the wrong length",
                        case.name
                    );
                }
                if case.json_parser_called != Some(false) {
                    bail!(
                        "wire negative {} must forbid parsing before the gate",
                        case.name
                    );
                }
                // The gate is a length decision only: it must refuse before the
                // parser is reachable, which is observable as the message being
                // rejected even though it is well-formed JSON.
                serde_json::from_str::<Value>(&message).map_err(|error| {
                    anyhow!(
                        "wire negative {} must stay well-formed JSON: {error}",
                        case.name
                    )
                })?;
                if codec.accepts_accumulated(message.len()) {
                    bail!("wire negative {} was inside the effective limit", case.name);
                }
                let rejection = codec
                    .decode_client_frame(message.as_bytes())
                    .err()
                    .ok_or_else(|| anyhow!("wire negative {} was accepted", case.name))?;
                expect_close_code(&case.name, rejection.close_code, case.expected_close_code)?;
            }
            "connection_state" => {
                let wire = case
                    .wire_utf8
                    .as_deref()
                    .ok_or_else(|| anyhow!("wire negative {} needs wire_utf8", case.name))?;
                let mut state = authenticated_state(limits);
                let frame = codec
                    .decode_server_frame(wire.as_bytes())
                    .map_err(|rejection| anyhow!("{:?}", rejection.error.message))?;
                let rejection = state
                    .accept_server_frame(&frame)
                    .err()
                    .ok_or_else(|| anyhow!("wire negative {} was accepted", case.name))?;
                if !rejection.is_connection_scoped() {
                    bail!("wire negative {} must fail the whole connection", case.name);
                }
                expect_close_code(&case.name, rejection.close_code, case.expected_close_code)?;
            }
            "channel_operation_schema" => {
                let wire = case
                    .wire_utf8
                    .as_deref()
                    .ok_or_else(|| anyhow!("wire negative {} needs wire_utf8", case.name))?;
                let operation = case.channel_operation.ok_or_else(|| {
                    anyhow!("wire negative {} needs the channel operation", case.name)
                })?;
                let mut state = authenticated_state(limits);
                state.record_opened("signal-1", operation)?;
                state.record_opened("account-1", WebSocketOperationId::AccountStreamSubscribe)?;
                let frame = codec
                    .decode_server_frame(wire.as_bytes())
                    .map_err(|rejection| anyhow!("{}", rejection.error.message))?;
                let rejection = state
                    .accept_server_frame(&frame)
                    .err()
                    .ok_or_else(|| anyhow!("wire negative {} was accepted", case.name))?;
                if rejection.is_connection_scoped() {
                    bail!("wire negative {} must stay channel-scoped", case.name);
                }
                if case.expected_channel_result.as_deref() != Some("error_then_closed") {
                    bail!(
                        "wire negative {} must terminate only its channel",
                        case.name
                    );
                }
                state.close_channel("signal-1");
                if case.connection_remains_open != Some(true)
                    || state.open_channel_ids() != ["account-1"]
                {
                    bail!("wire negative {} disturbed a sibling channel", case.name);
                }
            }
            stage => bail!("wire negative {} has an unknown stage {stage}", case.name),
        }
    }
    Ok(cases.len())
}

fn expect_close_code(
    name: &str,
    actual: Option<WebSocketCloseCode>,
    expected: Option<u16>,
) -> Result<()> {
    let expected = expected.ok_or_else(|| anyhow!("case {name} must state a close code"))?;
    let actual = actual
        .ok_or_else(|| anyhow!("case {name} produced no connection-scoped close code"))?
        .as_u16();
    if actual != expected {
        bail!("case {name} closed with {actual}, expected {expected}");
    }
    Ok(())
}

// ── §5–§7 multiplex trace ───────────────────────────────────────────────────

fn fixture_limits(limits: &FixtureLimits) -> WebSocketConnectionLimits {
    WebSocketConnectionLimits {
        max_frame_bytes: limits.fixture_advertised_max_frame_bytes,
        max_channels: limits.max_channels,
        max_connection_pending_bytes: 65_536,
        max_channel_pending_bytes: 16_384,
        max_connection_pending_frames: 128,
        max_channel_pending_frames: 32,
        heartbeat_interval_ms: 30_000,
    }
}

fn authenticated_state(limits: &FixtureLimits) -> WebSocketConnectionState {
    let mut state = WebSocketConnectionState::new(
        "Y29ubmVjdGlvbi0wMTIzNDU2Nzg5YWJjZGVm",
        fixture_limits(limits),
    );
    state.authenticated();
    state
}

#[derive(Clone, Debug, Deserialize)]
struct MultiplexTrace {
    connection_id: String,
    steps: Vec<String>,
    frame_case_sequence: Vec<String>,
    expected: MultiplexExpectation,
}

#[derive(Clone, Debug, Deserialize)]
struct MultiplexExpectation {
    open_channels_after_events_close: Vec<String>,
    account_cursor: String,
    events_cursor: String,
    signal_cursor: Option<String>,
    signal_catchup: bool,
    channel_id_reuse: String,
    physical_connection_open: bool,
}

fn run_multiplex_trace(
    fixture: &Value,
    frames: &[FrameSchemaCase],
    limits: &FixtureLimits,
) -> Result<()> {
    let trace: MultiplexTrace =
        serde_json::from_value(super::required_field(fixture, "multiplex_trace")?.clone())?;
    if trace.steps != MULTIPLEX_STEPS {
        bail!("{FIXTURE} multiplex steps drifted from what this runner executes");
    }
    if trace.expected.signal_cursor.is_some() || trace.expected.signal_catchup {
        bail!("the Signal channel has no cursor and no catch-up (§6.2)");
    }
    if trace.expected.channel_id_reuse != "conflict" {
        bail!("a reused channel_id must conflict (§5)");
    }

    let codec = WebSocketFrameCodec::new(limits.fixture_advertised_max_frame_bytes, None);
    let mut state =
        WebSocketConnectionState::new(trace.connection_id.clone(), fixture_limits(limits));
    let mut open_frames: Vec<WebSocketClientFrame> = Vec::new();

    for name in &trace.frame_case_sequence {
        let case = frame_case(frames, name)?;
        match direction_of(&case.direction_schema_ref)? {
            Direction::Client => {
                let frame = codec
                    .decode_client_frame(case.wire_utf8.as_bytes())
                    .map_err(|rejection| anyhow!("{}", rejection.error.message))?;
                match &frame {
                    WebSocketClientFrame::Authenticate { connection_id, .. } => {
                        if connection_id != &trace.connection_id {
                            bail!("the trace authenticate names another connection");
                        }
                        frame.validate()?;
                    }
                    WebSocketClientFrame::Open { .. } => {
                        match state.admit_open(&frame)? {
                            WebSocketOpenAdmission::Opened { .. } => {}
                            _ => bail!("the trace open {name} was refused"),
                        }
                        open_frames.push(frame.clone());
                    }
                    other => bail!("the multiplex trace does not send {other:?}"),
                }
            }
            Direction::Server => {
                let frame = codec
                    .decode_server_frame(case.wire_utf8.as_bytes())
                    .map_err(|rejection| anyhow!("{}", rejection.error.message))?;
                let event = state
                    .accept_server_frame(&frame)
                    .map_err(|rejection| anyhow!("{}", rejection.error.message))?;
                match event {
                    WebSocketServerEvent::Data { channel_id, .. }
                    | WebSocketServerEvent::ChannelControl { channel_id, .. } => {
                        // §6.1 — the resume point only becomes durable after the
                        // receiver checkpoints it locally.
                        if let Some(channel) = state.channel_mut(&channel_id) {
                            channel.checkpoint();
                        }
                    }
                    WebSocketServerEvent::ChannelError { channel_id, .. }
                        if state.channel(&channel_id).is_none() =>
                    {
                        bail!("a channel error arrived on a closed channel");
                    }
                    _ => {}
                }
            }
        }
    }

    if state.phase() != WebSocketConnectionPhase::Authenticated
        || !trace.expected.physical_connection_open
    {
        bail!("the multiplex trace must leave the physical connection open");
    }
    let open: Vec<String> = state
        .open_channel_ids()
        .into_iter()
        .map(str::to_owned)
        .collect();
    if open != trace.expected.open_channels_after_events_close {
        bail!("open channels after the events close drifted: {open:?}");
    }
    let account_cursor = state
        .channel("account-1")
        .and_then(|channel| channel.durable_cursor.clone())
        .ok_or_else(|| anyhow!("the account channel must hold a durable cursor"))?;
    if account_cursor != trace.expected.account_cursor {
        bail!("account durable cursor drifted: {account_cursor}");
    }
    // events-1 is closed by the trace, so its cursor is read from the retired
    // channel: a closed channel keeps the resume point the client checkpointed.
    let events_cursor = retired_cursor(&state, "events-1")?;
    if events_cursor != trace.expected.events_cursor {
        bail!("events durable cursor drifted: {events_cursor}");
    }
    let signal = state
        .channel("signal-1")
        .ok_or_else(|| anyhow!("the Signal channel must still be open"))?;
    if signal.durable_cursor.is_some() || signal.pending_cursor.is_some() {
        bail!("the Signal channel produced a cursor");
    }

    let reused = open_frames
        .iter()
        .find(|frame| matches!(frame, WebSocketClientFrame::Open { channel_id, .. } if channel_id == "events-1"))
        .ok_or_else(|| anyhow!("the trace never opened events-1"))?
        .clone();
    match state.admit_open(&reused)? {
        WebSocketOpenAdmission::Conflict(rejection) => {
            if rejection.is_connection_scoped() {
                bail!("a channel_id conflict must not close the connection");
            }
        }
        _ => bail!("a reused channel_id must conflict"),
    }
    if state.channel("events-1").is_some() {
        bail!("a conflicting open must never reopen the channel");
    }
    Ok(())
}

/// Read the durable cursor of a channel that is closed but still reserved.
fn retired_cursor(state: &WebSocketConnectionState, channel_id: &str) -> Result<String> {
    state
        .retired_channel(channel_id)
        .and_then(|channel| channel.durable_cursor.clone())
        .ok_or_else(|| anyhow!("channel {channel_id} has no durable cursor to resume from"))
}

// ── §3 reauth ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct ReauthCase {
    name: String,
    server_frame: String,
    #[serde(default)]
    new_nonce: bool,
    #[serde(default)]
    new_jti: bool,
    #[serde(default)]
    new_session_grant: bool,
    #[serde(default)]
    new_ath: bool,
    #[serde(default)]
    authenticate_within_ms: Option<u64>,
    #[serde(default)]
    reuse_old_nonce: bool,
    #[serde(default)]
    reuse_old_jti: bool,
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    expected_close_code: Option<u16>,
    #[serde(default)]
    old_authorization_continues: Option<bool>,
}

fn run_reauth_trace(fixture: &Value, kat: &DpopKat) -> Result<()> {
    let cases: Vec<ReauthCase> =
        serde_json::from_value(super::required_field(fixture, "reauth_trace")?.clone())?;
    if cases.len() != 2 {
        bail!("{FIXTURE} reauth_trace must cover the fresh and the replayed proof");
    }
    let key = kat.signing_key()?;
    let reauth_nonce = "cmVhdXRoLW5vbmNlLTAxMjM0NTY3ODlhYg";
    let reauth_grant = "ak.session.grant.fixture.websocket.v1.reauth";
    let reauth_jti = "d3MtYXV0aC1qdGktMDAwMg";

    for case in &cases {
        if case.server_frame != "reauth_required" {
            bail!("reauth case {} must start from reauth_required", case.name);
        }
        // A reauth establishes a fresh challenge record on the same connection.
        let issued_at = kat.expires_at;
        let challenge = WebSocketChallengeRecord {
            connection_id: kat.connection_id.clone(),
            nonce: reauth_nonce.to_owned(),
            canonical_origin: kat.challenge_state.canonical_origin.clone(),
            canonical_base_url: kat.challenge_state.canonical_base_url.clone(),
            issued_at,
            expires_at: issued_at
                + chrono::Duration::milliseconds(WEBSOCKET_AUTHENTICATION_DEADLINE_MS as i64),
            consumed: false,
        };

        if case.reuse_old_nonce || case.reuse_old_jti {
            // The old proof is presented verbatim against the new challenge.
            let request = WebSocketAuthVerificationRequest {
                compact_jws: &kat.compact_jws,
                connection_id: &kat.connection_id,
                session_grant: &kat.session_grant,
                socket_origin: &kat.origin,
                challenge: &challenge,
                grant_cnf_jkt: &kat.cnf_jkt,
                replay_ledger_hit: case.reuse_old_jti,
                now: issued_at,
            };
            if verify_websocket_auth_proof(&request).is_ok() {
                bail!("reauth case {} accepted a replayed proof", case.name);
            }
            if case.expected_close_code != Some(WebSocketCloseCode::PolicyViolation.as_u16()) {
                bail!("a failed reauth closes the whole connection with 1008");
            }
            if case.old_authorization_continues != Some(false) {
                bail!("the old authorization must not survive a failed reauth");
            }
            continue;
        }

        if !(case.new_nonce && case.new_jti && case.new_session_grant && case.new_ath) {
            bail!("reauth case {} must refresh every proof input", case.name);
        }
        let within_ms = case
            .authenticate_within_ms
            .ok_or_else(|| anyhow!("reauth case {} needs a deadline", case.name))?;
        if within_ms > WEBSOCKET_AUTHENTICATION_DEADLINE_MS {
            bail!(
                "reauth case {} exceeds the authentication deadline",
                case.name
            );
        }
        let now = issued_at + chrono::Duration::milliseconds(within_ms as i64);
        let proof = build_websocket_auth_proof(
            &WebSocketAuthProofRequest {
                base_url: &kat.base_url,
                session_grant: reauth_grant,
                nonce: reauth_nonce,
                issued_at: now,
                jti: reauth_jti,
            },
            &key,
        )?;
        if proof.claims.ath == kat.claims_json_utf8 {
            bail!("the refreshed proof must not reuse the old ath");
        }
        let verified = verify_websocket_auth_proof(&WebSocketAuthVerificationRequest {
            compact_jws: &proof.compact_jws,
            connection_id: &kat.connection_id,
            session_grant: reauth_grant,
            socket_origin: &kat.origin,
            challenge: &challenge,
            grant_cnf_jkt: &kat.cnf_jkt,
            replay_ledger_hit: false,
            now,
        })
        .map_err(|error| anyhow!("a fresh reauth must succeed: {error}"))?;
        if verified.replay_ledger_key.jti == kat.expected_replay_ledger_key[1] {
            bail!("the refreshed proof must mint a new replay ledger key");
        }
        if case.expected.as_deref() != Some("channels_continue") {
            bail!("a successful reauth keeps the admitted channels");
        }
    }
    Ok(())
}

// ── §8 drain, close codes and fallback ──────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
struct DrainCase {
    name: String,
    input: String,
    #[serde(default)]
    websocket_close: Option<u16>,
    #[serde(default)]
    other_channels_continue: Option<bool>,
    #[serde(default)]
    new_channel_admission: Option<String>,
    #[serde(default)]
    durable_checkpoint_until_deadline: Option<bool>,
    #[serde(default)]
    expected_close_code: Option<u16>,
    #[serde(default)]
    minimum_reconnect_delay_ms: Option<u32>,
    #[serde(default)]
    expected_transport: Option<String>,
    #[serde(default)]
    first_close_code: Option<u16>,
    #[serde(default)]
    fresh_socket_and_grant_attempts: Option<u8>,
    #[serde(default)]
    second_close_code: Option<u16>,
    #[serde(default)]
    attempts: Option<u8>,
}

fn run_drain_and_close_traces(fixture: &Value, limits: &FixtureLimits) -> Result<()> {
    let cases: Vec<DrainCase> =
        serde_json::from_value(super::required_field(fixture, "drain_and_close_traces")?.clone())?;
    if cases.len() != 6 {
        bail!("{FIXTURE} drain_and_close_traces must cover all six outcomes");
    }
    for case in &cases {
        match case.name.as_str() {
            "channel_error_isolated" => {
                if case.websocket_close.is_some() || case.other_channels_continue != Some(true) {
                    bail!("a channel error never closes the physical connection");
                }
                let mut state = authenticated_state(limits);
                state.record_opened("events-1", WebSocketOperationId::EventsStreamSubscribe)?;
                state.record_opened("account-1", WebSocketOperationId::AccountStreamSubscribe)?;
                state.close_channel("events-1");
                if state.open_channel_ids() != ["account-1"] {
                    bail!("case {} disturbed a sibling channel", case.name);
                }
            }
            "graceful_service_drain" => {
                let mut state = authenticated_state(limits);
                state.record_opened("account-1", WebSocketOperationId::AccountStreamSubscribe)?;
                let reconnect_after_ms = case
                    .minimum_reconnect_delay_ms
                    .ok_or_else(|| anyhow!("case {} needs the drain reconnect delay", case.name))?;
                let drain = WebSocketServerFrame::connection_control(
                    &WebSocketConnectionControlPayload::Drain {
                        reconnect_after_ms,
                        deadline: Utc::now() + chrono::Duration::seconds(30),
                        reason: Some("service_restart".to_owned()),
                    },
                )?;
                state
                    .accept_server_frame(&drain)
                    .map_err(|rejection| anyhow!("{}", rejection.error.message))?;
                if state.phase() != WebSocketConnectionPhase::Draining {
                    bail!("case {} must put the connection into drain", case.name);
                }
                if case.new_channel_admission.as_deref() != Some("rejected")
                    || case.durable_checkpoint_until_deadline != Some(true)
                {
                    bail!("a drain refuses new channels and keeps checkpointing");
                }
                let open =
                    WebSocketClientFrame::open("events-2", &WebSocketOpenParameters::Signal)?;
                if !matches!(
                    state.admit_open(&open)?,
                    WebSocketOpenAdmission::RateLimited(_)
                ) {
                    bail!("a draining connection must not admit a new channel");
                }
                let mut policy = WebSocketFallbackPolicy::new();
                policy.welcomed();
                let decision = policy.on_close(
                    close_code(case.expected_close_code, &case.name)?,
                    Some(reconnect_after_ms),
                );
                match decision {
                    WebSocketTransportDecision::RetryWebSocket { after_ms }
                        if after_ms >= reconnect_after_ms => {}
                    other => bail!(
                        "case {} must honour the drain delay, got {other:?}",
                        case.name
                    ),
                }
            }
            "protocol_error" | "message_too_big" => {
                let mut policy = WebSocketFallbackPolicy::new();
                policy.welcomed();
                expect_transport(
                    &case.name,
                    policy.on_close(close_code(case.expected_close_code, &case.name)?, None),
                    case.expected_transport.as_deref(),
                )?;
            }
            "policy_error_retry_once" => {
                let mut policy = WebSocketFallbackPolicy::new();
                policy.welcomed();
                let first = policy.on_close(close_code(case.first_close_code, &case.name)?, None);
                if !matches!(first, WebSocketTransportDecision::RetryWebSocket { .. }) {
                    bail!("case {} must allow one fresh-grant retry", case.name);
                }
                if case.fresh_socket_and_grant_attempts != Some(1) {
                    bail!("case {} allows exactly one retry", case.name);
                }
                expect_transport(
                    &case.name,
                    policy.on_close(close_code(case.second_close_code, &case.name)?, None),
                    case.expected_transport.as_deref(),
                )?;
            }
            "restart_retry_budget" => {
                let attempts = case
                    .attempts
                    .ok_or_else(|| anyhow!("case {} needs an attempt count", case.name))?;
                let mut policy = WebSocketFallbackPolicy::new();
                let mut decision = WebSocketTransportDecision::FallbackHttp;
                for _ in 0..attempts {
                    // Every attempt closes before `welcome`, so the budget is
                    // never reset.
                    decision = policy.on_close(WebSocketCloseCode::ServiceRestart, None);
                }
                expect_transport(&case.name, decision, case.expected_transport.as_deref())?;
            }
            name => bail!("unknown drain case {name}"),
        }
        if case.input.is_empty() {
            bail!("case {} must describe its input", case.name);
        }
    }
    Ok(())
}

fn close_code(code: Option<u16>, name: &str) -> Result<WebSocketCloseCode> {
    let code = code.ok_or_else(|| anyhow!("case {name} must state a close code"))?;
    WebSocketCloseCode::from_u16(code)
        .ok_or_else(|| anyhow!("case {name} uses unregistered close code {code}"))
}

fn expect_transport(
    name: &str,
    decision: WebSocketTransportDecision,
    expected: Option<&str>,
) -> Result<()> {
    match (decision, expected) {
        (WebSocketTransportDecision::FallbackHttp, Some("http_json")) => Ok(()),
        (WebSocketTransportDecision::RetryWebSocket { .. }, Some("websocket")) => Ok(()),
        (decision, expected) => bail!("case {name} produced {decision:?}, expected {expected:?}"),
    }
}

#[derive(Clone, Debug, Deserialize)]
struct FallbackCase {
    name: String,
    #[serde(default)]
    failures: Vec<String>,
    #[serde(default)]
    websocket_retry_before_fallback: Option<bool>,
    #[serde(default)]
    old_websocket_owner_closed: Option<bool>,
    #[serde(default)]
    old_channels_closed: Option<bool>,
    #[serde(default)]
    durable_cursors_persisted_before_switch: Option<bool>,
    #[serde(default)]
    http_owner_started_after_old_owner_stopped: Option<bool>,
    #[serde(default)]
    duplicate_consumers: Option<bool>,
    #[serde(default)]
    signal_catchup_attempted: Option<bool>,
    expected_transport: String,
}

fn run_fallback_cases(fixture: &Value) -> Result<()> {
    let cases: Vec<FallbackCase> =
        serde_json::from_value(super::required_field(fixture, "fallback_cases")?.clone())?;
    if cases.len() != 2 {
        bail!("{FIXTURE} fallback_cases must cover the handshake and the owner switch");
    }
    for case in &cases {
        if case.expected_transport != "http_json" {
            bail!(
                "fallback case {} must end on the mandatory binding",
                case.name
            );
        }
        match case.name.as_str() {
            "upgrade_or_proxy_failure" => {
                if case.websocket_retry_before_fallback != Some(false) {
                    bail!("an upgrade failure gets no WebSocket retry");
                }
                for failure in &case.failures {
                    let failure = match failure.as_str() {
                        "upgrade_status_not_101" => {
                            WebSocketHandshakeFailure::UpgradeStatusNotSwitchingProtocols
                        }
                        "subprotocol_not_selected" => {
                            WebSocketHandshakeFailure::SubprotocolNotSelected
                        }
                        "proxy_blocked" => WebSocketHandshakeFailure::ProxyBlocked,
                        other => bail!("unknown handshake failure {other}"),
                    };
                    let mut policy = WebSocketFallbackPolicy::new();
                    expect_transport(
                        &case.name,
                        policy.on_handshake_failure(failure),
                        Some(&case.expected_transport),
                    )?;
                }
                if case.failures.len() != 3 {
                    bail!("fallback case {} must cover all three failures", case.name);
                }
            }
            "single_owner_transport_switch" => {
                if case.duplicate_consumers != Some(false)
                    || case.signal_catchup_attempted != Some(false)
                {
                    bail!("a transport switch never duplicates a consumer or replays Signal");
                }
                let mut handoff = WebSocketConsumerHandoff::new();
                handoff.start(WebSocketConsumerOwner::WebSocket)?;
                if handoff.switch_to(WebSocketConsumerOwner::Http).is_ok() {
                    bail!("the switch must refuse while the old owner runs");
                }
                if case.old_websocket_owner_closed != Some(true)
                    || case.old_channels_closed != Some(true)
                {
                    bail!("the old owner and its channels must be closed first");
                }
                handoff.stop();
                if handoff.switch_to(WebSocketConsumerOwner::Http).is_ok() {
                    bail!("the switch must refuse before cursors are persisted");
                }
                if case.durable_cursors_persisted_before_switch != Some(true) {
                    bail!("durable cursors must be persisted before the switch");
                }
                handoff.persist_cursors();
                handoff.switch_to(WebSocketConsumerOwner::Http)?;
                if case.http_owner_started_after_old_owner_stopped != Some(true)
                    || handoff.owner() != WebSocketConsumerOwner::Http
                {
                    bail!("the HTTP owner must start only after the handoff");
                }
            }
            name => bail!("unknown fallback case {name}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn websocket_binding_suite_runs_clean() {
        super::run_websocket_binding_suite().unwrap();
    }
}
