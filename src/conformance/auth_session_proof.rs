//! Auth, DID-proof, and sender-constrained session proof conformance vectors.

use anyhow::{Result, anyhow, bail};
use arkret_canonical as canonical;
use arkret_identifiers::{DeviceId, DidCoreId, Hash, SessionGrantId};
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantOutcome, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
    human_session_grant_intent_digest, session_grant_refresh_request_digest,
};
use arkret_models_identity::{
    CanonicalSessionPublicJwk, STANDARD_INITIAL_SESSION_GRANT_OPERATIONS,
};
use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, SignatureInput, SignatureVerificationPolicy,
    SignedRequestParts, canonical_message, sign_message, verify_signed_http_message,
};
use arkret_wire::{ProfileId, ProofContextId};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use super::schema_validation_fixture::SchemaEnv;

pub const VECTOR_ID_AUTH_SESSION_GRANT_AUDIENCE_BINDING: &str =
    "ak.vector.auth.session_grant_audience_binding.v1";
pub const VECTOR_ID_SESSION_POP_PRESENTATION: &str = "ak.vector.session.pop_presentation.v1";
pub const VECTOR_ID_SESSION_BARE_BEARER_REJECTED_PROTECTED: &str =
    "ak.vector.session.bare_bearer_rejected_protected.v1";

pub const ALL_AUTH_SESSION_PROOF_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AUTH_SESSION_GRANT_AUDIENCE_BINDING,
    VECTOR_ID_SESSION_POP_PRESENTATION,
    VECTOR_ID_SESSION_BARE_BEARER_REJECTED_PROTECTED,
];

const AUTH_SESSION_PROOF_FIXTURE_FILE: &str = "auth-session-proof-fixture.json";
const SESSION_GRANT_REQUEST_SCHEMA: &str =
    "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody";
const SESSION_GRANT_OUTCOME_SCHEMA: &str =
    "schemas/service-operation-dtos.schema.json#/$defs/SessionGrantOutcome";
const MAX_HTTP_SIGNATURE_WINDOW_SECONDS: i64 = 300;
const HTTP_SIGNATURE_SKEW_SECONDS: i64 = 30;

fn auth_session_proof_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(AUTH_SESSION_PROOF_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::AUTH_SERVER_V1)?;
    validate_auth_session_proof_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_auth_session_proof_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("auth_session_proof") {
        bail!("auth session proof fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("auth session proof fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("auth session proof fixture missing cases[]"))?;

    for vector_id in ALL_AUTH_SESSION_PROOF_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("auth session proof fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("auth session proof fixture missing asserted case {vector_id}");
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
        .ok_or_else(|| anyhow!("auth session proof fixture missing case {vector_id}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing string field {field}"))
}

fn expected_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing expected.{field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("case missing u64 field {field}"))
}

fn required_i64(value: &Value, field: &str) -> Result<i64> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("case missing i64 field {field}"))
}

fn required_string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("case missing array field {field}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{field} entries must be strings"))
        })
        .collect()
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(canonical::parse_timestamp_canonical(value)?)
}

fn did(value: &str) -> Result<DidCoreId> {
    DidCoreId::new(value.to_owned()).map_err(Into::into)
}

fn device(value: &str) -> Result<DeviceId> {
    DeviceId::new(value.to_owned()).map_err(Into::into)
}

fn schema_valid(schema_ref: &str, value: &Value) -> Result<()> {
    let env = SchemaEnv::load()?;
    let validator = env.compile(schema_ref)?;
    if !validator.is_valid(value) {
        let errors = validator
            .iter_errors(value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("value failed schema {schema_ref}: {errors}");
    }
    Ok(())
}

fn session_grant_request_value(
    vector: &Value,
    audience: &str,
    session_intent_digest: &Hash,
) -> Result<Value> {
    let issued_at = parse_time(required_str(vector, "issued_at")?)?;
    let expires_at = parse_time(required_str(vector, "expires_at")?)?;
    Ok(json!({
        "request_id": required_str(vector, "request_id")?,
        "principal_id": required_str(vector, "principal_id")?,
        "device_id": required_str(vector, "device_id")?,
        "audience": audience,
        "accepted_device_possession_proof": {
            "context": ProofContextId::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1,
            "purpose": "session_grant_issue",
            "request_id": required_str(vector, "request_id")?,
            "account_subject": required_str(vector, "account_subject")?,
            "account_handoff_grant_digest": required_str(vector, "account_handoff_grant_digest")?,
            "principal_id": required_str(vector, "principal_id")?,
            "device_id": required_str(vector, "device_id")?,
            "audience": audience,
            "holder_jkt": required_str(vector, "holder_jkt")?,
            "session_intent_digest": session_intent_digest,
            "issued_at": arkret_canonical::format_timestamp_canonical(issued_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
            "verification_method": required_str(vector, "verification_method")?,
            "signature": arkret_canonical::base64url_encode([0x5a; 64])
        }
    }))
}

fn parse_session_grant_request(value: Value) -> Result<SessionGrantRequestBody> {
    schema_valid(SESSION_GRANT_REQUEST_SCHEMA, &value)?;
    serde_json::from_value(value).map_err(Into::into)
}

fn issue_session_grant(
    request: &SessionGrantRequestBody,
    target_audience: &str,
    server_max_ttl: Duration,
    now: DateTime<Utc>,
) -> std::result::Result<SessionGrantOutcome, &'static str> {
    let SessionGrantRequestBody::Human(request) = request else {
        return Err(arkret_wire::ReasonCode::PROOF_INVALID);
    };
    if request.audience.as_str() != target_audience {
        return Err(arkret_wire::ErrorCode::AUDIENCE_MISMATCH);
    }
    if request.validate().is_err() {
        return Err(arkret_wire::ReasonCode::PROOF_INVALID);
    }

    Ok(SessionGrantOutcome {
        principal_id: request.principal_id.clone(),
        device_id: Some(request.device_id.clone()),
        session_grant: "ak.session.grant.test".to_owned(),
        expires_at: now + server_max_ttl,
        session_grant_id: SessionGrantId::from_issuance_digest(canonical::sha256_bytes(
            request
                .accepted_device_possession_proof
                .session_intent_digest
                .as_str()
                .as_bytes(),
        )),
        session_public_key: CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .map_err(|_| arkret_wire::ReasonCode::PROOF_INVALID)?,
        audience: request.audience.clone(),
        granted_scope: STANDARD_INITIAL_SESSION_GRANT_OPERATIONS
            .iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
        scope_details: None,
    })
}

fn development_mode_verified_profiles(attempted: &[String]) -> Vec<String> {
    attempted
        .iter()
        .filter(|profile| profile.as_str() != ProfileId::AUTH_SERVER_V1)
        .cloned()
        .collect()
}

fn validate_closed_human_session_shapes() -> Result<()> {
    let principal_id = did("ak:did_core:webvh:z6mkfixture")?;
    let device_id = device("ak:device:0196419b-0000-7000-8000-000000000001")?;
    let audience = did("ak:did_core:webvh:z6mkfixtureserviceexample")?;
    let predecessor = SessionGrantId::from_issuance_digest(canonical::sha256_bytes(b"previous"));
    let holder_jkt = "ERERERERERERERERERERERERERERERERERERERERERE";
    let intent = session_grant_refresh_request_digest(
        "grant.jwt.fixture",
        &predecessor,
        &principal_id,
        &device_id,
        &audience,
        holder_jkt,
    )?;
    let refresh = json!({
        "grant_jwt": "grant.jwt.fixture",
        "audience": audience,
        "device_id": device_id,
        "accepted_device_possession_proof": {
            "context": ProofContextId::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1,
            "purpose": "session_grant_refresh",
            "predecessor_session_grant_id": predecessor,
            "principal_id": principal_id,
            "device_id": device_id,
            "audience": audience,
            "holder_jkt": holder_jkt,
            "session_intent_digest": intent,
            "issued_at": "2026-06-19T00:00:00.000Z",
            "expires_at": "2026-06-19T00:05:00.000Z",
            "verification_method": "did:webvh:z6mkfixture:alice.example#device-key-1",
            "signature": canonical::base64url_encode([0x5a; 64])
        }
    });
    let parsed: SessionGrantRefreshRequestBody = serde_json::from_value(refresh.clone())?;
    parsed.validate()?;

    let request_id = "ak:request:0196419b-0000-7000-8000-000000000002".parse()?;
    let issue_intent = human_session_grant_intent_digest(
        &request_id,
        &principal_id,
        &device_id,
        &audience,
        holder_jkt,
    )?;
    let mut issue = json!({
        "request_id": request_id,
        "principal_id": principal_id,
        "device_id": device_id,
        "audience": audience,
        "accepted_device_possession_proof": {
            "context": ProofContextId::SESSION_GRANT_ACCEPTED_DEVICE_POSSESSION_PROOF_V1,
            "purpose": "session_grant_issue",
            "request_id": request_id,
            "account_subject": format!("sha256:{}", "a".repeat(64)),
            "account_handoff_grant_digest": format!("sha256:{}", "b".repeat(64)),
            "principal_id": principal_id,
            "device_id": device_id,
            "audience": audience,
            "holder_jkt": holder_jkt,
            "session_intent_digest": issue_intent,
            "issued_at": "2026-06-19T00:00:00.000Z",
            "expires_at": "2026-06-19T00:05:00.000Z",
            "verification_method": "did:webvh:z6mkfixture:alice.example#device-key-1",
            "signature": canonical::base64url_encode([0x5a; 64])
        }
    });
    let parsed: SessionGrantRequestBody = serde_json::from_value(issue.clone())?;
    parsed.validate()?;

    issue["requested_scope"] = json!(["ak.self.events.write"]);
    if serde_json::from_value::<SessionGrantRequestBody>(issue).is_ok() {
        bail!("human session issue accepted caller-controlled requested_scope");
    }
    Ok(())
}

#[derive(Clone)]
struct SignedRequest {
    method: String,
    target_uri: String,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

struct SelfRequestSigning<'a> {
    signing_key: &'a SigningKey,
    key_id: &'a str,
    method: &'a str,
    target_uri: &'a str,
    authority: &'a str,
    path: &'a str,
    body: &'a [u8],
    idempotency_key: Option<&'a str>,
    created: i64,
    expires: i64,
}

fn sign_self_request(request: SelfRequestSigning<'_>) -> Result<SignedRequest> {
    let SelfRequestSigning {
        signing_key,
        key_id,
        method,
        target_uri,
        authority,
        path,
        body,
        idempotency_key,
        created,
        expires,
    } = request;
    let mut covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
    ];
    let mut names = vec!["\"@method\"", "\"@target-uri\"", "\"@authority\""];
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut signed_headers: Vec<(String, String)> = Vec::new();
    let digest = if body.is_empty() {
        None
    } else {
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        covered.push(Component::Header("content-digest".to_owned()));
        names.push("\"content-digest\"");
        headers.push(("content-digest".to_owned(), digest.wire_value.clone()));
        Some(digest.wire_value)
    };
    if let Some(idempotency_key) = idempotency_key {
        covered.push(Component::Header("idempotency-key".to_owned()));
        names.push("\"idempotency-key\"");
        headers.push(("idempotency-key".to_owned(), idempotency_key.to_owned()));
        signed_headers.push(("idempotency-key".to_owned(), idempotency_key.to_owned()));
    }

    let params_value = format!(
        "({});created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\"",
        names.join(" ")
    );
    let signature_input = SignatureInput {
        label: "sig1".to_owned(),
        covered_components: covered,
        created,
        expires,
        key_id: key_id.to_owned(),
        algorithm: "ed25519".to_owned(),
        params_value: params_value.clone(),
    };
    let parts = SignedRequestParts {
        method: method.to_owned(),
        target_uri: target_uri.to_owned(),
        authority: authority.to_owned(),
        path: path.to_owned(),
        headers: signed_headers,
        body_digest: digest,
    };
    let canonical = canonical_message(&parts, &signature_input)?;
    let signature = sign_message(&canonical, signing_key);
    headers.push(("signature-input".to_owned(), format!("sig1={params_value}")));
    headers.push(("signature".to_owned(), format!("sig1=:{signature}:")));
    Ok(SignedRequest {
        method: method.to_owned(),
        target_uri: target_uri.to_owned(),
        authority: authority.to_owned(),
        path: path.to_owned(),
        headers,
        body: body.to_vec(),
    })
}

fn verify_self_pop(
    request: &SignedRequest,
    public_key: &VerifyingKey,
    expected_key_id: &str,
    now: i64,
) -> std::result::Result<(), &'static str> {
    let policy = if request.body.is_empty() {
        SignatureVerificationPolicy::new(vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ])
        .require_content_digest(false)
    } else {
        SignatureVerificationPolicy::service_ingest().require_content_digest(true)
    }
    .max_clock_skew_seconds(HTTP_SIGNATURE_SKEW_SECONDS);

    let verified = verify_signed_http_message(
        &request.method,
        &request.target_uri,
        &request.authority,
        &request.path,
        request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        &request.body,
        public_key,
        &policy,
        now,
    )
    .map_err(|_| arkret_wire::ErrorCode::UNAUTHENTICATED)?;
    if verified.signature_input.key_id != expected_key_id {
        return Err(arkret_wire::ErrorCode::UNAUTHENTICATED);
    }
    if verified.signature_input.expires - verified.signature_input.created
        > MAX_HTTP_SIGNATURE_WINDOW_SECONDS
    {
        return Err(arkret_wire::ErrorCode::UNAUTHENTICATED);
    }
    Ok(())
}

/// Reference model for the `ak.vector.session.bare_bearer_rejected_protected.v1`
/// admission rule (api-conventions.md sender-constrained hardening): production
/// current-v1 protected endpoints MUST reject bare `Authorization: Bearer`
/// unless a sender-constrained proof (DPoP, RFC 9421 HTTP Message Signature,
/// detached JWS, mTLS or equivalent) accompanies it — for EVERY profile, not
/// just high-security. High-security profiles additionally demand RFC 9421 PoP
/// for every protected `ak.self.*` operation.
fn protected_bare_bearer_admission(
    _profile: &str,
    action: &str,
    has_sender_constrained_proof: bool,
) -> std::result::Result<(), &'static str> {
    let protected = matches!(action, "protected_current_v1_endpoint" | "regular_write")
        || action.starts_with("ak.self.");
    if protected && !has_sender_constrained_proof {
        return Err(arkret_wire::ErrorCode::UNAUTHENTICATED);
    }
    Ok(())
}

/// Public metadata surfaces never treat bare bearer as session or capability
/// authentication — the request is served as an unauthenticated public read.
fn classify_public_metadata_bare_bearer() -> &'static str {
    "treated_as_unauthenticated_public_request"
}

pub fn run_auth_session_grant_audience_binding_vector() -> Result<()> {
    let fixture = auth_session_proof_fixture()?;
    let vector = case(&fixture, VECTOR_ID_AUTH_SESSION_GRANT_AUDIENCE_BINDING)?;
    let now = parse_time("2026-06-19T00:00:00.000Z")?;
    let target_audience = required_str(vector, "target_audience")?;
    let server_max_ttl = Duration::seconds(required_u64(vector, "server_max_ttl_seconds")? as i64);

    let principal_id = did(required_str(vector, "principal_id")?)?;
    let device_id = device(required_str(vector, "device_id")?)?;
    let request_id = required_str(vector, "request_id")?.parse()?;
    let holder_jkt = required_str(vector, "holder_jkt")?;
    let target = did(target_audience)?;
    let expected_digest = human_session_grant_intent_digest(
        &request_id,
        &principal_id,
        &device_id,
        &target,
        holder_jkt,
    )?;

    let mismatched_audience = required_str(vector, "mismatched_audience")?;
    let mismatched_digest = human_session_grant_intent_digest(
        &request_id,
        &principal_id,
        &device_id,
        &did(mismatched_audience)?,
        holder_jkt,
    )?;
    let mismatched_request = parse_session_grant_request(session_grant_request_value(
        vector,
        mismatched_audience,
        &mismatched_digest,
    )?)?;
    if issue_session_grant(&mismatched_request, target_audience, server_max_ttl, now).err()
        != Some(expected_str(vector, "audience_mismatch_reason")?)
    {
        bail!("audience-mismatched session grant proof was not rejected");
    }

    let invalid_binding_request = parse_session_grant_request(session_grant_request_value(
        vector,
        target_audience,
        &mismatched_digest,
    )?)?;
    if issue_session_grant(
        &invalid_binding_request,
        target_audience,
        server_max_ttl,
        now,
    )
    .err()
        != Some(expected_str(vector, "invalid_binding_reason")?)
    {
        bail!("accepted-device proof with a mismatched session intent was not rejected");
    }

    let request = parse_session_grant_request(session_grant_request_value(
        vector,
        target_audience,
        &expected_digest,
    )?)?;
    let outcome = issue_session_grant(&request, target_audience, server_max_ttl, now)
        .map_err(|reason| anyhow!("valid session grant unexpectedly rejected: {reason}"))?;
    let outcome_value = serde_json::to_value(&outcome)?;
    schema_valid(SESSION_GRANT_OUTCOME_SCHEMA, &outcome_value)?;
    if expected_str(vector, "ttl_behavior")? != "issuer_fixed"
        || outcome.expires_at != now + server_max_ttl
    {
        bail!("human session grant TTL was not issuer-owned");
    }

    let attempted = required_string_array(vector, "attempted_verified_profiles")?;
    if !development_mode_verified_profiles(&attempted).is_empty() {
        bail!("development mode advertised a verified auth server profile");
    }
    Ok(())
}

pub fn run_session_pop_presentation_vector() -> Result<()> {
    let fixture = auth_session_proof_fixture()?;
    let vector = case(&fixture, VECTOR_ID_SESSION_POP_PRESENTATION)?;
    let key = signing_key(7);
    let body = required_str(vector, "body")?.as_bytes();
    let created = required_i64(vector, "created")?;
    let expires = required_i64(vector, "expires")?;
    if expires - created != 120 {
        bail!("PoP fixture control window drifted");
    }
    let request = sign_self_request(SelfRequestSigning {
        signing_key: &key,
        key_id: required_str(vector, "key_id")?,
        method: required_str(vector, "method")?,
        target_uri: required_str(vector, "target_uri")?,
        authority: required_str(vector, "authority")?,
        path: required_str(vector, "path")?,
        body,
        idempotency_key: Some(required_str(vector, "idempotency_key")?),
        created,
        expires,
    })?;
    verify_self_pop(
        &request,
        &key.verifying_key(),
        required_str(vector, "key_id")?,
        created,
    )
    .map_err(|reason| anyhow!("valid PoP presentation rejected: {reason}"))?;
    if expected_str(vector, "valid_write")? != "accepted" {
        bail!("valid PoP expectation drifted");
    }

    let mut tampered_transcript = request.clone();
    tampered_transcript.target_uri =
        "https://soland.example.com/_arkret/self/events/tampered".to_owned();
    if verify_self_pop(
        &tampered_transcript,
        &key.verifying_key(),
        required_str(vector, "key_id")?,
        created,
    )
    .err()
        != Some(expected_str(vector, "tampered_transcript_reason")?)
    {
        bail!("PoP transcript mismatch was not rejected");
    }

    let mut tampered_body = request;
    tampered_body.body = b"{\"hello\":\"tampered\"}".to_vec();
    if verify_self_pop(
        &tampered_body,
        &key.verifying_key(),
        required_str(vector, "key_id")?,
        created,
    )
    .err()
        != Some(expected_str(vector, "tampered_digest_reason")?)
    {
        bail!("PoP body digest mismatch was not rejected");
    }
    Ok(())
}

pub fn run_session_bare_bearer_rejected_protected_vector() -> Result<()> {
    let fixture = auth_session_proof_fixture()?;
    let vector = case(&fixture, VECTOR_ID_SESSION_BARE_BEARER_REJECTED_PROTECTED)?;
    // High-security profile: bare bearer on a protected `.read.` operation is
    // rejected as unauthenticated.
    if protected_bare_bearer_admission(
        required_str(vector, "high_security_profile")?,
        required_str(vector, "protected_read_operation_id")?,
        false,
    )
    .err()
        != Some(expected_str(vector, "high_security_bare_bearer_reason")?)
    {
        bail!("high-security profile accepted bare bearer");
    }
    // Default profile: bare bearer on ANY production current-v1 protected
    // endpoint is rejected — there is no low-sensitivity bearer compat path.
    if protected_bare_bearer_admission(
        required_str(vector, "default_profile")?,
        required_str(vector, "bare_bearer_action")?,
        false,
    )
    .err()
        != Some(expected_str(
            vector,
            "default_protected_bare_bearer_reason",
        )?)
    {
        bail!("default profile accepted bare bearer on a protected endpoint");
    }
    // The same endpoint admits the session when a sender-constrained proof
    // accompanies the presentation.
    protected_bare_bearer_admission(
        required_str(vector, "default_profile")?,
        required_str(vector, "bare_bearer_action")?,
        true,
    )
    .map_err(|reason| anyhow!("sender-constrained presentation rejected: {reason}"))?;
    // Public metadata surfaces: bare bearer never authenticates — the request
    // is classified as an unauthenticated public read, not an auth failure.
    if required_str(vector, "public_metadata_surface")? != "unauthenticated_public_response_only" {
        bail!("public metadata surface control drifted");
    }
    if required_str(vector, "public_metadata_operation_id")? != "ak.self.events.read.describe.v1" {
        bail!("public metadata operation classification drifted");
    }
    if classify_public_metadata_bare_bearer()
        != expected_str(vector, "public_metadata_bare_bearer")?
    {
        bail!("public metadata bare bearer classification drifted");
    }

    let key = signing_key(8);
    let body = br#"{"hello":"world"}"#;
    let created = required_i64(vector, "created")?;
    let expires = required_i64(vector, "expires")?;
    if expires - created <= required_u64(vector, "max_window_seconds")? as i64 {
        bail!("over-window PoP control is not outside the replay window");
    }
    let request = sign_self_request(SelfRequestSigning {
        signing_key: &key,
        key_id: "did:web:alice.example#session-key-1",
        method: "POST",
        target_uri: "https://soland.example.com/_arkret/self/events",
        authority: "soland.example.com",
        path: "/_arkret/self/events",
        body,
        idempotency_key: None,
        created,
        expires,
    })?;
    if verify_self_pop(
        &request,
        &key.verifying_key(),
        "did:web:alice.example#session-key-1",
        created,
    )
    .err()
        != Some(expected_str(vector, "over_window_pop_reason")?)
    {
        bail!("over-window PoP was not rejected");
    }
    Ok(())
}

pub fn run_auth_session_proof_fixture_suite() -> Result<()> {
    validate_auth_session_proof_fixture_metadata(&auth_session_proof_fixture()?)?;
    if ALL_AUTH_SESSION_PROOF_VECTOR_IDS.len() != 3 {
        bail!(
            "expected 3 auth session proof vector ids, got {}",
            ALL_AUTH_SESSION_PROOF_VECTOR_IDS.len()
        );
    }

    run_auth_session_grant_audience_binding_vector()?;
    validate_closed_human_session_shapes()?;
    run_session_pop_presentation_vector()?;
    run_session_bare_bearer_rejected_protected_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_session_proof_vectors_run_clean() {
        run_auth_session_proof_fixture_suite().unwrap();
    }
}
