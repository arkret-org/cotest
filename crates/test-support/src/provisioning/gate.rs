//! The standard Arkret gate operations of the canonical chain.
//!
//! Steps 3, 5 and 7 of `docs/canonical-provisioning-operations.md`, plus the
//! OAuth authorization that step 3 consumes. Everything here is a registered
//! operation with an operation id, in contrast to the Coauth product API in
//! `super::coauth_account`.
//!
//! Protocol material is not built here. The handoff body, the challenge request
//! and the register body come from [`crate::wire`] — the same functions the
//! TypeScript suite reaches through the `cotest-wire` CLI — so the two sides
//! cannot drift on what a registration looks like.

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::account_operations::{
    AccountRegisterOutcome, AccountRegisterRequestBody,
};
use arkret_models_collaboration::session_grants::SessionGrantOutcome;
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::http::{json_object, post_json};

/// A completed OAuth authorization, ready to be exchanged for a handoff.
#[derive(Clone, Debug)]
pub struct OidcAuthorization {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

/// The redirect target registered for the joint deployment's OAuth client.
///
/// `patch-coauth-config.py` registers this pair alongside any Inkson origin, so
/// it is available whether or not a browser lane is running — which is what
/// lets a headless provisioning path complete the authorization at all.
const LOOPBACK_REDIRECT_URI: &str = "http://127.0.0.1/auth/callback";

/// Run the authorization-code flow against Coauth as the logged-in account.
///
/// The client **must not follow redirects**: the authorize response is a 302
/// into the approval page, and its `Location` carries the grant id this flow
/// needs. A client that follows it silently loses the one value the step exists
/// to produce.
pub async fn authorize_with_current_account(
    http: &reqwest::Client,
    coauth_base: &str,
    client_id: &str,
) -> Result<OidcAuthorization> {
    let base = coauth_base.trim_end_matches('/');
    let discovery =
        super::http::get_plain_json(http, &format!("{base}/.well-known/openid-configuration"))
            .await
            .context("read Coauth OIDC discovery")?;
    let discovery = json_object(&discovery, "OIDC discovery")?;
    let issuer = discovery
        .get("issuer")
        .and_then(Value::as_str)
        .context("OIDC discovery omitted issuer")?
        .to_owned();
    let authorization_endpoint = discovery
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .context("OIDC discovery omitted authorization_endpoint")?;

    let state = random_b64url("state");
    let nonce = random_b64url("nonce");
    let code_verifier = random_b64url("verifier");
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(code_verifier.as_bytes()));

    let mut authorize =
        url::Url::parse(authorization_endpoint).context("parse authorization_endpoint")?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", LOOPBACK_REDIRECT_URI)
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &code_challenge);

    let response = http
        .get(authorize.as_str())
        .send()
        .await
        .context("GET Coauth authorize")?;
    let status = response.status();
    if !status.is_redirection() {
        let body = response.text().await.unwrap_or_default();
        bail!(
            "Coauth authorize did not enter approval ({status}): {body}. \
             A 200 here usually means the HTTP client is following redirects."
        );
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .context("Coauth authorize redirect carried no Location")?
        .to_owned();
    let approval = url::Url::parse(&location)
        .or_else(|_| url::Url::parse(base).and_then(|b| b.join(&location)))
        .context("parse approval location")?;
    if !approval.path().contains("/oauth/approval/") {
        bail!("Coauth authorize returned an unexpected location: {approval}");
    }
    let grant_id = approval
        .path_segments()
        .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
        .context("approval location carried no grant id")?
        .to_owned();

    let approved = post_json(
        http,
        &format!("{base}/_coauth/self/oauth/authorization-grants/{grant_id}/decision"),
        &json!({ "action": "approve" }),
    )
    .await
    .context("approve the OAuth authorization grant")?;
    let approved = json_object(&approved, "OAuth approval")?;
    if approved.get("status").and_then(Value::as_str) != Some("success") {
        bail!("Coauth OAuth approval did not succeed: {approved:?}");
    }
    let redirect = approved
        .get("redirect_url")
        .and_then(Value::as_str)
        .context("OAuth approval returned no callback URL")?;
    let callback = url::Url::parse(redirect).context("parse OAuth callback URL")?;

    let mut returned_state = None;
    let mut authorization_code = None;
    for (key, value) in callback.query_pairs() {
        match key.as_ref() {
            "state" => returned_state = Some(value.into_owned()),
            "code" => authorization_code = Some(value.into_owned()),
            _ => {}
        }
    }
    // The state check is the whole point of sending one; a callback that comes
    // back with someone else's state is the failure this flow must not accept.
    if returned_state.as_deref() != Some(state.as_str()) {
        bail!("Coauth OAuth callback state did not match the request");
    }

    Ok(OidcAuthorization {
        issuer,
        client_id: client_id.to_owned(),
        redirect_uri: LOOPBACK_REDIRECT_URI.to_owned(),
        state,
        nonce,
        authorization_code: authorization_code
            .context("OAuth callback omitted the authorization code")?,
        code_verifier,
    })
}

/// Test-scoped entropy, derived rather than drawn from an RNG.
///
/// This is a `state`/`nonce`/`code_verifier` for one provisioning run in one
/// test process; it never protects anything outside it. Deriving from the clock
/// and a label keeps the crate free of an RNG dependency, and the values are
/// still unique per call because the nanosecond clock advances between them.
/// Production PKCE material is CSPRNG-backed in the real clients.
fn random_b64url(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(b"cotest-provisioning-v1");
    hasher.update(label.as_bytes());
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The founding device's DPoP key, and the seed the wire oracle needs to sign
/// with it.
///
/// Derived, not drawn from an RNG, for the same reason the PKCE material is:
/// this key exists for one provisioning run in one test process. The real
/// clients generate device keys from the OS CSPRNG.
#[derive(Clone, Debug)]
pub struct FoundingDeviceKey {
    pub seed_b64url: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl FoundingDeviceKey {
    pub fn derive(label: &str) -> Self {
        let seed: [u8; 32] = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before Unix epoch")
                .as_nanos();
            let mut hasher = Sha256::new();
            hasher.update(b"cotest-provisioning-device-v1");
            hasher.update(label.as_bytes());
            hasher.update(nanos.to_le_bytes());
            hasher.update(std::process::id().to_le_bytes());
            hasher.finalize().into()
        };
        Self {
            seed_b64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed),
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// The canonical JSON of this key's public JWK.
    ///
    /// `{"crv","kty","x"}` in canonical order — the same value the TypeScript
    /// helper passes as `session_public_key`. The initial session grant binds to
    /// this key, so it has to be the one whose proofs the Station will see next.
    pub fn canonical_public_jwk(&self) -> Result<String> {
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.signing_key.verifying_key().to_bytes());
        let jwk = json!({ "crv": "Ed25519", "kty": "OKP", "x": x });
        let canonical = crate::wire::canonical_json(json!({ "value": jwk }))
            .context("canonicalize the founding device public JWK")?;
        canonical
            .get("canonical")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("canonical-json returned no canonical form")
    }

    /// The founding device's signing key.
    ///
    /// In-process only, and deliberately not reachable through the bridge: a
    /// caller that holds this key can act as the principal. The Rust harness
    /// needs it to build a client that signs its own DPoP proofs; the
    /// TypeScript suite asks the bridge to act instead.
    /// Restore the exact run-owned key; generating a replacement would break holder binding.
    pub fn restore(seed_b64url: &str) -> Result<Self> {
        let bytes = arkret_canonical::base64url_decode(seed_b64url)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored session key seed has the wrong length"))?;
        Ok(Self {
            seed_b64url: seed_b64url.to_owned(),
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }

    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        self.signing_key.clone()
    }

    fn dpop_header(&self, method: &str, url: &str) -> Result<String> {
        let request = arkret_http_client::DpopProofRequest::new(method, url);
        garth::session::dpop::build_http_dpop_proof(request, &self.signing_key)
            .map_err(|error| anyhow::anyhow!("build DPoP proof for {method} {url}: {error}"))
    }
}

/// Registered operation ids for the gate calls in this module.
///
/// Every canonical Arkret endpoint requires `Arkret-Operation`; the TypeScript
/// helper derives the value from the spec's operation registry by matching
/// method and path. These are named directly because there are few of them and
/// the mapping is stable. If this list grows past a handful, read the registry
/// rather than adding constants.
const CREATE_HANDOFF_OPERATION_ID: &str = "ak.gate.account.exchange.create_handoff.v1";

/// An account handoff, accepted by the Account Authority.
#[derive(Clone, Debug)]
pub struct AccountHandoff {
    pub request_id: String,
    pub account_subject: arkret_identifiers::Hash,
    pub account_handoff_grant: String,
    pub expires_at: String,
    /// The identity-creation binding. A fresh account must come back
    /// `identity_creation_active` with a lease; anything else means this
    /// account cannot found a principal and the caller must not proceed.
    pub binding: Value,
    pub device_key: FoundingDeviceKey,
}

/// Exchange an authorization for an account handoff grant.
///
/// Step 3, `ak.gate.account.exchange.create_handoff.v1`. The request body and
/// the outcome validation both come from [`crate::wire`] — which routes through
/// Garth's `oidc_account_handoff_request` — so this function only carries the
/// HTTP and the checks that depend on what the caller asked for.
pub async fn create_account_handoff(
    http: &reqwest::Client,
    coauth_base: &str,
    audience_id: &str,
    authorization: &OidcAuthorization,
    device_key: FoundingDeviceKey,
) -> Result<AccountHandoff> {
    let handoff =
        exchange_account_handoff(http, coauth_base, audience_id, authorization, device_key).await?;
    let binding: arkret_models_identity::account::AccountHandoffBinding =
        serde_json::from_value(handoff.binding.clone())?;
    ensure!(
        matches!(
            binding,
            arkret_models_identity::account::AccountHandoffBinding::IdentityCreationActive { .. }
        ),
        "a fresh account must receive an active identity-creation lease"
    );
    Ok(handoff)
}

/// Exchange an already-bound account without weakening the fresh-account gate.
pub async fn create_returning_account_handoff(
    http: &reqwest::Client,
    coauth_base: &str,
    audience_id: &str,
    authorization: &OidcAuthorization,
    device_key: FoundingDeviceKey,
    expected_principal: &arkret_identifiers::DidCoreId,
    expected_did: &arkret_identifiers::Did,
) -> Result<AccountHandoff> {
    let handoff =
        exchange_account_handoff(http, coauth_base, audience_id, authorization, device_key).await?;
    let binding: arkret_models_identity::account::AccountHandoffBinding =
        serde_json::from_value(handoff.binding.clone())?;
    ensure!(
        matches!(binding, arkret_models_identity::account::AccountHandoffBinding::Bound { principal_id, did } if &principal_id == expected_principal && &did == expected_did),
        "returning handoff is not bound to the accepted principal"
    );
    Ok(handoff)
}

async fn exchange_account_handoff(
    http: &reqwest::Client,
    coauth_base: &str,
    audience_id: &str,
    authorization: &OidcAuthorization,
    device_key: FoundingDeviceKey,
) -> Result<AccountHandoff> {
    let request_id = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let body = crate::wire::account_handoff_request(json!({
        "request_id": request_id,
        "audience_id": audience_id,
        "oidc_issuer_uri": authorization.issuer,
        "client_id": authorization.client_id,
        "redirect_uri": authorization.redirect_uri,
        "state": authorization.state,
        "nonce": authorization.nonce,
        "authorization_code": authorization.authorization_code,
        "code_verifier": authorization.code_verifier,
        "dpop_seed_b64url": device_key.seed_b64url,
    }))
    .context("build the account handoff request body")?;

    let url = format!(
        "{}/_arkret/gate/account/authentication-handoffs",
        coauth_base.trim_end_matches('/')
    );
    let response = http
        .post(&url)
        .header("Arkret-Operation", CREATE_HANDOFF_OPERATION_ID)
        .header("DPoP", device_key.dpop_header("POST", &url)?)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let text = response.text().await.context("read handoff response")?;
    if !status.is_success() {
        bail!("{url} returned {status}: {text}");
    }
    let outcome: Value = serde_json::from_str(&text)
        .with_context(|| "parse the canonical handoff outcome".to_owned())?;

    // Validated through the same oracle the TypeScript side uses, so a change
    // in what a valid outcome looks like reaches both at once.
    let validated = crate::wire::account_handoff_outcome(outcome)
        .context("validate the account handoff outcome")?;
    let validated = json_object(&validated, "account handoff outcome")?;
    if validated.get("request_id").and_then(Value::as_str) != Some(request_id.as_str()) {
        bail!("account handoff outcome answered a different request");
    }
    let binding = validated
        .get("binding")
        .cloned()
        .context("account handoff outcome carried no binding")?;

    Ok(AccountHandoff {
        request_id,
        account_subject: serde_json::from_value(
            validated
                .get("account_subject")
                .cloned()
                .context("handoff outcome omitted account subject")?,
        )?,
        account_handoff_grant: validated
            .get("account_handoff_grant")
            .and_then(Value::as_str)
            .context("handoff outcome omitted the grant")?
            .to_owned(),
        expires_at: validated
            .get("expires_at")
            .and_then(Value::as_str)
            .context("handoff outcome omitted expires_at")?
            .to_owned(),
        binding,
        device_key,
    })
}

/// A principal, founded through the canonical chain.
///
/// The register response is parsed into the SDK's own `AccountRegisterOutcome`
/// rather than kept as a `Value`. Two reasons. A caller reaching into
/// `session_grant_outcome["account_id"]["station_id"]` writes that path again
/// on each side of the bridge, and the copies get to drift. And the SDK type is
/// `deny_unknown_fields`, so a Station answering with a shape the model does
/// not declare fails here, loudly, instead of being read past — which is the
/// difference between a suite that checks conformance and one that checks that
/// two implementations happen to agree.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FoundedPrincipal {
    /// The exact SDK request whose accepted receipts must survive host recovery.
    pub accepted_request: AccountRegisterRequestBody,
    /// The register outcome, in the model's own type.
    pub outcome: AccountRegisterOutcome,
    /// The resolvable DID the chain minted, from the registration checkpoint.
    pub did: String,
    /// The founding device, as asked for. The grant is checked to agree.
    pub device_id: String,
    /// `<did>#<device_id>`: the verification method Events signed by this
    /// principal's founding device resolve through. Public by construction —
    /// the seed behind it is not, and stays in [`Self::checkpoint`]'s owner.
    pub event_verification_method: String,
    /// The 24-word recovery mnemonic. Held by the caller, never logged.
    pub recovery_key: String,
    /// The full registration checkpoint.
    ///
    /// **Carries `device_signing_seed_b64url`.** In-process callers may use it;
    /// it must not be handed across the bridge, which is why `cotest-provision`
    /// answers with named fields rather than this value.
    pub checkpoint: Value,
}

impl FoundedPrincipal {
    /// Revalidate disk-restored custody and accepted authority before opening a runtime store.
    pub async fn validate_restored(
        &self,
        http: &reqwest::Client,
        coauth: &str,
        station: &str,
        trust_domain: &str,
        session_key: &FoundingDeviceKey,
    ) -> Result<()> {
        garth::validate_identity_creation_outcome(&self.outcome, &self.accepted_request)?;
        let grant = self
            .outcome
            .session_grant_outcome
            .as_ref()
            .context("stored initial grant absent")?;
        ensure!(
            self.did == self.accepted_request.did.as_str()
                && grant.account_id.principal_id == self.accepted_request.principal_id
                && grant.audience_id == grant.account_id.station_id
                && grant.device_id.as_ref().map(|id| id.as_str()) == Some(self.device_id.as_str())
                && self.event_verification_method == format!("{}#{}", self.did, self.device_id)
                && serde_json::to_value(&grant.session_public_key)?
                    == json!(session_key.canonical_public_jwk()?)
                && grant.expires_at > chrono::Utc::now(),
            "stored Account, Device, signer or session holder binding differs from accepted material"
        );
        let registration = self
            .accepted_request
            .identity_creation
            .as_ref()
            .context("stored registration request absent")?;
        let device: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(
                &registration.pcr_genesis_unit.events[1].payload,
            )?)?;
        let event_key = FoundingDeviceKey::restore(
            self.event_signing_seed_b64url()
                .context("stored Event key absent")?,
        )?;
        let multikey = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &event_key.signing_key().verifying_key().to_bytes(),
        );
        ensure!(
            device.device_id.as_str() == self.device_id
                && device.device_public_key_did.as_str() == format!("did:key:{multikey}")
                && registration
                    .pcr_genesis_unit
                    .create()
                    .actor_id
                    .as_account_id()
                    == Some(&grant.account_id)
                && registration
                    .pcr_genesis_unit
                    .create()
                    .payload
                    .get("object")
                    .and_then(|object| object.get("trust_domain"))
                    .and_then(Value::as_str)
                    == Some(trust_domain),
            "stored Device private key or trust domain differs from the accepted founding PCR"
        );
        verify_accepted_identity_material(
            http,
            coauth,
            station,
            &self.accepted_request,
            &self.outcome,
            session_key,
        )
        .await
    }

    /// The initial DPoP-bound session grant.
    ///
    /// Not an `Option`: the chain asks for one and a founding that produced no
    /// grant did not finish, so [`found_principal`] fails before returning.
    pub fn session_grant(&self) -> &SessionGrantOutcome {
        self.outcome
            .session_grant_outcome
            .as_ref()
            .expect("found_principal rejects an outcome without a session grant")
    }

    /// The closed `AccountId`: this principal at this Station.
    pub fn account_id(&self) -> &arkret_wire::AccountId {
        &self.session_grant().account_id
    }

    /// The signing seed for the founding device's Event signer.
    ///
    /// Key material. In-process only — see the note on [`Self::checkpoint`].
    pub fn event_signing_seed_b64url(&self) -> Option<&str> {
        self.checkpoint
            .get("device_signing_seed_b64url")
            .and_then(Value::as_str)
    }
}

const ISSUE_BINDING_CHALLENGE_OPERATION_ID: &str =
    "ak.gate.account.command.issue_identity_binding_challenge.v1";
const GATE_REGISTER_OPERATION_ID: &str = "ak.gate.account.command.register.v1";
const SELF_ACCOUNT_VIEWER_OPERATION_ID: &str = "ak.self.account.read.viewer.v1";

/// The outcome of a session-grant-authorized read.
///
/// Status and body, not `Result`: a caller checking that the Station refuses a
/// grant it should refuse needs the rejection, and turning it into an error
/// would make the negative case indistinguishable from a broken deployment.
#[derive(Clone, Debug)]
pub struct SessionGrantRead {
    pub status: u16,
    pub body: Value,
}

/// Read the founded principal's own account, as the Station sees it.
///
/// This is the smallest honest proof that a founding actually worked: the
/// grant the register step returned is presented against the Station, bound to
/// the same device key the grant was issued to, and the Station answers with
/// the account it recorded. A chain that produced an unusable grant would pass
/// every assertion about its receipts and fail here.
///
/// `account/viewer` rather than `account/describe`: the latter answers with the
/// *service* description and does not resolve a session at all, so it would
/// have returned 200 for a grant the Station would never honour.
///
/// The endpoint is named here rather than taken as a parameter on purpose. A
/// caller that could pass its own URL and operation id would be carrying
/// protocol knowledge on the other side of the bridge, which is what having
/// one implementation of the chain is meant to prevent.
pub async fn read_self_account_viewer(
    http: &reqwest::Client,
    station_base: &str,
    session_grant: &str,
    device_key: &FoundingDeviceKey,
) -> Result<SessionGrantRead> {
    let url = format!(
        "{}/_arkret/self/account/viewer",
        station_base.trim_end_matches('/')
    );
    // The proof is bound to the grant through `access_token`; the Station
    // checks that binding, so a proof minted without it is refused even though
    // it is validly signed by the right key.
    let request = arkret_http_client::DpopProofRequest::new("GET", &url)
        .access_token(session_grant.to_owned());
    let proof = garth::session::dpop::build_http_dpop_proof(request, &device_key.signing_key)
        .map_err(|error| anyhow::anyhow!("build DPoP proof for GET {url}: {error}"))?;
    let response = http
        .get(&url)
        .header("Arkret-Operation", SELF_ACCOUNT_VIEWER_OPERATION_ID)
        .header("Authorization", format!("DPoP {session_grant}"))
        .header("DPoP", proof)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status().as_u16();
    let text = response.text().await.context("read response body")?;
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    Ok(SessionGrantRead { status, body })
}

/// Found a principal: steps 4 through 7.
///
/// The protocol material — DID operation, PCR genesis unit, recovery key,
/// register body — is built by [`crate::wire`], the same functions the
/// TypeScript suite reaches through `cotest-wire`. What this adds is the two
/// HTTP calls between them and the DPoP the handoff grant requires.
///
/// Returns the recovery key alongside the receipts: a caller that cannot
/// recover the principal it just founded has not really founded one.
///
/// The inputs are packed into [`FoundPrincipalRequest`] rather than passed as
/// six positional strings, where a swapped pair would type-check and fail
/// somewhere deep in the chain.
pub struct FoundPrincipalRequest<'a> {
    pub coauth_base: &'a str,
    pub station_base: &'a str,
    /// From the Station's own description, not from configuration.
    pub trust_domain: &'a str,
    /// The Station service id the initial grant binds to.
    pub audience_id: &'a str,
    pub device_id: &'a str,
    pub display_name: &'a str,
}

/// Private host checkpoint containing the original request and local key custody.
/// Protocol carriers inside this record are the SDK's existing types.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPrincipalRegistration {
    pub coauth_base: String,
    pub station_base: String,
    pub trust_domain: String,
    pub audience_id: String,
    pub device_id: String,
    pub checkpoint: Value,
    pub recovery_key: String,
    pub register_body: AccountRegisterRequestBody,
}

pub async fn found_principal(
    http: &reqwest::Client,
    request: FoundPrincipalRequest<'_>,
    handoff: &AccountHandoff,
) -> Result<FoundedPrincipal> {
    let prepared = prepare_principal_registration(http, request, handoff).await?;
    submit_prepared_principal_registration(http, &prepared, handoff).await
}

/// Prepare once. The host commits this checkpoint before the first register POST.
pub async fn prepare_principal_registration(
    http: &reqwest::Client,
    request: FoundPrincipalRequest<'_>,
    handoff: &AccountHandoff,
) -> Result<PreparedPrincipalRegistration> {
    let FoundPrincipalRequest {
        coauth_base,
        station_base,
        trust_domain,
        audience_id,
        device_id,
        display_name,
    } = request;
    let coauth = coauth_base.trim_end_matches('/');
    let lease = handoff
        .binding
        .get("identity_creation_lease")
        .cloned()
        .context("handoff binding carried no identity-creation lease")?;

    // Step 4: every piece of protocol material, in one call, in Rust.
    let fixture = crate::wire::principal_registration_fixture(json!({
        "station_url": station_base.trim_end_matches('/'),
        "gate_account_base_url": format!("{coauth}/_arkret/gate/account"),
        "handoff_request_id": handoff.request_id,
        "identity_creation_lease": lease,
        "device_id": device_id,
        "trust_domain": trust_domain,
        "initial_session": {
            "session_public_key": handoff.device_key.canonical_public_jwk()?,
            "audience_id": audience_id,
        },
    }))
    .context("build the principal registration fixture")?;
    let fixture = json_object(&fixture, "principal registration fixture")?;
    let recovery_key = fixture
        .get("recovery_key")
        .and_then(Value::as_str)
        .context("registration fixture omitted the recovery key")?
        .to_owned();
    let checkpoint = fixture
        .get("checkpoint")
        .context("registration fixture omitted the checkpoint")?;

    // Step 5: the identity-binding challenge, authorized by the handoff grant.
    let challenge_url = format!("{coauth}/_arkret/gate/account/identity-binding-challenges");
    let challenge = handoff
        .post_authorized(
            http,
            &challenge_url,
            ISSUE_BINDING_CHALLENGE_OPERATION_ID,
            fixture
                .get("challenge_request")
                .context("registration fixture omitted the challenge request")?,
        )
        .await
        .context("request the identity-binding challenge")?;

    // Step 6: the register body, again from the shared oracle.
    let register_body = crate::wire::identity_creation_register_request(json!({
        "challenge": challenge,
        "challenge_request": fixture.get("challenge_request").context("registration fixture omitted challenge request")?,
        "account_subject": handoff.account_subject,
        "origin": reqwest::Url::parse(coauth)?.origin().ascii_serialization(),
        "trust_domain": trust_domain,
        "pcr_genesis_unit": checkpoint
            .get("pcr_genesis_unit")
            .context("checkpoint omitted the PCR genesis unit")?,
        "initial_session": checkpoint
            .get("initial_session")
            .context("checkpoint omitted the initial session")?,
        "recovery_key": recovery_key,
        "display_name": display_name,
    }))
    .context("build the identity-creation register request")?;

    Ok(PreparedPrincipalRegistration {
        coauth_base: coauth.to_owned(),
        station_base: station_base.to_owned(),
        trust_domain: trust_domain.to_owned(),
        audience_id: audience_id.to_owned(),
        device_id: device_id.to_owned(),
        checkpoint: checkpoint.clone(),
        recovery_key,
        register_body: serde_json::from_value(register_body)?,
    })
}

/// Submit or replay the exact frozen register request; never regenerate proofs.
pub async fn submit_prepared_principal_registration(
    http: &reqwest::Client,
    prepared: &PreparedPrincipalRegistration,
    handoff: &AccountHandoff,
) -> Result<FoundedPrincipal> {
    let coauth = prepared.coauth_base.as_str();
    let station_base = prepared.station_base.as_str();
    let audience_id = prepared.audience_id.as_str();
    let device_id = prepared.device_id.as_str();
    let checkpoint = &prepared.checkpoint;
    let recovery_key = prepared.recovery_key.clone();
    let register_body = serde_json::to_value(&prepared.register_body)?;
    ensure!(
        prepared
            .register_body
            .identity_creation
            .as_ref()
            .context("frozen creation request absent")?
            .initial_session
            .session_public_key
            .as_str()
            == handoff.device_key.canonical_public_jwk()?,
        "frozen registration holder key differs from durable handoff"
    );
    // Step 7.
    let registered = handoff
        .post_authorized(
            http,
            &format!("{coauth}/_arkret/gate/account/register"),
            GATE_REGISTER_OPERATION_ID,
            &register_body,
        )
        .await
        .context("register the principal identity")?;
    // Parsed into the model's type, not read field by field. The Station's
    // answer either is an `AccountRegisterOutcome` or it is not, and finding
    // out here beats finding out in whichever assertion happens to touch the
    // missing field first.
    let outcome: AccountRegisterOutcome = serde_json::from_value(registered.clone())
        .context("parse the identity-creation register outcome")?;
    let accepted_request: AccountRegisterRequestBody = serde_json::from_value(register_body)
        .context("parse the canonical frozen identity-creation request")?;
    garth::validate_identity_creation_outcome(&outcome, &accepted_request)
        .context("bind registration outcome to its canonical request")?;
    let grant = outcome
        .session_grant_outcome
        .as_ref()
        .context("register outcome carried no session grant")?;
    ensure!(
        grant.account_id.principal_id == accepted_request.principal_id
            && grant.account_id.station_id.as_str() == audience_id
            && grant.audience_id.as_str() == audience_id
            && grant.device_id.as_ref().map(|id| id.as_str()) == Some(device_id)
            && serde_json::to_value(&grant.session_public_key)?
                == json!(handoff.device_key.canonical_public_jwk()?)
            && grant.expires_at > chrono::Utc::now(),
        "initial grant does not match the accepted Account, Station, Device and session key"
    );

    verify_accepted_identity_material(
        http,
        coauth,
        station_base,
        &accepted_request,
        &outcome,
        &handoff.device_key,
    )
    .await
    .context("verify canonical registration authority receipts before retaining identity")?;

    let did = checkpoint
        .get("did")
        .and_then(Value::as_str)
        .context("checkpoint omitted the DID")?
        .to_owned();
    Ok(FoundedPrincipal {
        accepted_request,
        event_verification_method: format!("{did}#{device_id}"),
        did,
        device_id: device_id.to_owned(),
        recovery_key,
        checkpoint: checkpoint.clone(),
        outcome,
    })
}

/// Receipt signatures use complete method-native history at their issuance
/// coordinate. No grant or current DID document substitutes for that history.
async fn verify_accepted_identity_material(
    http: &reqwest::Client,
    coauth: &str,
    station: &str,
    request: &AccountRegisterRequestBody,
    outcome: &AccountRegisterOutcome,
    device_key: &FoundingDeviceKey,
) -> Result<()> {
    fn scoped_builder(
        base: &str,
        http: &reqwest::Client,
    ) -> Result<arkret_http_client::ClientBuilder> {
        let url = url::Url::parse(base)?;
        let mut builder =
            arkret_http_client::Client::builder(url.clone()).http_client(http.clone());
        if let Some(host) = url.host_str() {
            for namespace in ["local.host", "localhost", "127.0.0.1"] {
                if host == namespace || host.ends_with(&format!(".{namespace}")) {
                    builder = builder.loopback_service_discovery(
                        namespace,
                        url.port_or_known_default()
                            .context("deployment HTTPS port absent")?,
                    )?;
                    break;
                }
            }
        }
        Ok(builder)
    }
    struct CompleteHistory(arkret_models_identity::IdentityLogListOutcome);
    impl arkret_identity::AuthorityDidHistoryResolver for CompleteHistory {
        fn resolve_complete_history(
            &self,
            did: &arkret_wire::Did,
        ) -> std::result::Result<
            arkret_models_identity::IdentityLogListOutcome,
            arkret_identity::AuthorityHistoryUnavailable,
        > {
            if did != &self.0.did {
                return Err(arkret_identity::AuthorityHistoryUnavailable {
                    message: "authority DID mismatch".into(),
                });
            }
            Ok(self.0.clone())
        }
    }
    let receipt = &outcome.binding_receipt;
    let authority_did =
        arkret_identity::verification_method_did(receipt.proof.verification_method.as_str())?;
    let authority_log = arkret_identity::DidWebvhResolver::log_url(&authority_did)?;
    let registration = request
        .identity_creation
        .as_ref()
        .context("identity creation request absent")?;
    let grant = outcome
        .session_grant_outcome
        .as_ref()
        .context("initial grant absent")?;
    let commits = outcome
        .pcr_genesis_commits
        .as_ref()
        .context("accepted PCR genesis receipts absent")?;
    let founding_station_did = arkret_identity::verification_method_did(
        commits[0].signature.verification_method.as_str(),
    )?;
    // This canonical deployment's Account Authority is the owning Station;
    // Coauth serves the gate at its own origin while the Station hosts the
    // authority DID and assertionMethod. Bind both to the original frozen
    // holder proof and accepted PCR, never to an arbitrary response DID.
    ensure!(
        receipt.account_authority_id == grant.account_id.station_id
            && receipt.account_authority_id == registration.initial_session.audience_id
            && receipt.account_authority_id == registration.control_proof.audience_id
            && arkret_wire::project_did_to_core_id(&authority_did)? == receipt.account_authority_id
            && authority_did == founding_station_did
            && registration.control_proof.origin.as_str()
                == url::Url::parse(coauth)?.origin().ascii_serialization()
            && url::Url::parse(&authority_log)?.origin() == url::Url::parse(station)?.origin(),
        "binding receipt authority must match the frozen owning Station and gate source"
    );
    // Account Authority is an authority role, not a service-kind registry entry.
    // Fetch only its method-native files from the original Station HTTPS origin;
    // this transport has no account cookies, bearer grant, or DPoP credentials.
    let ca_path = std::env::var("COTEST_RUN_SCOPED_CA_PEM")
        .context("canonical receipt verification requires the run-scoped CA")?;
    let ca_pem = std::fs::read(ca_path)?;
    let discovery = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem)?)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .gzip(false)
        .build()?;
    async fn fetch_native_file(
        http: &reqwest::Client,
        url: &str,
        optional: bool,
    ) -> Result<Option<Vec<u8>>> {
        let mut response = http
            .get(url)
            .header("Accept-Encoding", "identity")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;
        if optional && response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.url().as_str() == url && response.status().is_success(),
            "native authority history fetch failed or changed its source"
        );
        ensure!(
            response
                .headers()
                .get("Content-Encoding")
                .is_none_or(|value| value.as_bytes() == b"identity"),
            "native authority history must use identity encoding"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= arkret_identity::DID_WEB_MAX_DOCUMENT_BYTES,
                "native authority history exceeds the SDK byte bound"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }
    let log_bytes = fetch_native_file(&discovery, &authority_log, false)
        .await?
        .context("complete authority native history absent")?;
    let witness_url = arkret_identity::DidWebvhResolver::witness_url(&authority_did)?;
    let witnesses = fetch_native_file(&discovery, &witness_url, true).await?;
    let log = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &authority_did,
        &log_bytes,
        witnesses.as_deref(),
    )?;
    let log_entries = log.log.raw_entries;
    arkret_identity::verify_account_binding_receipt_at_issuance(
        receipt,
        &CompleteHistory(arkret_models_identity::IdentityLogListOutcome {
            did: authority_did,
            method: arkret_models_identity::DidMethodUri::Webvh,
            native_history: Some(true),
            entries: log_entries,
            next_cursor: None,
            has_more: false,
        }),
    )?;

    for (event, commit) in registration.pcr_genesis_unit.events.iter().zip(commits) {
        ensure!(
            commit.event_ref == event.event_id && commit.realm_id == event.realm_id,
            "PCR receipt must bind the exact frozen founding Event and Realm"
        );
    }
    ensure!(
        grant.device_id.as_ref() == Some(&registration.initial_session.device_id)
            && grant.audience_id == registration.initial_session.audience_id
            && grant.session_public_key == registration.initial_session.session_public_key,
        "initial grant must bind the frozen SDK initial-session intent"
    );
    // A disk-restored locator cannot authorize sending the retained grant.
    // Resolve the original Commit signer's native route without credentials first.
    let station_did = arkret_identity::verification_method_did(
        commits[0].signature.verification_method.as_str(),
    )?;
    let station_resolution = scoped_builder(station, http)?
        .build()?
        .resolve_service_from_did(&station_did, arkret_wire::ServiceKind::Station)
        .await?;
    let route = station_resolution.projection()?;
    ensure!(
        route.service_id == grant.account_id.station_id
            && url::Url::parse(&route.base_url)?
                == url::Url::parse(&format!("{}/", station.trim_end_matches('/')))?,
        "retained Station locator differs from its authenticated native route"
    );
    let signer = std::sync::Arc::new(device_key.signing_key());
    let auth = arkret_http_client::Auth::Dpop(arkret_http_client::DpopAuth::with_dpop_token(
        grant.session_grant.clone(),
        move |request| {
            garth::session::dpop::build_http_dpop_proof(request, &signer)
                .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
        },
    ));
    let sdk = scoped_builder(station, http)?.auth(auth).build()?;
    let authority = garth::AuthorityClient::new(sdk);
    let nonce = arkret_wire::Base64UrlString::new(random_b64url("pcr_authority_nonce"))
        .map_err(anyhow::Error::msg)?;
    let bundle_request = arkret_wire::AuthorityBundleRequest {
        realm_id: registration.pcr_genesis_unit.create().realm_id.clone(),
        nonce: nonce.clone(),
    };
    let bundle = authority.resolve_authority(&bundle_request).await?;
    ensure!(
        bundle.genesis_event == *registration.pcr_genesis_unit.create(),
        "PCR authority bundle must contain the original frozen genesis Event"
    );
    let keys = garth::fetch_historical_station_keys_for_commits(
        authority.transport(),
        &bundle,
        &[&commits[0], &commits[1]],
    )
    .await?;
    let freshness = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce);
    let verified = arkret_identity::verify_realm_authority_bundle(&bundle, &freshness, &keys)?;
    for (event, commit) in registration.pcr_genesis_unit.events.iter().zip(commits) {
        verified.verify_committed_item(
            &arkret_wire::CommittedEventFullView {
                event: event.clone(),
                commit: commit.clone(),
            },
            &keys,
        )?;
    }
    Ok(())
}

impl AccountHandoff {
    /// POST a gate operation authorized by this handoff grant.
    ///
    /// `Authorization: DPoP <grant>` plus a proof over this exact method and
    /// URL, bound to the grant. Both halves are required; a proof without the
    /// token, or a token without a matching proof, is refused.
    async fn post_authorized(
        &self,
        http: &reqwest::Client,
        url: &str,
        operation_id: &str,
        body: &Value,
    ) -> Result<Value> {
        let request = arkret_http_client::DpopProofRequest::new("POST", url)
            .access_token(self.account_handoff_grant.clone());
        let proof =
            garth::session::dpop::build_http_dpop_proof(request, &self.device_key.signing_key)
                .map_err(|error| anyhow::anyhow!("build DPoP proof for POST {url}: {error}"))?;
        let response = http
            .post(url)
            .header("Arkret-Operation", operation_id)
            .header(
                "Authorization",
                format!("DPoP {}", self.account_handoff_grant),
            )
            .header("DPoP", proof)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = response.status();
        let text = response.text().await.context("read response body")?;
        if !status.is_success() {
            bail!("{url} returned {status}: {text}");
        }
        serde_json::from_str(&text).with_context(|| format!("parse response of {url}: {text}"))
    }
}
