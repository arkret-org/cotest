//! Executable WebRTC plaintext-media downgrade conformance suite.
//!
//! This drives Inkson's production `join_call_media` authorization object.
//! The same opaque authorization gates token exchange and the single
//! MLS-exporter-backed frame-key publication point; this is not a fixture
//! reference implementation.

use std::cell::Cell;

use anyhow::{Result, ensure};
use arkret_crypto::sframe::MlsExporterSource;
use inkson::media::rtc::{
    DesiredMedia, MediaGovernanceEvidence, MediaJoinRequest, RtcClientError, authorize_media_join,
};

use super::{
    CaseExecutionResult, SuiteExecutionResult, fixture_runner_entrypoint, load_fixture_value,
    required_field, required_str, value_array,
};

const FIXTURE: &str = "webrtc-media-plaintext-fixture.json";
pub const WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT: &str = "ak.suite.webrtc.media_plaintext_downgrade.v1";
const PARTICIPANT_ID: &str = "ak:rtc_participant:00000000-0000-7000-8000-000000000001";

struct CountingExporter {
    calls: Cell<usize>,
}

impl CountingExporter {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl MlsExporterSource for CountingExporter {
    fn export_secret(
        &self,
        _label: &str,
        _context: &[u8],
        length: usize,
    ) -> arkret_crypto::Result<zeroize::Zeroizing<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        Ok(zeroize::Zeroizing::new(vec![0xa5; length]))
    }
}

pub fn run_webrtc_media_plaintext_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture_runner_entrypoint(&fixture)? == WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT,
        "WebRTC plaintext-media entrypoint drifted"
    );
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    ensure!(
        cases.len() == 5,
        "WebRTC plaintext-media suite must have five cases"
    );

    let exporter = CountingExporter::new();
    let mut results = Vec::with_capacity(cases.len());

    assert_case_contract(
        &cases[0],
        "realm_policy_has_not_authorized_media_decryption",
        "reject",
        Some("media_plaintext_service_not_authorised"),
    )?;
    let missing_policy = media_join_request(false, true, true)?;
    assert_rejection(
        &missing_policy,
        &exporter,
        RtcClientError::MediaPlaintextServiceNotAuthorised,
    )?;
    results.push(case_result(&cases[0], 3)?);

    assert_case_contract(
        &cases[1],
        "sfu_service_did_absent_from_plaintext_visible_services",
        "reject",
        Some("media_plaintext_service_not_authorised"),
    )?;
    let missing_allowlist = media_join_request(true, false, true)?;
    assert_rejection(
        &missing_allowlist,
        &exporter,
        RtcClientError::MediaPlaintextServiceNotAuthorised,
    )?;
    results.push(case_result(&cases[1], 3)?);

    assert_case_contract(
        &cases[2],
        "the_required_plaintext_warning_was_not_shown",
        "reject",
        Some("media_plaintext_warning_required"),
    )?;
    let missing_warning = media_join_request(true, true, false)?;
    assert_rejection(
        &missing_warning,
        &exporter,
        RtcClientError::MediaPlaintextWarningRequired,
    )?;
    results.push(case_result(&cases[2], 3)?);

    assert_case_contract(
        &cases[3],
        "no_media_key_is_published_on_any_of_the_three_refusals",
        "accept",
        None,
    )?;
    ensure!(
        exporter.calls() == 0,
        "a refused join reached the media-key exporter"
    );
    results.push(case_result(&cases[3], 3)?);

    assert_case_contract(
        &cases[4],
        "a_fully_authorized_join_publishes_the_media_key",
        "accept",
        None,
    )?;
    let authorized = media_join_request(true, true, true)?;
    let permit = authorize_media_join(&authorized)?;
    let key = permit.publish_frame_key(&exporter, PARTICIPANT_ID)?;
    ensure!(
        key.len() == 32,
        "authorized media frame key is not 32 bytes"
    );
    ensure!(
        exporter.calls() == 1,
        "authorized join did not publish exactly one media key"
    );
    results.push(case_result(&cases[4], 3)?);

    let execution = SuiteExecutionResult {
        entrypoint: WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}

fn assert_rejection(
    request: &MediaJoinRequest,
    exporter: &CountingExporter,
    expected: RtcClientError,
) -> Result<()> {
    let calls_before = exporter.calls();
    let actual = match authorize_media_join(request) {
        Ok(_) => anyhow::bail!("decrypting media join unexpectedly passed its governance gate"),
        Err(error) => error,
    };
    ensure!(
        actual == expected,
        "wrong media join refusal: {}",
        actual.as_wire()
    );
    ensure!(
        exporter.calls() == calls_before,
        "refused media join published a frame key"
    );
    Ok(())
}

fn media_join_request(
    policy_authorized: bool,
    service_allowlisted: bool,
    warning_acknowledged: bool,
) -> Result<MediaJoinRequest> {
    let realm_id = arkret_sdk::RealmId::new(
        "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned(),
    )?;
    let governance_binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
        realm_id,
        Some(arkret_sdk::EventId::from_digest([0x42; 32])),
        6,
        7,
        3,
    )?;
    let policy_bundle_payload = Some(serde_json::json!({
        "policy_revision": 3,
        "media_service_decrypts": policy_authorized
    }));
    let media_service_id = arkret_sdk::DidCoreId::new("ak:did_core:web:media.example".to_owned())?;
    let plaintext_visible_services_payload = service_allowlisted.then(|| {
        arkret_sdk::PlaintextVisibleServicesPayload::new(vec![
            arkret_sdk::PlaintextVisibleService::new(
                media_service_id,
                "media_service",
                vec![arkret_sdk::PlaintextDataClassKind::MediaPlaintext],
                vec!["video_transcoding".to_owned()],
                arkret_sdk::PlaintextServiceVisibility::PrivatePlaintext,
            ),
        ])
    });
    Ok(MediaJoinRequest {
        realm_id: "ak:realm:AVxu7KCm9qmiOqakDKBXUia9rbZ3NBurP875XbqG1rbs".to_owned(),
        call_id: "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz".to_owned(),
        actor_id: "ak:did_core:web:alice.example".to_owned(),
        device_id: "ak:device:01904100-0000-7000-8000-000000000005".to_owned(),
        focus_id: "fra-1".to_owned(),
        epoch_id: 7,
        desired_media: DesiredMedia::audio_video(),
        media_service_ids: vec!["ak:did_core:web:media.example".to_owned()],
        verified_media_routes: Vec::new(),
        governance_evidence: Some(MediaGovernanceEvidence {
            governance_binding,
            media_service_payload: serde_json::json!({
                "service_id": "ak:did_core:web:media.example",
                "foci": [{
                    "focus_id": "fra-1",
                    "focus_kind": "livekit",
                    "token_endpoint": "https://media.example/_arkret/self/rtc/token",
                    "connect_url": "wss://media.example/livekit"
                }]
            }),
            policy_bundle_payload,
            plaintext_visible_services_payload,
            media_plaintext_ui_confirmed: warning_acknowledged,
        }),
        media_service_decryption_requested: true,
    })
}

fn assert_case_contract(
    case: &serde_json::Value,
    name: &str,
    decision: &str,
    reason: Option<&str>,
) -> Result<()> {
    ensure!(
        required_str(case, "name")? == name,
        "fixture case order drifted"
    );
    ensure!(
        required_str(case, "decision")? == decision,
        "{name}: fixture decision drifted"
    );
    ensure!(
        case.get("reason").and_then(serde_json::Value::as_str) == reason,
        "{name}: fixture reason drifted"
    );
    Ok(())
}

fn case_result(case: &serde_json::Value, assertions: usize) -> Result<CaseExecutionResult> {
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions,
    })
}
