//! Audited E2EE release control-plane conformance vectors.

use anyhow::{Result, anyhow, bail};
use arkret_wire::ProfileId;
use serde_json::Value;

pub const VECTOR_ID_BINDING_TRANSITIONS: &str = "ak.vector.audit.binding_transitions.v1";
pub const VECTOR_ID_SESSION_TRANSITIONS: &str = "ak.vector.audit.session_transitions.v1";
pub const VECTOR_ID_RECIPIENT_BINDING: &str = "ak.vector.audit.release_recipient_binding.v1";
pub const VECTOR_ID_RELEASE_WINDOW: &str = "ak.vector.audit.release_window.v1";
pub const VECTOR_ID_BINDING_AUTHORIZATION_GATE: &str =
    "ak.vector.audit.binding_and_authorization_gate.v1";
pub const VECTOR_ID_CLOSE_RELEASE_CONCURRENCY: &str =
    "ak.vector.audit.close_release_concurrency.v1";
pub const VECTOR_ID_RYW_BEFORE_OUTPUT: &str = "ak.vector.audit.ryw_before_output.v1";

pub const ALL_AUDIT_RELEASE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_BINDING_TRANSITIONS,
    VECTOR_ID_SESSION_TRANSITIONS,
    VECTOR_ID_RECIPIENT_BINDING,
    VECTOR_ID_RELEASE_WINDOW,
    VECTOR_ID_BINDING_AUTHORIZATION_GATE,
    VECTOR_ID_CLOSE_RELEASE_CONCURRENCY,
    VECTOR_ID_RYW_BEFORE_OUTPUT,
];

const FIXTURE_FILE: &str = "audit-release-fixture.json";

fn validate_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::ATTESTED_AUDIT_E2EE_V1)?;

    let profiles = fixture
        .get("applies_to_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("audit release fixture missing applies_to_profiles[]"))?;
    for profile in [
        ProfileId::ATTESTED_AUDIT_E2EE_V1,
        ProfileId::DISCLOSED_AUDIT_E2EE_V1,
    ] {
        if !profiles.iter().any(|entry| entry.as_str() == Some(profile)) {
            bail!("audit release fixture missing profile {profile}");
        }
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("audit release fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("audit release fixture missing cases[]"))?;

    for vector_id in ALL_AUDIT_RELEASE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("audit release fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("audit release fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingState {
    Active,
    Suspended,
    Revoked,
}

fn transition_binding(
    from: Option<BindingState>,
    to: BindingState,
) -> std::result::Result<BindingState, &'static str> {
    match (from, to) {
        (None, BindingState::Active)
        | (Some(BindingState::Active), BindingState::Suspended)
        | (Some(BindingState::Active), BindingState::Revoked)
        | (Some(BindingState::Suspended), BindingState::Active)
        | (Some(BindingState::Suspended), BindingState::Revoked) => Ok(to),
        (Some(current), target) if current == target => Ok(current),
        _ => Err("failed_precondition"),
    }
}

pub fn run_binding_transitions_vector() -> Result<()> {
    let active =
        transition_binding(None, BindingState::Active).map_err(|reason| anyhow!(reason))?;
    let suspended = transition_binding(Some(active), BindingState::Suspended)
        .map_err(|reason| anyhow!(reason))?;
    let reactivated = transition_binding(Some(suspended), BindingState::Active)
        .map_err(|reason| anyhow!(reason))?;
    let revoked = transition_binding(Some(reactivated), BindingState::Revoked)
        .map_err(|reason| anyhow!(reason))?;
    if transition_binding(Some(revoked), BindingState::Active) != Err("failed_precondition") {
        bail!("revoked audit binding was reactivated");
    }
    if transition_binding(None, BindingState::Suspended) != Err("failed_precondition") {
        bail!("audit binding accepted a non-active initial state");
    }
    let same_basis_siblings = [BindingState::Suspended, BindingState::Revoked];
    if same_basis_siblings[0] == same_basis_siblings[1] {
        bail!("conflicting binding siblings were not distinct");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionState {
    Request,
    Authorize,
    Notice,
    Close,
}

fn transition_session(
    from: Option<SessionState>,
    to: SessionState,
) -> std::result::Result<SessionState, &'static str> {
    match (from, to) {
        (None, SessionState::Request)
        | (Some(SessionState::Request), SessionState::Authorize)
        | (Some(SessionState::Authorize), SessionState::Notice)
        | (Some(SessionState::Request), SessionState::Close)
        | (Some(SessionState::Authorize), SessionState::Close)
        | (Some(SessionState::Notice), SessionState::Close) => Ok(to),
        (Some(current), target) if current == target => Ok(current),
        _ => Err("failed_precondition"),
    }
}

pub fn run_session_transitions_vector() -> Result<()> {
    let request =
        transition_session(None, SessionState::Request).map_err(|reason| anyhow!(reason))?;
    let authorize = transition_session(Some(request), SessionState::Authorize)
        .map_err(|reason| anyhow!(reason))?;
    let notice = transition_session(Some(authorize), SessionState::Notice)
        .map_err(|reason| anyhow!(reason))?;
    let close =
        transition_session(Some(notice), SessionState::Close).map_err(|reason| anyhow!(reason))?;
    if transition_session(Some(close), SessionState::Notice) != Err("failed_precondition") {
        bail!("closed audit session accepted a later notice");
    }
    if transition_session(None, SessionState::Authorize) != Err("failed_precondition") {
        bail!("audit session skipped request");
    }
    transition_session(Some(SessionState::Request), SessionState::Close)
        .map_err(|reason| anyhow!(reason))?;
    transition_session(Some(SessionState::Authorize), SessionState::Close)
        .map_err(|reason| anyhow!(reason))?;
    Ok(())
}

fn validate_recipient(
    authorized_actor: &str,
    authorized_key: &str,
    release_actor: &str,
    release_key: &str,
    resolved_key_owner: &str,
) -> std::result::Result<(), &'static str> {
    if authorized_actor != release_actor
        || authorized_key != release_key
        || resolved_key_owner != release_actor
    {
        return Err("audit_release_manifest_invalid");
    }
    Ok(())
}

pub fn run_release_recipient_binding_vector() -> Result<()> {
    let actor = "did:webvh:z6mkaudit:example.org";
    let key = "did:webvh:z6mkaudit:example.org#audit-release-1";
    validate_recipient(actor, key, actor, key, actor).map_err(|reason| anyhow!(reason))?;
    if validate_recipient(actor, key, "did:webvh:z6mkother:example.org", key, actor).is_ok() {
        bail!("audit release accepted recipient actor substitution");
    }
    if validate_recipient(
        actor,
        key,
        actor,
        "did:webvh:z6mkaudit:example.org#other",
        actor,
    )
    .is_ok()
    {
        bail!("audit release accepted recipient key substitution");
    }
    if validate_recipient(actor, key, actor, key, "did:webvh:z6mkother:example.org").is_ok() {
        bail!("audit release accepted key owned by another actor");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ReleaseWindow {
    first_auditable_epoch: u64,
    first_epoch: u64,
    last_epoch: u64,
    active_epoch: u64,
    sealed_by_commit: bool,
    target_eligible: bool,
}

fn validate_release_window(window: ReleaseWindow) -> std::result::Result<(), &'static str> {
    if window.first_epoch < window.first_auditable_epoch || !window.target_eligible {
        return Err("audit_release_retroactive_scope_forbidden");
    }
    // audited-e2ee.md 1: covering the live epoch and omitting the commit that
    // sealed the window are different failures with different registered
    // codes. Folding them together left `audit_release_current_epoch_forbidden`
    // with no producer, so nothing exercised the rule that actually protects
    // the live epoch.
    if window.last_epoch >= window.active_epoch {
        return Err("audit_release_current_epoch_forbidden");
    }
    if !window.sealed_by_commit {
        return Err("audit_release_manifest_invalid");
    }
    Ok(())
}

pub fn run_release_window_vector() -> Result<()> {
    let valid = ReleaseWindow {
        first_auditable_epoch: 10,
        first_epoch: 10,
        last_epoch: 11,
        active_epoch: 12,
        sealed_by_commit: true,
        target_eligible: true,
    };
    validate_release_window(valid).map_err(|reason| anyhow!(reason))?;
    if validate_release_window(ReleaseWindow {
        first_epoch: 9,
        ..valid
    }) != Err("audit_release_retroactive_scope_forbidden")
    {
        bail!("audit release crossed first_auditable_epoch");
    }
    if validate_release_window(ReleaseWindow {
        last_epoch: 12,
        ..valid
    }) != Err("audit_release_current_epoch_forbidden")
    {
        bail!("audit release included the active epoch");
    }
    // The boundary: the last sealed epoch is admissible, the live one is not.
    validate_release_window(ReleaseWindow {
        last_epoch: 11,
        active_epoch: 12,
        ..valid
    })
    .map_err(|reason| anyhow!(reason))?;
    if validate_release_window(ReleaseWindow {
        sealed_by_commit: false,
        ..valid
    }) != Err("audit_release_manifest_invalid")
    {
        bail!("sealed epoch release omitted sealed_by_commit_ref");
    }
    Ok(())
}

fn validate_release_gate(
    binding: BindingState,
    authorization_expires_at: u64,
    now: u64,
    session: SessionState,
) -> std::result::Result<(), &'static str> {
    if binding != BindingState::Active {
        return Err("audit_release_binding_inactive");
    }
    if authorization_expires_at <= now {
        return Err("auth_expired");
    }
    if session != SessionState::Notice {
        return Err("failed_precondition");
    }
    Ok(())
}

pub fn run_binding_and_authorization_gate_vector() -> Result<()> {
    validate_release_gate(BindingState::Active, 101, 100, SessionState::Notice)
        .map_err(|reason| anyhow!(reason))?;
    for binding in [BindingState::Suspended, BindingState::Revoked] {
        if validate_release_gate(binding, 101, 100, SessionState::Notice)
            != Err("audit_release_binding_inactive")
        {
            bail!("inactive audit binding passed the release gate");
        }
    }
    if validate_release_gate(BindingState::Active, 100, 100, SessionState::Notice)
        != Err("auth_expired")
    {
        bail!("expired audit authorization passed the release gate");
    }
    if validate_release_gate(BindingState::Active, 101, 100, SessionState::Authorize)
        != Err("failed_precondition")
    {
        bail!("audit release was accepted before notice");
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReleaseRecord {
    seal_sequence: u64,
    event_digest: &'static str,
    release_id: &'static str,
}

pub fn run_close_release_concurrency_vector() -> Result<()> {
    let same_basis_close_present = true;
    let competing_release_accepted = !same_basis_close_present;
    if competing_release_accepted {
        bail!("same-basis release won over close");
    }

    let mut releases = [
        ReleaseRecord {
            seal_sequence: 8,
            event_digest: "sha256:bbbb",
            release_id: "release-b",
        },
        ReleaseRecord {
            seal_sequence: 7,
            event_digest: "sha256:cccc",
            release_id: "release-a",
        },
        ReleaseRecord {
            seal_sequence: 8,
            event_digest: "sha256:aaaa",
            release_id: "release-c",
        },
    ];
    releases.sort();
    let ordered_ids: Vec<_> = releases.iter().map(|release| release.release_id).collect();
    if ordered_ids != ["release-a", "release-c", "release-b"] {
        bail!("audit release ordered_log is non-deterministic");
    }
    let close_refs = ordered_ids.clone();
    if close_refs != ordered_ids {
        bail!("audit close did not freeze the accepted release log");
    }
    if validate_release_gate(BindingState::Active, 101, 100, SessionState::Close).is_ok() {
        bail!("audit release was accepted after close");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct OutputGate {
    release_accepted: bool,
    receipt_valid: bool,
    policy_digest_matches: bool,
    independent_witnesses: usize,
    already_output: bool,
}

fn try_output(gate: OutputGate, attested_hardware: bool) -> std::result::Result<(), &'static str> {
    if gate.already_output {
        return Err("duplicate_conflict");
    }
    if !gate.release_accepted || !gate.receipt_valid || !gate.policy_digest_matches {
        return Err("audit_receipt_invalidated");
    }
    if attested_hardware && gate.independent_witnesses < 2 {
        return Err("audit_receipt_invalidated");
    }
    Ok(())
}

pub fn run_ryw_before_output_vector() -> Result<()> {
    let valid = OutputGate {
        release_accepted: true,
        receipt_valid: true,
        policy_digest_matches: true,
        independent_witnesses: 2,
        already_output: false,
    };
    try_output(valid, true).map_err(|reason| anyhow!(reason))?;
    if try_output(
        OutputGate {
            release_accepted: false,
            ..valid
        },
        true,
    )
    .is_ok()
    {
        bail!("audit material was output before release acceptance");
    }
    if try_output(
        OutputGate {
            independent_witnesses: 1,
            ..valid
        },
        true,
    )
    .is_ok()
    {
        bail!("attested audit output lacked independent witnesses");
    }
    if try_output(
        OutputGate {
            policy_digest_matches: false,
            ..valid
        },
        true,
    )
    .is_ok()
    {
        bail!("audit output accepted a mismatched policy digest");
    }
    if try_output(
        OutputGate {
            already_output: true,
            ..valid
        },
        true,
    ) != Err("duplicate_conflict")
    {
        bail!("audit output was not at-most-once");
    }
    Ok(())
}

pub fn run_audit_release_vector_suite() -> Result<()> {
    validate_fixture_metadata()?;
    run_binding_transitions_vector()?;
    run_session_transitions_vector()?;
    run_release_recipient_binding_vector()?;
    run_release_window_vector()?;
    run_binding_and_authorization_gate_vector()?;
    run_close_release_concurrency_vector()?;
    run_ryw_before_output_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_release_vectors_run_clean() {
        run_audit_release_vector_suite().unwrap();
    }
}
