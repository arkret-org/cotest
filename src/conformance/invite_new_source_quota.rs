//! `ak.suite.invite.new_source_quota.v1` -- the executable runner for the
//! canonical per-holder new-source quota fixture.
//!
//! The fixture is the single normative source for both
//! `ak.vector.invite.new_source_quota_holder_admission.v1` and
//! `ak.vector.invite.new_source_quota_effective_bounds.v1`. Nothing here
//! invents an input or an expected outcome: the effective-value cases are
//! executed through the shared SDK carrier, and the admission timelines are
//! replayed through a reference model of `consent-model.md` sections 6.1.1.1
//! to 6.1.1.4, then compared with the decisions the fixture declares.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use arkret_wire::receive_policy::{
    EffectiveNewSourceQuota, NewSourceQuotaConstraints, NewSourceQuotaOverride,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::load_fixture;

pub const INVITE_NEW_SOURCE_QUOTA_FIXTURE: &str = "invite-new-source-quota-fixture.json";

const SUITE: &str = "invite_new_source_quota";
const ENTRYPOINT: &str = "ak.suite.invite.new_source_quota.v1";
pub const VECTOR_ID_NEW_SOURCE_QUOTA_HOLDER_ADMISSION: &str =
    "ak.vector.invite.new_source_quota_holder_admission.v1";
pub const VECTOR_ID_NEW_SOURCE_QUOTA_EFFECTIVE_BOUNDS: &str =
    "ak.vector.invite.new_source_quota_effective_bounds.v1";

/// Closed set of ledger identity-key components. `source_id` is deliberately
/// absent: it is the authenticated transport source service DID, and charging
/// by Station would both punish a whole Station collectively and let a
/// harasser bypass the ceiling by switching Stations (section 6.1.1.2).
const IDENTITY_KEY_COMPONENTS: [&str; 2] = ["holder_account_id", "source_peer_principal_id"];

const REQUIRED_EFFECTIVE_BOUNDS_CASES: [&str; 10] = [
    "holder_override_above_deployment_max_is_clamped",
    "holder_override_below_default_narrows",
    "holder_zero_override_is_legal_and_narrows_to_zero",
    "max_below_default_rejects_the_whole_constraints_object",
    "max_retention_below_default_retention_rejects_the_whole_constraints_object",
    "omitted_constraints_object_takes_specification_defaults",
    "omitted_members_take_specification_defaults",
    "partial_holder_override_takes_the_deployment_default_for_the_omitted_member",
    "retention_shorter_than_window_rejects_the_whole_constraints_object",
    "zero_deployment_member_rejects_the_whole_constraints_object",
];

const REQUIRED_ADMISSION_CASES: [&str; 10] = [
    "deduplicated_replay_is_not_evaluated",
    "denied_source_is_not_ledgered_and_stays_new_next_window",
    "require_explicit_consent_profile_has_no_quarantine_face",
    "retention_ceiling_denies_even_with_short_window_room",
    "retention_prune_frees_the_long_window",
    "seen_source_is_enqueued_without_recharge_or_refresh",
    "short_window_ceiling_admits_then_drops_while_a_charged_source_still_enters",
    "sliding_short_window_readmits_after_the_window_passes",
    "window_and_retention_boundaries_are_exact",
    "zero_holder_override_locks_the_inbox",
];

const REQUIRED_IDENTITY_KEY_CASES: [&str; 3] = [
    "holder_dimension_is_the_complete_account_id",
    "source_dimension_is_the_peer_principal_not_the_transport_source",
    "two_peers_behind_one_transport_source_stay_distinct",
];

const REQUIRED_CONCURRENCY_CASES: [&str; 2] = [
    "concurrent_distinct_first_contacts_cannot_overshoot",
    "concurrent_first_contacts_from_one_source_charge_exactly_once",
];

/// The five-way equivalence class of section 6.1.1. A quota drop is one member
/// of it, which is why no assertion in this suite may read the requester side.
const INDISTINGUISHABLE_EQUIVALENCE_CLASS: [&str; 5] = [
    "admitted_to_quarantine",
    "new_source_quota_drop",
    "ttl_drop",
    "holder_absent",
    "holder_policy_deny",
];

const FORBIDDEN_SIGNALS: [&str; 4] = [
    "http_429",
    "retry_after_header",
    "rate_limited_error",
    "cached_drop_outcome",
];

const CONVERGING_SURFACE_OPERATION_IDS: [&str; 3] = [
    "ak.peer.invites.command.submit.v1",
    "ak.peer.contacts.command.submit.v1",
    "ak.self.consent.command.request.v1",
];

#[derive(Debug, Deserialize)]
struct Fixture {
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    specification_defaults: SpecificationDefaults,
    principals: Principals,
    deployment_constraints_profiles: BTreeMap<String, NewSourceQuotaConstraints>,
    effective_bounds_cases: Vec<EffectiveBoundsCase>,
    identity_key_cases: Vec<IdentityKeyCase>,
    admission_cases: Vec<AdmissionCase>,
    concurrency_cases: Vec<ConcurrencyCase>,
    chokepoint_contract: ChokepointContract,
    ledger_contract: LedgerContract,
    opaque_outcome_contract: OpaqueOutcomeContract,
    minimum_independent_runners: u32,
}

#[derive(Debug, Deserialize)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
struct SpecificationDefaults {
    window_seconds: u64,
    default_new_sources_per_window: u64,
    max_new_sources_per_window: u64,
    retention_seconds: u64,
    default_new_sources_per_retention: u64,
    max_new_sources_per_retention: u64,
}

#[derive(Debug, Deserialize)]
struct Principals {
    holder: AccountRef,
    holder_same_principal_other_station: AccountRef,
    sources: BTreeMap<String, String>,
    transport_sources: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AccountRef {
    principal_id: String,
    station_id: String,
}

#[derive(Debug, Deserialize)]
struct EffectiveBoundsCase {
    name: String,
    deployment_constraints: Option<NewSourceQuotaConstraints>,
    holder_override: Option<NewSourceQuotaOverride>,
    expected: EffectiveBoundsExpectation,
    invariants: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EffectiveBoundsExpectation {
    decision: String,
    effective: Option<ExpectedEffective>,
    error: Option<String>,
    partial_member_evaluation: Option<bool>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ExpectedEffective {
    window_seconds: u64,
    new_sources_per_window: u64,
    retention_seconds: u64,
    new_sources_per_retention: u64,
}

#[derive(Debug, Deserialize)]
struct IdentityKeyCase {
    name: String,
    left: IdentityKeyOperand,
    right: IdentityKeyOperand,
    expected: IdentityKeyExpectation,
    invariants: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct IdentityKeyOperand {
    holder: String,
    source_peer_principal_id: String,
    source_id: String,
}

#[derive(Debug, Deserialize)]
struct IdentityKeyExpectation {
    same_ledger_key: bool,
}

#[derive(Debug, Deserialize)]
struct AdmissionCase {
    name: String,
    deployment_constraints_profile: String,
    holder_override: Option<NewSourceQuotaOverride>,
    consent_profile: ConsentProfile,
    initial_ledger: Vec<LedgerRow>,
    initial_quarantine_entry_sources: Vec<String>,
    contacts: Vec<Contact>,
    expected: AdmissionExpectation,
    invariants: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConsentProfile {
    Default,
    RequireExplicitConsent,
}

#[derive(Debug, Deserialize)]
struct LedgerRow {
    source: String,
    first_admitted_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct Contact {
    at: DateTime<Utc>,
    source: String,
    #[serde(default)]
    deduplicated_replay: bool,
    expected_decision: Decision,
}

/// Decision the admission chokepoint reaches for one contact
/// (`consent-model.md` section 6.1.1.3). `NotEvaluated` covers the two paths
/// that never reach the chokepoint at all: a deduplicated replay and the
/// `require_explicit_consent` profile, which has no quarantine surface.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Admitted,
    Seen,
    Denied,
    NotEvaluated,
}

#[derive(Debug, Deserialize)]
struct AdmissionExpectation {
    final_ledger: Vec<LedgerRow>,
    quarantine_entry_sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ConcurrencyCase {
    name: String,
    deployment_constraints_profile: String,
    holder_override: Option<NewSourceQuotaOverride>,
    initial_ledger: Vec<LedgerRow>,
    concurrent_contacts: Vec<ConcurrentContact>,
    expected: ConcurrencyExpectation,
    invariants: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ConcurrentContact {
    at: DateTime<Utc>,
    source: String,
}

#[derive(Debug, Deserialize)]
struct ConcurrencyExpectation {
    admitted_count: usize,
    seen_count: usize,
    denied_count: usize,
    final_ledger_size: usize,
    identical_in_every_interleaving: bool,
    distinguishable_error_returned: bool,
}

#[derive(Debug, Deserialize)]
struct ChokepointContract {
    converging_surface_operation_ids: Vec<String>,
    evaluated_exactly_once_before_cell_cas_write: bool,
    reevaluated_inside_cell_cas_retry_loop: bool,
    cas_retry_exhaustion_refunds_the_charge: bool,
    substitutable_by_generic_endpoint_rate_limit: bool,
    substitutable_by_directory_psi_device_quota: bool,
    substitutable_by_private_configuration: bool,
}

#[derive(Debug, Deserialize)]
struct LedgerContract {
    identity_key: Vec<String>,
    row_fields: Vec<String>,
    source_id_participates_in_identity_key: bool,
    wire_readable: bool,
    is_account_data_cell: bool,
    holder_observable_surface: String,
    source_column_storage: String,
    retention_seconds_is_both_ledger_lifetime_and_long_window: bool,
    account_erasure_deletes_the_whole_ledger: bool,
    consent_revoke_touches_the_ledger: bool,
    source_allow_or_deny_list_change_touches_the_ledger: bool,
    audit_persists_dropped_source_did: bool,
}

#[derive(Debug, Deserialize)]
struct OpaqueOutcomeContract {
    wire_status: String,
    disclosed_outcome_present: bool,
    indistinguishable_equivalence_class: Vec<String>,
    forbidden_signals: Vec<String>,
    disclosed_outcome_enum: Vec<String>,
}

/// One admission timeline lifted out of the canonical fixture so a live
/// deployment can replay it instead of restating its own numbers.
#[derive(Clone, Debug)]
pub struct CanonicalAdmissionCase {
    pub name: String,
    pub deployment_constraints: NewSourceQuotaConstraints,
    pub holder_override: Option<NewSourceQuotaOverride>,
    pub contacts: Vec<CanonicalContact>,
    /// Source aliases of the holder's quarantine entries, oldest first, after
    /// the whole timeline has been replayed.
    pub quarantine_entry_sources: Vec<String>,
    /// True when the timeline starts from an empty ledger and an empty cell,
    /// which is the precondition for replaying it against a fresh live holder.
    pub starts_from_empty_state: bool,
}

#[derive(Clone, Debug)]
pub struct CanonicalContact {
    pub source: String,
    pub expected_decision: Decision,
}

impl CanonicalAdmissionCase {
    /// Deployment ceiling as the Station environment declares it. The values
    /// come from the fixture, so a live scenario cannot drift from the
    /// canonical vector by editing its own constants.
    pub fn deployment_environment(&self) -> Vec<(&'static str, String)> {
        let constraints = &self.deployment_constraints;
        [
            (
                "SOLAND_RECEIVE_POLICY_NEW_SOURCE_WINDOW_SECONDS",
                constraints
                    .window_seconds
                    .unwrap_or(NewSourceQuotaConstraints::DEFAULT_WINDOW_SECONDS),
            ),
            (
                "SOLAND_RECEIVE_POLICY_NEW_SOURCE_DEFAULT_PER_WINDOW",
                constraints
                    .default_new_sources_per_window
                    .unwrap_or(NewSourceQuotaConstraints::DEFAULT_NEW_SOURCES_PER_WINDOW),
            ),
            (
                "SOLAND_RECEIVE_POLICY_NEW_SOURCE_MAX_PER_WINDOW",
                constraints
                    .max_new_sources_per_window
                    .unwrap_or(NewSourceQuotaConstraints::MAX_NEW_SOURCES_PER_WINDOW),
            ),
            (
                "SOLAND_RECEIVE_POLICY_NEW_SOURCE_RETENTION_SECONDS",
                constraints
                    .retention_seconds
                    .unwrap_or(NewSourceQuotaConstraints::DEFAULT_RETENTION_SECONDS),
            ),
            (
                "SOLAND_RECEIVE_POLICY_NEW_SOURCE_DEFAULT_PER_RETENTION",
                constraints
                    .default_new_sources_per_retention
                    .unwrap_or(NewSourceQuotaConstraints::DEFAULT_NEW_SOURCES_PER_RETENTION),
            ),
            (
                "SOLAND_RECEIVE_POLICY_NEW_SOURCE_MAX_PER_RETENTION",
                constraints
                    .max_new_sources_per_retention
                    .unwrap_or(NewSourceQuotaConstraints::MAX_NEW_SOURCES_PER_RETENTION),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect()
    }

    /// Quarantine entry sources expected after the first `count` contacts.
    pub fn quarantine_entry_sources_after(&self, count: usize) -> Vec<String> {
        self.contacts
            .iter()
            .take(count)
            .filter(|contact| {
                matches!(
                    contact.expected_decision,
                    Decision::Admitted | Decision::Seen
                )
            })
            .map(|contact| contact.source.clone())
            .collect()
    }
}

/// Read one admission timeline out of the canonical fixture.
pub fn canonical_admission_case(name: &str) -> Result<CanonicalAdmissionCase> {
    let fixture: Fixture = load_fixture(INVITE_NEW_SOURCE_QUOTA_FIXTURE)?;
    let case = fixture
        .admission_cases
        .iter()
        .find(|case| case.name == name)
        .with_context(|| format!("canonical fixture has no admission case {name}"))?;
    let deployment_constraints = fixture
        .deployment_constraints_profiles
        .get(&case.deployment_constraints_profile)
        .with_context(|| {
            format!(
                "unknown deployment constraints profile {}",
                case.deployment_constraints_profile
            )
        })?
        .clone();
    Ok(CanonicalAdmissionCase {
        name: case.name.clone(),
        deployment_constraints,
        holder_override: case.holder_override.clone(),
        contacts: case
            .contacts
            .iter()
            .map(|contact| CanonicalContact {
                source: contact.source.clone(),
                expected_decision: contact.expected_decision,
            })
            .collect(),
        quarantine_entry_sources: case.expected.quarantine_entry_sources.clone(),
        starts_from_empty_state: case.initial_ledger.is_empty()
            && case.initial_quarantine_entry_sources.is_empty(),
    })
}

pub fn run_invite_new_source_quota_suite() -> Result<()> {
    let fixture: Fixture = load_fixture(INVITE_NEW_SOURCE_QUOTA_FIXTURE)?;

    ensure!(
        fixture.suite == SUITE
            && fixture.runner.kind == "named_suite"
            && fixture.runner.entrypoint == ENTRYPOINT,
        "invite new-source quota fixture identity drifted"
    );
    ensure!(
        fixture.covers_vectors
            == vec![
                VECTOR_ID_NEW_SOURCE_QUOTA_HOLDER_ADMISSION.to_owned(),
                VECTOR_ID_NEW_SOURCE_QUOTA_EFFECTIVE_BOUNDS.to_owned(),
            ],
        "the fixture must stay the canonical evidence for exactly both registry vectors"
    );
    ensure!(
        fixture.minimum_independent_runners >= 2,
        "an artifact-driven certification vector needs at least two independent runners"
    );

    check_specification_defaults(&fixture.specification_defaults)?;
    run_effective_bounds_cases(&fixture)?;
    run_identity_key_cases(&fixture)?;
    run_admission_cases(&fixture)?;
    run_concurrency_cases(&fixture)?;
    check_chokepoint_contract(&fixture.chokepoint_contract)?;
    check_ledger_contract(&fixture.ledger_contract)?;
    check_opaque_outcome_contract(&fixture.opaque_outcome_contract)
}

/// The fixture restates the six specification defaults so the timelines read
/// standalone. They MUST be the shared SDK carrier's values, or the fixture
/// would become a second, drifting source for them.
fn check_specification_defaults(defaults: &SpecificationDefaults) -> Result<()> {
    ensure!(
        defaults.window_seconds == NewSourceQuotaConstraints::DEFAULT_WINDOW_SECONDS
            && defaults.default_new_sources_per_window
                == NewSourceQuotaConstraints::DEFAULT_NEW_SOURCES_PER_WINDOW
            && defaults.max_new_sources_per_window
                == NewSourceQuotaConstraints::MAX_NEW_SOURCES_PER_WINDOW
            && defaults.retention_seconds == NewSourceQuotaConstraints::DEFAULT_RETENTION_SECONDS
            && defaults.default_new_sources_per_retention
                == NewSourceQuotaConstraints::DEFAULT_NEW_SOURCES_PER_RETENTION
            && defaults.max_new_sources_per_retention
                == NewSourceQuotaConstraints::MAX_NEW_SOURCES_PER_RETENTION,
        "fixture specification_defaults drifted from the shared receive-policy carrier"
    );
    Ok(())
}

fn run_effective_bounds_cases(fixture: &Fixture) -> Result<()> {
    check_closed_case_set(
        "effective_bounds_cases",
        fixture
            .effective_bounds_cases
            .iter()
            .map(|case| case.name.as_str()),
        &REQUIRED_EFFECTIVE_BOUNDS_CASES,
    )?;

    for case in &fixture.effective_bounds_cases {
        ensure!(
            !case.invariants.is_empty(),
            "{}: every effective-bounds case must carry invariants",
            case.name
        );
        let constraints = case.deployment_constraints.clone().unwrap_or_default();
        let outcome = constraints.effective(case.holder_override.as_ref());

        match case.expected.decision.as_str() {
            "accepted" => {
                let expected = case.expected.effective.as_ref().with_context(|| {
                    format!("{}: an accepted case must declare effective", case.name)
                })?;
                let effective = outcome.map_err(|error| {
                    anyhow::anyhow!("{}: constraints were rejected but the case expects them to be accepted: {error}", case.name)
                })?;
                ensure!(
                    &observed_effective(&effective) == expected,
                    "{}: effective quota is {:?}, fixture declares {expected:?}",
                    case.name,
                    observed_effective(&effective)
                );
            }
            "rejected" => {
                ensure!(
                    case.expected.effective.is_none(),
                    "{}: a rejected case must not declare an effective value",
                    case.name
                );
                ensure!(
                    case.expected.error.as_deref() == Some("schema_violation"),
                    "{}: a violated cross-field MUST is reported as schema_violation",
                    case.name
                );
                ensure!(
                    case.expected.partial_member_evaluation == Some(false),
                    "{}: a rejected constraints object must not keep evaluating its remaining members",
                    case.name
                );
                ensure!(
                    outcome.is_err(),
                    "{}: the carrier accepted a constraints object the fixture rejects",
                    case.name
                );
            }
            other => bail!("{}: unknown effective-bounds decision `{other}`", case.name),
        }
    }
    Ok(())
}

fn observed_effective(effective: &EffectiveNewSourceQuota) -> ExpectedEffective {
    ExpectedEffective {
        window_seconds: effective.window_seconds,
        new_sources_per_window: effective.new_sources_per_window,
        retention_seconds: effective.retention_seconds,
        new_sources_per_retention: effective.new_sources_per_retention,
    }
}

fn run_identity_key_cases(fixture: &Fixture) -> Result<()> {
    check_closed_case_set(
        "identity_key_cases",
        fixture
            .identity_key_cases
            .iter()
            .map(|case| case.name.as_str()),
        &REQUIRED_IDENTITY_KEY_CASES,
    )?;

    for case in &fixture.identity_key_cases {
        ensure!(
            !case.invariants.is_empty(),
            "{}: every identity-key case must carry invariants",
            case.name
        );
        let left = ledger_key(fixture, &case.left)?;
        let right = ledger_key(fixture, &case.right)?;
        ensure!(
            (left == right) == case.expected.same_ledger_key,
            "{}: ledger key equality is {}, fixture declares {}",
            case.name,
            left == right,
            case.expected.same_ledger_key
        );
    }
    Ok(())
}

/// Build the ledger identity key strictly from the components the fixture
/// declares in `ledger_contract.identity_key`. Declaring `source_id` there
/// would change every key this function builds, and the transport-source case
/// would then fail -- which is exactly the bypass section 6.1.1.2 forbids.
fn ledger_key(fixture: &Fixture, operand: &IdentityKeyOperand) -> Result<String> {
    let holder = resolve_holder(fixture, &operand.holder)?;
    let source_peer_principal_id = fixture
        .principals
        .sources
        .get(&operand.source_peer_principal_id)
        .with_context(|| {
            format!(
                "unknown fixture source alias {}",
                operand.source_peer_principal_id
            )
        })?;
    let source_id = fixture
        .principals
        .transport_sources
        .get(&operand.source_id)
        .with_context(|| {
            format!(
                "unknown fixture transport source alias {}",
                operand.source_id
            )
        })?;

    let mut components = Vec::with_capacity(fixture.ledger_contract.identity_key.len());
    for component in &fixture.ledger_contract.identity_key {
        match component.as_str() {
            "holder_account_id" => {
                components.push(format!("{}|{}", holder.principal_id, holder.station_id));
            }
            "source_peer_principal_id" => components.push(source_peer_principal_id.clone()),
            "source_id" => components.push(source_id.clone()),
            other => bail!("ledger_contract.identity_key declares unknown component `{other}`"),
        }
    }
    Ok(components.join("\u{1f}"))
}

fn resolve_holder<'a>(fixture: &'a Fixture, alias: &str) -> Result<&'a AccountRef> {
    match alias {
        "holder" => Ok(&fixture.principals.holder),
        "holder_same_principal_other_station" => {
            Ok(&fixture.principals.holder_same_principal_other_station)
        }
        other => bail!("unknown fixture holder alias {other}"),
    }
}

fn run_admission_cases(fixture: &Fixture) -> Result<()> {
    check_closed_case_set(
        "admission_cases",
        fixture
            .admission_cases
            .iter()
            .map(|case| case.name.as_str()),
        &REQUIRED_ADMISSION_CASES,
    )?;

    for case in &fixture.admission_cases {
        ensure!(
            !case.invariants.is_empty(),
            "{}: every admission case must carry invariants",
            case.name
        );
        let quota = effective_quota(
            fixture,
            &case.deployment_constraints_profile,
            case.holder_override.as_ref(),
        )?;
        let mut ledger = initial_ledger(&case.initial_ledger);
        let mut cell = case.initial_quarantine_entry_sources.clone();

        for (index, contact) in case.contacts.iter().enumerate() {
            let evaluated =
                case.consent_profile == ConsentProfile::Default && !contact.deduplicated_replay;
            let decision = if evaluated {
                evaluate_admission(&mut ledger, &contact.source, contact.at, &quota)
            } else {
                Decision::NotEvaluated
            };
            ensure!(
                decision == contact.expected_decision,
                "{}: contact[{index}] on {} decided {decision:?}, fixture declares {:?}",
                case.name,
                contact.source,
                contact.expected_decision
            );
            if matches!(decision, Decision::Admitted | Decision::Seen) {
                cell.push(contact.source.clone());
            }
        }

        let expected_ledger = initial_ledger(&case.expected.final_ledger);
        ensure!(
            ledger == expected_ledger,
            "{}: final ledger is {ledger:?}, fixture declares {expected_ledger:?}",
            case.name
        );
        ensure!(
            cell == case.expected.quarantine_entry_sources,
            "{}: quarantine entry sources are {cell:?}, fixture declares {:?}",
            case.name,
            case.expected.quarantine_entry_sources
        );
    }
    Ok(())
}

fn run_concurrency_cases(fixture: &Fixture) -> Result<()> {
    check_closed_case_set(
        "concurrency_cases",
        fixture
            .concurrency_cases
            .iter()
            .map(|case| case.name.as_str()),
        &REQUIRED_CONCURRENCY_CASES,
    )?;

    for case in &fixture.concurrency_cases {
        ensure!(
            !case.invariants.is_empty(),
            "{}: every concurrency case must carry invariants",
            case.name
        );
        ensure!(
            case.expected.identical_in_every_interleaving
                && !case.expected.distinguishable_error_returned,
            "{}: linearized admission never depends on the interleaving and never returns a distinguishable error",
            case.name
        );
        let quota = effective_quota(
            fixture,
            &case.deployment_constraints_profile,
            case.holder_override.as_ref(),
        )?;

        for order in permutations(case.concurrent_contacts.len()) {
            let mut ledger = initial_ledger(&case.initial_ledger);
            let mut admitted = 0usize;
            let mut seen = 0usize;
            let mut denied = 0usize;
            for index in &order {
                let contact = &case.concurrent_contacts[*index];
                match evaluate_admission(&mut ledger, &contact.source, contact.at, &quota) {
                    Decision::Admitted => admitted += 1,
                    Decision::Seen => seen += 1,
                    Decision::Denied => denied += 1,
                    Decision::NotEvaluated => bail!(
                        "{}: a concurrent first contact is always evaluated",
                        case.name
                    ),
                }
            }
            ensure!(
                admitted == case.expected.admitted_count
                    && seen == case.expected.seen_count
                    && denied == case.expected.denied_count
                    && ledger.len() == case.expected.final_ledger_size,
                "{}: interleaving {order:?} produced admitted={admitted} seen={seen} denied={denied} ledger={}, fixture declares admitted={} seen={} denied={} ledger={}",
                case.name,
                ledger.len(),
                case.expected.admitted_count,
                case.expected.seen_count,
                case.expected.denied_count,
                case.expected.final_ledger_size
            );
            ensure!(
                admitted as u64 <= quota.new_sources_per_window,
                "{}: interleaving {order:?} admitted more new sources than the effective short-window ceiling",
                case.name
            );
        }
    }
    Ok(())
}

fn effective_quota(
    fixture: &Fixture,
    profile: &str,
    holder_override: Option<&NewSourceQuotaOverride>,
) -> Result<EffectiveNewSourceQuota> {
    let constraints = fixture
        .deployment_constraints_profiles
        .get(profile)
        .with_context(|| format!("unknown deployment constraints profile {profile}"))?;
    constraints
        .effective(holder_override)
        .with_context(|| format!("deployment constraints profile {profile} is not admissible"))
}

fn initial_ledger(rows: &[LedgerRow]) -> BTreeMap<String, DateTime<Utc>> {
    rows.iter()
        .map(|row| (row.source.clone(), row.first_admitted_at))
        .collect()
}

/// Reference model of the admission chokepoint, `consent-model.md` section
/// 6.1.1.3. The four numbered steps are executed in order and the ledger is
/// mutated exactly as the section prescribes.
fn evaluate_admission(
    ledger: &mut BTreeMap<String, DateTime<Utc>>,
    source: &str,
    now: DateTime<Utc>,
    quota: &EffectiveNewSourceQuota,
) -> Decision {
    // Step 1: rows at or beyond the retention horizon are both ignored and
    // physically removed.
    let retention_floor = now - Duration::seconds(quota.retention_seconds as i64);
    ledger.retain(|_, first_admitted_at| *first_admitted_at > retention_floor);

    // Step 2: membership precedes both ceilings, and a seen source is neither
    // charged again nor re-timestamped.
    if ledger.contains_key(source) {
        return Decision::Seen;
    }

    // Step 3: both sliding windows are counted straight off the timestamps.
    let window_floor = now - Duration::seconds(quota.window_seconds as i64);
    let rate = ledger
        .values()
        .filter(|first_admitted_at| **first_admitted_at > window_floor)
        .count() as u64;
    let total = ledger.len() as u64;
    if rate >= quota.new_sources_per_window || total >= quota.new_sources_per_retention {
        // Step 4: a denied source is never written, so the next window cannot
        // misread it as seen.
        return Decision::Denied;
    }

    ledger.insert(source.to_owned(), now);
    Decision::Admitted
}

fn permutations(len: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut current = Vec::with_capacity(len);
    let mut used = vec![false; len];
    build_permutations(len, &mut used, &mut current, &mut result);
    result
}

fn build_permutations(
    len: usize,
    used: &mut Vec<bool>,
    current: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if current.len() == len {
        result.push(current.clone());
        return;
    }
    for index in 0..len {
        if used[index] {
            continue;
        }
        used[index] = true;
        current.push(index);
        build_permutations(len, used, current, result);
        current.pop();
        used[index] = false;
    }
}

fn check_chokepoint_contract(contract: &ChokepointContract) -> Result<()> {
    ensure!(
        contract.converging_surface_operation_ids == CONVERGING_SURFACE_OPERATION_IDS,
        "the quota chokepoint must stay the single convergence point of exactly the three declared surfaces"
    );
    ensure!(
        contract.evaluated_exactly_once_before_cell_cas_write
            && !contract.reevaluated_inside_cell_cas_retry_loop
            && !contract.cas_retry_exhaustion_refunds_the_charge,
        "quota evaluation runs exactly once before the cell CAS write, never inside its retry loop, and is not refunded"
    );
    ensure!(
        !contract.substitutable_by_generic_endpoint_rate_limit
            && !contract.substitutable_by_directory_psi_device_quota
            && !contract.substitutable_by_private_configuration,
        "receive_policy_constraints.new_source_quota is the only carrier for this ceiling"
    );
    Ok(())
}

fn check_ledger_contract(contract: &LedgerContract) -> Result<()> {
    ensure!(
        contract.identity_key == IDENTITY_KEY_COMPONENTS,
        "the ledger identity key is exactly the holder AccountId and the source peer principal"
    );
    ensure!(
        contract.row_fields
            == vec![
                "holder_account_id".to_owned(),
                "source_peer_principal_id".to_owned(),
                "first_admitted_at".to_owned(),
            ],
        "the ledger row is exactly the holder, the source and its first admission instant"
    );
    ensure!(
        !contract.source_id_participates_in_identity_key,
        "the authenticated transport source DID must not enter the quota identity"
    );
    ensure!(
        !contract.wire_readable
            && !contract.is_account_data_cell
            && contract.holder_observable_surface == "ak.account.invite_quarantine",
        "the ledger has no wire carrier; the quarantine cell stays the holder's only observable surface"
    );
    ensure!(
        contract.source_column_storage == "server_private_keyed_digest",
        "the source column stores a server-private keyed digest, because membership only needs equality"
    );
    ensure!(
        contract.retention_seconds_is_both_ledger_lifetime_and_long_window,
        "retention_seconds is one parameter serving as both the ledger lifetime and the long counting window"
    );
    ensure!(
        contract.account_erasure_deletes_the_whole_ledger
            && !contract.consent_revoke_touches_the_ledger
            && !contract.source_allow_or_deny_list_change_touches_the_ledger,
        "anti-abuse admission state is erased with the account and is otherwise separate from consent state"
    );
    ensure!(
        !contract.audit_persists_dropped_source_did,
        "audit may count drops but must not persist the identifiable dropped source DID"
    );
    Ok(())
}

fn check_opaque_outcome_contract(contract: &OpaqueOutcomeContract) -> Result<()> {
    ensure!(
        contract.wire_status == "deferred" && !contract.disclosed_outcome_present,
        "a quota drop stays status=deferred without disclosed_outcome"
    );
    ensure!(
        contract.indistinguishable_equivalence_class == INDISTINGUISHABLE_EQUIVALENCE_CLASS,
        "the indistinguishable equivalence class is the closed five-way list of section 6.1.1"
    );
    ensure!(
        contract.forbidden_signals == FORBIDDEN_SIGNALS,
        "a quota drop must never surface as 429, Retry-After, rate_limited or a cached drop outcome"
    );
    ensure!(
        contract.disclosed_outcome_enum == vec!["delivered".to_owned(), "blocked".to_owned()],
        "disclosed_outcome stays the closed delivered|blocked enum; quarantined is not a returnable value"
    );
    Ok(())
}

fn check_closed_case_set<'a>(
    label: &str,
    names: impl Iterator<Item = &'a str>,
    required: &[&str],
) -> Result<()> {
    let observed = names.collect::<BTreeSet<_>>();
    let expected = required.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        observed == expected,
        "{label} is not the closed declared set: {observed:?} != {expected:?}"
    );
    Ok(())
}
