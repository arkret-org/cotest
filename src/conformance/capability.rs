use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{
    CapabilityFixture, ResourceRef, ResourceSelector, load_fixture_value, parse_fixture_value,
    required_str, validate_profile,
};

pub fn run_capability_fixture_suite() -> Result<()> {
    let value = load_fixture_value("capability-fixture.json")?;
    if value.get("suite").is_none() {
        return run_capability_artifact_suite(&value);
    }
    let fixture: CapabilityFixture = parse_fixture_value("capability-fixture.json", value)?;
    if fixture.suite != "capability" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "resource_selector_grammar" => {
                let selector = case
                    .selector
                    .ok_or_else(|| anyhow!("capability fixture {} missing selector", case.name))?;
                let task = ResourceRef {
                    kind: "entity".to_owned(),
                    space_id: selector.space_id.clone(),
                    entity_type: Some("task".to_owned()),
                };
                let note = ResourceRef {
                    kind: "entity".to_owned(),
                    space_id: selector.space_id.clone(),
                    entity_type: Some("note".to_owned()),
                };
                if !selector.matches(&task) || selector.matches(&note) {
                    bail!("capability fixture {} selector grammar mismatch", case.name);
                }
            }
            "constraint_fail_closed" => {
                let grant = CapabilityGrant {
                    required_claims: BTreeSet::from(["employee".to_owned()]),
                    approval_mode: ApprovalMode::None,
                    approved: false,
                    revoked_claims: BTreeSet::new(),
                    scope: selector_scope("task")?,
                };
                if grant.is_usable(&BTreeSet::new()) {
                    bail!("capability fixture {} did not fail closed", case.name);
                }
            }
            "approval_proposal" => {
                let grant = CapabilityGrant {
                    required_claims: BTreeSet::new(),
                    approval_mode: ApprovalMode::ProposalThenApprove,
                    approved: false,
                    revoked_claims: BTreeSet::new(),
                    scope: selector_scope("task")?,
                };
                if grant.is_usable(&BTreeSet::new()) {
                    bail!(
                        "capability fixture {} allowed unapproved proposal",
                        case.name
                    );
                }
            }
            "claim_revocation" => {
                let grant = CapabilityGrant {
                    required_claims: BTreeSet::from(["employee".to_owned()]),
                    approval_mode: ApprovalMode::None,
                    approved: false,
                    revoked_claims: BTreeSet::from(["employee".to_owned()]),
                    scope: selector_scope("task")?,
                };
                if grant.is_usable(&BTreeSet::from(["employee".to_owned()])) {
                    bail!("capability fixture {} ignored revoked claim", case.name);
                }
            }
            "delegation_cycle_and_scope_narrowing" => {
                let parent = Delegation {
                    from: "did:web:alice.example".to_owned(),
                    to: "did:web:bob.example".to_owned(),
                    scope: selector_scope("task")?,
                };
                let child_ok = Delegation {
                    from: "did:web:bob.example".to_owned(),
                    to: "did:web:carol.example".to_owned(),
                    scope: selector_scope("task")?,
                };
                let child_bad_scope = Delegation {
                    from: "did:web:bob.example".to_owned(),
                    to: "did:web:carol.example".to_owned(),
                    scope: selector_scope("entity")?,
                };
                let cycle = Delegation {
                    from: "did:web:carol.example".to_owned(),
                    to: "did:web:alice.example".to_owned(),
                    scope: selector_scope("task")?,
                };
                validate_delegations(&[parent.clone(), child_ok.clone()])?;
                if validate_delegations(&[parent.clone(), child_bad_scope]).is_ok() {
                    bail!(
                        "capability fixture {} allowed widened child scope",
                        case.name
                    );
                }
                if validate_delegations(&[parent, child_ok.clone(), cycle]).is_ok() {
                    bail!("capability fixture {} allowed delegation cycle", case.name);
                }
            }
            _ => bail!("unknown capability fixture case {}", case.name),
        }
    }

    Ok(())
}

fn run_capability_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.capability_vectors.v1")?;
    let fixtures = value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability artifact missing fixtures"))?;
    for fixture in fixtures {
        let name = required_str(fixture, "name")?;
        if fixture.get("expected").is_none() && fixture.get("requests").is_none() {
            bail!("capability fixture {name} missing expected outcome");
        }
        if name == "approval_constraint_requires_controller_approval" {
            let requests = fixture
                .get("requests")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("approval fixture missing requests"))?;
            if !requests.iter().any(|request| {
                request
                    .pointer("/expected/decision")
                    .and_then(Value::as_str)
                    == Some("require_review")
            }) {
                bail!("approval fixture no longer requires review without proof");
            }
        }
        if name == "revoked_grant_denies_later_write"
            && fixture
                .pointer("/expected/decision")
                .and_then(Value::as_str)
                != Some("deny")
        {
            bail!("revoked grant fixture no longer denies later write");
        }
    }
    Ok(())
}

// ── Capability facet fixture suite ──────────────────────────────────────────

pub fn run_capability_facet_fixture_suite() -> Result<()> {
    let grant = FacetGrant {
        allowed_entity_facets: BTreeSet::from(["rankable".to_owned(), "stateful".to_owned()]),
        critical: true,
    };
    let matching = EntityTarget {
        entity_type: "task".to_owned(),
        facets: Some(BTreeSet::from([
            "rankable".to_owned(),
            "renderable".to_owned(),
            "stateful".to_owned(),
        ])),
    };
    if !grant.allows(&matching) {
        bail!("capability facet suite rejected matching entity facets");
    }

    let missing_facets = EntityTarget {
        entity_type: "task".to_owned(),
        facets: None,
    };
    if grant.allows(&missing_facets) {
        bail!("capability facet suite did not fail closed for missing critical facets");
    }

    let compatibility_label_only = EntityTarget {
        entity_type: "rankable_stateful_task".to_owned(),
        facets: Some(BTreeSet::from(["renderable".to_owned()])),
    };
    if grant.allows(&compatibility_label_only) {
        bail!("capability facet suite allowed entity_type labels to satisfy facet constraints");
    }

    Ok(())
}

// ── Internal types ──────────────────────────────────────────────────────────

fn selector_scope(entity_type: &str) -> Result<ResourceSelector> {
    Ok(ResourceSelector {
        kind: "entity".to_owned(),
        space_id: "cx:space:01JS0SP000000000000000000".to_owned(),
        entity_type: Some(entity_type.to_owned()),
    })
}

enum ApprovalMode {
    None,
    ProposalThenApprove,
}

struct CapabilityGrant {
    required_claims: BTreeSet<String>,
    approval_mode: ApprovalMode,
    approved: bool,
    revoked_claims: BTreeSet<String>,
    scope: ResourceSelector,
}

impl CapabilityGrant {
    fn is_usable(&self, claims: &BTreeSet<String>) -> bool {
        let _ = &self.scope;
        if !self.required_claims.is_subset(claims) {
            return false;
        }
        if self
            .required_claims
            .iter()
            .any(|claim| self.revoked_claims.contains(claim))
        {
            return false;
        }
        match self.approval_mode {
            ApprovalMode::None => true,
            ApprovalMode::ProposalThenApprove => self.approved,
        }
    }
}

struct FacetGrant {
    allowed_entity_facets: BTreeSet<String>,
    critical: bool,
}

struct EntityTarget {
    entity_type: String,
    facets: Option<BTreeSet<String>>,
}

impl FacetGrant {
    fn allows(&self, target: &EntityTarget) -> bool {
        let _ = &target.entity_type;
        match &target.facets {
            Some(facets) => self.allowed_entity_facets.is_subset(facets),
            None => !self.critical && self.allowed_entity_facets.is_empty(),
        }
    }
}

#[derive(Clone)]
struct Delegation {
    from: String,
    to: String,
    scope: ResourceSelector,
}

fn validate_delegations(delegations: &[Delegation]) -> Result<()> {
    let mut graph = HashMap::<String, String>::new();
    for delegation in delegations {
        graph.insert(delegation.from.clone(), delegation.to.clone());
    }
    for delegation in delegations {
        let mut seen = HashSet::new();
        let mut current = delegation.to.as_str();
        while let Some(next) = graph.get(current) {
            if !seen.insert(current.to_owned()) || next == &delegation.from {
                bail!("delegation cycle detected");
            }
            current = next;
        }
    }
    for window in delegations.windows(2) {
        if !window[0].scope.contains(&window[1].scope) {
            bail!("delegation widened child scope");
        }
    }
    Ok(())
}
