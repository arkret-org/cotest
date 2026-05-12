use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

pub fn run_capability_fixture_suite() -> Result<()> {
    let value = load_fixture_value("capability-fixture.json")?;
    validate_profile(&value, "cx.profile.capability_vectors.v1")?;
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

pub fn run_capability_facet_fixture_suite() -> Result<()> {
    let grant = FacetGrant {
        facet_allow: BTreeSet::from(["assignable".to_owned(), "stateful".to_owned()]),
        critical: true,
    };
    let matching = ObjectTarget {
        object_type: "morph".to_owned(),
        facets: Some(BTreeSet::from([
            "assignable".to_owned(),
            "renderable".to_owned(),
            "stateful".to_owned(),
        ])),
    };
    if !grant.allows(&matching) {
        bail!("capability facet suite rejected matching object facets");
    }

    let missing_facets = ObjectTarget {
        object_type: "morph".to_owned(),
        facets: None,
    };
    if grant.allows(&missing_facets) {
        bail!("capability facet suite did not fail closed for missing critical facets");
    }

    let label_only = ObjectTarget {
        object_type: "assignable_stateful_morph".to_owned(),
        facets: Some(BTreeSet::from(["renderable".to_owned()])),
    };
    if grant.allows(&label_only) {
        bail!("capability facet suite allowed object_type labels to satisfy facet constraints");
    }

    Ok(())
}

struct FacetGrant {
    facet_allow: BTreeSet<String>,
    critical: bool,
}

struct ObjectTarget {
    object_type: String,
    facets: Option<BTreeSet<String>>,
}

impl FacetGrant {
    fn allows(&self, target: &ObjectTarget) -> bool {
        let _ = &target.object_type;
        match &target.facets {
            Some(facets) => self.facet_allow.is_subset(facets),
            None => !self.critical && self.facet_allow.is_empty(),
        }
    }
}
