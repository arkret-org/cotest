//! Profile-role validator for `server.describe` claims, loading the spec
//! artifact at runtime.
//!
//! This is the cotest-side companion of the SDK's
//! [`contrix_core::ProfileValidator`]: the SDK owns a frozen table baked at
//! build time, cotest reads the live artifact off disk so a stale SDK build
//! cannot mask a spec change. The two are wired together in
//! [`assert_sdk_matches_artifact`] which is called by the smoke suite.
//!
//! Three claim provenances are supported:
//!
//! * [`ClaimKind::SelfClaimed`]    — implementor self-attests.
//! * [`ClaimKind::CotestVerified`] — claim was produced by a successful `cotest` suite run.
//! * [`ClaimKind::Experimental`]   — claim is intentionally outside the v1 conformance catalogue;
//!   role partitioning still applies when the id is in the spec.
//!
//! ## Example
//!
//! ```no_run
//! use cotest::profile_validator::{ClaimKind, ServiceRole, validate_describe_profile_claims};
//! use serde_json::json;
//!
//! let describe = json!({
//!     "supported_profiles": [
//!         "cx.profile.chat_mvp.v1",
//!         "cx.profile.kanban_mvp.v1",
//!     ],
//! });
//! let outcome = validate_describe_profile_claims(
//!     &describe,
//!     ServiceRole::Client,
//!     ClaimKind::CotestVerified,
//! )
//! .expect("artifact loads");
//! assert!(outcome.is_compliant());
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use crate::conformance::spec_artifacts_root;

/// Role partition for profile claims. Mirrors
/// `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json#/profile_roles`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceRole {
    Client,
    Server,
    Gateway,
    Directory,
    Admin,
    Interop,
}

impl ServiceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Gateway => "gateway",
            Self::Directory => "directory",
            Self::Admin => "admin",
            Self::Interop => "interop",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "client" => Ok(Self::Client),
            "server" => Ok(Self::Server),
            "gateway" => Ok(Self::Gateway),
            "directory" => Ok(Self::Directory),
            "admin" => Ok(Self::Admin),
            "interop" => Ok(Self::Interop),
            other => bail!("unknown service role {other}"),
        }
    }
}

/// Provenance for a per-profile claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClaimKind {
    SelfClaimed,
    CotestVerified,
    Experimental,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfClaimed => "self_claimed",
            Self::CotestVerified => "cotest_verified",
            Self::Experimental => "experimental",
        }
    }
}

/// One reason the profile claim was rejected. The structured variant lets
/// downstream callers (e.g. `cotest` report renderers, soland CI gates) render
/// per-profile diagnostics without re-deriving the role table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileClaimFailure {
    /// `profile_id` is not in the spec catalogue (and the claim is not
    /// `Experimental`, which would surface as
    /// [`Self::ExperimentalUnknownProfile`]).
    UnknownProfile { profile_id: String },
    /// The profile is known but its `profile_roles` entry is incompatible
    /// with `service_role`. Interop profiles are pre-filtered as allowed and
    /// never appear here.
    RoleMismatch {
        profile_id: String,
        declared_role: ServiceRole,
        service_role: ServiceRole,
    },
    /// Experimental claim whose id is not in the spec — surfaced so the
    /// caller can decide whether the deployment allows experimental ids.
    ExperimentalUnknownProfile { profile_id: String },
}

/// Outcome of [`validate_describe_profile_claims`]: per-profile classification
/// plus the failure list. The full breakdown lets callers render a "claimed
/// 3 / accepted 2 / rejected 1" summary in one pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileClaimOutcome {
    pub accepted: Vec<(String, ServiceRole)>,
    pub experimental_unknown_allowed: Vec<String>,
    pub failures: Vec<ProfileClaimFailure>,
}

impl ProfileClaimOutcome {
    pub fn is_compliant(&self) -> bool {
        self.failures.is_empty()
    }

    /// True when at least one accepted profile carries the `Interop` role.
    /// Useful for asserting "bridge" semantics in regression tests.
    pub fn has_interop_bridge(&self) -> bool {
        self.accepted
            .iter()
            .any(|(_, role)| *role == ServiceRole::Interop)
    }
}

/// Permitted role allow-set for a given [`ServiceRole`] *consumer* of the
/// validator. Mirrors the SDK's `ProfileValidator::permitted_roles` rule:
/// `Interop` and `Admin` are always allowed; the consumer's own role is
/// always allowed; everything else is rejected.
pub fn permitted_roles_for(role: ServiceRole) -> Vec<ServiceRole> {
    let mut roles = vec![role, ServiceRole::Admin, ServiceRole::Interop];
    // Server-style services often also expose directory-shaped profiles
    // (identity registry, public network identity). Allow that pairing so
    // principal_server + directory_service consumers don't have to be
    // separately modelled.
    if matches!(role, ServiceRole::Server) {
        roles.push(ServiceRole::Directory);
    }
    if matches!(role, ServiceRole::Directory) {
        roles.push(ServiceRole::Server);
    }
    roles.sort();
    roles.dedup();
    roles
}

/// Loaded `profile_roles` table from the spec artifact.
#[derive(Clone, Debug)]
pub struct ProfileRoleTable {
    pub source_path: PathBuf,
    pub roles: BTreeMap<String, ServiceRole>,
}

impl ProfileRoleTable {
    pub fn load() -> Result<Self> {
        let source_path = spec_artifacts_root()
            .join("profiles")
            .join("conformance-profiles.json");
        Self::load_from(&source_path)
    }

    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read profile artifact at {}", path.display()))?;
        let artifact: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse profile artifact at {}", path.display()))?;
        let object = artifact
            .get("profile_roles")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("missing top-level profile_roles object"))?;
        let mut roles = BTreeMap::new();
        for (id, value) in object {
            let role_str = value
                .as_str()
                .ok_or_else(|| anyhow!("profile_roles[{id}] must be a string"))?;
            let role =
                ServiceRole::parse(role_str).with_context(|| format!("profile_roles[{id}]"))?;
            roles.insert(id.clone(), role);
        }
        Ok(Self {
            source_path: path.to_path_buf(),
            roles,
        })
    }

    pub fn role_of(&self, profile_id: &str) -> Option<ServiceRole> {
        self.roles.get(profile_id).copied()
    }

    pub fn ids_with_role(&self, role: ServiceRole) -> Vec<String> {
        self.roles
            .iter()
            .filter(|(_, r)| **r == role)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.roles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }
}

/// Validate the `supported_profiles` array of a `server.describe` response
/// against the spec `profile_roles` table.
///
/// `service_role` declares what kind of surface the responder claims to be;
/// `claim_kind` is the provenance applied to every entry in
/// `supported_profiles`. (For mixed-provenance manifests, call
/// [`validate_profile_claims`] directly with the per-profile pairs.)
pub fn validate_describe_profile_claims(
    describe: &Value,
    service_role: ServiceRole,
    claim_kind: ClaimKind,
) -> Result<ProfileClaimOutcome> {
    let table = ProfileRoleTable::load()?;
    let profiles = describe
        .get("supported_profiles")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|item| (item.to_owned(), claim_kind))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(validate_profile_claims(&profiles, service_role, &table))
}

/// Validate a `[(profile_id, ClaimKind)]` batch. Pure function — exposed for
/// tests and for manifest-style consumers that already carry per-profile
/// provenance.
pub fn validate_profile_claims(
    claims: &[(String, ClaimKind)],
    service_role: ServiceRole,
    table: &ProfileRoleTable,
) -> ProfileClaimOutcome {
    let permitted: BTreeSet<ServiceRole> = permitted_roles_for(service_role).into_iter().collect();
    let mut outcome = ProfileClaimOutcome::default();
    for (profile_id, claim_kind) in claims {
        match table.role_of(profile_id) {
            Some(role) => {
                if role == ServiceRole::Interop || permitted.contains(&role) {
                    outcome.accepted.push((profile_id.clone(), role));
                } else {
                    outcome.failures.push(ProfileClaimFailure::RoleMismatch {
                        profile_id: profile_id.clone(),
                        declared_role: role,
                        service_role,
                    });
                }
            }
            None => match claim_kind {
                ClaimKind::Experimental => {
                    outcome
                        .experimental_unknown_allowed
                        .push(profile_id.clone());
                }
                ClaimKind::SelfClaimed | ClaimKind::CotestVerified => {
                    outcome.failures.push(ProfileClaimFailure::UnknownProfile {
                        profile_id: profile_id.clone(),
                    });
                }
            },
        }
    }
    outcome
}

/// Assert that the SDK's frozen role table matches the spec artifact.
///
/// Run from the cotest smoke harness so an out-of-date SDK build can't mask a
/// spec-side role change. Returns `Err` only when the two views diverge — the
/// inner error message lists every mismatched profile id.
pub fn assert_sdk_matches_artifact() -> Result<()> {
    let table = ProfileRoleTable::load()?;
    let mut diffs = Vec::new();
    for (profile_id, expected) in &table.roles {
        match contrix_core::profile_role(profile_id) {
            Some(sdk_role) => {
                if sdk_role.as_str() != expected.as_str() {
                    diffs.push(format!(
                        "{profile_id}: artifact={} sdk={}",
                        expected.as_str(),
                        sdk_role.as_str()
                    ));
                }
            }
            None => diffs.push(format!(
                "{profile_id}: artifact={} sdk=<missing>",
                expected.as_str()
            )),
        }
    }
    if diffs.is_empty() {
        Ok(())
    } else {
        bail!(
            "SDK profile_roles table out of sync with artifact:\n  {}",
            diffs.join("\n  ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permitted_roles_for_includes_self_admin_interop() {
        for role in [
            ServiceRole::Client,
            ServiceRole::Server,
            ServiceRole::Gateway,
            ServiceRole::Directory,
            ServiceRole::Admin,
            ServiceRole::Interop,
        ] {
            let permitted = permitted_roles_for(role);
            assert!(permitted.contains(&role));
            assert!(permitted.contains(&ServiceRole::Admin));
            assert!(permitted.contains(&ServiceRole::Interop));
        }
    }
}
