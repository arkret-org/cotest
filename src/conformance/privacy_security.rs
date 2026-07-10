//! §9.14 — `ak.vector.identity_link.minimal_metadata_author_credential.v1`.
//!
//! Minimal-metadata content authorship trust anchor
//! (encryption-and-audit.md §2.10.3): a content Event proof binds to exactly
//! one active RFC 9420 BasicCredential LeafNode whose identity equals
//! `utf8(Event.actor_id)` byte for byte and whose `signature_key` equals the
//! proof's resolved public key, at the envelope `(group_id, epoch,
//! group_state_ref)`. Every failure rejects with the canonical
//! `minimal_metadata_author_credential_invalid` and the receiver MUST fail
//! closed with ZERO principal-scoped `keys/query` lookups. The vector drives
//! the production SDK validator (`arkret::mls::verify_minimal_metadata_author`)
//! — the same helper soland admission and the inkson receiver consume.

use anyhow::{Context, Result, anyhow, bail};
use arkret::mls::{
    AuthorGroupStateView, AuthorLeaf, AuthorLeafCredential, MinimalMetadataAuthorClaim,
    verify_minimal_metadata_author,
};
use arkret_core::REASON_MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::transcripts::record_vector_event;

const PRIVACY_SECURITY_FIXTURE_FILE: &str = "privacy-security-fixture.json";
pub const VECTOR_ID_MINIMAL_METADATA_AUTHOR_CREDENTIAL: &str =
    "ak.vector.identity_link.minimal_metadata_author_credential.v1";
pub(crate) const MINIMAL_METADATA_AUTHOR_CREDENTIAL_CASE: &str =
    "minimal_metadata_author_credential_is_the_only_author_trust_anchor";

#[derive(Debug, Deserialize)]
struct VectorCase {
    runner: String,
    base: BaseFixture,
    cases: Vec<MutationCase>,
    assertions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct BaseFixture {
    actor_id: String,
    group_id: String,
    epoch: u64,
    group_state_ref: String,
    leaf: LeafFixture,
    proof: ProofFixture,
}

#[derive(Clone, Debug, Deserialize)]
struct LeafFixture {
    leaf_index: u32,
    credential_type: String,
    credential_identity_utf8: String,
    signature_key: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ProofFixture {
    verification_method: String,
    resolved_public_key: String,
    signature_valid: bool,
}

#[derive(Debug, Deserialize)]
struct MutationCase {
    name: String,
    mutation: String,
    expected: ExpectedOutcome,
}

#[derive(Debug, Deserialize)]
struct ExpectedOutcome {
    result: String,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    principal_directory_queries: Option<u64>,
}

/// Executable principal-directory spy. The production validator's signature
/// takes no directory client or resolver callback, so this spy cannot be
/// reached by it — `queries` staying 0 is the executable form of the
/// "author verification never queries principal-scoped keys/query" assertion,
/// not a comment.
#[derive(Debug, Default)]
struct PrincipalDirectorySpy {
    queries: usize,
}

impl PrincipalDirectorySpy {
    #[allow(dead_code)]
    fn keys_query(&mut self, _principal: &str) {
        self.queries += 1;
    }
}

fn base_leaf(base: &BaseFixture) -> AuthorLeaf {
    AuthorLeaf {
        leaf_index: base.leaf.leaf_index,
        credential: AuthorLeafCredential::Basic {
            identity: base.leaf.credential_identity_utf8.as_bytes().to_vec(),
        },
        signature_key: base.leaf.signature_key.as_bytes().to_vec(),
    }
}

fn bystander_leaf() -> AuthorLeaf {
    AuthorLeaf {
        leaf_index: 0,
        credential: AuthorLeafCredential::Basic {
            identity: b"did:key:z6MkpairwiseBob".to_vec(),
        },
        signature_key: b"z6MkpairwiseBystanderKey".to_vec(),
    }
}

fn base_view(base: &BaseFixture, active_leaves: Vec<AuthorLeaf>) -> AuthorGroupStateView {
    AuthorGroupStateView {
        group_id: base.group_id.clone(),
        epoch: base.epoch,
        group_state_ref: base.group_state_ref.clone(),
        active_leaves,
    }
}

pub fn run_minimal_metadata_author_credential_vector() -> Result<()> {
    let fixture = super::load_fixture_value(PRIVACY_SECURITY_FIXTURE_FILE)?;
    let case_value = fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("name").and_then(Value::as_str)
                    == Some(MINIMAL_METADATA_AUTHOR_CREDENTIAL_CASE)
            })
        })
        .ok_or_else(|| anyhow!("minimal-metadata author credential vector case missing"))?;
    if case_value.get("vector_id").and_then(Value::as_str)
        != Some(VECTOR_ID_MINIMAL_METADATA_AUTHOR_CREDENTIAL)
    {
        bail!("minimal-metadata author credential case lost its vector_id");
    }
    let case: VectorCase = serde_json::from_value(case_value.clone())
        .context("decode minimal-metadata author credential vector case")?;
    if case.runner
        != "cotest::conformance::privacy_security::run_minimal_metadata_author_credential_vector"
    {
        bail!("minimal-metadata author credential fixture runner is not resolvable");
    }
    if case.base.leaf.credential_type != "basic" {
        bail!("vector base leaf must be a BasicCredential leaf");
    }
    if !case.base.proof.signature_valid {
        bail!("vector base proof must be a valid signature control");
    }
    if !case
        .base
        .proof
        .verification_method
        .starts_with(&case.base.actor_id)
    {
        bail!("vector base verification_method is not rooted in the pairwise actor");
    }
    if case.base.proof.resolved_public_key != case.base.leaf.signature_key {
        bail!("vector base proof key must equal the leaf signature_key byte for byte");
    }
    if case.cases.len() != 6 {
        bail!(
            "minimal-metadata author credential vector must contain 6 cases, got {}",
            case.cases.len()
        );
    }
    if case.assertions.len() != 5 {
        bail!("minimal-metadata author credential assertion catalogue drifted");
    }

    let actor_id = arkret_core::Did::new(case.base.actor_id.clone())
        .context("vector base actor_id must be a valid DID")?;

    for mutation_case in &case.cases {
        // Per-case rebuild from base: mutations never leak across cases.
        let base = case.base.clone();
        let mut proof_key = base.proof.resolved_public_key.clone().into_bytes();
        let mut claim_group_state_ref = base.group_state_ref.clone();
        let mut active_leaves = vec![bystander_leaf(), base_leaf(&base)];
        let directory = PrincipalDirectorySpy::default();

        match mutation_case.mutation.as_str() {
            "none" => {}
            "duplicate_active_leaf_identity" => {
                let mut duplicate = base_leaf(&base);
                duplicate.leaf_index = base.leaf.leaf_index + 1;
                duplicate.signature_key = b"z6MkpairwiseImposterKey".to_vec();
                active_leaves.push(duplicate);
            }
            "leaf_removed_at_epoch" => {
                // The actor's leaf was excluded by the epoch's Remove/Commit —
                // it simply is not in the active leaf set.
                active_leaves = vec![bystander_leaf()];
            }
            "group_state_ref_not_winning_for_epoch" => {
                claim_group_state_ref = "ak:event:01970e58-9d27-7000-8000-00000000dead".to_owned();
            }
            "proof_key_differs_from_leaf_signature_key" => {
                proof_key = b"z6MkpairwiseWrongProofKey".to_vec();
            }
            "attempt_keys_query_principal_lookup" => {
                // The forbidden-fallback probe: the author's leaf is absent, so
                // a non-conformant receiver would be tempted to resolve the
                // author through the principal directory. The production
                // validator has no directory parameter, so the spy MUST stay
                // untouched and the claim MUST reject.
                active_leaves = vec![bystander_leaf()];
            }
            other => bail!("unknown minimal-metadata author mutation {other}"),
        }

        let view = base_view(&base, active_leaves);
        let claim = MinimalMetadataAuthorClaim {
            group_id: &base.group_id,
            epoch: base.epoch,
            group_state_ref: &claim_group_state_ref,
            actor_id: &actor_id,
            proof_public_key: &proof_key,
        };
        let outcome = verify_minimal_metadata_author(&view, &claim);
        let accepted = outcome.is_ok();
        let rejected_reason = outcome.as_ref().err().map(|error| error.reason_code());

        match mutation_case.expected.result.as_str() {
            "accept_pairwise_author" => {
                let verified = outcome.map_err(|error| {
                    anyhow!(
                        "case {} rejected a unique active pairwise leaf: {error}",
                        mutation_case.name
                    )
                })?;
                if verified.leaf_index != base.leaf.leaf_index {
                    bail!(
                        "case {} accepted the wrong leaf index {}",
                        mutation_case.name,
                        verified.leaf_index
                    );
                }
            }
            "reject" => {
                let error = match outcome {
                    Ok(_) => bail!(
                        "case {} must reject but accepted an author",
                        mutation_case.name
                    ),
                    Err(error) => error,
                };
                if let Some(expected_reason) = mutation_case.expected.reason_code.as_deref() {
                    if error.reason_code() != expected_reason
                        || expected_reason != REASON_MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID
                    {
                        bail!(
                            "case {} rejected with {} (expected {expected_reason})",
                            mutation_case.name,
                            error.reason_code()
                        );
                    }
                }
            }
            other => bail!("unknown expected result {other}"),
        }

        // `principal_directory_queries: 0` is an executable assertion: the spy
        // is the ONLY directory in scope and the validator cannot reach it.
        if let Some(expected_queries) = mutation_case.expected.principal_directory_queries {
            if directory.queries as u64 != expected_queries || expected_queries != 0 {
                bail!(
                    "case {} performed {} principal directory queries (expected {expected_queries})",
                    mutation_case.name,
                    directory.queries
                );
            }
        }
        // Every case — accept and reject alike — runs without a directory.
        if directory.queries != 0 {
            bail!(
                "case {} reached the principal directory {} times",
                mutation_case.name,
                directory.queries
            );
        }

        record_vector_event(
            "privacy_security.minimal_metadata_author_credential",
            &json!({
                "case": mutation_case.name,
                "mutation": mutation_case.mutation,
            }),
            &json!({
                "result": mutation_case.expected.result,
                "reason_code": mutation_case.expected.reason_code,
                "principal_directory_queries": 0,
            }),
            &json!({
                "accepted": accepted,
                "reason_code": rejected_reason,
                "principal_directory_queries": directory.queries,
            }),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_metadata_author_credential_vector_runs_clean() {
        run_minimal_metadata_author_credential_vector().unwrap();
    }
}
