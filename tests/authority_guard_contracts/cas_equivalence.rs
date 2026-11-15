//! The old pair is an oracle only. It is never decoded as a write request.
use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result, ensure};
use arkret_wire::RealmCommit;
use jsonschema::{Registry, Resource};
use serde_json::{Value, json};

fn guard_paths(node: &Value, pointer: &str, output: &mut Vec<String>) {
    match node {
        Value::Object(object) => {
            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                for name in properties.keys() {
                    if name.starts_with("expected_") && name.ends_with("_commit_id") {
                        output.push(format!("{pointer}/properties/{name}"));
                    }
                }
            }
            for (key, child) in object {
                guard_paths(
                    child,
                    &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                    output,
                );
            }
        }
        Value::Array(rows) => {
            for (index, child) in rows.iter().enumerate() {
                guard_paths(child, &format!("{pointer}/{index}"), output);
            }
        }
        _ => {}
    }
}

/// Exercise the exact 43 converted slots against actual native accepted
/// Commit bodies. The functional dependency is the proof, not a second copy
/// of each domain's business predicate: verified ID -> full body -> position.
pub(super) fn assert_registered_guard_equivalence(commits: &[RealmCommit]) -> Result<()> {
    ensure!(commits.len() >= 3, "oracle needs the native A/B/A chain");
    let mut identities = BTreeMap::new();
    for commit in commits {
        commit.verify_commit_id_matches_content()?;
        commit.validate_shape()?;
        ensure!(
            commit.stream_ref == commits[0].stream_ref,
            "compare only one exact stream"
        );
        if let Some(position) = identities.insert(commit.commit_id.clone(), commit.stream_position)
        {
            ensure!(
                position == commit.stream_position,
                "same content identity acquired two positions"
            );
        }
    }
    let root = cotest::conformance::spec_artifacts_root().join("schemas");
    let mut documents = BTreeMap::new();
    let mut builder = Registry::new();
    for entry in fs::read_dir(&root)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let document: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        let id = document["$id"]
            .as_str()
            .context("schema has no canonical identity")?
            .to_owned();
        builder = builder
            .add(id.as_str(), Resource::from_contents(document.clone()))
            .map_err(|error| anyhow::anyhow!("schema registration: {error}"))?;
        documents.insert(
            path.file_name()
                .context("schema filename")?
                .to_string_lossy()
                .into_owned(),
            document,
        );
    }
    let registry = builder
        .prepare()
        .map_err(|error| anyhow::anyhow!("schema registry: {error}"))?;
    let mut slots = Vec::new();
    for file in [
        "event-payload.schema.json",
        "realm-actor.schema.json",
        "identity-resolution.schema.json",
        "applet-install-operations.schema.json",
    ] {
        let document = &documents[file];
        let mut pointers = Vec::new();
        guard_paths(document, "", &mut pointers);
        for pointer in pointers {
            // These three are independently registered contracts: a head
            // predecessor that was always scalar, and two later Call results.
            if file == "event-payload.schema.json" && [
                "/$defs/realm_governance_station_change_payload/properties/expected_realm_stream_commit_id",
                "/$defs/call_state_payload/properties/recording_transition/properties/expected_commit_id",
                "/$defs/call_state_payload/properties/transcript_transition/properties/expected_commit_id",
            ].contains(&pointer.as_str()) { continue; }
            slots.push((file, pointer));
        }
    }
    slots.push((
        "event-payload.schema.json",
        "/$defs/consent_expected_current/oneOf/1/properties/commit_id".to_owned(),
    ));
    ensure!(
        slots.len() == 43,
        "converted write inventory drifted: {} slots",
        slots.len()
    );
    for (file, pointer) in slots {
        let document = &documents[file];
        let id = document["$id"].as_str().context("schema id")?;
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&json!({"$ref":format!("{id}#{pointer}")}))
            .map_err(|error| anyhow::anyhow!("guard validator {file}#{pointer}: {error}"))?;
        for current in commits {
            for expected in commits {
                let scalar = json!(expected.commit_id);
                ensure!(
                    validator.is_valid(&scalar),
                    "{file}#{pointer} rejects an actual verified Commit ID"
                );
                let old_pair = json!({"commit_id":expected.commit_id,"stream_position":expected.stream_position});
                ensure!(
                    !validator.is_valid(&old_pair),
                    "{file}#{pointer} restored the retired pair wire"
                );
                let pair_result = (current.commit_id.clone(), current.stream_position)
                    == (expected.commit_id.clone(), expected.stream_position);
                let scalar_result = current.commit_id == expected.commit_id;
                ensure!(
                    pair_result == scalar_result,
                    "legal guard equivalence failed at {file}#{pointer}"
                );
            }
        }
        // Wrong coordinates are outside the legal pair domain. Their removal
        // is an intentional wire-input change, not an additional scalar permit.
        let malformed_pair = json!({"commit_id":commits[0].commit_id,"stream_position":commits[0].stream_position+1});
        ensure!(
            !validator.is_valid(&malformed_pair),
            "malformed pair reached the new write input"
        );
    }
    Ok(())
}
