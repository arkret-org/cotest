//! Registered canonical-JSON digest constructions and their known answers.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::{
    canonical_json, load_artifact_json, load_fixture_value, required_field, required_str,
    sha256_prefixed, value_array,
};

pub const CANONICAL_JSON_DIGEST_DOMAINS: [&str; 5] = [
    "ak.accountability_scope_set.v1",
    "ak.contact.glare_unconsumed_slot.v1",
    "ak.contact.no_outgoing_slot.v1",
    "ak.contact.request_acceptance_core.v1",
    "ak.contact.request_source_checkpoint.v1",
];

struct Kat {
    transcript: Value,
    canonical: String,
    expected_digest: String,
}

pub fn run_digest_construction_known_answers() -> Result<()> {
    let registry = load_artifact_json("registry/proof-context-registry.json")?;
    let constructions = value_array(
        required_field(&registry, "digest_constructions")?,
        "digest_constructions",
    )?;
    let construction_ids = constructions
        .iter()
        .map(|row| required_str(row, "construction_id"))
        .collect::<Result<BTreeSet<_>>>()?;

    let kats = load_kats()?;
    ensure!(
        kats.len() == CANONICAL_JSON_DIGEST_DOMAINS.len(),
        "known-answer map does not cover every registered digest domain"
    );

    let rows = value_array(
        required_field(&registry, "domain_separations")?,
        "domain_separations",
    )?;
    let mut executed = BTreeSet::new();
    for row in rows
        .iter()
        .filter(|row| row.get("primitive").and_then(Value::as_str) == Some("canonical_json_sha256"))
    {
        let domain = required_str(row, "domain")?;
        ensure!(
            CANONICAL_JSON_DIGEST_DOMAINS.contains(&domain),
            "unowned canonical_json_sha256 domain {domain}"
        );
        ensure!(executed.insert(domain), "duplicate digest domain {domain}");
        let construction = required_str(row, "digest_construction")?;
        ensure!(
            construction_ids.contains(construction),
            "{domain}: unknown digest construction {construction}"
        );

        let prefix = format!("{domain}\n");
        ensure!(
            hex::encode(prefix.as_bytes()) == required_str(row, "prefix_bytes_hex")?,
            "{domain}: prefix bytes are not recomputed from domain + LF"
        );
        let kat = kats
            .get(domain)
            .ok_or_else(|| anyhow!("{domain}: no executable known answer"))?;
        ensure!(
            canonical_json(&kat.transcript)? == kat.canonical,
            "{domain}: SDK JCS bytes differ from the fixture"
        );
        let mut digest_input = prefix.into_bytes();
        digest_input.extend_from_slice(kat.canonical.as_bytes());
        ensure!(
            sha256_prefixed(&digest_input) == kat.expected_digest,
            "{domain}: digest known answer failed"
        );

        let transcript_keys = kat
            .transcript
            .as_object()
            .ok_or_else(|| anyhow!("{domain}: transcript must be an object"))?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let binding_fields = value_array(required_field(row, "binding_fields")?, "binding_fields")?
            .iter()
            .map(|field| {
                field
                    .as_str()
                    .map(|field| field.trim_end_matches('?'))
                    .ok_or_else(|| anyhow!("{domain}: binding field must be a string"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            transcript_keys.is_subset(&binding_fields),
            "{domain}: transcript contains a field outside binding_fields"
        );
    }
    ensure!(
        executed == CANONICAL_JSON_DIGEST_DOMAINS.into_iter().collect(),
        "canonical_json_sha256 domain coverage drifted: {executed:?}"
    );
    Ok(())
}

fn load_kats() -> Result<BTreeMap<String, Kat>> {
    let fixture = load_fixture_value("canonical-json-digest-kat-fixture.json")?;
    let mut kats = BTreeMap::new();
    for case in value_array(required_field(&fixture, "cases")?, "cases")? {
        let domain = required_str(case, "domain")?.to_owned();
        kats.insert(
            domain,
            Kat {
                transcript: required_field(case, "transcript")?.clone(),
                canonical: required_str(case, "canonical_transcript_utf8")?.to_owned(),
                expected_digest: required_str(case, "expected_digest")?.to_owned(),
            },
        );
    }

    let contact = load_fixture_value("contact-round-kat.json")?;
    let absence = contact
        .pointer("/outgoing_slot_absence/case")
        .ok_or_else(|| anyhow!("contact-round KAT lost outgoing_slot_absence.case"))?;
    kats.insert(
        "ak.contact.no_outgoing_slot.v1".to_owned(),
        Kat {
            transcript: required_field(absence, "transcript")?.clone(),
            canonical: required_str(absence, "canonical_transcript")?.to_owned(),
            expected_digest: required_str(absence, "expected_digest")?.to_owned(),
        },
    );
    let acceptance = contact
        .pointer("/producer_signer_kat/cases/0/signed_object")
        .ok_or_else(|| anyhow!("contact-round KAT lost producer signer case"))?;
    let core = required_field(acceptance, "core")?.clone();
    kats.insert(
        "ak.contact.request_acceptance_core.v1".to_owned(),
        Kat {
            canonical: canonical_json(&core)?,
            transcript: core,
            expected_digest: required_str(acceptance, "receipt_digest")?.to_owned(),
        },
    );
    Ok(kats)
}
