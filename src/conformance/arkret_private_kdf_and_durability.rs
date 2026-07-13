use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::fixture_path;

const FIXTURE: &str = "arkret-private-kdf-fixture.json";
const MLS_LABEL_PREFIX: &[u8] = b"MLS 1.0 ";

pub fn run_arkret_private_kdf_and_durability_suite() -> Result<()> {
    let path = fixture_path(FIXTURE);
    let fixture: Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;

    if fixture.pointer("/runner/kind").and_then(Value::as_str)
        != Some("arkret_private_kdf_and_durability")
    {
        bail!("arkret private KDF fixture runner kind drifted");
    }

    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| anyhow!("arkret private KDF fixture missing cases[]"))?;
    run_content_kdf(case(cases, "content_key_derivation_sha256_aes256gcm")?)?;
    run_content_negatives(case(cases, "content_key_derivation_fail_closed_negatives")?)?;
    run_reaction_hmac(case(cases, "reaction_routing_hmac_nfc")?)?;
    run_rrk_missing_seals(case(cases, "rrk_eager_seal_before_gc")?)?;
    run_rrk_recipient_validation(case(
        cases,
        "rrk_recipient_method_must_be_active_and_designated",
    )?)?;
    run_rrk_complete_target_set(case(cases, "rrk_threshold_target_set_complete")?)?;
    Ok(())
}

fn run_content_kdf(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let exporter_secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm_id = required_str(input, "realm_id_utf8")?.as_bytes();
    let history_label = required_str(input, "history_label")?;
    let content_label = required_str(input, "content_label")?;
    let nh = required_u64(input, "kdf_nh")? as usize;
    let nk = required_u64(input, "aead_nk")? as usize;

    let history_secret = mls_exporter(&exporter_secret, history_label, realm_id, nh)?;
    assert_hex(
        "history_secret",
        &history_secret,
        expected,
        "history_secret_hex",
    )?;

    let info = kdf_label(nk, content_label, &[])?;
    assert_hex(
        "content ExpandWithLabel info",
        &info,
        expected,
        "content_expand_with_label_info_hex",
    )?;
    let content_key = hkdf_expand(&history_secret, &info, nk)?;
    assert_hex("content_key", &content_key, expected, "content_key_hex")
}

fn run_content_negatives(case: &Value) -> Result<()> {
    let fixture: Value = serde_json::from_slice(&fs::read(fixture_path(FIXTURE))?)?;
    let cases = fixture["cases"].as_array().unwrap();
    let base = case_by_name(cases, required_str(&case["input"], "base_case")?)?;
    let input = &base["input"];
    let secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm = required_str(input, "realm_id_utf8")?.as_bytes();
    let expected = hex::decode(required_str(&base["expected"], "content_key_hex")?)?;

    let swapped_history = mls_exporter(&secret, "ak.content-v1", realm, 32)?;
    let swapped_key = expand_with_label(&swapped_history, "ak.content-v1", &[], 32)?;
    require_different("swapped history label", &swapped_key, &expected)?;

    let history = mls_exporter(&secret, "ak.history-v1", realm, 32)?;
    require_different(
        "swapped content label",
        &expand_with_label(&history, "ak.history-v1", &[], 32)?,
        &expected,
    )?;
    require_different(
        "empty exporter context",
        &expand_with_label(
            &mls_exporter(&secret, "ak.history-v1", &[], 32)?,
            "ak.content-v1",
            &[],
            32,
        )?,
        &expected,
    )?;
    require_different(
        "realm content context",
        &expand_with_label(&history, "ak.content-v1", realm, 32)?,
        &expected,
    )?;

    let next_epoch_secret = Sha256::digest([secret.as_slice(), b"next epoch"].concat());
    let next_history = mls_exporter(&next_epoch_secret, "ak.history-v1", realm, 32)?;
    require_different(
        "next epoch key",
        &expand_with_label(&next_history, "ak.content-v1", &[], 32)?,
        &expected,
    )
}

fn run_reaction_hmac(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm = required_str(input, "realm_id_utf8")?.as_bytes();
    let label = required_str(input, "exporter_label")?;
    let key = mls_exporter(&secret, label, realm, 32)?;
    assert_hex(
        "reaction routing key",
        &key,
        expected,
        "routing_hmac_key_hex",
    )?;

    let emoji_cases = input["emoji_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("reaction fixture missing emoji_cases[]"))?;
    let tags = expected["tags_hex"]
        .as_array()
        .ok_or_else(|| anyhow!("reaction fixture missing tags_hex[]"))?;
    for (index, emoji) in emoji_cases.iter().enumerate() {
        let source = codepoints_to_string(&emoji["source_codepoints"])?;
        let normalized = source.nfc().collect::<String>();
        assert_eq_hex(
            &format!("emoji case {index} NFC"),
            normalized.as_bytes(),
            required_str(emoji, "nfc_utf8_hex")?,
        )?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)?;
        mac.update(normalized.as_bytes());
        assert_eq_hex(
            &format!("emoji case {index} tag"),
            &mac.finalize().into_bytes(),
            tags[index]
                .as_str()
                .ok_or_else(|| anyhow!("reaction tag {index} must be a string"))?,
        )?;
    }

    let decomposed = codepoints_to_string(&emoji_cases[0]["source_codepoints"])?;
    let mut raw_mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)?;
    raw_mac.update(decomposed.as_bytes());
    require_different(
        "reaction without NFC",
        &raw_mac.finalize().into_bytes(),
        &hex::decode(tags[0].as_str().unwrap())?,
    )?;
    require_different(
        "reaction wrong exporter label",
        &mls_exporter(&secret, "arkret-reaction-routing-v0", realm, 32)?,
        &key,
    )?;
    require_different(
        "reaction different realm",
        &mls_exporter(&secret, label, b"ak:realm:different", 32)?,
        &key,
    )
}

#[derive(Debug)]
struct DurabilityState {
    recipients: BTreeSet<String>,
    accepted: BTreeSet<String>,
    history_secret_retained: bool,
}

impl DurabilityState {
    fn gc(&mut self) -> Result<()> {
        if self.accepted != self.recipients {
            bail!("durability_seal_missing_before_gc");
        }
        self.history_secret_retained = false;
        Ok(())
    }
}

fn run_rrk_missing_seals(case: &Value) -> Result<()> {
    let policy = &case["input"]["durability_policy"];
    let mut state = DurabilityState {
        recipients: strings(&policy["recovery_recipients"])?,
        accepted: strings(&case["input"]["accepted_share_recipients"])?,
        history_secret_retained: true,
    };
    let error = state
        .gc()
        .expect_err("GC before every eager seal must fail");
    if !error
        .to_string()
        .contains(required_str(&case["expected"], "reason_code")?)
    {
        bail!("RRK missing-seal rejection reason drifted");
    }
    if !state.history_secret_retained {
        bail!("failed RRK GC discarded the history secret");
    }
    Ok(())
}

fn run_rrk_recipient_validation(case: &Value) -> Result<()> {
    let input = &case["input"];
    let active = required_str(input, "verification_method_state")? == "active";
    let designated =
        required_str(input, "did_service_type")? == "ArkretRealmHistoryRecoveryKey" && active;
    if active && designated {
        bail!("revoked RRK method was unexpectedly accepted");
    }
    if case["expected"]["must_not_fallback_to_other_key"].as_bool() != Some(true) {
        bail!("RRK fixture no longer pins no-fallback behavior");
    }
    Ok(())
}

fn run_rrk_complete_target_set(case: &Value) -> Result<()> {
    let input = &case["input"];
    let recipient_count = required_u64(input, "recipient_count")?;
    let accepted_count = required_u64(input, "accepted_share_count")?;
    let threshold = required_u64(input, "threshold")?;
    let required_targets = required_u64(&case["expected"], "required_share_target_count")?;
    if threshold >= recipient_count || required_targets != recipient_count {
        bail!("threshold incorrectly reduced the eager-seal target set");
    }
    if accepted_count != required_targets
        || input["accepted_share_recipients_unique"].as_bool() != Some(true)
    {
        bail!("RRK GC accepted an incomplete or duplicate target set");
    }
    Ok(())
}

fn mls_exporter(secret: &[u8], label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
    let derived = expand_with_label(secret, label, &[], 32)?;
    let context_hash = Sha256::digest(context);
    expand_with_label(&derived, "exported", &context_hash, length)
}

fn expand_with_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
    hkdf_expand(secret, &kdf_label(length, label, context)?, length)
}

fn hkdf_expand(secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| anyhow!("invalid HKDF PRK"))?;
    let mut output = vec![0; length];
    hkdf.expand(info, &mut output)
        .map_err(|_| anyhow!("HKDF output length invalid"))?;
    Ok(output)
}

fn kdf_label(length: usize, label: &str, context: &[u8]) -> Result<Vec<u8>> {
    let length = u16::try_from(length).context("KDF output length exceeds uint16")?;
    let full_label = [MLS_LABEL_PREFIX, label.as_bytes()].concat();
    let mut out = length.to_be_bytes().to_vec();
    out.extend(encode_varint(full_label.len())?);
    out.extend(full_label);
    out.extend(encode_varint(context.len())?);
    out.extend(context);
    Ok(out)
}

fn encode_varint(value: usize) -> Result<Vec<u8>> {
    if value < 64 {
        Ok(vec![value as u8])
    } else if value < 16_384 {
        Ok(((value as u16) | 0x4000).to_be_bytes().to_vec())
    } else if value < (1 << 30) {
        Ok(((value as u32) | 0x8000_0000).to_be_bytes().to_vec())
    } else {
        bail!("MLS varint value too large")
    }
}

fn codepoints_to_string(value: &Value) -> Result<String> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("source_codepoints must be an array"))?
        .iter()
        .map(|value| {
            let raw = value
                .as_str()
                .ok_or_else(|| anyhow!("codepoint must be a string"))?;
            let scalar = u32::from_str_radix(raw.trim_start_matches("U+"), 16)?;
            char::from_u32(scalar).ok_or_else(|| anyhow!("invalid Unicode scalar {raw}"))
        })
        .collect()
}

fn case<'a>(cases: &'a [Value], name: &str) -> Result<&'a Value> {
    case_by_name(cases, name)
}

fn case_by_name<'a>(cases: &'a [Value], name: &str) -> Result<&'a Value> {
    cases
        .iter()
        .find(|case| case["name"].as_str() == Some(name))
        .ok_or_else(|| anyhow!("fixture missing case {name}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| anyhow!("missing integer field {field}"))
}

fn strings(value: &Value) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("expected string array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("array member must be a string"))
        })
        .collect()
}

fn assert_hex(label: &str, actual: &[u8], expected: &Value, field: &str) -> Result<()> {
    assert_eq_hex(label, actual, required_str(expected, field)?)
}

fn assert_eq_hex(label: &str, actual: &[u8], expected_hex: &str) -> Result<()> {
    let expected = hex::decode(expected_hex)?;
    if actual != expected {
        bail!(
            "{label} mismatch: expected {expected_hex}, got {}",
            hex::encode(actual)
        );
    }
    Ok(())
}

fn require_different(label: &str, actual: &[u8], golden: &[u8]) -> Result<()> {
    if actual == golden {
        bail!("negative mutation {label} reproduced the golden bytes");
    }
    Ok(())
}
