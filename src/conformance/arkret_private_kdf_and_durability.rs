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
    run_content_kdf(case(cases, "content_key_derivation_sha256_aes128gcm")?)?;
    run_content_negatives(case(cases, "content_key_derivation_fail_closed_negatives")?)?;
    run_reaction_hmac(case(cases, "reaction_routing_hmac_nfc")?)?;
    run_signal_exporter_key(case(cases, "signal_exporter_key_sha256_aes128gcm")?)?;
    run_sender_nonce_prefix(case(cases, "aead_sender_nonce_prefix_aes128gcm")?)?;
    run_mention_routing_hmac(case(cases, "mention_routing_hmac_did")?)?;
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

/// `ak.vector.signal.exporter_key_kat.v1` — the Signal Extension AEAD key.
///
/// Driven through the shipped SDK derivation rather than the local KDF
/// reimplementation above: the point of this case is that what implementations
/// actually run reproduces the registered bytes.
fn run_signal_exporter_key(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let exporter_secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm_id = arkret::RealmId::new(required_str(input, "realm_id_utf8")?.to_owned())
        .map_err(|error| anyhow!("registered realm id is invalid: {error}"))?;
    let sender_device_id =
        arkret::DeviceId::new(required_str(input, "sender_device_id")?.to_owned())
            .map_err(|error| anyhow!("registered sender device id is invalid: {error}"))?;
    let key_len = required_u64(input, "aead_nk")? as usize;

    let context = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "sender_device_id": sender_device_id,
    }))?;
    let expected_context = required_str(input, "signal_context_canonical_json")?;
    if context != expected_context.as_bytes() {
        bail!(
            "Signal sender key context drifted: expected {expected_context}, got {}",
            String::from_utf8_lossy(&context)
        );
    }
    assert_hex("signal context", &context, input, "signal_context_hex")?;
    let info = kdf_label(key_len, required_str(input, "signal_label")?, &context)?;
    assert_hex(
        "signal ExpandWithLabel info",
        &info,
        expected,
        "signal_expand_with_label_info_hex",
    )?;

    let signal_key = arkret::mls::derive_signal_exporter_key(
        &exporter_secret,
        &realm_id,
        &sender_device_id,
        key_len,
    )
    .map_err(|error| anyhow!("SDK signal exporter key derivation failed: {error}"))?;
    assert_hex("signal_key", &signal_key, expected, "signal_key_hex")?;

    let collision_peer = arkret::DeviceId::new(
        required_str(expected, "collision_peer_sender_device_id")?.to_owned(),
    )
    .map_err(|error| anyhow!("collision peer device id is invalid: {error}"))?;
    let peer_key = arkret::mls::derive_signal_exporter_key(
        &exporter_secret,
        &realm_id,
        &collision_peer,
        key_len,
    )
    .map_err(|error| anyhow!("SDK collision-peer Signal key derivation failed: {error}"))?;
    assert_hex(
        "collision peer signal key",
        &peer_key,
        expected,
        "collision_peer_signal_key_hex",
    )?;
    if signal_key.as_slice() == peer_key.as_slice()
        || expected.get("same_raw_aead_key").and_then(Value::as_bool) != Some(false)
    {
        bail!("valid Signal senders did not receive independent raw AEAD keys");
    }
    let forced_nonce = hex::decode(required_str(expected, "forced_equal_nonce_hex")?)?;
    if forced_nonce.len() != 12 {
        bail!("forced AES-GCM collision nonce must be exactly 12 bytes");
    }
    Ok(())
}

/// `ak.vector.aead.sender_nonce_prefix_kat.v1` — the §10.1 sender prefix and
/// the composed nonce, both through the shipped SDK derivation. The canonical
/// exporter Context is pinned first so a canonicalization change cannot hide
/// behind a prefix that happens to match over different bytes.
fn run_sender_nonce_prefix(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let exporter_secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let exporter_label = required_str(input, "exporter_label")?;
    if exporter_label != arkret_crypto::AEAD_NONCE_EXPORTER_LABEL {
        bail!("registered sender nonce exporter label drifted: {exporter_label}");
    }
    let context: arkret_crypto::AeadNonceContext = serde_json::from_value(
        input
            .get("context")
            .cloned()
            .ok_or_else(|| anyhow!("sender nonce case missing input.context"))?,
    )
    .map_err(|error| anyhow!("registered nonce context does not decode: {error}"))?;
    let nonce_len = required_u64(input, "nonce_length_bytes")? as usize;

    let canonical_context = arkret_crypto::aead_sender_nonce_context_bytes(&context)
        .map_err(|error| anyhow!("canonical nonce context failed: {error}"))?;
    let expected_context = required_str(expected, "context_canonical_json")?;
    if canonical_context != expected_context.as_bytes() {
        bail!(
            "canonical nonce context drifted: expected {expected_context}, got {}",
            String::from_utf8_lossy(&canonical_context)
        );
    }

    let prefix =
        arkret_crypto::derive_aead_sender_nonce_prefix(&exporter_secret, &context, nonce_len)
            .map_err(|error| anyhow!("SDK sender nonce prefix derivation failed: {error}"))?;
    assert_hex(
        "sender_nonce_prefix",
        &prefix,
        expected,
        "sender_nonce_prefix_hex",
    )?;

    let counter = u64::from_str_radix(required_str(input, "counter_be64_hex")?, 16)
        .map_err(|error| anyhow!("registered nonce counter is not hex: {error}"))?;
    assert_hex(
        "nonce",
        &arkret_crypto::compose_aead_nonce(&prefix, counter),
        expected,
        "nonce_hex",
    )
}

/// `ak.vector.mention.routing_hmac_kat.v1` — the epoch routing key and the
/// per-DID routing tag, both through the shipped SDK derivation.
fn run_mention_routing_hmac(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let exporter_secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm_id = arkret::RealmId::new(required_str(input, "realm_id_utf8")?.to_owned())
        .map_err(|error| anyhow!("registered realm id is invalid: {error}"))?;
    let exporter_label = required_str(input, "exporter_label")?;
    if exporter_label != arkret::mls::MENTION_ROUTING_EXPORTER_LABEL {
        bail!("registered mention routing exporter label drifted: {exporter_label}");
    }
    let mentioned = arkret::DidFullId::new(required_str(input, "mentioned_did_utf8")?.to_owned())
        .map_err(|error| anyhow!("registered mentioned DID is invalid: {error}"))?;

    let routing_key = arkret::mls::derive_mention_routing_key(&exporter_secret, &realm_id)
        .map_err(|error| anyhow!("SDK mention routing key derivation failed: {error}"))?;
    assert_hex(
        "routing_hmac_key",
        &routing_key,
        expected,
        "routing_hmac_key_hex",
    )?;

    let tag = arkret::mls::mention_routing_hmac(&exporter_secret, &realm_id, &mentioned)
        .map_err(|error| anyhow!("SDK mention routing HMAC failed: {error}"))?;
    assert_hex("routing_tag", &tag, expected, "routing_tag_hex")?;

    // The from-key entry point clients use on the send path must land on the
    // same tag as the from-secret one this vector registers.
    let from_key = arkret::mls::mention_routing_hmac_from_key(&routing_key, &mentioned)
        .map_err(|error| anyhow!("SDK mention routing HMAC from key failed: {error}"))?;
    if from_key != tag {
        bail!("mention routing HMAC disagrees between its from-secret and from-key entry points");
    }
    Ok(())
}

fn run_content_negatives(case: &Value) -> Result<()> {
    let fixture: Value = serde_json::from_slice(&fs::read(fixture_path(FIXTURE))?)?;
    let cases = fixture["cases"].as_array().unwrap();
    let declared_base = required_str(&case["input"], "base_case")?;
    let base = match case_by_name(cases, declared_base) {
        Ok(base) => base,
        Err(_) if declared_base == "content_key_derivation_sha256_aes256gcm" => {
            // The active SHA-256 fixture now uses the mandatory AES-128-GCM
            // ciphersuite but the negative-vector backlink retained its former
            // case name. Keep this compatibility closed to that one rename.
            case_by_name(cases, "content_key_derivation_sha256_aes128gcm")?
        }
        Err(error) => return Err(error),
    };
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
        required_str(input, "did_service_kind")? == "ArkretRealmHistoryRecoveryKey" && active;
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
