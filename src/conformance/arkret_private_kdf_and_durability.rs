//! Registered Signal, reaction-routing and nonce KATs for standard MLS.

use std::fs;

use anyhow::{Context, Result, bail};
use arkret_wire::{EventId, ExporterLabelId, RealmId, ScopeRef};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use super::{fixture_path, required_str, required_u64};

const FIXTURE: &str = "arkret-private-kdf-fixture.json";

pub fn run_arkret_private_kdf_and_durability_suite() -> Result<()> {
    let fixture: Value = serde_json::from_slice(&fs::read(fixture_path(FIXTURE))?)?;
    if fixture["runner"]["kind"] != "arkret_private_kdf_and_durability" {
        bail!("private KDF fixture runner kind drifted");
    }
    let cases = fixture["cases"]
        .as_array()
        .context("private KDF cases missing")?;
    if cases.len() != 3 {
        bail!("private KDF fixture must cover exactly three registered vectors");
    }
    run_nonce(case(cases, "full_width_counter_nonce_aes128gcm")?)?;
    run_signal(case(cases, "signal_exporter_key_sha256_aes128gcm")?)?;
    run_reaction(case(cases, "reaction_routing_hmac_nfc")?)?;
    Ok(())
}

fn case<'a>(cases: &'a [Value], name: &str) -> Result<&'a Value> {
    cases
        .iter()
        .find(|case| case["name"] == name)
        .with_context(|| format!("private KDF fixture missing {name}"))
}

fn assert_hex(label: &str, actual: &[u8], expected: &Value, field: &str) -> Result<()> {
    let golden = required_str(expected, field)?;
    if hex::encode(actual) != golden {
        bail!(
            "{label} KAT mismatch: expected {golden}, got {}",
            hex::encode(actual)
        );
    }
    Ok(())
}

fn run_nonce(case: &Value) -> Result<()> {
    let counter = required_u64(&case["input"], "counter")?;
    let nonce_len = required_u64(&case["input"], "aead_nn")? as usize;
    let nonce = arkret_crypto::compose_aead_nonce(counter, nonce_len)?;
    assert_hex(
        "full-width counter nonce",
        &nonce,
        &case["expected"],
        "nonce_hex",
    )?;
    if nonce[..nonce_len - 1]
        .iter()
        .filter(|byte| **byte == 0)
        .count()
        < required_u64(&case["expected"], "high_order_zero_bytes")? as usize
    {
        bail!("counter nonce lost its high-order zero padding");
    }
    Ok(())
}

fn exporter_secret(input: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(required_str(input, "exporter_secret_hex")?)?)
}

fn run_signal(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let realm = RealmId::new(required_str(input, "realm_id_utf8")?.to_owned())?;
    let scope = ScopeRef::Realm { realm_id: realm };
    let scope_context = scope.canonical_effective_scope_key_bytes()?;
    if required_str(input, "signal_root_label")? != ExporterLabelId::SIGNAL_ROOT_V1 {
        bail!("Signal root exporter label drifted");
    }
    let root = arkret::mls::mls_exporter_from_secret(
        &exporter_secret(input)?,
        ExporterLabelId::SIGNAL_ROOT_V1,
        &scope_context,
        arkret::mls::MLS_HASH_LEN,
    )?;
    assert_hex("Signal root", &root, expected, "signal_root_hex")?;
    let key_len = required_u64(input, "aead_nk")? as usize;
    let sender = required_str(input, "verified_sender_domain_utf8")?.as_bytes();
    assert_hex(
        "Signal sender domain",
        sender,
        input,
        "verified_sender_domain_hex",
    )?;
    let info =
        arkret_crypto::mls_exporter::mls_kdf_label(key_len, ExporterLabelId::SIGNAL_V1, sender)?;
    assert_hex(
        "Signal label info",
        &info,
        expected,
        "signal_expand_with_label_info_hex",
    )?;
    let key = arkret::mls::expand_with_registered_label(
        &root,
        ExporterLabelId::SignalV1,
        sender,
        key_len,
    )?;
    assert_hex("Signal sender key", &key, expected, "signal_key_hex")?;
    let peer = required_str(expected, "peer_verified_sender_domain_utf8")?.as_bytes();
    let peer_key =
        arkret::mls::expand_with_registered_label(&root, ExporterLabelId::SignalV1, peer, key_len)?;
    assert_hex(
        "peer Signal key",
        &peer_key,
        expected,
        "peer_signal_key_hex",
    )?;
    if key == peer_key {
        bail!("different verified senders reused a Signal key");
    }
    let wrong_label = arkret_crypto::mls_exporter::mls_expand_with_label(
        &root,
        "ak.content-v1",
        sender,
        key_len,
    )?;
    let empty_context = arkret_crypto::mls_exporter::mls_expand_with_label(
        &root,
        ExporterLabelId::SIGNAL_V1,
        b"",
        key_len,
    )?;
    let mut next_epoch_exporter = exporter_secret(input)?;
    next_epoch_exporter[0] ^= 1;
    let next_epoch_root = arkret::mls::mls_exporter_from_secret(
        &next_epoch_exporter,
        ExporterLabelId::SIGNAL_ROOT_V1,
        &scope_context,
        arkret::mls::MLS_HASH_LEN,
    )?;
    let next_epoch_key = arkret::mls::expand_with_registered_label(
        &next_epoch_root,
        ExporterLabelId::SignalV1,
        sender,
        key_len,
    )?;
    if key.as_slice() == wrong_label.as_slice()
        || key.as_slice() == empty_context.as_slice()
        || key.as_slice() == next_epoch_key.as_slice()
    {
        bail!("Signal label, context, or epoch mutation reused the accepted key");
    }
    let forced_nonce = hex::decode(required_str(expected, "forced_equal_nonce_hex")?)?;
    if forced_nonce.len() != 12 || expected["same_raw_aead_key"] != false {
        bail!("Signal forced-equal-nonce negative control drifted");
    }
    Ok(())
}

fn run_reaction(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let scope: ScopeRef = serde_json::from_value(input["effective_scope"].clone())?;
    let scope_context = scope.canonical_effective_scope_key_bytes()?;
    if required_str(input, "routing_root_label")? != ExporterLabelId::REACTION_ROUTING_ROOT_V1
        || required_str(input, "expand_with_label")? != ExporterLabelId::REACTION_ROUTING_V1
    {
        bail!("reaction routing labels drifted");
    }
    let root = arkret::mls::mls_exporter_from_secret(
        &exporter_secret(input)?,
        ExporterLabelId::REACTION_ROUTING_ROOT_V1,
        &scope_context,
        arkret::mls::MLS_HASH_LEN,
    )?;
    assert_hex("reaction routing root", &root, input, "routing_root_hex")?;
    let context = arkret::mls::ReactionRoutingKeyContext {
        effective_scope: scope,
        target_ref: EventId::new(required_str(input, "target_ref")?.to_owned())?,
        routing_window: required_u64(input, "routing_window")?,
    };
    let canonical = String::from_utf8(arkret_canonical::canonical_json_bytes(&context)?)?;
    if canonical != required_str(input, "routing_context_canonical_json")? {
        bail!("reaction routing context canonicalization drifted");
    }
    let key = arkret::mls::derive_reaction_routing_key(&root, &context)?;
    assert_hex("reaction HMAC key", &key, expected, "routing_hmac_key_hex")?;
    let cases = input["emoji_cases"]
        .as_array()
        .context("reaction emoji cases missing")?;
    let tags = expected["tags_hex"]
        .as_array()
        .context("reaction tags missing")?;
    if cases.len() != tags.len() {
        bail!("reaction emoji case and tag counts differ");
    }
    for (emoji, tag) in cases.iter().zip(tags) {
        let raw = emoji["source_codepoints"]
            .as_array()
            .context("emoji codepoints missing")?
            .iter()
            .map(|value| {
                let scalar = value.as_str().context("emoji scalar missing")?;
                let code = u32::from_str_radix(scalar.trim_start_matches("U+"), 16)?;
                char::from_u32(code).context("invalid emoji scalar")
            })
            .collect::<Result<String>>()?;
        let normalized = raw.nfc().collect::<String>();
        assert_hex("NFC emoji", normalized.as_bytes(), emoji, "nfc_utf8_hex")?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)?;
        mac.update(normalized.as_bytes());
        if hex::encode(mac.finalize().into_bytes()) != tag.as_str().context("tag missing")? {
            bail!("reaction routing HMAC KAT mismatch");
        }
    }
    Ok(())
}
