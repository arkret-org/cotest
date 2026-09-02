use std::fs;

use aes_gcm::aead::{Aead, KeyInit as AesKeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use arkret_models_crypto::EventContentPreEncryptionHeader;
use arkret_wire::{EventId, ScopeRef};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::{fixture_path, required_str, required_u64};

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
    run_content_kdf(case(
        cases,
        "content_key_derivation_ordinary_sender_sha256_aes128gcm",
    )?)?;
    run_content_kdf(case(
        cases,
        "content_key_derivation_minimal_metadata_sender_sha256_aes128gcm",
    )?)?;
    run_content_sender_isolation(cases)?;
    run_content_negatives(case(cases, "content_key_derivation_fail_closed_negatives")?)?;
    run_reaction_hmac(case(cases, "reaction_routing_hmac_nfc")?)?;
    run_signal_exporter_key(case(cases, "signal_exporter_key_sha256_aes128gcm")?)?;
    run_full_width_counter_nonce(case(cases, "full_width_counter_nonce_aes128gcm")?)?;
    run_exporter_aead_seal_open(case(cases, "mls_exporter_aead_seal_open_transcript")?)?;
    Ok(())
}

fn run_content_kdf(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let exporter_secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm_id = required_str(input, "realm_id_utf8")?.as_bytes();
    let history_label = required_str(input, "history_label")?;
    let content_label = required_str(input, "content_label")?;
    let sender_domain = required_str(input, "verified_sender_domain_utf8")?.as_bytes();
    let nh = required_u64(input, "kdf_nh")? as usize;
    let nk = required_u64(input, "aead_nk")? as usize;

    let history_secret = mls_exporter(&exporter_secret, history_label, realm_id, nh)?;
    assert_hex(
        "history_secret",
        &history_secret,
        expected,
        "history_secret_hex",
    )?;

    assert_hex(
        "verified sender domain",
        sender_domain,
        input,
        "verified_sender_domain_hex",
    )?;
    let info = kdf_label(nk, content_label, sender_domain)?;
    assert_hex(
        "content ExpandWithLabel info",
        &info,
        expected,
        "content_expand_with_label_info_hex",
    )?;
    let content_key =
        arkret::mls::derive_content_key_from_history_secret(&history_secret, sender_domain, nk)
            .map_err(|error| anyhow!("SDK content-key derivation failed: {error}"))?;
    assert_hex("content_key", &content_key, expected, "content_key_hex")
}

fn run_content_sender_isolation(cases: &[Value]) -> Result<()> {
    let ordinary = case(
        cases,
        "content_key_derivation_ordinary_sender_sha256_aes128gcm",
    )?;
    let minimal = case(
        cases,
        "content_key_derivation_minimal_metadata_sender_sha256_aes128gcm",
    )?;
    let history_secret = hex::decode(required_str(&ordinary["expected"], "history_secret_hex")?)?;
    if history_secret != hex::decode(required_str(&minimal["expected"], "history_secret_hex")?)? {
        bail!("sender-isolation KATs must share one history secret");
    }
    let key_len = required_u64(&ordinary["input"], "aead_nk")? as usize;
    let ordinary_domain =
        required_str(&ordinary["input"], "verified_sender_domain_utf8")?.as_bytes();
    let minimal_domain = required_str(&minimal["input"], "verified_sender_domain_utf8")?.as_bytes();
    let ordinary_key = arkret::mls::derive_content_key_from_history_secret(
        &history_secret,
        ordinary_domain,
        key_len,
    )?;
    let minimal_key = arkret::mls::derive_content_key_from_history_secret(
        &history_secret,
        minimal_domain,
        key_len,
    )?;
    if ordinary_key.as_slice() == minimal_key.as_slice() {
        bail!("ordinary and minimal-metadata sender domains reused one content key");
    }
    Ok(())
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
    let sender_domain = required_str(input, "verified_sender_domain_utf8")?.as_bytes();
    let key_len = required_u64(input, "aead_nk")? as usize;

    assert_hex(
        "verified sender domain",
        sender_domain,
        input,
        "verified_sender_domain_hex",
    )?;
    let info = kdf_label(key_len, required_str(input, "signal_label")?, sender_domain)?;
    assert_hex(
        "signal ExpandWithLabel info",
        &info,
        expected,
        "signal_expand_with_label_info_hex",
    )?;

    let signal_key = arkret::mls::derive_signal_exporter_key(
        &exporter_secret,
        &realm_id,
        sender_domain,
        key_len,
    )
    .map_err(|error| anyhow!("SDK signal exporter key derivation failed: {error}"))?;
    assert_hex("signal_key", &signal_key, expected, "signal_key_hex")?;

    let peer_sender_domain = required_str(expected, "peer_verified_sender_domain_utf8")?.as_bytes();
    let peer_key = arkret::mls::derive_signal_exporter_key(
        &exporter_secret,
        &realm_id,
        peer_sender_domain,
        key_len,
    )
    .map_err(|error| anyhow!("SDK collision-peer Signal key derivation failed: {error}"))?;
    assert_hex(
        "collision peer signal key",
        &peer_key,
        expected,
        "peer_signal_key_hex",
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

/// `ak.vector.aead.full_width_counter_nonce.v1` — the §10.1 canonical
/// `I2OSP(counter, AEAD.Nn)` encoding and its fail-closed boundaries.
fn run_full_width_counter_nonce(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let counter = required_u64(input, "counter")?;
    let nonce_len = required_u64(input, "aead_nn")? as usize;
    if required_str(input, "encoding")? != "I2OSP(counter, AEAD.Nn)" {
        bail!("registered full-width nonce encoding drifted");
    }
    let nonce = arkret_crypto::compose_aead_nonce(counter, nonce_len)?;
    assert_hex("nonce", &nonce, expected, "nonce_hex")?;
    let high_order_zero_bytes = nonce.iter().take_while(|byte| **byte == 0).count();
    if required_u64(expected, "high_order_zero_bytes")? as usize != high_order_zero_bytes {
        bail!("full-width nonce leading-zero count drifted");
    }

    let mutations = expected
        .get("negative_mutations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("full-width nonce KAT omits negative_mutations[]"))?;
    let expected_mutations = [
        "nonzero_high_order_padding",
        "counter_reuse_with_different_ciphertext",
        "counter_rollback",
        "counter_increment_after_u64_max",
    ];
    if mutations
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        != expected_mutations
        || required_str(expected, "negative_decision")? != "reject"
    {
        bail!("full-width nonce negative mutation registry drifted");
    }

    let context = arkret_crypto::AeadNonceContext {
        mls_group_id: "cotest-full-width-counter".to_owned(),
        epoch: 1,
        sender_domain: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
    };
    let mut malformed = nonce.clone();
    malformed[0] = 1;
    arkret_crypto::verify_aead_sender_nonce(&context, &malformed, nonce_len, None)
        .expect_err("non-zero high-order I2OSP padding must be rejected");
    let mut replay = arkret_crypto::AeadNonceReplayTracker::new();
    arkret_crypto::verify_aead_sender_nonce(&context, &nonce, nonce_len, Some(&mut replay))?;
    arkret_crypto::verify_aead_sender_nonce(&context, &nonce, nonce_len, Some(&mut replay))
        .expect_err("a reused sender counter must be rejected");
    if counter.checked_sub(1).is_none() || u64::MAX.checked_add(1).is_some() {
        bail!("durable sender counter arithmetic boundary drifted");
    }
    Ok(())
}

fn run_content_negatives(case: &Value) -> Result<()> {
    let fixture: Value = serde_json::from_slice(&fs::read(fixture_path(FIXTURE))?)?;
    let cases = fixture["cases"].as_array().unwrap();
    let declared_base = required_str(&case["input"], "base_case")?;
    let base = case_by_name(cases, declared_base)?;
    let input = &base["input"];
    let secret = hex::decode(required_str(input, "exporter_secret_hex")?)?;
    let realm = required_str(input, "realm_id_utf8")?.as_bytes();
    let sender_domain = required_str(input, "verified_sender_domain_utf8")?.as_bytes();
    let nh = required_u64(input, "kdf_nh")? as usize;
    let nk = required_u64(input, "aead_nk")? as usize;
    let expected = hex::decode(required_str(&base["expected"], "content_key_hex")?)?;

    let swapped_history = mls_exporter(&secret, "ak.content-v1", realm, nh)?;
    let swapped_key = expand_with_label(&swapped_history, "ak.content-v1", sender_domain, nk)?;
    require_different("swapped history label", &swapped_key, &expected)?;

    let history = mls_exporter(&secret, "ak.history-v1", realm, nh)?;
    require_different(
        "swapped content label",
        &expand_with_label(&history, "ak.history-v1", sender_domain, nk)?,
        &expected,
    )?;
    require_different(
        "empty exporter context",
        &expand_with_label(
            &mls_exporter(&secret, "ak.history-v1", &[], nh)?,
            "ak.content-v1",
            sender_domain,
            nk,
        )?,
        &expected,
    )?;
    require_different(
        "unverified sender domain",
        &expand_with_label(
            &history,
            "ak.content-v1",
            b"ak:device:01904100-0000-7000-8000-00000000ffff",
            nk,
        )?,
        &expected,
    )?;
    if arkret::mls::derive_content_key_from_history_secret(&history, &[], nk).is_ok() {
        bail!("empty verified sender domain was accepted");
    }

    let next_epoch_secret = Sha256::digest([secret.as_slice(), b"next epoch"].concat());
    let next_history = mls_exporter(&next_epoch_secret, "ak.history-v1", realm, nh)?;
    require_different(
        "next epoch key",
        &expand_with_label(&next_history, "ak.content-v1", sender_domain, nk)?,
        &expected,
    )
}

fn run_exporter_aead_seal_open(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let history_secret = hex::decode(required_str(input, "history_secret_hex")?)?;
    let sender_domain = required_str(input, "verified_sender_domain")?.as_bytes();
    let content_key =
        arkret::mls::derive_content_key_from_history_secret(&history_secret, sender_domain, 16)?;
    assert_hex(
        "exporter AEAD content key",
        &content_key,
        input,
        "content_key_hex",
    )?;
    let header: EventContentPreEncryptionHeader =
        serde_json::from_value(expected["reconstructed_pre_encryption_header"].clone())?;
    let aad = header.canonical_bytes()?;
    if aad != required_str(expected, "aead_aad_canonical_json")?.as_bytes() {
        bail!("exporter AEAD canonical AAD drifted");
    }
    let counter = required_u64(
        &input["wire_envelope_without_ciphertext"]["encryption_context"],
        "counter",
    )?;
    let nonce = arkret_crypto::compose_aead_nonce(counter, 12)?;
    assert_hex("exporter AEAD nonce", &nonce, expected, "derived_nonce_hex")?;
    let plaintext = hex::decode(required_str(input, "plaintext_hex")?)?;
    let cipher = Aes128Gcm::new_from_slice(&content_key)
        .map_err(|_| anyhow!("invalid exporter AES-128-GCM content key"))?;
    let nonce = Nonce::try_from(nonce.as_slice())
        .map_err(|_| anyhow!("invalid exporter AES-128-GCM nonce"))?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("independent exporter AEAD seal failed"))?;
    assert_hex(
        "exporter AEAD ciphertext",
        &ciphertext,
        expected,
        "ciphertext_with_tag_hex",
    )?;
    let aead_profile = required_str(&input["exact_group_state"], "ciphersuite_id")?;
    let opened = arkret::mls::decrypt_content_exporter_aead_standalone(
        &history_secret,
        sender_domain,
        &header,
        aead_profile,
        &ciphertext,
    )?;
    assert_hex(
        "exporter AEAD opened plaintext",
        &opened,
        expected,
        "opened_plaintext_hex",
    )?;

    let required_mutations = [
        "envelope_version",
        "content_type",
        "outer_event.kind",
        "outer_event.effective_scope",
        "producer_verification_method",
        "group_state_ref",
        "content_scheme",
        "counter",
        "ciphertext_tag",
    ];
    if strings_in_order(&expected["negative_mutations"])? != required_mutations
        || required_str(expected, "negative_decision")? != "reject"
    {
        bail!("exporter AEAD negative mutation set drifted");
    }
    for (field, replacement) in [
        ("envelope_version", serde_json::json!("1.1")),
        ("content_type", serde_json::json!("application/json")),
        ("event_kind", serde_json::json!("ak.message.edit")),
        (
            "effective_scope",
            serde_json::json!({
                "kind": "realm",
                "realm_id": "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN"
            }),
        ),
        (
            "sender_domain",
            serde_json::json!("ak:device:019a7360-0000-7000-8000-000000000002"),
        ),
        (
            "group_state_ref",
            serde_json::json!("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ),
        ("scheme", serde_json::json!("mls_rfc9420")),
        ("counter", serde_json::json!(8)),
    ] {
        let mut mutated = serde_json::to_value(&header)?;
        mutated[field] = replacement;
        if let Ok(mutated) = serde_json::from_value::<EventContentPreEncryptionHeader>(mutated) {
            arkret::mls::decrypt_content_exporter_aead_standalone(
                &history_secret,
                sender_domain,
                &mutated,
                aead_profile,
                &ciphertext,
            )
            .expect_err("mutated exporter AEAD AAD must fail closed");
        }
    }
    let mut tampered = ciphertext;
    *tampered
        .last_mut()
        .context("exporter AEAD ciphertext is empty")? ^= 1;
    arkret::mls::decrypt_content_exporter_aead_standalone(
        &history_secret,
        sender_domain,
        &header,
        aead_profile,
        &tampered,
    )
    .expect_err("mutated exporter AEAD tag must fail closed");
    Ok(())
}

fn run_reaction_hmac(case: &Value) -> Result<()> {
    let input = &case["input"];
    let expected = &case["expected"];
    let routing_root = hex::decode(required_str(input, "routing_root_hex")?)?;
    let scope: ScopeRef = serde_json::from_value(input["effective_scope"].clone())?;
    let target_ref = EventId::new(required_str(input, "target_ref")?)?;
    let routing_window = required_u64(input, "routing_window")?;
    let context = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "effective_scope": scope,
        "target_ref": target_ref,
        "routing_window": routing_window,
    }))?;
    if context != required_str(input, "routing_context_canonical_json")?.as_bytes() {
        bail!("reaction routing context canonical bytes drifted");
    }
    let key = expand_with_label(&routing_root, "ak.reaction-routing-v1", &context, 32)?;
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
        let production_tag = arkret::mls::reaction_routing_tag_from_root(
            &routing_root,
            &scope,
            &target_ref,
            routing_window,
            &source,
        )?;
        assert_eq_hex(
            &format!("emoji case {index} production tag"),
            &URL_SAFE_NO_PAD.decode(production_tag)?,
            tags[index]
                .as_str()
                .ok_or_else(|| anyhow!("reaction tag {index} must be a string"))?,
        )?;
    }

    let decomposed = codepoints_to_string(&emoji_cases[0]["source_codepoints"])?;
    let normalized = decomposed.nfc().collect::<String>();
    let original_tag = URL_SAFE_NO_PAD.decode(arkret::mls::reaction_routing_tag_from_root(
        &routing_root,
        &scope,
        &target_ref,
        routing_window,
        &decomposed,
    )?)?;
    let mut raw_mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)?;
    raw_mac.update(decomposed.as_bytes());
    require_different(
        "reaction without NFC",
        &raw_mac.finalize().into_bytes(),
        &hex::decode(tags[0].as_str().unwrap())?,
    )?;
    require_different(
        "reaction wrong exporter label",
        &expand_with_label(&routing_root, "ak.content-v1", &context, 32)?,
        &key,
    )?;
    let other_scope: ScopeRef = serde_json::from_value(serde_json::json!({
        "kind": "realm",
        "realm_id": "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
    }))?;
    let other_scope_tag = URL_SAFE_NO_PAD.decode(arkret::mls::reaction_routing_tag_from_root(
        &routing_root,
        &other_scope,
        &target_ref,
        routing_window,
        &normalized,
    )?)?;
    require_different(
        "reaction different effective scope",
        &other_scope_tag,
        &original_tag,
    )?;

    let other_target = EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
    let other_target_tag = URL_SAFE_NO_PAD.decode(arkret::mls::reaction_routing_tag_from_root(
        &routing_root,
        &scope,
        &other_target,
        routing_window,
        &normalized,
    )?)?;
    require_different(
        "reaction different target",
        &other_target_tag,
        &original_tag,
    )?;

    let other_context = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "effective_scope": scope,
        "target_ref": target_ref,
        "routing_window": routing_window + 1,
    }))?;
    require_different(
        "reaction different routing window",
        &expand_with_label(&routing_root, "ak.reaction-routing-v1", &other_context, 32)?,
        &key,
    )?;
    let other_window_tag = URL_SAFE_NO_PAD.decode(arkret::mls::reaction_routing_tag_from_root(
        &routing_root,
        &scope,
        &target_ref,
        routing_window + 1,
        &normalized,
    )?)?;
    require_different(
        "reaction different routing-window tag",
        &other_window_tag,
        &original_tag,
    )?;

    let mut next_epoch_root = routing_root;
    next_epoch_root[0] ^= 1;
    let next_epoch_tag = URL_SAFE_NO_PAD.decode(arkret::mls::reaction_routing_tag_from_root(
        &next_epoch_root,
        &scope,
        &target_ref,
        routing_window,
        &normalized,
    )?)?;
    require_different("reaction next-epoch root", &next_epoch_tag, &original_tag)?;

    if strings_in_order(&expected["negative_mutations"])?
        != [
            "skip_NFC",
            "wrong_exporter_label",
            "different_effective_scope",
            "different_target_ref",
            "different_routing_window",
            "reuse_key_after_epoch_change",
        ]
        || required_str(expected, "negative_decision")? != "reject"
    {
        bail!("reaction routing negative mutation set drifted");
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

fn strings_in_order(value: &Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("expected string array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
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
