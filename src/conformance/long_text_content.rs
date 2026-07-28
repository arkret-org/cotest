use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::events_payloads::message::{
    CONTENT_TEXT_INLINE_MAX_BYTES, ContentBlock, LONG_TEXT_FALLBACK_MAX_BYTES, LongTextBodyKind,
    LongTextFormat, long_text_line_count, long_text_prefix, normalize_long_text,
};
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

const FIXTURE: &str = "long-text-content-fixture.json";
const PROFILE: &str = "ak.profile.chat_mvp.v1";

pub fn run_long_text_content_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    validate_profile(&fixture, PROFILE)?;
    if fixture.get("suite").and_then(Value::as_str) != Some("long_text_content")
        || fixture.pointer("/runner/kind").and_then(Value::as_str) != Some("generated_limit_cases")
    {
        bail!("long-text fixture runner metadata drifted");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("long-text fixture missing cases[]"))?;
    for case in cases {
        let generator = case
            .pointer("/input/generator")
            .or_else(|| case.pointer("/given_state/generator"))
            .ok_or_else(|| anyhow!("long-text case missing generator"))?;
        match required_str(generator, "kind")? {
            "normalized_utf8_content_block_matrix" => {
                if generator.get("inline_limit_bytes").and_then(Value::as_u64)
                    != Some(CONTENT_TEXT_INLINE_MAX_BYTES as u64)
                    || generator
                        .get("fallback_limit_bytes")
                        .and_then(Value::as_u64)
                        != Some(LONG_TEXT_FALLBACK_MAX_BYTES as u64)
                {
                    bail!("long-text UTF-8 limits drifted from the SDK");
                }
                let multibyte = "\u{4e2d}".repeat(1_400);
                let prefix = long_text_prefix(&multibyte);
                if prefix.len() > LONG_TEXT_FALLBACK_MAX_BYTES
                    || !multibyte.is_char_boundary(prefix.len())
                {
                    bail!("long-text prefix split a Unicode scalar");
                }
            }
            "long_text_selection" => {
                let body = generator["normalized_body_bytes"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("long-text selection missing body size"))?;
                let event = generator["event_without_blob_indirection_bytes"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("long-text selection missing Event size"))?;
                let actual = if body > CONTENT_TEXT_INLINE_MAX_BYTES as u64
                    || event > arkret_wire::MAX_EVENT_ENVELOPE_BYTES as u64
                {
                    "accept_long_text"
                } else {
                    "reject"
                };
                if case.pointer("/expected/decision").and_then(Value::as_str) != Some(actual) {
                    bail!("long-text selection decision drifted");
                }
            }
            "long_text_normalization_matrix" => {
                let normalized = normalize_long_text("one\r\ntwo\rthree\n")?;
                if normalized != "one\ntwo\nthree\n" || long_text_line_count(&normalized) != 3 {
                    bail!("long-text normalization or line count drifted");
                }
                if normalize_long_text("\u{feff}body").is_ok()
                    || normalize_long_text("bell\u{7}").is_ok()
                {
                    bail!("long-text forbidden control input was accepted");
                }
            }
            "long_text_fallback_matrix" | "long_text_plaintext_descriptor" => {
                let source = format!("{}\nend", "x".repeat(CONTENT_TEXT_INLINE_MAX_BYTES + 1));
                let block = ContentBlock::plaintext_long_text(
                    &source,
                    LongTextFormat::Markdown,
                    format!("ak:blob:sha256:{}", "a".repeat(64)),
                    LongTextBodyKind::Prefix,
                    None,
                )?;
                block.validate_long_text()?;
                if block.body != long_text_prefix(&source) {
                    bail!("long-text builder prefix drifted");
                }
            }
            "long_text_e2ee_descriptor" => {
                let size = generator["size_bytes"].as_u64().unwrap_or_default();
                let segment = generator["segment_bytes"].as_u64().unwrap_or_default();
                let count = generator["segment_count"].as_u64().unwrap_or_default();
                if segment == 0 || size.div_ceil(segment) != count {
                    bail!("long-text E2EE segment matrix drifted");
                }
            }
            "long_text_lifecycle" => {
                for field in [
                    "all_message_derived_views_invalidated",
                    "blob_gc_uses_reference_tracking",
                    "push_provider_never_receives_full_text",
                    "mentions_do_not_require_server_blob_scan",
                ] {
                    if case
                        .pointer(&format!("/expected/{field}"))
                        .and_then(Value::as_bool)
                        != Some(true)
                    {
                        bail!("long-text lifecycle expectation {field} drifted");
                    }
                }
            }
            other => bail!("unknown long-text generator {other}"),
        }
    }
    Ok(())
}
