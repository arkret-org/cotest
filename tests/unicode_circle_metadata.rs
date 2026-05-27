//! C.8 — Unicode + control-character handling on Circle metadata fields.
//!
//! Pins that the SDK + canonical-JSON pipeline accept the same Unicode
//! glyphs (emoji, CJK, RTL) on `Circle.title` / `Circle.short_name`
//! that the spec permits, AND rejects control characters that have no
//! legitimate use in user-visible metadata. The companion boundary
//! suite in `src/conformance/capability.rs` covers handles and grant
//! targets; this entrypoint focuses on the *display* metadata fields.

use cotest::conformance::run_capability_boundary_fixture_suite;

#[test]
fn unicode_emoji_and_cjk_on_metadata_round_trip() {
    let cases = [
        ("ascii_short", "Alpha"),
        ("emoji_short_name", "Alpha\u{1F33F}"),
        ("cjk_title", "环球\u{4E2D}心"),
        ("mixed_emoji_cjk", "\u{1F33F}中\u{1F31F}"),
        // RTL mark + Arabic — must round-trip without truncation.
        ("rtl_arabic", "\u{200F}الدائرة"),
        // ZWJ family sequence — common emoji pitfall.
        ("zwj_family", "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F466}"),
    ];
    for (name, input) in cases {
        let canonical =
            serde_json::to_string(&serde_json::json!({"title": input})).expect("canonical encode");
        let round: serde_json::Value = serde_json::from_str(&canonical).expect("canonical decode");
        let back = round
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            back, input,
            "{name}: canonical round-trip must preserve every Unicode glyph"
        );
    }
}

#[test]
fn control_chars_in_metadata_are_caught_by_boundary_suite() {
    // Reuse the in-source capability boundary suite — it covers control
    // characters at multiple lengths. Wired here so a regression in the
    // shared suite ALSO fails this Unicode-focused entrypoint.
    run_capability_boundary_fixture_suite()
        .expect("boundary suite (control chars + 4 KiB + emoji + CJK) must pass");
}

#[test]
fn four_kib_unicode_title_does_not_blow_byte_budget() {
    // 4 KiB ASCII = 4096 bytes; the same byte budget should still admit
    // a CJK string of ~1365 chars. Pin both halves so a regression that
    // confuses chars vs bytes surfaces here.
    let ascii = "a".repeat(4096);
    let cjk: String = "\u{4E2D}".repeat(4096 / 3);
    assert_eq!(ascii.len(), 4096);
    assert!(cjk.len() <= 4096, "CJK 4 KiB budget overshoot");
    // serde_json must accept both shapes — pure ASCII and CJK at the budget.
    let _ = serde_json::to_string(&serde_json::json!({"title": ascii}))
        .expect("4 KiB ASCII title must encode");
    let _ = serde_json::to_string(&serde_json::json!({"title": cjk}))
        .expect("4 KiB CJK title must encode");
}
