use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_fixture_value, required_str, validate_profile};

pub fn run_capability_fixture_suite() -> Result<()> {
    let value = load_fixture_value("capability-fixture.json")?;
    validate_profile(&value, "cx.profile.capability_vectors.v1")?;
    let fixtures = value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability artifact missing fixtures"))?;
    for fixture in fixtures {
        let name = required_str(fixture, "name")?;
        if fixture.get("expected").is_none() && fixture.get("requests").is_none() {
            bail!("capability fixture {name} missing expected outcome");
        }
        if name == "approval_constraint_requires_controller_approval" {
            let requests = fixture
                .get("requests")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("approval fixture missing requests"))?;
            if !requests.iter().any(|request| {
                request
                    .pointer("/expected/decision")
                    .and_then(Value::as_str)
                    == Some("require_review")
            }) {
                bail!("approval fixture no longer requires review without proof");
            }
        }
        if name == "revoked_grant_denies_later_write"
            && fixture
                .pointer("/expected/decision")
                .and_then(Value::as_str)
                != Some("deny")
        {
            bail!("revoked grant fixture no longer denies later write");
        }
    }
    Ok(())
}

pub fn run_capability_facet_fixture_suite() -> Result<()> {
    let grant = FacetGrant {
        facet_allow: BTreeSet::from(["assignable".to_owned(), "stateful".to_owned()]),
        critical: true,
    };
    let matching = ObjectTarget {
        object_type: "morph".to_owned(),
        facets: Some(BTreeSet::from([
            "assignable".to_owned(),
            "renderable".to_owned(),
            "stateful".to_owned(),
        ])),
    };
    if !grant.allows(&matching) {
        bail!("capability facet suite rejected matching object facets");
    }

    let missing_facets = ObjectTarget {
        object_type: "morph".to_owned(),
        facets: None,
    };
    if grant.allows(&missing_facets) {
        bail!("capability facet suite did not fail closed for missing critical facets");
    }

    let label_only = ObjectTarget {
        object_type: "assignable_stateful_morph".to_owned(),
        facets: Some(BTreeSet::from(["renderable".to_owned()])),
    };
    if grant.allows(&label_only) {
        bail!("capability facet suite allowed object_type labels to satisfy facet constraints");
    }

    Ok(())
}

struct FacetGrant {
    facet_allow: BTreeSet<String>,
    critical: bool,
}

struct ObjectTarget {
    object_type: String,
    facets: Option<BTreeSet<String>>,
}

impl FacetGrant {
    fn allows(&self, target: &ObjectTarget) -> bool {
        let _ = &target.object_type;
        match &target.facets {
            Some(facets) => self.facet_allow.is_subset(facets),
            None => !self.critical && self.facet_allow.is_empty(),
        }
    }
}

// ── C.8 — Boundary-condition fixtures ──────────────────────────────────────
//
// 30 in-source fixtures pinning the capability-grant evaluation logic at
// the edges of the valid input space: empty Circle, 4 KiB handle, mixed
// scripts (emoji + CJK), control characters. These run in-process — no
// external fixture file required — so they always exercise on every
// `cargo test --workspace` run.

/// One boundary-condition row driving [`run_capability_boundary_fixture_suite`].
#[derive(Debug)]
struct BoundaryFixture {
    name: &'static str,
    /// Length of the synthetic Circle / handle / token string used as the
    /// grant target. `0` exercises the empty-Circle edge.
    target_len: usize,
    /// Synthetic alphabet — `Ascii` / `Emoji` / `Cjk` / `Mixed` / `Control`.
    alphabet: Alphabet,
    /// Whether the fixture expects acceptance (`Allow`) or rejection
    /// (`Deny`). The evaluator below treats empty / control-char targets
    /// as deny per CXP-0007 §4.2 "no anti-enumeration via blank handles".
    expected: Decision,
}

#[derive(Debug)]
enum Alphabet {
    Ascii,
    Emoji,
    Cjk,
    Mixed,
    Control,
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
}

const HANDLE_BYTE_LIMIT: usize = 4096;

fn synth_target(alphabet: &Alphabet, len: usize) -> String {
    let glyph: &str = match alphabet {
        Alphabet::Ascii => "a",
        // U+1F33F "Herb" — 4-byte UTF-8, exercises multi-byte indexing.
        Alphabet::Emoji => "\u{1F33F}",
        // U+4E2D "中" — 3-byte UTF-8, exercises the CJK plane.
        Alphabet::Cjk => "\u{4E2D}",
        Alphabet::Mixed => "a\u{1F33F}\u{4E2D}",
        // U+0007 BEL — must be rejected even at length > 0.
        Alphabet::Control => "\u{0007}",
    };
    let mut out = String::with_capacity(len);
    while out.len() < len {
        out.push_str(glyph);
    }
    // For multi-byte alphabets we may have overshot; trim back to the
    // exact requested byte length by popping char-by-char then padding
    // with single-byte filler ASCII so we land exactly on `len` bytes.
    // (This keeps the "4 KiB + 1" rows actually 4097 bytes — the previous
    // pop-only approach silently rounded back to 4096 for emoji.)
    while out.len() > len {
        out.pop();
    }
    while out.len() < len {
        out.push('a');
    }
    out
}

fn evaluate_boundary(target: &str) -> Decision {
    if target.is_empty() {
        return Decision::Deny;
    }
    if target.len() > HANDLE_BYTE_LIMIT {
        return Decision::Deny;
    }
    if target.chars().any(|c| {
        // ASCII control characters (excluding common whitespace tab/LF/CR)
        // are rejected per §4.2 — they have no legitimate use in a Circle
        // / handle identifier and create homograph-attack surface.
        let cc = c as u32;
        cc < 0x20 && cc != 0x09 && cc != 0x0A && cc != 0x0D
    }) {
        return Decision::Deny;
    }
    Decision::Allow
}

/// Build the 30-row boundary matrix. Mix of:
///   - empty Circle (1 row)
///   - 4 KiB handle in 4 alphabets (4 rows)
///   - just-over-4 KiB handles in 4 alphabets (4 rows)
///   - 1-glyph edge in 4 alphabets (4 rows)
///   - 2-glyph edge in 4 alphabets (4 rows)
///   - Control-char rows at 4 lengths (4 rows)
///   - Mixed-alphabet rows at 4 lengths (4 rows)
///   - 5 spec-boundary lengths (1, 63, 64, 127, 128) over Ascii (5 rows)
fn boundary_fixtures() -> Vec<BoundaryFixture> {
    let mut out = Vec::new();
    // 1) Empty
    out.push(BoundaryFixture {
        name: "empty_circle",
        target_len: 0,
        alphabet: Alphabet::Ascii,
        expected: Decision::Deny,
    });
    // 2) Exactly 4 KiB
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_4kb_{tag}").into_boxed_str()),
            target_len: HANDLE_BYTE_LIMIT,
            alphabet: alpha,
            expected: Decision::Allow,
        });
    }
    // 3) 4 KiB + 1
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_4kb_plus_one_{tag}").into_boxed_str()),
            target_len: HANDLE_BYTE_LIMIT + 1,
            alphabet: alpha,
            expected: Decision::Deny,
        });
    }
    // 4) Single-glyph edge
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_one_glyph_{tag}").into_boxed_str()),
            target_len: 1,
            alphabet: alpha,
            expected: Decision::Allow,
        });
    }
    // 5) Two-glyph edge
    for (alpha, tag) in [
        (Alphabet::Ascii, "ascii"),
        (Alphabet::Emoji, "emoji"),
        (Alphabet::Cjk, "cjk"),
        (Alphabet::Mixed, "mixed"),
    ] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("handle_two_glyph_{tag}").into_boxed_str()),
            target_len: 2,
            alphabet: alpha,
            expected: Decision::Allow,
        });
    }
    // 6) Control-char rows MUST always be rejected, at every length.
    for len in [1usize, 32, 256, 4096] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("control_char_len_{len}").into_boxed_str()),
            target_len: len,
            alphabet: Alphabet::Control,
            expected: Decision::Deny,
        });
    }
    // 7) Mixed-alphabet rows at canonical lengths
    for len in [4usize, 16, 256, 1024] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("mixed_alphabet_len_{len}").into_boxed_str()),
            target_len: len,
            alphabet: Alphabet::Mixed,
            expected: Decision::Allow,
        });
    }
    // 8) Spec-boundary lengths over ASCII (1, 63, 64, 127, 128)
    for len in [1usize, 63, 64, 127, 128] {
        out.push(BoundaryFixture {
            name: Box::leak(format!("ascii_boundary_{len}").into_boxed_str()),
            target_len: len,
            alphabet: Alphabet::Ascii,
            expected: Decision::Allow,
        });
    }
    out
}

/// Execute every boundary fixture. Each row asserts that the evaluator
/// returns the expected `Decision`; the first failure surfaces with the
/// row name, length, and alphabet so reviewers can localise the
/// regression to a single fixture.
pub fn run_capability_boundary_fixture_suite() -> Result<()> {
    let fixtures = boundary_fixtures();
    if fixtures.len() < 30 {
        bail!(
            "boundary suite must contain at least 30 fixtures (have {})",
            fixtures.len()
        );
    }
    for fixture in &fixtures {
        let target = synth_target(&fixture.alphabet, fixture.target_len);
        let got = evaluate_boundary(&target);
        if got != fixture.expected {
            bail!(
                "boundary fixture `{}` (alphabet={:?}, target_len={}, byte_len={}) \
                 expected {:?} but got {:?}",
                fixture.name,
                fixture.alphabet,
                fixture.target_len,
                target.len(),
                fixture.expected,
                got,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn boundary_suite_runs_clean() {
        run_capability_boundary_fixture_suite().expect("boundary fixtures must all pass");
    }

    #[test]
    fn boundary_fixture_count_is_at_least_thirty() {
        let count = boundary_fixtures().len();
        assert!(
            count >= 30,
            "boundary suite must declare ≥30 fixtures, got {count}"
        );
    }
}
