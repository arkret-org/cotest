//! P2F.4 — directory `member_count` bucket function.
//!
//! teabay's directory MUST NOT publish the exact `member_count` of any
//! Realm or Circle entry. Instead it publishes a bucketed value drawn
//! from a fixed ladder. The bucket ladder is part of the v1 wire
//! contract — every downstream client that renders "Members: 10-50"
//! depends on this mapping, so a drift here is a wire break.
//!
//! Ladder (inclusive, normative):
//!   [1, 10], [11, 50], [51, 200], [201, 1000], [1001, 5000], [5001, ∞]
//!
//! Encoded label form: `"1-10"`, `"11-50"`, `"51-200"`, `"201-1000"`,
//! `"1001-5000"`, `"5001+"`. Empty counts (`0`) MUST surface as the
//! literal `"hidden"` (never `"0-0"` — that would leak the existence of
//! an empty Realm vs. a takedown).

use anyhow::{Result, anyhow};

/// Normative bucket ladder. `None` upper bound means "open-ended"
/// (`5001+`).
pub const MEMBER_COUNT_BUCKETS: &[(u64, Option<u64>, &str)] = &[
    (1, Some(10), "1-10"),
    (11, Some(50), "11-50"),
    (51, Some(200), "51-200"),
    (201, Some(1000), "201-1000"),
    (1001, Some(5000), "1001-5000"),
    (5001, None, "5001+"),
];

/// Bucket `count` per the normative ladder.
pub fn bucket_for(count: u64) -> &'static str {
    if count == 0 {
        return "hidden";
    }
    for (lo, hi, label) in MEMBER_COUNT_BUCKETS {
        if count >= *lo
            && match hi {
                Some(h) => count <= *h,
                None => true,
            }
        {
            return label;
        }
    }
    // Unreachable because the last bucket is open-ended, but stay safe.
    "hidden"
}

/// P2F.4.1 — assert every input on a representative sample maps to the
/// expected label. Catches off-by-one drifts and accidental label
/// renames (e.g. `"1—10"` em-dash vs `"1-10"` hyphen).
pub async fn anti_enumeration_buckets_run() -> Result<()> {
    let vectors: &[(u64, &str)] = &[
        (0, "hidden"),
        (1, "1-10"),
        (10, "1-10"),
        (11, "11-50"),
        (50, "11-50"),
        (51, "51-200"),
        (200, "51-200"),
        (201, "201-1000"),
        (1000, "201-1000"),
        (1001, "1001-5000"),
        (5000, "1001-5000"),
        (5001, "5001+"),
        (100_000, "5001+"),
        (u64::MAX, "5001+"),
    ];
    for (count, expected) in vectors {
        let got = bucket_for(*count);
        if got != *expected {
            return Err(anyhow!(
                "member_count bucket drift: count={count} expected=`{expected}` got=`{got}`"
            ));
        }
    }
    // Bucket ladder MUST cover [1, u64::MAX] contiguously without gaps
    // or overlaps. Walk the contract.
    let mut prev_hi: u64 = 0;
    for (i, (lo, hi, _)) in MEMBER_COUNT_BUCKETS.iter().enumerate() {
        if i == 0 {
            if *lo != 1 {
                return Err(anyhow!("first bucket MUST start at 1; starts at {lo}"));
            }
        } else if *lo != prev_hi + 1 {
            return Err(anyhow!(
                "bucket ladder has a gap between {prev_hi} and {lo}"
            ));
        }
        if let Some(h) = hi {
            if *h < *lo {
                return Err(anyhow!("bucket `{lo}-{h}` is inverted"));
            }
            prev_hi = *h;
        }
    }
    // Labels MUST be unique (so client lookup tables don't collide).
    let mut labels: Vec<&str> = MEMBER_COUNT_BUCKETS.iter().map(|(_, _, l)| *l).collect();
    labels.sort_unstable();
    let mut deduped = labels.clone();
    deduped.dedup();
    if labels.len() != deduped.len() {
        return Err(anyhow!(
            "bucket labels MUST be unique; got duplicates in {labels:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn buckets_round_trip() {
        anti_enumeration_buckets_run().await.unwrap();
    }
}
