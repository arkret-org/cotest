//! T8.2 — cross-service property tests for the SDK's handle-claim
//! validator. These run from cotest's vantage point so the same
//! invariants the conformance suite asserts on the wire are also
//! exercised on randomly-generated inputs.
//!
//! Invariants pinned (post R3.1 wire rename — arkret-spec @ 7157ee8):
//!
//!  1. **Canonical round-trip.** Any valid `<localpart>:<domain>` handle survives parse → canonical
//!     without re-shape.
//!  2. **alias canonicalisation.** `acct:` interop form maps to the same canonical handle
//!     regardless of localpart casing.
//!  3. **audience mismatch is fatal.** When `member_delivery_binding` is set, the claim MUST also
//!     carry `audience` + `handle` + `expires_at` or `validate()` rejects.
//!  4. **expiry boundary.** `binding_state=verified` MUST require `expires_at` regardless of
//!     whether `verified_at` is set.
//!  5. **issuer is opaque.** Random issuer strings (no schema effect) never change validation
//!     outcome on their own.

use std::collections::BTreeSet;

use arkret_core::Did;
use arkret_models_identity::{
    DeliveryBindingHint, DeliveryMode, Handle, HandleBindingState, HandleClaim,
    HandleHintBindingSource, RecipientServiceType,
};
use chrono::{Duration, Utc};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

fn arb_localpart() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._+~\\-]{0,12}"
}

fn arb_domain() -> impl Strategy<Value = String> {
    // R3.1 schema-conformant domain — at least 2 dot-separated labels.
    proptest::collection::vec("[a-z0-9]{1,6}", 2..=3).prop_map(|l| l.join("."))
}

/// R3.1 canonical handle generator — `<localpart>:<domain>`.
fn arb_handle() -> impl Strategy<Value = String> {
    (arb_localpart(), arb_domain()).prop_map(|(l, d)| format!("{l}:{d}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Canonical handle parse → canonical() yields exactly the input bytes.
    #[test]
    fn canonical_handle_round_trip(handle in arb_handle()) {
        let p = Handle::parse(&handle).expect("valid canonical handle parses");
        prop_assert_eq!(p.canonical(), handle.as_str());
    }

    /// `acct:` alias maps to the same canonical regardless of casing.
    #[test]
    fn acct_alias_canonical_independent_of_case(
        local in "[A-Za-z0-9]{1,10}",
        domain in arb_domain(),
    ) {
        let lower = Handle::from_acct(&format!("acct:{}@{domain}", local.to_lowercase())).unwrap();
        let mixed = Handle::from_acct(&format!("acct:{local}@{domain}")).unwrap();
        prop_assert_eq!(lower.canonical(), mixed.canonical());
    }

    /// `audience` MUST be present when `member_delivery_binding` is set,
    /// or `validate()` rejects.
    #[test]
    fn audience_mismatch_rejected(
        handle in arb_handle(),
        audience in prop::option::of("[a-z0-9.]{2,16}"),
    ) {
        let claim = HandleClaim {
            handle: Some(Handle::parse(&handle).unwrap()),
            member_delivery_binding: Some(member_delivery_binding()),
            expires_at: Some(Utc::now() + Duration::minutes(5)),
            audience: audience.clone().map(|a| format!("did:web:{a}.example")),
            ..Default::default()
        };
        let outcome = claim.validate();
        if audience.is_some() {
            prop_assert!(outcome.is_ok(), "complete claim should validate");
        } else {
            prop_assert!(outcome.is_err(), "missing audience MUST reject");
        }
    }

    /// `binding_state=verified` requires `expires_at` even when
    /// `verified_at` is supplied. Issuer / aliases never relax this.
    #[test]
    fn verified_requires_expires_regardless_of_verified_at(
        handle in arb_handle(),
        with_expiry in any::<bool>(),
        with_verified_at in any::<bool>(),
    ) {
        let claim = HandleClaim {
            binding_state: Some(HandleBindingState::Verified),
            handle: Some(Handle::parse(&handle).unwrap()),
            issuer: Some("did:web:issuer.example".to_owned()),
            expires_at: with_expiry.then(|| Utc::now() + Duration::minutes(5)),
            verified_at: with_verified_at.then(Utc::now),
            ..Default::default()
        };
        let outcome = claim.validate();
        if with_expiry {
            prop_assert!(outcome.is_ok());
        } else {
            prop_assert!(outcome.is_err(), "verified+no_expiry MUST reject");
        }
    }

    /// Issuer is opaque to `validate()` — random strings do not change
    /// the outcome of an otherwise-valid claim.
    #[test]
    fn issuer_is_validation_opaque(
        handle in arb_handle(),
        issuer in "[a-z0-9.:_\\-]{4,32}",
    ) {
        let claim = HandleClaim {
            handle: Some(Handle::parse(&handle).unwrap()),
            issuer: Some(issuer),
            ..Default::default()
        };
        // No binding_state, no recipient — should validate trivially.
        prop_assert!(claim.validate().is_ok());
    }
}

fn member_delivery_binding() -> DeliveryBindingHint {
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    DeliveryBindingHint {
        recipient_service_id: Did::new("did:web:rs.example".to_owned()).unwrap(),
        recipient_service_type: RecipientServiceType::PrincipalServer,
        binding_source: HandleHintBindingSource::OrganizationPolicy,
        delivery_modes: modes,
        service_acceptance_ref: None,
        policy_event_ref: None,
    }
}
