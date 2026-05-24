//! T8.2 — cross-service property tests for the SDK's handle-claim
//! validator. These run from cotest's vantage point so the same
//! invariants the conformance suite asserts on the wire are also
//! exercised on randomly-generated inputs.
//!
//! Invariants pinned:
//!
//!  1. **URI canonical round-trip.** Any valid `contrix://` URI
//!     survives parse → canonical without re-shape.
//!  2. **alias canonicalisation.** `acct:` interop form maps to the
//!     same canonical `contrix://` regardless of localpart casing.
//!  3. **audience mismatch is fatal.** When `member_delivery_binding`
//!     is set, the claim MUST also carry `audience` + `handle_uri` +
//!     `expires_at` or `validate()` rejects.
//!  4. **expiry boundary.** `binding_state=verified` MUST require
//!     `expires_at` regardless of whether `verified_at` is set.
//!  5. **issuer is opaque.** Random issuer strings (no schema effect)
//!     never change validation outcome on their own.

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use contrix_core::Did;
use contrix_core::model::{
    DeliveryBindingHint, DeliveryMode, HandleBindingState, HandleClaim, HandleHintBindingSource,
    HandleUri, RecipientServiceType,
};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

fn arb_localpart() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._+~\\-]{0,12}"
}

fn arb_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9]{1,6}", 1..=3).prop_map(|l| l.join("."))
}

fn arb_uri() -> impl Strategy<Value = String> {
    (arb_localpart(), arb_domain()).prop_map(|(l, d)| format!("contrix://{d}/users/{l}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Canonical URI parse → canonical() yields exactly the input bytes.
    #[test]
    fn canonical_uri_round_trip(uri in arb_uri()) {
        let p = HandleUri::parse(&uri).expect("valid uri parses");
        prop_assert_eq!(p.canonical(), uri.as_str());
    }

    /// `acct:` alias maps to the same canonical regardless of casing.
    #[test]
    fn acct_alias_canonical_independent_of_case(
        local in "[A-Za-z0-9]{1,10}",
        domain in arb_domain(),
    ) {
        let lower = HandleUri::from_acct(&format!("acct:{}@{domain}", local.to_lowercase())).unwrap();
        let mixed = HandleUri::from_acct(&format!("acct:{local}@{domain}")).unwrap();
        prop_assert_eq!(lower.canonical(), mixed.canonical());
    }

    /// `audience` MUST be present when `member_delivery_binding` is set,
    /// or `validate()` rejects.
    #[test]
    fn audience_mismatch_rejected(
        uri in arb_uri(),
        audience in prop::option::of("[a-z0-9.]{2,16}"),
    ) {
        let mut claim = HandleClaim::default();
        claim.handle_uri = Some(HandleUri::parse(&uri).unwrap());
        claim.member_delivery_binding = Some(member_delivery_binding());
        claim.expires_at = Some(Utc::now() + Duration::minutes(5));
        claim.audience = audience.clone().map(|a| format!("did:web:{a}.example"));
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
        uri in arb_uri(),
        with_expiry in any::<bool>(),
        with_verified_at in any::<bool>(),
    ) {
        let mut claim = HandleClaim::default();
        claim.binding_state = Some(HandleBindingState::Verified);
        claim.handle_uri = Some(HandleUri::parse(&uri).unwrap());
        claim.issuer = Some("did:web:issuer.example".to_owned());
        if with_expiry {
            claim.expires_at = Some(Utc::now() + Duration::minutes(5));
        }
        if with_verified_at {
            claim.verified_at = Some(Utc::now());
        }
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
        uri in arb_uri(),
        issuer in "[a-z0-9.:_\\-]{4,32}",
    ) {
        let mut claim = HandleClaim::default();
        claim.handle_uri = Some(HandleUri::parse(&uri).unwrap());
        claim.issuer = Some(issuer);
        // No binding_state, no recipient — should validate trivially.
        prop_assert!(claim.validate().is_ok());
    }
}

fn member_delivery_binding() -> DeliveryBindingHint {
    let mut modes = BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    DeliveryBindingHint {
        recipient_service_did: Did::new("did:web:rs.example".to_owned()).unwrap(),
        recipient_service_type: RecipientServiceType::PrincipalServer,
        binding_source: HandleHintBindingSource::OrganizationPolicy,
        delivery_modes: modes,
        service_acceptance_ref: None,
        policy_ref: None,
    }
}
