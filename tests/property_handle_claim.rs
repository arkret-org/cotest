//! Property checks for canonical handles and Station-scoped handle claims.

use arkret_identifiers::DidCoreId;
use arkret_models_identity::{Handle, HandleClaim};
use arkret_wire::AccountId;
use chrono::{Duration, Utc};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

fn arb_localpart() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._+~\\-]{0,12}"
}

fn arb_domain() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z0-9]{1,6}", 2..=3).prop_map(|labels| labels.join("."))
}

fn arb_handle() -> impl Strategy<Value = String> {
    (arb_localpart(), arb_domain()).prop_map(|(local, domain)| format!("{local}:{domain}"))
}

fn account(station: &str) -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new(station).unwrap(),
    )
}

fn base_claim(handle: &str, station: &str) -> HandleClaim {
    let issued_at = Utc::now() - Duration::minutes(1);
    cotest::fixture_verified_handle_claim(
        handle,
        account(station),
        DidCoreId::new("ak:did_core:web:issuer.example").unwrap(),
        None,
        issued_at,
        Some(issued_at + Duration::minutes(10)),
    )
    .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    #[test]
    fn canonical_handle_round_trip(handle in arb_handle()) {
        let parsed = Handle::parse(&handle).expect("valid canonical handle parses");
        prop_assert_eq!(parsed.canonical(), handle.as_str());
    }

    #[test]
    fn acct_alias_canonical_independent_of_case(
        local in "[A-Za-z0-9]{1,10}",
        domain in arb_domain(),
    ) {
        let lower = Handle::from_acct(&format!("acct:{}@{domain}", local.to_lowercase())).unwrap();
        let mixed = Handle::from_acct(&format!("acct:{local}@{domain}")).unwrap();
        prop_assert_eq!(lower.canonical(), mixed.canonical());
    }

    #[test]
    fn retired_flat_status_members_are_rejected(handle in arb_handle()) {
        let claim = base_claim(&handle, "ak:did_core:web:station-a.example");
        let mut wire = serde_json::to_value(claim).unwrap();
        wire["binding_state"] = serde_json::json!("verified");
        prop_assert!(serde_json::from_value::<HandleClaim>(wire).is_err());
    }

    #[test]
    fn same_principal_at_different_stations_is_not_the_same_subject(handle in arb_handle()) {
        let claim_a = base_claim(&handle, "ak:did_core:web:station-a.example");
        let claim_b = base_claim(&handle, "ak:did_core:web:station-b.example");
        prop_assert_eq!(&claim_a.claim.subject_account_id.principal_id, &claim_b.claim.subject_account_id.principal_id);
        prop_assert_ne!(&claim_a.claim.subject_account_id, &claim_b.claim.subject_account_id);
        prop_assert_ne!(
            claim_a.claim.subject_account_id.canonical_key().unwrap(),
            claim_b.claim.subject_account_id.canonical_key().unwrap()
        );
    }
}
