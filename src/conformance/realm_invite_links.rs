//! Production SDK possession proofs and private fragment codec KATs.

use anyhow::{Result, ensure};
use arkret_models_collaboration::governance::realm_invite_link::*;
use arkret_signatures::realm_invite_link::{
    sign_realm_invite_link_proof, verify_realm_invite_link_proof,
};
use arkret_wire::{AccountId, Hash, RealmId, RealmInviteLinkId, RequestId};
use serde_json::Value;

use super::{CaseExecutionResult, SuiteExecutionResult, load_fixture_value};

const ENTRYPOINT: &str = "ak.suite.realm_invite_link.proofs.v1";
const FIXTURE: &str = "realm-invite-link-proof-kat-fixture.json";

pub fn run_realm_invite_link_proof_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    let public = fixture["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("proof KAT key absent"))?;
    let token: RealmInviteLinkToken = serde_json::from_value(fixture["token"].clone())?;
    let secret = token.secret_seed.clone();
    let mut cases = Vec::new();
    for row in fixture["accepted_proof_cases"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("proof KAT cases absent"))?
    {
        let b = &row["binding"];
        let realm: RealmId = serde_json::from_value(b["realm_id"].clone())?;
        let link: RealmInviteLinkId = serde_json::from_value(b["realm_invite_link_id"].clone())?;
        let account: AccountId = serde_json::from_value(b["subject_account_id"].clone())?;
        let request: RequestId = serde_json::from_value(b["request_id"].clone())?;
        let accepting = row["case"] == "accept_purpose";
        let expected: RealmInviteLinkProof = serde_json::from_value(row["proof"].clone())?;
        let actual =
            sign_realm_invite_link_proof(&secret, &realm, &link, &account, &request, accepting)?;
        ensure!(actual == expected, "SDK proof differs from independent KAT");
        verify_realm_invite_link_proof(
            public, &actual, &realm, &link, &account, &request, accepting,
        )?;
        ensure!(
            realm_invite_link_proof_bytes(&realm, &link, &account, &request, accepting)?
                == row["signing_bytes_utf8"].as_str().unwrap().as_bytes(),
            "proof transcript differs"
        );
        cases.push(CaseExecutionResult {
            case_id: row["case"].as_str().unwrap().into(),
            assertions: 3,
        });
    }
    let base = &fixture["accepted_proof_cases"][0];
    let b = &base["binding"];
    let realm: RealmId = serde_json::from_value(b["realm_id"].clone())?;
    let link: RealmInviteLinkId = serde_json::from_value(b["realm_invite_link_id"].clone())?;
    let account: AccountId = serde_json::from_value(b["subject_account_id"].clone())?;
    let request: RequestId = serde_json::from_value(b["request_id"].clone())?;
    let proof: RealmInviteLinkProof = serde_json::from_value(base["proof"].clone())?;
    for name in fixture["negative_mutations"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        let rejected = match name {
            "purpose" => verify_realm_invite_link_proof(
                public, &proof, &realm, &link, &account, &request, false,
            )
            .is_err(),
            "realm_id" => {
                let different = RealmId::from_event_id(&link.event_id());
                verify_realm_invite_link_proof(
                    public, &proof, &different, &link, &account, &request, true,
                )
                .is_err()
            }
            "realm_invite_link_id" => {
                let different = RealmInviteLinkId::from_event_id(&realm.event_id());
                verify_realm_invite_link_proof(
                    public, &proof, &realm, &different, &account, &request, true,
                )
                .is_err()
            }
            "principal_id" | "station_id" => {
                let other: arkret_wire::DidCoreId = "ak:did_core:web:other.example".parse()?;
                let different = if name == "principal_id" {
                    AccountId::new(other, account.station_id.clone())
                } else {
                    AccountId::new(account.principal_id.clone(), other)
                };
                verify_realm_invite_link_proof(
                    public, &proof, &realm, &link, &different, &request, true,
                )
                .is_err()
            }
            "request_id" => {
                let different: RequestId =
                    "ak:request:01904100-0000-7000-8000-000000000002".parse()?;
                verify_realm_invite_link_proof(
                    public, &proof, &realm, &link, &account, &different, true,
                )
                .is_err()
            }
            "audience" => {
                let mut value = b.clone();
                value["audience"] = Value::String("arkret.realm_invite_link.preview".into());
                let bytes = [
                    b"ak.realm_invite_link.accept_proof.v1\n".as_slice(),
                    arkret_canonical::canonical_json_bytes(&value)?.as_slice(),
                ]
                .concat();
                proof.validate_transcript(&bytes).is_err()
            }
            "transcript_digest" => {
                let mut altered = proof.clone();
                altered.transcript_digest =
                    Hash::new(arkret_canonical::sha256_digest(b"different transcript"))?;
                verify_realm_invite_link_proof(
                    public, &altered, &realm, &link, &account, &request, true,
                )
                .is_err()
            }
            "signature" => {
                let mut altered = proof.clone();
                let mut raw = arkret_canonical::base64url_decode(&altered.signature)?;
                raw[0] ^= 1;
                altered.signature = arkret_canonical::base64url_encode(raw);
                verify_realm_invite_link_proof(
                    public, &altered, &realm, &link, &account, &request, true,
                )
                .is_err()
            }
            "unknown_field" => {
                let mut altered = base["proof"].clone();
                altered["unexpected"] = Value::Bool(true);
                serde_json::from_value::<RealmInviteLinkProof>(altered).is_err()
            }
            "padded_base64url" => {
                let mut altered = proof.clone();
                altered.signature.push('=');
                verify_realm_invite_link_proof(
                    public, &altered, &realm, &link, &account, &request, true,
                )
                .is_err()
            }
            "token_wrong_realm" => RealmInviteLinkToken::decode(
                &token.encode()?,
                &RealmId::from_event_id(&link.event_id()),
            )
            .is_err(),
            "token_noncanonical_json" => {
                let mut bytes = arkret_canonical::canonical_json_bytes(&fixture["token"])?;
                bytes.push(b' ');
                RealmInviteLinkToken::decode(&arkret_canonical::base64url_encode(bytes), &realm)
                    .is_err()
            }
            "token_unknown_field" => {
                let mut value = fixture["token"].clone();
                value["unexpected"] = Value::Bool(true);
                RealmInviteLinkToken::decode(
                    &arkret_canonical::base64url_encode(arkret_canonical::canonical_json_bytes(
                        &value,
                    )?),
                    &realm,
                )
                .is_err()
            }
            _ => anyhow::bail!("unexecuted proof KAT case {name}"),
        };
        ensure!(
            rejected,
            "production SDK accepted negative proof case {name}"
        );
        cases.push(CaseExecutionResult {
            case_id: name.into(),
            assertions: 1,
        });
    }
    let encoded = token.encode()?;
    let decoded = RealmInviteLinkToken::decode(&encoded, &realm)?;
    ensure!(
        decoded.realm_invite_link_id == link && decoded.encode()?.as_str() == encoded.as_str(),
        "credential canonical roundtrip failed"
    );
    ensure!(
        !format!("{token:?}").contains(fixture["private_key_seed"].as_str().unwrap()),
        "private seed leaked through Debug"
    );
    Ok(SuiteExecutionResult {
        entrypoint: ENTRYPOINT.into(),
        fixture: FIXTURE.into(),
        cases,
    })
}
