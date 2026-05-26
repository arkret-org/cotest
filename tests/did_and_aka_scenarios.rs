//! P4-E / P4-F — DID format normalization + alsoKnownAs verifier
//! authority guard.

use cotest::scenarios::alsoknownas_verifier_authority::alsoknownas_verifier_authority_run;
use cotest::scenarios::did_format_normalization::did_format_normalization_run;

#[tokio::test]
async fn did_format_normalization() {
    did_format_normalization_run().await.unwrap();
}

#[tokio::test]
async fn alsoknownas_verifier_authority() {
    alsoknownas_verifier_authority_run().await.unwrap();
}
