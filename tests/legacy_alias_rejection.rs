//! P4-D — legacy alias rejection negative suite.

use cotest::scenarios::legacy_alias_rejection::{
    ann_announce_id::ann_announce_id_run,
    legacy_secret_storage_wire::legacy_secret_storage_wire_run, renamed_fields::renamed_fields_run,
};

#[tokio::test]
async fn legacy_renamed_fields_rejected() {
    renamed_fields_run().await.unwrap();
}

#[tokio::test]
async fn legacy_secret_storage_wire_rejected() {
    legacy_secret_storage_wire_run().await.unwrap();
}

#[tokio::test]
async fn legacy_ann_announce_id_rejected() {
    ann_announce_id_run().await.unwrap();
}
