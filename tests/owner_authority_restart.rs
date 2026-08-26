//! Live restart coverage for current-v1 compiled owner authority.

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn owner_invite_remove_grant_revoke_survive_restart() {
    cotest::scenarios::owner_authority_restart::owner_invite_remove_grant_revoke_survive_restart()
        .await
        .unwrap();
}
