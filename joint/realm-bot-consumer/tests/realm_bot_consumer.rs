//! Joint Coland transport and Savfox consumer regressions.
//! Run through `joint/realm-bot-consumer/Cargo.toml`.
#[path = "../../../../coland/crates/storage-postgres/tests/support/applet_authoring.rs"]
#[allow(dead_code)]
mod applet_authoring;
#[path = "realm_bot_consumer/consumer.rs"]
mod consumer;
#[path = "../../../../coland/crates/storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

async fn run_case(rotate_during_reply: bool) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let consumer = consumer::SavfoxBotConsumer::default();
    Box::pin(applet_authoring::realm_bot_consumer(
        database.pool(),
        rotate_during_reply,
        &consumer,
    ))
    .await;
    consumer.assert_completed();
}

#[tokio::test]
async fn realm_bot_consumes_native_mentions_and_publishes_own_reply() {
    run_case(false).await;
}

#[tokio::test]
async fn realm_bot_retains_output_across_mls_update_and_worker_restart() {
    run_case(true).await;
}
