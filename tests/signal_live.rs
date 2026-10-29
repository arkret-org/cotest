use anyhow::Result;
use serial_test::serial;

#[test]
fn signal_entry_future_keeps_large_child_state_on_the_heap() {
    fn check<F: std::future::Future>(_: impl FnOnce() -> F) {
        assert!(
            std::mem::size_of::<F>() < 64 * 1024,
            "Signal entry future must not inline its large fixture state"
        );
    }
    check(cotest::scenarios::signal_live::run);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn accepted_signal_self_peer_recipient_and_read_only_denials() -> Result<()> {
    cotest::scenarios::signal_live::run().await
}
