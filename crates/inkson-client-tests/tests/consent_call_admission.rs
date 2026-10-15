//! Required production success across the three call Consent cuts.

#[test]
#[serial_test::serial]
fn legal_voice_and_video_calls_use_real_product_ringing_and_media_cuts() -> anyhow::Result<()> {
    std::thread::spawn(||tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?.block_on(cotest_inkson_client_tests::conformance::consent_call_admission::run_legal_three_cut_calls()))
        .join().map_err(|_|anyhow::anyhow!("call Consent production worker panicked"))?
}

#[test]
#[serial_test::serial]
fn two_stations_use_real_call_cuts_and_recover_accepted_private_bindings() -> anyhow::Result<()> {
    std::thread::spawn(||tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?.block_on(cotest_inkson_client_tests::conformance::consent_call_admission::run_cross_station_three_cut_calls()))
        .join().map_err(|_|anyhow::anyhow!("cross-Station Call Consent worker panicked"))?
}
