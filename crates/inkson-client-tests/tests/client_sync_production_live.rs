use anyhow::{Context, Result};

#[test]
#[serial_test::serial]
fn sidecar_checkpoint_cases_use_the_actual_account_driver() -> Result<()> {
    std::thread::Builder::new().stack_size(32 * 1024 * 1024)
        .spawn(|| -> Result<()> {
            let transcript_dir = std::path::Path::new(env!("CARGO_BIN_EXE_cotest-inkson-checkpoint-readback"))
                .parent().context("Cargo provided no readback binary directory")?
                .join("conformance-transcripts");
            let _transcript = cotest::transcripts::init_transcript_writer("sidecar-checkpoint-production", Some(&transcript_dir))?;
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024).enable_all().build()?;
            let cases = runtime.block_on(cotest_inkson_client_tests::conformance::client_sync::run_sidecar_checkpoint_production_cases(
                std::path::Path::new(env!("CARGO_BIN_EXE_cotest-inkson-checkpoint-readback")),
            ))?;
            assert_eq!(cases.len(), 3);
            assert!(cases.iter().all(|case| case.assertions > 0));
            Ok(())
        })?.join().map_err(|_| anyhow::anyhow!("Account checkpoint evidence worker panicked"))?
}
