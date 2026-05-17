// Placeholder bin entry. cotest is primarily a library + integration test
// crate; `cargo test --tests` is the canonical entrypoint. This bin exists
// only so `cargo test`'s auto-detected default-run target compiles cleanly.
fn main() {
    eprintln!(
        "cotest: this binary is a placeholder. Run integration tests with `cargo test --tests`."
    );
}
