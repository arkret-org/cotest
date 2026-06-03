//! C.8 — smoke test for the chaos-injection framework + testcontainers
//! bring-up wiring.
//!
//! The chaos vocabulary smoke runs everywhere. The container path is
//! Linux-only and only when the `test-with-containers` feature is on.

use cotest::scenarios::chaos_inject::{
    ChaosInjectable, ChaosKind, simulate_disk_full, simulate_network_timeout,
    simulate_process_killed,
};

struct DummySubject {
    last: Option<ChaosKind>,
}

impl ChaosInjectable for DummySubject {
    fn inject(&mut self, kind: ChaosKind) -> anyhow::Result<()> {
        self.last = Some(kind);
        Ok(())
    }
}

#[test]
fn chaos_inject_smoke() {
    let mut subject = DummySubject { last: None };
    subject.inject(ChaosKind::DiskFull).unwrap();
    assert_eq!(subject.last, Some(ChaosKind::DiskFull));
    assert!(simulate_disk_full().to_string().contains("disk-full"));
    assert!(simulate_network_timeout().to_string().contains("timeout"));
    assert!(simulate_process_killed().to_string().contains("killed"));
}

/// Gating: requires Linux + the `test-with-containers` feature + a
/// running Docker daemon. Skipped on Windows and on default-feature
/// builds because testcontainers + named-pipe docker-engine on Windows
/// is unreliable.
#[cfg(all(not(target_os = "windows"), feature = "test-with-containers"))]
#[test]
#[ignore = "Gating: requires `test-with-containers` feature + Linux + Docker daemon"]
fn testcontainers_postgres_bringup_smoke() {
    use cotest::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_testcontainers;
    let pg = spawn_ephemeral_postgres_testcontainers().expect("bring-up returned");
    let Some(pg) = pg else {
        eprintln!("docker daemon unavailable on this runner — skipping");
        return;
    };
    assert!(
        pg.connect_url
            .starts_with("postgresql://cokret:cokret@127.0.0.1:")
    );
}
