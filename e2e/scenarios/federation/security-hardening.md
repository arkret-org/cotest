# Federation Security Hardening

Validates deployment-level federation protections across two soland services.

- denylisted peer inbound push returns a hard 4xx instead of partial accept
- denylisted outbound peer does not receive fanout

Harness requirements:

- `-DualSoland`
- `COTEST_EXPECT_FEDERATION_DENYLIST=1` for denylist cases

CI wiring:

- `.github/workflows/integration.yml` runs this spec in a dedicated
  dual-soland topology with `SOLAND_FEDERATION_DENYLIST` on beta and
  `SOLAND_FEDERATION_PEER_DENYLIST` on alpha. This profile is separate from
  the positive cross-server federation run so denylist posture cannot silently
  skip or mask the hardening checks.
- The two nodes run under distinct hostnames (`soland-{alpha,beta}.security-ci.local`,
  mapped to loopback), because the denylist matcher compares hosts without
  ports: nodes sharing `127.0.0.1` could only be deny-listed as one. The
  hostnames also give each node a distinct service DID and trust domain,
  since soland derives both from `SOLAND_PUBLIC_BASE_URL`.
- The job keeps private-network egress **allowed** and hands both nodes a fixed
  `SOLAND_NOTARY_SIGNING_KEY`, so the topology is genuinely reachable and the
  inbound push is genuinely well-signed. Blocking private egress instead would
  make every assertion here hold without the denylist ever running. The egress
  guard has its own coverage in soland's `security.rs` unit tests.
