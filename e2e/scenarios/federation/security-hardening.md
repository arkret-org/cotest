# Federation Security Hardening

Validates deployment-level federation protections across two soland services.

- denylisted peer inbound push returns a hard 4xx instead of partial accept
- denylisted outbound peer does not receive fanout
- private-network federation pull targets are rejected by the egress guard

Harness requirements:

- `-DualSoland`
- `COTEST_EXPECT_FEDERATION_DENYLIST=1` for denylist cases
- `COTEST_EXPECT_PRIVATE_EGRESS_BLOCKED=1` for private egress rejection

CI wiring:

- `.github/workflows/integration.yml` runs this spec in a dedicated
  dual-soland topology with `SOLAND_FEDERATION_DENYLIST`,
  `SOLAND_FEDERATION_PEER_DENYLIST`, and
  `SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS=0` set explicitly. This profile is
  separate from the positive cross-server federation run so denylist posture
  cannot silently skip or mask the hardening checks.
