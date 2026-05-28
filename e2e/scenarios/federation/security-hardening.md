# Federation Security Hardening

Validates deployment-level federation protections across two soland services.

- denylisted peer inbound push returns a hard 4xx instead of partial accept
- denylisted outbound peer does not receive fanout
- private-network federation pull targets are rejected by the egress guard

Harness requirements:

- `-DualSoland`
- `COTEST_EXPECT_FEDERATION_DENYLIST=1` for denylist cases
- `COTEST_EXPECT_PRIVATE_EGRESS_BLOCKED=1` for private egress rejection
