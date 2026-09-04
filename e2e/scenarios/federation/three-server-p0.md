# Three-server federation P0

This scenario is mandatory for `joint-full -ServerCount 3`. It fails closed when the topology has fewer than three independent Stations, when fewer than five cases appear in JUnit, or when any P0 case is skipped/fixme.

Normative invariants:

1. `sync/federation.md` §§4.1-4.5: authenticated fanout, idempotent replay, current authorization, peer query, and deterministic convergence.
2. `sync/federation.md` §5: candidate hints do not grant ingress authority; the selected source must be a currently authorized joined-member Station.
3. `authz/event-auth-state-resolution.md`: concurrent accepted Events and conflict outcomes are deterministic from the same accepted input set.

Topology: `alice@server1`, `bob@server2`, and `carol@server3`; each server has its own Soland, PostgreSQL, service identity/state, Coauth authority/store, and logs. The test reads `topology.json` through the numbered environment interface and never enumerates named second/third-server branches.

The five cases cover convergence and duplicate replay, service-delegation isolation with a positive sentinel Realm, a real runner-controlled server2 process/container outage followed by authorized peer-query recovery and duplicate-materialization checks, ordered candidate probe evidence followed by a successful authorized source, and three-way concurrent writes followed by a real server2 restart. Candidate, recovery, control, and restart attempts are attached to the Playwright report as JSON evidence. The runner reconciles a replacement process into its managed-service set so cleanup and crash detection still apply after the test-triggered restart.

P0.4 is deliberately not sufficient to close the candidate-failover acceptance item yet: it demonstrates the two outcomes and report shape, but Soland does not currently consume the ordered candidates as one bounded production forwarding operation. The gap map therefore keeps this P0 item pending instead of treating harness-side sequencing as a product relay.
