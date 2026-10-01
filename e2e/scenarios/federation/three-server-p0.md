# Three-server federation P0

This scenario is mandatory for `joint-full -ServerCount 3`. It fails closed when the topology has fewer than three independent Stations, when fewer than five cases appear in JUnit, or when any P0 case is skipped/fixme.

Normative invariants:

1. `sync/federation.md` §§4.1-4.5: authenticated fanout, idempotent replay, current authorization, peer query, and deterministic convergence.
2. `sync/federation.md` §5: candidate hints do not grant ingress authority; the selected source must be a currently authorized joined-member Station.
3. `authz/event-auth-state-resolution.md`: concurrent accepted Events and conflict outcomes are deterministic from the same accepted input set.

Topology: `alice@server1`, `bob@server2`, and `carol@server3`; each server has its own Soland, PostgreSQL, service identity/state, Coauth authority/store, and logs. The test reads `topology.json` through the numbered environment interface and never enumerates named second/third-server branches.

The ordinary Realms explicitly use `since_join`: each member Station retains its own opening join onward, and cross-Station equality compares the common suffix from the latest accepted join. Restart checks preserve each Station's complete own readable Event set. The owner accepts the default discussion before the remote joins and grants Message write authority to each exact remote AccountId. Every remote join is made readable before its grant is issued; the exact grant Event/Commit is then read back from that member Station, exercising authorization-cut invalidation and refresh rather than racing the initial bootstrap Snapshot.

The five cases cover convergence and duplicate replay, service-delegation isolation with a positive sentinel Realm, a real runner-controlled server2 process/container outage followed by authorized peer-query recovery and duplicate-materialization checks, ordered candidate probe evidence followed by a successful authorized source, and three-way concurrent writes followed by a real server2 restart. Candidate, recovery, control, and restart attempts are attached to the Playwright report as JSON evidence. The runner reconciles a replacement process into its managed-service set so cleanup and crash detection still apply after the test-triggered restart.

P0.4 is deliberately not sufficient to close the candidate-failover acceptance item yet: it demonstrates the two outcomes and report shape, but Soland does not currently consume the ordered candidates as one bounded production forwarding operation. The gap map therefore keeps this P0 item pending instead of treating harness-side sequencing as a product relay.

P0.5 permits at most three submissions of the exact same signed Event when the response is the registered HTTP 503 `temporarily_unavailable` (authority-commit-log.md §4). The Account Station creates fresh forwarding evidence on each self request. Other failures remain fatal. Retry diagnostics contain only Event ID, Station, attempt and status; all three accepted Event IDs must occur exactly once on every Station before restart, and each complete readable set must remain identical after restart.
