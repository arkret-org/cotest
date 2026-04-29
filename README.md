# cotest

`cotest` is the external Contrix server test harness for `E:\Works\contrix-dev\serverx`.
It follows the same out-of-repository idea as Complement: tests start real server
processes, call public HTTP/SDK APIs, and avoid linking to server internals.

## Run

```powershell
cargo test
```

The tests start `serverx` with in-memory storage by default. Set `SERVERX_MANIFEST`
when testing a different compatible serverx checkout:

```powershell
$env:SERVERX_MANIFEST = "E:\Works\contrix-dev\serverx\Cargo.toml"
cargo test
```

## Phase Layout

- `M0`: harness bootstrap, process lifecycle, service description, endpoint surface.
- `M1`: account, session, and contacts.
- `M2`: space lifecycle, event send, entity state operations, sync, index, and backfill.
- `M3`: repo and protocol payload workflows.
- `M4`: keys, to-device delivery, blob/media, push, and moderation.
- `M5`: multi-server process topology and federation readiness.
- `M6`: real cross-server collaboration through federation transaction/push/pull endpoints.
- `M7`: API contract, auth, invalid input, permission, and parameter edges.
- `M8`: applet and AI agent extension surface tracking.
- `M9`: full regression checklist.

See [docs/test-strategy.md](docs/test-strategy.md) and
[docs/complement-map.md](docs/complement-map.md) for the coverage map and
server/client lifecycle model.
