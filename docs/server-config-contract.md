# Arkret server configuration contract

Arkret server processes use the same source precedence even when their native
configuration file formats differ.

## Precedence

Without `--config`, servers preserve their development behaviour:

1. built-in safe defaults;
2. a nearby `.env`, when that server historically supported it;
3. process environment;
4. explicit runtime CLI options such as `--bind`.

With `--config FILE`, `.env` is never loaded:

1. built-in safe defaults;
2. the selected file;
3. process environment values for the service;
4. explicit runtime CLI options.

This is the production-friendly mode. A non-secret baseline can live in the
file while Compose, Kubernetes, or a secret manager injects credentials and
deployment-specific values through the environment.

`--config FILE --no-env-overrides` selects hermetic mode:

1. built-in safe defaults;
2. the selected file;
3. explicit runtime CLI options.

The corresponding service environment is ignored in this mode. Cotest uses it
for every managed Arkret server so a developer shell or CI host cannot leak
configuration into a run.

## Native formats

- Soland, Starid, and Teabay accept dotenv-compatible env files. Keys are
  restricted to the server prefix plus `DATABASE_URL` and `RUST_LOG`.
- Coauth keeps its typed YAML configuration and maps `COAUTH_*` variables using
  its existing double-underscore nesting convention.
- Floria keeps YAML/KDL. In explicit config mode, `FLORIA_*` variables use
  double underscores for nested fields, for example `FLORIA_HTTP__PORT=5001`.

The common contract standardizes loading and precedence; it does not force all
servers into one file syntax.

## Cotest preparation

The joint runner starts native server binaries with generated hermetic config
files. Docker remains an explicit packaging/runtime lane, not a prerequisite
for local functional tests. Soland and a stale Inkson web bundle are prepared
in parallel when both need rebuilding. A fresh Inkson bundle is served as
static files, avoiding a repeated `dx serve` compile pass.

Pure Rust unit and integration tests remain in their owning Cargo test lanes.
Playwright only covers live browser/service behavior and does not invoke
`cargo test` from a browser spec.
