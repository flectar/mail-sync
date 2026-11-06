# Contributing

Contributions are accepted under the licence of the files they change:

- `crates/flectar-mail-sync-proto`, `crates/flectar-mail-sync-crypto` and
  `deploy/`: Apache-2.0.
- `docs/`: CC BY 4.0.
- `crates/flectar-mail-sync-server`: Business Source License 1.1. Changes here
  also need a contributor licence agreement, so that Flectar can offer the
  server under commercial terms. It will be in place before outside
  contributions to the server open.

Before opening a pull request, run:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Protocol changes start in `docs/SPEC.md`.
