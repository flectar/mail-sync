# Flectar Mail Sync

End-to-end encrypted sync of Flectar Mail accounts, settings and devices.
This repository holds the protocol, the client library and the server.

The server stores only ciphertext. It never holds a key that could read your
data, and every device keeps a full copy, so any device can rebuild a lost
server. Mail, contacts and calendars keep syncing with your mail provider;
this service carries what has no home there.

**Status:** early development. Not ready for real data.

| Crate | What it is | Licence |
|---|---|---|
| `flectar-mail-sync-proto` | Wire types | Apache-2.0 |
| `flectar-mail-sync-crypto` | Key schedule, record sealing, key wraps, signed membership operations, pairing messages | Apache-2.0 |
| `flectar-mail-sync-client` | Sessions, chain verification, pairing, and the record sync engine behind a storage trait the app implements | Apache-2.0 |
| `flectar-mail-sync-server` | The server: Rust, axum, SQLite | BUSL-1.1 |

The protocol is specified in [`docs/SPEC.md`](docs/SPEC.md).

## Run the server

The image runs as a non-root user and keeps its database in `/data`. To run it
behind Caddy with automatic HTTPS:

```sh
cd deploy
SYNC_DOMAIN=sync.example.org docker compose up -d
```

Without Docker:

```sh
cargo build --release -p flectar-mail-sync-server
FLECTAR_MAIL_SYNC_PUBLIC_URL=https://sync.example.org \
  ./target/release/flectar-mail-sync-server --database ./sync.db
```

| Variable | Default | Meaning |
|---|---|---|
| `FLECTAR_MAIL_SYNC_PUBLIC_URL` | (required) | The URL devices use. Logins are bound to it. |
| `FLECTAR_MAIL_SYNC_DATABASE` | `/data/sync.db` | SQLite database file |
| `FLECTAR_MAIL_SYNC_LISTEN` | `0.0.0.0:8080` | Listen address |
| `FLECTAR_MAIL_SYNC_READERS` | `4` | Reader connections |
| `FLECTAR_MAIL_SYNC_TRUSTED_PROXIES` | (none) | Comma-separated addresses or CIDR ranges of reverse proxies whose `X-Forwarded-For` is believed. Rate limits count per client address, so set this behind a proxy. |
| `FLECTAR_MAIL_SYNC_MAX_GROUP_BYTES` | `67108864` | Stored bytes per group |
| `FLECTAR_MAIL_SYNC_MAX_DEVICES` | `25` | Devices per group |
| `RUST_LOG` | `info` | Log filter; logs are JSON |

Other subcommands:
- `healthcheck`: used by the image's `HEALTHCHECK`.
- `backup DESTINATION`: writes a consistent copy of the database.
- `migrate`: applies database migrations and exits.

## Develop

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Licence

Self-hosting is free: for yourself, your family or your organisation. Offering
the server to others as a paid hosted service needs a commercial licence. Each
server release becomes Apache-2.0 four years after it is published. See
[`LICENSE.md`](LICENSE.md).
