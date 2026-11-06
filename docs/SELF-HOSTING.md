# Self-hosting Flectar Mail Sync

The server keeps only ciphertext, so running it needs no trust in whoever
hosts it. It is one small binary with an SQLite database. Running it for
yourself, your family or your organisation is free; offering it to others as
a paid hosted service needs a commercial licence (see
[`LICENSE.md`](../LICENSE.md)).

## What you need

- A machine with Docker and Docker Compose.
- A domain name pointing at it, with ports 80 and 443 open. Caddy obtains and
  renews the HTTPS certificate.
- Little memory: the server measured 8.5 MiB resident at idle. Each group
  stores at most 64 MiB by default.

## Start

```sh
cd deploy
SYNC_DOMAIN=sync.example.org docker compose up -d
```

In Flectar Mail, open **Settings → Sync & devices**, choose a custom server and
enter `https://sync.example.org`. Every device of a group uses the same
address: logins are bound to it.

## Settings

The server reads these environment variables. In `deploy/compose.yaml` they
go under the `sync` service's `environment`.

| Variable | Default | Meaning |
|---|---|---|
| `FLECTAR_MAIL_SYNC_PUBLIC_URL` | (required) | The address devices use, such as `https://sync.example.org` |
| `FLECTAR_MAIL_SYNC_DATABASE` | `/data/sync.db` | The SQLite database |
| `FLECTAR_MAIL_SYNC_LISTEN` | `0.0.0.0:8080` | The address the server listens on |
| `FLECTAR_MAIL_SYNC_READERS` | `4` | Database reader connections |
| `FLECTAR_MAIL_SYNC_TRUSTED_PROXIES` | (none) | Reverse proxies whose `X-Forwarded-For` is believed: addresses or CIDR ranges, comma-separated |
| `FLECTAR_MAIL_SYNC_MAX_GROUP_BYTES` | `67108864` | Stored bytes per group |
| `FLECTAR_MAIL_SYNC_MAX_DEVICES` | `25` | Devices per group |
| `RUST_LOG` | `info` | Log filter; logs are JSON lines |

## Behind another reverse proxy

The bundled Caddy needs no changes. With your own proxy:

- Forward to port 8080 and set `FLECTAR_MAIL_SYNC_PUBLIC_URL` to the public
  `https://` address.
- Set `FLECTAR_MAIL_SYNC_TRUSTED_PROXIES` to the proxy's address. Rate limits
  count per client address. Without this setting, every request seems to come
  from the proxy. The server believes only the rightmost `X-Forwarded-For`
  entry that is not a trusted proxy, so clients cannot forge their address.
- Do not publish port 8080 itself, or anyone could claim any address in
  `X-Forwarded-For`.
- Allow long requests: event streams stay open, and pairing reads wait up to
  25 s. The server sends `X-Accel-Buffering: no` on event streams, which turns
  off nginx's response buffering for them.

## Backups

Devices keep a full copy of their group, so they rebuild a server that lost
data, even one that lost everything (SPEC §8). Backups still save devices
from re-uploading after a disk failure.

### Continuous, with Litestream

[Litestream](https://litestream.io) copies every change to S3-compatible
storage within seconds. Start the server with the extra compose file:

```sh
cd deploy
export SYNC_DOMAIN=sync.example.org
export LITESTREAM_ACCESS_KEY_ID=… LITESTREAM_SECRET_ACCESS_KEY=…
export LITESTREAM_BUCKET=my-backups
# Only for storage other than AWS S3:
export LITESTREAM_ENDPOINT=https://s3.example.com LITESTREAM_REGION=…
docker compose -f compose.yaml -f compose.litestream.yaml up -d
```

- **Where:** backups go to `flectar-mail-sync/sync.db` in the bucket. Set
  `LITESTREAM_PATH` to change that.
- **Restoring:** when the server's volume is empty, for example on a new
  machine, the `restore` service puts back the newest backup before the
  server starts.
- **What Litestream needs:** the server meets its requirements. It uses WAL
  mode and a busy timeout, and it is the only process writing the database.
- **Disks:** keep the volume on a local disk. Litestream's documentation
  warns against network filesystems.

### Snapshots

The server copies its database consistently while it runs:

```sh
docker compose exec sync /usr/local/bin/flectar-mail-sync-server backup /data/snapshot.db
```

Copy `snapshot.db` off the volume and keep it with your other backups. To
restore, stop the server and put the snapshot in place of `/data/sync.db`.
Delete `sync.db-wal` and `sync.db-shm` next to it if they exist.

## Upgrades

```sh
docker compose pull && docker compose up -d
```

The server migrates its database at start. To migrate without serving, run
the `migrate` subcommand. A group's devices accept any server that speaks
their protocol version (`GET /v1/info`).

## Monitoring

- `GET /healthz` answers `200 ok` when the database answers; the image's
  health check uses it.
- Logs never contain group ids or paths with them. Request logs name the
  route template.
