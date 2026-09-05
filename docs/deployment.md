# Deployment

## Docker Compose

The default stack uses Valkey, a Redis-protocol-compatible state server. Redis
is a supported alternative; the relay requires one of them, never both.

- The state service has no published host port.
- Data uses a persistent volume with append-only persistence enabled.
- The relay runs as a non-root user with a read-only root filesystem and no
  Linux capabilities.
- The relay publishes only to `127.0.0.1` by default.
- Bootstrap material is mounted as a Compose secret rather than committed in
  `.env`.

On Linux, set `TEAM_RELAY_UID` and `TEAM_RELAY_GID` in a private `.env` to the
owner of `secrets/bootstrap-token` (`id -u` and `id -g`). The same identity runs
the non-root relay and one-shot administrator containers, allowing them to read
owner-only bind-mounted credential files. The defaults are `1000:1000`; they
will not work for a token owned by a different numeric user.

To use Redis, set `TEAM_RELAY_STATE_IMAGE` and
`TEAM_RELAY_STATE_COMMAND` in a private `.env` file.

The image also contains `team-relay-admin`. Run administrative operations as
one-shot containers on the private backend network:

```bash
docker compose run --rm --no-deps admin <command>
```

For commands that need a credential, bind-mount its private host file read-only
and pass the container path with `--token-file`. When the relay is already
running, address it as `http://relay:8080`; the `admin` service does not need a
host-published relay port. Compose scopes the admin client's cleartext exception
to that exact service hostname through `TEAM_RELAY_ALLOW_HTTP_HOST` on the
isolated backend network. Do not reuse the exception for native clients or a
publicly reachable hostname. The [developer quickstart](quickstart.md) shows the
complete bootstrap and invitation commands.

Bootstrap and credential rotation also need a writable, current-user-private
directory for `--admin-token-file` or `--replacement-token-file` and their
short-lived recovery sidecars. With the read-only admin container, bind-mount
that exact host directory read-write. The quickstart uses `./secrets` for this
purpose. Never mount a broad home or project directory just to make it writable.

## Non-Docker

Run `team-relay-server` with:

- `REDIS_URL`: `redis://` or `rediss://` compatible endpoint.
- `TEAM_RELAY_ADDR`: listen address; default `127.0.0.1:8080`.
- `TEAM_RELAY_BOOTSTRAP_TOKEN_FILE`: required through confirmed bootstrap and
  any exact lost-response retry. Keeping it configured afterward cannot create
  a second organization; the endpoint permits only the original exact replay.
- `TEAM_RELAY_HEALTH_URL`: optional container healthcheck URL.

Use a service manager such as launchd, systemd, or Windows Service Control and
store credentials with the platform's secret facility.

## TLS and scaling

Use Caddy, nginx, Traefik, or another standards-based reverse proxy. It must
support long-lived SSE connections and disable response buffering for `/v1/events`.
Native clients bound the connection and response-header phase separately, then
leave a healthy SSE response open until caller cancellation or disconnection;
do not impose a short total-response timeout at the reverse proxy.
Identity headers from a reverse proxy are ignored; Team Relay bearer credentials
remain authoritative.

The relay has no built-in per-device, per-IP, storage-byte, or SSE-connection
rate limiting in this preview. For controlled network testing, configure limits
at the reverse proxy and monitor Redis/Valkey memory. This is compensating
protection, not a substitute for application-level quotas before public release.

The developer preview supports one relay replica. Durable request state is in
Redis/Valkey, but low-latency SSE fan-out is currently process-local. Redis
Streams or Pub/Sub fan-out is required before running multiple replicas.

## Recipient-process isolation

The native recipient and its Claude Code, Codex, or external child currently run
under the same OS user. The child receives a small operational environment plus
recipient-named `environment_allowlist` entries; `TEAM_RELAY_*` variables are
always removed. Environment filtering does not stop that child from reading the
user's Team Relay config, device token, or local approval token by filesystem
path. Do not treat native file modes as a sandbox. Use the preview only with
trusted local runtime installations and controlled requests until a separate
identity or equivalent filesystem boundary is implemented.
