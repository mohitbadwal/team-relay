# Deployment

## Docker Compose

For a new single-node relay host, run `./install-docker` from the repository
root. It performs the private bootstrap-file, UID/GID, Compose startup, health,
and first-administrator steps below as one guided flow. The details in this
section remain useful for production review and recovery.

The default stack uses Valkey, a Redis-protocol-compatible state server. Redis
is a supported alternative; the relay requires one of them, never both.

- The state service has no published host port.
- Data uses a persistent volume with append-only persistence enabled.
- The relay runs as a non-root user with a read-only root filesystem and no
  Linux capabilities.
- The relay publishes only to `127.0.0.1` by default.
- Only the relay joins the ordinary `frontend` bridge for host port publishing;
  it also joins the internal `backend` network shared with Valkey and the admin
  client. Valkey and admin remain on `backend` only. An internal-only relay can
  be healthy inside Docker while its host port is unavailable.
- Bootstrap material is mounted as a Compose secret rather than committed in
  `.env`.

The installer requires host `curl` and verifies `/health/ready` through the
published loopback address before reporting success. If an older installation
reported `http://invalid IP:0`, update the checkout and rerun `./install-docker`.
Compose recreates the relay with its additional network and preserves the state
volume and administrator credentials.

### Choose who can reach the relay

Local-only is the default. To publish on all IPv4 interfaces:

```bash
./install-docker --bind 0.0.0.0
```

The installer saves `TEAM_RELAY_BIND_ADDRESS=0.0.0.0` in `.env`, so subsequent
installer and `docker compose up` runs keep the setting. Use
`./install-docker --bind 127.0.0.1` to return to local-only. The supported values
are `127.0.0.1` and `0.0.0.0`; an explicit `--bind` wins over an environment
variable, which wins over `.env`. The installer persists the selected value.
For Compose-only usage, set `TEAM_RELAY_BIND_ADDRESS` in `.env` or the environment.
Set `TEAM_RELAY_PORT` in `.env` to change the published port (default `8080`).

`0.0.0.0` is a listening address, not a URL to send teammates. Use a reachable
host IP or DNS name. The readiness check still uses `127.0.0.1` locally; it does
not prove access from another machine. Publishing to all interfaces may expose
the service publicly depending on the host's networking. Restrict access with
firewall rules and put an HTTPS reverse proxy in front before sending tokens
over the network. Native clients reject non-loopback HTTP by default. This
option does not publish Valkey or change authentication.

### Container identity and administration

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

Run `./install-native` first to build all Team Relay commands into `./bin`. The
installer does not claim to provision Redis/Valkey or register a durable OS
service; those remain explicit operator choices.

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
