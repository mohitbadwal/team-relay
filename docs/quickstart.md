# Developer quickstart

This guide starts a loopback-only relay and two separately enrolled local client
identities for a single-machine developer test. The relay rejects self-targeting,
so the requester and recipient must never share one device credential or config.
This is not a production deployment. Use HTTPS for traffic between machines and
read the release blockers in [the security model](security-model.md) first.
Recipient runtimes currently share the receiver daemon's OS identity, so they
may be able to read its local credentials or leave a background process behind.
The controls below reduce exposure but do not provide process isolation.

## 1. Build the native client commands

```bash
mkdir -p bin
go build -o bin/team-relay ./cmd/team-relay
go build -o bin/team-relay-agent ./cmd/team-relay-agent
go build -o bin/team-relay-mcp ./cmd/team-relay-mcp
```

The relay and administrator commands in this guide run from the Compose image;
Go is needed only on the workstation building these preview client binaries.

## 2. Start the state service and relay

Generate a bootstrap credential:

```bash
export TEAM_RELAY_UID="$(id -u)"
export TEAM_RELAY_GID="$(id -g)"
install -d -m 700 secrets
(
  umask 077
  docker compose run --rm --no-deps admin \
    generate-bootstrap-token > secrets/bootstrap-token
)
```

Do not put `secrets/bootstrap-token` in source control or a shell argument. On a
platform without `install` or `umask`, create the file with the OS credential
store or ACL so only the current operator can read it. Keep the UID and GID
exports in the shell used for the remaining Compose commands; they let the
non-root relay and administrator containers read owner-only mounted token files.
Then:

```bash
docker compose up -d --build
curl http://127.0.0.1:8080/health/ready
```

## 3. Bootstrap the administrator

```bash
docker compose run --rm --no-deps \
  --volume "$PWD/secrets:/run/team-relay-admin:rw" \
  admin bootstrap \
  --server http://relay:8080 \
  --token-file /run/team-relay-admin/bootstrap-token \
  --admin-token-file /run/team-relay-admin/admin-token \
  --organization "Example Team" \
  --name "Relay Admin" \
  --email admin@example.test
```

Before the request, the admin client stages the generated credential in the
owner-only `admin-token.bootstrap-attempt` file; the relay receives only its
hash. It publishes `/run/team-relay-admin/admin-token` after confirmation. If
the command reports an uncertain result, rerun the identical command: the
recovery file retains the credential and exact retry identity. Do not delete it
or generate a different token. See [the administrator guide](admin.md) for
rotation.

## 4. Create a teammate invitation

```bash
docker compose run --rm --no-deps \
  --volume "$PWD/secrets:/run/team-relay-admin:ro" \
  admin invite create \
  --server http://relay:8080 \
  --token-file /run/team-relay-admin/admin-token \
  --name "Alice" \
  --expires 24h
```

Deliver the `tr_inv_...` value privately. It can be used exactly once. For this
local test, save only that value in `/private/path/alice-invite` and restrict the
file to the receiving OS user.

## 5. Join from the recipient workstation

Choose a runtime and permission profile. This example deliberately uses the
invitation file instead of putting the credential in shell history or requiring
an interactive end-of-file keystroke:

```bash
bin/team-relay setup \
  --server http://127.0.0.1:8080 \
  --invite-file /private/path/alice-invite \
  --name "Alice" \
  --device-name "Alice developer test" \
  --runtime claude-code \
  --permission read_only \
  --work-dir "$PWD" \
  --workspace repo="$PWD"
```

Available runtimes are `claude-code`, `codex`, and `external`. An external
runtime also requires `--executable /absolute/path/to/runner`; use
`--external-id local-agent` for its stable identity and optionally
`--external-name "Local Agent"` for its display name. Available permission
profiles are `read_only`, `guarded_write`, and `custom`.

MCP inheritance is provider-specific. Claude Code and external runtimes default
to `--inherit-mcps=true`; pass `--inherit-mcps=false` to disable it. Codex setup
defaults to false because the current CLI cannot launch from an exact,
secret-safe MCP snapshot. An explicit `--inherit-mcps=true` with Codex is
rejected before enrollment. A typical Codex setup therefore uses
`--runtime codex --permission guarded_write --inherit-mcps=false`.
`team-relay-agent doctor` also verifies that the installed Codex supports the
required isolation controls and that no MCP remains active through system or
managed configuration.

`--model` is optional. When omitted or blank, Team Relay does not add a model
override. Claude Code and external runners then use their normal local default.
Isolated Codex runs do not load `config.toml`, so they use Codex's
built-in/account default; pass `--model <model>` when the recipient needs an
exact configured choice. A requester cannot select it.

The generated profile gives child runtimes only a small operational environment.
If this recipient's runtime or an inherited MCP requires an environment
variable, add its **name**, not its value, to `environment_allowlist` in the
private `config.yaml`, then export the value in the environment that starts
`team-relay-agent`. Team Relay authority variables are always blocked; see
[the runtime guide](runtime-adapters.md).

Before its first network call, setup generates the complete device credential
and a private enrollment retry ID locally. On Unix it stores every config,
token, retry, and staging file with mode `0600` inside a `0700` directory. On
Windows it creates the directory and files with protected DACLs granting access
only to the current user; the directory ACL also protects newly created child
state. ACL setup is part of creation and fails closed. Existing state
directories are revalidated and rejected if they are not already private;
likewise, a config, device token, control token, pending-inbox snapshot, or
receiver mutation, standing-grant, or session snapshot whose file privacy was
relaxed is rejected on load. File
contents are flushed before publication,
and only credential hashes cross the network. The relay binds the retry ID to
the exact enrollment request, so a lost HTTP response can be retried without
creating a second device or requiring a new invitation. `config.yaml` is
published last as the local completion marker.

If setup reports an unknown enrollment outcome or a publication failure, keep
the original invitation and rerun the **identical** setup command. The saved
`config.yaml.enrollment-attempt` record causes the same device credential and
retry ID to be reused; it is removed only after the final configuration is
durably published. A changed server, invite, identity, runtime, permission,
model, path, or generated configuration is rejected instead of being guessed.
Do not delete or move the recovery record blindly. Once setup succeeds, run
`team-relay-agent doctor`. An administrator who revokes the member or device
also invalidates enrollment retries for it.

An abrupt crash before the recovery record itself is durable can still leave an
empty reserved destination or a `.<name>.setup-*` file. Inspect those files
before removing them; no enrollment network call occurs until the complete
credential and recovery record have both been flushed.

Windows publication uses same-directory replacement with write-through because
Windows does not expose a supported POSIX-style directory `fsync`. The files
remain individually atomic and their contents are flushed, but no application
can promise that the final directory entry survives a sudden power loss on
every Windows filesystem and storage stack.

Verify the locally selected runtime before accepting work:

```bash
bin/team-relay-agent doctor
```

Then start the recipient process:

```bash
bin/team-relay-agent run
```

With no standing grants, the receiver never runs a remote request until the
recipient makes a local decision. Keep `run` active in one terminal. After the
requester sends a proposal, use a second terminal to list pending requests:

```bash
bin/team-relay-agent pending
```

This CLI and its authenticated loopback API are the approval interface in the
current preview. There is no packaged tray or system-notification approval UI.

Before deciding, inspect the complete prompt, requested workspace modes, and
attachment metadata. The inspection step does not start the runtime or release
attachment bytes. Then deny the request or choose one approval level:

```bash
bin/team-relay-agent inspect REQUEST_ID
bin/team-relay-agent approve REQUEST_ID ask_always
# or: approve matching turns in this conversation for a fixed 30 minutes
bin/team-relay-agent approve REQUEST_ID conversation_30m
# or: approve this server-authenticated teammate on all enrolled devices
bin/team-relay-agent approve REQUEST_ID teammate_always
# or: approve all teammates to this receiver
bin/team-relay-agent approve REQUEST_ID all_always
# or
bin/team-relay-agent deny REQUEST_ID
```

The approval values mean:

- `ask_always` allows this turn, stores no standing grant, and prompts again for
  the next request. The legacy `allow-once REQUEST_ID` command is equivalent to
  `approve REQUEST_ID ask_always`.
- `conversation_30m` allows this turn and matching turns in this conversation
  for 30 minutes from this decision. The deadline is fixed and does not slide
  forward when another turn arrives.
- `teammate_always` allows future requests from the same server-authenticated
  member identity to this receiver. It follows the teammate across devices that
  an administrator enrolls under that member identity.
- `all_always` allows future requests from every teammate to this receiver,
  including authenticated teammates enrolled later. It never applies to another
  receiving installation.

Each standing grant also captures the resource ceiling of the request used to
create it. A later request can match only if it uses the same approved workspace
aliases or a subset, requests the same or a weaker mode for every alias, and has
no more attachments or total decoded attachment bytes than the approved
request. A zero-attachment grant therefore cannot automatically approve a
request with files. A broader request returns to this manual decision flow.

Standing grants are private local state. They can be reviewed and withdrawn at
any time:

```bash
bin/team-relay-agent approval-grants
bin/team-relay-agent revoke-approval-grant GRANT_ID
```

Changing the relay enrollment or device credential, recipient agent identity,
effective runtime policy/configuration, or resolved workspace configuration
invalidates old grants automatically. Runtime configuration includes the fixed
executable and arguments, model override, environment allowlist, timeout, and
effective MCP isolation. Claude Code freezes its exact filtered MCP records when
the receiver starts; Codex recipient runs use an exact empty MCP inventory that
is checked again immediately before launch.
The effective runtime working directory is also part of that binding, including
the directory resolved from process startup when `work_dir` was left blank.
Work directories and workspace paths are canonicalized, so the binding follows
the resolved filesystem location rather than a symlink or other alternate
spelling. Restart the receiver after changing local runtime or MCP configuration;
the new fingerprint intentionally returns future requests to manual approval.

The selected scope becomes durable before the receiver sends this request's
`allow_once` decision. If that HTTP response is lost, retrying the same request
reuses the same scope and decision identity; a conflicting second choice cannot
replace it. Revoking a standing grant stops it from matching new requests. It
does not retract a per-request `allow_once` decision that was already durably
prepared or accepted; cancel that request separately when needed. Revocation
also leaves a durable local tombstone, so crash recovery cannot recreate the
withdrawn grant. A later, explicit recipient approval may intentionally create
that grant again.

The authenticated loopback control API exposes the same operations:
`POST /v1/requests/{request_id}/approve` with JSON `{ "level": "..." }`,
`GET /v1/approval-grants`, and `DELETE /v1/approval-grants/{grant_id}`.
While a teammate runtime is active, every authenticated control endpoint except
`/health` returns HTTP `423 Locked`; health remains available to a local
supervisor. This narrows the same-user exposure window but is not a security
boundary against a hostile child or a process it leaves running.

The requester cannot request, select, or see approval grants. A missing or
legacy requester member identity fails closed to manual approval. A grant only
skips repeated human prompting; it never expands the runtime, workspace, MCP,
network, shell, tool, or other recipient policy. For every matched request, the
receiver still records a fresh relay `allow_once` decision and execution claim.

The approval scope, standing grant, per-request decision, execution claim, and
exact result payload are stored in the recipient state directory before their
corresponding network mutations. Repeating an approval after an uncertain
network response reuses the same decision identity. Startup and periodic
heartbeat reconciliation safely resume a claim that never crossed its durable
runtime-start boundary and replay a prepared result. The receiver never
automatically reruns a runtime that may already have started. Run only one
receiver daemon per state directory; a second daemon is rejected before it
publishes a heartbeat or recovers work.

Immediately before `MarkRunning`, the receiver recomputes the fetched prompt's
SHA-256 and compares the requester agent and authenticated member identity,
title, expiry, requested access, and attachment descriptors with the approved
pending notice. A changed execution payload is rejected before the runtime-start
boundary.

## 6. Load the requester MCP

The recipient config above cannot request itself. Repeat Step 4 with
`--name "Bob"`, save only the new invitation token as
`/private/path/bob-invite`, and enroll a separate requester identity and config.

```bash
bin/team-relay setup \
  --server http://127.0.0.1:8080 \
  --invite-file /private/path/bob-invite \
  --name "Bob" \
  --device-name "Bob requester test" \
  --runtime claude-code \
  --permission read_only \
  --work-dir "$PWD" \
  --workspace repo="$PWD" \
  --outbound-attachments \
  --config /private/path/bob/config.yaml
```

`--outbound-attachments` is an explicit workstation-owner opt-in. Omit it when
the requester must not upload local files.

Every caller must publish a live heartbeat before sending. Start Bob's agent
with separate state and control paths so it does not collide with Alice's local
receiver; `--accepting-requests=false` keeps this requester-only identity out of
the accepting-recipient list:

```bash
bin/team-relay-agent \
  --config /private/path/bob/config.yaml \
  --state-dir /private/path/bob/state \
  --control-address 127.0.0.1:8788 \
  --accepting-requests=false \
  run
```

Configure the requester agent to launch the MCP with Bob's config:

```text
/absolute/path/bin/team-relay-mcp --config /private/path/bob/config.yaml
```

Install `skills/requester/SKILL.md` into the requesting client and
`skills/recipient/SKILL.md` for recipient runtimes. Client-specific automated
installers are planned; the skill text is already provider-neutral.

The current file limits in both directions are five files, no more than 2 MiB
per file, and no more than 2 MiB decoded content across the whole request or
result. Returned files require a write-capable recipient profile. The requester
MCP saves a returned file only as a direct child of a fixed
`team-relay-downloads/` directory beneath the selected local workspace alias;
it rejects non-portable Windows names and never overwrites an existing file.
