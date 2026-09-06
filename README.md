# Team Relay

[![Build](https://github.com/mohitbadwal/team-relay/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mohitbadwal/team-relay/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platforms](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-5B6573)](docs/quickstart.md)
[![MCP](https://img.shields.io/badge/MCP-compatible-6B4EFF)](skills/requester/SKILL.md)
[![Install with your AI agent](https://img.shields.io/badge/Install_with-your_AI_agent-D97757.svg)](#let-your-ai-agent-install-it)

**Ask your teammate's agent, not just your teammate.**

Team Relay is an open-source, self-hosted, permission-gated way for one local AI
agent to ask a teammate's local AI agent for help. The recipient sees the
request, chooses its scope, and keeps control of the runtime, model, tools,
repositories, and files used on their machine.

![Team Relay approval flow](docs/assets/team-relay-approval.gif)

*Illustrated approval flow. The macOS client now includes a native menu-bar app;
this GIF is still a design illustration, not a recording of the app.*

> **Status:** developer preview. The core protocol has automated tests,
> but this is not a production release and has not had an independent security
> audit. Do not expose it to untrusted users or the public internet. In
> particular, recipient runtimes still run as the workstation user and can read
> that user's Team Relay credentials or leave a background process behind, and
> the relay has no built-in request or connection rate limiting. These are
> public-release blockers.

## Join an existing team

**Teammates install the client. Only the admin installs the shared server.**
Your client handles both directions: an MCP in your usual agent sends requests;
the menu-bar app receives requests and lets you approve the work.

### macOS: one setup window, then the menu bar

Source preview requirements: macOS 13+, Go 1.24+, Apple Command Line Tools,
and a signed-in Claude Code or Codex installation.

```bash
git clone https://github.com/mohitbadwal/team-relay.git && cd team-relay && ./install-native
```

The installer opens **Team Relay.app**. There are two short screens:

1. Paste the **relay address and invitation** your admin sent you. Your name
   is prefilled.
2. Choose **Claude Code or Codex**, your usual **working folder**, and
   **read-only or guarded tools**, then click **Connect**.

Model overrides and outbound file sharing are optional settings. Skills are
**always included**—there is no separate skill-install prompt. Connect registers
the Team Relay MCP in the selected agent at user scope, installs the requester
and recipient skills, checks the actual MCP tool handshake and receiving runtime,
and starts the local connection. Credentials stay in private files, not process
arguments or the agent's MCP configuration.

If a later step fails, the app keeps the enrollment and offers **Finish setup**;
you do not need another invitation. It preserves other MCPs, customized skills,
and existing enrollment. A conflicting `team-relay` entry from a different
installation is reported, never silently overwritten.

After setup, use **TR** in the menu bar for:

- Start, stop or restart your connection.
- Compact incoming-request approvals: allow once, allow this conversation for
  30 minutes, always allow a teammate, or always allow your team.
- Pending requests, saved-allowance revocation and teammate discovery.
- Activity/logs, setup checks and integration repair.

Stopping the connection stops receiving work; it does not uninstall the outgoing
MCP. Quitting the menu-bar app leaves the connection running. Starting the native
connection registers it for future user logins. The setup checkbox controls
whether the menu-bar app also opens at login.

The app is built at `bin/Team Relay.app`; reopen it from Finder. This is a
**source-built preview**, not yet a signed/notarized download or a Windows/Linux
tray release. Native Windows/Linux binaries and the advanced headless setup
remain available; they do not yet have this UI. External adapters also use the
advanced setup for now. Runtime configuration changes after enrollment still
use `config.yaml`; the app does not yet include a profile editor.

### Send a request from your agent

Start a **new chat** in the Claude Code or Codex client you selected, so it loads
the newly installed MCP and skills. Tell it:

> Find my available teammates using Team Relay.

Then:

> Ask Suyog's agent to explain how their repository handles authentication.
> Ask for a short summary and relevant file paths.

Your agent discovers the exact teammate and sends the request through the MCP.
Their menu-bar app asks for approval. The answer and any returned files come
back to **your agent chat**. No sender command or separate sender app is needed.

The receiving runtime's tools remain governed by local policy. In particular,
the current Codex adapter requires guarded tools and disables inherited MCPs
**inside incoming teammate sessions**. This does not disable the outgoing MCP
installed in your normal Codex chat. Choose Claude Code when incoming work needs
supported local MCPs or the strict shell-disabled read-only profile.

## Set up the shared relay — admin only

Run this **once**, on the computer or host that will serve the team.

### Docker

Requires Docker with Compose and `curl`; no local Go installation is needed.

```bash
git clone https://github.com/mohitbadwal/team-relay.git && cd team-relay && ./install-docker
```

This installs the relay, Valkey and admin tooling, and guides administrator
bootstrap. Create invitations following the [admin guide](docs/admin.md), then
send each teammate the relay address and their invitation privately.
**Do not send teammates server-start commands or administrator credentials.**

For a trusted LAN test, use `./install-docker --bind 0.0.0.0` and give teammates
the host's actual private-IP address, such as `http://192.168.1.4:8080`.
Never give them `0.0.0.0` as a destination. HTTP is unencrypted: tokens, prompts
and files can be observed on the network. Use HTTPS for normal shared deployments.

### Without Docker

Run `./install-native --admin` to additionally build the shared server and admin
commands. Provide Redis or Valkey and follow the [native deployment guide](docs/deployment.md).
This is an administrator flow, not teammate onboarding.

### Advanced configuration and headless operation

Both installers preserve an editable, private `team-relay.conf`. Server and
connection lifecycles are independent internally; the teammate UI hides that
infrastructure distinction. The underlying start/stop/status/logs commands remain
available for administrators, automation and troubleshooting in the
[deployment guide](docs/deployment.md) and [developer quickstart](docs/quickstart.md).

Use `./install-native --headless` for the terminal setup, or `--no-open` to build
the macOS app without opening it. The source preview still requires its build
tools; prebuilt signed installers are not published yet.

## Let your AI agent install it

Copy this into your coding agent:

```text
Install the Team Relay teammate client from https://github.com/mohitbadwal/team-relay.
Read its README and security notes, then run ./install-native.
On macOS, leave the final setup choices to me in the Team Relay window.
Do not install or start the shared relay server unless I explicitly ask to host it.
MCP registration and requester/recipient skills should be included automatically.
Do not paste credentials into chat, command arguments, logs or source control.
Preserve my existing integrations and report conflicts rather than overwriting them.
```

## How it works

```text
requester agent -> local MCP -> relay server -> recipient daemon
                                                   |
                                   Inspect -> choose approval / Deny
                                                   |
                               Claude Code / Codex / external runtime
```

- The relay uses ordinary HTTP/SSE plus Redis or Valkey. It has no cloud,
  Kubernetes, or proprietary-gateway dependency.
- An administrator creates a short-lived, single-use invitation. Enrollment
  exchanges it for one revocable device credential. The client durably creates
  that credential before the request and uses an exact-match retry identity, so
  a lost response does not create a second device or lose the credential.
- Bootstrap and administrator rotation generate and durably stage the new
  administrator credential in the admin client before contacting the relay.
  Only its hash crosses the network. Exact retries recover a lost response;
  the server never generates or stores the raw administrator credential.
- The recipient chooses their runtime, optional model override, working
  directory, and permission profile locally. `--model` is an optional
  recipient-owned override. Claude Code and external runners retain their
  normal local default when it is blank; isolated Codex runs use Codex's
  built-in/account default because mutable user configuration is excluded. A
  requester can never select a model or increase permissions.
- Requests, follow-ups, answers, and bounded files retain conversation affinity
  without exposing either runtime's private session ID. Each request or result
  may contain at most five files, 2 MiB per file and 2 MiB decoded in total.
- Uploads reject symlink components and non-portable filenames. Returned-file
  downloads are confined to a fixed `team-relay-downloads/` directory beneath
  the selected local workspace and never overwrite an existing file.
- Request prompts and files are untrusted input. The recipient can inspect the
  complete prompt and file metadata before deciding; runtime execution and file
  bytes remain gated. Each turn receives a fresh relay `allow_once` decision,
  either after a human prompt or after the receiver matches a private local
  standing grant.
- Before marking the request running, the receiver fetches the gated execution
  payload, recomputes the prompt SHA-256, and compares its requester agent and
  member identity, title, expiry, requested access, and attachment descriptors
  with the locally approved pending notice. Any mismatch fails closed.
- Recipient decisions, execution claims, and result submissions use private
  durable write-ahead state. Exact retries recover lost HTTP responses without
  running the local agent twice or changing an already terminal result. An
  operating-system lock rejects a second receiver daemon using the same state
  directory before it can contact the relay or execute a shared claim.
- Device/member revocation deletes collaboration presence, permanently
  tombstones the random agent IDs, and closes their active SSE streams after
  the authoritative credential revocation commits.

## Recipient approval choices

The recipient chooses how often the local receiver should prompt:

- `ask_always` — allow this request, save no grant, and ask again next time.
- `conversation_30m` — allow this request and automatically approve matching
  turns in the same Team Relay conversation for 30 minutes. The deadline is
  fixed when granted; later activity does not extend it.
- `teammate_always` — allow this request and future requests from the same
  server-authenticated member identity, including that teammate's other or
  future enrolled devices, to this receiver.
- `all_always` — allow this request and future requests from all authenticated
  teammates to this receiver, including members enrolled later.

Standing grants are private recipient-local state. The recipient can list them
with `team-relay-agent approval-grants` and revoke one with
`team-relay-agent revoke-approval-grant GRANT_ID`. The requester cannot request,
select, or inspect a grant. A legacy request without a server-authenticated
requester member identity never matches a standing grant and returns to manual
approval. Grants are also invalidated if the receiver's relay enrollment,
recipient agent identity, effective permission profile, resolved workspace
configuration, or runtime configuration changes. The runtime binding covers the
recipient-selected executable, arguments, model, environment allowlist, timeout,
working directory, and effective MCP isolation. Claude Code freezes the exact
filtered MCP inventory when the receiver starts. Codex currently permits only
an exact empty MCP inventory for recipient runs; `doctor` verifies the required
CLI controls and rejects any MCP still supplied by system or managed
configuration. Working directories and workspaces are bound by their canonical
resolved paths, not merely the path text in configuration. Restarting after an
authority-changing configuration update invalidates earlier grants.

Every standing grant also records the resource ceiling of the request that
created it. A future request can match only when it uses the same approved
workspace aliases or a subset, asks for the same or a weaker mode for each, and
does not exceed the approved attachment count or total decoded bytes. A grant
created without attachments cannot automatically approve a request with files.
Any broader request returns to manual approval.

A grant skips only repeated human prompting. It never expands the recipient's
runtime, model, workspace, write, shell, MCP, network, tool, or environment
policy. The receiver still records a new relay `allow_once` decision and unique
execution claim for every request.

The chosen scope is written locally before that request's relay decision is
attempted, so an uncertain retry cannot silently change the recipient's choice.
Revoking a grant writes a durable tombstone, so crash recovery cannot silently
recreate it. Revocation stops future matches; it does not retract an
`allow_once` decision already durably prepared for one specific request.

## Receiver permission profiles

- `read_only` — requests the strongest inspect-only mode implemented by the
  selected adapter. Claude Code uses a read-tool allowlist, not an
  operating-system filesystem sandbox. Codex has native write denial but no
  portable shell-disable control, so the receiver fails closed instead of
  running Codex under a `read_only` profile it cannot fully honor.
- `guarded_write` — enables normal editing and tools for recipient-selected
  directories. Command-pattern and nested-relay denial are best-effort where a
  provider CLI has no stronger primitive. Claude Code may inherit its frozen,
  filtered MCP set. Current Codex recipient runs must keep MCP inheritance off.
- `custom` — recipient-owned `allow_writes`, `allow_shell`, `allow_mcps`,
  `network`, and additional denied-command settings. Per-MCP allowlists and
  independently disabling inherited memories/skills are not implemented.
  Claude Code refuses the unsafe combination of shell access with writes
  denied, because Bash itself can modify files.

Runtime adapters report `native`, `tool_level`, `best_effort`, or `unsupported`
enforcement. In the current preview, the receiver refuses Allow Once for any
request containing a read-only workspace when the recipient's local profile
allows writes; mixed per-workspace access is not supported by any adapter. See the
[runtime guide](docs/runtime-adapters.md) for the exact boundaries.

Runtime children receive a small operational environment by default. A
recipient can opt in additional variable names with `environment_allowlist`;
the values still come from the receiver daemon's environment and are not stored
in `config.yaml`. Team Relay authority variables are always removed, even if
named explicitly.

## Deployment boundary

The Compose stack contains the relay and one state service. Valkey, a
Redis-protocol-compatible server, is the default; Redis is a supported
alternative selected through `.env`. Only one is required. The default
published port is loopback-only. HTTPS is required for public addresses and DNS
hostnames; unencrypted HTTP to literal private IPs is available for trusted LAN tests.

The recipient receiver remains native because it needs the recipient's local
agent CLI, repositories, memories, MCP configuration, credentials, and approval
workflow. In the current preview, approval is through the local CLI/control
endpoint rather than a packaged tray or system-notification UI. While a
teammate runtime is active, every sensitive loopback control endpoint returns
HTTP `423 Locked`; only authenticated health remains available.

This is defense in depth, not an isolation boundary: the runtime shares the
workstation user's OS identity, can potentially read Team Relay's own device or
approval credentials, and may leave a background process behind. Use only on a
controlled test machine until child-process identity and filesystem isolation
are implemented.

## Repository map

```text
cmd/team-relay             enrollment and local setup
cmd/team-relay-admin       bootstrap, admin rotation, invites, revocation, audit
cmd/team-relay-server      relay server
cmd/team-relay-agent       recipient runtime and approval loop
cmd/team-relay-mcp         requester MCP over stdio
internal/collaboration     directory, requests, approvals, artifacts, SSE
internal/runtime           Claude Code, Codex, and external adapters
internal/store             organization, member, device, invite, audit state
skills                     requester, recipient, and administrator guidance
```

## Documentation

- [Architecture mental model](docs/architecture.html)
- [Quickstart](docs/quickstart.md)
- [Administrator flow](docs/admin.md)
- [Runtime adapters and permissions](docs/runtime-adapters.md)
- [Deployment](docs/deployment.md)
- [Security model](docs/security-model.md)

## License

Apache-2.0. Claude, Anthropic, Codex, OpenAI, Redis, and Valkey are trademarks
of their respective owners. This project is not endorsed by those projects or
companies.
