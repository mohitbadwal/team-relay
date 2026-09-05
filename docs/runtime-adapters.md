# Runtime adapters and permissions

Team Relay abstracts local **agent runtimes**, not merely model APIs. A runtime
may bring project instructions, user memories, tools, MCP servers, credentials,
and private resumable sessions.

Bundled adapters:

- `claude-code` — Claude Code streaming JSON and private session resume.
- `codex` — Codex non-interactive JSON events and private thread resume.
- `external` — a fixed recipient-configured executable implementing
  `team-relay-runner/v1`.

The requester chooses a teammate. Only the recipient chooses runtime, binary,
model, policy, environment, MCPs, and working directories. The model setting is
an optional override. When blank, Claude Code and external runners use their
normal local default. Isolated Codex runs exclude `config.toml`, so blank means
Codex's built-in/account default; pass `--model <model>` during setup when an
exact choice matters. The requester cannot provide or change this value.

At receiver construction, each adapter computes a one-way approval fingerprint
over its recipient-owned executable, fixed arguments, model, environment
allowlist, timeout, effective policy, canonical work directory, and MCP
isolation. Claude Code freezes its filtered user/local MCP set once and reuses
that private snapshot for every run. Codex uses an exact empty MCP inventory:
it launches with user configuration ignored, integration sources disabled, and
project configuration untrusted. Enabling MCPs for a Codex recipient fails
closed because the current CLI cannot consume an exact, secret-safe snapshot.
`doctor` exercises the required offline CLI controls and rejects any MCP that
remains through a system or managed configuration layer. The receiver repeats
that residual-MCP check immediately before every Codex child launch.
These controls prevent a newly added MCP from silently broadening a standing
approval. The fingerprint is the only value exposed to approval state;
credential-bearing MCP JSON is never logged or stored there.

## Permission profiles

`read_only` asks the adapter for its strongest inspect-only mode. Claude Code
uses a `Read,Glob,Grep` tool allowlist; this is tool-level enforcement, not an
operating-system filesystem sandbox. Codex can natively deny writes and disable
network and MCP servers, but it has no portable switch that disables shell
execution. Because `read_only` explicitly denies shell, Team Relay fails closed
during `doctor`/startup and does not run that profile with Codex. Use a runtime
that reports shell control, or select a recipient-owned policy that allows
shell after considering the exposure. An external runner reports its own
enforcement, and the locally installed runner is part of the recipient's
trusted computing base.

`guarded_write` enables normal tools, editing, and network access. Claude Code
may also load the recipient-approved frozen MCP set; the Team Relay requester
MCP is excluded so an approved task cannot recursively ask another teammate.
Current Codex recipient runs require `inherit_mcps: false`, ignore
`config.toml`, disable plugin/app/connector integration paths, and mark project
ancestors untrusted. They also disable hooks because executable hooks are not
conversational memory. Codex profiles and config- or feature-mutating prefix
arguments are rejected because they could reintroduce mutable MCP authority.

Claude Code always runs with `--strict-mcp-config` and a temporary private
file. That file is assembled only from the recipient's user-scoped and matching
local-scoped entries in `~/.claude.json`; disabled entries are honored, Team
Relay aliases/transports are removed, and the repository's `.mcp.json` is never
read by Team Relay. When MCPs are disabled, the file contains an empty server
map and Claude state is not read. Credential-bearing MCP JSON therefore stays
out of process arguments. Claude also receives a highest-precedence
`disableAllHooks` session setting, so ordinary user, project, local, and plugin
hooks cannot execute outside the tool policy; organization-managed hooks remain
under the recipient administrator's policy. Memories, project instructions,
skills, other settings, and the filtered recipient MCP set continue to load.
The bundled Team Relay MCP independently refuses to load credentials whenever
an adapter-owned recipient-run marker is present.

Claude Code releases before `2.1.246` may still pause to ask about a project
`.mcp.json` even in strict mode, although strict mode prevents those project
servers from loading. Upgrade Claude Code to `2.1.246` or newer to avoid that
startup/liveness issue. See the official [Claude Code MCP
documentation](https://code.claude.com/docs/en/mcp).

These nested-relay controls prevent ordinary and accidentally renamed local
configurations; they are not an operating-system sandbox against a malicious
wrapper owned by the same workstation user. Codex supplies its native
workspace-write sandbox. Claude Code uses provider tool controls and denied
command patterns, so its filesystem, network, destructive-command, and nested
relay restrictions are best-effort. The receiver currently refuses to transmit
an Allow Once decision for any request containing a read-only workspace when
the local profile permits writes, for Claude Code, Codex, and external runners
alike. Mixed per-workspace access is therefore not supported in this preview.

`custom` starts with capabilities disabled and accepts recipient-owned
`allow_writes`, `allow_shell`, `allow_mcps`, `network`, and `denied_commands`
settings in `config.yaml`. Filesystem locations come from the profile's
`work_dir` and the top-level `workspaces` aliases. `allowed_mcps` is rejected
because portable per-MCP enforcement is not implemented; MCP inheritance is
all-or-none. `deny_nested_team_relay` cannot be disabled. Independently
disabling inherited user config, project instructions, or skills is also not
supported across every bundled runtime. Claude Code rejects
`allow_writes: false` together with `allow_shell: true`: omitting Edit and Write
does not make Bash read-only, because shell redirection and invoked programs can
still modify files.

For example, this Codex custom profile permits shell explicitly while denying
writes, network, and MCPs:

```yaml
profiles:
  default:
    runtime: codex
    executable: auto
    model: "" # use isolated Codex's built-in/account default; pin if required
    work_dir: /absolute/path/to/repository
    environment_allowlist:
      - MY_AGENT_PROVIDER_KEY # the value comes from the daemon environment
    policy:
      mode: custom
      allow_writes: false
      allow_shell: true
      allow_mcps: false
      network: deny
      denied_commands:
        - git push
      deny_nested_team_relay: true
```

`team-relay setup --permission custom` creates the conservative, disabled
baseline. Edit the generated private configuration explicitly to enable only the
capabilities the recipient wants. Custom switches still inherit adapter limits:
for example, Claude Code can omit its Bash tool when `allow_shell` is false,
whereas Codex fails closed for that setting because it has no portable
shell-only CLI switch.

For every mode, denied command strings are enforcement inputs or model guidance,
not a portable OS security boundary. Capability reporting distinguishes
`native`, `tool_level`, `best_effort`, and `unsupported`.

## Child-process environment

Runtime and probe processes start with a small operational set of variables for
paths, locale, certificates, proxies, and provider configuration directories.
They do not inherit the receiver daemon's entire environment. Add only the names
a runtime or inherited MCP actually needs to the profile's
`environment_allowlist`; values are read from the daemon environment at launch,
so secrets do not belong in `config.yaml`.

Variables beginning with `TEAM_RELAY_` are always stripped and cannot be
re-enabled through the allowlist. This protects relay authority from ordinary
child-process inheritance. It does not stop a runtime sharing the same OS user
from reading accessible config files, shell profiles, credential stores, or
other process-external secret sources.

## External runner protocol

The external executable and any prefix arguments are configured locally. The
same fixed command is invoked directly for probe and run operations, never
through a shell; remote input cannot select its path or arguments. Set a stable
runner identity during enrollment, for example:

```bash
team-relay setup \
  --server https://relay.example.com \
  --invite-file /absolute/private/path/invite-token \
  --name "Alice" \
  --device-name "Alice workstation" \
  --runtime external \
  --external-id local-agent \
  --external-name "Local Agent" \
  --executable /absolute/path/to/runner \
  --permission read_only \
  --work-dir /absolute/path/to/repository
```

`--external-id` defaults to `local`; `--external-name` is optional. The same
identity is stored at enrollment and advertised in receiver heartbeats.

For both operations, Team Relay invokes that same fixed command with no
operation subcommand. It writes exactly one newline-terminated JSON envelope (a
one-record NDJSON stream) to stdin and reads newline-delimited JSON (NDJSON)
envelopes from stdout.

```text
probe stdin:
  {"protocol":"team-relay-runner/v1","type":"probe"}

probe stdout:
  {"protocol":"team-relay-runner/v1","type":"capabilities","capabilities":{"version":"1.0","supports_resume":true,"supports_streaming":true,"supports_model_selection":true,"preserves_local_context":true,"loads_local_mcps":true,"policy":{"read_only":"native","guarded_write":"best_effort","filesystem_isolation":"native","network_isolation":"native","shell_control":"tool_level","mcp_control":"tool_level","destructive_command_deny":"best_effort"}}}

run stdin:
  {"protocol":"team-relay-runner/v1","type":"run","model":"recipient-optional-override", ...}

run stdout, one envelope per line:
  {"protocol":"team-relay-runner/v1","type":"started","session_id":"..."}
  {"protocol":"team-relay-runner/v1","type":"event","event":{...}}
  {"protocol":"team-relay-runner/v1","type":"result","result":{...}}
```

The probe capability-description response includes resume, streaming, model
selection, local-context, MCP, and every policy-enforcement field, including
`shell_control`. Set `supports_model_selection` to `true` only when the runner
can honor a non-empty `model` in the run envelope. Before a run, Team Relay
rejects an external runner that reports `unsupported` for the effective mode,
filesystem isolation, or destructive-command denial. Network isolation is also
required when network is denied, shell control when shell is denied, and MCP
control when MCP use is denied. `native`, `tool_level`, and `best_effort` are
honest strength declarations, not interchangeable security guarantees.

A run input includes the prompt, recipient-resolved work directory and approved
paths, effective policy, optional recipient-selected `model`, and an optional
private session ID. The `model` field is omitted when the setting is blank, and
the runner must then use its normal local default. A runner may instead emit a
protocol envelope with `type: "error"` and a bounded message. Each output line
must be one complete JSON object.

Secrets, prompts, tool inputs, and private session IDs must not be copied into
relay logs or safe progress summaries.
