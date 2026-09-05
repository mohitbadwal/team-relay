# Security model

The core authority rule is:

```text
authenticated sender
intersect shared organization
intersect recipient approval choice
intersect recipient permission profile
intersect runtime and operating-system enforcement
```

The network request is a proposal. It is not inherited permission to operate a
teammate's computer.

## Trust boundaries

- Remote prompts, files, URLs, answers, and artifacts are untrusted.
- Event notifications and the durable local pending list contain only a bounded
  preview and file metadata. The exact target may explicitly fetch the complete
  prompt for human inspection before deciding; this does not start the runtime
  or release attachment bytes. Attachment bytes and execution payloads remain
  gated until the receiver records that request's relay `allow_once` decision.
- Every follow-up receives a new per-request relay decision. It prompts the
  recipient unless a private local `conversation_30m`, `teammate_always`, or
  `all_always` grant matches; `ask_always` stores no standing grant.
- Immediately before `MarkRunning`, the receiver revalidates the gated execution
  payload against the locally approved pending notice. It recomputes the prompt
  SHA-256 and compares requester agent and authenticated member identity, title,
  expiry, requested access, and attachment descriptors. A mismatch fails closed
  before the runtime-start boundary.
- Terminal result fields are state-specific: completed results cannot carry an
  error, while failed or cancelled results cannot carry an answer or files.
  Answers are capped at 128 KiB and failure diagnostics at 4 KiB.
- The bundled requester MCP uploads only when the workstation owner enables it.
  It walks pinned directory handles, rejects symlink files and components before
  reading, and blocks common sensitive and agent-control paths. The relay
  independently validates portable direct filenames, including Windows device,
  alternate-data-stream, separator, and trailing-dot/space rules, plus Base64
  encoding, declared size, checksum, at most five files, 2 MiB per file, and
  2 MiB total decoded content. Alias and sensitive-source checks are local-client
  controls, not claims the relay can prove for a custom API client. Returned
  files have the same count and byte limits. Downloads are confined to a fixed
  `team-relay-downloads/` subtree, reject symlinked output roots, and never
  overwrite an existing file. Recipient result collection pins the original
  per-request return-directory identity, so replacing it with another request's
  directory or an in-root symlink is rejected.
- The requester cannot target any agent owned by its own member identity,
  including another enrolled device.
- Enrollment creates the raw device token locally before contacting the relay;
  only its hash crosses the network. A separate random retry identity is bound
  to the exact invite and enrollment fields, and the relay stores only its hash.
  Exact retries return the original device IDs, changed retries conflict, and a
  revoked member, device, or credential cannot be revived by retrying setup.
  Setup and receiver state directories use mode `0700` on Unix and a protected,
  inheritable current-user-only DACL on Windows. Config, credential, approval,
  standing-grant, inbox, and session files use mode `0600` on Unix or a protected
  current-user-only Windows DACL. The same protections are used for per-request
  artifact sandboxes. Files are created privately rather than created
  permissively and repaired afterward; loading fails if a file's
  platform-specific privacy check no longer passes.
- Bootstrap and admin rotation likewise create and durably stage raw admin
  credentials only in current-user-protected client files. Requests carry the
  new token hash and a separately generated retry identity; the relay stores
  only hashes bound to the exact operation. Bootstrap permits only an exact
  replay of the single completed initialization. A rotation retry whose old
  token was already invalidated authenticates with the staged new token and
  must match the durable rotation record.
- Revocation atomically commits credential/member/device state and permanent
  collaboration-agent tombstones in the same Redis transaction. It then removes
  those non-reusable agent IDs from presence and closes their process-local SSE
  subscriptions. The tombstone is checked on heartbeat, directory lookup,
  request targeting, and approval. A queued request whose sender was revoked is
  terminally cancelled instead of being released for execution.
- Runtime executable paths, flags, models, credentials, MCPs, and permission
  profiles are recipient-owned and never accepted from a remote request.
- Approval grants are private recipient-local state. The requester cannot ask
  for, select, or inspect them. `ask_always` authorizes only the current request
  and stores no grant. `conversation_30m` is bound to the conversation and its
  server-authenticated requester member identity, uses a fixed 30-minute
  deadline, and does not extend on activity. `teammate_always` is bound to the
  server-authenticated member identity and therefore covers that teammate's
  current and future enrolled devices. `all_always` covers all authenticated
  teammates only for this receiver. A missing or legacy requester member
  identity never matches and falls back to a human decision.
- Every standing grant is capped by the request that created it. A later request
  may use only previously approved workspace aliases (or a subset), with the
  same or weaker mode for each, and no more attachments or total decoded
  attachment bytes than the approved ceiling. A grant created without an
  attachment cannot match a request with one. Attachment names and contents may
  differ within that ceiling, so recipients should choose standing approval only
  when that future-file trust is intended. Any broader request requires another
  human decision.
- Each standing grant is bound to a one-way fingerprint of the relay enrollment
  and effective receiver configuration, plus the recipient agent ID. The
  effective runtime policy, executable, fixed arguments, model, environment
  allowlist, timeout, MCP isolation, and canonical resolved runtime working
  directory and workspaces participate in that binding. Claude Code freezes and
  reuses its exact filtered MCP inventory. Codex permits only an exact empty MCP
  inventory for recipient runs, ignoring user configuration and disabling
  current plugin/app/connector integration paths and hooks; enabling Codex MCP
  inheritance fails closed. An empty-home preflight rejects residual system or
  managed MCP entries during `doctor`, approval binding, and immediately before
  child launch. Restarting after an authority-changing configuration update
  produces a new fingerprint and prunes the old grant instead of carrying broad
  approval into new authority.
- A standing grant skips only repeated human prompting. It cannot expand the
  runtime, workspace, write, shell, MCP, network, tool, environment, or any
  other recipient-owned policy. Each matched request still follows the normal
  validation and execution lifecycle.
- Before contacting the relay, every approval—interactive or matched from a
  standing grant—durably records a recipient-generated 256-bit decision
  identity and a separate 256-bit execution claim. The relay still receives
  `allow_once` for that exact request; standing-grant state never crosses the
  network. The relay binds an exact decision retry to its request, target, and
  decision value; changed retries conflict. It atomically changes an accepted
  request to `running` for the winning execution claim. Retrying that claim is
  idempotent, a competing claim is rejected, and only the winning claim may
  submit a result.
- For an interactive standing choice, the selected scope and its local grant
  are durable before the current request's relay decision is attempted. An
  ambiguous retry must reuse that choice; a conflicting click cannot replace
  it. The receiver refuses to create an interactive approval or standing grant
  for another request while a teammate runtime is active. Revoking the grant
  writes a durable tombstone that prevents crash recovery from recreating it.
  Revocation prevents new matches but does not revoke a per-request decision
  already durably prepared under it; a later explicit approval can intentionally
  create the standing grant again.
- While a teammate runtime is active, the authenticated loopback control server
  returns HTTP `423 Locked` for every sensitive read or mutation; authenticated
  health remains available. This reduces the ability of the active same-user
  child to inspect or modify another request, but it is process-local defense in
  depth rather than an OS security boundary.
- The receiver holds an exclusive operating-system lock on its private state
  directory for the complete daemon lifetime. A second process using that state
  fails before heartbeat or recovery, preventing two processes from treating an
  exact same-claim retry as permission to execute twice.
- The receiver syncs a `runtime_started` boundary before spawning the runtime.
  A restart may safely finish a claim whose running response was lost before
  that boundary, but it refuses to spawn a runtime again after the boundary.
  This chooses at-most-once execution over automatic recovery at the unavoidable
  crash edge: a task can remain `running` even though its runtime never started.
- A completed or failed result, including returned file bytes, is durably staged
  before submission. The relay binds its digest to the request, target, winning
  claim, and terminal state, so the exact payload can be replayed after a lost
  response while a changed payload cannot alter the terminal result.
- Startup and periodic heartbeat reconciliation retry a prepared decision,
  safely finish a not-yet-started winning claim, and replay a prepared result
  even when SSE remained connected and only the mutation response was lost.
  Reconciliation also cancels an active runtime when a terminal relay state was
  missed on SSE. A journal whose request has aged out of relay retention is
  discarded instead of permanently blocking receiver startup.

## Relay visibility

Transport must use HTTPS outside loopback. The only bundled exception is the
one-shot Compose administrator service: it explicitly allows the exact `relay`
hostname on Compose's isolated internal network through
`TEAM_RELAY_ALLOW_HTTP_HOST`. Do not set that escape hatch for native clients or
an externally reachable network. Bearer credentials are stored as hashes.
Prompt and file payloads are nevertheless readable by the self-hosted relay
administrator while retained in Redis/Valkey; Base64 is not encryption.
End-to-end payload encryption is outside the first protocol version.

Logs and audit events must exclude prompt text, answers, file bytes, tool inputs,
commands, provider credentials, bearer credentials, and private session IDs.

Runtime children inherit only a small operational environment plus variable
names the recipient explicitly lists in `environment_allowlist`. Relay-authority
variables (`TEAM_RELAY_*`) are always removed. This is defense in depth, not
filesystem or same-user process isolation.

## Known preview limitations

- No independent security audit yet.
- Recipient runtimes run under the same OS identity as the native daemon. They
  can potentially read Team Relay device and local approval credentials by
  filesystem path; environment-variable scrubbing and output redaction are not
  a complete isolation boundary. The receiver blocks approval of a second
  request while a runtime is active, but a hostile runtime with shell/write
  access may still evade process-local controls or leave a background process.
  Separate child-process identity/filesystem isolation is required before public
  release.
- The relay has no built-in per-device, per-IP, storage-byte, or SSE-connection
  rate limits. Reverse-proxy limits are required for controlled network testing;
  application-level quotas remain a public-release blocker.
- One relay replica because live event fan-out is process-local.
- Runtime policy strength differs; capability reporting must be trusted rather
  than assuming every agent has an OS-level sandbox.
- Claude Code can remove Bash from its tool set, but cannot make an enabled Bash
  tool read-only. Its adapter therefore rejects any policy that allows shell
  while denying writes.
- Codex's read-only sandbox denies writes, but it cannot portably disable shell
  commands or hide every path readable by the workstation user. Team Relay
  therefore refuses a Codex policy that denies shell instead of advertising or
  running the composite `read_only` profile.
- External-runner capabilities are self-reported by recipient-installed code;
  Team Relay rejects missing required controls but cannot independently attest
  that a runner enforces what it declares.
- Local approval currently uses the CLI/control endpoint. There is no packaged
  tray, system-notification approval UI, native service installer, auto-updater,
  signed binary release, or release SBOM yet.
- A request whose durable `runtime_started` boundary was reached before a crash
  is not automatically reclaimed or rerun. Manual resolution is required; this
  avoids duplicate tool effects but can strand a request in `running`. The same
  applies to a running request with no matching local journal or a claim owned
  by a different state directory. Two daemons cannot concurrently own one local
  state directory.
- The current inline attachment limit is five files, 2 MiB per file, and 2 MiB
  total. Object storage is not yet implemented.
