---
name: team-relay-admin
description: Bootstrap and operate a self-hosted Team Relay, rotate administrator credentials, issue one-time invitations, revoke devices, and inspect metadata-only audit events.
---

# Team Relay administrator

- Bootstrap an uninitialized relay exactly once with a private `tr_boot_`
  credential and store the shown-once `tr_admin_` credential securely.
- Give teammates short-lived, single-use `tr_inv_` credentials. Never distribute
  a shared admin or device credential.
- Each enrolled installation receives a unique `tr_dev_` credential. Revoke a
  lost device individually; revoke a member only when every device should stop.
- When enrolling another device under an existing member, remember that a
  recipient's `teammate_always` grant intentionally follows that
  server-authenticated member identity across all of its enrolled devices.
- Rotate the administrator credential with `team-relay-admin credential rotate`.
  Secure the shown-once replacement immediately; the credential used for the
  rotation becomes invalid.
- Keep the public relay behind HTTPS. Do not enable trust in arbitrary proxy
  identity headers.
- Audit metadata may include actor, action, target, and time. Never place prompts,
  answers, attachments, tool inputs, provider credentials, or bearer tokens in
  administrative logs.
- Administration cannot view or choose recipient approval grants. The
  `ask_always`, `conversation_30m`, `teammate_always`, and `all_always` choices
  respectively mean this request only, a fixed non-sliding 30-minute
  conversation window, one authenticated member across enrolled devices, and
  all authenticated teammates on this receiver. They are private local receiver
  state. Every approved request still receives an
  exact relay `allow_once` decision, and no grant can bypass recipient-local
  runtime, workspace, MCP, network, or tool policy. Standing matches remain
  capped by previously approved workspace aliases and modes plus attachment
  count and decoded-byte volume. Changing relay enrollment, recipient agent,
  effective policy, fixed runtime configuration, effective MCP isolation, or
  canonical resolved work locations invalidates old grants. Claude Code freezes
  a filtered MCP inventory; current Codex recipient runs require MCP inheritance
  off and use an exact empty inventory.
- Revoking a local standing grant leaves a durable tombstone so receiver recovery
  cannot recreate it. It does not retract a per-request `allow_once` decision
  that was already durably prepared.
- Treat the current build as a private developer preview. Same-OS-user recipient
  isolation and application-level rate limits must be resolved before public
  exposure.

Skills are operational guidance, not authorization enforcement.
