# Administrator flow

Team Relay uses separate credentials for separate authority:

| Prefix | Purpose | Lifetime |
|---|---|---|
| `tr_boot_` | create the first organization and administrator | one bootstrap |
| `tr_admin_` | invitations, revocation, rotation, and metadata-only audit | until rotated |
| `tr_inv_` | enroll one new device/member | single use and expiring |
| `tr_dev_` | presence and collaboration for one device | until revoked |

Never give teammates a shared permanent team credential. Unique devices provide
attribution and let an administrator revoke one lost machine without disconnecting
everyone else.

Administrative commands:

```text
team-relay-admin generate-bootstrap-token
team-relay-admin bootstrap
team-relay-admin credential rotate
team-relay-admin invite create|list|revoke
team-relay-admin member list|revoke
team-relay-admin device list|revoke
team-relay-admin audit
```

With Docker Compose, replace `team-relay-admin` with
`docker compose run --rm --no-deps admin`. Bind-mount any required credential
file read-only, pass its container path with `--token-file`, and use
`--server http://relay:8080` while the relay service is running.

The admin client generates new administrator credentials locally, durably
stages them in a private recovery file, and sends only SHA-256 digests to the
relay. Bootstrap and rotation responses never contain a raw administrator
credential. Team Relay validates current member/device status on every
authenticated call.
Administrative audit data contains identities, actions, targets, and timestamps;
it must not contain prompt text, answers, file bytes, provider credentials, tool
arguments, or runtime session IDs.

Revoking a member revokes all of that member's devices. Revoking a device affects
only that installation. Requests created by an administrator still require a
recipient-controlled per-request decision, either from a human prompt or a
matching private local standing grant. After the authoritative revocation commits, the
relay removes the affected agents from its directory, records permanent
presence tombstones for their non-reusable agent IDs, and closes their active
SSE subscriptions. A request queued just before revocation can still be denied,
but can no longer be approved; an exact approval committed before revocation is
not retroactively cancelled. The revoked installation also cannot re-advertise
or attach another event stream afterward.
The HTTP operation is acknowledged only after presence eviction succeeds. If
that cleanup reports an error after credential revocation committed, the live
stream is still closed locally; retry the same idempotent revoke command to
finish durable presence cleanup.

## Bootstrap recovery

Bootstrap requires an explicit private destination for the first administrator
credential:

```bash
team-relay-admin bootstrap \
  --server https://relay.example.com \
  --token-file /private/path/bootstrap-token \
  --admin-token-file /private/path/admin-token \
  --organization "Example Team" \
  --name "Relay Admin" \
  --email admin@example.com
```

Before the network request, the client writes
`admin-token.bootstrap-attempt`. It contains the client-generated raw token and
retry identity with current-user-only protection. The relay stores only their
hashes and binds them to the exact normalized bootstrap fields. If the HTTP
response is lost, rerun the identical command. A changed organization, admin,
server, token, or retry identity conflicts; it can never create a second
organization. The client publishes `admin-token` and removes the recovery file
only after a confirmed exact response.

## Rotate the administrator credential

Rotation creates a replacement credential and invalidates the credential used
for the rotation in the same server operation:

```bash
team-relay-admin credential rotate \
  --server https://relay.example.com \
  --token-file /private/path/admin-token \
  --replacement-token-file /private/path/admin-token
```

`--replacement-token-file` defaults to `--token-file`; a separate destination
is required when the current credential comes from an environment variable.
Before contacting the relay, the client writes a private
`<replacement>.rotation-attempt` containing the locally generated replacement
and retry identity. The relay atomically records their hashes, installs the new
credential, and invalidates the old one. If its response is lost, rerun the same
command: it first tries the old credential and then safely proves the exact
operation with the staged new credential. On confirmation it atomically
publishes the replacement token file and removes the recovery record.

Do not delete an attempt file after an uncertain response. These local recovery
files contain raw credentials and must remain restricted to the current OS
user. The preview still supports one administrator identity; it has no offline
recovery if both the final token and its in-progress recovery file are lost.
