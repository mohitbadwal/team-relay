#!/bin/sh

# Exercise the real installer in a private checkout copy and an isolated Compose
# project. Nothing in the caller's .env, secrets, or running stack is reused.
set -eu
umask 077

repo_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
for dependency in docker curl jq git tar cmp; do
  command -v "$dependency" >/dev/null 2>&1 || {
    printf 'Docker install test requires %s.\n' "$dependency" >&2
    exit 1
  }
done
docker compose version >/dev/null
docker info >/dev/null

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/team-relay-docker-test.XXXXXX")
work_dir="$test_dir/checkout"
test_suffix=$(printf '%s' "${test_dir##*.}" | tr '[:upper:]' '[:lower:]')
project="team-relay-test-$test_suffix"
image="team-relay-install-test:$test_suffix"
mkdir "$work_dir"

# A caller may already have Compose overrides for their own deployment.
unset COMPOSE_FILE COMPOSE_ENV_FILES COMPOSE_PROFILES COMPOSE_DISABLE_ENV_FILE
unset TEAM_RELAY_STATE_IMAGE TEAM_RELAY_STATE_COMMAND TEAM_RELAY_UID TEAM_RELAY_GID TEAM_RELAY_BIND_ADDRESS
COMPOSE_PROJECT_NAME=$project
TEAM_RELAY_IMAGE=$image
TEAM_RELAY_PORT=0
TEAM_RELAY_INSTALL_ORGANIZATION='Installer Regression Team'
TEAM_RELAY_INSTALL_ADMIN_NAME='Installer Regression Admin'
TEAM_RELAY_INSTALL_ADMIN_EMAIL='admin@example.invalid'
export COMPOSE_PROJECT_NAME TEAM_RELAY_IMAGE TEAM_RELAY_PORT
export TEAM_RELAY_INSTALL_ORGANIZATION TEAM_RELAY_INSTALL_ADMIN_NAME TEAM_RELAY_INSTALL_ADMIN_EMAIL

fail() {
  printf 'Docker install test: %s\n' "$*" >&2
  exit 1
}

compose() {
  docker compose --project-name "$project" --project-directory "$work_dir" "$@"
}

# Refuse even an unlikely collision before taking ownership of any resources.
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ] || fail "test project already exists"
[ -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ] || fail "test volume already exists"
if docker image inspect "$image" >/dev/null 2>&1; then
  fail "test image already exists"
fi

cleanup() {
  result=$1
  trap - 0 INT TERM
  if [ -f "$work_dir/compose.yaml" ]; then
    if ! compose down --volumes >/dev/null 2>&1; then
      printf 'Cleanup could not remove isolated Compose project %s.\n' "$project" >&2
      result=1
    fi
  fi
  if docker image inspect "$image" >/dev/null 2>&1; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  if [ "$result" -eq 0 ]; then
    # This exact directory was allocated above; never remove the source checkout.
    case "$test_dir" in
      */team-relay-docker-test.??????) rm -rf "$test_dir" ;;
      *) printf 'Unexpected temporary path; preserving %s.\n' "$test_dir" >&2 ;;
    esac
  else
    printf 'Private test files preserved for diagnosis: %s\n' "$test_dir" >&2
    printf 'Do not upload its secrets or invitation output as CI artifacts.\n' >&2
  fi
  exit "$result"
}
trap 'cleanup "$?"' 0
trap 'exit 130' INT
trap 'exit 143' TERM

# Copy tracked working-tree contents, including local edits, but no untracked
# credentials, binaries, or .env. The installer always runs from this copy.
git -C "$repo_dir" ls-files -z > "$test_dir/tracked-files"
tar -C "$repo_dir" --null -T "$test_dir/tracked-files" -cf "$test_dir/source.tar"
tar -C "$work_dir" -xf "$test_dir/source.tar"
cd "$work_dir"

assert_private() {
  target=$1
  expected_mode=$2
  [ ! -L "$target" ] || fail "private material is a symlink"
  if stat -c '%a' "$target" >/dev/null 2>&1; then
    actual_mode=$(stat -c '%a' "$target")
    actual_owner=$(stat -c '%u' "$target")
  else
    actual_mode=$(stat -f '%Lp' "$target")
    actual_owner=$(stat -f '%u' "$target")
  fi
  [ "$actual_mode" = "$expected_mode" ] || fail "incorrect private file permissions"
  [ "$actual_owner" = "$(id -u)" ] || fail "incorrect private file owner"
}

assert_credentials() {
  assert_private .env 600
  assert_private secrets 700
  assert_private secrets/.bootstrap-profile 700
  for credential in bootstrap-token admin-token; do
    [ -s "secrets/$credential" ] || fail "missing $credential"
    assert_private "secrets/$credential" 600
  done
  for field in organization admin-name admin-email; do
    assert_private "secrets/.bootstrap-profile/$field" 600
  done
}

assert_host_ready() {
  expected_bind=$1
  address=$(compose port relay 8080)
  case "$address" in
    "$expected_bind":*) ;;
    *) fail "relay published address does not match requested $expected_bind binding" ;;
  esac
  container=$(compose ps -q relay)
  docker inspect "$container" > "$test_dir/published-container.json"
  jq -e --arg bind "$expected_bind" '
    .[0].NetworkSettings.Ports["8080/tcp"] |
    length == 1 and .[0].HostIp == $bind
  ' "$test_dir/published-container.json" >/dev/null || fail "unexpected actual host port binding"
  # Wildcard is a listening address, not a URL a teammate should connect to.
  local_address="127.0.0.1:${address##*:}"
  curl --disable --noproxy '*' --fail --silent --show-error --connect-timeout 3 \
    --max-time 5 "http://$local_address/health/ready" > "$test_dir/readiness.json"
  printf 'Published host readiness verified at %s with binding %s.\n' "$local_address" "$expected_bind"
}

assert_networks() {
  compose --profile tools config --format json > "$test_dir/compose.json"
  jq -e '
    (.services.state.networks | keys) == ["backend"] and
    (.services.admin.networks | keys) == ["backend"] and
    (.services.relay.networks | keys) == ["backend", "frontend"] and
    .networks.backend.internal == true and
    (.networks.frontend.internal // false) == false and
    (.services.state.ports // [] | length) == 0 and
    (.services.admin.ports // [] | length) == 0
  ' "$test_dir/compose.json" >/dev/null || fail "unexpected Compose network exposure"
  for network in backend frontend; do
    network_name=$(jq -r --arg network "$network" '.networks[$network].name' "$test_dir/compose.json")
    docker network inspect "$network_name" > "$test_dir/network.json"
    if [ "$network" = backend ]; then
      jq -e '.[0].Internal == true' "$test_dir/network.json" >/dev/null
    else
      jq -e '.[0].Internal == false and .[0].Driver == "bridge"' "$test_dir/network.json" >/dev/null
    fi
  done
  for service in relay state; do
    container=$(compose ps -q "$service")
    [ -n "$container" ] || fail "$service is not running"
    docker inspect "$container" > "$test_dir/container.json"
    jq -e --arg service "$service" --slurpfile config "$test_dir/compose.json" '
      (.[0].NetworkSettings.Networks | keys) ==
      ([$config[0].services[$service].networks | keys[] as $key |
        $config[0].networks[$key].name] | sort)
    ' "$test_dir/container.json" >/dev/null || fail "unexpected running container networks"
  done
}

admin() {
  compose run --rm --no-deps --volume "$work_dir/secrets:/run/test-secrets:ro" \
    admin "$@" --server http://relay:8080 --token-file /run/test-secrets/admin-token
}

printf 'Running fresh Docker installation in isolated project %s.\n' "$project"
./install-docker </dev/null
assert_host_ready 127.0.0.1
assert_credentials
assert_networks
cp secrets/bootstrap-token "$test_dir/bootstrap.before"
cp secrets/admin-token "$test_dir/admin.before"

# Create actual application state and check that it survives recreation. The
# create command emits an invitation token, so its output must remain private.
admin invite create --name 'Regression Teammate' --email 'teammate@example.invalid' \
  > "$test_dir/private-invitation-output" 2> "$test_dir/invitation-stderr"
admin invite list > "$test_dir/invites.before"
grep -F 'teammate@example.invalid' "$test_dir/invites.before" >/dev/null || fail "test invitation was not persisted"

assert_rerun_state() {
  assert_host_ready "$1"
  assert_credentials
  assert_networks
  cmp -s secrets/bootstrap-token "$test_dir/bootstrap.before" || fail "bootstrap credential changed on rerun"
  cmp -s secrets/admin-token "$test_dir/admin.before" || fail "administrator credential changed on rerun"
  admin invite list > "$test_dir/invites.after"
  cmp -s "$test_dir/invites.before" "$test_dir/invites.after" || fail "application state changed or was lost on rerun"
}

printf 'Recreating containers and opting in to all-interface binding.\n'
compose down
./install-docker --bind 0.0.0.0 </dev/null
assert_rerun_state 0.0.0.0

printf 'Checking that a plain rerun preserves the selected binding.\n'
./install-docker </dev/null
assert_rerun_state 0.0.0.0

printf 'Returning the existing installation to loopback-only binding.\n'
./install-docker --bind 127.0.0.1 </dev/null
assert_rerun_state 127.0.0.1
printf 'Docker installation passed: host readiness, configurable bindings, private credentials, network boundaries, and persistent state after recreation.\n'
