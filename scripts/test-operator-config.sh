#!/bin/sh

# No Docker daemon or service manager is used here. Every file and mock command
# lives in an isolated fixture; the real Docker runtime has its own test suite.
set -eu
umask 077

repo_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/team-relay-operator-test.XXXXXX")
test_dir=$(CDPATH='' cd "$test_dir" && pwd)
fixture="$test_dir/checkout with spaces"
conf_file="$fixture/team-relay.conf"
checks=0

cleanup() {
  result=$?
  trap - 0 INT TERM
  case "$test_dir" in
    */team-relay-operator-test.??????) rm -rf "$test_dir" ;;
    *) printf 'Unexpected temporary path; preserving %s.\n' "$test_dir" >&2; result=1 ;;
  esac
  exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'Operator config test: %s\n' "$*" >&2
  exit 1
}

pass() {
  checks=$((checks + 1))
}

assert_equal() {
  [ "$1" = "$2" ] || fail "$3"
  pass
}

assert_contains() {
  grep -F -- "$2" "$1" >/dev/null || fail "$3"
  pass
}

expect_failure() {
  expected=$1
  shift
  if "$@" > "$test_dir/result" 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
  assert_contains "$test_dir/result" "$expected" "failure did not explain: $expected"
}

run_helper() (
  script_dir=$fixture
  relay_conf_file=$conf_file
  # shellcheck source=scripts/relay-config.sh
  . "$repo_dir/scripts/relay-config.sh"
  "$@"
)

private_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

mkdir -p "$fixture/scripts" "$test_dir/mock-bin"
cp "$repo_dir/team-relay.conf.example" "$fixture/team-relay.conf.example"
cp "$repo_dir/scripts/relay-config.sh" "$fixture/scripts/relay-config.sh"
cp "$repo_dir/team-relay" "$fixture/team-relay"
printf '# Fixture only; mock Docker never reads this file.\n' > "$fixture/compose.yaml"

# New defaults are private, with the requested installation mode. Reinstalling
# never replaces a user's chosen mode, edited settings, or comments.
run_helper relay_config_init docker
assert_equal "$(run_helper relay_config_get TEAM_RELAY_SERVER_MODE)" docker 'wrong initial server mode'
assert_equal "$(run_helper relay_config_get TEAM_RELAY_BIND_ADDRESS)" 127.0.0.1 'new installs must default to loopback'
assert_equal "$(private_mode "$conf_file")" 600 'new config is not private'
assert_equal "$(private_mode "$test_dir")" 700 'fixture directory is not private'
run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS 0.0.0.0
printf '\n# Keep this operator note.\n' >> "$conf_file"
cp "$conf_file" "$test_dir/config.before"
run_helper relay_config_init native
cmp "$conf_file" "$test_dir/config.before" || fail 'reinitialization changed an existing config'
pass
run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS 127.0.0.1
assert_equal "$(grep -c '^TEAM_RELAY_BIND_ADDRESS=' "$conf_file")" 1 'setting update duplicated a key'
assert_contains "$conf_file" '# Keep this operator note.' 'setting update removed comments'
assert_equal "$(private_mode "$conf_file")" 600 'updated config is not private'

# Only chmod our own fixture; never chown files or borrow another user's data.
# Both reading a setting for dispatch and reinstalling must reject weak modes.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) : ;; # Native Windows ownership uses DACLs, not Unix modes.
  *)
    for weak_mode in 644 666; do
      chmod "$weak_mode" "$conf_file"
      expect_failure 'private' run_helper relay_config_validate
      expect_failure 'private' run_helper relay_config_init docker
      expect_failure 'private' sh "$fixture/team-relay" config
      chmod 600 "$conf_file"
    done
    run_helper relay_config_validate
    pass
    ;;
esac

# Legacy .env migration copies only bind and port, without executing values,
# copying credentials, or changing the original Docker overrides file.
mv "$conf_file" "$test_dir/first-config"
printf '%s\n' 'TEAM_RELAY_BIND_ADDRESS=127.0.0.1' 'TEAM_RELAY_BIND_ADDRESS=0.0.0.0' \
  'TEAM_RELAY_PORT=9001' 'TEAM_RELAY_UID=1234' 'DO_NOT_COPY=this-is-not-a-token' \
  "UNTRUSTED=\$(touch $test_dir/env-executed)" > "$fixture/.env"
cp "$fixture/.env" "$test_dir/env.before"
run_helper relay_config_init native
assert_equal "$(run_helper relay_config_get TEAM_RELAY_SERVER_MODE)" native 'native initialization mode was ignored'
assert_equal "$(run_helper relay_config_get TEAM_RELAY_BIND_ADDRESS)" 0.0.0.0 'last legacy bind was not migrated'
assert_equal "$(run_helper relay_config_get TEAM_RELAY_PORT)" 9001 'legacy port was not migrated'
cmp "$fixture/.env" "$test_dir/env.before" || fail 'migration changed the legacy .env'
pass
if grep -E 'DO_NOT_COPY|UNTRUSTED|TEAM_RELAY_UID' "$conf_file" >/dev/null; then
  fail 'migration copied unrelated or credential-bearing settings'
fi
pass
[ ! -e "$test_dir/env-executed" ] || fail 'migration executed .env data'
pass
mv "$fixture/.env" "$test_dir/legacy.env"
cp "$conf_file" "$test_dir/valid-config"

# Literal values may contain spaces, dollars, quotes, backticks, or semicolons.
# Neither reading nor writing them is allowed to evaluate shell syntax.
literal_value="\$(touch $test_dir/dollar-executed); \`touch $test_dir/backtick-executed\` \$HOME 'quoted'"
run_helper relay_config_set TEAM_RELAY_RECEIVER_CONFIG "$literal_value"
run_helper relay_config_validate
assert_equal "$(run_helper relay_config_get TEAM_RELAY_RECEIVER_CONFIG)" "$literal_value" 'literal value was expanded or changed'
for marker in dollar-executed backtick-executed; do
  [ ! -e "$test_dir/$marker" ] || fail 'config evaluation executed shell content'
  pass
done
run_helper relay_config_set TEAM_RELAY_RECEIVER_STATE_DIR ''
assert_equal "$(run_helper relay_config_get TEAM_RELAY_RECEIVER_STATE_DIR fallback)" fallback 'empty setting did not use fallback'
expect_failure 'one line' run_helper relay_config_set TEAM_RELAY_RECEIVER_CONFIG 'first
second'
expect_failure 'unknown configuration key' run_helper relay_config_set UNRECOGNIZED value
cp "$test_dir/valid-config" "$conf_file"

printf '\nTEAM_RELAY_PORT=9002\n' >> "$conf_file"
expect_failure 'duplicate configuration key' run_helper relay_config_validate
cp "$test_dir/valid-config" "$conf_file"
printf '\nUNRECOGNIZED=value\n' >> "$conf_file"
expect_failure 'unknown configuration key' run_helper relay_config_validate
cp "$test_dir/valid-config" "$conf_file"
printf '\nnot-an-assignment\n' >> "$conf_file"
expect_failure 'literal KEY=value' run_helper relay_config_validate
cp "$test_dir/valid-config" "$conf_file"

# Missing final newlines are valid, while symlinks and directories cannot be
# used to replace another file through either init or a config update.
printf 'TEAM_RELAY_SERVER_MODE=docker' > "$conf_file"
run_helper relay_config_validate
pass
mv "$conf_file" "$test_dir/link-target"
ln -s "$test_dir/link-target" "$conf_file"
expect_failure 'not a symlink' run_helper relay_config_init docker
expect_failure 'not a symlink' run_helper relay_config_set TEAM_RELAY_PORT 8080
assert_equal "$(wc -c < "$test_dir/link-target" | tr -d ' ')" 29 'symlink target was changed'
rm "$conf_file"
mkdir "$conf_file"
expect_failure 'regular file' run_helper relay_config_validate
rmdir "$conf_file"
cp "$test_dir/valid-config" "$conf_file"

for bind in 127.0.0.1 0.0.0.0; do
  run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS "$bind"
  run_helper relay_config_docker_values
  pass
done
# shellcheck disable=SC2016 # Deliberately pass literal shell syntax as data.
for bind in localhost 192.0.2.1 :: '$(touch never)'; do
  run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS "$bind"
  expect_failure 'must be 127.0.0.1 or 0.0.0.0' run_helper relay_config_docker_values
done
run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS 127.0.0.1
for port in 0 1 8080 65535; do
  run_helper relay_config_set TEAM_RELAY_PORT "$port"
  run_helper relay_config_docker_values
  pass
done
# shellcheck disable=SC2016 # Deliberately pass literal shell syntax as data.
for port in -1 65536 100000 80abc 0.5 '$(touch never)'; do
  run_helper relay_config_set TEAM_RELAY_PORT "$port"
  expect_failure 'number from 0 to 65535' run_helper relay_config_docker_values
done
cp "$test_dir/valid-config" "$conf_file"
run_helper relay_config_set TEAM_RELAY_SERVER_MODE docker
run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS 0.0.0.0
run_helper relay_config_set TEAM_RELAY_PORT 9001

# Executable mocks record exact argument boundaries. They never open a socket,
# launch a container, or invoke a native service manager.
# shellcheck disable=SC2016 # Expand mock variables when the mock runs, not here.
printf '%s\n' '#!/bin/sh
set -eu
{
  printf "call:"
  printf " <%s>" "$@"
  printf "\nbind=%s port=%s\n" "${TEAM_RELAY_BIND_ADDRESS:-}" "${TEAM_RELAY_PORT:-}"
} >> "$MOCK_DOCKER_LOG"
case "$*" in
  "") exit 96 ;;
esac
verb=$1
shift
case "$verb" in
  compose)
    [ "$#" -ge 4 ] || exit 96
    [ "$1" = --project-directory ] && [ "$2" = "$MOCK_CHECKOUT_DIR" ] || exit 96
    [ "$3" = -f ] && [ "$4" = "$MOCK_CHECKOUT_DIR/compose.yaml" ] || exit 96
    shift 4
    case "$*" in
      "config --format yaml") printf "name: %s\n" "$MOCK_PROJECT_NAME" ;;
      "port relay 8080") printf "%s\n" "$MOCK_PUBLISHED_ADDRESS" ;;
      "up -d state relay"|"up -d state"|"up -d --no-deps --force-recreate relay"|"stop relay state"|"ps --all"|"logs --tail 100 relay"|"logs --tail 100 --follow relay") : ;;
      *) printf "Unrecognized mocked Compose command: %s\n" "$*" >&2; exit 96 ;;
    esac
    ;;
  ps)
    [ "$#" -eq 3 ] || exit 96
    [ "$1" = -aq ] && [ "$2" = --filter ] || exit 96
    [ "$3" = "label=com.docker.compose.project=$MOCK_PROJECT_NAME" ] || exit 96
    if [ -n "$MOCK_CONTAINER_IDS" ]; then printf "%s\n" "$MOCK_CONTAINER_IDS"; fi
    ;;
  inspect)
    [ "$#" -eq 3 ] || exit 96
    [ "$1" = --format ] || exit 96
    [ "$2" = "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}" ] || exit 96
    [ "$3" = fixture-container ] || exit 96
    [ "$MOCK_INSPECT_FAIL" = 0 ] || exit 1
    printf "%s\n" "$MOCK_WORKING_DIR"
    ;;
  *) printf "Unrecognized mocked Docker command: %s\n" "$verb" >&2; exit 96 ;;
esac' > "$test_dir/mock-bin/docker"
# shellcheck disable=SC2016 # Expand mock variables when the mock runs, not here.
printf '%s\n' '#!/bin/sh
set -eu
printf " <%s>" "$@" >> "$MOCK_CURL_LOG"
printf "\n" >> "$MOCK_CURL_LOG"' > "$test_dir/mock-bin/curl"
chmod +x "$test_dir/mock-bin/docker" "$test_dir/mock-bin/curl"
MOCK_DOCKER_LOG="$test_dir/docker.log"
MOCK_CURL_LOG="$test_dir/curl.log"
MOCK_PUBLISHED_ADDRESS=0.0.0.0:9001
MOCK_CHECKOUT_DIR=$fixture
MOCK_PROJECT_NAME='operator-fixture'
MOCK_CONTAINER_IDS=''
MOCK_WORKING_DIR=$fixture
MOCK_INSPECT_FAIL=0
PATH="$test_dir/mock-bin:$PATH"
export MOCK_DOCKER_LOG MOCK_CURL_LOG MOCK_PUBLISHED_ADDRESS PATH
export MOCK_CHECKOUT_DIR MOCK_PROJECT_NAME MOCK_CONTAINER_IDS MOCK_WORKING_DIR MOCK_INSPECT_FAIL
: > "$MOCK_DOCKER_LOG"
: > "$MOCK_CURL_LOG"
operator="$fixture/team-relay"

sh "$operator" server start > "$test_dir/start-output"
assert_contains "$MOCK_DOCKER_LOG" '<up> <-d> <state> <relay>' 'start did not start server and state'
assert_contains "$MOCK_DOCKER_LOG" "<--project-directory> <$fixture> <-f> <$fixture/compose.yaml>" 'checkout path with spaces was split'
assert_contains "$MOCK_DOCKER_LOG" 'bind=0.0.0.0 port=9001' 'config bind and port were not exported to Compose'
assert_contains "$MOCK_CURL_LOG" '<http://127.0.0.1:9001/health/ready>' 'wildcard bind was used as readiness URL'
assert_contains "$MOCK_CURL_LOG" '<--disable> <--noproxy> <*>' 'host readiness did not bypass curl config and proxies'
assert_contains "$test_dir/start-output" 'listening on 0.0.0.0:9001' 'start did not show the configured listener'
assert_contains "$MOCK_DOCKER_LOG" '<config> <--format> <yaml>' 'start did not resolve the Compose project identity'
assert_contains "$MOCK_DOCKER_LOG" '<ps> <-aq> <--filter> <label=com.docker.compose.project=operator-fixture>' 'start did not check existing project ownership'

: > "$MOCK_DOCKER_LOG"
sh "$operator" server restart > "$test_dir/restart-output"
assert_contains "$MOCK_DOCKER_LOG" '<up> <-d> <state>' 'restart did not ensure state is running'
assert_contains "$MOCK_DOCKER_LOG" '<up> <-d> <--no-deps> <--force-recreate> <relay>' 'restart did not apply edited Compose settings'
: > "$MOCK_DOCKER_LOG"
sh "$operator" server stop
assert_contains "$MOCK_DOCKER_LOG" '<stop> <relay> <state>' 'stop did not preserve containers and volumes'
if grep -E '<down>|<--volumes>|<rm>' "$MOCK_DOCKER_LOG" >/dev/null; then
  fail 'stop attempted to delete Docker resources'
fi
pass
sh "$operator" server status
assert_contains "$MOCK_DOCKER_LOG" '<ps> <--all>' 'status did not include stopped containers'
sh "$operator" server logs
assert_contains "$MOCK_DOCKER_LOG" '<logs> <--tail> <100> <relay>' 'logs did not bound output'
sh "$operator" server logs --follow
assert_contains "$MOCK_DOCKER_LOG" '<logs> <--tail> <100> <--follow> <relay>' 'follow logs were not forwarded'

# A mistaken edit must not strand the previously running server. Diagnostic and
# stop actions use harmless values for Compose rendering, without saving them.
run_helper relay_config_set TEAM_RELAY_PORT invalid-port
run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS invalid-bind
cp "$conf_file" "$test_dir/invalid-config.before"
for recovery_action in stop status logs; do
  : > "$MOCK_DOCKER_LOG"
  sh "$operator" server "$recovery_action"
  assert_contains "$MOCK_DOCKER_LOG" 'bind=127.0.0.1 port=8080' 'recovery action did not use safe rendering values'
  cmp "$conf_file" "$test_dir/invalid-config.before" || fail 'recovery action changed the edited config'
  pass
done
run_helper relay_config_set TEAM_RELAY_PORT 9001
run_helper relay_config_set TEAM_RELAY_BIND_ADDRESS 0.0.0.0

# Existing containers with this project name must belong to this installation.
# Block every mutation before it can stop/recreate another checkout's stack.
MOCK_CONTAINER_IDS='fixture-container'
MOCK_WORKING_DIR="$test_dir/another-checkout"
export MOCK_CONTAINER_IDS MOCK_WORKING_DIR
for mutation_action in start restart stop; do
  : > "$MOCK_DOCKER_LOG"
  expect_failure 'different' sh "$operator" server "$mutation_action"
  if grep -E '<up>|<stop>|<restart>|<down>|<rm>' "$MOCK_DOCKER_LOG" >/dev/null; then
    fail 'foreign project check allowed a Docker mutation'
  fi
  pass
done
MOCK_WORKING_DIR=$fixture
export MOCK_WORKING_DIR
MOCK_INSPECT_FAIL=1
export MOCK_INSPECT_FAIL
: > "$MOCK_DOCKER_LOG"
expect_failure 'verify Docker project ownership' sh "$operator" server stop
if grep -F '<stop>' "$MOCK_DOCKER_LOG" >/dev/null; then
  fail 'failed ownership inspection allowed a Docker mutation'
fi
pass
MOCK_INSPECT_FAIL=0
export MOCK_INSPECT_FAIL
: > "$MOCK_DOCKER_LOG"
sh "$operator" server stop
assert_contains "$MOCK_DOCKER_LOG" '<inspect> <--format>' 'matching project was not inspected'
assert_contains "$MOCK_DOCKER_LOG" '<stop> <relay> <state>' 'matching project incorrectly prevented stop'
MOCK_CONTAINER_IDS=''
export MOCK_CONTAINER_IDS

# Invalid usage must fail before Docker is invoked. Config inspection is also
# a read-only operation and must not start or reload anything.
: > "$MOCK_DOCKER_LOG"
expect_failure 'unknown option' sh "$operator" server status --unexpected
expect_failure 'requires a path' sh "$operator" server status --config
expect_failure 'only supported for logs' sh "$operator" server start --follow
expect_failure 'choose start' sh "$operator" server destroy
expect_failure 'top-level command' sh "$operator" server config
expect_failure 'choose start' sh "$operator" server
sh "$operator" config > "$test_dir/config-output"
assert_contains "$test_dir/config-output" "$conf_file" 'config command did not locate the editable file'
[ ! -s "$MOCK_DOCKER_LOG" ] || fail 'invalid usage or config inspection invoked Docker'
pass

for address in 'invalid IP:0' 127.0.0.1:9001 0.0.0.0:0 0.0.0.0:65536 0.0.0.0:nope; do
  MOCK_PUBLISHED_ADDRESS=$address
  export MOCK_PUBLISHED_ADDRESS
  expect_failure 'Docker' sh "$operator" server start
done

# Native receiver and server dispatch preserve both config paths and flags.
mkdir "$fixture/bin with spaces"
# shellcheck disable=SC2016 # Expand mock variables when the mock runs, not here.
printf '%s\n' '#!/bin/sh
set -eu
printf " <%s>" "$@" >> "$MOCK_NATIVE_LOG"
printf "\n" >> "$MOCK_NATIVE_LOG"' > "$fixture/bin with spaces/team-relay"
chmod +x "$fixture/bin with spaces/team-relay"
MOCK_NATIVE_LOG="$test_dir/native.log"
export MOCK_NATIVE_LOG
: > "$MOCK_DOCKER_LOG"
run_helper relay_config_set TEAM_RELAY_RECEIVER_EXECUTABLE 'bin with spaces/team-relay-agent'
sh "$operator" receiver logs --follow
assert_contains "$MOCK_NATIVE_LOG" "<receiver> <logs> <--config> <$conf_file> <--follow>" 'receiver dispatch lost argument boundaries'
run_helper relay_config_set TEAM_RELAY_SERVER_MODE native
run_helper relay_config_set TEAM_RELAY_SERVER_EXECUTABLE 'bin with spaces/team-relay-server'
sh "$operator" server restart
assert_contains "$MOCK_NATIVE_LOG" "<server> <restart> <--config> <$conf_file>" 'native server dispatch was not forwarded'
[ ! -s "$MOCK_DOCKER_LOG" ] || fail 'native lifecycle invoked Docker'
pass

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) : ;;
  *)
    : > "$MOCK_NATIVE_LOG"
    chmod 644 "$conf_file"
    expect_failure 'private' sh "$operator" receiver status
    [ ! -s "$MOCK_NATIVE_LOG" ] || fail 'weakly protected config selected a native executable'
    pass
    chmod 600 "$conf_file"
    ;;
esac

# Exercise installer path reconciliation without invoking the real Go compiler,
# enrolling anyone, or starting a service. Mock builds create harmless scripts
# only inside the installer's private staging directory in this fixture.
cp "$repo_dir/install-native" "$fixture/install-native"
printf 'module github.com/mohitbadwal/team-relay\n' > "$fixture/go.mod"
install_prefix="$fixture/custom native bin"
MOCK_INSTALL_PREFIX=$install_prefix
MOCK_GO_LOG="$test_dir/go.log"
MOCK_INSTALLED_RUN_LOG="$test_dir/installed-run.log"
MOCK_SERVICE_LOG="$test_dir/service.log"
export MOCK_INSTALL_PREFIX MOCK_GO_LOG MOCK_INSTALLED_RUN_LOG MOCK_SERVICE_LOG
# shellcheck disable=SC2016 # Mock code and generated scripts expand at execution.
printf '%s\n' '#!/bin/sh
set -eu
printf " <%s>" "$@" >> "$MOCK_GO_LOG"
printf "\n" >> "$MOCK_GO_LOG"
case "$*" in
  "env GOVERSION") printf "go1.24.0\n"; exit 0 ;;
  "env GOOS") printf "linux\n"; exit 0 ;;
esac
[ "$#" -eq 5 ] && [ "$1" = build ] || exit 96
[ "$2" = -trimpath ] && [ "$3" = -o ] || exit 96
build_target=$4
case "$build_target" in
  "$MOCK_INSTALL_PREFIX"/.team-relay-install.??????/*) : ;;
  *) exit 96 ;;
esac
case "$5" in
  ./cmd/team-relay|./cmd/team-relay-agent|./cmd/team-relay-mcp|./cmd/team-relay-admin|./cmd/team-relay-server) : ;;
  *) exit 96 ;;
esac
[ "${build_target##*/}" = "${5##*/}" ] || exit 96
printf "%s\n" "#!/bin/sh" "printf command-ran >> \"\$MOCK_INSTALLED_RUN_LOG\"" "exit 97" > "$build_target"' > "$test_dir/mock-bin/go"
chmod +x "$test_dir/mock-bin/go"
# If an installer regression attempts service management, fail before any real
# service manager could be reached. These commands never delegate elsewhere.
for service_command in launchctl systemctl journalctl; do
  # shellcheck disable=SC2016 # Expand the log variable only when a mock runs.
  printf '%s\n' '#!/bin/sh
printf "unexpected-service-call\n" >> "$MOCK_SERVICE_LOG"
exit 96' > "$test_dir/mock-bin/$service_command"
  chmod +x "$test_dir/mock-bin/$service_command"
done
: > "$MOCK_GO_LOG"
: > "$MOCK_INSTALLED_RUN_LOG"
: > "$MOCK_SERVICE_LOG"
: > "$MOCK_DOCKER_LOG"

run_native_install() {
  sh "$fixture/install-native" --prefix "$install_prefix" </dev/null > "$test_dir/native-install-output"
  assert_contains "$test_dir/native-install-output" 'Non-interactive build complete; no enrollment was attempted.' 'installer attempted enrollment without a terminal'
  [ ! -s "$MOCK_INSTALLED_RUN_LOG" ] || fail 'installer ran a generated command or enrolled a receiver'
  [ ! -s "$MOCK_SERVICE_LOG" ] || fail 'installer attempted native service management'
  [ ! -s "$MOCK_DOCKER_LOG" ] || fail 'native installer attempted Docker management'
  pass
}

# Docker-first install creates .conf before any native binaries exist. The
# absent placeholder paths must be updated to the requested custom prefix.
cp "$fixture/team-relay.conf.example" "$conf_file"
chmod 600 "$conf_file"
run_native_install
assert_equal "$(run_helper relay_config_get TEAM_RELAY_SERVER_MODE)" docker 'native installation changed the existing Docker server mode'
assert_equal "$(run_helper relay_config_get TEAM_RELAY_SERVER_EXECUTABLE)" "$install_prefix/team-relay-server" 'Docker-first server placeholder did not follow custom prefix'
assert_equal "$(run_helper relay_config_get TEAM_RELAY_RECEIVER_EXECUTABLE)" "$install_prefix/team-relay-agent" 'Docker-first receiver placeholder did not follow custom prefix'
assert_equal "$(private_mode "$conf_file")" 600 'native installation weakened config permissions'
for native_command in team-relay team-relay-agent team-relay-mcp team-relay-admin team-relay-server; do
  [ -x "$install_prefix/$native_command" ] || fail "native mock build did not install $native_command"
  pass
done
assert_equal "$(grep -c '<build>' "$MOCK_GO_LOG")" 5 'native installer did not build exactly five commands'

# Configurations from older versions can omit the executable keys entirely.
# Their implicit defaults should be reconciled in exactly the same way.
sed '/^TEAM_RELAY_SERVER_EXECUTABLE=/d; /^TEAM_RELAY_RECEIVER_EXECUTABLE=/d' "$conf_file" > "$test_dir/without-executables.conf"
cp "$test_dir/without-executables.conf" "$conf_file"
run_native_install
assert_equal "$(run_helper relay_config_get TEAM_RELAY_SERVER_EXECUTABLE)" "$install_prefix/team-relay-server" 'omitted server executable did not follow custom prefix'
assert_equal "$(run_helper relay_config_get TEAM_RELAY_RECEIVER_EXECUTABLE)" "$install_prefix/team-relay-agent" 'omitted receiver executable did not follow custom prefix'

# A working installation at the default paths is a real operator choice, not
# an unused template. Installing elsewhere must not redirect or overwrite it.
mkdir "$fixture/bin"
printf '#!/bin/sh\nexit 0\n' > "$fixture/bin/team-relay-server"
printf '#!/bin/sh\nexit 0\n' > "$fixture/bin/team-relay-agent"
chmod +x "$fixture/bin/team-relay-server" "$fixture/bin/team-relay-agent"
cp "$fixture/bin/team-relay-server" "$test_dir/default-server.before"
cp "$fixture/bin/team-relay-agent" "$test_dir/default-receiver.before"
run_helper relay_config_set TEAM_RELAY_SERVER_EXECUTABLE bin/team-relay-server
run_helper relay_config_set TEAM_RELAY_RECEIVER_EXECUTABLE ./bin/team-relay-agent
cp "$conf_file" "$test_dir/working-defaults.before"
run_native_install
cmp "$conf_file" "$test_dir/working-defaults.before" || fail 'installer redirected a working default installation'
cmp "$fixture/bin/team-relay-server" "$test_dir/default-server.before" || fail 'installer replaced a working server outside its prefix'
cmp "$fixture/bin/team-relay-agent" "$test_dir/default-receiver.before" || fail 'installer replaced a working receiver outside its prefix'
pass

# Explicit manual paths remain authoritative even if currently unavailable.
run_helper relay_config_set TEAM_RELAY_SERVER_EXECUTABLE 'manual tools/server'
run_helper relay_config_set TEAM_RELAY_RECEIVER_EXECUTABLE "$fixture/operator-managed/agent"
cp "$conf_file" "$test_dir/manual-paths.before"
run_native_install
cmp "$conf_file" "$test_dir/manual-paths.before" || fail 'installer replaced manually selected executable paths'
pass

printf 'Operator configuration and command regression tests passed (%s checks).\n' "$checks"
