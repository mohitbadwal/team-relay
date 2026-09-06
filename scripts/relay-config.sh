#!/bin/sh
# Shared installer/operator configuration helpers. The .conf is data, not shell.

relay_config_fail() {
  printf 'team-relay: %s\n' "$*" >&2
  exit 1
}

relay_config_key_valid() {
  case "$1" in
    TEAM_RELAY_SERVER_MODE|TEAM_RELAY_BIND_ADDRESS|TEAM_RELAY_PORT|TEAM_RELAY_REDIS_URL|TEAM_RELAY_BOOTSTRAP_TOKEN_FILE|TEAM_RELAY_SERVER_EXECUTABLE|TEAM_RELAY_RECEIVER_EXECUTABLE|TEAM_RELAY_RECEIVER_CONFIG|TEAM_RELAY_RECEIVER_STATE_DIR|TEAM_RELAY_RECEIVER_CONTROL_ADDRESS) return 0 ;;
    *) return 1 ;;
  esac
}

relay_config_validate() {
  [ -f "$relay_conf_file" ] && [ ! -L "$relay_conf_file" ] || \
    relay_config_fail "$relay_conf_file must be a regular file, not a symlink"
  if stat -c '%a' "$relay_conf_file" >/dev/null 2>&1; then
    relay_conf_mode=$(stat -c '%a' "$relay_conf_file")
    relay_conf_owner=$(stat -c '%u' "$relay_conf_file")
  else
    relay_conf_mode=$(stat -f '%Lp' "$relay_conf_file")
    relay_conf_owner=$(stat -f '%u' "$relay_conf_file")
  fi
  [ "$relay_conf_owner" = "$(id -u)" ] && [ "$relay_conf_mode" = 600 ] || \
    relay_config_fail "config must be owned by the current user with private permissions (chmod 600): $relay_conf_file"
  relay_seen_keys=' '
  while IFS= read -r relay_line || [ -n "$relay_line" ]; do
    case "$relay_line" in
      ''|'#'*) continue ;;
      *=*) relay_key=${relay_line%%=*} ;;
      *) relay_config_fail "expected literal KEY=value in $relay_conf_file" ;;
    esac
    relay_config_key_valid "$relay_key" || relay_config_fail "unknown configuration key: $relay_key"
    case "$relay_seen_keys" in
      *" $relay_key "*) relay_config_fail "duplicate configuration key: $relay_key" ;;
    esac
    relay_seen_keys="$relay_seen_keys$relay_key "
  done < "$relay_conf_file"
}

relay_config_get() {
  relay_config_key_valid "$1" || relay_config_fail "unknown configuration key: $1"
  relay_setting=$(sed -n "s/^${1}=//p" "$relay_conf_file")
  printf '%s\n' "${relay_setting:-${2:-}}"
}

relay_config_set() {
  relay_config_key_valid "$1" || relay_config_fail "unknown configuration key: $1"
  case "$2" in
    *'
'*) relay_config_fail "configuration values must fit on one line" ;;
  esac
  relay_config_validate
  relay_conf_tmp=$(mktemp "$relay_conf_file.tmp.XXXXXX") || relay_config_fail "cannot stage config update"
  if ! sed "/^${1}=/d" "$relay_conf_file" > "$relay_conf_tmp" || \
     ! printf '\n%s=%s\n' "$1" "$2" >> "$relay_conf_tmp"; then
    rm -f "$relay_conf_tmp"
    relay_config_fail "cannot write configuration"
  fi
  chmod 0600 "$relay_conf_tmp"
  mv "$relay_conf_tmp" "$relay_conf_file"
}

relay_config_init() {
  case "$1" in
    docker|native) ;;
    *) relay_config_fail "server mode must be docker or native" ;;
  esac
  relay_conf_file=${relay_conf_file:-$script_dir/team-relay.conf}
  relay_config_created=0
  if [ -e "$relay_conf_file" ] || [ -L "$relay_conf_file" ]; then
    relay_config_validate
    return
  fi
  [ -f "$script_dir/team-relay.conf.example" ] || relay_config_fail "missing team-relay.conf.example"
  # noclobber avoids replacing a config created concurrently by another command.
  (umask 077; set -C; sed "s/^TEAM_RELAY_SERVER_MODE=.*/TEAM_RELAY_SERVER_MODE=$1/" \
    "$script_dir/team-relay.conf.example" > "$relay_conf_file") || relay_config_fail "cannot create $relay_conf_file"
  # Used by install-native to set newly installed executable paths only once.
  # shellcheck disable=SC2034
  relay_config_created=1
  # Carry forward the previously installed bind/port without reading any token.
  if [ -f "$script_dir/.env" ] && [ ! -L "$script_dir/.env" ]; then
    for relay_migrate_key in TEAM_RELAY_BIND_ADDRESS TEAM_RELAY_PORT; do
      relay_migrate_value=$(sed -n "s/^$relay_migrate_key=//p" "$script_dir/.env" | tail -n 1)
      if [ -n "$relay_migrate_value" ]; then
        relay_config_set "$relay_migrate_key" "$relay_migrate_value"
      fi
    done
  fi
  relay_config_validate
}

relay_config_docker_values() {
  TEAM_RELAY_BIND_ADDRESS=$(relay_config_get TEAM_RELAY_BIND_ADDRESS 127.0.0.1)
  TEAM_RELAY_PORT=$(relay_config_get TEAM_RELAY_PORT 8080)
  case "$TEAM_RELAY_BIND_ADDRESS" in
    127.0.0.1|0.0.0.0) ;;
    *) relay_config_fail "TEAM_RELAY_BIND_ADDRESS must be 127.0.0.1 or 0.0.0.0" ;;
  esac
  case "$TEAM_RELAY_PORT" in
    ''|*[!0-9]*) relay_config_fail "TEAM_RELAY_PORT must be a number from 0 to 65535" ;;
  esac
  if [ "${#TEAM_RELAY_PORT}" -gt 5 ] || [ "$TEAM_RELAY_PORT" -gt 65535 ]; then
    relay_config_fail "TEAM_RELAY_PORT must be a number from 0 to 65535"
  fi
  export TEAM_RELAY_BIND_ADDRESS TEAM_RELAY_PORT
}

relay_assert_docker_project_dir() {
  relay_expected_dir=$(CDPATH='' cd "$1" && pwd -P)
  # The canonical rendered name includes .env/COMPOSE_PROJECT_NAME overrides.
  # Filter before displaying anything: Compose config can contain private data.
  relay_project_name=$(relay_compose config --format yaml | sed -n 's/^name: //p') || \
    relay_config_fail "could not resolve the Docker project"
  case "$relay_project_name" in
    \"*\") relay_project_name=${relay_project_name#\"}; relay_project_name=${relay_project_name%\"} ;;
    \'*\') relay_project_name=${relay_project_name#\'}; relay_project_name=${relay_project_name%\'} ;;
  esac
  case "$relay_project_name" in
    ''|*[!a-z0-9_-]*) relay_config_fail "could not resolve a valid Docker project name" ;;
  esac
  relay_containers=$(docker ps -aq --filter "label=com.docker.compose.project=$relay_project_name") || \
    relay_config_fail "could not inspect the Docker project"
  for relay_container in $relay_containers; do
    relay_owner_dir=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$relay_container") || \
      relay_config_fail "could not verify Docker project ownership"
    if [ -d "$relay_owner_dir" ]; then
      relay_owner_dir=$(CDPATH='' cd "$relay_owner_dir" && pwd -P)
    fi
    [ "$relay_owner_dir" = "$relay_expected_dir" ] || \
      relay_config_fail "Docker project $relay_project_name belongs to a different checkout; use its original checkout or choose a distinct COMPOSE_PROJECT_NAME in .env"
  done
}
