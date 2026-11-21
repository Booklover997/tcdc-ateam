#!/bin/bash
# Rotate nigel and scoring OS user passwords on this Ubuntu box.
#   sudo bash change_passwords.sh
# Paste one password per account. Nothing is saved.
# Extra names (blueteam score1 score2 patch) rotate only when
# /etc/hawk-rotate-extras exists on this host.

set -uo pipefail

NIGEL_USERS=(nigel1 nigel2 nigel3 nigel4 nigel5)
OS_USERS=(
  washington kennedy teddy lincoln ross streep franklin parks
  armstrong hamilton mlk tubman manziel deniro bush
)
EXTRA_USERS=(blueteam score1 score2 patch)
PROTECTED=(blackteam whiteteam root nobody)
EXTRAS_FLAG=/etc/hawk-rotate-extras

STAMP=$(date +%Y%m%d-%H%M%S)
LOG="/var/log/hawk-passwd-${STAMP}.log"
HOST=$(hostname)

CHANGED=()
FAILED=()
SKIPPED=()

in_list() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

is_protected() { in_list "$1" "${PROTECTED[@]}"; }

pair() {
  printf '%s / %s' "$HOST" "$1"
}

tty_say() {
  printf '%s\n' "$*" >/dev/tty
}

log_line() {
  printf '%s\n' "$*"
}

mark_changed() {
  CHANGED+=("$1")
  log_line "CHANGED $1"
}

mark_failed() {
  FAILED+=("$1")
  log_line "FAILED $(pair "$1") — Linux lead: chpasswd did not take on this host"
}

mark_skipped() {
  SKIPPED+=("$1")
  log_line "SKIPPED $1"
}

remove_from_failed() {
  local user="$1" i
  local kept=()
  for i in "${FAILED[@]+"${FAILED[@]}"}"; do
    [[ "$i" == "$user" ]] && continue
    kept+=("$i")
  done
  FAILED=("${kept[@]+"${kept[@]}"}")
}

ask_retry() {
  local user="$1" ans
  printf 'Retry %s? [y/N] ' "$(pair "$user")" >/dev/tty
  IFS= read -r ans </dev/tty
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

try_set_password() {
  local user="$1"
  local pass=""
  tty_say ""
  tty_say "$(pair "$user") — paste password, then press Enter"
  IFS= read -r -s pass </dev/tty
  printf '\n' >/dev/tty
  if [[ -z "${pass:-}" ]]; then
    unset pass
    return 1
  fi
  if printf '%s:%s\n' "$user" "$pass" | chpasswd; then
    unset pass
    return 0
  fi
  unset pass
  return 1
}

set_user_password() {
  local user="$1"
  if is_protected "$user"; then
    mark_skipped "$user"
    return
  fi
  if ! id "$user" >/dev/null 2>&1; then
    mark_skipped "$user"
    return
  fi
  while true; do
    if try_set_password "$user"; then
      remove_from_failed "$user"
      mark_changed "$user"
      return
    fi
    mark_failed "$user"
    if ! ask_retry "$user"; then
      return
    fi
    remove_from_failed "$user"
  done
}

print_names() {
  local title="$1"
  shift
  printf '%s\n' "$title"
  if [[ "$#" -eq 0 ]]; then
    printf '  (none)\n'
    return
  fi
  local n
  for n in "$@"; do
    printf '  %s\n' "$n"
  done
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    printf 'FAILED must be run as root. Use:\n  sudo bash change_passwords.sh\n'
    exit 1
  fi
  if [[ ! -r /dev/tty ]]; then
    printf 'FAILED this script needs a terminal so passwords are not logged. Run it from a shell, not a pipe.\n'
    exit 1
  fi

  mkdir -p /var/log
  touch "$LOG"
  chmod 600 "$LOG"
  exec > >(tee -a "$LOG") 2>&1

  local targets=("${NIGEL_USERS[@]}" "${OS_USERS[@]}")
  if [[ -e "$EXTRAS_FLAG" ]]; then
    targets+=("${EXTRA_USERS[@]}")
    log_line "extras enabled on $HOST ($EXTRAS_FLAG)"
  else
    log_line "extras not enabled on $HOST (create $EXTRAS_FLAG to rotate blueteam score1 score2 patch)"
  fi

  tty_say "Host: $HOST"
  tty_say "Paste a different password for each account. One paste, then Enter. Nothing is saved."
  tty_say "blackteam and whiteteam are never changed."
  tty_say "Ctrl+C stops immediately."
  tty_say "Then update https://dash.playtcdc.org/team/passwords for scoring OS users."

  local user
  for user in "${targets[@]}"; do
    set_user_password "$user"
  done

  printf '\n--- Summary ---\n'
  print_names "CHANGED" "${CHANGED[@]+"${CHANGED[@]}"}"
  print_names "FAILED" "${FAILED[@]+"${FAILED[@]}"}"
  print_names "SKIPPED" "${SKIPPED[@]+"${SKIPPED[@]}"}"
  printf 'Update https://dash.playtcdc.org/team/passwords for every scoring OS user you changed, or uptime checks fail.\n'

  if [[ "${#FAILED[@]}" -gt 0 ]]; then
    printf 'Unresolved on this host:\n'
    for user in "${FAILED[@]}"; do
      printf '  %s\n' "$(pair "$user")"
    done
    exit 1
  fi
}

main "$@"
