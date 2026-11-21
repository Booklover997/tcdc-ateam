#!/bin/bash
# Rotate nigel and scoring OS user passwords on this Ubuntu box.
#   sudo bash change_passwords.sh
# Paste a different password twice for each account. Nothing is saved.

set -uo pipefail

NIGEL_USERS=(nigel1 nigel2 nigel3 nigel4 nigel5)
OS_USERS=(
  washington kennedy teddy lincoln ross streep franklin parks
  armstrong hamilton mlk tubman manziel deniro bush
  blueteam score1 score2 patch
)
PROTECTED=(blackteam whiteteam root nobody)
IMMUTABLE_FILES=(/etc/passwd /etc/shadow /etc/group /etc/gshadow)

STAMP=$(date +%Y%m%d-%H%M%S)
LOG="/var/log/hawk-passwd-${STAMP}.log"
COUNT_FILE="/var/log/hawk-passwd-${STAMP}.counts"
CHATTR_LIFTED=0

ok() { printf 'OK %s\n' "$*"; printf 'OK\n' >>"$COUNT_FILE"; }
warn() { printf 'WARN %s\n' "$*"; printf 'WARN\n' >>"$COUNT_FILE"; }
fail() { printf 'FAIL %s\n' "$*"; printf 'FAIL\n' >>"$COUNT_FILE"; }
skip() { printf 'SKIP %s\n' "$*"; printf 'SKIP\n' >>"$COUNT_FILE"; }

count_of() {
  local tag="$1"
  [[ -f "$COUNT_FILE" ]] || { printf '0\n'; return; }
  awk -v t="$tag" '$0 == t { n++ } END { print n + 0 }' "$COUNT_FILE"
}

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

tty_say() {
  printf '%s\n' "$*" >/dev/tty
}

restore_immutable() {
  local f
  [[ "$CHATTR_LIFTED" -eq 1 ]] || return 0
  command -v chattr >/dev/null 2>&1 || return 0
  for f in "${IMMUTABLE_FILES[@]}"; do
    [[ -e "$f" ]] || continue
    chattr +i "$f" >/dev/null 2>&1 || true
  done
  CHATTR_LIFTED=0
}

lift_immutable() {
  local f
  if ! command -v chattr >/dev/null 2>&1; then
    fail "chattr is missing; trying chpasswd anyway"
    return
  fi
  for f in "${IMMUTABLE_FILES[@]}"; do
    if [[ ! -e "$f" ]]; then
      skip "chattr -i $f (absent)"
      continue
    fi
    if chattr -i "$f"; then
      ok "chattr -i $f"
      CHATTR_LIFTED=1
    else
      fail "chattr -i $f"
    fi
  done
}

read_password_pair() {
  local user="$1"
  pass1=""
  pass2=""
  tty_say ""
  tty_say "$user"
  printf 'Password: ' >/dev/tty
  IFS= read -r -s pass1 </dev/tty || true
  printf '\n' >/dev/tty
  printf 'Again: ' >/dev/tty
  IFS= read -r -s pass2 </dev/tty || true
  printf '\n' >/dev/tty
}

set_user_password() {
  local user="$1"
  if is_protected "$user"; then
    skip "$user is never changed"
    return
  fi
  if ! id "$user" >/dev/null 2>&1; then
    skip "$user is not on this box"
    return
  fi
  read_password_pair "$user"
  if [[ -z "${pass1:-}" ]]; then
    fail "$user empty password; not changed"
    unset pass1 pass2
    return
  fi
  if [[ "$pass1" != "$pass2" ]]; then
    fail "$user pastes did not match; not changed"
    unset pass1 pass2
    return
  fi
  if printf '%s:%s\n' "$user" "$pass1" | chpasswd; then
    ok "$user"
  else
    fail "$user chpasswd failed"
  fi
  unset pass1 pass2
}

on_exit() {
  restore_immutable
  unset pass1 pass2
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    printf 'FAIL must be run as root. Use:\n  sudo bash change_passwords.sh\n'
    exit 1
  fi
  if [[ ! -r /dev/tty ]]; then
    printf 'FAIL this script needs a terminal so passwords are not logged. Run it from a shell, not a pipe.\n'
    exit 1
  fi

  mkdir -p /var/log
  touch "$LOG" "$COUNT_FILE"
  chmod 600 "$LOG" "$COUNT_FILE"
  exec > >(tee -a "$LOG") 2>&1

  trap on_exit EXIT INT TERM

  ok "log $LOG"
  case "${LANG:-}${LC_ALL:-}" in
    *UTF-8*|*utf8*) ok "locale is UTF-8" ;;
    *) warn "locale is not UTF-8; a Cyrillic paste may be mangled" ;;
  esac

  tty_say "This box will get a NEW password for each of these accounts."
  tty_say "Paste a different password twice for each name. Nothing is printed or saved."
  tty_say "blackteam, whiteteam, and root are never changed."
  tty_say "Then update https://dash.playtcdc.org/team/passwords for scoring OS users."

  lift_immutable

  local user
  for user in "${NIGEL_USERS[@]}" "${OS_USERS[@]}"; do
    set_user_password "$user"
  done

  restore_immutable
  ok "put the immutable bit back on passwd and shadow"

  printf '\n--- Summary ---\n'
  printf 'OK count %s\n' "$(count_of OK)"
  printf 'WARN count %s\n' "$(count_of WARN)"
  printf 'FAIL count %s\n' "$(count_of FAIL)"
  printf 'SKIP count %s\n' "$(count_of SKIP)"
  printf 'Update https://dash.playtcdc.org/team/passwords for every scoring OS user you changed, or uptime checks fail.\n'
}

main "$@"
