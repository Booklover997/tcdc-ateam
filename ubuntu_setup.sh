#!/bin/bash
# Local Ubuntu 26.04 setup for one box. Run as root:
#   sudo bash ubuntu_setup.sh
#   sudo bash ubuntu_setup.sh --accounts-only  (passwords and Nigel provisioning)
#   sudo bash ubuntu_setup.sh --ssh            (skip locking OS/system users)
# Calls apt only to install fail2ban when that package is missing.
# Does not store passwords. Test on a non-competition VM first.

set +x
set -uo pipefail

PACKET_USERS=(
  washington kennedy teddy lincoln ross streep franklin parks
  armstrong hamilton mlk tubman manziel deniro bush
)
EXTRA_USERS=(blueteam score1 score2 patch)
SCORING_USERS=("${PACKET_USERS[@]}" "${EXTRA_USERS[@]}")
NEVER_DISABLE=(blackteam whiteteam nigel1 nigel2 nigel3 nigel4 nigel5)
NIGEL_USERS=(nigel1 nigel2 nigel3 nigel4 nigel5)
KEEP_USERS=("${SCORING_USERS[@]}" "${NEVER_DISABLE[@]}")
LOCK_EXEMPT=(blackteam whiteteam nigel1 nigel2 nigel3 nigel4 nigel5)
SSH_MODE=0

NORMAL_PATHS="/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin"
RESPAWN_LINE="* * * * * pgrep -af '[s]shd -f /etc/ssh/sshd_config_2222' >/dev/null || /usr/sbin/sshd -f /etc/ssh/sshd_config_2222"

ACCOUNT_FILES=(/etc/passwd /etc/shadow /etc/group /etc/gshadow)
IMMUTABLE_FILES=(
  /etc/sudoers
  /etc/crontab
  /etc/cron.allow
  /etc/ssh/sshd_config
  /etc/ssh/sshd_config_2222
  /var/spool/cron/crontabs/root
)

SUID_MUST_CLEAR=(
  /usr/bin/find /bin/find
  /bin/bash /usr/bin/bash
  /bin/rbash /usr/bin/rbash
  /bin/sh /usr/bin/sh
  /bin/dash /usr/bin/dash
  /usr/bin/ssh /usr/bin/scp /usr/bin/ssh-keygen
  /usr/bin/vim /usr/bin/vim.basic /usr/bin/vi /usr/bin/nano
  /usr/bin/python /usr/bin/python3 /usr/bin/perl /usr/bin/ruby
  /usr/bin/awk /usr/bin/less /usr/bin/more
  /bin/cp /usr/bin/cp /bin/mv /usr/bin/mv
  /bin/tar /usr/bin/tar /usr/bin/wget /usr/bin/curl
  /usr/bin/env /usr/bin/tee /usr/bin/strace /usr/bin/gdb
  /usr/bin/rsync /bin/busybox /usr/bin/busybox /usr/bin/nmap
)

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="/var/log/hawk-ubuntu-setup-${STAMP}.log"
BACKUP="/root/hawk-backup-${STAMP}"
HAVE_CHATTR=0

COUNT_FILE="/var/log/hawk-ubuntu-setup-${STAMP}.counts"

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

is_keep_user() { in_list "$1" "${KEEP_USERS[@]}"; }
is_scoring_user() { in_list "$1" "${SCORING_USERS[@]}"; }
is_never_disable() { in_list "$1" "${NEVER_DISABLE[@]}" || is_scoring_user "$1"; }

hands_off_path() {
  local f="$1"
  case "$f" in
    *wazuh*|*ossec*|*auditd*|/etc/audit*|/etc/audisp*|*cloud-init*|*cloudinit*|*xe-guest*|*nftables*|*iptables*|/etc/ufw*|/etc/ufw/*)
      return 0
      ;;
  esac
  return 1
}

backup_file() {
  local f="$1" dest
  [[ -e "$f" || -L "$f" ]] || return 0
  dest="${BACKUP}${f}"
  mkdir -p "$(dirname -- "$dest")"
  cp -a "$f" "$dest"
}

restore_file() {
  local f="$1" src="${BACKUP}${f}"
  if [[ -e "$src" || -L "$src" ]]; then
    if cp -a "$src" "$f"; then
      ok "restored $f from backup"
      return 0
    fi
    fail "could not restore $f"
    return 1
  fi
  fail "no backup for $f"
  return 1
}

run_section() {
  local name="$1"
  shift
  local rc started
  started=$(date '+%H:%M:%S')
  printf '\n============================================================\n'
  printf 'START [%s] %s\n' "$started" "$name"
  printf '============================================================\n'
  set +e
  (
    set -uo pipefail
    "$@"
  )
  rc=$?
  set +e
  if [[ "$rc" -ne 0 ]]; then
    fail "section ${name} aborted with status ${rc}; the next section still runs"
    printf 'END   [%s] %s completed with errors\n' "$(date '+%H:%M:%S')" "$name"
  else
    printf 'END   [%s] %s completed\n' "$(date '+%H:%M:%S')" "$name"
  fi
}

show_plan() {
  printf '\nTCDC Ubuntu setup plan for %s\n' "$(hostname)"
  printf 'Mode: %s\n' "$1"
  printf 'Log: %s\n' "$LOG"
  printf 'Backup directory: %s\n' "$BACKUP"
  printf 'Passwords are entered at hidden terminal prompts and are not printed to this log.\n'
  printf 'The PAM step only reports suspicious entries. It does not edit PAM configuration.\n'
  printf 'Root will be disabled only after Nigel accounts have passwords and sudo access.\n'
  printf '\n'
}

path_is_normal() {
  local d="$1"
  local okp
  [[ -z "$d" || "$d" == '$PATH' || "$d" == '${PATH}' ]] && return 0
  for okp in $NORMAL_PATHS; do
    [[ "$d" == "$okp" ]] && return 0
  done
  return 1
}

bad_exec_path() {
  local line="$1"
  [[ "$line" == *'/tmp'* || "$line" == *'/dev/shm'* || "$line" == *'/var/tmp'* || "$line" == *'/home'* || "$line" == *'/root'* ]]
}

curl_pipe_shell() {
  local line="$1"
  [[ "$line" == *curl* || "$line" == *wget* ]] || return 1
  [[ "$line" == *'| sh'* || "$line" == *'| bash'* || "$line" == *'|sh'* || "$line" == *'|bash'* || "$line" == *'|/bin/sh'* || "$line" == *'|/bin/bash'* ]]
}

# --- 1. Identity and lift immutable bits ------------------------------------

section_identity() {
  printf 'Identify this host and create a protected backup directory.\n'
  printf 'Remove old immutable flags from account, sudo, SSH, and cron files so setup can manage them.\n'
  ok "hostname $(hostname)"
  ok "date $(date)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    ok "os ${PRETTY_NAME:-unknown}"
  else
    fail "missing /etc/os-release"
  fi
  mkdir -p "$BACKUP"
  chmod 700 "$BACKUP"
  ok "backup dir $BACKUP"

  if command -v chattr >/dev/null 2>&1; then
    HAVE_CHATTR=1
    local f
    for f in "${ACCOUNT_FILES[@]}" "${IMMUTABLE_FILES[@]}"; do
      if [[ ! -e "$f" ]]; then
        skip "chattr -i $f (absent)"
        continue
      fi
      if chattr -i "$f"; then
        ok "chattr -i $f"
      else
        fail "chattr -i $f"
      fi
    done
  else
    fail "chattr is missing; immutable bits stay as they are"
  fi

  local early
  for early in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/crontab /etc/ssh/sshd_config; do
    backup_file "$early"
  done
}

# --- 2. User bashrc ----------------------------------------------------------

hash_extra_dotfiles() {
  local home="$1" extra h
  for extra in .profile .bash_profile .bash_logout .bash_aliases .ssh/rc .ssh/authorized_keys; do
    [[ -f "$home/$extra" ]] || continue
    h=$(sha256sum -- "$home/$extra" | awk '{print $1}')
    ok "hash $home/$extra $h"
  done
}

section_bashrc() {
  local skel="/etc/skel/.bashrc" skel_hash name x uid gid gecos home shell target h
  if [[ ! -f "$skel" ]]; then
    fail "missing $skel; user bashrc files left in place"
    return
  fi
  skel_hash=$(sha256sum -- "$skel" | awk '{print $1}')
  ok "skel bashrc $skel_hash"

  if [[ -f /root/.bashrc ]]; then
    local rh
    rh=$(sha256sum -- /root/.bashrc | awk '{print $1}')
    if [[ "$rh" != "$skel_hash" ]]; then
      backup_file /root/.bashrc
      if cp -a "$skel" /root/.bashrc; then
        chown root:root /root/.bashrc
        ok "replaced /root/.bashrc was $rh now $skel_hash"
      else
        fail "could not replace /root/.bashrc"
        restore_file /root/.bashrc || true
      fi
    else
      ok "/root/.bashrc matches skel $rh"
    fi
  fi

  while IFS=: read -r name x uid gid gecos home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$name" == root ]] && continue
    [[ -d "$home" ]] || continue
    [[ -d "$home/.bashrc" ]] && continue
    if [[ "$name" == blackteam || "$name" == whiteteam ]]; then
      skip "bashrc $name"
      hash_extra_dotfiles "$home"
      continue
    fi
    target="$home/.bashrc"
    if [[ ! -f "$target" ]]; then
      if cp -a "$skel" "$target"; then
        chown -- "$name" "$target" 2>/dev/null || true
        ok "installed skel bashrc for $name $skel_hash"
      else
        fail "could not install bashrc for $name"
      fi
    else
      h=$(sha256sum -- "$target" | awk '{print $1}')
      if [[ "$h" != "$skel_hash" ]]; then
        backup_file "$target"
        if cp -a "$skel" "$target"; then
          chown -- "$name" "$target" 2>/dev/null || true
          ok "replaced $target was $h now $skel_hash"
        else
          fail "could not replace $target"
          restore_file "$target" || true
        fi
      else
        ok "$target matches skel $h"
      fi
    fi
    hash_extra_dotfiles "$home"
  done < /etc/passwd
}

# --- 3. System bash and PATH -------------------------------------------------

section_dpkg_and_path() {
  local pkg out line f n val dirs d bad
  for pkg in bash coreutils libpam-modules libpam-runtime; do
    if ! dpkg-query -W "$pkg" >/dev/null 2>&1; then
      fail "package $pkg is not installed"
      continue
    fi
    out=$(dpkg -V "$pkg" 2>&1 || true)
    if [[ -z "$out" ]]; then
      ok "dpkg -V $pkg clean"
    else
      while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        fail "dpkg -V $pkg $line"
      done <<< "$out"
    fi
  done

  if [[ -f "$SCRIPT_DIR/known-good.sha256" ]]; then
    if sha256sum -c "$SCRIPT_DIR/known-good.sha256"; then
      ok "known-good.sha256 matched"
    else
      fail "known-good.sha256 had mismatches"
    fi
  else
    warn "known-good.sha256 not next to the script"
  fi

  for f in /etc/bash.bashrc /etc/profile /etc/environment /root/.bashrc; do
    [[ -f "$f" ]] || continue
    n=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      n=$((n + 1))
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      if [[ "$line" == *LD_PRELOAD* || "$line" == *LD_LIBRARY_PATH* || "$line" == *PROMPT_COMMAND* || "$line" == *BASH_ENV* ]]; then
        fail "$f:$n shell hook left in place: $line"
      fi
      [[ "$line" == *PATH* && "$line" == *"="* ]] || continue
      val=${line#*=}
      val=${val%%#*}
      val=${val//\"/}
      val=${val//\'/}
      val=${val// /}
      bad=0
      IFS=':' read -r -a dirs <<< "$val"
      for d in "${dirs[@]}"; do
        path_is_normal "$d" || bad=1
      done
      if [[ "$bad" -eq 1 ]]; then
        fail "$f:$n PATH outside system dirs, left in place: $line"
      fi
    done < "$f"
  done

  local prof
  for prof in /etc/profile.d/*; do
    [[ -f "$prof" ]] || continue
    n=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      n=$((n + 1))
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      if [[ "$line" == *LD_PRELOAD* || "$line" == *LD_LIBRARY_PATH* || "$line" == *PROMPT_COMMAND* || "$line" == *BASH_ENV* ]]; then
        fail "$prof:$n shell hook left in place: $line"
      fi
      [[ "$line" == *PATH* && "$line" == *"="* ]] || continue
      val=${line#*=}
      val=${val%%#*}
      val=${val//\"/}
      val=${val//\'/}
      val=${val// /}
      bad=0
      IFS=':' read -r -a dirs <<< "$val"
      for d in "${dirs[@]}"; do
        path_is_normal "$d" || bad=1
      done
      if [[ "$bad" -eq 1 ]]; then
        fail "$prof:$n PATH outside system dirs, left in place: $line"
      fi
    done < "$prof"
  done
}

# --- 4. Cron, keys, PAM, preload, systemd, sudoers --------------------------

save_user_crontab() {
  local user="$1" dest
  dest="${BACKUP}/crontabs/${user}"
  mkdir -p "$(dirname -- "$dest")"
  if crontab -l -u "$user" >"$dest" 2>/dev/null; then
    return 0
  fi
  rm -f "$dest"
  return 1
}

filter_root_crontab() {
  local line tmp kept=0
  tmp=$(mktemp)
  if ! crontab -l -u root >"${tmp}.in" 2>/dev/null; then
    rm -f "$tmp" "${tmp}.in"
    ok "root has no crontab"
    return
  fi
  backup_file "${tmp}.in"
  cp -a "${tmp}.in" "${BACKUP}/crontabs/root"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *'sshd -f /etc/ssh/sshd_config_2222'* || "$line" == *'[s]shd -f /etc/ssh/sshd_config_2222'* ]]; then
      printf '%s\n' "$line" >>"$tmp"
      kept=1
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
      printf '%s\n' "$line" >>"$tmp"
      continue
    fi
    if [[ "$line" == *wazuh* || "$line" == *ossec* || "$line" == *auditd* ]]; then
      printf '%s\n' "$line" >>"$tmp"
      continue
    fi
    if [[ "$line" == *'/tmp'* || "$line" == *'/dev/shm'* || "$line" == *'/var/tmp'* ]] || curl_pipe_shell "$line"; then
      fail "removed root cron line: $line"
      continue
    fi
    printf '%s\n' "$line" >>"$tmp"
    kept=1
  done <"${tmp}.in"
  if [[ "$kept" -eq 0 ]]; then
    crontab -r -u root 2>/dev/null || true
    ok "root crontab had only removed lines"
  elif crontab -u root "$tmp"; then
    ok "root crontab filtered"
  else
    fail "root crontab install failed; restoring the previous crontab"
    if [[ -s "${BACKUP}/crontabs/root" ]]; then
      crontab -u root "${BACKUP}/crontabs/root" || fail "could not restore root crontab"
    fi
  fi
  rm -f "$tmp" "${tmp}.in"
}

strip_bad_lines_in_file() {
  local f="$1" line tmp changed=0
  hands_off_path "$f" && { skip "cron file $f"; return; }
  [[ -f "$f" ]] || return 0
  tmp=$(mktemp)
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
      printf '%s\n' "$line" >>"$tmp"
      continue
    fi
    if [[ "$line" == *wazuh* || "$line" == *ossec* || "$line" == *auditd* ]]; then
      printf '%s\n' "$line" >>"$tmp"
      continue
    fi
    if bad_exec_path "$line" || curl_pipe_shell "$line"; then
      fail "removed line from $f: $line"
      changed=1
      continue
    fi
    printf '%s\n' "$line" >>"$tmp"
  done <"$f"
  if [[ "$changed" -eq 1 ]]; then
    backup_file "$f"
    cat "$tmp" >"$f"
    ok "rewrote $f"
  fi
  rm -f "$tmp"
}

purge_cron_dirs() {
  local dir f owner
  for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$dir" ]] || continue
    for f in "$dir"/* "$dir"/.*; do
      [[ -e "$f" ]] || continue
      [[ "$f" == */. || "$f" == */.. ]] && continue
      hands_off_path "$f" && { skip "cron file $f"; continue; }
      owner=$(dpkg -S "$f" 2>/dev/null || true)
      case "$owner" in
        *wazuh*|*ossec*|*auditd*)
          skip "package cron $f"
          continue
          ;;
      esac
      if [[ -n "$owner" ]]; then
        strip_bad_lines_in_file "$f"
        continue
      fi
      if grep -Eqs '/tmp|/dev/shm|/var/tmp|/home|/root|curl|wget' "$f"; then
        backup_file "$f"
        rm -f "$f"
        fail "removed unpacked cron file $f"
      fi
    done
  done
  strip_bad_lines_in_file /etc/crontab
}

filter_user_crontab() {
  local user="$1" line tmp kept=0
  tmp=$(mktemp)
  if ! crontab -l -u "$user" >"${tmp}.in" 2>/dev/null; then
    rm -f "$tmp" "${tmp}.in"
    return
  fi
  save_user_crontab "$user"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
      printf '%s\n' "$line" >>"$tmp"
      continue
    fi
    if [[ "$line" == *wazuh* || "$line" == *ossec* || "$line" == *auditd* ]]; then
      printf '%s\n' "$line" >>"$tmp"
      kept=1
      continue
    fi
    if bad_exec_path "$line" || curl_pipe_shell "$line"; then
      fail "removed cron line for $user: $line"
      continue
    fi
    printf '%s\n' "$line" >>"$tmp"
    kept=1
  done <"${tmp}.in"
  if [[ "$kept" -eq 0 ]]; then
    crontab -r -u "$user" 2>/dev/null || true
    ok "purged crontab for $user (all lines suspicious)"
  elif crontab -u "$user" "$tmp"; then
    ok "filtered crontab for $user"
  else
    fail "crontab install failed for $user"
  fi
  rm -f "$tmp" "${tmp}.in"
}

purge_user_crontabs() {
  local name x uid
  while IFS=: read -r name x uid x x x x; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$name" == root ]] && continue
    in_list "$name" "${LOCK_EXEMPT[@]}" && { skip "crontab $name"; continue; }
    if save_user_crontab "$name"; then
      if is_scoring_user "$name"; then
        filter_user_crontab "$name"
      else
        crontab -r -u "$name" 2>/dev/null || true
        ok "removed crontab for $name"
      fi
    fi
  done < /etc/passwd
  filter_root_crontab
  purge_cron_dirs
}

purge_ssh_dir() {
  local home="$1" name="$2" f
  [[ -d "$home/.ssh" ]] || return 0

  for f in "$home/.ssh/id_rsa_backup" "$home/.ssh/id_dsa_backup" "$home/.ssh/id_ecdsa_backup" "$home/.ssh/id_ed25519_backup"; do
    if [[ -f "$f" ]]; then
      backup_file "$f"
      rm -f "$f"
      ok "removed fake key $f"
    fi
  done

  if [[ "$name" == blackteam || "$name" == whiteteam ]]; then
    warn "keeping $home/.ssh/authorized_keys (${name})"
    return 0
  fi

  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    if [[ -f "$f" ]]; then
      backup_file "$f"
      rm -f "$f"
      ok "removed $f"
    fi
  done
}

report_or_purge_keys() {
  local name home f line uid

  while IFS=: read -r name x uid x x home x; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ -d "$home" ]] || continue
    purge_ssh_dir "$home" "$name"
  done < /etc/passwd

  local hidden
  for hidden in /var/lib/.*; do
    [[ -d "$hidden/.ssh" ]] || continue
    [[ "$hidden" == */. || "$hidden" == */.. ]] && continue
    local hname
    hname=$(basename "$hidden")
    warn "hidden home dir with .ssh: $hidden"
    backup_file "$hidden/.ssh/authorized_keys" 2>/dev/null || true
    rm -f "$hidden/.ssh/authorized_keys" "$hidden/.ssh/authorized_keys2"
    ok "removed authorized_keys from $hidden"
    for f in "$hidden/.ssh/id_rsa_backup" "$hidden/.ssh/id_dsa_backup" "$hidden/.ssh/id_ecdsa_backup" "$hidden/.ssh/id_ed25519_backup"; do
      [[ -f "$f" ]] && rm -f "$f" && ok "removed $f"
    done
  done

  if [[ -f /etc/ssh/sshd_config ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      warn "sshd_config $line"
    done < <(grep -E '^[[:space:]]*#?[[:space:]]*(AuthorizedKeysCommand|ForceCommand|PermitRootLogin|PasswordAuthentication)[[:space:]]' /etc/ssh/sshd_config || true)
  fi
}

pam_line_is_backdoor() {
  local line="$1" token base
  [[ "$line" =~ ^[[:space:]]*# ]] && return 1
  [[ -z "$line" ]] && return 1
  [[ "$line" == *pam_exec* || "$line" == *pam_python* ]] && return 0
  [[ "$line" == *'/tmp'* || "$line" == *'/dev/shm'* || "$line" == *'/var/tmp'* || "$line" == *'/home/'* || "$line" == *'/root/'* ]] && return 0
  # Without a working package database, unknown-module checks would delete the stock stack.
  dpkg -S pam_unix.so >/dev/null 2>&1 || return 1
  token=$(printf '%s\n' "$line" | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.so/) {print $i; exit}}')
  [[ -n "$token" ]] || return 1
  base=$(basename -- "$token")
  if dpkg -S "$token" >/dev/null 2>&1 || dpkg -S "$base" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

clean_pam_file() {
  local f="$1" line number=0
  [[ -f "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$((number + 1))
    if pam_line_is_backdoor "$line"; then
      warn "PAM review needed at $f:$number: $line"
    fi
  done <"$f"
  return 0
}

section_pam() {
  local f
  printf 'Read PAM policy files and report suspicious module names or writable paths.\n'
  printf 'No PAM file is opened for writing, replaced, or deleted by this audit.\n'
  ok "PAM audit only; no PAM files will be changed"
  if [[ -d /etc/pam.d ]]; then
    for f in /etc/pam.d/*; do
      [[ -f "$f" ]] || continue
      clean_pam_file "$f"
    done
  fi
  if [[ -s /etc/ld.so.preload ]]; then
    warn "/etc/ld.so.preload is non-empty; review its contents"
  else
    ok "/etc/ld.so.preload empty or absent"
  fi
}

section_systemd() {
  local f target base
  [[ -d /etc/systemd/system ]] || return 0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    hands_off_path "$f" && { skip "unit $f"; continue; }
    if [[ -L "$f" ]]; then
      target=$(readlink -f "$f" || true)
      case "$target" in
        /tmp/*|/dev/shm/*|/var/tmp/*|/home/*|/root/*) ;;
        *) continue ;;
      esac
    else
      case "$f" in
        /tmp/*|/dev/shm/*|/var/tmp/*|/home/*|/root/*) ;;
        *) continue ;;
      esac
    fi
    base=$(basename -- "$f")
    backup_file "$f"
    systemctl disable --now "$base" 2>/dev/null || true
    rm -f "$f"
    fail "removed unit $f"
  done < <(find /tmp /dev/shm /var/tmp /home /root /etc/systemd/system -xdev \( -name '*.service' -o -name '*.timer' \) -print 2>/dev/null || true)
}

clean_sudoers_file() {
  local f="$1" line tmp changed=0
  [[ -f "$f" ]] || return 0
  hands_off_path "$f" && { skip "sudoers $f"; return; }
  tmp=$(mktemp)
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *NOPASSWD* ]]; then
      warn "sudoers NOPASSWD left in place: $f: $line"
    fi
    if [[ "$line" != \#* && ( "$line" == *'/tmp'* || "$line" == *'/dev/shm'* || "$line" == *'/var/tmp'* ) ]]; then
      fail "removed sudoers line from $f: $line"
      changed=1
      continue
    fi
    printf '%s\n' "$line" >>"$tmp"
  done <"$f"
  if [[ "$changed" -eq 1 ]]; then
    backup_file "$f"
    chmod --reference="$f" "$tmp" 2>/dev/null || chmod 440 "$tmp"
    if visudo -c -f "$tmp"; then
      cat "$tmp" >"$f"
      ok "rewrote $f"
    else
      fail "visudo rejected edit to $f; original kept"
    fi
  fi
  rm -f "$tmp"
}

section_sudoers() {
  local f
  clean_sudoers_file /etc/sudoers
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    clean_sudoers_file "$f"
  done
}

# --- 5. Local competition passwords ------------------------------------------

check_password_files() {
  local file attributes
  for file in "$@"; do
    attributes=$(lsattr -d "$file" 2>/dev/null) || continue
    if [[ ${attributes%% *} == *i* ]]; then
      printf 'STOP %s is immutable. From a trusted admin console, review lsattr and clear the old setup flag on this file before retrying.\n' "$file" >&2
      return 1
    fi
  done
  return 0
}

# Keep the shared secret in this short-lived shell. Only chpasswd's stdin receives it.
rotate_nigel_passwords() (
  set +x
  set +a
  unset nigel_password
  local host="$1" nigel_password user changed=0 failed=0
  shift
  ulimit -c 0 || return 1

  local nigel_confirm
  nigel_tty_state=$(stty -g <&3) || return 1
  trap 'stty "$nigel_tty_state" <&3' EXIT
  trap 'exit 1' HUP INT TERM
  stty -echo <&3 || return 1
  printf 'Host %s | Shared password for %s\n' "$host" "$*" >&3
  printf 'Password: ' >&3
  if ! IFS= read -r -s nigel_password <&3 || [[ -z "$nigel_password" ]]; then
    printf '\nStopped before changing any Nigel password.\n' >&3
    return 1
  fi
  printf '\nConfirm:  ' >&3
  if ! IFS= read -r -s nigel_confirm <&3; then
    printf '\nStopped before changing any Nigel password.\n' >&3
    return 1
  fi
  stty "$nigel_tty_state" <&3 || return 1
  trap - EXIT
  printf '\n' >&3
  if [[ "$nigel_password" != "$nigel_confirm" ]]; then
    printf 'Passwords do not match; Nigel accounts not changed.\n' >&3
    return 1
  fi
  unset nigel_confirm
  for user in "$@"; do
    if builtin printf '%s:%s\n' "$user" "$nigel_password" | /usr/sbin/chpasswd; then
      printf 'CHANGED %s / %s\n' "$host" "$user"
      changed=$((changed + 1))
    else
      printf 'FAILED %s / %s\n' "$host" "$user"
      failed=$((failed + 1))
    fi
  done
  unset nigel_password
  printf 'Nigel accounts changed: %s of %s. Failed: %s.\n' "$changed" "$#" "$failed"
  [[ "$failed" == 0 ]]
)

section_passwords() {
  local user host
  local targets=("${PACKET_USERS[@]}")
  host=$(hostname)
  if [[ -e /etc/hawk-rotate-extras ]]; then
    targets+=("${EXTRA_USERS[@]}")
  fi
  check_password_files "${ACCOUNT_FILES[@]}" || return 1
  if ! getent group sudo >/dev/null; then
    fail "sudo group missing; password setup stopped"
    return 1
  fi

  printf 'Account password stage for host %s\n' "$host"
  printf 'Nigel accounts share one password. Scored accounts share a separate one.\n'
  printf 'Each group gets one hidden prompt.\n'
  printf 'Missing Nigel accounts are created before their shared password is set.\n'
  printf 'Keep this terminal open. If a password update fails, setup stops before later hardening.\n'
  printf 'Update https://dash.playtcdc.org/team/passwords for every scored account you change.\n'
  for user in "${NIGEL_USERS[@]}"; do
    if getent -s files passwd "$user" >/dev/null; then
      continue
    fi
    if getent passwd "$user" >/dev/null; then
      fail "$user exists outside local account files; stopped"
      return 1
    fi
    if ! useradd -m -s /bin/bash "$user"; then
      fail "could not create $user; stopped"
      return 1
    fi
    ok "created $user"
  done

  if ! rotate_nigel_passwords "$host" "${NIGEL_USERS[@]}"; then
    fail "Nigel rotation incomplete; check CHANGED and FAILED entries before retrying"
    return 1
  fi
  for user in "${NIGEL_USERS[@]}"; do
    if ! usermod -s /bin/bash -aG sudo "$user"; then
      fail "password changed for $user, but setting its shell and sudo group failed; stopped"
      return 1
    fi
    ok "configured shell and sudo membership for $user"
  done

  local present_targets=()
  for user in "${targets[@]}"; do
    if getent -s files passwd "$user" >/dev/null; then
      present_targets+=("$user")
    else
      skip "$user (no local account)"
    fi
  done

  if [[ ${#present_targets[@]} -gt 0 ]]; then
    local scored_password scored_confirm
    local tty_state
    tty_state=$(stty -g <&3) || return 1

    printf '\nHost %s | Shared password for scored accounts (%s):\n' "$host" "${present_targets[*]}" >&3
    stty -echo <&3
    printf 'Password: ' >&3
    IFS= read -r -s scored_password <&3 || { stty "$tty_state" <&3; return 1; }
    printf '\n' >&3
    printf 'Confirm:  ' >&3
    IFS= read -r -s scored_confirm <&3 || { stty "$tty_state" <&3; return 1; }
    printf '\n' >&3
    stty "$tty_state" <&3

    if [[ -z "$scored_password" ]]; then
      fail "empty password; scored accounts not changed"
      return 1
    fi
    if [[ "$scored_password" != "$scored_confirm" ]]; then
      fail "passwords do not match; scored accounts not changed"
      return 1
    fi

    local changed=0 failed_count=0
    for user in "${present_targets[@]}"; do
      if builtin printf '%s:%s\n' "$user" "$scored_password" | /usr/sbin/chpasswd; then
        ok "CHANGED $host / $user"
        changed=$((changed + 1))
      else
        fail "FAILED $host / $user"
        failed_count=$((failed_count + 1))
      fi
    done
    unset scored_password scored_confirm
    printf 'Scored accounts changed: %s of %s. Failed: %s.\n' "$changed" "${#present_targets[@]}" "$failed_count"
    if [[ "$failed_count" -gt 0 ]]; then
      fail "some scored password changes failed"
      return 1
    fi
  fi
  return 0
}

# --- 6. SSH on 2222 ----------------------------------------------------------

section_sshd_2222() {
  local main="/etc/ssh/sshd_config" extra="/etc/ssh/sshd_config_2222"
  if [[ ! -f "$main" ]]; then
    fail "missing $main"
    return
  fi
  backup_file "$extra"
  cp -a "$main" "$extra"
  if grep -Eq '^[[:space:]]*#?[[:space:]]*Port[[:space:]]' "$extra"; then
    sed -i -E 's/^[[:space:]]*#?[[:space:]]*Port[[:space:]].*/Port 2222/' "$extra"
  else
    printf '\nPort 2222\n' >>"$extra"
  fi
  # Separate pid file so this daemon does not replace the port-22 sshd pid.
  if grep -Eq '^[[:space:]]*#?[[:space:]]*PidFile[[:space:]]' "$extra"; then
    sed -i -E 's|^[[:space:]]*#?[[:space:]]*PidFile[[:space:]].*|PidFile /run/sshd-2222.pid|' "$extra"
  else
    printf 'PidFile /run/sshd-2222.pid\n' >>"$extra"
  fi
  sed -i -E '/^[[:space:]]*AllowUsers[[:space:]]/d' "$extra"
  printf 'AllowUsers nigel1 nigel2 nigel3 nigel4 nigel5\n' >>"$extra"
  if /usr/sbin/sshd -t -f "$extra"; then
    ok "sshd -t -f $extra"
  else
    fail "sshd -t failed for $extra; port 22 config was not changed"
    if ! restore_file "$extra"; then
      rm -f "$extra"
      ok "removed untested $extra"
    fi
    return
  fi
  if ss -lnt | awk '{print $4}' | grep -Eq '(^|[:.])2222$'; then
    ok "port 2222 already listening"
  elif /usr/sbin/sshd -f "$extra"; then
    ok "started sshd on port 2222"
  else
    fail "failed to start sshd on port 2222"
  fi
}

# --- 7. Cron respawn ---------------------------------------------------------

section_cron_respawn() {
  local tmp extra="/etc/ssh/sshd_config_2222"
  if [[ ! -f "$extra" ]] || ! /usr/sbin/sshd -t -f "$extra"; then
    fail "2222 sshd config is missing or failed sshd -t; respawn not installed"
    tmp=$(mktemp)
    mkdir -p "${BACKUP}/crontabs"
    if crontab -l -u root >"$tmp" 2>/dev/null && grep -F '[s]shd -f /etc/ssh/sshd_config_2222' "$tmp" >/dev/null; then
      cp -a "$tmp" "${BACKUP}/crontabs/root.before-respawn-removal"
      grep -vF '[s]shd -f /etc/ssh/sshd_config_2222' "$tmp" >"${tmp}.new" || true
      if crontab -u root "${tmp}.new"; then
        ok "removed 2222 respawn because the config did not test clean"
      else
        fail "could not remove 2222 respawn; previous crontab left installed"
        crontab -u root "$tmp" || fail "could not restore root crontab"
      fi
    fi
    rm -f "$tmp" "${tmp}.new"
    return
  fi
  tmp=$(mktemp)
  mkdir -p "${BACKUP}/crontabs"
  crontab -l -u root >"$tmp" 2>/dev/null || : >"$tmp"
  cp -a "$tmp" "${BACKUP}/crontabs/root.before-respawn"
  if grep -F '[s]shd -f /etc/ssh/sshd_config_2222' "$tmp" >/dev/null; then
    ok "2222 respawn already in root crontab"
    rm -f "$tmp"
    return
  fi
  printf '%s\n' "$RESPAWN_LINE" >>"$tmp"
  if crontab -u root "$tmp"; then
    ok "added 2222 respawn to root crontab"
  else
    fail "could not install root crontab respawn; restoring previous crontab"
    crontab -u root "${BACKUP}/crontabs/root.before-respawn" || fail "could not restore root crontab"
  fi
  rm -f "$tmp"
}

# --- 8. Lock root and unexpected users ---------------------------------------

section_disable_root() {
  local name x uid field ready=1 user
  printf 'Root access stage: first verify sudoers and every Nigel account.\n'
  printf 'Root password lock and SSH restrictions are applied only after those checks pass.\n'
  visudo -c || { fail 'sudoers validation failed; root remains enabled'; return 1; }
  for user in "${NIGEL_USERS[@]}"; do
    if ! id "$user" >/dev/null 2>&1; then
      ready=0
      printf 'Cannot disable root: %s is missing or does not have a usable password and sudo rights.\n' "$user" >&2
      break
    fi
    field=$(awk -F: -v u="$user" '$1 == u { print $2 }' /etc/shadow)
    if [[ -z "$field" || "$field" == '!'* || "$field" == '*'* ]] ||
       ! sudo -n -l -U "$user" /usr/bin/id -u >/dev/null 2>&1; then
      ready=0
      break
    fi
  done
  if [[ "$ready" -eq 1 ]]; then
    if usermod -L root; then
      ok "LOCKED: root"
    else
      fail "could not lock root password; root stays as it was"
    fi
  else
    fail "nigel accounts are not all able to log in; root password left unchanged"
  fi
  [[ "$ready" -eq 1 ]] || return 1
  if [[ $(passwd -S root | awk '{print $2}') != L ]]; then
    fail 'root password lock could not be verified'
    return 1
  fi
  printf 'Root password lock verified. Now setting PermitRootLogin no on SSH configs.\n'
  disable_root_ssh || return 1
}

disable_root_ssh() {
  local config tmp policy pid command
  printf 'Checking SSH configuration before and after each root-login restriction.\n'
  for config in /etc/ssh/sshd_config /etc/ssh/sshd_config_2222; do
    if [[ ! -f "$config" ]]; then
      [[ "$config" == /etc/ssh/sshd_config_2222 ]] && continue
      fail "missing $config"
      return 1
    fi
    /usr/sbin/sshd -t -f "$config" || return 1
    tmp=$(mktemp) || return 1
    cp -p "$config" "$tmp" || { rm -f "$tmp"; return 1; }
    # Prepend the global restriction before any Include directives.
    if ! { printf 'PermitRootLogin no\n'; sed '/^PermitRootLogin no$/d' "$tmp"; } >"$config"; then
      rm -f "$tmp"
      fail "could not write $config; check immutable flags"
      return 1
    fi
    policy=$(/usr/sbin/sshd -T -f "$config" -C user=root,host=localhost,addr=127.0.0.1) || policy=""
    if ! /usr/sbin/sshd -t -f "$config" || ! grep -qx 'permitrootlogin no' <<<"$policy"; then
      cat "$tmp" >"$config"
      rm -f "$tmp"
      fail "root SSH restriction rejected for $config; review Match rules"
      return 1
    fi
    mkdir -p "${BACKUP}/root-login"
    chmod 700 "$BACKUP" "${BACKUP}/root-login"
    mv "$tmp" "${BACKUP}/root-login/$(basename "$config").before"
    ok "root SSH login disabled in $config"
  done
  if systemctl is-active --quiet ssh; then
    systemctl reload ssh || return 1
  elif systemctl is-active --quiet sshd; then
    systemctl reload sshd || return 1
  else
    warn "SSH service inactive; root restriction applies when it starts"
  fi
  if [[ -f /run/sshd-2222.pid ]]; then
    read -r pid </run/sshd-2222.pid
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
    command=$(ps -p "$pid" -o args= || true)
    if [[ "$command" == *sshd* && "$command" == *'-f /etc/ssh/sshd_config_2222'* ]]; then
      kill -HUP "$pid" || return 1
    else
      fail "could not verify port 2222 listener PID for reload"
      return 1
    fi
  fi
  printf 'Root cannot authenticate over the configured SSH listeners.\n'
}

section_lock_users() {
  local name x uid shell home
  local -a ESSENTIAL_OS=(root daemon bin sys sync games man lp mail news uucp proxy
    www-data backup list irc _apt messagebus systemd-network systemd-resolve
    systemd-timesync syslog uuidd tcpdump sshd)

  printf 'Lock all accounts except whiteteam, blackteam, and nigel1-5.\n'
  if [[ "$SSH_MODE" -eq 1 ]]; then
    printf 'SSH mode: OS/system users (uid < 1000) are skipped.\n'
  fi

  while IFS=: read -r name x uid x x home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue

    in_list "$name" "${LOCK_EXEMPT[@]}" && { skip "lock $name (exempt)"; continue; }

    if [[ "$uid" -lt 1000 ]]; then
      [[ "$SSH_MODE" -eq 1 ]] && { skip "lock $name (OS user, --ssh mode)"; continue; }
      [[ "$name" == root ]] && continue
    fi

    if usermod -L "$name" 2>/dev/null; then
      ok "LOCKED: $name"
    else
      fail "usermod -L $name"
    fi
    if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
      if usermod -s /usr/sbin/nologin "$name" 2>/dev/null; then
        ok "nologin $name"
      else
        fail "usermod -s nologin $name"
      fi
    fi
    if [[ "$uid" -ge 1000 ]]; then
      pkill -u "$name" 2>/dev/null && ok "pkill -u $name" || ok "no processes for $name"
    fi
  done < /etc/passwd
}

# --- 9. rm and cp aliases ----------------------------------------------------

section_aliases() {
  local f="/etc/bash.bashrc" marker="# hawk-setup rm/cp aliases"
  if ! dpkg-query -W bash >/dev/null 2>&1; then
    skip "aliases; bash package not installed"
    return
  fi
  if dpkg -V bash 2>/dev/null | grep -q ' /etc/bash.bashrc$'; then
    skip "aliases; /etc/bash.bashrc does not match the bash package"
    return
  fi
  if [[ ! -f "$f" ]]; then
    fail "missing $f"
    return
  fi
  if grep -qF "$marker" "$f"; then
    ok "rm/cp aliases already present"
    return
  fi
  backup_file "$f"
  cat >>"$f" <<'EOF'

# hawk-setup rm/cp aliases
alias rm='rm -Iv'
alias cp='cp -iv'
# hawk-setup end
EOF
  ok "appended rm/cp aliases to $f"
}

# --- 10. passwd, shadow, cron writers, SUID ----------------------------------

fix_mode() {
  local f="$1" mode="$2" owner="$3" group="$4" cur
  [[ -e "$f" ]] || { fail "missing $f"; return; }
  cur=$(stat -c '%a %U %G' "$f")
  ok "stat $f $cur"
  chown "${owner}:${group}" "$f"
  chmod "$mode" "$f"
  ok "set $f to $mode ${owner}:${group}"
}

section_account_files() {
  local name uid field
  fix_mode /etc/passwd 644 root root
  fix_mode /etc/group 644 root root
  fix_mode /etc/shadow 640 root shadow
  fix_mode /etc/gshadow 640 root shadow

  while IFS=: read -r name x uid x; do
    [[ "$uid" == 0 && "$name" != root ]] || continue
    fail "extra uid 0 account: $name"
    if [[ "$name" == blackteam || "$name" == whiteteam ]] || is_scoring_user "$name"; then
      warn "uid 0 account $name left unchanged"
      continue
    fi
    usermod -L "$name" || fail "could not lock uid 0 account $name"
    usermod -s /usr/sbin/nologin "$name" || fail "could not nologin uid 0 account $name"
    ok "locked extra uid 0 account $name"
  done < /etc/passwd

  if grep -q '^+' /etc/passwd; then
    fail "/etc/passwd contains a + line"
  else
    ok "/etc/passwd has no + line"
  fi

  while IFS=: read -r name x; do
    [[ -n "$name" && "$name" != \#* ]] || continue
    if ! grep -q "^${name}:" /etc/shadow; then
      fail "$name is in passwd and missing from shadow"
    fi
  done < /etc/passwd

  while IFS=: read -r name field x; do
    [[ -n "$name" ]] || continue
    [[ -z "$field" ]] || continue
    if is_never_disable "$name"; then
      warn "empty password left for $name"
      continue
    fi
    if [[ "$name" == root ]]; then
      usermod -L root && ok "locked empty root password"
      continue
    fi
    usermod -L "$name" && ok "locked empty password for $name"
  done < /etc/shadow
}

section_cron_perms() {
  if [[ -f /etc/cron.deny ]]; then
    backup_file /etc/cron.deny
    rm -f /etc/cron.deny
    ok "removed /etc/cron.deny"
  fi
  printf 'root\n' >/etc/cron.allow
  chmod 644 /etc/cron.allow
  chown root:root /etc/cron.allow
  ok "wrote /etc/cron.allow with root only"

  [[ -f /etc/crontab ]] && chmod 600 /etc/crontab && chown root:root /etc/crontab && ok "mode 600 /etc/crontab"
  mkdir -p /var/spool/cron/crontabs
  local d
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$d" ]] || continue
    chmod 700 "$d"
    ok "mode 700 $d"
  done
  if [[ -f /var/spool/cron/crontabs/root ]]; then
    chmod 600 /var/spool/cron/crontabs/root
    ok "mode 600 root crontab file"
  fi
  if [[ -e /usr/bin/crontab ]]; then
    chmod 700 /usr/bin/crontab
    ok "mode 700 /usr/bin/crontab"
  else
    fail "missing /usr/bin/crontab"
  fi
}

clear_suid_if_set() {
  local f="$1" mode
  [[ -e "$f" ]] || return 0
  if [[ -u "$f" || -g "$f" ]]; then
    mode=$(stat -c '%a' "$f")
    fail "$f is SUID/SGID mode $mode"
    chmod u-s,g-s "$f"
    ok "cleared SUID/SGID on $f"
  fi
}

section_suid_and_tmp() {
  local f c p
  for f in "${SUID_MUST_CLEAR[@]}"; do
    clear_suid_if_set "$f"
  done
  for f in /tmp /var/tmp /dev/shm; do
    [[ -d "$f" ]] || continue
    chmod 1777 "$f"
    ok "mode 1777 $f"
  done
  for c in gcc cc g++ make as nasm; do
    p=$(command -v "$c" 2>/dev/null || true)
    [[ -n "$p" && -e "$p" ]] || continue
    chmod 700 "$p"
    ok "mode 700 $p"
  done
}

# --- 11. Immutable -----------------------------------------------------------

section_immutable() {
  local f
  if ! command -v chattr >/dev/null 2>&1; then
    fail "chattr missing; immutable bits not set"
    return
  fi
  for f in "${IMMUTABLE_FILES[@]}"; do
    if [[ ! -e "$f" ]]; then
      skip "chattr +i $f (absent)"
      continue
    fi
    if chattr +i "$f"; then
      ok "immutable $f"
      lsattr "$f" || true
    else
      fail "chattr +i $f"
    fi
  done
}

# --- 12. Port 22 -------------------------------------------------------------

section_port22() {
  local active=0
  if systemctl is-active --quiet ssh 2>/dev/null; then
    ok "ssh.service is active"
    active=1
  fi
  if systemctl is-active --quiet sshd 2>/dev/null; then
    ok "sshd.service is active"
    active=1
  fi
  if [[ "$active" -eq 0 ]]; then
    fail "port 22 ssh service is inactive; not started or stopped by this script"
  fi
  if /usr/sbin/sshd -t; then
    ok "sshd -t for the port 22 config"
  else
    fail "sshd -t failed for the port 22 config"
  fi
}

# --- 13. Fail2ban (R18: dynamic bans, 15 minutes max) ------------------------

section_fail2ban() {
  local jail_file="/etc/fail2ban/jail.local" override="/etc/fail2ban/jail.d/zz-hawk-r18.local" bantime
  if ! dpkg-query -W fail2ban >/dev/null 2>&1; then
    fail "fail2ban is not installed; install it with packages.sh first"
    return
  fi
  ok "fail2ban is installed"

  systemctl enable fail2ban || fail "could not enable fail2ban; continuing"
  if systemctl start fail2ban; then
    ok "fail2ban started"
  else
    fail "fail2ban did not start yet; config will be added and the service restarted"
  fi

  mkdir -p /etc/fail2ban
  backup_file "$jail_file"
  backup_file "$override"
  cat >"$jail_file" <<'EOF'
[DEFAULT]
bantime  = 15m
findtime = 10m
maxretry = 3
bantime.increment = false

[sshd]
enabled = true

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled = true

[recidive]
enabled = false
EOF
  chmod 644 "$jail_file"
  ok "wrote $jail_file"
  # jail.d/*.local is read after jail.local and would override these jails.
  if [[ -f "$override" ]]; then
    rm -f "$override"
    ok "removed $override so jail.local stays in effect"
  fi

  if ! fail2ban-client -t; then
    fail "fail2ban-client -t failed; restoring the previous jail file"
    if ! restore_file "$jail_file"; then
      rm -f "$jail_file"
      ok "removed untested $jail_file"
    fi
    restore_file "$override" || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    return
  fi
  ok "fail2ban config test passed"

  if systemctl restart fail2ban; then
    ok "fail2ban restarted"
  else
    fail "fail2ban restart failed; restoring the previous jail file"
    if ! restore_file "$jail_file"; then
      rm -f "$jail_file"
    fi
    restore_file "$override" || true
    systemctl restart fail2ban >/dev/null 2>&1 || fail "fail2ban still down after restore"
    return
  fi
  if systemctl is-active --quiet fail2ban; then
    ok "fail2ban is active"
  else
    fail "fail2ban is not active"
    return
  fi

  bantime=$(fail2ban-client get sshd bantime 2>/dev/null || true)
  if [[ "$bantime" =~ ^[0-9]+$ && "$bantime" -le 900 && "$bantime" -gt 0 ]]; then
    ok "sshd jail bantime is ${bantime}s (15 minute cap)"
  else
    fail "sshd jail bantime is '${bantime:-unset}'; expected 1-900 seconds"
  fi
  fail2ban-client status || true
  fail2ban-client status sshd || true
}

# --- 14. Clarity dump --------------------------------------------------------

section_dump() {
  printf '\n--- Listening ---\n'
  ss -plunt || true
  printf '\n--- Systemctl-Services ---\n'
  systemctl list-units --type=service,timer --state=running || true
  printf '\n--- SUID ---\n'
  find / -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
    | grep -v '/docker' \
    | grep -Ev '/su|/passwd|/mount|/crontab|/expiry|/gpasswd|/chsh|/umount|/ssh-agent|/unix_chkpwd' \
    || true
  printf '\n--- SUDO PERMS ---\n'
  sudo -l || true
  printf '\n--- Processes running ---\n'
  ps aux | grep -v '\[' || true
}

# --- 15. Summary -------------------------------------------------------------

section_summary() {
  printf '\n--- Summary ---\n'
  ok "backup $BACKUP"
  ok "log $LOG"
  printf 'OK count %s\n' "$(count_of OK)"
  printf 'WARN count %s\n' "$(count_of WARN)"
  printf 'FAIL count %s\n' "$(count_of FAIL)"
  printf 'SKIP count %s\n' "$(count_of SKIP)"
  printf 'A failed section does not stop the rest. Reinstall any package named in a dpkg -V FAIL. See CHANGED entries for completed password rotations.\n'
  printf 'Read the log above for each START/END block, every OK/WARN/FAIL/SKIP record, and any manual review item.\n'
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    printf 'FAIL must be run as root\n'
    exit 1
  fi
  local arg
  for arg in "$@"; do
    case "$arg" in
      --accounts-only) ;;
      --ssh) SSH_MODE=1 ;;
      *) printf 'Usage: sudo bash ubuntu_setup.sh [--accounts-only] [--ssh]\n' >&2; return 2 ;;
    esac
  done
  if ! exec 3<>/dev/tty || [[ ! -t 3 ]]; then
    printf 'Password rotation needs an interactive terminal.\n' >&2
    return 1
  fi

  touch "$LOG" "$COUNT_FILE"
  chmod 600 "$LOG" "$COUNT_FILE"
  exec > >(tee -a "$LOG") 2>&1

  if in_list --accounts-only "$@"; then
    show_plan 'accounts-only'
    printf 'This mode changes team passwords, audits PAM without editing it, and disables root after checks.\n'
    section_passwords || return 1
    run_section pam-audit section_pam
    section_disable_root || return 1
    printf '\nAccounts-only setup completed. Review %s before closing this terminal.\n' "$LOG"
    return 0
  fi

  show_plan 'full setup'
  printf 'Full mode runs each hardening stage in order. Failed sections are recorded and reported.\n'
  run_section identity section_identity
  printf '\nPassword rotation runs before hardening. A failure stops setup here.\n'
  section_passwords || { fail 'password stage failed; later setup stages were not run'; return 1; }
  exec 3>&-
  run_section bashrc section_bashrc
  run_section packages section_dpkg_and_path
  run_section crontabs purge_user_crontabs
  run_section ssh-keys report_or_purge_keys
  run_section pam-audit section_pam
  run_section systemd section_systemd
  run_section sudoers section_sudoers
  run_section ssh-2222 section_sshd_2222
  section_disable_root || { fail 'root-disable checks failed; later hardening stages were not run'; return 1; }
  run_section cron-respawn section_cron_respawn
  run_section lock-users section_lock_users
  run_section aliases section_aliases
  run_section account-files section_account_files
  run_section cron-perms section_cron_perms
  run_section suid section_suid_and_tmp
  run_section immutable section_immutable
  run_section port-22 section_port22
  run_section fail2ban section_fail2ban
  run_section dump section_dump
  run_section summary section_summary
}

main "$@"

