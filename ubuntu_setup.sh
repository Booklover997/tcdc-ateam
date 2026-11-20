#!/bin/bash
# Local Ubuntu 26.04 setup for one box. Run as root:
#   sudo bash ubuntu_setup.sh
# Calls apt only to install fail2ban when that package is missing.
# Does not store passwords. Test on a non-competition VM first.

set -uo pipefail

SCORING_USERS=(
  washington kennedy teddy lincoln ross streep franklin parks
  armstrong hamilton mlk tubman manziel deniro bush
  blueteam score1 score2 patch
)
NEVER_DISABLE=(blackteam whiteteam nigel1 nigel2 nigel3 nigel4 nigel5)
NIGEL_USERS=(nigel1 nigel2 nigel3 nigel4 nigel5)
KEEP_USERS=("${SCORING_USERS[@]}" "${NEVER_DISABLE[@]}")

NORMAL_PATHS="/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin"
RESPAWN_LINE="* * * * * pgrep -af '[s]shd -f /etc/ssh/sshd_config_2222' >/dev/null || /usr/sbin/sshd -f /etc/ssh/sshd_config_2222"

IMMUTABLE_FILES=(
  /etc/passwd
  /etc/shadow
  /etc/group
  /etc/gshadow
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
  local rc
  set +e
  (
    set -uo pipefail
    "$@"
  )
  rc=$?
  set +e
  if [[ "$rc" -ne 0 ]]; then
    fail "section ${name} aborted with status ${rc}; the next section still runs"
  fi
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
    for f in "${IMMUTABLE_FILES[@]}"; do
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

  while IFS=: read -r name x uid gid gecos home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge 1000 ]] || continue
    [[ -d "$home" ]] || continue
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
    for f in "$dir"/*; do
      [[ -e "$f" ]] || continue
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

purge_user_crontabs() {
  local name x uid
  while IFS=: read -r name x uid x x x x; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge 1000 ]] || continue
    if is_keep_user "$name"; then
      skip "crontab $name"
      continue
    fi
    if save_user_crontab "$name"; then
      crontab -r -u "$name" 2>/dev/null || true
      ok "removed crontab for $name"
    fi
  done < /etc/passwd
  filter_root_crontab
  purge_cron_dirs
}

report_or_purge_keys() {
  local name home f n line uid
  while IFS=: read -r name x uid x x home x; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ -d "$home" ]] || continue
    if [[ "$name" == root ]]; then
      :
    elif [[ "$uid" -lt 1000 ]]; then
      continue
    fi
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -f "$f" ]] || continue
      n=$(grep -cve '^[[:space:]]*$' "$f" || true)
      if [[ "$name" == blackteam || "$name" == whiteteam ]] || is_scoring_user "$name"; then
        warn "keeping $f ($n key lines)"
        while IFS= read -r line || [[ -n "$line" ]]; do
          [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue
          warn "key comment $f ${line##* }"
        done <"$f"
        continue
      fi
      backup_file "$f"
      rm -f "$f"
      ok "removed $f"
    done
  done < /etc/passwd

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
  if [[ "$line" == auth* && "$line" == *pam_permit.so* ]]; then
    return 0
  fi
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

pam_file_safe() {
  local f="$1" base
  [[ -s "$f" ]] || return 1
  base=$(basename -- "$f")
  case "$base" in
    sshd|login|common-auth|su|sudo)
      grep -q pam_unix "$f" || return 1
      ;;
  esac
  return 0
}

clean_pam_file() {
  local f="$1" line tmp changed=0
  [[ -f "$f" ]] || return 0
  hands_off_path "$f" && { skip "pam $f"; return; }
  tmp=$(mktemp)
  while IFS= read -r line || [[ -n "$line" ]]; do
    if pam_line_is_backdoor "$line"; then
      fail "removed PAM line from $f: $line"
      changed=1
      continue
    fi
    if [[ "$line" == *pam_unix* && "$line" == *nullok* ]]; then
      line=${line//nullok_secure/}
      line=${line//nullok/}
      fail "stripped nullok in $f"
      changed=1
    fi
    printf '%s\n' "$line" >>"$tmp"
  done <"$f"
  if [[ "$changed" -eq 1 ]]; then
    backup_file "$f"
    if cat "$tmp" >"$f" && pam_file_safe "$f"; then
      ok "rewrote $f"
    else
      fail "PAM rewrite of $f looked unsafe"
      restore_file "$f" || true
    fi
  else
    ok "pam clean $f"
  fi
  rm -f "$tmp"
}

section_pam() {
  local f
  if [[ -d /etc/pam.d ]]; then
    for f in /etc/pam.d/*; do
      [[ -f "$f" ]] || continue
      clean_pam_file "$f"
    done
  fi
  clean_pam_file /etc/pam.conf

  if [[ -s /etc/ld.so.preload ]]; then
    fail "/etc/ld.so.preload was non-empty"
    backup_file /etc/ld.so.preload
    : > /etc/ld.so.preload
    ok "truncated /etc/ld.so.preload"
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

# --- 5. Nigel users ----------------------------------------------------------

gen_pass() {
  python3 - <<'PY'
import secrets
alphabet = "абвгдежзийклмнопрстуфхцчшщъыьэюя0123456789"
print("".join(secrets.choice(alphabet) for _ in range(16)))
PY
}

section_nigel() {
  local ans="n" user pass
  if [[ ! -r /dev/tty ]]; then
    skip "nigel password prompt (no terminal)"
    return
  fi
  printf 'Create or refresh nigel1 through nigel5 with new passwords? [y/N] ' >/dev/tty
  IFS= read -r ans </dev/tty || ans="n"
  if [[ "$ans" != "y" ]]; then
    skip "nigel password refresh"
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 missing; nigel passwords not generated"
    return
  fi
  if ! getent group sudo >/dev/null; then
    fail "sudo group missing; nigel users not modified"
    return
  fi
  for user in "${NIGEL_USERS[@]}"; do
    if id "$user" >/dev/null 2>&1; then
      usermod -s /bin/bash "$user"
      ok "shell /bin/bash for existing $user"
    else
      if useradd -m -s /bin/bash "$user"; then
        ok "created $user"
      else
        fail "useradd $user"
        continue
      fi
    fi
    pass=$(gen_pass) || true
    if [[ -z "${pass:-}" ]]; then
      fail "password generation failed for $user"
      unset pass
      continue
    fi
    printf '%s %s\n' "$user" "$pass" >/dev/tty
    if printf '%s:%s\n' "$user" "$pass" | chpasswd; then
      unset pass
      if usermod -aG sudo "$user"; then
        ok "password set and sudo granted for $user"
      else
        fail "password set for $user but sudo group update failed"
      fi
    else
      unset pass
      fail "chpasswd failed for $user; other users still continue"
    fi
  done
  printf 'Copy the five passwords from this terminal. They were not written to the log.\n' >/dev/tty
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

section_lock_users() {
  local name x uid field ready=1 user
  for user in "${NIGEL_USERS[@]}"; do
    if ! id "$user" >/dev/null 2>&1; then
      ready=0
      break
    fi
    field=$(awk -F: -v u="$user" '$1 == u { print $2 }' /etc/shadow)
    if [[ -z "$field" || "$field" == '!'* || "$field" == '*' ]]; then
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
  skip "root shell unchanged; root processes not killed"

  while IFS=: read -r name x uid x x x shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge 1000 ]] || continue
    [[ "$name" == nobody ]] && continue
    if is_never_disable "$name"; then
      skip "lock $name"
      continue
    fi
    if usermod -L "$name"; then
      ok "LOCKED: $name"
    else
      fail "usermod -L $name"
    fi
    if usermod -s /usr/sbin/nologin "$name"; then
      ok "nologin $name"
    else
      fail "usermod -s nologin $name"
    fi
    if pkill -u "$name" 2>/dev/null; then
      ok "pkill -u $name"
    else
      ok "no processes for $name"
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
    ok "fail2ban is not installed; installing it"
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban; then
      fail "apt-get install fail2ban failed"
      return
    fi
    ok "installed fail2ban"
  else
    ok "fail2ban is already installed"
  fi

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
  printf 'A failed section does not stop the rest. Reinstall any package named in a dpkg -V FAIL. If nigel passwords were created, they were printed on the terminal only.\n'
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    printf 'FAIL must be run as root\n'
    exit 1
  fi
  touch "$LOG" "$COUNT_FILE"
  chmod 600 "$LOG" "$COUNT_FILE"
  exec > >(tee -a "$LOG") 2>&1

  run_section identity section_identity
  run_section bashrc section_bashrc
  run_section packages section_dpkg_and_path
  run_section crontabs purge_user_crontabs
  run_section ssh-keys report_or_purge_keys
  run_section pam section_pam
  run_section systemd section_systemd
  run_section sudoers section_sudoers
  run_section nigel section_nigel
  run_section ssh-2222 section_sshd_2222
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
