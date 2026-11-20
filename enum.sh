#!/usr/bin/env bash
# audit.sh - Quick system audit, with optional deep scan (-F).

set -euo pipefail

FULL=0
[[ "${1:-}" == "-F" ]] && FULL=1

MY_IP=""
[[ -n ${SSH_CLIENT:-} ]] && MY_IP=$(awk '{print $1}' <<< "$SSH_CLIENT")

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
CYN='\033[1;36m'
DIM='\033[0;37m'
RST='\033[0m'

echo -e "${BLU}============================================${RST}"
echo -e "${BLU}  System Audit - $(date)${RST}"
[[ $FULL -eq 1 ]] && echo -e "  Mode: ${YLW}FULL (deep scan)${RST}" || echo -e "  Mode: ${GRN}QUICK${RST}"
[[ -n $MY_IP ]] && echo -e "  Your IP: ${GRN}$MY_IP${RST} (filtered out)"
echo -e "${BLU}============================================${RST}"

echo ""
echo -e "${BLU}=== Logged-In Users ===${RST}"
if [[ -n $MY_IP ]]; then
    others=$(w -ih | grep -v "$MY_IP" || true)
    if [[ -n $others ]]; then
        echo -e "  ${RED}Other sessions detected:${RST}"
        echo "$others" | while IFS= read -r line; do
            ip=$(awk '{print $3}' <<< "$line")
            user=$(awk '{print $1}' <<< "$line")
            echo -e "  ${DIM}$user${RST} from ${RED}$ip${RST}  $line"
        done
    else
        echo -e "  ${GRN}No one else logged in${RST}"
    fi
else
    w
fi

echo ""
echo -e "${BLU}=== Listening Ports ===${RST}"
ss -plunt | grep -i listen | grep -v '\[::' | while IFS= read -r line; do
    port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
    proc=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
    if [[ $port -lt 1024 ]]; then
        echo -e "  ${YLW}:$port${RST} ${DIM}($proc)${RST}  $line"
    else
        echo -e "  :$port ${DIM}($proc)${RST}  $line"
    fi
done

echo ""
echo -e "${BLU}=== Established Connections ===${RST}"
conns=$(ss -tupn state established 2>/dev/null | tail -n +2 | grep -v '\[::' || true)
if [[ -n $MY_IP ]]; then
    conns=$(echo "$conns" | grep -v "$MY_IP" || true)
fi
if [[ -n $conns ]]; then
    echo "$conns" | while IFS= read -r line; do
        peer=$(echo "$line" | awk '{print $5}')
        echo -e "  ${YLW}$peer${RST}  $line"
    done
else
    echo -e "  ${GRN}None (besides yours)${RST}"
fi

echo ""
echo -e "${BLU}=== TTY/PTY Shells ===${RST}"
shells=$(ps aux | grep -E '\b(bash|sh|zsh|dash|fish|nc|ncat|socat|python|perl|ruby)\b' \
    | grep -v grep \
    | grep -v "audit.sh" || true)
if [[ -n $shells ]]; then
    echo "$shells" | while IFS= read -r line; do
        user=$(awk '{print $1}' <<< "$line")
        tty=$(awk '{print $7}' <<< "$line")
        cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf $i " "; print ""}')
        if echo "$cmd" | grep -qE '(nc|ncat|socat|/dev/tcp)'; then
            echo -e "  ${RED}[SUSPECT]${RST} ${RED}$user${RST} tty=$tty  $cmd"
        elif [[ $user == "root" ]]; then
            echo -e "  ${YLW}$user${RST} tty=$tty  $cmd"
        else
            echo -e "  ${DIM}$user${RST} tty=$tty  $cmd"
        fi
    done
else
    echo -e "  ${GRN}(none found)${RST}"
fi

echo ""
echo -e "${BLU}=== Running Services & Timers ===${RST}"
systemctl list-units --type=timer --type=service --state=running --no-pager

echo ""
echo -e "${BLU}=== Cron Jobs (all users) ===${RST}"
echo "-- User crontabs:"
found_cron=0
while IFS=: read -r user _ _ _ _ _ shell; do
    [[ "$shell" == */nologin || "$shell" == */false ]] && continue
    jobs=$(crontab -l -u "$user" 2>/dev/null) || continue
    [[ -z $jobs ]] && continue
    found_cron=1
    echo -e "  ${YLW}[$user]${RST}"
    echo "$jobs" | while IFS= read -r line; do
        if [[ $line == \#* || -z $line ]]; then
            echo -e "    ${DIM}$line${RST}"
        else
            echo -e "    ${RED}$line${RST}"
        fi
    done
done < /etc/passwd
[[ $found_cron -eq 0 ]] && echo -e "  ${GRN}(none)${RST}"
echo "-- System cron:"
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d $d ]] && echo -e "  ${CYN}$d:${RST} $(ls "$d" 2>/dev/null | tr '\n' ' ')"
done

echo ""
echo -e "${BLU}=== Authorized SSH Keys ===${RST}"
found_keys=0
while IFS=: read -r user _ _ _ _ home _; do
    keyfile="$home/.ssh/authorized_keys"
    [[ -f $keyfile ]] || continue
    count=$(grep -c '^' "$keyfile" 2>/dev/null || echo 0)
    [[ $count -eq 0 ]] && continue
    found_keys=1
    echo -e "  ${YLW}$user${RST} ($keyfile): ${RED}$count key(s)${RST}"
    while IFS= read -r key; do
        comment=$(awk '{print $NF}' <<< "$key")
        type=$(awk '{print $1}' <<< "$key")
        echo -e "    ${DIM}$type${RST} ... ${YLW}$comment${RST}"
    done < "$keyfile"
done < /etc/passwd
[[ $found_keys -eq 0 ]] && echo -e "  ${GRN}(none found)${RST}"

echo ""
echo -e "${BLU}=== UID 0 Accounts ===${RST}"
while IFS=: read -r user _ uid _ _ _ shell; do
    [[ $uid -eq 0 ]] || continue
    if [[ $user == "root" ]]; then
        echo -e "  ${GRN}root${RST} ${DIM}(shell: $shell)${RST}"
    else
        echo -e "  ${RED}*** $user has UID 0 (shell: $shell) ***${RST}"
    fi
done < /etc/passwd

echo ""
echo -e "${BLU}=== Users With Login Shells ===${RST}"
while IFS=: read -r user _ uid _ _ _ shell; do
    [[ "$shell" =~ (nologin|false|sync|halt|shutdown) ]] && continue
    if [[ $uid -eq 0 ]]; then
        echo -e "  ${YLW}$user${RST} -> $shell"
    else
        echo -e "  $user -> ${DIM}$shell${RST}"
    fi
done < /etc/passwd

echo ""
echo -e "${BLU}=== SUDO Permissions ===${RST}"
echo -e "  ${CYN}Users in sudo group:${RST}"
sudo_members=$(getent group sudo 2>/dev/null | awk -F: '{print $4}' || true)
if [[ -n $sudo_members ]]; then
    echo -e "    ${YLW}$sudo_members${RST}"
else
    echo -e "    ${GRN}(none)${RST}"
fi
echo ""
sudo_out=$(sudo -l 2>/dev/null || true)
if [[ -n $sudo_out ]]; then
    in_commands=0
    echo "$sudo_out" | while IFS= read -r line; do
        if [[ $line == *"may run the following"* ]]; then
            in_commands=1
            echo -e "  ${DIM}$line${RST}"
        elif [[ $in_commands -eq 1 && -n $line ]]; then
            echo -e "  ${RED}$line${RST}"
        else
            echo -e "  ${DIM}$line${RST}"
        fi
    done
else
    echo -e "  ${GRN}(could not check sudo)${RST}"
fi

echo ""
echo -e "${BLU}=== /tmp and /dev/shm Contents ===${RST}"
echo "-- /tmp:"
tmp_files=$(ls -A /tmp/ 2>/dev/null | grep -v '^systemd-private' | grep -v '^\.' || true)
if [[ -n $tmp_files ]]; then
    for f in $tmp_files; do
        stat_line=$(ls -ld "/tmp/$f" 2>/dev/null)
        owner=$(awk '{print $3}' <<< "$stat_line")
        if [[ $owner == "root" ]]; then
            echo -e "  ${YLW}$stat_line${RST}"
        else
            echo -e "  $stat_line"
        fi
    done
else
    echo -e "  ${GRN}(clean)${RST}"
fi
echo "-- /dev/shm:"
shm_files=$(ls -A /dev/shm/ 2>/dev/null || true)
if [[ -n $shm_files ]]; then
    ls -la /dev/shm/ 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        echo -e "  ${YLW}$line${RST}"
    done
else
    echo -e "  ${GRN}(empty)${RST}"
fi

echo ""
echo -e "${BLU}=== Recently Modified Files (/etc /usr /var, last 30 min) ===${RST}"
recent=$(sudo find /etc /usr /var -mmin -30 -type f 2>/dev/null \
    | grep -Ev '/(log|journal|cache|tmp)/' || true)
if [[ -n $recent ]]; then
    echo "$recent" | while IFS= read -r f; do
        if [[ $f == /etc/* ]]; then
            echo -e "  ${RED}$f${RST}"
        else
            echo -e "  ${YLW}$f${RST}"
        fi
    done
else
    echo -e "  ${GRN}(none found)${RST}"
fi

echo ""
echo -e "${BLU}=== Running Processes ===${RST}"
ps aux | grep -v '\[' | while IFS= read -r line; do
    user=$(awk '{print $1}' <<< "$line")
    if [[ $user == "USER" ]]; then
        echo -e "${CYN}$line${RST}"
    elif [[ $user == "root" ]]; then
        echo "$line"
    else
        echo -e "${DIM}$line${RST}"
    fi
done

if [[ $FULL -eq 1 ]]; then
    echo ""
    echo -e "${BLU}=== SUID/SGID Binaries ===${RST}"
    suid=$(sudo find / \
        -not \( -path /proc -prune \) \
        -not \( -path /sys -prune \) \
        -not \( -path /run -prune \) \
        \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
        | grep -v '/docker' \
        | grep -Ev '/(su|passwd|mount|crontab|expiry|gpasswd|chsh|umount|ssh-agent|unix_chkpwd|journal|fonts|apt-update|ssh-keysign|dbus-daemon-launch-helper|pam_extrausers_chkpwd|chage|chfn|fusermount3|mail)$' \
        || true)
    if [[ -n $suid ]]; then
        echo -e "${RED}$suid${RST}"
    else
        echo -e "  ${GRN}(none found outside whitelist)${RST}"
    fi

    echo ""
    echo -e "${BLU}=== World-Writable Files (root-owned) ===${RST}"
    ww=$(sudo find / \
        -not \( -path /proc -prune \) \
        -not \( -path /sys -prune \) \
        -not \( -path /run -prune \) \
        -not \( -path /dev -prune \) \
        -not \( -path /tmp -prune \) \
        -not \( -path /var/tmp -prune \) \
        -user root -writable -type f 2>/dev/null \
        | grep -Ev '/(run|dev|sys|proc)/' || true)
    if [[ -n $ww ]]; then
        echo -e "${RED}$ww${RST}"
    else
        echo -e "  ${GRN}(none found)${RST}"
    fi

    echo ""
    echo -e "${BLU}=== World-Writable Directories (non-standard) ===${RST}"
    wwd=$(sudo find / \
        -not \( -path /proc -prune \) \
        -not \( -path /sys -prune \) \
        -not \( -path /run -prune \) \
        -not \( -path /dev -prune \) \
        -not \( -path /tmp -prune \) \
        -not \( -path /var/tmp -prune \) \
        -type d -perm -0002 2>/dev/null \
        | grep -Ev '/(tmp|cache|lock|spool|run|dev|sys|proc)/' || true)
    if [[ -n $wwd ]]; then
        echo -e "${RED}$wwd${RST}"
    else
        echo -e "  ${GRN}(none found)${RST}"
    fi

    echo ""
    echo -e "${BLU}=== Loaded Kernel Modules ===${RST}"
    lsmod
fi

echo ""
echo -e "${BLU}=== Done ===${RST}"
