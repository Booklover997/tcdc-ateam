#!/usr/bin/env bash
# port_monitor.sh - watch specified ports, auto-exclude your SSH IP.

DEFAULT_PORTS=(22 21 80 8080 53)

usage() {
    cat <<EOF
Usage: sudo -E $0 [OPTIONS]

  -d, --default         Monitor ports: ${DEFAULT_PORTS[*]}
  -p, --ports PORTS     Ports to monitor (comma/space separated)
  -e, --exclude IP      Exclude this IP (repeatable)
  -x                    Hex/ASCII packet dump
  -h, --help            Show this help
EOF
}

HEXDUMP=0
USE_DEFAULT=0
PORTS=()
EXCLUDE_IPS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--default) USE_DEFAULT=1; shift ;;
        -p|--ports) IFS=', ' read -ra p <<< "$2"; PORTS+=("${p[@]}"); shift 2 ;;
        -e|--exclude) EXCLUDE_IPS+=("$2"); shift 2 ;;
        -x) HEXDUMP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ $USE_DEFAULT -eq 1 ]] && PORTS+=("${DEFAULT_PORTS[@]}")
[[ ${#PORTS[@]} -eq 0 ]] && { echo "Need --default or --ports"; exit 1; }
# Auto-escalate to root, preserving SSH_CLIENT
if [[ $EUID -ne 0 ]]; then
    exec sudo SSH_CLIENT="$SSH_CLIENT" "$0" "$@"
fi

# --- Detect SSH client IP ---
SSH_IP=""
if [[ -n ${SSH_CLIENT:-} ]]; then
    SSH_IP="${SSH_CLIENT%% *}"
elif [[ -n ${SUDO_USER:-} ]]; then
    SSH_IP=$(who | grep "$SUDO_USER" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi
if [[ -z $SSH_IP ]]; then
    SSH_IP=$(ss -tn state established '( sport = :22 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi

if [[ -n $SSH_IP ]]; then
    echo "SSH client IP: $SSH_IP (auto-excluded)"
else
    echo "WARNING: could not detect SSH client IP"
    read -rp "Enter your IP to exclude: " SSH_IP
fi

# --- Interactive extra excludes ---
read -rp "Extra IP(s) to exclude (blank to skip): " extra
for ip in ${extra//,/ }; do EXCLUDE_IPS+=("$ip"); done

# --- Deduplicate ports ---
declare -A seen
all_ports=()
for p in "${PORTS[@]}"; do
    p=$((10#$p))
    [[ -n ${seen[$p]:-} ]] && continue
    seen[$p]=1
    all_ports+=("$p")
done

# --- Build BPF filter ---
port_expr=$(printf 'port %s or ' "${all_ports[@]}")
filter="(${port_expr% or })"

# Exclude SSH IP both directions
[[ -n $SSH_IP ]] && filter="($filter) and (not host $SSH_IP)"

# Exclude manual IPs
for ip in "${EXCLUDE_IPS[@]}"; do
    filter="($filter) and (not host $ip)"
done

LOG="port_monitor_$(date +%Y%m%d).log"

echo ""
echo "Ports: ${all_ports[*]}"
[[ -n $SSH_IP ]] && echo "Excluded: $SSH_IP"
[[ ${#EXCLUDE_IPS[@]} -gt 0 ]] && echo "Also excluded: ${EXCLUDE_IPS[*]}"
echo "Filter: $filter"
echo "Log: $LOG"
echo "----------------------------------------"

opts=(-i any -nn -l -tttt)
[[ $HEXDUMP -eq 1 ]] && opts+=(-X)

echo "Running: tcpdump ${opts[*]} '$filter'"
echo "----------------------------------------"

tcpdump "${opts[@]}" "$filter" 2>&1 | tee -a "$LOG"

