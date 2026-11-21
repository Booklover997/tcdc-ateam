#!/usr/bin/env bash
# port_monitor.sh - watch specified ports, auto-exclude your SSH IP.
# Requires: tcpdump, root privileges.

DEFAULT_PORTS=(22 21 80 8080 53)

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

  -d, --default         Monitor default ports: ${DEFAULT_PORTS[*]}
  -p, --ports PORTS     Ports to monitor (comma/space separated)
  -e, --exclude IP      Exclude this IP (repeatable)
  -x                    Hex/ASCII packet dump
  -h, --help            Show this help

SSH client IP is auto-excluded. Use -e for additional IPs.
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
        *) echo "Unknown: $1" >&2; usage; exit 1 ;;
    esac
done

[[ $USE_DEFAULT -eq 1 ]] && PORTS+=("${DEFAULT_PORTS[@]}")

if [[ ${#PORTS[@]} -eq 0 ]]; then
    echo "Error: need --default or --ports" >&2
    exit 1
fi

[[ $EUID -ne 0 ]] && { echo "Run with sudo." >&2; exit 1; }
command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump not found." >&2; exit 1; }

# Auto-detect SSH client IP (sudo strips $SSH_CLIENT)
SSH_IP=""
if [[ -n ${SSH_CLIENT:-} ]]; then
    SSH_IP=$(awk '{print $1}' <<< "$SSH_CLIENT")
elif [[ -n ${SUDO_USER:-} ]]; then
    SSH_IP=$(who | grep "$SUDO_USER" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi
if [[ -z $SSH_IP ]]; then
    SSH_IP=$(ss -tn state established '( sport = :22 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi
[[ -n $SSH_IP ]] && echo "SSH client IP: $SSH_IP (auto-excluded)"

# Interactive prompt
read -rp "Extra IP(s) to exclude (blank to skip): " extra
if [[ -n $extra ]]; then
    for ip in ${extra//,/ }; do EXCLUDE_IPS+=("$ip"); done
fi

# Deduplicate ports
declare -A seen
all_ports=()
for p in "${PORTS[@]}"; do
    p=$((10#$p))
    [[ -n ${seen[$p]:-} ]] && continue
    seen[$p]=1
    all_ports+=("$p")
done

# Build filter
port_expr=$(printf 'port %s or ' "${all_ports[@]}")
filter="(${port_expr% or })"

[[ -n $SSH_IP ]] && filter+=" and not host $SSH_IP"
for ip in "${EXCLUDE_IPS[@]}"; do
    filter+=" and not host $ip"
done

LOG="port_monitor_$(date +%Y%m%d).log"

echo ""
echo "Ports: ${all_ports[*]}"
[[ ${#EXCLUDE_IPS[@]} -gt 0 ]] && echo "Excluded IPs: ${EXCLUDE_IPS[*]}"
echo "Filter: $filter"
echo "Log: $LOG  (Ctrl+C to stop)"
echo "----------------------------------------"

opts=(-i any -nn -l -tttt)
[[ $HEXDUMP -eq 1 ]] && opts+=(-X)

tcpdump "${opts[@]}" "$filter" \
    | sed -u -E 's/, win [0-9]+//; s/, options \[[^]]*\]//' \
    | tee -a "$LOG"

