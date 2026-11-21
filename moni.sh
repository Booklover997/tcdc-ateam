#!/usr/bin/env bash
# port_monitor.sh - watch traffic with full include/exclude control over ports and IPs.
# Requires: tcpdump, root privileges.

set -euo pipefail

DEFAULT_PORTS=(22 21 80 8080 53)

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Port filters (at least one required):
  -d,  --default               Monitor default ports: ${DEFAULT_PORTS[*]}
  --pi, --port-include PORTS   Ports to monitor (comma/space separated, repeatable)
  --px, --port-exclude PORTS   Ports to ignore (comma/space separated, repeatable)

IP filters:
  --ii, --ip-include IPS       Only show traffic from these IPs (comma/space separated, repeatable)
  --ix, --ip-exclude IPS       Hide traffic from these IPs (comma/space separated, repeatable)

Other:
  -x                           Add hex/ASCII packet dump (tcpdump -X)
  -h, --help                   Show this help

Your SSH client IP (\$SSH_CLIENT) is always auto-excluded.
An interactive prompt asks for extra IPs to exclude at startup.

Examples:
  sudo $0 --default
  sudo $0 -d --pi 443 --px 8080
  sudo $0 --pi 22,80,443
  sudo $0 --pi 22,80 --ii 10.0.0.50 --ix 10.0.0.99
EOF
}

HEXDUMP=0
USE_DEFAULT=0
PORT_INCLUDE=()
PORT_EXCLUDE=()
IP_INCLUDE=()
IP_EXCLUDE=()

parse_csv() { IFS=', ' read -ra arr <<< "$1"; printf '%s\n' "${arr[@]}"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--default)
            USE_DEFAULT=1
            shift ;;
        --pi|--port-include)
            while IFS= read -r v; do PORT_INCLUDE+=("$v"); done < <(parse_csv "$2")
            shift 2 ;;
        --px|--port-exclude)
            while IFS= read -r v; do PORT_EXCLUDE+=("$v"); done < <(parse_csv "$2")
            shift 2 ;;
        --ii|--ip-include)
            while IFS= read -r v; do IP_INCLUDE+=("$v"); done < <(parse_csv "$2")
            shift 2 ;;
        --ix|--ip-exclude)
            while IFS= read -r v; do IP_EXCLUDE+=("$v"); done < <(parse_csv "$2")
            shift 2 ;;
        -x)
            HEXDUMP=1
            shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage; exit 1 ;;
    esac
done

# Merge default ports into include list
if [[ $USE_DEFAULT -eq 1 ]]; then
    PORT_INCLUDE+=("${DEFAULT_PORTS[@]}")
fi

if [[ ${#PORT_INCLUDE[@]} -eq 0 && ${#PORT_EXCLUDE[@]} -eq 0 ]]; then
    echo "Error: at least --default, --port-include, or --port-exclude is required." >&2
    usage
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (e.g. sudo $0) - tcpdump needs it to capture packets." >&2
    exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "tcpdump not found. Install it (e.g. apt install tcpdump)." >&2
    exit 1
fi

validate_ipv4() {
    local ip=$1
    if ! [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] ||
       (( BASH_REMATCH[1] > 255 || BASH_REMATCH[2] > 255 || BASH_REMATCH[3] > 255 || BASH_REMATCH[4] > 255 )); then
        echo "Invalid IPv4 address: $ip" >&2
        return 1
    fi
}

validate_port() {
    local p=$1
    if ! [[ $p =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
        echo "Invalid port: $p" >&2
        return 1
    fi
}

# Auto-detect SSH client IP (sudo strips $SSH_CLIENT, so try multiple methods)
SSH_IP=""
if [[ -n ${SSH_CLIENT:-} ]]; then
    SSH_IP=$(awk '{print $1}' <<< "$SSH_CLIENT")
elif [[ -n ${SUDO_USER:-} ]]; then
    SSH_IP=$(who | grep "$SUDO_USER" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi
if [[ -z $SSH_IP ]]; then
    SSH_IP=$(ss -tn state established '( dport = :22 or sport = :22 )' 2>/dev/null \
        | awk 'NR>1 {print $4}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi
[[ -n $SSH_IP ]] && echo "SSH client IP detected: $SSH_IP (auto-excluded both directions)"

# Validate IPs
for ip in "${IP_INCLUDE[@]}" "${IP_EXCLUDE[@]}"; do
    validate_ipv4 "$ip"
done

# Interactive prompt for extra IPs to exclude
read -rp "Enter additional IP(s) to exclude (comma/space separated, or blank to skip): " extra_ips
if [[ -n $extra_ips ]]; then
    for ip in ${extra_ips//,/ }; do
        validate_ipv4 "$ip"
        IP_EXCLUDE+=("$ip")
    done
fi

# Build port sets (deduplicated)
declare -A inc_ports exc_ports
for p in "${PORT_INCLUDE[@]}"; do
    validate_port "$p"
    inc_ports[$((10#$p))]=1
done
for p in "${PORT_EXCLUDE[@]}"; do
    validate_port "$p"
    exc_ports[$((10#$p))]=1
done

# Final port list: included minus excluded
# If only --port-exclude given with no --port-include, filter is "not these ports"
final_ports=()
if [[ ${#PORT_INCLUDE[@]} -gt 0 ]]; then
    for p in "${!inc_ports[@]}"; do
        [[ -z ${exc_ports[$p]:-} ]] && final_ports+=("$p")
    done
    if [[ ${#final_ports[@]} -eq 0 ]]; then
        echo "Error: all included ports were excluded — nothing to monitor." >&2
        exit 1
    fi
fi

# Build BPF filter
# Port filter
port_filter=""
if [[ ${#final_ports[@]} -gt 0 ]]; then
    port_expr=$(printf 'port %s or ' "${final_ports[@]}")
    port_filter="(${port_expr% or })"
elif [[ ${#PORT_EXCLUDE[@]} -gt 0 ]]; then
    exc_expr=$(printf 'port %s or ' "${!exc_ports[@]}")
    port_filter="not (${exc_expr% or })"
fi

# IP filter
ip_filter=""

# --ip-include: only from these
if [[ ${#IP_INCLUDE[@]} -gt 0 ]]; then
    declare -A seen_inc
    inc_parts=()
    for ip in "${IP_INCLUDE[@]}"; do
        [[ -n ${seen_inc[$ip]:-} ]] && continue
        seen_inc[$ip]=1
        inc_parts+=("src host $ip")
    done
    inc_joined=$(printf '%s or ' "${inc_parts[@]}")
    ip_filter+=" and (${inc_joined% or })"
fi

# SSH IP: exclude BOTH directions (not host = not src and not dst)
if [[ -n $SSH_IP ]]; then
    ip_filter+=" and not host $SSH_IP"
fi

# --ip-exclude + interactive: exclude src only (you want to see traffic TO these)
declare -A seen_exc
for ip in "${IP_EXCLUDE[@]}"; do
    [[ -n ${seen_exc[$ip]:-} ]] && continue
    seen_exc[$ip]=1
    ip_filter+=" and not src host $ip"
done

filter="${port_filter}${ip_filter}"

LOG="port_monitor_$(date +%Y%m%d).log"

echo ""
echo "=== Monitor Config ==="
if [[ ${#final_ports[@]} -gt 0 ]]; then
    echo "Ports (include): ${final_ports[*]}"
    [[ ${#exc_ports[@]} -gt 0 ]] && echo "Ports (excluded): ${!exc_ports[*]}"
else
    echo "Ports (exclude only): ${!exc_ports[*]}"
fi
[[ -n $SSH_IP ]] && echo "SSH client (auto-excluded): $SSH_IP"
[[ ${#IP_INCLUDE[@]} -gt 0 ]] && echo "IPs (include only): ${IP_INCLUDE[*]}"
[[ ${#IP_EXCLUDE[@]} -gt 0 ]] && echo "IPs (excluded): ${IP_EXCLUDE[*]}"
echo "Log: $LOG"
echo "Filter: $filter"
echo "================================================================"

opts=(-i any -nn -l -tttt)
[[ $HEXDUMP -eq 1 ]] && opts+=(-X)

tcpdump "${opts[@]}" "$filter" \
    | sed -u -E 's/, win [0-9]+//; s/, options \[[^]]*\]//' \
    | tee -a "$LOG"

