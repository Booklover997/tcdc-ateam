#!/usr/bin/env bash
# port_monitor.sh - watch the given ports and show traffic NOT coming from your IP.
# Requires: tcpdump, root privileges.

usage() { echo "Usage: sudo $0 [-x]   (-x adds tcpdump -X hex/ASCII packet dump)"; }

HEXDUMP=0
while getopts "xh" opt; do
    case $opt in
        x) HEXDUMP=1 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (e.g. sudo $0) - tcpdump needs it to capture packets." >&2
    exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "tcpdump not found. Install it (e.g. apt install tcpdump)." >&2
    exit 1
fi

read -p "Enter extra ports to monitor (22 is always included) i.e. (80, 443, 25, 8080): " ports
read -p "Enter your IPv4 address: " ip

# Validate IPv4 (four octets, each 0-255)
if ! [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] ||
   (( BASH_REMATCH[1] > 255 || BASH_REMATCH[2] > 255 || BASH_REMATCH[3] > 255 || BASH_REMATCH[4] > 255 )); then
    echo "Invalid IPv4 address: $ip" >&2
    exit 1
fi

# Port 22 is always monitored; add any extras entered (commas and/or spaces)
ports=${ports//,/ }
declare -A seen=([22]=1)
filter_ports=("dst port 22")
all_ports=(22)
for p in $ports; do
    if ! [[ $p =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
        echo "Invalid port: $p" >&2
        exit 1
    fi
    p=$((10#$p))
    [[ -n ${seen[$p]} ]] && continue
    seen[$p]=1
    all_ports+=("$p")
    filter_ports+=("dst port $p")
done

# Join into: (dst port 22 or dst port 80 ...) and not src host <ip>
port_expr=$(printf '%s or ' "${filter_ports[@]}")
port_expr=${port_expr% or }
filter="($port_expr) and not src host $ip"

LOG="port_monitor_$(date +%Y%m%d).log"

echo "Monitoring inbound traffic to ports: ${all_ports[*]}"
echo "Ignoring source: $ip"
echo "Logging to: $LOG   (Ctrl+C to stop)"
echo "Filter: $filter"
echo "----------------------------------------------------------------"

# -nn no name/port resolution, -l line buffered, -tttt readable timestamps.
opts=(-i any -nn -l -tttt)
# With -x: add -X to dump each packet as hex + ASCII (no link-layer header)
[[ $HEXDUMP -eq 1 ]] && opts+=(-X)

# sed strips the ", win N" and ", options [...]" fields from each summary line
# (hex/ASCII dump lines from -X don't contain them, so they pass through untouched).
tcpdump "${opts[@]}" "$filter" \
    | sed -u -E 's/, win [0-9]+//; s/, options \[[^]]*\]//' \
    | tee -a "$LOG"
