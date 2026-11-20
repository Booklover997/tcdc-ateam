#!/bin/bash
# init_firewall.sh — Interactive setup: configure UFW, launch ufw_guard.py in background

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UFW_GUARD="$SCRIPT_DIR/firewall/ufw_guard.py"

UFW_GUARD_LOG="/var/log/ufw_guard.log"
UFW_GUARD_PID="/var/run/ufw_guard.pid"

DEFAULT_PORTS="22,2222"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)"
    exit 1
fi

if [ ! -f "$UFW_GUARD" ]; then
    echo "Error: ufw_guard.py not found at $UFW_GUARD"
    exit 1
fi

# Check if already running
if [ -f "$UFW_GUARD_PID" ] && kill -0 "$(cat "$UFW_GUARD_PID")" 2>/dev/null; then
    echo "[!] ufw_guard.py already running (PID $(cat "$UFW_GUARD_PID"))"
    echo "    To stop: kill $(cat "$UFW_GUARD_PID")"
    echo "    Log: $UFW_GUARD_LOG"
    exit 1
fi

echo "========================================"
echo "  Firewall Init"
echo "========================================"
echo ""
echo "Default allowed ports: $DEFAULT_PORTS"
echo ""
echo "Enter additional allowed source ports (comma-separated)."
echo "These are the LOCAL ports your services listen on."
echo "Example: 80,443,53"
echo "(Leave blank to use only the defaults)"
echo ""
read -rp "Additional ports: " EXTRA_PORTS

if [ -n "$EXTRA_PORTS" ]; then
    if ! echo "$EXTRA_PORTS" | grep -qP '^[\d,\s\-]+$'; then
        echo "Error: invalid format. Use comma-separated numbers or ranges (e.g. 80,443,1000-2000)"
        exit 1
    fi
    PORTS="$DEFAULT_PORTS,$EXTRA_PORTS"
else
    PORTS="$DEFAULT_PORTS"
fi

# --- UFW setup: default deny inbound, allow outbound ---
echo ""
echo "[*] Configuring UFW (default deny inbound)..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw logging high
IFS=',' read -ra PORT_LIST <<< "$PORTS"
for p in "${PORT_LIST[@]}"; do
    p="$(echo "$p" | xargs)"
    if [ -n "$p" ]; then
        ufw allow in "$p"
        echo "    ufw allow in $p"
    fi
done
ufw reload
echo "[+] UFW enabled: deny inbound (except allowed ports), allow outbound, logging high."

# --- Ensure rsyslog is running (needed for ufw_guard) ---
if ! pgrep -x rsyslogd > /dev/null 2>&1; then
    echo "[*] Starting rsyslog..."
    apt-get install -y -qq rsyslog 2>/dev/null || true
    rsyslogd 2>/dev/null || true
    sleep 1
fi

# --- Launch ufw_guard.py (watches UFW logs, adds ufw deny rules) ---
echo ""
echo "[*] Starting ufw_guard.py (UFW log watcher — reactive blocking)"
echo "    Allowed ports: $PORTS"
echo "    Log: $UFW_GUARD_LOG"
echo ""

nohup python3 "$UFW_GUARD" --ports "$PORTS" --log "$UFW_GUARD_LOG" > "$UFW_GUARD_LOG" 2>&1 &
PID=$!
echo "$PID" > "$UFW_GUARD_PID"

sleep 1

if kill -0 "$PID" 2>/dev/null; then
    echo "[+] ufw_guard.py running in background (PID $PID)"
    echo "    Log:  tail -f $UFW_GUARD_LOG"
    echo "    Stop: kill $PID"
else
    echo "[!] ufw_guard.py failed to start. Check $UFW_GUARD_LOG"
    rm -f "$UFW_GUARD_PID"
    exit 1
fi

