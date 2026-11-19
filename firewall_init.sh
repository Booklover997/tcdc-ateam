#!/bin/bash
# init_firewall.sh — Interactive setup: ask for allowed source ports, then launch igris.py in background

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IGRIS="$SCRIPT_DIR/firewall/igris.py"
LOG="/var/log/igris.log"
PIDFILE="/var/run/igris.pid"

DEFAULT_PORTS="22,2222"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)"
    exit 1
fi

if [ ! -f "$IGRIS" ]; then
    echo "Error: igris.py not found at $IGRIS"
    exit 1
fi

# Check if already running
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[!] igris.py is already running (PID $(cat "$PIDFILE"))"
    echo "    To stop: kill $(cat "$PIDFILE")"
    echo "    Log: $LOG"
    exit 1
fi

echo "========================================"
echo "  Igris Firewall Init"
echo "========================================"
echo ""
echo "Default allowed ports: $DEFAULT_PORTS"
echo ""
echo "Enter additional allowed source ports (comma-separated)."
echo "These are the LOCAL ports your services listen on."
echo "Example: 22,80,443,53"
echo "(Leave blank to use only the defaults)"
echo ""
read -rp "Additional ports: " EXTRA_PORTS

if [ -n "$EXTRA_PORTS" ]; then
    if ! echo "$EXTRA_PORTS" | grep -qP '^[\d,\s\-]+$'; then
        echo "Error: invalid format. Use comma-separated numbers or ranges (e.g. 22,80,443,1000-2000)"
        exit 1
    fi
    PORTS="$DEFAULT_PORTS,$EXTRA_PORTS"
else
    PORTS="$DEFAULT_PORTS"
fi

echo ""
echo "[*] Configuring UFW (default deny inbound)..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
IFS=',' read -ra PORT_LIST <<< "$PORTS"
for p in "${PORT_LIST[@]}"; do
    p="$(echo "$p" | xargs)"
    if [ -n "$p" ]; then
        ufw allow in "$p"
        echo "    ufw allow in $p"
    fi
done
ufw reload
echo "[+] UFW enabled: deny inbound (except allowed ports), allow outbound."

# Install NetfilterQueue if missing
if ! python3 -c "import netfilterqueue" 2>/dev/null; then
    echo "[*] Installing NetfilterQueue for nfqueue mode..."
    apt-get install -y -qq libnetfilter-queue-dev python3-pip 2>/dev/null
    pip3 install NetfilterQueue 2>/dev/null || pip3 install --break-system-packages NetfilterQueue 2>/dev/null
fi

echo ""
echo "[*] Launching igris.py in background (nfqueue mode)"
echo "    Allowed ports: $PORTS"
echo "    Log: $LOG"
echo ""

nohup python3 "$IGRIS" --ports "$PORTS" --mode nfqueue --log "$LOG" > "$LOG" 2>&1 &
PID=$!
echo "$PID" > "$PIDFILE"

sleep 1
if kill -0 "$PID" 2>/dev/null; then
    echo "[+] igris.py running in background (PID $PID)"
    echo "    Log:  tail -f $LOG"
    echo "    Stop: kill $PID"
else
    echo "[!] igris.py failed to start. Check $LOG"
    rm -f "$PIDFILE"
    exit 1
fi

