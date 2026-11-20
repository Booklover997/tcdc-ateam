#!/bin/bash
# init_firewall.sh — Interactive setup: configure UFW, launch igris.py in background

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IGRIS="$SCRIPT_DIR/firewall/igris.py"

IGRIS_LOG="/var/log/igris.log"
IGRIS_PID="/var/run/igris.pid"

DEFAULT_PORTS="22,2222"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)"
    exit 1
fi

if [ ! -f "$IGRIS" ]; then
    echo "Error: igris.py not found at $IGRIS"
    exit 1
fi

# --- Pass-through commands (work while igris is running) ---
case "${1:-}" in
    --remove-whitelist)
        python3 "$IGRIS" --remove-whitelist
        # Signal running igris.py to reload its in-memory whitelist
        if [ -f "$IGRIS_PID" ] && kill -0 "$(cat "$IGRIS_PID")" 2>/dev/null; then
            kill -HUP "$(cat "$IGRIS_PID")"
            echo "[+] Sent reload signal to igris.py (PID $(cat "$IGRIS_PID"))"
        fi
        exit 0
        ;;
    --add-whitelist|--whitelist-packages)
        python3 "$IGRIS" --add-whitelist --whitelist-packages
        # Signal running igris.py to reload its in-memory whitelist
        if [ -f "$IGRIS_PID" ] && kill -0 "$(cat "$IGRIS_PID")" 2>/dev/null; then
            kill -HUP "$(cat "$IGRIS_PID")"
            echo "[+] Sent reload signal to igris.py (PID $(cat "$IGRIS_PID"))"
        fi
        exit 0
        ;;
    --teardown)
        python3 "$IGRIS" --teardown
        if [ -f "$IGRIS_PID" ]; then
            kill "$(cat "$IGRIS_PID")" 2>/dev/null || true
            rm -f "$IGRIS_PID"
        fi
        exit 0
        ;;
    --status)
        if [ -f "$IGRIS_PID" ] && kill -0 "$(cat "$IGRIS_PID")" 2>/dev/null; then
            echo "[+] igris.py running (PID $(cat "$IGRIS_PID"))"
        else
            echo "[-] igris.py not running"
        fi
        sudo ufw status | grep -E "igris_|DENY OUT|ALLOW OUT"
        exit 0
        ;;
esac

# Check if already running
if [ -f "$IGRIS_PID" ] && kill -0 "$(cat "$IGRIS_PID")" 2>/dev/null; then
    echo "[!] igris.py already running (PID $(cat "$IGRIS_PID"))"
    echo "    To stop: kill $(cat "$IGRIS_PID")"
    echo "    Log: $IGRIS_LOG"
    echo ""
    echo "    Whitelist toggle:"
    echo "      $0 --whitelist-packages    (add package repo whitelist)"
    echo "      $0 --remove-whitelist      (remove whitelist)"
    echo "      $0 --teardown              (stop + remove all rules)"
    echo "      $0 --status                (show status)"
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
ufw allow out to 10.112.10.53 port 53 comment "igris_dns"
echo "    ufw allow out to 10.112.10.53 port 53 (DNS)"
ufw allow out to 10.112.20.88 port 53 comment "igris_dns"
echo "    ufw allow out to 10.112.20.88 port 53 (AD DNS)"
ufw reload
echo "[+] UFW enabled: deny inbound (except allowed ports), allow outbound, logging high."

# --- Ensure rsyslog is running ---
if ! pgrep -x rsyslogd > /dev/null 2>&1; then
    echo "[*] Starting rsyslog..."
    apt-get install -y -qq rsyslog 2>/dev/null || true
    rsyslogd 2>/dev/null || true
    sleep 1
fi

# --- IP Whitelist ---
echo ""
read -rp "Whitelist Ubuntu package repo IPs? (for apt) [Y/n]: " WL_PKG
read -rp "Additional whitelist IPs (comma-separated, blank for none): " WL_EXTRA

WL_FLAGS=""
if [[ ! "$WL_PKG" =~ ^[Nn]$ ]]; then
    WL_FLAGS="--whitelist-packages"
fi
if [ -n "$WL_EXTRA" ]; then
    WL_FLAGS="$WL_FLAGS --whitelist-ips $WL_EXTRA"
fi

# --- Launch igris.py ---
echo ""
echo "[*] Starting igris.py (UFW log watcher — reactive blocking)"
echo "    Allowed ports: $PORTS"
echo "    Log: $IGRIS_LOG"
if [ -n "$WL_FLAGS" ]; then
    echo "    Whitelist: $WL_FLAGS"
fi
echo ""

# shellcheck disable=SC2086
nohup python3 "$IGRIS" --ports "$PORTS" --log "$IGRIS_LOG" $WL_FLAGS > /dev/null 2>&1 &
PID=$!
echo "$PID" > "$IGRIS_PID"

sleep 2

if kill -0 "$PID" 2>/dev/null; then
    echo "[+] igris.py running in background (PID $PID)"
    echo "    Log:  tail -f $IGRIS_LOG"
    echo "    Stop: kill $PID"
    echo ""
    echo "Whitelist toggle:"
    echo "  Remove whitelist: sudo python3 $IGRIS --remove-whitelist"
    echo "  Remove all rules: sudo python3 $IGRIS --teardown"
else
    echo "[!] igris.py failed to start. Check $IGRIS_LOG"
    rm -f "$IGRIS_PID"
    exit 1
fi

