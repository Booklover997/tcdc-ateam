#!/usr/bin/env bash
# packages.sh — Reinstall core packages, deploy compiled coreutils to /binaries,
#                and prepend /binaries/bin to PATH system-wide.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARIES_DIR="/binaries"
BASHRC_DEFAULT="/etc/bash.bashrc"
COREUTILS_TAR="$SCRIPT_DIR/binaries/coreutils-26.04-amd64.tar.gz"

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
DIM='\033[0;37m'
RST='\033[0m'

echo -e "${BLU}========================================${RST}"
echo -e "${BLU}  Package & Coreutils Installer${RST}"
echo -e "${BLU}  $(date)${RST}"
echo -e "${BLU}========================================${RST}"

# --- Step 1: Install required packages ---
echo ""
echo -e "${YLW}[1/5] Installing required packages...${RST}"
apt-get update -qq

PACKAGES=(
    # Logging
    rsyslog auditd audispd-plugins
    # Netfilter / firewall
    libnetfilter-queue-dev nftables iptables-persistent
    ufw fail2ban
    # Network analysis
    tcpdump nmap netcat-openbsd
    net-tools iproute2 dnsutils whois traceroute mtr-tiny
    # Monitoring
    iftop nethogs iotop-c htop nload
    lsof strace ltrace sysstat
    # Hardening
    apparmor apparmor-utils apparmor-profiles
    rkhunter chkrootkit clamav clamav-daemon
    libpam-pwquality libpam-google-authenticator
    lynis aide
    # Build tools
    build-essential python3 python3-pip python3-venv python3-dev
    # Utilities
    curl wget git tmux screen
    jq tree unzip zip gzip bzip2 xz-utils
    openssl ca-certificates gnupg
    acl attr logrotate
    psmisc procps coreutils findutils
    cryptsetup
)

apt-get install -y "${PACKAGES[@]}" 2>&1 | while IFS= read -r line; do
    echo -e "  ${DIM}$line${RST}"
done
echo -e "${GRN}  Done.${RST}"

echo ""
echo -e "${YLW}  Verifying...${RST}"
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo -e "  ${GRN}✓${RST} $pkg"
    else
        echo -e "  ${RED}✗${RST} $pkg (failed to install)"
    fi
done
echo -e "${GRN}  Done.${RST}"

# --- Step 2: Reinstall all currently installed packages ---
echo ""
echo -e "${YLW}[2/5] Reinstalling all installed packages...${RST}"
dpkg --get-selections | awk '$2 == "install" {print $1}' \
    | xargs apt-get install --reinstall -y -qq 2>&1 | tail -5
echo -e "${GRN}  Done.${RST}"

# --- Step 3: Reinstall coreutils from apt ---
echo ""
echo -e "${YLW}[3/5] Reinstalling coreutils from apt...${RST}"
apt-get install --reinstall -y coreutils
echo -e "${GRN}  Done.${RST}"

# --- Step 4: Extract compiled coreutils to /binaries ---
echo ""
echo -e "${YLW}[4/5] Deploying compiled coreutils to ${BINARIES_DIR}...${RST}"

if [ ! -f "$COREUTILS_TAR" ]; then
    echo -e "${RED}  Error: $COREUTILS_TAR not found${RST}"
    echo "  Build it first: see README or compile coreutils 9.6 with --prefix"
    exit 1
fi

mkdir -p "$BINARIES_DIR"
tar xzf "$COREUTILS_TAR" -C "$BINARIES_DIR"
echo -e "  Extracted to ${BINARIES_DIR}/"
echo -e "  Binaries: $(ls "$BINARIES_DIR/bin/" | wc -l) commands"
echo -e "${GRN}  Done.${RST}"

# --- Step 5: Add /binaries/bin to system-wide PATH ---
echo ""
echo -e "${YLW}[5/5] Adding ${BINARIES_DIR}/bin to system-wide PATH...${RST}"

PATH_LINE='export PATH="/binaries/bin:$PATH"'
MARKER="# tcdc-ateam: compiled coreutils"

if grep -qF "$MARKER" "$BASHRC_DEFAULT" 2>/dev/null; then
    echo -e "  ${GRN}Already present in ${BASHRC_DEFAULT}, skipping.${RST}"
else
    cat >> "$BASHRC_DEFAULT" <<EOF

${MARKER}
${PATH_LINE}
EOF
    echo -e "  ${GRN}Added to ${BASHRC_DEFAULT}${RST}"
fi

echo ""
echo -e "${BLU}========================================${RST}"
echo -e "${GRN}  Complete.${RST}"
echo -e "  Compiled coreutils: ${BINARIES_DIR}/bin/"
echo -e "  PATH updated in:    ${BASHRC_DEFAULT}"
echo -e "  New shells will use ${BINARIES_DIR}/bin/ first."
echo -e "  To use now:  ${YLW}source ${BASHRC_DEFAULT}${RST}"
echo -e "${BLU}========================================${RST}"

