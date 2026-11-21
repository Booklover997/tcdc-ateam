#!/usr/bin/env bash
# packages.sh — Install core security/admin packages, deploy compiled coreutils
#                to /binaries, and prepend /binaries/bin to PATH system-wide.

set -uo pipefail

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
RST='\033[0m'

echo -e "${BLU}========================================${RST}"
echo -e "${BLU}  Package & Coreutils Installer${RST}"
echo -e "${BLU}  $(date)${RST}"
echo -e "${BLU}========================================${RST}"

# --- Step 1: Install required packages ---
echo ""
echo -e "${YLW}[1/3] Installing required packages...${RST}"
apt-get update -qq

PACKAGES=(
    # Firewall / intrusion prevention
    nftables ufw fail2ban
    # Network analysis
    tcpdump nmap net-tools iproute2
    # Monitoring
    htop lsof strace
    # Hardening / auditing
    auditd apparmor apparmor-utils
    rkhunter lynis
    # Build tools
    build-essential
    # Utilities
    curl git tmux jq unzip
)

echo -e "  Installing ${#PACKAGES[@]} packages individually..."
for pkg in "${PACKAGES[@]}"; do
    if ! apt-get install -y "$pkg" &>/dev/null; then
        echo -e "  ${RED}✗${RST} $pkg (apt-get failed)"
    fi
done

echo ""
echo -e "${YLW}  Verifying installs...${RST}"
FAILED=0
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo -e "  ${GRN}✓${RST} $pkg"
    else
        echo -e "  ${RED}✗${RST} $pkg (FAILED)"
        FAILED=$((FAILED + 1))
    fi
done
if [ $FAILED -gt 0 ]; then
    echo -e "  ${RED}$FAILED package(s) failed to install${RST}"
else
    echo -e "${GRN}  All packages installed.${RST}"
fi

# --- Step 2: Extract compiled coreutils to /binaries ---
echo ""
echo -e "${YLW}[2/3] Deploying compiled coreutils to ${BINARIES_DIR}...${RST}"

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

# --- Step 3: Add /binaries/bin to system-wide PATH ---
echo ""
echo -e "${YLW}[3/3] Adding ${BINARIES_DIR}/bin to system-wide PATH...${RST}"

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

# Also add to the current user's ~/.bashrc
CALLER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
CALLER_BASHRC="$CALLER_HOME/.bashrc"

if grep -qF "$MARKER" "$CALLER_BASHRC" 2>/dev/null; then
    echo -e "  ${GRN}Already present in ${CALLER_BASHRC}, skipping.${RST}"
else
    cat >> "$CALLER_BASHRC" <<EOF

${MARKER}
${PATH_LINE}
EOF
    echo -e "  ${GRN}Added to ${CALLER_BASHRC}${RST}"
fi

echo ""
echo -e "${BLU}========================================${RST}"
echo -e "${GRN}  Complete.${RST}"
echo -e "  Compiled coreutils: ${BINARIES_DIR}/bin/"
echo -e "  PATH updated in:    ${BASHRC_DEFAULT} + ${CALLER_BASHRC}"
echo -e "  New shells will use ${BINARIES_DIR}/bin/ first."
echo -e "  To use now:  ${YLW}source ${CALLER_BASHRC}${RST}"
echo -e "${BLU}========================================${RST}"

