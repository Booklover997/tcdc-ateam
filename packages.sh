#!/usr/bin/env bash
# packages.sh — Verify and install core security/admin packages, deploy compiled
#                coreutils to /binaries, and prepend /binaries/bin to PATH.

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
echo -e "${BLU}  Package Verify & Coreutils Installer${RST}"
echo -e "${BLU}  $(date)${RST}"
echo -e "${BLU}========================================${RST}"

# --- Step 1: Ensure debsums is available ---
echo ""
echo -e "${YLW}[1/5] Ensuring debsums is available...${RST}"
if ! command -v debsums &>/dev/null; then
    apt-get update -qq
    apt-get install -y debsums
fi
echo -e "${GRN}  debsums ready.${RST}"

# --- Step 2: Verify integrity of all installed packages ---
echo ""
echo -e "${YLW}[2/5] Verifying installed package integrity against known checksums...${RST}"
echo -e "  (this checks every file from every installed package)"

TAMPERED_PKGS=()
TAMPERED_LOG="/var/log/tcdc-tampered-$(date +%Y%m%d-%H%M%S).log"

debsums -c 2>/dev/null | tee "$TAMPERED_LOG" || true

if [ -s "$TAMPERED_LOG" ]; then
    # Extract unique package names from modified file paths
    while IFS= read -r file; do
        pkg=$(dpkg -S "$file" 2>/dev/null | cut -d: -f1)
        if [ -n "$pkg" ]; then
            TAMPERED_PKGS+=("$pkg")
        fi
    done < "$TAMPERED_LOG"

    # Deduplicate
    mapfile -t TAMPERED_PKGS < <(printf '%s\n' "${TAMPERED_PKGS[@]}" | sort -u)

    echo ""
    echo -e "  ${RED}Found ${#TAMPERED_PKGS[@]} package(s) with modified files:${RST}"
    for pkg in "${TAMPERED_PKGS[@]}"; do
        echo -e "  ${RED}✗${RST} $pkg"
    done
    echo -e "  Full log: ${TAMPERED_LOG}"

    echo ""
    echo -e "  ${YLW}Reinstalling tampered packages from repository...${RST}"
    for pkg in "${TAMPERED_PKGS[@]}"; do
        if apt-get install --reinstall -y "$pkg" &>/dev/null; then
            echo -e "  ${GRN}✓${RST} $pkg (reinstalled)"
        else
            echo -e "  ${RED}✗${RST} $pkg (reinstall failed)"
        fi
    done
else
    echo -e "  ${GRN}All installed packages pass integrity check.${RST}"
    rm -f "$TAMPERED_LOG"
fi

# --- Step 3: Install missing required packages ---
echo ""
echo -e "${YLW}[3/5] Checking required packages...${RST}"
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

MISSING=()
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo -e "  ${GRN}✓${RST} $pkg"
    else
        echo -e "  ${YLW}○${RST} $pkg (missing)"
        MISSING+=("$pkg")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo -e "  Installing ${#MISSING[@]} missing package(s)..."
    for pkg in "${MISSING[@]}"; do
        if apt-get install -y "$pkg" &>/dev/null; then
            echo -e "  ${GRN}✓${RST} $pkg (installed)"
        else
            echo -e "  ${RED}✗${RST} $pkg (failed)"
        fi
    done
else
    echo -e "${GRN}  All ${#PACKAGES[@]} packages present.${RST}"
fi

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

# --- Step 5: Add /binaries/bin to PATH ---
echo ""
echo -e "${YLW}[5/5] Adding ${BINARIES_DIR}/bin to PATH...${RST}"

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

