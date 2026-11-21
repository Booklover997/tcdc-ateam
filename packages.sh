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

# --- Step 3: PAM integrity audit ---
echo ""
echo -e "${YLW}[3/7] Auditing PAM files for backdoors and tampering...${RST}"

PAM_KNOWN_GOOD="$SCRIPT_DIR/pam-sha256.txt"
PAM_DIR="/etc/pam.d"
PAM_ISSUES=0

# 3a: Check for dangerous PAM patterns
echo -e "  ${YLW}Scanning for backdoor patterns...${RST}"
PAM_CRITICAL_FILES=(
    "$PAM_DIR/common-auth"
    "$PAM_DIR/common-account"
    "$PAM_DIR/common-password"
    "$PAM_DIR/common-session"
    "$PAM_DIR/sshd"
    "$PAM_DIR/sudo"
    "$PAM_DIR/su"
    "$PAM_DIR/login"
)

for f in "${PAM_CRITICAL_FILES[@]}"; do
    [ -f "$f" ] || continue
    n=0
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [ -z "$line" ] && continue

        # auth sufficient pam_permit.so — lets anyone in with any password
        if echo "$line" | grep -qE '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so'; then
            echo -e "  ${RED}BACKDOOR${RST} $f:$n  $line"
            PAM_ISSUES=$((PAM_ISSUES + 1))
        fi

        # pam_exec.so or pam_python.so — runs arbitrary commands during auth
        if echo "$line" | grep -qE 'pam_exec\.so|pam_python\.so'; then
            echo -e "  ${RED}BACKDOOR${RST} $f:$n  $line"
            PAM_ISSUES=$((PAM_ISSUES + 1))
        fi

        # pam_rootok.so in sudo/su with sufficient — bypasses password for any uid 0
        if echo "$line" | grep -qE 'sufficient[[:space:]]+pam_rootok\.so'; then
            if [[ "$f" != */su ]]; then
                echo -e "  ${RED}SUSPECT${RST} $f:$n  $line"
                PAM_ISSUES=$((PAM_ISSUES + 1))
            fi
        fi

        # Modules loaded from writable paths
        if echo "$line" | grep -qE '/tmp/|/dev/shm/|/var/tmp/|/home/|/root/'; then
            echo -e "  ${RED}BACKDOOR${RST} $f:$n  $line"
            PAM_ISSUES=$((PAM_ISSUES + 1))
        fi

        # Unknown .so not owned by any package
        mod=$(echo "$line" | grep -oE '[^ ]+\.so' | head -1)
        if [ -n "$mod" ]; then
            if ! dpkg -S "$mod" &>/dev/null && ! dpkg -S "$(basename "$mod")" &>/dev/null; then
                echo -e "  ${RED}UNKNOWN MODULE${RST} $f:$n  $mod"
                PAM_ISSUES=$((PAM_ISSUES + 1))
            fi
        fi
    done < "$f"
done

# 3b: Check /etc/ld.so.preload
if [ -s /etc/ld.so.preload ]; then
    echo -e "  ${RED}SUSPECT${RST} /etc/ld.so.preload is non-empty:"
    echo -e "  $(cat /etc/ld.so.preload)"
    PAM_ISSUES=$((PAM_ISSUES + 1))
fi

# 3c: Verify PAM file hashes against known-good baseline
if [ -f "$PAM_KNOWN_GOOD" ]; then
    echo ""
    echo -e "  ${YLW}Verifying PAM hashes against known-good baseline...${RST}"
    while IFS='  ' read -r expected_hash pam_file; do
        [ -z "$expected_hash" ] && continue
        [[ "$expected_hash" =~ ^# ]] && continue
        if [ ! -f "$pam_file" ]; then
            echo -e "  ${RED}MISSING${RST} $pam_file"
            PAM_ISSUES=$((PAM_ISSUES + 1))
            continue
        fi
        actual_hash=$(sha256sum "$pam_file" | awk '{print $1}')
        if [ "$actual_hash" = "$expected_hash" ]; then
            echo -e "  ${GRN}✓${RST} $pam_file"
        else
            echo -e "  ${RED}MODIFIED${RST} $pam_file"
            echo -e "    expected: $expected_hash"
            echo -e "    actual:   $actual_hash"
            PAM_ISSUES=$((PAM_ISSUES + 1))
        fi
    done < "$PAM_KNOWN_GOOD"
else
    echo ""
    echo -e "  ${YLW}No known-good baseline found at ${PAM_KNOWN_GOOD}${RST}"
    echo -e "  Generating baseline from current state..."
    sha256sum "$PAM_DIR"/* 2>/dev/null > "$PAM_KNOWN_GOOD"
    echo -e "  ${GRN}Saved to ${PAM_KNOWN_GOOD}${RST}"
    echo -e "  ${YLW}REVIEW THIS FILE on a clean system before trusting it.${RST}"
fi

if [ $PAM_ISSUES -gt 0 ]; then
    echo ""
    echo -e "  ${RED}$PAM_ISSUES PAM issue(s) found — review above${RST}"
else
    echo -e "  ${GRN}PAM audit clean.${RST}"
fi

# --- Step 4: Install missing required packages ---
echo ""
echo -e "${YLW}[4/7] Checking required packages...${RST}"
apt-get update -qq

PACKAGES=(
    # Logging (required by igris.py firewall)
    rsyslog
    # Firewall / intrusion prevention
    nftables ufw fail2ban
    # Network analysis
    tcpdump net-tools iproute2
    # Monitoring
    htop lsof strace
    # Hardening / auditing
    auditd apparmor
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
echo -e "${YLW}[5/7] Deploying compiled coreutils to ${BINARIES_DIR}...${RST}"

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
echo -e "${YLW}[6/7] Adding ${BINARIES_DIR}/bin to PATH...${RST}"

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

# --- Step 7: Re-verify PAM after all changes ---
echo ""
echo -e "${YLW}[7/7] Final PAM re-check...${RST}"
FINAL_PAM_OK=1
if [ -f "$PAM_KNOWN_GOOD" ]; then
    while IFS='  ' read -r expected_hash pam_file; do
        [ -z "$expected_hash" ] && continue
        [[ "$expected_hash" =~ ^# ]] && continue
        [ -f "$pam_file" ] || continue
        actual_hash=$(sha256sum "$pam_file" | awk '{print $1}')
        if [ "$actual_hash" != "$expected_hash" ]; then
            echo -e "  ${RED}✗${RST} $pam_file still modified"
            FINAL_PAM_OK=0
        fi
    done < "$PAM_KNOWN_GOOD"
fi
if [ $FINAL_PAM_OK -eq 1 ]; then
    echo -e "  ${GRN}PAM files match known-good baseline.${RST}"
else
    echo -e "  ${RED}PAM files do not match — investigate before going live.${RST}"
fi

echo ""
echo -e "${BLU}========================================${RST}"
echo -e "${GRN}  Complete.${RST}"
echo -e "  Compiled coreutils: ${BINARIES_DIR}/bin/"
echo -e "  PATH updated in:    ${BASHRC_DEFAULT} + ${CALLER_BASHRC}"
echo -e "  New shells will use ${BINARIES_DIR}/bin/ first."
echo -e "  To use now:  ${YLW}source ${CALLER_BASHRC}${RST}"
echo -e "${BLU}========================================${RST}"

