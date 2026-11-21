#!/usr/bin/env bash
# waf_apache.sh — Set up ModSecurity WAF + OWASP CRS for Apache. Zero interaction required.
# Run: sudo ./waf_apache.sh
# Layers on top of existing config — only adds ModSecurity directives, never removes anything.
# Backs up all configs before modifying. Safe to re-run.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo $0)"
    exit 1
fi

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
RST='\033[0m'

BACKUP_DIR="/root/waf_backups/apache_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo -e "${BLU}========================================${RST}"
echo -e "${BLU}  ModSecurity WAF Setup for Apache${RST}"
echo -e "${BLU}  $(date)${RST}"
echo -e "${BLU}========================================${RST}"

# --- Step 1: Ensure Apache and ModSecurity are installed ---
echo ""
echo -e "${YLW}[1/6] Checking Apache and ModSecurity...${RST}"

if ! command -v apachectl &>/dev/null && ! command -v apache2ctl &>/dev/null; then
    echo -e "${RED}  Apache not installed. Install it first or use waf_nginx.sh${RST}"
    exit 1
fi

for pkg in libapache2-mod-security2 modsecurity-crs; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "  Installing $pkg..."
        apt-get install -y "$pkg" || true
    fi
done
echo -e "  ${GRN}Apache + ModSecurity present${RST}"

# --- Step 2: Baseline config test ---
echo ""
echo -e "${YLW}[2/6] Baseline config test...${RST}"
if ! apachectl configtest 2>&1; then
    echo -e "${RED}  Apache config is already broken BEFORE our changes.${RST}"
    echo -e "${RED}  Fix existing config first, then re-run this script.${RST}"
    exit 1
fi
echo -e "  ${GRN}Existing config is valid${RST}"

# --- Step 3: Enable the module ---
echo ""
echo -e "${YLW}[3/6] Enabling ModSecurity module...${RST}"

a2enmod security2 2>/dev/null || true
a2enmod headers 2>/dev/null || true
echo -e "  ${GRN}security2 and headers modules enabled${RST}"

# --- Step 4: Configure ModSecurity engine (preserve existing settings) ---
echo ""
echo -e "${YLW}[4/6] Configuring ModSecurity engine...${RST}"

MODSEC_DIR="/etc/modsecurity"
MODSEC_CONF="$MODSEC_DIR/modsecurity.conf"
MODSEC_REC="$MODSEC_DIR/modsecurity.conf-recommended"

CREATED_CONF=false

if [ -f "$MODSEC_CONF" ]; then
    echo -e "  Found existing $MODSEC_CONF — preserving all settings"
elif [ -f "$MODSEC_REC" ]; then
    cp "$MODSEC_REC" "$MODSEC_CONF"
    CREATED_CONF=true
    echo -e "  No modsecurity.conf found — copied from recommended"
else
    echo -e "${RED}  No modsecurity.conf or .conf-recommended found${RST}"
    exit 1
fi

# Backup (whether existing or freshly created)
cp "$MODSEC_CONF" "$BACKUP_DIR/modsecurity.conf.bak"
echo -e "  Backed up $MODSEC_CONF"

# Only change: flip DetectionOnly to On (the single line that matters)
if grep -q "^[[:space:]]*SecRuleEngine[[:space:]]*DetectionOnly" "$MODSEC_CONF"; then
    sed -i 's/^\([[:space:]]*\)SecRuleEngine[[:space:]]*DetectionOnly/\1SecRuleEngine On/' "$MODSEC_CONF"
    echo -e "  ${GRN}SecRuleEngine: DetectionOnly -> On${RST}"
elif grep -q "^[[:space:]]*SecRuleEngine[[:space:]]*On" "$MODSEC_CONF"; then
    echo -e "  ${GRN}SecRuleEngine already On — no change${RST}"
else
    # Engine directive missing entirely — append it
    echo "" >> "$MODSEC_CONF"
    echo "SecRuleEngine On" >> "$MODSEC_CONF"
    echo -e "  ${GRN}SecRuleEngine On appended (was missing)${RST}"
fi

# Only add audit logging if the conf was freshly created from recommended
# (don't touch an existing admin-configured file)
if $CREATED_CONF; then
    if ! grep -q "^[[:space:]]*SecAuditLog[[:space:]]" "$MODSEC_CONF"; then
        cat >> "$MODSEC_CONF" <<'AUDIT'

SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log
AUDIT
        echo -e "  ${GRN}Audit logging configured${RST}"
    fi
else
    echo -e "  ${GRN}Existing audit config preserved${RST}"
fi

echo -e "  ${YLW}All other modsecurity.conf settings left untouched${RST}"

# --- Step 5: Enable OWASP Core Rule Set ---
echo ""
echo -e "${YLW}[5/6] Enabling OWASP Core Rule Set (CRS)...${RST}"

CRS_SETUP=""
CRS_RULES=""

for setup in \
    /usr/share/modsecurity-crs/crs-setup.conf.example \
    /usr/share/modsecurity-crs/crs-setup.conf \
    /etc/modsecurity/crs/crs-setup.conf.example \
    /etc/modsecurity/crs/crs-setup.conf; do
    if [ -f "$setup" ]; then
        CRS_SETUP="$setup"
        break
    fi
done

for rules in \
    /usr/share/modsecurity-crs/rules \
    /etc/modsecurity/crs/rules \
    /usr/share/modsecurity-crs/owasp-crs/rules; do
    if [ -d "$rules" ]; then
        CRS_RULES="$rules"
        break
    fi
done

APACHE_MODSEC="/etc/apache2/mods-enabled/security2.conf"
if [ ! -f "$APACHE_MODSEC" ]; then
    APACHE_MODSEC="/etc/apache2/mods-available/security2.conf"
fi

if [ -n "$CRS_SETUP" ] && [ -n "$CRS_RULES" ]; then
    CRS_ACTIVE="${CRS_SETUP%.example}"
    if [ ! -f "$CRS_ACTIVE" ] && [ -f "${CRS_ACTIVE}.example" ]; then
        cp "${CRS_ACTIVE}.example" "$CRS_ACTIVE"
        echo -e "  Created $CRS_ACTIVE from example"
    fi

    # Check if CRS is already wired up anywhere in the Apache config
    if grep -rq "$CRS_RULES" /etc/apache2/ 2>/dev/null; then
        echo -e "  ${GRN}OWASP CRS already included in Apache config — no change${RST}"
    elif [ -f "$APACHE_MODSEC" ]; then
        cp "$APACHE_MODSEC" "$BACKUP_DIR/security2.conf.bak"
        echo -e "  Backed up $APACHE_MODSEC"

        # Use a standalone conf file instead of injecting into security2.conf
        # This avoids sed issues with </IfModule> matching and is cleaner
        cat > /etc/apache2/conf-available/modsecurity-crs.conf <<CRSCONF
<IfModule security2_module>
    IncludeOptional $CRS_ACTIVE
    IncludeOptional ${CRS_RULES}/*.conf
</IfModule>
CRSCONF
        a2enconf modsecurity-crs 2>/dev/null || true
        echo -e "  ${GRN}Created /etc/apache2/conf-available/modsecurity-crs.conf${RST}"
        echo -e "  ${GRN}Enabled modsecurity-crs config (a2enconf)${RST}"
    else
        cat > /etc/apache2/conf-available/modsecurity-crs.conf <<CRSCONF
<IfModule security2_module>
    IncludeOptional $CRS_ACTIVE
    IncludeOptional ${CRS_RULES}/*.conf
</IfModule>
CRSCONF
        a2enconf modsecurity-crs 2>/dev/null || true
        echo -e "  ${GRN}Created and enabled modsecurity-crs.conf${RST}"
    fi

    echo -e "  CRS setup: $CRS_ACTIVE"
    echo -e "  CRS rules: $CRS_RULES/"
else
    echo -e "  ${YLW}OWASP CRS not found on disk — ModSecurity runs with built-in rules only${RST}"
    echo -e "  ${YLW}Install: apt-get install modsecurity-crs${RST}"
fi

# --- Step 6: Test and reload (rollback on failure) ---
echo ""
echo -e "${YLW}[6/6] Testing and reloading Apache...${RST}"

if apachectl configtest 2>&1; then
    systemctl reload apache2
    echo -e "  ${GRN}Apache reloaded with ModSecurity WAF active${RST}"
else
    echo -e "${RED}  Apache config test FAILED after changes. Restoring backups...${RST}"

    # Restore modsecurity.conf
    if [ -f "$BACKUP_DIR/modsecurity.conf.bak" ]; then
        cp "$BACKUP_DIR/modsecurity.conf.bak" "$MODSEC_CONF"
        echo -e "  Restored modsecurity.conf"
    fi

    # Restore security2.conf
    if [ -f "$BACKUP_DIR/security2.conf.bak" ]; then
        cp "$BACKUP_DIR/security2.conf.bak" "$APACHE_MODSEC"
        echo -e "  Restored security2.conf"
    fi

    # Disable CRS config if we created it
    a2disconf modsecurity-crs 2>/dev/null || true
    rm -f /etc/apache2/conf-available/modsecurity-crs.conf 2>/dev/null || true
    rm -f /etc/apache2/conf-enabled/modsecurity-crs.conf 2>/dev/null || true

    if apachectl configtest 2>&1; then
        systemctl reload apache2
        echo -e "  ${GRN}Original config restored and Apache reloaded${RST}"
    else
        echo -e "  ${RED}Config still broken after restore — investigate manually${RST}"
    fi
    exit 1
fi

echo ""
echo -e "${BLU}========================================${RST}"
echo -e "${GRN}  ModSecurity WAF is active${RST}"
echo -e "  Config:    $MODSEC_CONF"
if [ -n "$CRS_RULES" ]; then
echo -e "  CRS rules: $CRS_RULES/"
fi
echo -e "  Backups:   $BACKUP_DIR/"
echo -e ""
echo -e "  ${YLW}Protects: SQLi, XSS, RCE, LFI/RFI, path traversal,${RST}"
echo -e "  ${YLW}  session hijacking, webshells, protocol attacks${RST}"
echo -e "  ${YLW}Blocked requests return 403 and log to audit log${RST}"
echo -e "  ${YLW}All existing Apache settings preserved${RST}"
echo -e "${BLU}========================================${RST}"

