#!/usr/bin/env bash
# waf_nginx.sh — Set up NAXSI WAF for nginx. Zero interaction required.
# Run: sudo ./waf_nginx.sh
# Layers on top of existing config — only adds NAXSI directives, never removes anything.
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

BACKUP_DIR="/root/waf_backups/nginx_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo -e "${BLU}========================================${RST}"
echo -e "${BLU}  NAXSI WAF Setup for nginx${RST}"
echo -e "${BLU}  $(date)${RST}"
echo -e "${BLU}========================================${RST}"

# --- Step 1: Ensure nginx and NAXSI are installed ---
echo ""
echo -e "${YLW}[1/7] Checking nginx and NAXSI...${RST}"

if ! command -v nginx &>/dev/null; then
    echo -e "${RED}  nginx not installed. Install it first or use waf_apache.sh${RST}"
    exit 1
fi

if ! dpkg -s libnginx-mod-http-naxsi &>/dev/null; then
    echo "  Installing libnginx-mod-http-naxsi..."
    apt-get install -y libnginx-mod-http-naxsi
fi
echo -e "  ${GRN}nginx + NAXSI present${RST}"

# --- Step 2: Baseline config test ---
echo ""
echo -e "${YLW}[2/7] Baseline config test...${RST}"
if ! nginx -t 2>&1; then
    echo -e "${RED}  nginx config is already broken BEFORE our changes.${RST}"
    echo -e "${RED}  Fix existing config first, then re-run this script.${RST}"
    exit 1
fi
echo -e "  ${GRN}Existing config is valid${RST}"

# --- Step 3: Locate naxsi_core.rules ---
echo ""
echo -e "${YLW}[3/7] Locating NAXSI core rules...${RST}"

CORE_RULES=""
for path in /usr/share/naxsi/naxsi_core.rules /etc/nginx/naxsi_core.rules /usr/local/etc/nginx/naxsi_core.rules; do
    if [ -f "$path" ]; then
        CORE_RULES="$path"
        break
    fi
done

if [ -z "$CORE_RULES" ]; then
    echo -e "  ${YLW}Not in common paths. Searching filesystem...${RST}"
    CORE_RULES=$(find / -name "naxsi_core.rules" -type f 2>/dev/null | head -1)
    if [ -z "$CORE_RULES" ]; then
        echo -e "${RED}  Cannot find naxsi_core.rules. NAXSI package may be broken.${RST}"
        exit 1
    fi
fi
echo -e "  ${GRN}Found: $CORE_RULES${RST}"

# --- Step 4: Create NAXSI threshold rules (preserve existing) ---
echo ""
echo -e "${YLW}[4/7] NAXSI threshold rules...${RST}"

NAXSI_RULES="/etc/nginx/naxsi.rules"
if [ -f "$NAXSI_RULES" ]; then
    cp "$NAXSI_RULES" "$BACKUP_DIR/naxsi.rules.bak"
    echo -e "  ${GRN}$NAXSI_RULES already exists — preserved (backed up)${RST}"
else
    cat > "$NAXSI_RULES" <<'NAXSI'
# NAXSI threshold rules — requests exceeding these scores are blocked
SecRulesEnabled;
DeniedUrl "/RequestDenied";

CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$UPLOAD >= 8" BLOCK;
NAXSI
    echo -e "  ${GRN}Created $NAXSI_RULES${RST}"
fi

# --- Step 5: Create the denied-request handler snippet (preserve existing) ---
echo ""
echo -e "${YLW}[5/7] NAXSI denied-request handler...${RST}"

mkdir -p /etc/nginx/snippets

DENIED_CONF="/etc/nginx/snippets/naxsi-denied.conf"
if [ -f "$DENIED_CONF" ]; then
    echo -e "  ${GRN}$DENIED_CONF already exists — preserved${RST}"
else
    cat > "$DENIED_CONF" <<'DENIED'
location /RequestDenied {
    internal;
    return 403 "Blocked by WAF";
}
DENIED
    echo -e "  ${GRN}Created $DENIED_CONF${RST}"
fi

# --- Step 6: Inject NAXSI into nginx config (additive only) ---
echo ""
echo -e "${YLW}[6/7] Injecting NAXSI into nginx configuration...${RST}"

NGINX_CONF="/etc/nginx/nginx.conf"

# Backup nginx.conf
cp "$NGINX_CONF" "$BACKUP_DIR/nginx.conf.bak"
echo -e "  Backed up $NGINX_CONF"

# Add core rules include to http block (if not already present)
if ! grep -q "naxsi_core.rules" "$NGINX_CONF"; then
    # Match "http {" with any leading whitespace
    if grep -qE '^[[:space:]]*http[[:space:]]*\{' "$NGINX_CONF"; then
        sed -i '/^[[:space:]]*http[[:space:]]*{/a\    # NAXSI core rules (scoring engine)\n    include '"$CORE_RULES"';' "$NGINX_CONF"
        echo -e "  ${GRN}Added naxsi_core.rules include to http block${RST}"
    else
        echo -e "  ${RED}Could not find 'http {' block in nginx.conf${RST}"
        echo -e "  ${YLW}Add manually: include $CORE_RULES; inside the http block${RST}"
    fi
else
    echo -e "  ${GRN}naxsi_core.rules already included — no change${RST}"
fi

# Process each enabled site
SITES_DIR="/etc/nginx/sites-enabled"
CONF_DIR="/etc/nginx/conf.d"
SITE_COUNT=0

inject_naxsi_into_site() {
    local conf_file="$1"
    local base
    base=$(basename "$conf_file")

    # Skip if already has naxsi rules (don't double-inject)
    if grep -q "naxsi.rules" "$conf_file"; then
        echo -e "  ${GRN}$base — already has NAXSI rules — no change${RST}"
        return
    fi

    # Backup the original
    cp "$conf_file" "$BACKUP_DIR/${base}.bak"
    echo -e "  Backed up $base"

    local changed=false

    # Add naxsi.rules include inside "location" blocks that serve content
    # Matches: location / {  or  location /something {  or  location ~ pattern {
    if grep -qE '^[[:space:]]*location[[:space:]]' "$conf_file"; then
        sed -i '/^[[:space:]]*location[[:space:]].*{/a\        include /etc/nginx/naxsi.rules;' "$conf_file"
        changed=true
    fi

    # Add the denied handler inside "server {" blocks
    if grep -qE '^[[:space:]]*server[[:space:]]*\{' "$conf_file"; then
        if ! grep -q "naxsi-denied" "$conf_file"; then
            sed -i '/^[[:space:]]*server[[:space:]]*{/a\    include /etc/nginx/snippets/naxsi-denied.conf;' "$conf_file"
            changed=true
        fi
    fi

    if $changed; then
        echo -e "  ${GRN}$base — NAXSI injected${RST}"
        SITE_COUNT=$((SITE_COUNT + 1))
    else
        echo -e "  ${YLW}$base — no location/server blocks found, skipped${RST}"
    fi
}

if [ -d "$SITES_DIR" ]; then
    for site in "$SITES_DIR"/*; do
        [ -f "$site" ] && inject_naxsi_into_site "$site"
    done
fi

if [ -d "$CONF_DIR" ]; then
    for conf in "$CONF_DIR"/*.conf; do
        [ -f "$conf" ] && inject_naxsi_into_site "$conf"
    done
fi

if [ "$SITE_COUNT" -eq 0 ]; then
    echo -e "  ${YLW}No sites modified (already have NAXSI or no location blocks)${RST}"
fi

# --- Step 7: Test and reload (rollback on failure) ---
echo ""
echo -e "${YLW}[7/7] Testing and reloading nginx...${RST}"

if nginx -t 2>&1; then
    systemctl reload nginx
    echo -e "  ${GRN}nginx reloaded with NAXSI WAF active${RST}"
else
    echo -e "${RED}  nginx config test FAILED after changes. Restoring ALL backups...${RST}"

    # Restore every backup we made
    for bak in "$BACKUP_DIR"/*.bak; do
        [ -f "$bak" ] || continue
        base=$(basename "$bak" .bak)
        if [ "$base" = "nginx.conf" ]; then
            cp "$bak" "$NGINX_CONF"
        elif [ "$base" = "naxsi.rules" ]; then
            cp "$bak" /etc/nginx/naxsi.rules
        elif [ -f "$SITES_DIR/$base" ]; then
            cp "$bak" "$SITES_DIR/$base"
        elif [ -f "$CONF_DIR/$base" ]; then
            cp "$bak" "$CONF_DIR/$base"
        fi
        echo -e "  Restored $base"
    done

    if nginx -t 2>&1; then
        systemctl reload nginx
        echo -e "  ${GRN}Original config restored and nginx reloaded${RST}"
    else
        echo -e "  ${RED}Config still broken after restore — was broken before our changes?${RST}"
    fi
    exit 1
fi

echo ""
echo -e "${BLU}========================================${RST}"
echo -e "${GRN}  NAXSI WAF is active${RST}"
echo -e "  Core rules:  $CORE_RULES"
echo -e "  Thresholds:  $NAXSI_RULES"
echo -e "  Denied page: $DENIED_CONF"
echo -e "  Backups:     $BACKUP_DIR/"
echo -e ""
echo -e "  ${YLW}Blocked requests return 403 and log to error.log${RST}"
echo -e "  ${YLW}Protects: SQLi, XSS, RFI, path traversal, upload, evasion${RST}"
echo -e "  ${YLW}All existing nginx settings preserved${RST}"
echo -e "${BLU}========================================${RST}"

