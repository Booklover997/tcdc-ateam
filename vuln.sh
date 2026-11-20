#!/bin/bash

# ==============================================================================
# ULTIMATE VULNERABLE UBUNTU 24.04 SERVER LAB SETUP - FULLY FIXED VERSION
# Run once with: sudo bash /tmp/vuln-setup.sh
# ==============================================================================

set -e  # Stop on any error

echo "=== EXTREME VULNERABLE LAB SETUP STARTED ==="

# 1. Disable defenses
ufw disable
systemctl stop apparmor || true
systemctl disable apparmor || true
echo 0 > /proc/sys/kernel/randomize_va_space
echo "kernel.randomize_va_space = 0" >> /etc/sysctl.conf
sysctl -p

# 2. Install everything
apt update -y
apt install -y \
    openssh-server apache2 libapache2-mod-php php php-mysql mariadb-server \
    samba nfs-kernel-server inetutils-telnetd git build-essential \
    phpmyadmin vsftpd

# 3. Configure services

# SSH password auth
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh

# Apache + PHP world-writable
a2enmod rewrite
chmod 777 /var/www/html
systemctl restart apache2

# Samba - guest writable shares including root
mkdir -p /var/smb/public /var/smb/secrets
chmod 777 /var/smb/public /var/smb/secrets
cat >> /etc/samba/smb.conf <<EOF

[public]
   path = /var/smb/public
   writable = yes
   guest ok = yes

[secrets]
   path = /var/smb/secrets
   writable = yes
   guest ok = yes

[root]
   path = /
   writable = yes
   guest ok = yes
EOF
systemctl restart smbd

# NFS - extreme no_root_squash
cat > /etc/exports <<EOF
/ *(rw,sync,no_root_squash,insecure,no_subtree_check)
/home *(rw,sync,no_root_squash,insecure,no_subtree_check)
EOF
exportfs -ra
systemctl restart nfs-kernel-server

# Telnet via inetd (correct way on Ubuntu)
echo "telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd" >> /etc/inetd.conf
systemctl restart inetutils-inetd

# vsftpd - fully anonymous + upload
cat > /etc/vsftpd.conf <<EOF
listen=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/var/ftp/pub
chroot_local_user=YES
allow_writeable_chroot=YES
EOF
mkdir -p /var/ftp/pub
chmod 777 /var/ftp/pub
systemctl restart vsftpd

# 4. MariaDB - completely open
mysql <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY 'password';
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS ''@'%';
GRANT ALL PRIVILEGES ON *.* TO ''@'%' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

echo "bind-address = 0.0.0.0" >> /etc/mysql/mariadb.conf.d/50-server.cnf
systemctl restart mariadb

# 5. DVWA + phpMyAdmin
git clone https://github.com/digininja/DVWA.git /var/www/html/DVWA
cp /var/www/html/DVWA/config/config.inc.php.dist /var/www/html/DVWA/config/config.inc.php
sed -i "s/p@ssw0rd/password123/" /var/www/html/DVWA/config/config.inc.php
sed -i "s/'root'/'admin'/" /var/www/html/DVWA/config/config.inc.php
mysql -u root -ppassword <<EOF
CREATE DATABASE IF NOT EXISTS dvwa;
GRANT ALL ON dvwa.* TO 'admin'@'%' IDENTIFIED BY 'password123';
FLUSH PRIVILEGES;
EOF
chown -R www-data:www-data /var/www/html/DVWA
chmod -R 755 /var/www/html/DVWA
ln -sf /usr/share/phpmyadmin /var/www/html/phpmyadmin

# 6. Weak users + privilege escalation
useradd -m -s /bin/bash -p '$(openssl passwd -1 password123)' guest_user
useradd -m -s /bin/bash -p '$(openssl passwd -1 123456)' ftp_user
useradd -m -s /bin/bash -p '$(openssl passwd -1 password123)' web_admin
useradd -m -s /bin/bash -p '$(openssl passwd -1 C0mplex_77!_HArd_To_Gu3ss)' it_admin

echo "ftp_user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "guest_user ALL=(ALL) NOPASSWD: /bin/bash" >> /etc/sudoers

# Setuid root shell
mkdir -p /opt/vuln
cat > /opt/vuln/vuln.c <<'EOF'
#include <unistd.h>
int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
EOF
gcc /opt/vuln/vuln.c -o /usr/local/bin/vuln-shell
chmod 4755 /usr/local/bin/vuln-shell

# 7. Sensitive data
mkdir -p /secrets /database
cat > /secrets/passwords.txt <<EOF
it_admin:C0mplex_77!_HArd_To_Gu3ss
ftp_user:123456
web_admin:password123
guest_user:password123
root:password
EOF
cat > /secrets/credit_cards.csv <<EOF
Name,CardNumber,Expiry
John Doe,4444-5555-6666-7777,12/28
Jane Smith,8888-9999-0000-1111,05/30
EOF
chmod -R 777 /secrets /database /var/ftp/pub

echo "=== SETUP COMPLETE ==="
echo "REBOOT NOW: sudo reboot"
echo "After reboot, run the verification script below."
