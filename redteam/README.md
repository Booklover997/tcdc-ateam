# Red Team Competition Toolkit — TCDC Open 2026

**SSH Key:** `redteam_key` / `redteam_key.pub` (ed25519)

---

## ROE Compliance Notes

- **R18 (Firewall):** Section 0 (Firewall Lockdown) uses default-deny outbound, which violates R18 for YOUR OWN boxes. **Section 0 is for purple teaming OTHER teams' boxes only.** Do NOT run Section 0 on your own team's boxes. R18 does not apply for purple teaming.
- **R8 (Users):** Scripts do NOT change, disable, or remove any existing users. We only ADD a backdoor user.
- **R7/R15 (Wazuh/auditd):** Scripts do NOT touch Wazuh, auditd, or any monitoring agent protected by the ROE.
- **R11 (Beyond repair):** All changes are reversible. Undo commands are at the bottom.
- **R12 (Lock-out):** SSH, RDP, and WinRM are always preserved. No passwords are changed.
- **R13 (Critical files):** No critical files are deleted. Configs are modified, not removed.
- **Log wiping:** REMOVED per ROE. No logs are cleared, no logging services disabled.
- **Callbacks:** REMOVED. No reverse shells or outbound connections back to our team.

---

## Files

| File | Target | Run As |
|------|--------|--------|
| `redteam-linux.sh` | Linux boxes | `root` |
| `redteam-windows.ps1` | Windows / AD boxes | Elevated PowerShell |
| `redteam_key` | Your attack box | Private key — `chmod 600` |
| `redteam_key.pub` | Planted by linux script | Public key |

---

## Quick Access

```bash
# SSH into a Linux box via backdoor
ssh -i redteam_key syshealth@<target>
```

```
# Windows sticky keys: on lock screen, press Shift 5 times → SYSTEM cmd
```

```bash
# Windows backdoor user (RDP / WinRM)
# User: healthsvc$   Pass: Comp2024!RT
```

```bash
# Webshell (Linux)
curl "http://<target>/.sys-check.php?c=whoami"
```

```bash
# Webshell (Windows/IIS)
curl "http://<target>/web.config.aspx.old?c=whoami"
```

---

## Firewall Posture (Section 0 — Purple Team Only)

**WARNING:** Section 0 violates R18 if used on your own boxes. Only run it on OTHER teams' boxes during purple teaming.

### Blocked Ports — Both Scripts (scored services)

| Port | Service | Protocol |
|------|---------|----------|
| 21 | FTP | TCP |
| 53 | DNS | TCP + UDP |
| 80 | HTTP | TCP |
| 443 | HTTPS | TCP |
| 1883 | MQTT | TCP |
| 3306 | MySQL | TCP |

### Blocked Ports — Windows Only (AD ports)

| Port | Service | Protocol |
|------|---------|----------|
| 88 | Kerberos | TCP + UDP |
| 135 | RPC Endpoint Mapper | TCP |
| 389 | LDAP | TCP + UDP |
| 445 | SMB | TCP |
| 464 | Kerberos kpasswd | TCP + UDP |
| 636 | LDAPS | TCP |
| 9389 | AD Web Services | TCP |
| 49152-65535 | AD RPC dynamic range | TCP |

### Allowed Ports — Linux

| Port | Service | Direction |
|------|---------|-----------|
| 22 | SSH | In + Out |
| 8080 | HTTP-alt | In + Out |
| lo | Loopback | In + Out |

### Allowed Ports — Windows

| Port | Service | Direction |
|------|---------|-----------|
| 22 | SSH | In + Out |
| 3389 | RDP | In + Out |
| 5985 | WinRM HTTP | In + Out |
| 5986 | WinRM HTTPS | In + Out |
| 8080 | HTTP-alt | In + Out |
| 67/udp | DHCP server | In + Out |
| 68/udp | DHCP client | In + Out |
| 123/udp | NTP | In + Out |
| ICMPv4 | Ping | In + Out |

### Firewall Persistence

| Mechanism | Linux | Windows |
|-----------|-------|---------|
| Persist script | `/usr/local/bin/.fw-persist.sh` (cron, every 1 min) | `C:\Windows\System32\fw-persist.ps1` (scheduled task, every 1 min) |
| What it does | Re-enables UFW if disabled | Re-enables firewall + resets default deny if changed |
| Config protection | `chattr +i` on all `/etc/ufw/*`, `/etc/default/ufw`, persist script, crontab spool | ACL-locked persist script, task XML, and `FirewallPolicy` registry key to SYSTEM-only |

---

## Linux — `redteam-linux.sh`

### Section 0: Firewall Lockdown — PURPLE TEAM ONLY (9 actions)

| # | Action | Detail |
|---|--------|--------|
| 1 | Reset UFW | `ufw --force reset` |
| 2 | Default deny | Block all inbound and outbound |
| 3 | Allow access ports | 22 (SSH), 8080 (HTTP-alt) — both directions |
| 4 | Explicit deny on scored ports | 21, 53, 80, 443, 1883, 3306 TCP + 53 UDP — both directions |
| 5 | Allow loopback | lo interface both directions |
| 6 | FW persist cron | `/usr/local/bin/.fw-persist.sh` re-enables UFW every minute |
| 7 | Immutable UFW configs | `chattr +i` on `/etc/ufw/*`, `/etc/default/ufw` |
| 8 | Immutable persist script | `chattr +i` on `.fw-persist.sh` |
| 9 | Immutable crontab spool | `chattr +i` on `/var/spool/cron/crontabs/root` |

### Section 1: Persistence (4 actions)

| # | Action | Detail |
|---|--------|--------|
| 10 | Backdoor user | `syshealth` added to sudo/adm/shadow, password `Comp2024!RT` |
| 11 | Hide user | UID changed to 999 in `/etc/passwd` |
| 12 | SSH key planted | Team ed25519 pubkey in `/home/syshealth/.ssh/authorized_keys` |
| 13 | PHP webshell | `.sys-check.php` in all webroots, backdated to Jan 2022 |

### Section 2: Service Disruption (3 actions)

| # | Action | Detail |
|---|--------|--------|
| 14 | Stop + disable services | apache2, nginx, httpd, mysql, mariadb, postgresql, vsftpd, proftpd, pure-ftpd, postfix, dovecot, named, bind9, samba, smbd, cups, docker (sshd NOT touched) |
| 15 | Corrupt Apache config | `Listen 80` → `Listen 8181` |
| 16 | Corrupt BIND zones | `BROKEN` appended to `/etc/bind/db.*` files |

### Section 3: Recovery Prevention (4 actions)

| # | Action | Detail |
|---|--------|--------|
| 17 | Break apt | `/etc/apt/sources.list` emptied + immutable |
| 18 | Break yum | `enabled=0` in all `.repo` files |
| 19 | Break sudo | Syntax error in `/etc/sudoers.d/zzz-break` |
| 20 | Alias admin commands | `iptables`, `ufw`, `systemctl`, `service`, `chattr` aliased to fake "command not found" |

**Linux total: 20 actions**

---

## Windows — `redteam-windows.ps1`

### Section 0: Firewall Lockdown — PURPLE TEAM ONLY (11 actions)

| # | Action | Detail |
|---|--------|--------|
| 1 | Reset firewall | `netsh advfirewall reset` |
| 2 | Default deny | Block all inbound + outbound, all profiles |
| 3 | Remove all rules | Wipes existing firewall rules |
| 4 | Allow TCP access ports | 22 (SSH), 3389 (RDP), 5985 (WinRM HTTP), 5986 (WinRM HTTPS), 8080 (HTTP-alt) — both directions |
| 5 | Allow UDP ports | 67 (DHCP server), 68 (DHCP client), 123 (NTP) — both directions |
| 6 | Explicit block on scored ports | 21, 53, 80, 443, 1883, 3306 TCP + 53 UDP — both directions |
| 7 | Explicit block on AD ports | 88, 135, 389, 445, 464, 636, 9389 TCP + 88, 389, 464 UDP — both directions |
| 8 | Block AD RPC dynamic range | 49152-65535 TCP — both directions |
| 9 | Allow loopback + ICMP | Loopback + ICMPv4 both directions |
| 10 | FW-Persist task | Scheduled task re-enables firewall + default deny every 1 min as SYSTEM |
| 11 | ACL-lock + registry lock | Persist script, task XML, and `FirewallPolicy` registry key restricted to SYSTEM-only |

### Section 1: Persistence (5 actions)

| # | Action | Detail |
|---|--------|--------|
| 12 | Backdoor user | `healthsvc$` added to local Administrators, password `Comp2024!RT` |
| 13 | Domain Admins | If DC, adds backdoor user to Domain Admins |
| 14 | Hide user | Registry `SpecialAccounts\UserList` = 0 |
| 15 | Sticky keys | `sethc.exe` replaced with `cmd.exe` — 5x Shift on lock screen = SYSTEM cmd |
| 16 | ASPX webshell | `web.config.aspx.old` in `wwwroot` and `ftproot`, backdated to Jan 2022 |

### Section 2: Service Disruption (3 actions)

| # | Action | Detail |
|---|--------|--------|
| 17 | Stop + disable services | W3SVC, MSSQLSERVER, SQLSERVERAGENT, MYSQL, dns, DFSR, NTDS, IISADMIN, SMTPSVC, POP3SVC, FTPSVC, Spooler (WinRM/RDP/SSH NOT touched) |
| 18 | Corrupt IIS config | Port 80 binding → 9999 in `applicationHost.config` |
| 19 | Corrupt IIS config | Port 80 binding → 9999 |

### Section 3: Disable Defenses (2 actions)

| # | Action | Detail |
|---|--------|--------|
| 20 | Disable Defender | Real-time monitoring, IOAV protection, behavior monitoring all off |
| 21 | Kill AMSI | All AMSI provider registry keys removed |

### Section 4: Recovery Prevention (5 actions)

| # | Action | Detail |
|---|--------|--------|
| 22 | Disable Windows Update | `wuauserv` stopped + disabled |
| 23 | Break Server Manager | `ServerManager.exe` renamed to `.bak` |
| 24 | Disable Task Manager | Disabled via default user registry hive (not for our session) |
| 25 | ACL-lock persistence | `sethc.exe` restricted to SYSTEM-only |
| 26 | Poison hosts file | `windowsupdate.microsoft.com`, `update.microsoft.com`, `download.windowsupdate.com`, `definitions.microsoft.com` → `127.0.0.1`, file set read-only + hidden |

**Windows total: 26 actions**

---

## Services NOT Touched (team access preserved)

| Service | Port | Linux | Windows |
|---------|------|-------|---------|
| SSH | 22 | sshd running, port open | Port open |
| RDP | 3389 | N/A | TermService running, port open |
| WinRM | 5985/5986 | N/A | WinRM running, port open |

---

## What AD Blocking Kills

With ports 88, 135, 389, 445, 464, 636, 9389, and 49152-65535 all blocked:

- **Domain authentication** — users can't log in with domain credentials
- **AD replication** — domain controllers can't sync with each other
- **Group Policy** — GPO updates stop propagating
- **DNS resolution** — if AD-integrated DNS was the only resolver
- **File shares** — SMB/CIFS completely dead
- **LDAP queries** — no directory lookups, no AD tools work
- **Kerberos** — no ticket granting, no service tickets
- **AD Web Services** — PowerShell AD cmdlets stop working

---

## What Was Removed (ROE compliance)

| Removed Action | Why |
|----------------|-----|
| All reverse shells (cron, systemd, bashrc, rc.local, scheduled task, WMI, registry Run) | No callbacks to our team |
| Callback firewall rules (port 4444 outbound) | No callbacks to our team |
| ss wrapper (hid callback connections) | No callbacks to hide |
| Clear Linux logs (auth.log, syslog, etc.) | Log wiping not allowed per ROE |
| Clear journald | Log wiping not allowed per ROE |
| Clear bash history | Log wiping not allowed per ROE |
| Clear Windows event logs | Log wiping not allowed per ROE |
| Disable EventLog service | Log wiping not allowed per ROE |
| Kill/delete Sysmon | Log wiping not allowed per ROE |
| Clear PowerShell history | Log wiping not allowed per ROE |
| Disable PowerShell logging | Log wiping not allowed per ROE |
| Reset all user passwords | Can't interfere with logins (R8/R12) |
| Disable SSH password auth | Can't interfere with logins (R8/R12) |
| Wipe authorized_keys | Can't interfere with logins (R8/R12) |
| Reset domain passwords | Can't interfere with logins (R8/R12) |
| MySQL root password change | Can't interfere with logins (R8/R12) |

---

## Blue Team Recovery Layers

For blue team to fully recover a Linux box, they need to:

1. Figure out `chattr` is aliased to a no-op → use full path `/usr/bin/chattr`
2. `chattr -i` on UFW configs, crontab, apt sources
3. Remove cron entry for firewall persist
4. Fix `/etc/sudoers.d/zzz-break`
5. Restore apt sources
6. Remove the `syshealth` user
7. Remove all command aliases from bashrc
8. Restore service configs (Apache ports, DNS zones)
9. Re-enable and start all services
10. Remove UFW deny rules and add allow rules for scored ports

For blue team to fully recover a Windows box, they need to:

1. `takeown` + `icacls` to regain access to ACL-locked files
2. Unregister `FW-Persist` scheduled task
3. Restore `sethc.exe` from backup or Windows component store
4. Remove `healthsvc$` user from local Admins (and Domain Admins if DC)
5. Reset firewall — remove all block rules for scored + AD ports, add allow rules
6. Re-enable all stopped services + fix IIS config
7. Re-enable Defender, restore AMSI providers
8. Clean hosts file
9. Restore `ServerManager.exe`, remove Task Manager GPO
10. Re-enable Windows Update
11. Unblock all AD ports (88, 135, 389, 445, 464, 636, 9389, 49152-65535)

---

## Undo (for your team)

### Linux
```bash
# Remove immutable flags
chattr -i /etc/ufw/* /etc/default/ufw /usr/local/bin/.fw-persist.sh \
  /var/spool/cron/crontabs/root /etc/apt/sources.list
```

```bash
# Kill firewall
ufw --force disable
```

```bash
# Remove persistence
crontab -r
rm /usr/local/bin/.fw-persist.sh
```

```bash
# Remove backdoor user
userdel -r syshealth
```

```bash
# Fix sudo
rm /etc/sudoers.d/zzz-break
```

### Windows
```powershell
# Unlock files
takeown /F C:\Windows\System32\Tasks\FW-Persist /A
icacls C:\Windows\System32\Tasks\FW-Persist /grant Administrators:F
takeown /F C:\Windows\System32\fw-persist.ps1 /A
icacls C:\Windows\System32\fw-persist.ps1 /grant Administrators:F
```

```powershell
# Remove tasks
Unregister-ScheduledTask -TaskName "FW-Persist" -Confirm:$false
```

```powershell
# Reset firewall
netsh advfirewall reset
```

```powershell
# Remove backdoor user
net user healthsvc$ /delete
```

```powershell
# Restore sethc
sfc /scannow
```
