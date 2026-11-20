#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive firewall setup — configure Windows Firewall + launch igris.ps1

.EXAMPLE
    .\init_firewall.ps1 -MachineType AD
    .\init_firewall.ps1 -MachineType MQTT
    .\init_firewall.ps1
    .\init_firewall.ps1 -RemoveWhitelist
    .\init_firewall.ps1 -AddWhitelist -WhitelistIPs "1.2.3.4,5.6.7.8"
    .\init_firewall.ps1 -Teardown
    .\init_firewall.ps1 -Status
#>

param(
    [ValidateSet("AD", "MQTT")]
    [string]$MachineType,
    [switch]$RemoveWhitelist,
    [switch]$AddWhitelist,
    [string]$WhitelistIPs,
    [switch]$Teardown,
    [switch]$Status
)

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$IGRIS = Join-Path $SCRIPT_DIR "igris.ps1"
$IGRIS_LOG = "C:\igris\igris.log"

# ---------------------------------------------------------------------------
# Machine type presets
# ---------------------------------------------------------------------------
# Base ports included on every machine
$BASE_PORTS = "22,3389"

# AD (Active Directory / Domain Controller)
#   DNS(53), Kerberos(88), RPC(135), NetBIOS(139), LDAP(389),
#   SMB(445), Kerberos-kpasswd(464), LDAPS(636),
#   Global Catalog(3268,3269)
$AD_PORTS = "$BASE_PORTS,53,88,135,139,389,445,464,636,3268,3269"

# MQTT (Message broker)
#   MQTT(1883), MQTT-TLS(8883)
$MQTT_PORTS = "$BASE_PORTS,1883,8883"

# ---------------------------------------------------------------------------

if (-not (Test-Path $IGRIS)) {
    Write-Error "Error: igris.ps1 not found at $IGRIS"
    exit 1
}

# --- Pass-through commands ---

if ($RemoveWhitelist) {
    & $IGRIS -RemoveWhitelist
    exit 0
}

if ($AddWhitelist) {
    if ($WhitelistIPs) {
        & $IGRIS -AddWhitelist -WhitelistIPs $WhitelistIPs
    } else {
        Write-Error "Error: specify -WhitelistIPs with -AddWhitelist"
        exit 1
    }
    exit 0
}

if ($Teardown) {
    & $IGRIS -Teardown
    $job = Get-Job -Name "igris" -ErrorAction SilentlyContinue
    if ($job) {
        Stop-Job -Name "igris" -ErrorAction SilentlyContinue
        Remove-Job -Name "igris" -ErrorAction SilentlyContinue
        Write-Host "[+] Stopped igris background job."
    }
    exit 0
}

if ($Status) {
    $job = Get-Job -Name "igris" -ErrorAction SilentlyContinue
    if ($job -and $job.State -eq "Running") {
        Write-Host "[+] igris.ps1 running (Job ID $($job.Id), State: $($job.State))"
    } else {
        Write-Host "[-] igris.ps1 not running"
    }
    Write-Host ""
    Write-Host "--- Igris firewall rules ---"
    foreach ($g in @("igris_auto", "igris_whitelist", "igris_dns", "igris_inbound")) {
        $rules = Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue
        if ($rules) {
            Write-Host ""
            Write-Host "  [$g]"
            $rules | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
        }
    }
    exit 0
}

# --- Check if already running ---

$existingJob = Get-Job -Name "igris" -ErrorAction SilentlyContinue
if ($existingJob -and $existingJob.State -eq "Running") {
    Write-Host "[!] igris.ps1 already running (Job ID $($existingJob.Id))"
    Write-Host "    Log: $IGRIS_LOG"
    Write-Host ""
    Write-Host "    Commands:"
    Write-Host "      .\init_firewall.ps1 -AddWhitelist -WhitelistIPs '1.2.3.4'"
    Write-Host "      .\init_firewall.ps1 -RemoveWhitelist"
    Write-Host "      .\init_firewall.ps1 -Teardown"
    Write-Host "      .\init_firewall.ps1 -Status"
    exit 1
}

# --- Interactive setup ---

Write-Host "========================================"
Write-Host "  Igris Firewall Init (Windows)"
Write-Host "========================================"
Write-Host ""

# Determine ports from machine type or prompt
if ($MachineType -eq "AD") {
    $allPorts = $AD_PORTS
    Write-Host "Machine type: AD (Active Directory)"
    Write-Host "Ports: $allPorts"
    Write-Host "  22    SSH"
    Write-Host "  3389  RDP"
    Write-Host "  53    DNS"
    Write-Host "  88    Kerberos"
    Write-Host "  135   RPC Endpoint Mapper"
    Write-Host "  139   NetBIOS Session"
    Write-Host "  389   LDAP"
    Write-Host "  445   SMB"
    Write-Host "  464   Kerberos kpasswd"
    Write-Host "  636   LDAPS"
    Write-Host "  3268  Global Catalog"
    Write-Host "  3269  Global Catalog SSL"
} elseif ($MachineType -eq "MQTT") {
    $allPorts = $MQTT_PORTS
    Write-Host "Machine type: MQTT"
    Write-Host "Ports: $allPorts"
    Write-Host "  22    SSH"
    Write-Host "  3389  RDP"
    Write-Host "  1883  MQTT"
    Write-Host "  8883  MQTT over TLS"
} else {
    Write-Host "No machine type specified. Available presets:"
    Write-Host "  -MachineType AD     Active Directory ($AD_PORTS)"
    Write-Host "  -MachineType MQTT   MQTT broker ($MQTT_PORTS)"
    Write-Host ""
    Write-Host "Base ports (always included): $BASE_PORTS"
    Write-Host ""
    Write-Host "Enter additional allowed source ports (comma-separated)."
    Write-Host "These are the LOCAL ports your services listen on."
    Write-Host "Example: 80,443,53"
    Write-Host "(Leave blank to use only the base ports)"
    Write-Host ""

    $extraPorts = Read-Host "Additional ports"

    if ($extraPorts) {
        if ($extraPorts -notmatch '^[\d,\s\-]+$') {
            Write-Error "Error: invalid format. Use comma-separated numbers or ranges (e.g. 80,443,1000-2000)"
            exit 1
        }
        $allPorts = "$BASE_PORTS,$extraPorts"
    } else {
        $allPorts = $BASE_PORTS
    }
}

# --- Setup Windows Firewall ---

Write-Host ""
Write-Host "[*] Running firewall setup..."
& $IGRIS -Setup

# --- Whitelist ---

Write-Host ""
$wlExtra = Read-Host "Whitelist IPs (comma-separated, blank for none)"

# --- Create log directory ---

$logDir = Split-Path $IGRIS_LOG -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# --- Launch igris.ps1 as background job ---

Write-Host ""
Write-Host "[*] Starting igris.ps1 (Windows Firewall log watcher)"
Write-Host "    Allowed ports: $allPorts"
Write-Host "    Log: $IGRIS_LOG"
Write-Host ""

$igrisPath = $IGRIS
$ports = $allPorts
$logPath = $IGRIS_LOG
$wl = $wlExtra

if ($wl) {
    $scriptBlock = [scriptblock]::Create("& '$igrisPath' -Ports '$ports' -Log '$logPath' -WhitelistIPs '$wl'")
} else {
    $scriptBlock = [scriptblock]::Create("& '$igrisPath' -Ports '$ports' -Log '$logPath'")
}

Start-Job -Name "igris" -ScriptBlock $scriptBlock | Out-Null

Start-Sleep -Seconds 2

$job = Get-Job -Name "igris" -ErrorAction SilentlyContinue
if ($job -and $job.State -eq "Running") {
    Write-Host "[+] igris.ps1 running in background (Job ID $($job.Id))"
    Write-Host "    Log:    Get-Content $IGRIS_LOG -Wait"
    Write-Host "    Stop:   Stop-Job -Name 'igris'"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  Add whitelist:    .\init_firewall.ps1 -AddWhitelist -WhitelistIPs '1.2.3.4,5.6.7.8'"
    Write-Host "  Remove whitelist: .\init_firewall.ps1 -RemoveWhitelist"
    Write-Host "  Teardown:         .\init_firewall.ps1 -Teardown"
    Write-Host "  Status:           .\init_firewall.ps1 -Status"
} else {
    Write-Host "[!] igris.ps1 failed to start. Check output:"
    if ($job) { Receive-Job -Name "igris" }
    exit 1
}

