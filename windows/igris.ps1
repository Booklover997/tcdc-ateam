#Requires -RunAsAdministrator
<#
.SYNOPSIS
    igris.ps1 — Windows Firewall reactive outbound blocker for CCDC

.DESCRIPTION
    Monitors Windows Firewall log for outbound connections from non-whitelisted
    source ports. Blocks destination IP:port with individual firewall rules.

    Reactive approach:
      1. Windows Firewall allows all outbound by default and logs it
      2. This script tails pfirewall.log in real time
      3. When it sees an outbound connection with a source port NOT in the
         whitelist, it adds: block out rule for that dst_ip:dst_port
      4. That rule blocks all future outbound traffic to that destination

    The first connection gets through (that's how it appears in the log),
    then the rule catches everything after.
    For TCP: only SYN escapes (no data, handshake never completes).
    For UDP: first packet carries actual data — logged as EMERGENCY.

.EXAMPLE
    .\igris.ps1 -Setup
    .\igris.ps1 -Ports "22,2222,80"
    .\igris.ps1 -Ports "22,2222" -WhitelistIPs "91.189.91.83,185.125.190.36"
    .\igris.ps1 -AddWhitelist -WhitelistIPs "1.2.3.4,5.6.7.8"
    .\igris.ps1 -RemoveWhitelist
    .\igris.ps1 -Teardown
#>

param(
    [string]$Ports,
    [int]$TeamNumber = 0,
    [string]$DnsIP,
    [switch]$Setup,
    [switch]$Teardown,
    [switch]$RemoveWhitelist,
    [switch]$AddWhitelist,
    [string]$WhitelistIPs,
    [string]$Log,
    [switch]$LogAllowed,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

$FIREWALL_LOG = "$env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log"
$GROUP_AUTO = "igris_auto"
$GROUP_WHITELIST = "igris_whitelist"
$GROUP_DNS = "igris_dns"
$GROUP_INBOUND = "igris_inbound"

# Original infra DNS + AD DNS (both always allowed)
$INFRA_DNS = "10.112.10.53"
if ($DnsIP) {
    $AD_DNS = $DnsIP
} elseif ($TeamNumber -gt 0) {
    $AD_DNS = "10.$($TeamNumber + 100).20.88"
} else {
    $AD_DNS = "10.112.20.88"
}
$DNS_IPS = @($INFRA_DNS, $AD_DNS)
$DEFAULT_WHITELISTED_IPS = $DNS_IPS

# Script-level state
$script:LogFile = $null
$script:Blocked = @{}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

function Get-Ts {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Write-Log {
    param([string]$Message)
    Write-Host $Message
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $Message } catch {}
    }
}

function Get-MyIPs {
    $ips = @()
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty IPAddress
    } catch {}
    return $ips
}

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

function Invoke-Setup {
    Write-Host "[*] Configuring Windows Firewall..."

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow

    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -LogAllowed True `
        -LogBlocked True `
        -LogFileName $FIREWALL_LOG `
        -LogMaxSizeKilobytes 32767

    Write-Host ""
    Write-Host "[+] Setup complete:"
    Write-Host "    Firewall: enabled on all profiles"
    Write-Host "    Inbound:  block (default)"
    Write-Host "    Outbound: allow (default)"
    Write-Host "    Logging:  allowed + blocked"
    Write-Host "    Log file: $FIREWALL_LOG"
    Write-Host ""
    Write-Host "You can now run:"
    Write-Host "    .\igris.ps1 -Ports '22,2222,80'"
}

function Invoke-Teardown {
    Write-Host "[*] Removing all igris rules..."
    $count = 0

    foreach ($group in @($GROUP_AUTO, $GROUP_WHITELIST, $GROUP_DNS, $GROUP_INBOUND)) {
        $rules = Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
        if ($rules) {
            $n = @($rules).Count
            $rules | Remove-NetFirewallRule
            $count += $n
            Write-Host "    Removed $n rules (group: $group)"
        }
    }

    if ($count -gt 0) {
        Write-Host "[+] Removed $count rules total."
    } else {
        Write-Host "[+] No igris rules found to remove."
    }
}

# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------

function Add-IgrisWhitelist {
    param([string[]]$IPs)
    $added = 0
    foreach ($ip in $IPs) {
        $ip = $ip.Trim()
        if (-not $ip) { continue }

        $name = "igris_wl_$ip"
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Host "    (already exists) allow out to $ip"
            continue
        }

        try {
            New-NetFirewallRule -DisplayName $name `
                -Group $GROUP_WHITELIST `
                -Direction Outbound `
                -Action Allow `
                -RemoteAddress $ip `
                -Enabled True | Out-Null
            Write-Host "    allow out to $ip"
            $added++
        } catch {
            Write-Host "    [!] Failed: ${ip}: $_"
        }
    }
    return $added
}

function Remove-IgrisWhitelist {
    Write-Host "[*] Removing igris whitelist rules..."
    $rules = Get-NetFirewallRule -Group $GROUP_WHITELIST -ErrorAction SilentlyContinue
    if ($rules) {
        $n = @($rules).Count
        $rules | Remove-NetFirewallRule
        Write-Host "[+] Removed $n whitelist rules."
    } else {
        Write-Host "[+] No whitelist rules found."
    }
}

function Get-WhitelistIPsFromUFW {
    $ips = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($ip in $DEFAULT_WHITELISTED_IPS) {
        [void]$ips.Add($ip)
    }
    $rules = Get-NetFirewallRule -Group $GROUP_WHITELIST -ErrorAction SilentlyContinue
    if ($rules) {
        foreach ($rule in $rules) {
            $filter = $rule | Get-NetFirewallAddressFilter
            if ($filter.RemoteAddress) {
                foreach ($addr in $filter.RemoteAddress) {
                    if ($addr -match '^\d+\.\d+\.\d+\.\d+') {
                        [void]$ips.Add($addr)
                    }
                }
            }
        }
    }
    return $ips
}

# ---------------------------------------------------------------------------
# Blocking
# ---------------------------------------------------------------------------

function Add-Block {
    param(
        [string]$Proto,
        [int]$SrcPort,
        [string]$SrcIP,
        [string]$DstIP,
        [int]$DstPort
    )

    $key = "${Proto}_${DstIP}_${DstPort}"
    if ($script:Blocked.ContainsKey($key)) { return }

    $ruleName = "igris_blk_${Proto}_${DstIP}_${DstPort}"

    try {
        New-NetFirewallRule -DisplayName $ruleName `
            -Group $GROUP_AUTO `
            -Direction Outbound `
            -Action Block `
            -Protocol $Proto `
            -RemoteAddress $DstIP `
            -RemotePort $DstPort `
            -Enabled True | Out-Null

        $script:Blocked[$key] = (Get-Ts)
        $ts = Get-Ts
        Write-Log "[BLOCKED] $ts  $($Proto.ToUpper()) ${SrcIP}:${SrcPort} -> ${DstIP}:${DstPort}  block out proto $Proto to $DstIP port $DstPort"
    } catch {
        $ts = Get-Ts
        Write-Log "[ERROR] $ts  Failed to add rule for ${DstIP}:${DstPort}: $_"
    }
}

# ---------------------------------------------------------------------------
# Log monitor
# ---------------------------------------------------------------------------

function Watch-FirewallLog {
    param(
        [System.Collections.Generic.HashSet[int]]$AllowedPorts,
        [System.Collections.Generic.HashSet[string]]$WhitelistedIPs,
        [switch]$LogAllowedConns
    )

    $seenConns = [System.Collections.Generic.HashSet[string]]::new()
    $myIPs = Get-MyIPs

    # pfirewall.log fields (space-separated):
    #  0:date 1:time 2:action 3:protocol 4:src-ip 5:dst-ip
    #  6:src-port 7:dst-port 8:size 9:tcpflags 10:tcpsyn 11:tcpack
    #  12:tcpwin 13:icmptype 14:icmpcode 15:info 16:path

    Get-Content -Path $FIREWALL_LOG -Wait -Tail 0 | ForEach-Object {
        $line = $_
        if ($line.StartsWith("#") -or [string]::IsNullOrWhiteSpace($line)) { return }

        $f = $line -split "\s+"
        if ($f.Count -lt 17) { return }

        $action  = $f[2]
        $proto   = $f[3]
        $srcIP   = $f[4]
        $dstIP   = $f[5]
        $srcPort = $f[6]
        $dstPort = $f[7]
        $path    = $f[16]

        if ($action -ne "ALLOW") { return }
        if ($path -ne "SEND") { return }
        if ($proto -ne "TCP" -and $proto -ne "UDP") { return }

        $srcPortInt = 0; $dstPortInt = 0
        if (-not [int]::TryParse($srcPort, [ref]$srcPortInt)) { return }
        if (-not [int]::TryParse($dstPort, [ref]$dstPortInt)) { return }

        # Skip loopback and self-traffic (destination only)
        if ($dstIP.StartsWith("127.")) { return }
        if ($dstIP -in $myIPs) { return }

        # Skip allowed source ports (our services)
        if ($AllowedPorts.Contains($srcPortInt)) {
            if ($LogAllowedConns) {
                $ts = Get-Ts
                Write-Log "[ALLOWED] $ts  $proto sport=$srcPortInt ($srcIP -> ${dstIP}:${dstPortInt})"
            }
            return
        }

        # Skip whitelisted destination IPs
        if ($WhitelistedIPs.Contains($dstIP)) { return }

        # Dedup by (proto, dst_ip, dst_port)
        $connKey = "${proto}_${dstIP}_${dstPortInt}"
        if (-not $seenConns.Add($connKey)) { return }
        if ($script:Blocked.ContainsKey($connKey)) { return }

        # UDP emergency — first packet carries data
        if ($proto -eq "UDP") {
            $ts = Get-Ts
            Write-Log "[EMERGENCY] $ts  UDP ${srcIP}:${srcPortInt} -> ${dstIP}:${dstPortInt}  UDP payload likely sent before rule applied"
        }

        Add-Block -Proto $proto -SrcPort $srcPortInt -SrcIP $srcIP -DstIP $dstIP -DstPort $dstPortInt
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($Setup) {
    Invoke-Setup
    exit 0
}

if ($Teardown) {
    Invoke-Teardown
    exit 0
}

if ($RemoveWhitelist) {
    Remove-IgrisWhitelist
    exit 0
}

if ($AddWhitelist) {
    $wlIPs = @()
    if ($WhitelistIPs) {
        $wlIPs = $WhitelistIPs.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    if ($wlIPs.Count -eq 0) {
        Write-Error "Error: use -WhitelistIPs with -AddWhitelist"
        exit 1
    }
    Write-Host "[*] Adding $($wlIPs.Count) whitelist allow rules..."
    Add-IgrisWhitelist -IPs $wlIPs
    Write-Host "[+] Whitelist active. Remove with: .\igris.ps1 -RemoveWhitelist"
    exit 0
}

# --- Monitor mode ---

if (-not $Ports) {
    Write-Error "Error: specify -Ports, -Setup, -Teardown, -RemoveWhitelist, or -AddWhitelist"
    exit 1
}

# Parse ports
$allowedPorts = [System.Collections.Generic.HashSet[int]]::new()
foreach ($token in $Ports.Split(",")) {
    $token = $token.Trim()
    if (-not $token) { continue }
    if ($token -match "^(\d+)-(\d+)$") {
        for ($p = [int]$Matches[1]; $p -le [int]$Matches[2]; $p++) {
            [void]$allowedPorts.Add($p)
        }
    } else {
        [void]$allowedPorts.Add([int]$token)
    }
}

if ($allowedPorts.Count -eq 0) {
    Write-Error "Error: no allowed ports specified."
    exit 1
}

# Preflight
if (-not (Test-Path $FIREWALL_LOG)) {
    Write-Error "Error: $FIREWALL_LOG not found. Run: .\igris.ps1 -Setup"
    exit 1
}

$profile = Get-NetFirewallProfile -Profile Domain
if (-not $profile.LogAllowed) {
    Write-Warning "[!] Firewall logging for allowed connections is not enabled. Run: .\igris.ps1 -Setup"
}

# Build whitelist
$whitelistedIPs = [System.Collections.Generic.HashSet[string]]::new()
foreach ($ip in $DEFAULT_WHITELISTED_IPS) {
    [void]$whitelistedIPs.Add($ip)
}
if ($WhitelistIPs) {
    foreach ($ip in $WhitelistIPs.Split(",")) {
        $ip = $ip.Trim()
        if ($ip) { [void]$whitelistedIPs.Add($ip) }
    }
}

# Add whitelist firewall rules
if ($whitelistedIPs.Count -gt 0) {
    Write-Host "[*] Adding $($whitelistedIPs.Count) whitelist allow rules..."
    Add-IgrisWhitelist -IPs $whitelistedIPs
}

# DNS allow rules — both infra DNS and AD DNS, both UDP + TCP
foreach ($dnsAddr in $DNS_IPS) {
    foreach ($dnsProto in @("UDP", "TCP")) {
        $dnsRuleName = "igris_dns_${dnsProto}_${dnsAddr}"
        $dnsRule = Get-NetFirewallRule -DisplayName $dnsRuleName -ErrorAction SilentlyContinue
        if (-not $dnsRule) {
            New-NetFirewallRule -DisplayName $dnsRuleName `
                -Group $GROUP_DNS `
                -Direction Outbound `
                -Action Allow `
                -Protocol $dnsProto `
                -RemoteAddress $dnsAddr `
                -RemotePort 53 `
                -Enabled True | Out-Null
            Write-Host "    allow out $dnsProto to $dnsAddr port 53 (DNS)"
        }
    }
}

# Inbound allow rules for service ports (both TCP and UDP)
Write-Host "[*] Adding inbound allow rules for service ports..."
foreach ($p in ($allowedPorts | Sort-Object)) {
    foreach ($proto in @("TCP", "UDP")) {
        $ruleName = "igris_in_${proto}_${p}"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Group $GROUP_INBOUND `
                -Direction Inbound `
                -Action Allow `
                -Protocol $proto `
                -LocalPort $p `
                -Enabled True | Out-Null
            Write-Host "    allow in $proto port $p"
        }
    }
}

# Load existing block rules to prevent duplicates on restart
$existingBlocks = Get-NetFirewallRule -Group $GROUP_AUTO -ErrorAction SilentlyContinue
if ($existingBlocks) {
    foreach ($rule in $existingBlocks) {
        if ($rule.DisplayName -match '^igris_blk_(\w+)_(.+)_(\d+)$') {
            $key = "$($Matches[1])_$($Matches[2])_$($Matches[3])"
            $script:Blocked[$key] = "pre-existing"
        }
    }
    if ($script:Blocked.Count -gt 0) {
        Write-Host "[*] Loaded $($script:Blocked.Count) existing block rules from previous run"
    }
}

# Set log file
if ($Log) {
    $script:LogFile = $Log
}

Write-Host "[*] Allowed source ports: $(($allowedPorts | Sort-Object) -join ', ')"
if ($whitelistedIPs.Count -gt 0) {
    Write-Host "[*] Whitelisted IPs: $(($whitelistedIPs | Sort-Object) -join ', ')"
}
Write-Host "[*] Watching: $FIREWALL_LOG"
if ($Log) {
    Write-Host "[*] Log file: $Log"
}

if ($DryRun) {
    Write-Host "[*] Dry run - not monitoring."
    exit 0
}

Write-Host ""
Write-Host "[+] Monitoring outbound connections (Ctrl+C to stop)..."
Write-Host "    First connection from a non-allowed source port goes through,"
Write-Host "    then Windows Firewall blocks all future traffic to that destination IP:port."
Write-Host ""

try {
    Watch-FirewallLog -AllowedPorts $allowedPorts -WhitelistedIPs $whitelistedIPs -LogAllowedConns:$LogAllowed
} finally {
    if ($script:Blocked.Count -gt 0) {
        Write-Host ""
        Write-Host "--- Summary: $($script:Blocked.Count) destinations blocked ---"
        foreach ($entry in $script:Blocked.GetEnumerator() | Sort-Object Key) {
            $parts = $entry.Key -split "_", 3
            Write-Host "  block out proto $($parts[0]) to $($parts[1]) port $($parts[2])  (added $($entry.Value))"
        }
        Write-Host ""
        Write-Host "To remove all rules: .\igris.ps1 -Teardown"
    } else {
        Write-Host ""
        Write-Host "--- No destinations were blocked ---"
    }
}

