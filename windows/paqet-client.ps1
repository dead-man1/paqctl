#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Paqet/GFK Windows Client v1.1.0 - Bypass Firewall Restrictions

.DESCRIPTION
    This script helps you connect to your server through firewalls that block normal connections.
    It supports two backends:

    PAQET (Recommended for most users)
    ─────────────────────────────────
    • Simple all-in-one solution with built-in SOCKS5 proxy
    • Uses KCP protocol over raw sockets to bypass DPI
    • Works on: Windows (with Npcap)
    • Configuration: Just needs server IP, port, and encryption key
    • Proxy: 127.0.0.1:1080 (SOCKS5)

    GFW-KNOCKER (For heavily restricted networks)
    ─────────────────────────────────────────────
    • Uses "violated TCP" packets + QUIC tunnel to evade deep packet inspection
    • More complex but better at evading sophisticated firewalls (like GFW)
    • Works on: Windows (with Npcap + Python)
    • Requires: Xray running on server port 443
    • Proxy: 127.0.0.1:14000 (forwards to server's Xray SOCKS5)

    CAN I RUN BOTH?
    ───────────────
    Yes! Both can run simultaneously on different ports:
    • Paqet SOCKS5: 127.0.0.1:1080
    • GFK tunnel:   127.0.0.1:14000
    This lets you have a backup if one method gets blocked.

.NOTES
    Requirements:
    • Administrator privileges (for raw socket access)
    • Npcap (https://npcap.com) - auto-installed if missing
    • Python 3.10+ (GFK only) - auto-installed if missing
#>

param(
    [string]$ServerAddr,
    [string]$Key,
    [string]$Action = "menu",  # menu, run, install, config, stop, status
    [string]$Backend = "",     # paqet, gfk (auto-detect if not specified)
    [switch]$WatchdogCheck
)

$ErrorActionPreference = "Stop"

# Directories and pinned versions (for stability - update after testing new releases)
$ClientVersion = "v1.1.0"
$InstallDir = "C:\paqet"
$PaqetExe = "$InstallDir\paqet_windows_amd64.exe"
$PaqetVersionPinned = "v1.0.0-alpha.20"   # Fallback if GitHub API unreachable
$GfkDir = "$InstallDir\gfk"
$ConfigFile = "$InstallDir\config.yaml"
$SettingsFile = "$InstallDir\settings.conf"

# Npcap (pinned version)
$NpcapVersion = "1.80"
$NpcapUrl = "https://npcap.com/dist/npcap-$NpcapVersion.exe"
$NpcapInstaller = "$env:TEMP\npcap-$NpcapVersion.exe"

# GFK scripts - bundled locally for faster setup (only works when running from downloaded repo)
# When running via "irm | iex", $MyInvocation.MyCommand.Path is null
$ScriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { $null }
$GfkLocalDir = if ($ScriptDir) { "$ScriptDir\..\gfk\client" } else { $null }
$GfkFiles = @("mainclient.py", "quic_client.py", "vio_client.py")  # parameters.py is generated

# Colors
function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Write-Err { Write-Host "[ERROR] $args" -ForegroundColor Red }

# Fetch latest paqet version from GitHub, fall back to pinned
function Get-LatestPaqetVersion {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/hanselime/paqet/releases/latest" -TimeoutSec 10
        if ($response.tag_name -match '^v?\d+\.\d+\.\d+') {
            return $response.tag_name
        }
    } catch {}
    return $PaqetVersionPinned
}
$PaqetVersion = Get-LatestPaqetVersion

# Input validation (security: prevent config injection)
function Test-ValidIP {
    param([string]$IP)
    return $IP -match '^(\d{1,3}\.){3}\d{1,3}$'
}

function Test-ValidMAC {
    param([string]$MAC)
    return $MAC -match '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
}

function Test-SafeString {
    param([string]$s)
    # Block characters that could break Python string literals
    if ($s.Contains('"') -or $s.Contains("'") -or $s.Contains('\') -or $s.Contains([char]10) -or $s.Contains([char]13)) {
        return $false
    }
    return $true
}

#═══════════════════════════════════════════════════════════════════════
# Prerequisite Checks
#═══════════════════════════════════════════════════════════════════════

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Npcap {
    $npcapPath = "C:\Windows\System32\Npcap"
    $wpcapDll = "C:\Windows\System32\wpcap.dll"
    return (Test-Path $npcapPath) -or (Test-Path $wpcapDll)
}

function Test-Python {
    try {
        $version = & python --version 2>&1
        return $version -match "Python 3\."
    } catch {
        return $false
    }
}

function Install-NpcapIfMissing {
    if (Test-Npcap) { return $true }

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "  NPCAP REQUIRED" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Npcap is required for raw socket access."
    Write-Host ""
    Write-Host "  IMPORTANT: During installation, check:" -ForegroundColor Yellow
    Write-Host "  [x] Install Npcap in WinPcap API-compatible Mode" -ForegroundColor Yellow
    Write-Host ""

    $choice = Read-Host "  Download and install Npcap now? [Y/n]"
    if ($choice -match "^[Nn]") {
        Write-Warn "Please install Npcap from https://npcap.com"
        return $false
    }

    Write-Info "Downloading Npcap $NpcapVersion..."
    try {
        Invoke-WebRequest -Uri $NpcapUrl -OutFile $NpcapInstaller -UseBasicParsing
        Write-Success "Downloaded"
    } catch {
        Write-Err "Download failed. Please install manually from https://npcap.com"
        Start-Process "https://npcap.com/#download"
        return $false
    }

    Write-Info "Launching Npcap installer..."
    Write-Host "  Check: [x] WinPcap API-compatible Mode" -ForegroundColor Yellow
    Start-Process -FilePath $NpcapInstaller -Wait | Out-Null
    Remove-Item $NpcapInstaller -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    if (Test-Npcap) {
        Write-Success "Npcap installed!"
        return $true
    } else {
        Write-Err "Npcap installation failed or cancelled"
        return $false
    }
}

function Install-PythonIfMissing {
    if (Test-Python) { return $true }

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "  PYTHON 3 REQUIRED" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  GFW-knocker requires Python 3.x"
    Write-Host ""
    Write-Host "  Please install Python from:" -ForegroundColor Yellow
    Write-Host "  https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  IMPORTANT: Check 'Add Python to PATH' during install!" -ForegroundColor Yellow
    Write-Host ""

    $choice = Read-Host "  Open Python download page? [Y/n]"
    if ($choice -notmatch "^[Nn]") {
        Start-Process "https://www.python.org/downloads/"
    }

    Read-Host "  Press Enter after installing Python"

    if (Test-Python) {
        Write-Success "Python detected!"
        return $true
    } else {
        Write-Err "Python not found. Please restart PowerShell after installing."
        return $false
    }
}

function Install-PythonPackages {
    Write-Info "Installing Python packages (scapy, aioquic)..."
    try {
        & python -m pip install --quiet --upgrade pip 2>&1 | Out-Null
        & python -m pip install --quiet scapy aioquic 2>&1 | Out-Null
        Write-Success "Python packages installed"
        return $true
    } catch {
        Write-Err "Failed to install Python packages: $_"
        Write-Info "Try manually: pip install scapy aioquic"
        return $false
    }
}

#═══════════════════════════════════════════════════════════════════════
# Network Detection
#═══════════════════════════════════════════════════════════════════════

function Get-NetworkInfo {
    $adapter = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "Virtual|VirtualBox|VMware|Hyper-V|Loopback"
    } | Select-Object -First 1

    if (-not $adapter) {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    }

    if (-not $adapter) {
        Write-Err "No active network adapter found"
        return $null
    }

    $ifIndex = $adapter.ifIndex
    $ipConfig = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 |
                Where-Object { $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1
    $gateway = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
               Select-Object -First 1

    if (-not $ipConfig) {
        Write-Err "No IPv4 address found on $($adapter.Name)"
        return $null
    }

    $gatewayIP = if ($gateway) { $gateway.NextHop } else { $null }
    $gatewayMAC = $null

    if ($gatewayIP) {
        $null = Test-Connection -ComputerName $gatewayIP -Count 1 -ErrorAction SilentlyContinue
        $arpEntry = Get-NetNeighbor -IPAddress $gatewayIP -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($arpEntry -and $arpEntry.LinkLayerAddress) {
            $gatewayMAC = $arpEntry.LinkLayerAddress -replace "-", ":"
        }
    }

    return @{
        Name = $adapter.Name
        Guid = $adapter.InterfaceGuid
        IP = $ipConfig.IPAddress
        GatewayIP = $gatewayIP
        GatewayMAC = $gatewayMAC
    }
}

#═══════════════════════════════════════════════════════════════════════
# Backend Detection
#═══════════════════════════════════════════════════════════════════════

function Get-InstalledBackend {
    if (Test-Path $SettingsFile) {
        $content = Get-Content $SettingsFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match '^BACKEND="?(\w+)"?') {
                return $Matches[1]
            }
        }
    }
    if (Test-Path $PaqetExe) { return "paqet" }
    if (Test-Path "$GfkDir\mainclient.py") { return "gfk" }
    return $null
}

function Get-Setting {
    param([string]$Key, [string]$DefaultValue = "")
    if (Test-Path $SettingsFile) {
        $content = Get-Content $SettingsFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match "^$Key=`"?(.*?)`"?$") {
                return $Matches[1]
            }
        }
    }
    return $DefaultValue
}

function Save-Settings {
    param(
        [string]$Backend,
        [string]$ServerAddr = "",
        [string]$SocksPort = "1080",
        [string]$RoutingMode = "",
        [string]$ForwardPort = "",
        [string]$ForwardTarget = "",
        [string]$KcpProfile = "",
        [string]$TurboEnabled = "",
        [string]$WatchdogEnabled = ""
    )

    $existing = @{}
    if (Test-Path $SettingsFile) {
        Get-Content $SettingsFile -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^([^=]+)="?(.*)"?$') {
                $existing[$Matches[1]] = $Matches[2]
            }
        }
    }

    if ($Backend) { $existing["BACKEND"] = $Backend }
    if ($ServerAddr) { $existing["SERVER_ADDR"] = $ServerAddr }
    if ($SocksPort) { $existing["SOCKS_PORT"] = $SocksPort }
    if ($RoutingMode) { $existing["ROUTING_MODE"] = $RoutingMode }
    if ($ForwardPort) { $existing["FORWARD_PORT"] = $ForwardPort }
    if ($ForwardTarget) { $existing["FORWARD_TARGET"] = $ForwardTarget }
    if ($KcpProfile) { $existing["KCP_PROFILE"] = $KcpProfile }
    if ($TurboEnabled) { $existing["TURBO_ENABLED"] = $TurboEnabled }
    if ($WatchdogEnabled) { $existing["WATCHDOG_ENABLED"] = $WatchdogEnabled }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $lines = @()
    foreach ($key in $existing.Keys) {
        $lines += "$key=`"$($existing[$key])`""
    }
    [System.IO.File]::WriteAllLines($SettingsFile, $lines)
}

#═══════════════════════════════════════════════════════════════════════
# Paqet Functions
#═══════════════════════════════════════════════════════════════════════

function Install-Paqet {
    Write-Host ""
    Write-Host "  Installing PAQET" -ForegroundColor Green
    Write-Host "  ────────────────" -ForegroundColor Green
    Write-Host "  Paqet is an all-in-one proxy solution with built-in SOCKS5."
    Write-Host "  It uses KCP protocol over raw sockets to bypass firewalls."
    Write-Host ""
    Write-Host "  What will be installed:" -ForegroundColor Yellow
    Write-Host "    1. Npcap (for raw socket access)"
    Write-Host "    2. Paqet binary"
    Write-Host ""
    Write-Host "  After setup, configure with your server's IP:port and key."
    Write-Host "  Your proxy will be: 127.0.0.1:1080 (SOCKS5)"
    Write-Host ""

    if (-not (Install-NpcapIfMissing)) {
        Write-Err "Cannot continue without Npcap"
        return $false
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    if (Test-Path $PaqetExe) {
        $installedVer = Get-InstalledPaqetVersion
        if ($installedVer -and $installedVer -ne $PaqetVersion) {
            Write-Info "Updating existing paqet ($installedVer) to latest ($PaqetVersion)..."
        } else {
            Write-Info "paqet already installed ($($installedVer -or 'unknown version'))"
            return $true
        }
    }

    $zipUrl = "https://github.com/hanselime/paqet/releases/download/$PaqetVersion/paqet-windows-amd64-$PaqetVersion.zip"
    $zipFile = "$env:TEMP\paqet.zip"

    Write-Info "Downloading paqet $PaqetVersion..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile
    } catch {
        Write-Err "Download failed: $_"
        return $false
    }

    Write-Info "Extracting..."
    Expand-Archive -Path $zipFile -DestinationPath $InstallDir -Force
    Remove-Item $zipFile -Force

    Write-Success "paqet installed to $InstallDir"
    Save-Settings -Backend "paqet"
    Save-PaqetVersion -Version $PaqetVersion
    return $true
}

function New-PaqetConfig {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SecretKey,
        [string]$TcpLocalFlag = "PA",
        [string]$TcpRemoteFlag = "PA",
        [string]$RoutingMode = "socks5",
        [string]$SocksPort = "1080",
        [string]$ForwardPort = "14000",
        [string]$ForwardTarget = "127.0.0.1:80",
        [string]$KcpProfile = "standard",
        [int]$KcpConn = 2,
        [int]$KcpMtu = 1350,
        [int]$KcpSndWnd = 1024,
        [int]$KcpRcvWnd = 1024,
        [int]$KcpNoDelay = 0,
        [int]$KcpInterval = 20,
        [int]$KcpResend = 2,
        [int]$KcpNoCongestion = 0,
        [int]$KcpSockBuf = 4194304,
        [int]$KcpSmuxBuf = 4194304
    )

    # Validate TCP flags (uppercase letters F,S,R,P,A,U,E,C, optionally comma-separated)
    if ($TcpLocalFlag -cnotmatch '^[FSRPAUEC]+(,[FSRPAUEC]+)*$') {
        Write-Warn "Invalid TCP local flag. Using default: PA"
        $TcpLocalFlag = "PA"
    }
    if ($TcpRemoteFlag -cnotmatch '^[FSRPAUEC]+(,[FSRPAUEC]+)*$') {
        Write-Warn "Invalid TCP remote flag. Using default: PA"
        $TcpRemoteFlag = "PA"
    }

    switch ($KcpProfile.ToLower()) {
        "highloss" {
            $KcpConn = 4; $KcpMtu = 1300; $KcpSndWnd = 1024; $KcpRcvWnd = 1024
            $KcpNoDelay = 0; $KcpInterval = 20; $KcpResend = 2; $KcpNoCongestion = 0; $KcpSockBuf = 4194304; $KcpSmuxBuf = 4194304
        }
        "cdntunnel" {
            $KcpConn = 8; $KcpMtu = 1400; $KcpSndWnd = 2048; $KcpRcvWnd = 2048
            $KcpNoDelay = 0; $KcpInterval = 20; $KcpResend = 2; $KcpNoCongestion = 0; $KcpSockBuf = 8388608; $KcpSmuxBuf = 8388608
        }
        "gaming" {
            $KcpConn = 2; $KcpMtu = 1200; $KcpSndWnd = 512; $KcpRcvWnd = 512
            $KcpNoDelay = 1; $KcpInterval = 10; $KcpResend = 2; $KcpNoCongestion = 1; $KcpSockBuf = 4194304; $KcpSmuxBuf = 4194304
        }
    }

    Write-Info "Detecting network..."
    $net = Get-NetworkInfo
    if (-not $net) { return $false }

    Write-Info "  Adapter:     $($net.Name)"
    Write-Info "  Local IP:    $($net.IP)"
    Write-Info "  Gateway MAC: $($net.GatewayMAC)"

    if (-not $net.GatewayMAC) {
        $net.GatewayMAC = Read-Host "  Enter gateway MAC (aa:bb:cc:dd:ee:ff)"
    }

    # Convert comma-separated flags to YAML array format: PA,A -> ["PA", "A"]
    $localFlagArray = ($TcpLocalFlag -split ',') | ForEach-Object { "`"$_`"" }
    $remoteFlagArray = ($TcpRemoteFlag -split ',') | ForEach-Object { "`"$_`"" }
    $localFlagYaml = "[" + ($localFlagArray -join ", ") + "]"
    $remoteFlagYaml = "[" + ($remoteFlagArray -join ", ") + "]"

    $guidEscaped = "\\Device\\NPF_$($net.Guid)"

    $routingSection = ""
    if ($RoutingMode -eq "forward") {
        $routingSection = @"
forward:
  - listen: "0.0.0.0:$ForwardPort"
    target: "$ForwardTarget"
"@
    } else {
        $routingSection = @"
socks5:
  - listen: "127.0.0.1:$SocksPort"
"@
    }

    $config = @"
role: "client"

log:
  level: "info"

$routingSection

network:
  interface: "$($net.Name)"
  guid: "$guidEscaped"
  ipv4:
    addr: "$($net.IP):0"
    router_mac: "$($net.GatewayMAC)"
  tcp:
    local_flag: $localFlagYaml
    remote_flag: $remoteFlagYaml

server:
  addr: "$Server"

transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "$SecretKey"
    conn: $KcpConn
    mtu: $KcpMtu
    sndwnd: $KcpSndWnd
    rcvwnd: $KcpRcvWnd
    nodelay: $KcpNoDelay
    interval: $KcpInterval
    resend: $KcpResend
    nocongestion: $KcpNoCongestion
    sockbuf: $KcpSockBuf
    smuxbuf: $KcpSmuxBuf
"@

    # Ensure install directory exists
    if (-not (Test-Path $InstallDir)) {
        Write-Err "Paqet is not installed. Please install paqet first (option 1)."
        return $false
    }

    [System.IO.File]::WriteAllText($ConfigFile, $config)
    Save-Settings -Backend "paqet" -ServerAddr $Server -SocksPort $SocksPort -RoutingMode $RoutingMode -ForwardPort $ForwardPort -ForwardTarget $ForwardTarget -KcpProfile $KcpProfile
    Write-Success "Configuration saved"
    return $true
}

function Start-Paqet {
    Remove-Item -Path "$InstallDir\.stopped" -Force -ErrorAction SilentlyContinue 2>$null
    if (-not (Test-Npcap)) {
        if (-not (Install-NpcapIfMissing)) { return }
    }

    if (-not (Test-Path $PaqetExe)) {
        Write-Err "paqet not installed"
        return
    }

    if (-not (Test-Path $ConfigFile)) {
        Write-Err "Config not found. Configure first."
        return
    }

    $installedVer = Get-InstalledPaqetVersion
    if ($installedVer -and $installedVer -ne $PaqetVersion) {
        Write-Warn "Notice: Installed paqet ($installedVer) differs from latest release ($PaqetVersion)."
        Write-Info "If you experience connection issues after a server update, use Option 7 (Update paqet)."
        Write-Host ""
    }

    Write-Host ""
    Write-Host "  Starting PAQET" -ForegroundColor Green
    Write-Host "  ──────────────"
    Write-Host "  Paqet will connect to your server using KCP over raw sockets."
    Write-Host ""
    Write-Host "  Your SOCKS5 proxy will be: 127.0.0.1:1080"
    Write-Host "  Configure your browser to use this proxy."
    Write-Host ""
    Write-Info "Starting paqet..."
    Write-Info "SOCKS5 proxy: 127.0.0.1:1080"
    Write-Info "Press Ctrl+C to stop"
    Write-Host ""

    & $PaqetExe run -c $ConfigFile
}

#═══════════════════════════════════════════════════════════════════════
# GFW-knocker Functions
#═══════════════════════════════════════════════════════════════════════

function Install-Gfk {
    Write-Host ""
    Write-Host "  Installing GFW-KNOCKER" -ForegroundColor Yellow
    Write-Host "  ──────────────────────" -ForegroundColor Yellow
    Write-Host "  GFK is an advanced anti-censorship tool designed for heavy DPI."
    Write-Host "  It uses 'violated TCP' packets + QUIC tunneling to evade detection."
    Write-Host ""
    Write-Host "  What will be installed:" -ForegroundColor Yellow
    Write-Host "    1. Npcap (for raw socket access)"
    Write-Host "    2. Python 3.10+ (for QUIC protocol)"
    Write-Host "    3. Python packages: scapy, aioquic"
    Write-Host "    4. GFK client scripts"
    Write-Host ""
    Write-Host "  IMPORTANT: Your server must have Xray running on port 443." -ForegroundColor Cyan
    Write-Host "  GFK is just a tunnel - Xray provides the actual SOCKS5 proxy."
    Write-Host ""
    Write-Host "  After setup, your proxy will be: 127.0.0.1:14000 (SOCKS5)"
    Write-Host ""

    # Check prerequisites
    if (-not (Install-NpcapIfMissing)) { return $false }
    if (-not (Install-PythonIfMissing)) { return $false }
    if (-not (Install-PythonPackages)) { return $false }

    # Create directories
    if (-not (Test-Path $GfkDir)) {
        New-Item -ItemType Directory -Path $GfkDir -Force | Out-Null
    }

    # Copy bundled GFK scripts or download from GitHub
    Write-Info "Setting up GFW-knocker scripts..."
    $GfkGitHubBase = "https://raw.githubusercontent.com/SamNet-dev/paqctl/main/gfk/client"
    foreach ($file in $GfkFiles) {
        $dest = "$GfkDir\$file"
        $src = if ($GfkLocalDir) { "$GfkLocalDir\$file" } else { $null }

        if ($src -and (Test-Path $src)) {
            # Copy from local bundled files (faster)
            Copy-Item -Path $src -Destination $dest -Force
            Write-Info "  Copied $file"
        } else {
            # Download from GitHub (for one-liner installation)
            Write-Info "  Downloading $file..."
            try {
                Invoke-WebRequest -Uri "$GfkGitHubBase/$file" -OutFile $dest -UseBasicParsing
                Write-Info "  Downloaded $file"
            } catch {
                Write-Err "Failed to download $file from GitHub"
                return $false
            }
        }
    }

    Write-Success "GFW-knocker installed to $GfkDir"
    Save-Settings -Backend "gfk"
    return $true
}

function New-GfkConfig {
    param(
        [Parameter(Mandatory)][string]$ServerIP,
        [Parameter(Mandatory)][string]$AuthCode,
        [string]$SocksPort = "1080",
        [string]$TcpFlags = "AP"
    )

    # Validate inputs (security: prevent config injection)
    if (-not (Test-ValidIP $ServerIP)) {
        Write-Err "Invalid server IP format"
        return $false
    }
    if (-not (Test-SafeString $AuthCode)) {
        Write-Err "Invalid auth code format"
        return $false
    }
    # Validate TCP flags (uppercase letters only: F,S,R,P,A,U,E,C)
    if ($TcpFlags -cnotmatch '^[FSRPAUEC]+$') {
        Write-Warn "Invalid TCP flags. Using default: AP"
        $TcpFlags = "AP"
    }

    Write-Info "Detecting network..."
    $net = Get-NetworkInfo
    if (-not $net) { return $false }

    Write-Info "  Adapter:  $($net.Name)"
    Write-Info "  Local IP: $($net.IP)"
    Write-Info "  Gateway:  $($net.GatewayMAC)"

    if (-not $net.GatewayMAC) {
        $net.GatewayMAC = Read-Host "  Enter gateway MAC (aa:bb:cc:dd:ee:ff)"
    }

    # Validate detected network values
    if (-not (Test-ValidIP $net.IP)) {
        Write-Err "Invalid local IP detected"
        return $false
    }
    if ($net.GatewayMAC -and -not (Test-ValidMAC $net.GatewayMAC)) {
        Write-Err "Invalid gateway MAC format"
        return $false
    }

    $quicMtu = Get-Setting -Key "KCP_MTU" -DefaultValue "1350"
    # Create parameters.py for GFK (matching expected variable names)
    $params = @"
# GFW-knocker client configuration (auto-generated)
from scapy.all import conf

# Network interface for scapy (Windows Npcap)
conf.iface = r"\Device\NPF_$($net.Guid)"
my_ip = "$($net.IP)"
gateway_mac = "$($net.GatewayMAC)"

# Server settings
vps_ip = "$ServerIP"
xray_server_ip = "127.0.0.1"

# Port mappings (local_port: remote_port)
tcp_port_mapping = {14000: 443}
udp_port_mapping = {}

# VIO (raw socket) ports
vio_tcp_server_port = 45000
vio_tcp_client_port = 40000
vio_udp_server_port = 35000
vio_udp_client_port = 30000

# QUIC tunnel ports
quic_server_port = 25000
quic_client_port = 20000
quic_local_ip = "127.0.0.1"

# QUIC settings
quic_verify_cert = False
quic_idle_timeout = 86400
udp_timeout = 300
quic_mtu = $quicMtu
quic_max_data = 1073741824
quic_max_stream_data = 1073741824
quic_auth_code = "$AuthCode"
quic_certificate = "cert.pem"
quic_private_key = "key.pem"

# TCP flags for violated packets (default: AP = ACK+PSH)
tcp_flags = "$TcpFlags"

# SOCKS proxy
socks_port = $SocksPort
"@

    # Ensure GFK directory exists
    if (-not (Test-Path $GfkDir)) {
        Write-Err "GFK is not installed. Please install GFK first (option 2)."
        return $false
    }

    [System.IO.File]::WriteAllText("$GfkDir\parameters.py", $params)
    Save-Settings -Backend "gfk" -ServerAddr $ServerIP -SocksPort $SocksPort
    Write-Success "GFK configuration saved"
    return $true
}

function Start-Gfk {
    Remove-Item -Path "$InstallDir\.stopped" -Force -ErrorAction SilentlyContinue 2>$null
    if (-not (Test-Npcap)) {
        if (-not (Install-NpcapIfMissing)) { return }
    }

    if (-not (Test-Python)) {
        Write-Err "Python not found"
        return
    }

    if (-not (Test-Path "$GfkDir\mainclient.py")) {
        Write-Err "GFK not installed"
        return
    }

    if (-not (Test-Path "$GfkDir\parameters.py")) {
        Write-Err "GFK not configured"
        return
    }

    Write-Host ""
    Write-Host "  Starting GFW-KNOCKER" -ForegroundColor Yellow
    Write-Host "  ────────────────────"
    Write-Host "  This will start:"
    Write-Host "    1. VIO client (raw socket handler)"
    Write-Host "    2. QUIC client (tunnel to server)"
    Write-Host ""
    Write-Host "  Your SOCKS5 proxy will be: 127.0.0.1:14000"
    Write-Host "  Configure your browser to use this proxy."
    Write-Host ""
    Write-Info "Starting GFW-knocker client..."
    Write-Info "This will start the raw socket client + Python SOCKS5 proxy"
    Write-Info "Press Ctrl+C to stop"
    Write-Host ""

    # Start GFK client
    Push-Location $GfkDir
    try {
        & python mainclient.py
    } finally {
        Pop-Location
    }
}

function Stop-GfkClient {
    New-Item -Path "$InstallDir\.stopped" -ItemType File -Force 2>$null | Out-Null
    # Get-Process doesn't have CommandLine property - use CIM instead
    $procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
             Where-Object { $_.CommandLine -match "mainclient|quic_client|vio_client|gfk" }
    if ($procs) {
        $procs | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Success "GFK client stopped"
    } else {
        Write-Info "GFK client not running"
    }
}

#═══════════════════════════════════════════════════════════════════════
# Common Functions
#═══════════════════════════════════════════════════════════════════════

function Stop-Client {
    New-Item -Path "$InstallDir\.stopped" -ItemType File -Force 2>$null | Out-Null
    # Stop paqet
    $paqetProc = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
    if ($paqetProc) {
        Stop-Process -Name "paqet_windows_amd64" -Force
        Write-Success "paqet stopped"
    }

    # Stop GFK
    Stop-GfkClient
}

function Get-ClientStatus {
    Write-Host "`n=== Client Status ===" -ForegroundColor Cyan

    $backend = Get-InstalledBackend
    Write-Host "Backend: $(if ($backend) { $backend } else { 'Not installed' })"

    # Npcap
    if (Test-Npcap) {
        Write-Success "Npcap: Installed"
    } else {
        Write-Err "Npcap: NOT installed"
    }

    # Python (for GFK)
    if ($backend -eq "gfk" -or -not $backend) {
        if (Test-Python) {
            Write-Success "Python: Installed"
        } else {
            Write-Warn "Python: Not found (needed for GFK)"
        }
    }

    # Paqet
    if (Test-Path $PaqetExe) {
        Write-Success "Paqet binary: Found"
    }

    # GFK
    if (Test-Path "$GfkDir\mainclient.py") {
        Write-Success "GFK scripts: Found"
    }

    # Config
    if (Test-Path $ConfigFile) {
        Write-Success "Paqet config: Found"
    }
    if (Test-Path "$GfkDir\parameters.py") {
        Write-Success "GFK config: Found"
    }

    # Running processes
    $paqetRunning = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
    if ($paqetRunning) {
        Write-Success "Paqet: RUNNING (PID: $($paqetRunning.Id))"
        Write-Info "  SOCKS5 proxy: 127.0.0.1:1080"
    }
    $gfkRunning = Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
                  Where-Object { $_.CommandLine -match "mainclient|quic_client|vio_client" }
    if ($gfkRunning) {
        $pids = ($gfkRunning | Select-Object -ExpandProperty ProcessId) -join ", "
        Write-Success "GFK: RUNNING (PIDs: $pids)"
        Write-Info "  SOCKS5 proxy: 127.0.0.1:14000"
    }
    if (-not $paqetRunning -and -not $gfkRunning) {
        Write-Warn "Status: STOPPED (neither Paqet nor GFK is running)"
    }

    Write-Host ""
}

#═══════════════════════════════════════════════════════════════════════
# Update Function
#═══════════════════════════════════════════════════════════════════════

function Get-InstalledPaqetVersion {
    if (Test-Path $PaqetExe) {
        try {
            $output = & $PaqetExe version 2>&1 | Out-String
            if ($output -match 'Version:\s+([^\r\n]+)') {
                return $Matches[1].Trim()
            }
        } catch {}
    }
    # Check settings file as backup
    if (Test-Path $SettingsFile) {
        $content = Get-Content $SettingsFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match '^PAQET_VERSION="?([^"]+)"?') {
                return $Matches[1]
            }
        }
    }
    return $null
}

function Save-PaqetVersion {
    param([string]$Version)

    if (-not (Test-Path $SettingsFile)) {
        return
    }

    $content = Get-Content $SettingsFile -Raw -ErrorAction SilentlyContinue
    if ($content -match 'PAQET_VERSION=') {
        # Update existing
        $content = $content -replace 'PAQET_VERSION="[^"]*"', "PAQET_VERSION=`"$Version`""
    } else {
        # Add new line
        $content = $content.TrimEnd() + "`nPAQET_VERSION=`"$Version`""
    }
    [System.IO.File]::WriteAllText($SettingsFile, $content)
}

function Update-Paqet {
    Write-Host ""
    Write-Host "  CHECKING FOR UPDATES" -ForegroundColor Cyan
    Write-Host "  ────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Check if paqet is installed
    if (-not (Test-Path $PaqetExe)) {
        Write-Warn "Paqet is not installed. Use option 1 to install first."
        return $false
    }

    # Get installed version
    $installedVersion = Get-InstalledPaqetVersion
    if (-not $installedVersion) {
        $installedVersion = $PaqetVersion
    }

    # Query GitHub API for latest release
    Write-Info "Querying GitHub for latest release..."
    try {
        $apiUrl = "https://api.github.com/repos/hanselime/paqet/releases/latest"
        $response = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 30
        $latestVersion = $response.tag_name
    } catch {
        Write-Err "Failed to check for updates: $_"
        return $false
    }

    # Show version info
    Write-Host ""
    Write-Host "  Installed version:  $installedVersion" -ForegroundColor White
    Write-Host "  Latest version:     $latestVersion" -ForegroundColor White
    Write-Host ""

    # Compare versions
    if ($installedVersion -eq $latestVersion) {
        Write-Success "You are already on the latest version!"
        return $true
    }

    # Confirm update
    Write-Host "  A new version is available!" -ForegroundColor Yellow
    $confirm = Read-Host "  Update to $latestVersion? [y/N]"
    if ($confirm -notmatch "^[Yy]") {
        Write-Info "Update cancelled"
        return $false
    }

    # Stop running paqet first
    $paqetProc = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
    if ($paqetProc) {
        Write-Info "Stopping paqet..."
        Stop-Process -Name "paqet_windows_amd64" -Force
        Start-Sleep -Seconds 2
    }

    # Download new version
    $zipUrl = "https://github.com/hanselime/paqet/releases/download/$latestVersion/paqet-windows-amd64-$latestVersion.zip"
    $zipFile = "$env:TEMP\paqet-update.zip"
    $extractDir = "$env:TEMP\paqet-update"

    Write-Info "Downloading paqet $latestVersion..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -TimeoutSec 120
    } catch {
        Write-Err "Download failed: $_"
        return $false
    }

    # Validate download
    if (-not (Test-Path $zipFile) -or (Get-Item $zipFile).Length -lt 1000) {
        Write-Err "Downloaded file is invalid or too small"
        return $false
    }

    # Extract
    Write-Info "Extracting..."
    try {
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
        Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force
    } catch {
        Write-Err "Extraction failed: $_"
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        return $false
    }

    # Find the binary
    $newBinary = Get-ChildItem -Path $extractDir -Filter "paqet_windows_amd64.exe" -Recurse | Select-Object -First 1
    if (-not $newBinary) {
        Write-Err "Could not find paqet binary in archive"
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }

    # Backup old binary
    $backupPath = "$InstallDir\paqet_windows_amd64.exe.bak"
    try {
        Copy-Item $PaqetExe $backupPath -Force
        Write-Info "Backed up old binary"
    } catch {
        Write-Warn "Could not backup old binary: $_"
    }

    # Install new binary
    try {
        Copy-Item $newBinary.FullName $PaqetExe -Force
    } catch {
        Write-Err "Failed to install new binary: $_"
        # Try to restore backup
        if (Test-Path $backupPath) {
            Copy-Item $backupPath $PaqetExe -Force -ErrorAction SilentlyContinue
        }
        return $false
    }

    # Save version to settings
    Save-PaqetVersion -Version $latestVersion

    # Cleanup
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Success "Updated to $latestVersion!"
    Write-Host ""
    Write-Info "Restart the client to use the new version"
    Write-Host ""

    return $true
}

function Test-ServerConnection {
    $backend = Get-InstalledBackend
    if (-not $backend) {
        Write-Warn "Install a backend first (option 1 or 2)"
        return
    }

    Write-Host ""
    Write-Host "  TESTING SERVER CONNECTION" -ForegroundColor Cyan
    Write-Host "  -------------------------" -ForegroundColor Cyan
    Write-Host ""

    if ($backend -eq "paqet") {
        if (-not (Test-Path $PaqetExe)) {
            Write-Err "paqet not installed"
            return
        }
        if (-not (Test-Path $ConfigFile)) {
            Write-Err "Config not found. Configure first (option 3)."
            return
        }
        Write-Info "Sending test ping via paqet..."
        try {
            & $PaqetExe ping -c $ConfigFile
        } catch {
            Write-Err "Ping failed: $_"
        }
    } else {
        if (-not (Test-Path "$GfkDir\parameters.py")) {
            Write-Err "GFK config not found. Configure first (option 3)."
            return
        }
        $serverIP = ""
        Get-Content "$GfkDir\parameters.py" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '(?:vps_ip|REMOTE_HOST)\s*=\s*["'']?([0-9a-zA-Z\.\-]+)["'']?') {
                $serverIP = $Matches[1]
            }
        }
        if (-not $serverIP) {
            Write-Err "Could not read server IP from parameters.py"
            return
        }
        Write-Info "Testing basic TCP reachability to GFK server ($serverIP:443)..."
        try {
            $tcp = Test-NetConnection -ComputerName $serverIP -Port 443 -WarningAction SilentlyContinue
            if ($tcp.TcpTestSucceeded) {
                Write-Success "TCP connection to $serverIP:443 succeeded!"
            } else {
                Write-Err "TCP connection to $serverIP:443 failed. Server or port may be blocked/offline."
            }
        } catch {
            Write-Err "Connection test failed: $_"
        }
    }
    Write-Host ""
}

function Test-ProxyRouting {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  DNS LEAK & PROXY ROUTING VERIFICATION" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    $backend = Get-InstalledBackend
    $socksPort = if ($backend -eq "gfk") { "14000" } else { "1080" }
    
    Write-Info "1. Checking Direct Public IP (ISP)..."
    try {
        $directIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 5 -ErrorAction Stop)
        Write-Host "   Direct IP: " -NoNewline; Write-Host "$directIP" -ForegroundColor Yellow
    } catch {
        Write-Err "Could not fetch direct IP: $_"
        $directIP = "failed"
    }
    Write-Host ""
    
    Write-Info "2. Checking Proxy Tunnel IP (via SOCKS5 127.0.0.1:$socksPort)..."
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        try {
            $proxyIP = (& curl.exe -s --max-time 8 --socks5-hostname "127.0.0.1:$socksPort" "https://api.ipify.org")
            if (-not $proxyIP) {
                Write-Err "Proxy tunnel did not respond on port $socksPort. Is the client running?"
            } elseif ($proxyIP -eq $directIP -and $directIP -ne "failed") {
                Write-Host "   Proxy IP: " -NoNewline; Write-Host "$proxyIP" -ForegroundColor Yellow
                Write-Warn "Proxy IP matches direct IP! Check if proxy is connected."
            } else {
                Write-Host "   Proxy IP: " -NoNewline; Write-Host "$proxyIP" -ForegroundColor Green
                Write-Success "Proxy routing verified! Traffic is tunneling properly."
            }
        } catch {
            Write-Err "Proxy test failed: $_"
        }
        Write-Host ""
        Write-Info "3. Checking DNS Resolution via Proxy Tunnel..."
        try {
            $dnsJson = (& curl.exe -s --max-time 8 --socks5-hostname "127.0.0.1:$socksPort" "https://edns.ip-api.com/json") | ConvertFrom-Json
            if ($dnsJson.dns.ip) {
                Write-Host "   DNS Resolver IP: " -NoNewline; Write-Host "$($dnsJson.dns.ip)" -ForegroundColor Green
                Write-Success "No DNS leaks detected via socks5-hostname resolution!"
            }
        } catch {
            Write-Warn "Could not reach DNS leak test endpoint."
        }
    } else {
        Write-Warn "curl.exe not found on Windows. Cannot test SOCKS5 proxy routing."
    }
    Write-Host ""
}

function Test-ServerSpeed {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  SERVER SPEED & BANDWIDTH TEST" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    $backend = Get-InstalledBackend
    $socksPort = if ($backend -eq "gfk") { "14000" } else { "1080" }
    
    Write-Info "Testing download speed over proxy tunnel (127.0.0.1:$socksPort)..."
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        try {
            & curl.exe -o NUL --progress-bar --socks5-hostname "127.0.0.1:$socksPort" -w "  Download Speed: %{speed_download} bytes/sec (Time: %{time_total}s)\n" "https://speed.cloudflare.com/__down?bytes=25000000"
        } catch {
            Write-Err "Speed test failed. Ensure your proxy client is running and connected."
        }
    } else {
        Write-Warn "curl.exe not found. Cannot perform speed test."
    }
    Write-Host ""
}

function Manage-ConfigString {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  CONFIG IMPORT / EXPORT STRING" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Export current config to string"
    Write-Host "  2. Import config from string"
    Write-Host "  b. Back"
    Write-Host ""
    $opt = Read-Host "  Select option"
    if ($opt -eq "1") {
        $backend = Get-InstalledBackend
        if ($backend -eq "paqet") {
            if (-not (Test-Path $ConfigFile)) { Write-Err "Config file not found."; return }
            $content = Get-Content $ConfigFile -Raw
            $server = ""; $key = ""
            if ($content -match 'server:\s*["'']?([^"''\s]+)["'']?') { $server = $Matches[1] }
            if ($content -match 'key:\s*["'']?([^"''\s]+)["'']?') { $key = $Matches[1] }
            if (-not $server -or -not $key) { Write-Err "Could not parse server/key from config."; return }
            $rmode = Get-Setting -Key "ROUTING_MODE" -DefaultValue "socks5"
            $fport = Get-Setting -Key "FORWARD_PORT" -DefaultValue "14000"
            $ftgt = Get-Setting -Key "FORWARD_TARGET" -DefaultValue "127.0.0.1:80"
            $prof = Get-Setting -Key "KCP_PROFILE" -DefaultValue "standard"
            $ip = $server; $port = "8443"
            if ($server -match '^([0-9a-zA-Z\.\-_]+|\[[0-9a-fA-F:]+\]):([0-9]+)$') {
                $ip = $Matches[1]; $port = $Matches[2]
            }
            $socksPort = Get-Setting -Key "SOCKS_PORT" -DefaultValue "1080"
            $raw = "paqet|$ip|$port|$key|$socksPort|$rmode|$fport|$ftgt|$prof"
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($raw))
            Write-Host "  Shareable Paqet String (v2 format):" -ForegroundColor White
            Write-Host "  paqet://$b64" -ForegroundColor Green
        } elseif ($backend -eq "gfk") {
            if (-not (Test-Path "$GfkDir\parameters.py")) { Write-Err "GFK config not found."; return }
            $server = ""; $auth = ""
            Get-Content "$GfkDir\parameters.py" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_ -match '(?:vps_ip|REMOTE_HOST)\s*=\s*["'']?([0-9a-zA-Z\.\-]+)["'']?') { $server = $Matches[1] }
                if ($_ -match '(?:quic_auth_code|AUTH_CODE)\s*=\s*b?["'']([^"'']+)["'']') { $auth = $Matches[1] }
            }
            if (-not $server -or -not $auth) { Write-Err "Could not parse server/auth from GFK config."; return }
            $raw = "gfk|$server|$auth|14000:443|14000"
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($raw))
            Write-Host "  Shareable GFK String:" -ForegroundColor White
            Write-Host "  gfk://$b64" -ForegroundColor Green
        } else {
            Write-Warn "No active backend installed."
        }
    } elseif ($opt -eq "2") {
        $str = Read-Host "  Paste config string (paqet://... or gfk://...)"
        if (-not $str) { return }
        if ($str -match '^paqet://(.+)$') {
            $b64 = $Matches[1].Trim() -replace '-', '+' -replace '_', '/'
            switch ($b64.Length % 4) { 2 { $b64 += "==" } 3 { $b64 += "=" } }
            try {
                $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
            } catch { Write-Err "Invalid or corrupted base64 string."; return }
            $parts = $decoded -split '\|'
            if ($parts.Length -lt 3 -or $parts[0] -ne "paqet") { Write-Err "Invalid paqet string."; return }
            if ($parts[1] -match '^([0-9a-zA-Z\.\-_]+|\[[0-9a-fA-F:]+\]):([0-9]+)$') {
                # 8-part combined format: paqet|IP:PORT|KEY|SOCKS|RMODE|FPORT|FTGT|PROF
                $server = $parts[1]; $key = $parts[2]
                $socks = if ($parts.Length -gt 3 -and $parts[3]) { $parts[3] } else { "1080" }
                $rmode = if ($parts.Length -gt 4 -and $parts[4]) { $parts[4] } else { "socks5" }
                $fport = if ($parts.Length -gt 5 -and $parts[5]) { $parts[5] } else { "14000" }
                $ftgt = if ($parts.Length -gt 6 -and $parts[6]) { $parts[6] } else { "127.0.0.1:80" }
                $prof = if ($parts.Length -gt 7 -and $parts[7]) { $parts[7] } else { "standard" }
            } else {
                # 9-part separate format: paqet|IP|PORT|KEY|SOCKS|RMODE|FPORT|FTGT|PROF
                $server = "$($parts[1]):$($parts[2])"; $key = $parts[3]
                $socks = if ($parts.Length -gt 4 -and $parts[4]) { $parts[4] } else { "1080" }
                $rmode = if ($parts.Length -gt 5 -and $parts[5]) { $parts[5] } else { "socks5" }
                $fport = if ($parts.Length -gt 6 -and $parts[6]) { $parts[6] } else { "14000" }
                $ftgt = if ($parts.Length -gt 7 -and $parts[7]) { $parts[7] } else { "127.0.0.1:80" }
                $prof = if ($parts.Length -gt 8 -and $parts[8]) { $parts[8] } else { "standard" }
            }

            Write-Info "Importing Paqet config ($server)..."
            if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
            New-PaqetConfig -Server $server -SecretKey $key -RoutingMode $rmode -SocksPort $socks -ForwardPort $fport -ForwardTarget $ftgt -KcpProfile $prof | Out-Null
            Save-Settings -Backend "paqet" -ServerAddr $server -SocksPort $socks -RoutingMode $rmode -ForwardPort $fport -ForwardTarget $ftgt -KcpProfile $prof
            Write-Success "Paqet config imported! Starting service..."
            Start-Paqet
        } elseif ($str -match '^gfk://(.+)$') {
            $b64 = $Matches[1].Trim() -replace '-', '+' -replace '_', '/'
            switch ($b64.Length % 4) { 2 { $b64 += "==" } 3 { $b64 += "=" } }
            try {
                $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
            } catch { Write-Err "Invalid or corrupted base64 string."; return }
            $parts = $decoded -split '\|'
            if ($parts.Length -lt 3 -or $parts[0] -ne "gfk") { Write-Err "Invalid gfk string."; return }
            $server = $parts[1]; $auth = $parts[2]
            Write-Info "Importing GFK config ($server)..."
            if (New-GfkConfig -ServerIP $server -AuthCode $auth -SocksPort "14000" -TcpFlags "") {
                Write-Success "GFK config imported! Starting service..."
                Start-Gfk
            }
        } else {
            Write-Err "Unknown protocol prefix."
        }
    }
    Write-Host ""
}

function Clear-SystemCache {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  SYSTEM CLEANUP & CACHE FLUSH" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Info "Flushing Windows DNS Resolver Cache..."
    try {
        & ipconfig /flushdns | Out-Null
        Write-Success "DNS cache flushed successfully."
    } catch {
        Write-Err "Failed to flush DNS cache: $_"
    }
    Write-Info "Cleaning up temporary log files..."
    if (Test-Path "$InstallDir\*.log") {
        Remove-Item "$InstallDir\*.log" -Force -ErrorAction SilentlyContinue
        Write-Success "Old log files removed."
    }
    Write-Host ""
}

#═══════════════════════════════════════════════════════════════════════
# Paqet v1.1.0 Performance Tuning, Watchdog & Shortcuts
#═══════════════════════════════════════════════════════════════════════

function Apply-ClientConfig {
    $backend = Get-InstalledBackend
    if ($backend -eq "paqet") {
        $server = Get-Setting -Key "SERVER_ADDR"
        $key = ""
        if (Test-Path $ConfigFile) {
            $content = Get-Content $ConfigFile -Raw
            if ($content -match 'key:\s*["'']?([^"''\s]+)["'']?') { $key = $Matches[1] }
        }
        if (-not $server -or -not $key) { return }
        $rmode = Get-Setting -Key "ROUTING_MODE" -DefaultValue "socks5"
        $socks = Get-Setting -Key "SOCKS_PORT" -DefaultValue "1080"
        $fport = Get-Setting -Key "FORWARD_PORT" -DefaultValue "14000"
        $ftgt = Get-Setting -Key "FORWARD_TARGET" -DefaultValue "127.0.0.1:80"
        $prof = Get-Setting -Key "KCP_PROFILE" -DefaultValue "standard"
        New-PaqetConfig -Server $server -SecretKey $key -RoutingMode $rmode -SocksPort $socks -ForwardPort $fport -ForwardTarget $ftgt -KcpProfile $prof | Out-Null
    }
}

function Restart-ClientService {
    Write-Info "Restarting Client Service..."
    Stop-Client
    Start-Sleep -Seconds 1
    $backend = Get-InstalledBackend
    if ($backend -eq "paqet") { Start-Paqet } elseif ($backend -eq "gfk") { Start-Gfk }
}

function Select-PerformanceProfile {
    Write-Host ""
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "  PERFORMANCE PROFILE SELECTION" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "  Note: Select a profile that matches your network link quality."
    Write-Host ""
    Write-Host "  1) Standard / Balanced [DEFAULT - conn: 2, mtu: 1350]"
    Write-Host "     • Smart default for general internet uplinks and everyday usage."
    Write-Host ""
    Write-Host "  2) High-Loss / Restricted Uplink [conn: 4, wnd: 1024, mtu: 1300]"
    Write-Host "     • Optimized for restricted networks, severe packet loss, or heavy DPI."
    Write-Host ""
    Write-Host "  3) High-Throughput / CDN Tunnel [conn: 8, wnd: 2048, sockbuf: 8MB]"
    Write-Host "     • Maximized concurrency for multi-layer CDN routing or Gigabit fiber."
    Write-Host ""
    Write-Host "  4) Low-Latency / Gaming & VOIP [conn: 2, mtu: 1200, nodelay: 1]"
    Write-Host "     • Ultra-fast response times for real-time applications."
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host ""
    $pChoice = Read-Host "  Select Profile [1-4, default: 1]"
    if (-not $pChoice) { $pChoice = "1" }
    $profile = "standard"; $conn = "2"; $mtu = "1350"; $sndwnd = "1024"; $rcvwnd = "1024"
    $nodelay = "0"; $interval = "20"; $resend = "2"; $nocongestion = "0"; $sockbuf = "4194304"; $smuxbuf = "4194304"
    switch ($pChoice) {
        "2" {
            $profile = "highloss"; $conn = "4"; $mtu = "1300"; $sndwnd = "1024"; $rcvwnd = "1024"
            $nodelay = "0"; $interval = "20"; $resend = "2"; $nocongestion = "0"; $sockbuf = "4194304"; $smuxbuf = "4194304"
        }
        "3" {
            $profile = "cdntunnel"; $conn = "8"; $mtu = "1400"; $sndwnd = "2048"; $rcvwnd = "2048"
            $nodelay = "0"; $interval = "20"; $resend = "2"; $nocongestion = "0"; $sockbuf = "8388608"; $smuxbuf = "8388608"
        }
        "4" {
            $profile = "gaming"; $conn = "2"; $mtu = "1200"; $sndwnd = "512"; $rcvwnd = "512"
            $nodelay = "1"; $interval = "10"; $resend = "2"; $nocongestion = "1"; $sockbuf = "4194304"; $smuxbuf = "4194304"
        }
    }
    Save-Settings -Backend (Get-InstalledBackend) -KcpProfile $profile
    $existing = @{}
    if (Test-Path $SettingsFile) {
        Get-Content $SettingsFile -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^([^=]+)="?(.*)"?$') { $existing[$Matches[1]] = $Matches[2] }
        }
    }
    $existing["KCP_PROFILE"] = $profile; $existing["KCP_CONN"] = $conn; $existing["KCP_MTU"] = $mtu
    $existing["KCP_SNDWND"] = $sndwnd; $existing["KCP_RCVWND"] = $rcvwnd; $existing["KCP_NODELAY"] = $nodelay
    $existing["KCP_INTERVAL"] = $interval; $existing["KCP_RESEND"] = $resend; $existing["KCP_NOCONGESTION"] = $nocongestion
    $existing["KCP_SOCKBUF"] = $sockbuf; $existing["KCP_SMUXBUF"] = $smuxbuf
    $lines = @()
    foreach ($key in $existing.Keys) { $lines += "$key=`"$($existing[$key])`"" }
    [System.IO.File]::WriteAllLines($SettingsFile, $lines)
    Write-Info "Performance Profile set to: $profile"
}

function Find-OptimalMtu {
    Write-Info "Running Smart MTU Auto-Discovery..."
    $server = Get-Setting -Key "SERVER_ADDR" -DefaultValue "8.8.8.8"
    $target = ($server -split ':')[0]
    if (-not $target) { $target = "8.8.8.8" }
    Write-Info "  Testing path MTU to $target..."
    $mtu = 1500
    $found = 0
    while ($mtu -ge 1200) {
        $bufferSize = $mtu - 28
        $res = ping -n 1 -w 1000 -f -l $bufferSize $target 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and ($res -match "TTL=|ttl=|time=|Reply from|bytes=$bufferSize")) {
            $found = $mtu
            break
        }
        $mtu -= 20
    }
    Write-Host ""
    if ($found -eq 0) {
        Write-Warn "ICMP ping blocked by network or firewall. Defaulting to safe MTU: 1350"
        $found = 1350
    } else {
        Write-Host "  Physical path MTU detected: " -NoNewline; Write-Host "$found" -ForegroundColor Green
        if ($found -gt 150) { $found = $found - 150 } else { $found = 1350 }
        Write-Host "  Applying Safe Tunnel MTU:   " -NoNewline; Write-Host "$found" -ForegroundColor Cyan
    }
    Write-Host "  (Reserved 150 bytes for KCP/AEAD encapsulation overhead to prevent 'Message too large' errors)" -ForegroundColor DarkGray
    $existing = @{}
    if (Test-Path $SettingsFile) {
        Get-Content $SettingsFile -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^([^=]+)="?(.*)"?$') { $existing[$Matches[1]] = $Matches[2] }
        }
    }
    $existing["KCP_MTU"] = "$found"
    $lines = @()
    foreach ($key in $existing.Keys) { $lines += "$key=`"$($existing[$key])`"" }
    [System.IO.File]::WriteAllLines($SettingsFile, $lines)
}

function Toggle-WindowsTurbo {
    $turbo = Get-Setting -Key "TURBO_ENABLED" -DefaultValue "false"
    if ($turbo -eq "true") {
        Write-Info "Disabling Windows Turbo Mode..."
        netsh int tcp set global autotuninglevel=normal 2>$null
        netsh int tcp set global ecncapability=disabled 2>$null
        netsh int tcp set global timestamps=disabled 2>$null
        Save-Settings -Backend (Get-InstalledBackend) -TurboEnabled "false"
        Write-Info "Windows Turbo Mode disabled."
    } else {
        Write-Info "Enabling Windows Turbo Mode (TCP Window Scaling & ECN)..."
        netsh int tcp set global autotuninglevel=experimental 2>$null
        if ($LASTEXITCODE -ne 0) { netsh int tcp set global autotuninglevel=restricted 2>$null }
        netsh int tcp set global ecncapability=enabled 2>$null
        netsh int tcp set global timestamps=enabled 2>$null
        netsh int tcp set global fastopen=enabled 2>$null
        Save-Settings -Backend (Get-InstalledBackend) -TurboEnabled "true"
        Write-Host "  Windows Turbo Mode enabled! TCP Auto-Tuning and ECN active." -ForegroundColor Green
    }
}

function Toggle-Watchdog {
    $watchdog = Get-Setting -Key "WATCHDOG_ENABLED" -DefaultValue "false"
    $taskName = "PaqetClientWatchdog"
    if ($watchdog -eq "true") {
        Write-Info "Disabling Auto-Reconnect Watchdog..."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Save-Settings -Backend (Get-InstalledBackend) -WatchdogEnabled "false"
        Write-Info "Watchdog disabled and scheduled task removed."
    } else {
        Write-Info "Enabling Auto-Reconnect Watchdog (Scheduled Task)..."
        $backend = Get-InstalledBackend
        if (-not $backend) {
            Write-Warn "No backend installed. Cannot enable watchdog."
            return
        }
        $scriptPath = "$PSScriptRoot\paqet-client.ps1"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -WatchdogCheck"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration ([TimeSpan]::MaxValue)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User "NT AUTHORITY\SYSTEM" -RunLevel Highest -Force 2>$null | Out-Null
        
        Save-Settings -Backend $backend -WatchdogEnabled "true"
        Write-Host "  Watchdog enabled! Windows will check health and auto-reconnect every 1m." -ForegroundColor Green
    }
}

function New-DesktopShortcut {
    Write-Info "Creating Desktop Shortcut..."
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = "$desktopPath\Paqet Client.lnk"
    $batPath = "$PSScriptRoot\Paqet-Client.bat"
    
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $batPath
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.Description = "Paqet/GFK Client Manager (v1.1.0)"
    $shortcut.Save()
    Write-Host "  Desktop shortcut created at: $shortcutPath" -ForegroundColor Green
}

function Show-TuningMenu {
    while ($true) {
        $profile = Get-Setting -Key "KCP_PROFILE" -DefaultValue "standard"
        $turbo = Get-Setting -Key "TURBO_ENABLED" -DefaultValue "false"
        $watchdog = Get-Setting -Key "WATCHDOG_ENABLED" -DefaultValue "false"
        $mtu = Get-Setting -Key "KCP_MTU" -DefaultValue "1350"
        $conn = Get-Setting -Key "KCP_CONN" -DefaultValue "2"

        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "  PERFORMANCE & SUPERCHARGING MENU (v1.1.0)" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Current Profile : " -NoNewline; Write-Host "$profile" -ForegroundColor Green -NoNewline; Write-Host " (conn: $conn, mtu: $mtu)"
        Write-Host "  Windows Turbo   : " -NoNewline; if ($turbo -eq "true") { Write-Host "ENABLED (TCP Window/Buffer Scaling)" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
        Write-Host "  Watchdog Monitor: " -NoNewline; if ($watchdog -eq "true") { Write-Host "ENABLED (Auto-Reconnect Task)" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  1. Select Performance Profile (Standard/High-Loss/CDN/Gaming)"
        Write-Host "  2. Run Smart MTU Auto-Discovery"
        Write-Host "  3. Toggle Windows Turbo Mode (TCP Auto-Tuning & Buffer Scaling)"
        Write-Host "  4. Toggle Auto-Reconnect Watchdog (Scheduled Task)"
        Write-Host "  5. Apply & Restart Client Service"
        Write-Host "  0. Back to Main Menu"
        Write-Host ""
        $choice = Read-Host "  Select option [1-5/0]"
        switch ($choice) {
            "1" { Select-PerformanceProfile; Apply-ClientConfig; Write-Info "Profile applied to config.yaml" }
            "2" { Find-OptimalMtu; Apply-ClientConfig; Write-Info "Optimal MTU applied to config.yaml" }
            "3" { Toggle-WindowsTurbo }
            "4" { Toggle-Watchdog }
            "5" { Apply-ClientConfig; Restart-ClientService }
            "0" { return }
            default { Write-Warn "Invalid option" }
        }
    }
}

function Show-ShortcutAndWatchdogMenu {
    while ($true) {
        $watchdog = Get-Setting -Key "WATCHDOG_ENABLED" -DefaultValue "false"
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "  DESKTOP SHORTCUT & AUTO-RECONNECT SETUP" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Watchdog Status : " -NoNewline; if ($watchdog -eq "true") { Write-Host "ENABLED (1m Auto-Reconnect Task)" -ForegroundColor Green } else { Write-Host "DISABLED" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  1. Create / Update Desktop Shortcut"
        Write-Host "  2. Toggle Auto-Reconnect Watchdog (Scheduled Task)"
        Write-Host "  0. Back to Main Menu"
        Write-Host ""
        $choice = Read-Host "  Select option [1-2/0]"
        switch ($choice) {
            "1" { New-DesktopShortcut }
            "2" { Toggle-Watchdog }
            "0" { return }
            default { Write-Warn "Invalid option" }
        }
    }
}

#═══════════════════════════════════════════════════════════════════════
# Interactive Menu
#═══════════════════════════════════════════════════════════════════════

function Show-Menu {
    param([string]$InitBackend = "")

    # Use passed backend parameter, or detect if not specified
    $backend = if ($InitBackend) { $InitBackend } else { Get-InstalledBackend }

    while ($true) {
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "  PAQET/GFK CLIENT MANAGER (v1.1.0)" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""
        if ($backend) {
            Write-Host "  Active backend: " -NoNewline
            Write-Host "$backend" -ForegroundColor Green
            if ($backend -eq "paqet") {
                Write-Host "  Proxy: 127.0.0.1:1080 (SOCKS5)" -ForegroundColor DarkGray
            } else {
                Write-Host "  Proxy: 127.0.0.1:14000 (SOCKS5 via tunnel)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  No backend installed yet" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  1. Install paqet        (simple, all-in-one SOCKS5)"
        Write-Host "  2. Install GFW-knocker  (advanced, for heavy DPI)"
        Write-Host "  3. Configure connection"
        Write-Host "  4. Start client"
        Write-Host "  5. Stop client"
        Write-Host "  6. Show status"
        Write-Host "  7. Test server connection (Ping)"
        Write-Host "  8. Update paqet"
        Write-Host "  9. About (how it works)"
        Write-Host "  10. Test DNS Leak & Proxy Routing"
        Write-Host "  11. Speed & Bandwidth Test"
        Write-Host "  12. Export / Import Config String"
        Write-Host "  13. System Cleanup & Cache Flush"
        Write-Host "  14. Performance & KCP Tuning Menu (v1.1.0)" -ForegroundColor Green
        Write-Host "  15. Desktop Shortcut & Auto-Reconnect Setup" -ForegroundColor Green
        Write-Host "  0. Exit"
        Write-Host ""

        $choice = Read-Host "  Select option"

        switch ($choice) {
            "1" {
                if (Install-Paqet) { $backend = "paqet" }
            }
            "2" {
                if (Install-Gfk) { $backend = "gfk" }
            }
            "3" {
                if (-not $backend) {
                    Write-Warn "Install a backend first (option 1 or 2)"
                    continue
                }

                if ($backend -eq "paqet") {
                    Write-Host ""
                    Write-Host "  PAQET CONFIGURATION" -ForegroundColor Green
                    Write-Host "  Get these values from your server admin or 'paqctl info' on server"
                    Write-Host ""
                    $server = Read-Host "  Server address (e.g., 1.2.3.4:8443)"
                    $key = Read-Host "  Encryption key (16+ chars)"

                    # Advanced options (hidden by default - just press Enter)
                    Write-Host ""
                    Write-Host "  Advanced options (press Enter for defaults - recommended):" -ForegroundColor DarkGray
                    Write-Host "    TCP flags must match your server config. Only change if server admin says so." -ForegroundColor DarkGray
                    Write-Host "    Valid flags: S A P R F U E C  |  Multiple: PA,A" -ForegroundColor DarkGray
                    $tcpLocal = Read-Host "  TCP local flag [PA]"
                    $tcpRemote = Read-Host "  TCP remote flag [PA]"
                    if (-not $tcpLocal) { $tcpLocal = "PA" }
                    if (-not $tcpRemote) { $tcpRemote = "PA" }

                    if ($server -and $key) {
                        Write-Host ""
                        Write-Host "====================================================================" -ForegroundColor Cyan
                        Write-Host "  ROUTING MODE SELECTION" -ForegroundColor Cyan
                        Write-Host "====================================================================" -ForegroundColor Cyan
                        Write-Host "  Note: Choose how traffic is handled across your proxy tunnel."
                        Write-Host ""
                        Write-Host "  1) SOCKS5 Proxy Mode [DEFAULT - Recommended for most users]"
                        Write-Host "     • Creates a standard all-in-one SOCKS5 proxy on port 1080."
                        Write-Host "     • Best for direct browser browsing, Telegram, and general apps."
                        Write-Host ""
                        Write-Host "  2) Direct Port Forwarding Mode [For advanced server-to-server setups]"
                        Write-Host "     • Forwards raw TCP/UDP traffic directly without SOCKS5 overhead."
                        Write-Host "     • Best for connecting backend Xray/sing-box panels or CDN tunnels."
                        Write-Host "====================================================================" -ForegroundColor Cyan
                        Write-Host ""
                        $rChoice = Read-Host "  Select Routing Mode [1-2, default: 1]"
                        $rmode = "socks5"; $socks = "1080"; $fport = "14000"; $ftgt = "127.0.0.1:80"
                        if ($rChoice -eq "2") {
                            $rmode = "forward"
                            $inputPort = Read-Host "  Local Forward Listen Port [14000]"
                            if ($inputPort) { $fport = $inputPort }
                            $inputTgt = Read-Host "  Target Address (IP:PORT) [127.0.0.1:80]"
                            if ($inputTgt) { $ftgt = $inputTgt }
                        } else {
                            $inputSocks = Read-Host "  SOCKS5 Port [1080]"
                            if ($inputSocks) { $socks = $inputSocks }
                        }

                        Write-Host ""
                        Write-Host "====================================================================" -ForegroundColor Cyan
                        Write-Host "  PERFORMANCE PROFILE SELECTION" -ForegroundColor Cyan
                        Write-Host "====================================================================" -ForegroundColor Cyan
                        Write-Host "  1) Standard / Balanced [DEFAULT]"
                        Write-Host "  2) High-Loss / Restricted Uplink"
                        Write-Host "  3) High-Throughput / CDN Tunnel"
                        Write-Host "  4) Low-Latency / Gaming & VOIP"
                        Write-Host "====================================================================" -ForegroundColor Cyan
                        $pChoice = Read-Host "  Select Profile [1-4, default: 1]"
                        $prof = "standard"
                        switch ($pChoice) {
                            "2" { $prof = "highloss" }
                            "3" { $prof = "cdntunnel" }
                            "4" { $prof = "gaming" }
                        }

                        if (New-PaqetConfig -Server $server -SecretKey $key -TcpLocalFlag $tcpLocal -TcpRemoteFlag $tcpRemote -RoutingMode $rmode -SocksPort $socks -ForwardPort $fport -ForwardTarget $ftgt -KcpProfile $prof) {
                            Write-Host ""
                            if ($rmode -eq "forward") {
                                Write-Host "  Port Forwarding active on: 0.0.0.0:$fport -> $ftgt" -ForegroundColor Green
                            } else {
                                Write-Host "  Your SOCKS5 proxy: 127.0.0.1:$socks" -ForegroundColor Green
                            }
                            Save-Settings -Backend "paqet" -ServerAddr $server -SocksPort $socks -RoutingMode $rmode -ForwardPort $fport -ForwardTarget $ftgt -KcpProfile $prof
                        }
                    }
                } else {
                    Write-Host ""
                    Write-Host "  GFK CONFIGURATION" -ForegroundColor Yellow
                    Write-Host "  Get these values from your server admin or 'paqctl info' on server"
                    Write-Host ""
                    $server = Read-Host "  Server IP (e.g., 1.2.3.4)"
                    $auth = Read-Host "  Auth code (from server setup)"

                    # Advanced options (hidden by default - just press Enter)
                    Write-Host ""
                    Write-Host "  Advanced options (press Enter for defaults - recommended):" -ForegroundColor DarkGray
                    Write-Host "    TCP flags must match your server config. Only change if server admin says so." -ForegroundColor DarkGray
                    Write-Host "    Valid flags: S A P R F U E C" -ForegroundColor DarkGray
                    $tcpFlags = Read-Host "  TCP flags [AP]"
                    if (-not $tcpFlags) { $tcpFlags = "AP" }

                    if ($server -and $auth) {
                        if (New-GfkConfig -ServerIP $server -AuthCode $auth -SocksPort "14000" -TcpFlags $tcpFlags) {
                            Write-Host ""
                            Write-Host "  Your SOCKS5 proxy: 127.0.0.1:14000" -ForegroundColor Green
                        }
                    }
                }
            }
            "4" {
                if (-not $backend) {
                    Write-Warn "Install a backend first"
                    continue
                }
                if ($backend -eq "paqet") {
                    Start-Paqet
                } else {
                    Start-Gfk
                }
            }
            "5" { Stop-Client }
            "6" { Get-ClientStatus }
            "7" { Test-ServerConnection }
            "8" { Update-Paqet }
            "9" { Show-About }
            "10" { Test-ProxyRouting }
            "11" { Test-ServerSpeed }
            "12" { Manage-ConfigString }
            "13" { Clear-SystemCache }
            "14" { Show-TuningMenu }
            "15" { Show-ShortcutAndWatchdogMenu }
            "0" { return }
            default { Write-Warn "Invalid option" }
        }
    }
}

function Show-About {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  HOW IT WORKS (v1.1.0)" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This tool helps bypass firewall restrictions"
    Write-Host "  by disguising your traffic. You have TWO options:"
    Write-Host ""
    Write-Host "  --- PAQET - Simple and Fast ---" -ForegroundColor Green
    Write-Host "  How: Uses KCP protocol over raw sockets"
    Write-Host "  Proxy: 127.0.0.1:1080 (SOCKS5)"
    Write-Host "  Best for: Most situations, easy setup"
    Write-Host ""
    Write-Host "  --- GFW-KNOCKER - Advanced Anti-DPI ---" -ForegroundColor Yellow
    Write-Host "  How: Violated TCP packets + QUIC tunnel"
    Write-Host "  Proxy: 127.0.0.1:14000 (SOCKS5 via Xray)"
    Write-Host "  Best for: When paqet is blocked, heavy censorship"
    Write-Host ""
    Write-Host "  --- CAN I RUN BOTH? ---" -ForegroundColor Magenta
    Write-Host "  YES! They use different ports:"
    Write-Host "    - Paqet: 127.0.0.1:1080"
    Write-Host "    - GFK:   127.0.0.1:14000"
    Write-Host "  Install both as backup - if one gets blocked, use the other!"
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}

#═══════════════════════════════════════════════════════════════════════
# Main Entry Point
#═══════════════════════════════════════════════════════════════════════

if (-not (Test-Admin)) {
    Write-Err "Administrator privileges required"
    Write-Info "Right-click PowerShell -> Run as Administrator"
    exit 1
}

if ($WatchdogCheck) {
    if (Test-Path "$InstallDir\.stopped") {
        exit 0
    }
    $backend = Get-InstalledBackend
    if ($backend -eq "paqet") {
        $running = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
        if (-not $running) { Start-Paqet }
    } elseif ($backend -eq "gfk") {
        $running = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match "gfk|quic" -or $_.CommandLine -match "gfk|quic" }
        if (-not $running) { Start-Gfk }
    }
    exit 0
}

# Auto-detect backend if not specified
if (-not $Backend) {
    $Backend = Get-InstalledBackend
}

switch ($Action.ToLower()) {
    "turbo" { Toggle-WindowsTurbo }
    "watchdog" { Toggle-Watchdog }
    "tune" { Show-TuningMenu }
    "shortcut" { New-DesktopShortcut }
    "install" {
        if ($Backend -eq "gfk") {
            Install-Gfk
        } else {
            Install-Paqet
        }
    }
    "config" {
        if ($Backend -eq "gfk") {
            if (-not $ServerAddr -or -not $Key) {
                Write-Err "Usage: -Action config -ServerAddr [ip] -Key [authcode]"
                exit 1
            }
            New-GfkConfig -ServerIP $ServerAddr -AuthCode $Key
        } else {
            if (-not $ServerAddr -or -not $Key) {
                Write-Err "Usage: -Action config -ServerAddr [ip:port] -Key [key]"
                exit 1
            }
            New-PaqetConfig -Server $ServerAddr -SecretKey $Key
        }
    }
    "run" {
        if ($ServerAddr -and $Key) {
            if ($Backend -eq "gfk") {
                Install-Gfk
                New-GfkConfig -ServerIP $ServerAddr -AuthCode $Key
                Start-Gfk
            } else {
                Install-Paqet
                New-PaqetConfig -Server $ServerAddr -SecretKey $Key
                Start-Paqet
            }
        } else {
            if ($Backend -eq "gfk") {
                Start-Gfk
            } else {
                Start-Paqet
            }
        }
    }
    "start" {
        if ($Backend -eq "gfk") { Start-Gfk } else { Start-Paqet }
    }
    "stop" { Stop-Client }
    "status" { Get-ClientStatus }
    "menu" { Show-Menu -InitBackend $Backend }
    default { Show-Menu -InitBackend $Backend }
}
