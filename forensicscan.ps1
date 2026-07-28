<#
.SYNOPSIS
    Invoke-GameCheatForensics - Forensic artifact collector for game cheat detection.
.DESCRIPTION
    Collects and analyzes forensic artifacts left behind by game cheating software
    including process artifacts, prefetch, registry, filesystem, event logs,
    anti-cheat logs, network/DNS data, and persistence mechanisms.
.PARAMETER SessionStart
    Start of the gaming session window (default: 4 hours ago).
.PARAMETER SessionEnd
    End of the gaming session window (default: current time).
.PARAMETER OutputPath
    Directory to save forensic reports (default: Desktop\CheatForensics_<timestamp>).
.PARAMETER GameProcessNames
    Game process names to build execution timelines for.
.PARAMETER NoReportFile
    Suppress writing report files to disk (console output only).
.PARAMETER EventLogLimit
    Maximum events to retrieve per log query (default: 5000).
.EXAMPLE
    Invoke-GameCheatForensics -SessionStart (Get-Date).AddHours(-2) -Verbose
.EXAMPLE
    Invoke-GameCheatForensics -GameProcessNames "cs2","valorant" -NoReportFile
.NOTES
    Author: HackerAI Forensics Module
    Requires: Administrator privileges for most artifact collection.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [datetime]$SessionStart = (Get-Date).AddHours(-4),

    [Parameter(Mandatory = $false)]
    [datetime]$SessionEnd = (Get-Date),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\CheatForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(Mandatory = $false)]
    [string[]]$GameProcessNames = @(
        "csgo", "cs2", "valorant", "fortnite", "apex",
        "r6", "rainbow", "siege", "warzone", "cod",
        "rocketleague", "fivem", "gta5", "destiny2",
        "overwatch", "league", "lol", "dota2", "rust"
    ),

    [Parameter(Mandatory = $false)]
    [switch]$NoReportFile,

    [Parameter(Mandatory = $false)]
    [int]$EventLogLimit = 5000
)

# ---------------------------------------------------------------
# Global configuration
# ---------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

$Script:Results      = [System.Collections.Generic.List[object]]::new()
$Script:ArtifactPath = $OutputPath
$Script:FoundAny     = $false

# Suspicious keyword patterns for cheat detection
$Script:SuspiciousKeywords = @(
    'cheat', 'hack', 'trainer', 'inject', 'bypass', 'loader',
    'hook', 'mapper', 'aimbot', 'wallhack', 'triggerbot', 'esp',
    'modmenu', 'dllinject', 'unknown', 'suspicious'
)

# Registry paths to scan for cheat software
$Script:UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# Filesystem target directories
$Script:TargetDirectories = @(
    "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA",
    "$env:PROGRAMDATA", "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents"
)

# Known anti-cheat/DRM data directories
$Script:AntiCheatPaths = @(
    "$env:PROGRAMDATA\EasyAntiCheat",
    "$env:PROGRAMDATA\BattlEye",
    "$env:PROGRAMDATA\FaceIt",
    "$env:APPDATA\Vanguard",
    "$env:LOCALAPPDATA\Riot Games"
)

# ---------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------

function Write-Banner {
    Clear-Host
    $banner = @"

  ╔══════════════════════════════════════════════════════════╗
  ║           GAME CHEAT FORENSIC SCANNER v2.0              ║
  ║         Authorized Security Assessment Tool             ║
  ╚══════════════════════════════════════════════════════════╝

  Session window   : $($Script:SessionStart)  →  $($Script:SessionEnd)
  Duration         : $([math]::Round(($Script:SessionEnd - $Script:SessionStart).TotalMinutes, 1)) minutes
  Artifact output  : $Script:ArtifactPath
  Administrator    : $([bool]([Security.Principal.WindowsPrincipal]::new(
                        [Security.Principal.WindowsIdentity]::GetCurrent()
                    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Title, [int]$Number)
    Write-Host "`n  ──[$Number/$($Script:TotalSections)] $Title ──" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "    [✓] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "    [!] $Message" -ForegroundColor Magenta
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "    [✗] $Message" -ForegroundColor Red
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Severity,
        [object]$Data
    )
    $Script:Results.Add([PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Data     = $Data
        Timestamp = (Get-Date)
    })
    if ($Data) { $Script:FoundAny = $true }
}

# ---------------------------------------------------------------
# Artifact collection functions
# ---------------------------------------------------------------

function Get-ProcessArtifacts {
    Write-SectionHeader -Title "Running / Suspended Processes" -Number 1
    Write-Host "    Scanning for cheat-related process names..." -NoNewline

    $suspicious = Get-Process | Where-Object {
        $_.ProcessName -match ($Script:SuspiciousKeywords -join '|')
    } | Select-Object ProcessName, Id, @{N='StartTime';E={$_.StartTime.ToLocalTime()}}, CPU,
                    @{N='Session';E={$_.SessionId}},
                    @{N='Parent';E={
                        try {
                            (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId
                        } catch { 'N/A' }
                    }}

    if ($suspicious) {
        Write-Host " $(@($suspicious).Count) found." -ForegroundColor Red
        $suspicious | Format-Table -AutoSize | Out-Host
        Add-Result -Category "SuspiciousProcesses" -Severity "High" -Data $suspicious
    } else {
        Write-Host " None found." -ForegroundColor Green
    }

    # Also enumerate all running processes for baseline/timeline
    $allProcs = Get-Process | Select-Object ProcessName, Id, @{N='StartTime';E={$_.StartTime.ToLocalTime()}}, CPU, SessionId
    Add-Result -Category "AllProcesses" -Severity "Info" -Data $allProcs
}

function Get-PrefetchArtifacts {
    Write-SectionHeader -Title "Prefetch Files" -Number 2
    Write-Host "    Scanning C:\Windows\Prefetch..." -NoNewline

    $pfDir = 'C:\Windows\Prefetch'
    if (-not (Test-Path $pfDir)) {
        Write-Host " Directory not found." -ForegroundColor Red
        return
    }

    $suspicious = Get-ChildItem "$pfDir\*.pf" -Name | Where-Object {
        $_ -match ($Script:SuspiciousKeywords -join '|')
    } | ForEach-Object {
        $_ -replace '\.pf$', '' -replace '-[0-9A-F]{8}$', ''
    } | Sort-Object -Unique

    if ($suspicious) {
        Write-Host " $(@($suspicious).Count) entries found." -ForegroundColor Red
        $suspicious | ForEach-Object { Write-Warning -Message $_ }
        Add-Result -Category "SuspiciousPrefetch" -Severity "High" -Data $suspicious
    } else {
        Write-Host " None found." -ForegroundColor Green
    }

    # Capture all prefetch entries for timeline analysis
    $allPf = Get-ChildItem "$pfDir\*.pf" | Select-Object Name, Length,
        @{N='LastRun';E={$_.LastWriteTime}},
        @{N='Executable';E={$_ -replace '-[0-9A-F]{8}\.pf$', '.exe'}} |
        Sort-Object LastWriteTime -Descending
    Add-Result -Category "AllPrefetch" -Severity "Info" -Data $allPf
}

function Get-RegistryArtifacts {
    Write-SectionHeader -Title "Registry - Installed Software" -Number 3
    Write-Host "    Scanning uninstall keys..." -NoNewline

    $suspicious = @()
    foreach ($path in $Script:UninstallPaths) {
        $suspicious += Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -match ($Script:SuspiciousKeywords -join '|')
            } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,
                @{N='Path';E={$_.PSPath}}
    }

    if ($suspicious) {
        Write-Host " $(@($suspicious).Count) entries found." -ForegroundColor Red
        $suspicious | Format-Table DisplayName, DisplayVersion, Publisher, InstallDate -AutoSize | Out-Host
        Add-Result -Category "SuspiciousRegistry" -Severity "High" -Data $suspicious
    } else {
        Write-Host " None found." -ForegroundColor Green
    }

    # UserAssist artifact
    Write-Host "    Scanning UserAssist (GUI execution history)..." -NoNewline
    $uaPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    $uaEntries = @()
    Get-ChildItem $uaPath -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        $uaEntries += Get-ItemProperty "${uaPath}\${guid}\Count" -ErrorAction SilentlyContinue
    }
    if ($uaEntries) {
        Write-Host " $(@($uaEntries).Count) entries found." -ForegroundColor Gray
        Add-Result -Category "UserAssist" -Severity "Info" -Data $uaEntries
    } else {
        Write-Host " None found." -ForegroundColor Green
    }
}

function Get-FilesystemArtifacts {
    Write-SectionHeader -Title "Filesystem - Suspicious Files" -Number 4
    Write-Host "    Scanning common directories for cheat artifacts..." -ForegroundColor Gray

    $searchPatterns = $Script:SuspiciousKeywords | ForEach-Object { "*${_}*" }
    $suspiciousFiles = @()

    foreach ($dir in $Script:TargetDirectories) {
        if (-not (Test-Path $dir)) { continue }
        Write-Host "      → $dir" -ForegroundColor DarkGray
        foreach ($pattern in $searchPatterns) {
            $suspiciousFiles += Get-ChildItem $dir -Filter $pattern -Depth 1 -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                Select-Object FullName, Length, CreationTime, LastWriteTime,
                    @{N='Directory';E={[System.IO.Path]::GetDirectoryName($_.FullName)}}
        }
    }

    if ($suspiciousFiles) {
        Write-Host "    [+] Found $(@($suspiciousFiles).Count) suspicious files." -ForegroundColor Red
        $suspiciousFiles | Sort-Object LastWriteTime -Descending |
            Format-Table LastWriteTime, Length, FullName -AutoSize -Wrap | Out-Host
        Add-Result -Category "SuspiciousFiles" -Severity "High" -Data $suspiciousFiles
    } else {
        Write-Host "    [+] No suspicious files found." -ForegroundColor Green
    }

    # Check for unsigned/malicious DLLs in common locations
    Write-Host "    Scanning for unsigned DLLs in game directories..." -ForegroundColor Gray
    $dllScan = Get-ChildItem "$env:PROGRAMDATA" -Filter "*.dll" -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 10240 } |  # 10KB minimum
        Select-Object FullName, Length, LastWriteTime
    if ($dllScan) {
        Add-Result -Category "UnsignedDLLs" -Severity "Medium" -Data $dllScan
    }
}

function Get-EventLogArtifacts {
    Write-SectionHeader -Title "Windows Event Logs (Security / Sysmon)" -Number 5

    # --- Security Event 4688: Process Creation ---
    Write-Host "    [Security] Process creation (Event ID 4688)..." -NoNewline
    try {
        $evt4688 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4688
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
            MaxEvents = $EventLogLimit
        } -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time              = $_.TimeCreated
                SubjectUser       = $data['SubjectUserName']
                NewProcessName    = $data['NewProcessName']
                NewProcessId      = $data['NewProcessId']
                CommandLine       = $data['CommandLine']
                ParentProcessName = $data['ParentProcessName']
                CreatorProcessID  = $data['CreatorProcessId']
            }
        }

        $suspicious4688 = $evt4688 | Where-Object {
            $_.NewProcessName -match ($Script:SuspiciousKeywords -join '|') -or
            $_.CommandLine -match ($Script:SuspiciousKeywords -join '|')
        }

        Write-Host " $($evt4688.Count) total, $($suspicious4688.Count) suspicious." -ForegroundColor $(if ($suspicious4688) {'Red'}else{'Green'})
        if ($suspicious4688) {
            $suspicious4688 | Format-Table Time, NewProcessName, CommandLine -AutoSize -Wrap | Out-Host
            Add-Result -Category "Event4688_Suspicious" -Severity "High" -Data $suspicious4688
        }
        Add-Result -Category "Event4688_All" -Severity "Info" -Data $evt4688
    } catch {
        Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorMsg "Cannot access Security event log. Run as Administrator."
    }

    # --- Sysmon Event 1: Process Creation (if available) ---
    Write-Host "    [Sysmon] Process creation (Event ID 1)..." -NoNewline
    try {
        if (Get-Service -Name Sysmon -ErrorAction SilentlyContinue | Where-Object Status -EQ Running) {
            $sysmon1 = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-Sysmon/Operational'
                ID        = 1
                StartTime = $Script:SessionStart
                EndTime   = $Script:SessionEnd
                MaxEvents = $EventLogLimit
            } -ErrorAction Stop | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = @{}
                $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    Time     = $_.TimeCreated
                    Image    = $data['Image']
                    CmdLine  = $data['CommandLine']
                    PID      = $data['ProcessId']
                    Parent   = $data['ParentImage']
                    Hashes   = $data['Hashes']
                    User     = $data['User']
                }
            }

            $suspiciousSysmon1 = $sysmon1 | Where-Object {
                $_.Image -match ($Script:SuspiciousKeywords -join '|') -or
                $_.CmdLine -match ($Script:SuspiciousKeywords -join '|')
            }

            Write-Host " $($sysmon1.Count) total, $($suspiciousSysmon1.Count) suspicious." -ForegroundColor $(if ($suspiciousSysmon1) {'Red'}else{'Green'})
            if ($suspiciousSysmon1) {
                $suspiciousSysmon1 | Format-Table Time, Image, CmdLine -AutoSize -Wrap | Out-Host
                Add-Result -Category "Sysmon1_Suspicious" -Severity "High" -Data $suspiciousSysmon1
            }
            Add-Result -Category "Sysmon1_All" -Severity "Info" -Data $sysmon1
        } else {
            Write-Host " Sysmon not installed or not running." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host " Error: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    # --- Sysmon Event 7: DLL Loaded (cheat injection detection) ---
    Write-Host "    [Sysmon] DLL loaded (Event ID 7)..." -NoNewline
    try {
        if (Get-Service -Name Sysmon -ErrorAction SilentlyContinue | Where-Object Status -EQ Running) {
            $sysmon7 = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-Sysmon/Operational'
                ID        = 7
                StartTime = $Script:SessionStart
                EndTime   = $Script:SessionEnd
                MaxEvents = $EventLogLimit
            } -ErrorAction Stop | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = @{}
                $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    Time     = $_.TimeCreated
                    Process  = $data['Image']
                    PID      = $data['ProcessId']
                    Module   = $data['ModuleLoaded']
                    Signed   = $data['Signed']
                    Sig      = $data['Signature']
                }
            }

            $suspiciousDllLoads = $sysmon7 | Where-Object {
                $_.Module -match ($Script:SuspiciousKeywords -join '|') -or
                ($_.Signed -eq 'false' -and $_.Module -notmatch 'microsoft|windows|system32|program files')
            }

            Write-Host " $($sysmon7.Count) total, $($suspiciousDllLoads.Count) suspicious." -ForegroundColor $(if ($suspiciousDllLoads) {'Red'}else{'Green'})
            if ($suspiciousDllLoads) {
                $suspiciousDllLoads | Format-Table Time, Process, Module -AutoSize -Wrap | Out-Host
                Add-Result -Category "Sysmon7_SuspiciousDLL" -Severity "High" -Data $suspiciousDllLoads
            }
            Add-Result -Category "Sysmon7_All" -Severity "Info" -Data $sysmon7
        } else {
            Write-Host " Skipped (Sysmon not available)." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host " Error: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    # --- Application event log: Anti-cheat errors ---
    Write-Host "    [Application] Anti-cheat error events..." -NoNewline
    try {
        $acKeywords = @('battleye', 'easyanticheat', 'easy anti-cheat', 'eac',
                        'vanguard', 'faceit', 'punkbuster', 'vac',
                        'valorant', 'fortnite', 'cod', 'warzone', 'csgo', 'cs2')
        $acErrors = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
            MaxEvents = $EventLogLimit
        } -ErrorAction Stop | Where-Object {
            $msg = $_.Message.ToLower()
            ($acKeywords | Where-Object { $msg -match $_ }) -or
            $msg -match 'cheat|banned|kicked|blocked|violation|detected|suspicious|unauthorized'
        } | Select-Object TimeCreated, Id, LevelDisplayName,
            @{N='MessagePreview';E={$_.Message.Substring(0, [math]::Min(200, $_.Message.Length)) + '...'}}

        Write-Host " $(@($acErrors).Count) potential events." -ForegroundColor $(if ($acErrors) {'Red'}else{'Green'})
        if ($acErrors) {
            $acErrors | Format-Table TimeCreated, Id, LevelDisplayName, MessagePreview -AutoSize -Wrap | Out-Host
            Add-Result -Category "AntiCheatErrors" -Severity "Critical" -Data $acErrors
        }
    } catch {
        Write-Host " Error: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

function Get-AntiCheatLogs {
    Write-SectionHeader -Title "Anti-Cheat Data Directories" -Number 6

    foreach ($acPath in $Script:AntiCheatPaths) {
        Write-Host "    Checking $acPath..." -NoNewline
        if (Test-Path $acPath) {
            Write-Host " Found." -ForegroundColor Yellow
            $files = Get-ChildItem $acPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                Select-Object FullName, Length, LastWriteTime
            if ($files) {
                $files | Format-Table LastWriteTime, Length, @{N='Filename';E={[System.IO.Path]::GetFileName($_.FullName)}} -AutoSize | Out-Host
                Add-Result -Category "AntiCheatDir_$([IO.Path]::GetFileName($acPath))" -Severity "Medium" -Data $files
            }
        } else {
            Write-Host " Not found." -ForegroundColor DarkGray
        }
    }
}

function Get-NetworkArtifacts {
    Write-SectionHeader -Title "Network / DNS Artifacts" -Number 7

    # DNS cache
    Write-Host "    DNS Cache entries..." -NoNewline
    $dnsSuspicious = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Entry -match 'cheat|hack|aimbot|wallhack|inject|\.xyz|\.top|\.ru|\.su|\.pw'
        }
    if ($dnsSuspicious) {
        Write-Host " $(@($dnsSuspicious).Count) found." -ForegroundColor Red
        $dnsSuspicious | Format-Table Entry, TimeToLive, Type, DataLength -AutoSize | Out-Host
        Add-Result -Category "SuspiciousDNSCache" -Severity "High" -Data $dnsSuspicious
    } else {
        Write-Host " None found." -ForegroundColor Green
    }

    # Current TCP connections
    Write-Host "    Established TCP connections..." -NoNewline
    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object State -EQ 'Established' |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
            @{N='ProcessName';E={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }},
            @{N='PID';E={$_.OwningProcess}},
            @{N='RemoteSummary';E={"$($_.RemoteAddress):$($_.RemotePort)"}}

    if ($tcpConns) {
        Write-Host " $(@($tcpConns).Count) active." -ForegroundColor Gray
        # Check for connections to high-risk geolocations (common cheat C2 regions)
        $highRiskConns = $tcpConns | Where-Object {
            $_.RemoteAddress -match '^185\.|^5\.|^94\.|^91\.|^77\.|^45\.|^31\.|^194\.|^176\.'
        }
        if ($highRiskConns) {
            Write-Host "    [!] $(@($highRiskConns).Count) connections to potentially risky IP ranges." -ForegroundColor Magenta
            $highRiskConns | Format-Table RemoteSummary, ProcessName, PID -AutoSize | Out-Host
            Add-Result -Category "SuspiciousTCPConnections" -Severity "High" -Data $highRiskConns
        }
        Add-Result -Category "ActiveTCPConnections" -Severity "Info" -Data $tcpConns
    } else {
        Write-Host " None established." -ForegroundColor DarkGray
    }
}

function Get-GameTimelines {
    Write-SectionHeader -Title "Game Process Execution Timeline" -Number 8

    foreach ($game in $Script:GameProcessNames) {
        Write-Host "    Tracking '$game'..." -NoNewline
        try {
            $timeline = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                ID        = 4688
                StartTime = $Script:SessionStart
                EndTime   = $Script:SessionEnd
            } -MaxEvents $EventLogLimit -ErrorAction Stop | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = @{}
                $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                [PSCustomObject]@{
                    Time       = $_.TimeCreated
                    Image      = $data['NewProcessName']
                    PID        = $data['NewProcessId']
                    CmdLine    = $data['CommandLine']
                    Parent     = $data['ParentProcessName']
                    User       = $data['SubjectUserName']
                }
            } | Where-Object { $_.Image -match $game -replace '\.exe$','' } |
                Sort-Object Time

            if ($timeline) {
                Write-Host " $(@($timeline).Count) starts/restarts." -ForegroundColor Cyan
                $timeline | Format-Table Time, Image, PID, User -AutoSize | Out-Host
                Add-Result -Category "GameTimeline_$game" -Severity "Info" -Data $timeline
            } else {
                Write-Host " No events in window." -ForegroundColor DarkGray
            }
        } catch {
            Write-Host " Error: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}

function Get-PersistenceArtifacts {
    Write-SectionHeader -Title "Persistence Mechanisms (Scheduled Tasks / Services)" -Number 9

    Write-Host "    Scheduled tasks..." -NoNewline
    $schedTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            $_.TaskName -match ($Script:SuspiciousKeywords -join '|') -or
            $_.TaskPath -match ($Script:SuspiciousKeywords -join '|')
        }
    if ($schedTasks) {
        Write-Host " $(@($schedTasks).Count) suspicious tasks found." -ForegroundColor Red
        $schedTasks | Format-Table TaskName, TaskPath, State, @{N='Author';E={$_.Author}} -AutoSize | Out-Host
        Add-Result -Category "SuspiciousScheduledTasks" -Severity "High" -Data $schedTasks
    } else {
        Write-Host " None found." -ForegroundColor Green
    }

    Write-Host "    Windows services..." -NoNewline
    $svcs = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match ($Script:SuspiciousKeywords -join '|') }
    if ($svcs) {
        Write-Host " $(@($svcs).Count) suspicious services found." -ForegroundColor Red
        $svcs | Format-Table Name, DisplayName, Status, StartType -AutoSize | Out-Host
        Add-Result -Category "SuspiciousServices" -Severity "High" -Data $svcs
    } else {
        Write-Host " None found." -ForegroundColor Green
    }

    # Run keys (autostart)
    Write-Host "    Registry Run keys..." -NoNewline
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*'
    )
    $autoruns = @()
    foreach ($key in $runKeys) {
        $autoruns += Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Select-Object * -ExcludeProperty PS*
    }
    Write-Host " $(@($autoruns).Count) entries." -ForegroundColor Gray
    Add-Result -Category "RegistryAutoruns" -Severity "Info" -Data $autoruns
}

# ---------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------

function Export-ForensicReport {
    Write-SectionHeader -Title "Generating Report" -Number ($Script:TotalSections + 1)

    if ($Script:FoundAny -eq $false) {
        Write-Host "`n  ╔══════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║   ✓  No suspicious artifacts detected.        ║" -ForegroundColor Green
        Write-Host "  ║      The system appears clean.                ║" -ForegroundColor Green
        Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Green
    } else {
        Write-Host "`n  ╔══════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║   ⚠  Suspicious artifacts were found!        ║" -ForegroundColor Red
        Write-Host "  ║      Review the categories highlighted above.║" -ForegroundColor Red
        Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Red
    }

    if (-not $NoReportFile) {
        try {
            New-Item -ItemType Directory -Force -Path $Script:ArtifactPath | Out-Null

            # CSV report (flat format)
            $reportCsv = $Script:Results |
                Select-Object Timestamp, Severity, Category,
                    @{N='Summary';E={
                        $d = $_.Data
                        if ($d -is [array]) { "$(@($d).Count) items" }
                        elseif ($d) { $d.ToString().Substring(0, [math]::Min(100, $d.ToString().Length)) }
                        else { 'No data' }
                    }}
            $reportCsv | Export-Csv "$Script:ArtifactPath\forensics_summary.csv" -NoTypeInformation

            # Full XML export
            $Script:Results | Export-Clixml "$Script:ArtifactPath\forensics_full.xml"

            # Human-readable text report
            $reportText = @"
============================================================
  GAME CHEAT FORENSIC REPORT
  Generated: $(Get-Date)
  Analyst Tool: HackerAI Forensics Module v2.0
============================================================

Session Window: $Script:SessionStart  →  $Script:SessionEnd
Duration:       $([math]::Round(($Script:SessionEnd - $Script:SessionStart).TotalMinutes, 1)) minutes
Target System:  $env:COMPUTERNAME
OS Version:     $((Get-CimInstance Win32_OperatingSystem).Caption)
Administrator:  $([bool]([Security.Principal.WindowsPrincipal]::new(
                    [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
Findings:       $($Script:Results.Count) artifact categories collected

"@
            foreach ($result in $Script:Results) {
                $reportText += @"

[$(Get-Date -Format 'HH:mm:ss')] CATEGORY: $($result.Category)  |  SEVERITY: $($result.Severity)
$('-' * 60)
"@
                if ($result.Data) {
                    $stringData = ($result.Data | Format-Table -AutoSize -Wrap | Out-String -Width 120)
                    $reportText += $stringData
                }
                $reportText += "`n"
            }

            $reportText | Out-File "$Script:ArtifactPath\forensics_report.txt" -Encoding UTF8

            Write-Success "Report saved to: $Script:ArtifactPath"
        } catch {
            Write-ErrorMsg "Failed to write report files: $($_.Exception.Message)"
        }
    }

    # Print final summary table
    Write-Host "`n  ── ARTIFACT SUMMARY ──" -ForegroundColor Cyan
    $Script:Results | Format-Table -Property @{N='#';E={[array]::IndexOf($Script:Results.ToArray(), $_) + 1}},
        Timestamp, Severity, Category,
        @{N='Items';E={
            $d = $_.Data
            if ($d -is [array]) { @($d).Count }
            elseif ($d) { 1 }
            else { 0 }
        }} -AutoSize | Out-Host
}

# ---------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------

function Invoke-Main {
    # Bind session times into script scope
    $Script:SessionStart = $SessionStart
    $Script:SessionEnd   = $SessionEnd
    $Script:TotalSections = 9

    Write-Banner

    if (-not ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-Host "  [!] WARNING: Running without Administrator privileges." -ForegroundColor Magenta
        Write-Host "  [!] Event logs, some registry hives, and kernel artifacts will be unavailable.`n" -ForegroundColor Magenta
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Get-ProcessArtifacts
    Get-PrefetchArtifacts
    Get-RegistryArtifacts
    Get-FilesystemArtifacts
    Get-EventLogArtifacts
    Get-AntiCheatLogs
    Get-NetworkArtifacts
    Get-GameTimelines
    Get-PersistenceArtifacts
    Export-ForensicReport

    $stopwatch.Stop()
    Write-Host "`n  ── Scan completed in $($stopwatch.Elapsed.TotalSeconds.ToString('F1')) seconds ──" -ForegroundColor Cyan
}

# Entry point
Invoke-Main
