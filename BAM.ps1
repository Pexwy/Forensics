#Requires -Version 5.1
<#
.SYNOPSIS
    BAM (Background Activity Moderator) Forensic Analyzer - DFIR GUI Tool

.DESCRIPTION
    Parses the Windows BAM registry key (HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings)
    from a live system or an offline SYSTEM registry hive, and presents the results in a modern,
    filterable WPF GUI for digital forensics / incident response analysis.

    BAM records the last execution time of applications per user SID and is a strong artifact
    for program execution analysis, even for applications launched from removable/network media.

.NOTES
    Author   : DFIR Tooling
    Run As   : Administrator (required to read BAM key / load offline hives)
    Tested On: PowerShell 5.1 / Windows 10 & 11
#>

# ============================================================================
#  SETUP
# ============================================================================

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Native P/Invoke to map \Device\HarddiskVolumeN -> Drive Letter (live system only)
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class BamNative {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
"@ -ErrorAction SilentlyContinue
} catch {}

$Global:AllEntries   = [System.Collections.Generic.List[object]]::new()
$Global:VolumeMap    = @{}
$Global:IsAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Global:SessionBoundaries = @{ BootTimeUtc = $null; LogonMap = @{} }

# ============================================================================
#  HELPER FUNCTIONS
# ============================================================================

function Build-VolumeMap {
    $map = @{}
    $sb = New-Object System.Text.StringBuilder 260
    foreach ($code in 65..90) {
        $letter = [char]$code
        $drive  = "$letter`:"
        $sb.Clear() | Out-Null
        try {
            $len = [BamNative]::QueryDosDevice($drive, $sb, 260)
            if ($len -gt 0) {
                $target = $sb.ToString()
                if ($target -match '^\\Device\\HarddiskVolume\d+') {
                    $map[$target] = "$drive\"
                }
            }
        } catch {}
    }
    return $map
}

function Resolve-SidToUsername {
    param([string]$Sid)
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return "Unresolved ($Sid)"
    }
}

function Convert-DevicePath {
    param([string]$Path)
    if ($Path -match '^\\Device\\HarddiskVolume(\d+)\\(.*)$') {
        $key = "\Device\HarddiskVolume$($matches[1])"
        if ($Global:VolumeMap.ContainsKey($key)) {
            return (Join-Path $Global:VolumeMap[$key] $matches[2])
        }
    }
    return $Path
}

function Test-SuspiciousEntry {
    <#
        Lightweight heuristic engine that flags common program-execution red flags.
        Returns reasons + a severity so the UI can highlight rows without needing
        network lookups, hashing, or AV signatures.
    #>
    param(
        [string]$ExecutablePath,
        [string]$FileName,
        [string]$FileExists
    )
    $reasons = New-Object System.Collections.Generic.List[string]
    $fnLower = if ($FileName) { $FileName.ToLowerInvariant() } else { "" }

    if ($ExecutablePath -match '\\(Temp|Tmp)\\' -or
        $ExecutablePath -match '\\AppData\\Local\\Temp\\' -or
        $ExecutablePath -match '\\AppData\\Roaming\\' -or
        $ExecutablePath -match '\\Downloads\\' -or
        $ExecutablePath -match '\\\$Recycle\.Bin\\' -or
        $ExecutablePath -match '\\ProgramData\\[A-Za-z0-9]{8,}\\') {
        $reasons.Add("Executed from a temp / user-writable directory")
    }
    if ($ExecutablePath -match '^[A-Za-z]:\\[^\\]+\.(exe|scr|com|bat|cmd|ps1)$' -or
        $ExecutablePath -match '^\\Device\\HarddiskVolume\d+\\[^\\]+\.(exe|scr|com|bat|cmd|ps1)$') {
        $reasons.Add("Executed directly from the root of a drive (unusual)")
    }
    if ($fnLower -match '\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|zip|rar|7z)\.(exe|scr|com|bat|cmd|ps1|vbs|js|jse|wsf)$') {
        $reasons.Add("Double file extension - possible masquerade")
    }
    if ($fnLower -match '\.(scr|pif|cpl|hta|vbs|js|jse|wsf|chm)$') {
        $reasons.Add("Uncommon / high-risk executable extension")
    }
    if ($fnLower -match '^[a-f0-9]{16,}\.(exe|dll|scr)$' -or
        $fnLower -match '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}') {
        $reasons.Add("Randomized / hash-like filename")
    }
    $systemNames = @('svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe',
                      'smss.exe','explorer.exe','spoolsv.exe','wininit.exe','taskhostw.exe')
    if ($systemNames -contains $fnLower -and $ExecutablePath -notmatch '\\Windows\\(System32|SysWOW64)\\') {
        $reasons.Add("Known system process name running from a non-standard path")
    }
    if ($ExecutablePath -match '^\\\\[^\\]+\\') {
        $reasons.Add("Executed from a network (UNC) path")
    }
    if ($FileExists -eq "No") {
        $reasons.Add("Executable no longer present on disk (deleted post-execution)")
    }

    $severity = "None"
    if ($reasons.Count -gt 0) {
        $highHit = $reasons | Where-Object { $_ -match "no longer present|Double file extension|Randomized|network \(UNC\)" }
        $severity = if ($highHit) { "High" } else { "Medium" }
    }

    [PSCustomObject]@{
        IsSuspicious = ($reasons.Count -gt 0)
        Severity     = $severity
        Reasons      = ($reasons -join "; ")
    }
}

function Get-SessionBoundaries {
    <#
        Establishes a reference point for the "Since Logon" filter:
          - Per-SID interactive logon start time (best case), via Win32_LogonSession
          - Falls back to system LastBootUpTime when a per-user session can't be resolved
        Only meaningful on a live system - offline hive data has no session context.
    #>
    $result = @{ BootTimeUtc = $null; LogonMap = @{} }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $result.BootTimeUtc = $os.LastBootUpTime.ToUniversalTime()
    } catch {}
    try {
        $sessions = Get-CimInstance Win32_LogonSession -ErrorAction Stop | Where-Object { $_.LogonType -in 2,10,11 }
        foreach ($s in $sessions) {
            try {
                $accts = Get-CimInstance -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId='$($s.LogonId)'} WHERE AssocClass=Win32_LoggedOnUser ResultClass=Win32_Account" -ErrorAction Stop
                foreach ($a in $accts) {
                    if ($a.SID -and $s.StartTime) {
                        $st = $s.StartTime.ToUniversalTime()
                        if (-not $result.LogonMap.ContainsKey($a.SID) -or $st -gt $result.LogonMap[$a.SID]) {
                            $result.LogonMap[$a.SID] = $st
                        }
                    }
                }
            } catch {}
        }
    } catch {}
    return $result
}

function Get-BamEntries {
    param(
        [Parameter(Mandatory)][string]$UserSettingsPath,
        [switch]$Offline,
        [string]$SourceLabel = "Live Registry"
    )
    $results = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path $UserSettingsPath)) { return $results }

    $sidKeys = Get-ChildItem -Path $UserSettingsPath -ErrorAction SilentlyContinue
    foreach ($sidKey in $sidKeys) {
        $sid      = Split-Path $sidKey.Name -Leaf
        $username = Resolve-SidToUsername -Sid $sid
        $regItem  = Get-Item -LiteralPath $sidKey.PSPath -ErrorAction SilentlyContinue
        if (-not $regItem) { continue }

        foreach ($valName in $regItem.Property) {
            if ($valName -in @('(default)','Version','SequenceNumber')) { continue }

            $rawBytes = $null
            try { $rawBytes = $regItem.GetValue($valName, $null, 'DoNotExpandEnvironmentNames') } catch {}
            if ($null -eq $rawBytes -or $rawBytes.Length -lt 8) { continue }

            try {
                $fileTime = [BitConverter]::ToInt64($rawBytes, 0)
                if ($fileTime -le 0) { continue }
                $utc = [DateTime]::FromFileTimeUtc($fileTime)
            } catch { continue }

            $resolvedPath = if ($Offline) { $valName } else { Convert-DevicePath -Path $valName }
            $exists = "N/A (offline)"
            if (-not $Offline) {
                $exists = if (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue) { "Yes" } else { "No" }
            }
            $fileName = $valName
            try { $fileName = Split-Path $valName -Leaf } catch {}

            $susp = Test-SuspiciousEntry -ExecutablePath $valName -FileName $fileName -FileExists $exists
            $suspLabel = switch ($susp.Severity) {
                "High"   { "⚠ HIGH" }
                "Medium" { "⚠ MED"  }
                default  { "" }
            }

            $results.Add([PSCustomObject]@{
                SID                = $sid
                Username           = $username
                FileName           = $fileName
                ExecutablePath     = $valName
                ResolvedPath       = $resolvedPath
                FileExists         = $exists
                LastExecutionUTC   = $utc
                LastExecutionLocal = $utc.ToLocalTime()
                Source             = $SourceLabel
                IsSuspicious       = $susp.IsSuspicious
                Severity           = $susp.Severity
                SuspiciousLabel    = $suspLabel
                SuspiciousReasons  = $susp.Reasons
            })
        }
    }
    return $results
}

function Load-OfflineHive {
    param([string]$HiveFilePath)

    if (-not $Global:IsAdmin) { throw "Administrator privileges are required to load an offline hive." }

    $mountKey  = "BAM_DFIR_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $mountArg  = "HKLM\$mountKey"
    $loadOut   = & reg.exe load $mountArg "$HiveFilePath" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg.exe load failed: $loadOut" }

    try {
        $currentCS = "ControlSet001"
        try {
            $sel = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\$mountKey\Select" -Name Current -ErrorAction Stop
            $currentCS = "ControlSet{0:D3}" -f $sel.Current
        } catch {}

        $userSettingsPath = "Registry::HKEY_LOCAL_MACHINE\$mountKey\$currentCS\Services\bam\State\UserSettings"
        if (-not (Test-Path $userSettingsPath)) {
            $userSettingsPath = "Registry::HKEY_LOCAL_MACHINE\$mountKey\ControlSet001\Services\bam\State\UserSettings"
        }
        return Get-BamEntries -UserSettingsPath $userSettingsPath -Offline -SourceLabel "Offline Hive"
    }
    finally {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 300
        & reg.exe unload $mountArg 2>&1 | Out-Null
    }
}

# ============================================================================
#  XAML - MODERN DARK UI
# ============================================================================

[xml]$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="BAM Forensic Analyzer  |  DFIR Toolkit"
        Height="900" Width="1440" MinHeight="650" MinWidth="1100"
        WindowStartupLocation="CenterScreen"
        Background="#0D1117" FontFamily="Segoe UI">

    <Window.Resources>
        <SolidColorBrush x:Key="PanelBg" Color="#161B22"/>
        <SolidColorBrush x:Key="BorderCol" Color="#30363D"/>
        <SolidColorBrush x:Key="Accent" Color="#58A6FF"/>
        <SolidColorBrush x:Key="AccentDim" Color="#1F6FEB"/>
        <SolidColorBrush x:Key="TextMain" Color="#C9D1D9"/>
        <SolidColorBrush x:Key="TextMuted" Color="#8B949E"/>
        <SolidColorBrush x:Key="Good" Color="#3FB950"/>
        <SolidColorBrush x:Key="Bad" Color="#F85149"/>

        <Style x:Key="CardBorder" TargetType="Border">
            <Setter Property="Background" Value="{StaticResource PanelBg}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="14,10"/>
        </Style>

        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="{StaticResource TextMain}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="Margin" Value="0,0,8,0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12.5"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#30363D"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="{StaticResource AccentDim}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="{StaticResource Accent}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#0D1117"/>
            <Setter Property="Foreground" Value="{StaticResource TextMain}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="CaretBrush" Value="{StaticResource Accent}"/>
        </Style>

        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#0D1117"/>
            <Setter Property="Foreground" Value="Black"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="Padding" Value="8,6"/>
        </Style>

        <Style TargetType="DatePicker">
            <Setter Property="Background" Value="#0D1117"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="Padding" Value="4"/>
        </Style>

        <Style TargetType="TextBlock" x:Key="Label">
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Margin" Value="0,0,0,4"/>
        </Style>

        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource TextMain}"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="Margin" Value="0,6,0,0"/>
        </Style>

        <Style x:Key="BamRowStyle" TargetType="DataGridRow">
            <Setter Property="ToolTip" Value="{Binding SuspiciousReasons}"/>
            <Style.Triggers>
                <DataTrigger Binding="{Binding Severity}" Value="High">
                    <Setter Property="Background" Value="#3A1618"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Severity}" Value="Medium">
                    <Setter Property="Background" Value="#332816"/>
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="FlagCellStyle" TargetType="DataGridCell" BasedOn="{StaticResource {x:Type DataGridCell}}">
            <Style.Triggers>
                <DataTrigger Binding="{Binding Severity}" Value="High">
                    <Setter Property="Foreground" Value="#F85149"/>
                    <Setter Property="FontWeight" Value="Bold"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Severity}" Value="Medium">
                    <Setter Property="Foreground" Value="#D29922"/>
                    <Setter Property="FontWeight" Value="Bold"/>
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="DataGrid">
            <Setter Property="Background" Value="{StaticResource PanelBg}"/>
            <Setter Property="Foreground" Value="{StaticResource TextMain}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="RowBackground" Value="#161B22"/>
            <Setter Property="AlternatingRowBackground" Value="#1C2129"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#21262D"/>
            <Setter Property="VerticalGridLinesBrush" Value="#21262D"/>
            <Setter Property="RowHeaderWidth" Value="0"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="CanUserDeleteRows" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="SelectionMode" Value="Extended"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="FontSize" Value="12.5"/>
            <Setter Property="EnableRowVirtualization" Value="True"/>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="{StaticResource TextMain}"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderCol}"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="10,6"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#1F6FEB"/>
                    <Setter Property="Foreground" Value="White"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- HEADER -->
        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,16">
            <TextBlock Text="BAM Forensic Analyzer" FontSize="24" FontWeight="Bold" Foreground="White"/>
            <TextBlock Text="Background Activity Moderator — Program Execution Artifact" FontSize="13"
                       Foreground="{StaticResource TextMuted}" Margin="16,7,0,0"/>
        </StackPanel>

        <!-- TOOLBAR -->
        <Border Grid.Row="1" Style="{StaticResource CardBorder}" Margin="0,0,0,14">
            <StackPanel Orientation="Horizontal">
                <Button x:Name="btnLoadLive" Style="{StaticResource AccentButton}" Content="⚡ Load Live Registry (this machine)"/>
                <Button x:Name="btnLoadOffline" Style="{StaticResource ModernButton}" Content="🗄 Load Offline SYSTEM Hive..."/>
                <Rectangle Width="1" Fill="{StaticResource BorderCol}" Margin="6,0"/>
                <Button x:Name="btnExportCsv" Style="{StaticResource ModernButton}" Content="⬇ Export CSV"/>
                <Button x:Name="btnExportJson" Style="{StaticResource ModernButton}" Content="⬇ Export JSON"/>
                <Button x:Name="btnCopyPath" Style="{StaticResource ModernButton}" Content="⧉ Copy Selected Path"/>
                <Rectangle Width="1" Fill="{StaticResource BorderCol}" Margin="6,0"/>
                <Button x:Name="btnClearAll" Style="{StaticResource ModernButton}" Content="🗑 Clear All Data"/>
            </StackPanel>
        </Border>

        <!-- STAT CARDS -->
        <Grid Grid.Row="2" Margin="0,0,0,14">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="10"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <Border Grid.Column="0" Style="{StaticResource CardBorder}">
                <StackPanel>
                    <TextBlock Text="TOTAL ENTRIES" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="txtStatTotal" Text="0" FontSize="20" FontWeight="Bold" Foreground="{StaticResource Accent}"/>
                </StackPanel>
            </Border>
            <Border Grid.Column="2" Style="{StaticResource CardBorder}">
                <StackPanel>
                    <TextBlock Text="FILTERED" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="txtStatFiltered" Text="0" FontSize="20" FontWeight="Bold" Foreground="White"/>
                </StackPanel>
            </Border>
            <Border Grid.Column="4" Style="{StaticResource CardBorder}" BorderBrush="#F85149">
                <StackPanel>
                    <TextBlock Text="⚠ SUSPICIOUS" Style="{StaticResource Label}" Foreground="#F85149"/>
                    <TextBlock x:Name="txtStatSuspicious" Text="0" FontSize="20" FontWeight="Bold" Foreground="#F85149"/>
                </StackPanel>
            </Border>
            <Border Grid.Column="6" Style="{StaticResource CardBorder}">
                <StackPanel>
                    <TextBlock Text="UNIQUE USERS" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="txtStatUsers" Text="0" FontSize="20" FontWeight="Bold" Foreground="White"/>
                </StackPanel>
            </Border>
            <Border Grid.Column="8" Style="{StaticResource CardBorder}">
                <StackPanel>
                    <TextBlock Text="UNIQUE EXECUTABLES" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="txtStatApps" Text="0" FontSize="20" FontWeight="Bold" Foreground="White"/>
                </StackPanel>
            </Border>
            <Border Grid.Column="10" Style="{StaticResource CardBorder}">
                <StackPanel>
                    <TextBlock Text="DATE RANGE (UTC)" Style="{StaticResource Label}"/>
                    <TextBlock x:Name="txtStatRange" Text="—" FontSize="13" FontWeight="Bold" Foreground="White" TextWrapping="Wrap"/>
                </StackPanel>
            </Border>
        </Grid>

        <!-- FILTER PANEL -->
        <Border Grid.Row="3" Style="{StaticResource CardBorder}" Margin="0,0,0,14">
            <StackPanel Orientation="Horizontal">
                <StackPanel Width="260" Margin="0,0,16,0">
                    <TextBlock Text="SEARCH (path / filename)" Style="{StaticResource Label}"/>
                    <TextBox x:Name="txtSearch"/>
                </StackPanel>
                <StackPanel Width="200" Margin="0,0,16,0">
                    <TextBlock Text="USER" Style="{StaticResource Label}"/>
                    <ComboBox x:Name="cmbUser"/>
                </StackPanel>
                <StackPanel Width="180" Margin="0,0,16,0">
                    <TextBlock Text="FILE EXISTS ON DISK" Style="{StaticResource Label}"/>
                    <ComboBox x:Name="cmbExists"/>
                </StackPanel>
                <StackPanel Width="150" Margin="0,0,16,0">
                    <TextBlock Text="FROM (UTC DATE)" Style="{StaticResource Label}"/>
                    <DatePicker x:Name="dpFrom"/>
                </StackPanel>
                <StackPanel Width="150" Margin="0,0,16,0">
                    <TextBlock Text="TO (UTC DATE)" Style="{StaticResource Label}"/>
                    <DatePicker x:Name="dpTo"/>
                </StackPanel>
                <StackPanel Width="170" Margin="0,0,16,0">
                    <TextBlock Text="FLAGS" Style="{StaticResource Label}"/>
                    <CheckBox x:Name="chkSuspiciousOnly" Content="⚠ Suspicious only"/>
                </StackPanel>
                <StackPanel Width="190" Margin="0,0,16,0">
                    <TextBlock Text="SESSION" Style="{StaticResource Label}"/>
                    <CheckBox x:Name="chkSinceLogon" Content="🕐 Since Logon only"
                              ToolTip="Shows only live-registry entries executed after the current logon session (or last boot if a per-user session can't be resolved). Offline hive entries are hidden while this is on."/>
                </StackPanel>
                <StackPanel VerticalAlignment="Bottom" Orientation="Horizontal">
                    <Button x:Name="btnClearFilter" Style="{StaticResource ModernButton}" Content="✕ Clear Filters"/>
                </StackPanel>
            </StackPanel>
        </Border>

        <!-- DATA GRID -->
        <Border Grid.Row="4" Style="{StaticResource CardBorder}" Padding="0" Margin="0,0,0,14">
            <DataGrid x:Name="dataGrid" RowStyle="{StaticResource BamRowStyle}">
                <DataGrid.Columns>
                    <DataGridTextColumn Header="Flag" Binding="{Binding SuspiciousLabel}" Width="70" CellStyle="{StaticResource FlagCellStyle}"/>
                    <DataGridTextColumn Header="Username" Binding="{Binding Username}" Width="150"/>
                    <DataGridTextColumn Header="SID" Binding="{Binding SID}" Width="140"/>
                    <DataGridTextColumn Header="File Name" Binding="{Binding FileName}" Width="180"/>
                    <DataGridTextColumn Header="Full Path" Binding="{Binding ResolvedPath}" Width="*"/>
                    <DataGridTextColumn Header="Exists" Binding="{Binding FileExists}" Width="90"/>
                    <DataGridTextColumn Header="Last Execution (UTC)" Binding="{Binding LastExecutionUTC}" Width="160"/>
                    <DataGridTextColumn Header="Last Execution (Local)" Binding="{Binding LastExecutionLocal}" Width="160"/>
                    <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="110"/>
                </DataGrid.Columns>
            </DataGrid>
        </Border>

        <!-- ENTRY DETAILS PANEL (shown when a row is selected) -->
        <Border Grid.Row="5" x:Name="detailsPanel" Style="{StaticResource CardBorder}" Margin="0,0,0,14" Visibility="Collapsed">
            <StackPanel>
                <TextBlock Text="ENTRY DETAILS  (double-click a row to copy its resolved path)" Style="{StaticResource Label}" Foreground="{StaticResource Accent}" FontWeight="Bold" Margin="0,0,0,10"/>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <StackPanel Grid.Row="0" Grid.Column="0" Margin="0,0,12,10">
                        <TextBlock Text="USERNAME" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetUsername" Foreground="White" TextWrapping="Wrap"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="1" Margin="0,0,12,10">
                        <TextBlock Text="SID" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetSid" Foreground="White" TextWrapping="Wrap"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="2" Margin="0,0,12,10">
                        <TextBlock Text="FILE EXISTS ON DISK" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetExists" Foreground="White"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="3" Margin="0,0,0,10">
                        <TextBlock Text="SOURCE" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetSource" Foreground="White"/>
                    </StackPanel>

                    <StackPanel Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="2" Margin="0,0,12,10">
                        <TextBlock Text="RAW / DEVICE PATH (as stored in the registry)" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetRawPath" Foreground="{StaticResource TextMuted}" TextWrapping="Wrap"/>
                    </StackPanel>
                    <StackPanel Grid.Row="1" Grid.Column="2" Grid.ColumnSpan="2" Margin="0,0,0,10">
                        <TextBlock Text="RESOLVED PATH (drive-letter, if available)" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetResolvedPath" Foreground="{StaticResource Accent}" TextWrapping="Wrap" FontWeight="SemiBold"/>
                    </StackPanel>

                    <StackPanel Grid.Row="2" Grid.Column="0" Margin="0,0,12,0">
                        <TextBlock Text="LAST EXEC (UTC)" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetUtc" Foreground="White"/>
                    </StackPanel>
                    <StackPanel Grid.Row="2" Grid.Column="1" Margin="0,0,12,0">
                        <TextBlock Text="LAST EXEC (LOCAL)" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetLocal" Foreground="White"/>
                    </StackPanel>
                    <StackPanel Grid.Row="2" Grid.Column="2" Margin="0,0,12,0">
                        <TextBlock Text="SEVERITY" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetSeverity" Foreground="White" FontWeight="Bold"/>
                    </StackPanel>
                    <StackPanel Grid.Row="2" Grid.Column="3">
                        <TextBlock Text="FLAG REASON(S)" Style="{StaticResource Label}"/>
                        <TextBlock x:Name="txtDetReasons" Foreground="#D29922" TextWrapping="Wrap"/>
                    </StackPanel>
                </Grid>
            </StackPanel>
        </Border>

        <!-- STATUS BAR -->
        <Border Grid.Row="6" Style="{StaticResource CardBorder}" Padding="12,8">
            <TextBlock x:Name="txtStatus" Text="Ready. Load the live registry or an offline SYSTEM hive to begin." Foreground="{StaticResource TextMuted}" FontSize="12"/>
        </Border>
    </Grid>
</Window>
'@

# ============================================================================
#  LOAD WINDOW
# ============================================================================

$reader = New-Object System.Xml.XmlNodeReader $Xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$ctl = @{}
@('btnLoadLive','btnLoadOffline','btnExportCsv','btnExportJson','btnCopyPath','btnClearAll',
  'txtStatTotal','txtStatFiltered','txtStatSuspicious','txtStatUsers','txtStatApps','txtStatRange',
  'txtSearch','cmbUser','cmbExists','dpFrom','dpTo','chkSuspiciousOnly','chkSinceLogon',
  'btnClearFilter','dataGrid','txtStatus',
  'detailsPanel','txtDetUsername','txtDetSid','txtDetExists','txtDetSource',
  'txtDetRawPath','txtDetResolvedPath','txtDetUtc','txtDetLocal','txtDetSeverity','txtDetReasons') | ForEach-Object {
    $ctl[$_] = $window.FindName($_)
}

if (-not $Global:IsAdmin) {
    $ctl.txtStatus.Text = "⚠ Not running as Administrator — live BAM key and offline hive loading may fail. Restart PowerShell as Admin for full functionality."
    $ctl.txtStatus.Foreground = [System.Windows.Media.Brushes]::OrangeRed
}

$ctl.cmbExists.Items.Add("All") | Out-Null
$ctl.cmbExists.Items.Add("Yes") | Out-Null
$ctl.cmbExists.Items.Add("No") | Out-Null
$ctl.cmbExists.Items.Add("N/A (offline)") | Out-Null
$ctl.cmbExists.SelectedIndex = 0

# ============================================================================
#  UI LOGIC
# ============================================================================

function Refresh-UserFilterList {
    $selected = $ctl.cmbUser.SelectedItem
    $ctl.cmbUser.Items.Clear()
    $ctl.cmbUser.Items.Add("All Users") | Out-Null
    $Global:AllEntries | Select-Object -ExpandProperty Username -Unique | Sort-Object | ForEach-Object {
        $ctl.cmbUser.Items.Add($_) | Out-Null
    }
    if ($selected -and $ctl.cmbUser.Items.Contains($selected)) {
        $ctl.cmbUser.SelectedItem = $selected
    } else {
        $ctl.cmbUser.SelectedIndex = 0
    }
}

function Update-SummaryStats {
    $total = $Global:AllEntries.Count
    $ctl.txtStatTotal.Text = "$total"
    $ctl.txtStatSuspicious.Text = "$(($Global:AllEntries | Where-Object { $_.IsSuspicious }).Count)"
    $ctl.txtStatUsers.Text = "$(($Global:AllEntries | Select-Object -ExpandProperty Username -Unique).Count)"
    $ctl.txtStatApps.Text  = "$(($Global:AllEntries | Select-Object -ExpandProperty ExecutablePath -Unique).Count)"
    if ($total -gt 0) {
        $minD = ($Global:AllEntries | Sort-Object LastExecutionUTC | Select-Object -First 1).LastExecutionUTC
        $maxD = ($Global:AllEntries | Sort-Object LastExecutionUTC | Select-Object -Last 1).LastExecutionUTC
        $ctl.txtStatRange.Text = "$($minD.ToString('yyyy-MM-dd')) to $($maxD.ToString('yyyy-MM-dd'))"
    } else {
        $ctl.txtStatRange.Text = "—"
    }
}

function Apply-Filters {
    $search = $ctl.txtSearch.Text
    $userSel = $ctl.cmbUser.SelectedItem
    $existsSel = $ctl.cmbExists.SelectedItem
    $from = $ctl.dpFrom.SelectedDate
    $to   = $ctl.dpTo.SelectedDate

    $filtered = $Global:AllEntries

    if (-not [string]::IsNullOrWhiteSpace($search)) {
        $filtered = $filtered | Where-Object {
            $_.ExecutablePath -like "*$search*" -or $_.FileName -like "*$search*" -or $_.Username -like "*$search*"
        }
    }
    if ($userSel -and $userSel -ne "All Users") {
        $filtered = $filtered | Where-Object { $_.Username -eq $userSel }
    }
    if ($existsSel -and $existsSel -ne "All") {
        $filtered = $filtered | Where-Object { $_.FileExists -eq $existsSel }
    }
    if ($from) {
        $filtered = $filtered | Where-Object { $_.LastExecutionUTC -ge $from }
    }
    if ($to) {
        $toEnd = $to.Value.Date.AddDays(1).AddSeconds(-1)
        $filtered = $filtered | Where-Object { $_.LastExecutionUTC -le $toEnd }
    }
    if ($ctl.chkSuspiciousOnly.IsChecked) {
        $filtered = $filtered | Where-Object { $_.IsSuspicious }
    }
    if ($ctl.chkSinceLogon.IsChecked) {
        $filtered = $filtered | Where-Object {
            if ($_.Source -ne "Live Registry") { return $false }
            $threshold = $null
            if ($Global:SessionBoundaries.LogonMap.ContainsKey($_.SID)) {
                $threshold = $Global:SessionBoundaries.LogonMap[$_.SID]
            } elseif ($Global:SessionBoundaries.BootTimeUtc) {
                $threshold = $Global:SessionBoundaries.BootTimeUtc
            }
            if (-not $threshold) { return $true }
            return $_.LastExecutionUTC -ge $threshold
        }
    }

    $filteredList = @($filtered)
    $ctl.dataGrid.ItemsSource = $filteredList
    $ctl.txtStatFiltered.Text = "$($filteredList.Count)"

    # Keep the Suspicious counter in sync with the ACTIVE filters.
    # Update-SummaryStats intentionally uses AllEntries for the unfiltered
    # overview, but every filter change must recalculate this value from the
    # rows that are currently visible.
    $filteredSuspiciousCount = @(
        $filteredList | Where-Object { $_.IsSuspicious }
    ).Count
    $ctl.txtStatSuspicious.Text = "$filteredSuspiciousCount"

    try {
        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ctl.dataGrid.ItemsSource)
        $view.SortDescriptions.Clear()
        $view.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription("LastExecutionUTC", [System.ComponentModel.ListSortDirection]::Descending)))
    } catch {}

    # Selection (and therefore the details panel) may no longer be valid after re-filtering
    $ctl.detailsPanel.Visibility = 'Collapsed'
}

function Show-EntryDetails {
    param($Item)
    if (-not $Item) {
        $ctl.detailsPanel.Visibility = 'Collapsed'
        return
    }
    $ctl.txtDetUsername.Text      = $Item.Username
    $ctl.txtDetSid.Text           = $Item.SID
    $ctl.txtDetExists.Text        = $Item.FileExists
    $ctl.txtDetSource.Text        = $Item.Source
    $ctl.txtDetRawPath.Text       = $Item.ExecutablePath
    $ctl.txtDetResolvedPath.Text  = $Item.ResolvedPath
    $ctl.txtDetUtc.Text           = $Item.LastExecutionUTC
    $ctl.txtDetLocal.Text         = $Item.LastExecutionLocal
    $ctl.txtDetSeverity.Text      = if ($Item.Severity -eq "None") { "—" } else { $Item.Severity }
    $ctl.txtDetReasons.Text       = if ($Item.SuspiciousReasons) { $Item.SuspiciousReasons } else { "No flags on this entry." }
    $ctl.detailsPanel.Visibility  = 'Visible'
}

function Load-Data {
    param([scriptblock]$LoaderScriptBlock, [string]$BusyText)
    $ctl.txtStatus.Text = $BusyText
    $ctl.txtStatus.Foreground = [System.Windows.Media.Brushes]::Orange
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        $newEntries = & $LoaderScriptBlock
        if ($newEntries -and $newEntries.Count -gt 0) {
            foreach ($e in $newEntries) { $Global:AllEntries.Add($e) }
        }
        Refresh-UserFilterList
        Update-SummaryStats
        Apply-Filters
        $ctl.txtStatus.Text = "Loaded $($newEntries.Count) BAM entries. Total in memory: $($Global:AllEntries.Count)."
        $ctl.txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
    } catch {
        $ctl.txtStatus.Text = "ERROR: $($_.Exception.Message)"
        $ctl.txtStatus.Foreground = [System.Windows.Media.Brushes]::OrangeRed
        [System.Windows.MessageBox]::Show($_.Exception.Message, "BAM Analyzer Error", 'OK', 'Error') | Out-Null
    } finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    }
}

# ============================================================================
#  EVENT HANDLERS
# ============================================================================

$ctl.btnLoadLive.Add_Click({
    Load-Data -BusyText "Reading live BAM registry key..." -LoaderScriptBlock {
        if (-not $Global:VolumeMap -or $Global:VolumeMap.Count -eq 0) {
            $Global:VolumeMap = Build-VolumeMap
        }
        $Global:SessionBoundaries = Get-SessionBoundaries
        if ($Global:SessionBoundaries.BootTimeUtc) {
            $ctl.chkSinceLogon.ToolTip = "Shows only live-registry entries executed after the current logon session (or last boot if a per-user session can't be resolved). Offline hive entries are hidden while this is on.`n`nLast boot (UTC): $($Global:SessionBoundaries.BootTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
        }
        $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        Get-BamEntries -UserSettingsPath $path -SourceLabel "Live Registry"
    }
})

$ctl.btnLoadOffline.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = "Select offline SYSTEM registry hive"
    $dlg.Filter = "SYSTEM hive|SYSTEM;*.hiv;*.dat|All files|*.*"
    if ($dlg.ShowDialog()) {
        $path = $dlg.FileName
        Load-Data -BusyText "Loading offline hive: $path ..." -LoaderScriptBlock {
            Load-OfflineHive -HiveFilePath $path
        }
    }
})

$ctl.btnClearAll.Add_Click({
    $Global:AllEntries.Clear()
    Refresh-UserFilterList
    Update-SummaryStats
    Apply-Filters
    $ctl.txtStatus.Text = "All data cleared."
    $ctl.txtStatus.Foreground = [System.Windows.Media.Brushes]::Gray
})

$ctl.btnExportCsv.Add_Click({
    $items = $ctl.dataGrid.ItemsSource
    if (-not $items -or $items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No data to export.", "Export CSV") | Out-Null
        return
    }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "CSV file|*.csv"
    $dlg.FileName = "BAM_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog()) {
        $items | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        $ctl.txtStatus.Text = "Exported $($items.Count) rows to $($dlg.FileName)"
    }
})

$ctl.btnExportJson.Add_Click({
    $items = $ctl.dataGrid.ItemsSource
    if (-not $items -or $items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No data to export.", "Export JSON") | Out-Null
        return
    }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "JSON file|*.json"
    $dlg.FileName = "BAM_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    if ($dlg.ShowDialog()) {
        $items | ConvertTo-Json -Depth 4 | Out-File -FilePath $dlg.FileName -Encoding UTF8
        $ctl.txtStatus.Text = "Exported $($items.Count) rows to $($dlg.FileName)"
    }
})

$ctl.btnCopyPath.Add_Click({
    $sel = $ctl.dataGrid.SelectedItems
    if ($sel -and $sel.Count -gt 0) {
        $paths = $sel | ForEach-Object { $_.ResolvedPath }
        [System.Windows.Clipboard]::SetText(($paths -join "`r`n"))
        $ctl.txtStatus.Text = "Copied $($sel.Count) path(s) to clipboard."
    } else {
        $ctl.txtStatus.Text = "No rows selected."
    }
})

$ctl.btnClearFilter.Add_Click({
    $ctl.txtSearch.Text = ""
    $ctl.cmbUser.SelectedIndex = 0
    $ctl.cmbExists.SelectedIndex = 0
    $ctl.dpFrom.SelectedDate = $null
    $ctl.dpTo.SelectedDate = $null
    $ctl.chkSuspiciousOnly.IsChecked = $false
    $ctl.chkSinceLogon.IsChecked = $false
    Apply-Filters
})

# Row selection -> populate the details panel underneath the grid
$ctl.dataGrid.Add_SelectionChanged({
    Show-EntryDetails -Item $ctl.dataGrid.SelectedItem
})

# Double-click a row -> copy its resolved path straight to the clipboard
$ctl.dataGrid.Add_MouseDoubleClick({
    $item = $ctl.dataGrid.SelectedItem
    if ($item) {
        [System.Windows.Clipboard]::SetText($item.ResolvedPath)
        $ctl.txtStatus.Text = "Copied path to clipboard: $($item.ResolvedPath)"
        $ctl.txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
    }
})

$ctl.txtSearch.Add_TextChanged({ Apply-Filters })
$ctl.cmbUser.Add_SelectionChanged({ Apply-Filters })
$ctl.cmbExists.Add_SelectionChanged({ Apply-Filters })
$ctl.dpFrom.Add_SelectedDateChanged({ Apply-Filters })
$ctl.dpTo.Add_SelectedDateChanged({ Apply-Filters })
$ctl.chkSuspiciousOnly.Add_Checked({ Apply-Filters })
$ctl.chkSuspiciousOnly.Add_Unchecked({ Apply-Filters })
$ctl.chkSinceLogon.Add_Checked({ Apply-Filters })
$ctl.chkSinceLogon.Add_Unchecked({ Apply-Filters })

# ============================================================================
#  SHOW WINDOW
# ============================================================================

$window.ShowDialog() | Out-Null
