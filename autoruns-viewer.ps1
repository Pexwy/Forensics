# autoruns-viewer.ps1
# Autoruns-style startup inspector: Registry Run keys, Startup folder,
# auto-start Services, and boot/logon-triggered Scheduled Tasks in one view.
# Requires admin rights for full visibility and to toggle entries.

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Column sorter ---
Add-Type -TypeDefinition @"
using System;
using System.Collections;
using System.Windows.Forms;

public class ListViewColumnSorter : IComparer
{
    private int ColumnToSort;
    private SortOrder OrderOfSort;
    private CaseInsensitiveComparer ObjectCompare;

    public ListViewColumnSorter()
    {
        ColumnToSort = 0;
        OrderOfSort = SortOrder.None;
        ObjectCompare = new CaseInsensitiveComparer();
    }

    public int Compare(object x, object y)
    {
        ListViewItem itemX = (ListViewItem)x;
        ListViewItem itemY = (ListViewItem)y;
        string textX = itemX.SubItems[ColumnToSort].Text;
        string textY = itemY.SubItems[ColumnToSort].Text;
        int compareResult = ObjectCompare.Compare(textX, textY);

        if (OrderOfSort == SortOrder.Ascending) return compareResult;
        else if (OrderOfSort == SortOrder.Descending) return -compareResult;
        else return 0;
    }

    public int SortColumn
    {
        set { ColumnToSort = value; }
        get { return ColumnToSort; }
    }

    public SortOrder Order
    {
        set { OrderOfSort = value; }
        get { return OrderOfSort; }
    }
}
"@ -ReferencedAssemblies System.Windows.Forms

# --- Palette (dark theme, matches other tools in this set) ---
$colorBg          = [System.Drawing.Color]::FromArgb(18, 19, 26)
$colorPanel       = [System.Drawing.Color]::FromArgb(27, 29, 38)
$colorHeaderBg    = [System.Drawing.Color]::FromArgb(14, 15, 21)
$colorText        = [System.Drawing.Color]::FromArgb(235, 236, 240)
$colorSubText     = [System.Drawing.Color]::FromArgb(130, 133, 150)
$colorGray        = [System.Drawing.Color]::FromArgb(120, 124, 140)
$colorRed         = [System.Drawing.Color]::FromArgb(248, 113, 113)
$colorAccent      = [System.Drawing.Color]::FromArgb(99, 102, 241)
$colorAccentHover = [System.Drawing.Color]::FromArgb(79, 82, 221)
$colorAccentDark  = [System.Drawing.Color]::FromArgb(45, 48, 66)
$colorAccentDarkH = [System.Drawing.Color]::FromArgb(58, 62, 84)
$colorDanger      = [System.Drawing.Color]::FromArgb(239, 68, 68)
$colorDangerHover = [System.Drawing.Color]::FromArgb(220, 38, 38)
$colorRowNormal   = [System.Drawing.Color]::FromArgb(27, 29, 38)
$colorRowFlagged  = [System.Drawing.Color]::FromArgb(58, 33, 33)
$colorRowDisabled = [System.Drawing.Color]::FromArgb(32, 34, 44)

function Enable-DoubleBuffer($ctrl) {
    $prop = [System.Windows.Forms.Control].GetProperty("DoubleBuffered", [System.Reflection.BindingFlags]"NonPublic, Instance")
    $prop.SetValue($ctrl, $true, $null)
}

function New-StyledButton($text, $x, $y, $width, $height, $bgColor, $hoverColor, $fg = [System.Drawing.Color]::White) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Size = New-Object System.Drawing.Size($width, $height)
    $btn.Location = New-Object System.Drawing.Point($x, $y)
    $btn.BackColor = $bgColor
    $btn.ForeColor = $fg
    $btn.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
    $btn.FlatStyle = "Flat"
    $btn.FlatAppearance.BorderSize = 0
    $btn.FlatAppearance.MouseOverBackColor = $hoverColor
    $btn.FlatAppearance.MouseDownBackColor = $hoverColor
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $btn
}

# --- Suspicion heuristics (shared pattern with scheduled-tasks-inspector.ps1) ---
function Get-SuspicionReason($commandLine) {
    $reasons = @()
    if ([string]::IsNullOrWhiteSpace($commandLine)) { return $reasons }

    if ($commandLine -match '\\(Temp|AppData\\Local\\Temp)\\') { $reasons += "Runs from Temp" }
    if ($commandLine -match '\\Users\\[^\\]+\\AppData\\Roaming\\') { $reasons += "Runs from AppData\Roaming" }
    if ($commandLine -match '\\ProgramData\\[^\\]+\.(exe|dll|vbs|ps1)') { $reasons += "Runs from ProgramData" }
    if ($commandLine -match '-enc(odedcommand)?\s') { $reasons += "Encoded PowerShell" }
    if ($commandLine -match '-w(indowstyle)?\s+hidden') { $reasons += "Hidden window" }
    if ($commandLine -match 'mshta\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe|rundll32\.exe') { $reasons += "LOLBin" }
    if ($commandLine -match 'certutil\.exe.*-urlcache') { $reasons += "certutil as downloader" }
    if ($commandLine -match 'http://|https://') { $reasons += "Contains a URL" }
    if ($commandLine -notmatch '^[A-Za-z]:\\|^"%|^%|^\\\\') { $reasons += "No fixed/qualified path" }

    return $reasons | Select-Object -Unique
}

function Get-ExecutablePath($commandLine) {
    if ([string]::IsNullOrWhiteSpace($commandLine)) { return "" }
    if ($commandLine.StartsWith('"')) {
        $end = $commandLine.IndexOf('"', 1)
        if ($end -gt 0) { return $commandLine.Substring(1, $end - 1) }
    }
    return ($commandLine -split '\s+')[0]
}

# --- Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Autoruns Viewer"
$form.Size = New-Object System.Drawing.Size(1080, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = $colorBg
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$form.MinimumSize = New-Object System.Drawing.Size(900, 500)

# --- Header ---
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(1080, 78)
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.BackColor = $colorHeaderBg
$headerPanel.Anchor = "Top,Left,Right"
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Autoruns Viewer"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 16)
$titleLabel.ForeColor = $colorText
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(24, 14)
$headerPanel.Controls.Add($titleLabel)

$subLabel = New-Object System.Windows.Forms.Label
$subLabel.Text = "Registry Run keys, Startup folder, auto-start Services, and logon/boot Scheduled Tasks"
$subLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subLabel.ForeColor = $colorSubText
$subLabel.AutoSize = $true
$subLabel.Location = New-Object System.Drawing.Point(26, 46)
$headerPanel.Controls.Add($subLabel)

$chipTotal = New-Object System.Windows.Forms.Label
$chipTotal.AutoSize = $true
$chipTotal.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
$chipTotal.ForeColor = $colorText
$chipTotal.Location = New-Object System.Drawing.Point(800, 14)
$chipTotal.Anchor = "Top,Right"
$headerPanel.Controls.Add($chipTotal)

$chipFlagged = New-Object System.Windows.Forms.Label
$chipFlagged.AutoSize = $true
$chipFlagged.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
$chipFlagged.ForeColor = $colorRed
$chipFlagged.Location = New-Object System.Drawing.Point(800, 38)
$chipFlagged.Anchor = "Top,Right"
$headerPanel.Controls.Add($chipFlagged)

# --- Filter bar ---
$filterPanel = New-Object System.Windows.Forms.Panel
$filterPanel.Size = New-Object System.Drawing.Size(1040, 36)
$filterPanel.Location = New-Object System.Drawing.Point(20, 88)
$filterPanel.Anchor = "Top,Left,Right"
$form.Controls.Add($filterPanel)

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Size = New-Object System.Drawing.Size(280, 26)
$searchBox.Location = New-Object System.Drawing.Point(0, 4)
$searchBox.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$searchBox.BackColor = $colorPanel
$searchBox.ForeColor = $colorText
$searchBox.BorderStyle = "FixedSingle"
$filterPanel.Controls.Add($searchBox)

$searchHint = New-Object System.Windows.Forms.Label
$searchHint.Text = "🔍 Filter by name, command, or location..."
$searchHint.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$searchHint.ForeColor = $colorGray
$searchHint.AutoSize = $true
$searchHint.Location = New-Object System.Drawing.Point(290, 8)
$filterPanel.Controls.Add($searchHint)

$sourceFilter = New-Object System.Windows.Forms.ComboBox
$sourceFilter.DropDownStyle = "DropDownList"
$sourceFilter.Size = New-Object System.Drawing.Size(160, 26)
$sourceFilter.Location = New-Object System.Drawing.Point(610, 4)
$sourceFilter.Anchor = "Top,Right"
$sourceFilter.Items.AddRange(@("All Sources", "Registry Run", "Startup Folder", "Service", "Scheduled Task"))
$sourceFilter.SelectedIndex = 0
$filterPanel.Controls.Add($sourceFilter)

$flaggedOnlyCheck = New-Object System.Windows.Forms.CheckBox
$flaggedOnlyCheck.Text = "Flagged only"
$flaggedOnlyCheck.ForeColor = $colorText
$flaggedOnlyCheck.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$flaggedOnlyCheck.AutoSize = $true
$flaggedOnlyCheck.Location = New-Object System.Drawing.Point(790, 7)
$flaggedOnlyCheck.Anchor = "Top,Right"
$filterPanel.Controls.Add($flaggedOnlyCheck)

$enabledOnlyCheck = New-Object System.Windows.Forms.CheckBox
$enabledOnlyCheck.Text = "Enabled only"
$enabledOnlyCheck.ForeColor = $colorText
$enabledOnlyCheck.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$enabledOnlyCheck.AutoSize = $true
$enabledOnlyCheck.Location = New-Object System.Drawing.Point(920, 7)
$enabledOnlyCheck.Anchor = "Top,Right"
$filterPanel.Controls.Add($enabledOnlyCheck)

# --- ListView ---
$listView = New-Object System.Windows.Forms.ListView
$listView.View = "Details"
$listView.FullRowSelect = $true
$listView.GridLines = $false
$listView.MultiSelect = $true
$listView.HideSelection = $false
$listView.Size = New-Object System.Drawing.Size(1040, 420)
$listView.Location = New-Object System.Drawing.Point(20, 130)
$listView.Anchor = "Top,Bottom,Left,Right"
$listView.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$listView.BackColor = $colorPanel
$listView.ForeColor = $colorText
$listView.BorderStyle = "FixedSingle"
$listView.Columns.Add("Source", 100) | Out-Null
$listView.Columns.Add("Name", 170) | Out-Null
$listView.Columns.Add("State", 80) | Out-Null
$listView.Columns.Add("Command / Path", 320) | Out-Null
$listView.Columns.Add("Location", 220) | Out-Null
$listView.Columns.Add("Flags", 150) | Out-Null
Enable-DoubleBuffer $listView
$form.Controls.Add($listView)

$script:sorter = New-Object ListViewColumnSorter
$listView.ListViewItemSorter = $script:sorter
$listView.Add_ColumnClick({
    param($sender, $e)
    if ($e.Column -eq $script:sorter.SortColumn) {
        $script:sorter.Order = if ($script:sorter.Order -eq [System.Windows.Forms.SortOrder]::Ascending) { [System.Windows.Forms.SortOrder]::Descending } else { [System.Windows.Forms.SortOrder]::Ascending }
    } else {
        $script:sorter.SortColumn = $e.Column
        $script:sorter.Order = [System.Windows.Forms.SortOrder]::Ascending
    }
    $listView.Sort()
})

# --- Detail box ---
$detailBox = New-Object System.Windows.Forms.TextBox
$detailBox.Multiline = $true
$detailBox.ReadOnly = $true
$detailBox.ScrollBars = "Vertical"
$detailBox.Size = New-Object System.Drawing.Size(1040, 70)
$detailBox.Location = New-Object System.Drawing.Point(20, 558)
$detailBox.Anchor = "Bottom,Left,Right"
$detailBox.BackColor = $colorPanel
$detailBox.ForeColor = $colorSubText
$detailBox.Font = New-Object System.Drawing.Font("Consolas", 8.5)
$detailBox.BorderStyle = "FixedSingle"
$detailBox.Text = "Select an entry above for full details."
$form.Controls.Add($detailBox)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Loading..."
$statusLabel.AutoSize = $true
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Italic)
$statusLabel.ForeColor = $colorSubText
$statusLabel.Location = New-Object System.Drawing.Point(20, 640)
$statusLabel.Anchor = "Bottom,Left"
$form.Controls.Add($statusLabel)

# --- Buttons ---
$enableButton = New-StyledButton "Enable" 560 636 90 34 $colorAccent $colorAccentHover
$enableButton.Anchor = "Bottom,Right"
$form.Controls.Add($enableButton)

$disableButton = New-StyledButton "Disable" 660 636 90 34 $colorAccentDark $colorAccentDarkH $colorText
$disableButton.Anchor = "Bottom,Right"
$form.Controls.Add($disableButton)

$openButton = New-StyledButton "Open Location" 760 636 110 34 ([System.Drawing.Color]::FromArgb(70,73,88)) ([System.Drawing.Color]::FromArgb(90,93,110)) $colorText
$openButton.Anchor = "Bottom,Right"
$form.Controls.Add($openButton)

$refreshButton = New-StyledButton "Refresh" 880 636 80 34 $colorGray ([System.Drawing.Color]::FromArgb(100,103,120)) $colorBg
$refreshButton.Anchor = "Bottom,Right"
$form.Controls.Add($refreshButton)

$exportButton = New-StyledButton "Export CSV" 970 636 90 34 $colorDanger $colorDangerHover
$exportButton.Anchor = "Bottom,Right"
$form.Controls.Add($exportButton)

# ============================================================
# DATA COLLECTION
# ============================================================
$script:allEntries = @()

function Get-RunKeyEntries {
    $entries = @()
    $keys = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM\...\Run" }
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM\...\Run (WOW6432)" }
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKLM\...\RunOnce" }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Label = "HKCU\...\Run" }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKCU\...\RunOnce" }
    )

    foreach ($k in $keys) {
        if (-not (Test-Path $k.Path)) { continue }
        $props = Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
            ForEach-Object {
                $cmd = $_.Value
                $disabled = $false
                # Check StartupApproved flag (what Task Manager's Startup tab actually toggles)
                $approvedPath = if ($k.Path -like "HKCU:*") { "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" } else { "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" }
                if (Test-Path $approvedPath) {
                    $approvedVal = (Get-ItemProperty -Path $approvedPath -ErrorAction SilentlyContinue).$($_.Name)
                    if ($approvedVal -and $approvedVal[0] -eq 3) { $disabled = $true }
                }
                $entries += [PSCustomObject]@{
                    Source     = "Registry Run"
                    Name       = $_.Name
                    State      = if ($disabled) { "Disabled" } else { "Enabled" }
                    Command    = $cmd
                    Location   = $k.Label
                    RegPath    = $k.Path
                    ApprovedPath = $approvedPath
                    Flags      = Get-SuspicionReason $cmd
                }
            }
    }
    return $entries
}

function Get-StartupFolderEntries {
    $entries = @()
    $folders = @(
        @{ Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Label = "All Users Startup" }
        @{ Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp"; Label = "User Startup" }
    )
    $shell = New-Object -ComObject WScript.Shell

    foreach ($f in $folders) {
        if (-not (Test-Path $f.Path)) { continue }
        Get-ChildItem -Path $f.Path -File -ErrorAction SilentlyContinue | ForEach-Object {
            $target = $_.FullName
            if ($_.Extension -eq ".lnk") {
                try {
                    $lnk = $shell.CreateShortcut($_.FullName)
                    $target = "$($lnk.TargetPath) $($lnk.Arguments)".Trim()
                } catch { $target = $_.FullName }
            }
            $entries += [PSCustomObject]@{
                Source   = "Startup Folder"
                Name     = $_.BaseName
                State    = "Enabled"
                Command  = $target
                Location = $f.Label
                FilePath = $_.FullName
                Flags    = Get-SuspicionReason $target
            }
        }
    }
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
    return $entries
}

function Get-AutoServiceEntries {
    $entries = @()
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartMode -eq "Auto" } |
        ForEach-Object {
            $entries += [PSCustomObject]@{
                Source     = "Service"
                Name       = $_.Name
                State      = $_.State
                Command    = $_.PathName
                Location   = "Services (Automatic)"
                ServiceName = $_.Name
                Flags      = Get-SuspicionReason $_.PathName
            }
        }
    return $entries
}

function Get-StartupTaskEntries {
    $entries = @()
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $t = $_
        $hasStartupTrigger = $false
        foreach ($trig in $t.Triggers) {
            $className = $trig.CimClass.CimClassName
            if ($className -match "LogonTrigger|BootTrigger") { $hasStartupTrigger = $true; break }
        }
        if (-not $hasStartupTrigger) { return }

        $execAction = $t.Actions | Where-Object { $_.Execute } | Select-Object -First 1
        $cmd = if ($execAction) { "$($execAction.Execute) $($execAction.Arguments)".Trim() } else { "" }

        $entries += [PSCustomObject]@{
            Source     = "Scheduled Task"
            Name       = $t.TaskName
            State      = $t.State.ToString()
            Command    = $cmd
            Location   = $t.TaskPath
            TaskName   = $t.TaskName
            TaskFolder = $t.TaskPath
            Flags      = Get-SuspicionReason $cmd
        }
    }
    return $entries
}

function Load-Entries {
    $statusLabel.Text = "Scanning startup locations..."
    [System.Windows.Forms.Application]::DoEvents()

    $all = @()
    $all += Get-RunKeyEntries
    $all += Get-StartupFolderEntries
    $all += Get-AutoServiceEntries
    $all += Get-StartupTaskEntries

    $script:allEntries = $all
    $chipTotal.Text = "$($all.Count) startup entries"
    $chipFlagged.Text = "$(($all | Where-Object { $_.Flags.Count -gt 0 }).Count) flagged"
    Render-List
    $statusLabel.Text = "Last scanned: $(Get-Date -Format 'HH:mm:ss')"
}

function Render-List {
    $listView.Items.Clear()
    $filterText = $searchBox.Text.Trim().ToLower()
    $sourceSel = $sourceFilter.SelectedItem
    $flaggedOnly = $flaggedOnlyCheck.Checked
    $enabledOnly = $enabledOnlyCheck.Checked

    foreach ($e in $script:allEntries) {
        if ($sourceSel -and $sourceSel -ne "All Sources" -and $e.Source -ne $sourceSel) { continue }
        if ($flaggedOnly -and $e.Flags.Count -eq 0) { continue }
        if ($enabledOnly -and $e.State -match "Disabled") { continue }
        if ($filterText -and
            $e.Name.ToLower() -notmatch [regex]::Escape($filterText) -and
            $e.Command.ToLower() -notmatch [regex]::Escape($filterText) -and
            $e.Location.ToLower() -notmatch [regex]::Escape($filterText)) { continue }

        $item = New-Object System.Windows.Forms.ListViewItem([string]$e.Source)
        $item.SubItems.Add([string]$e.Name) | Out-Null
        $item.SubItems.Add([string]$e.State) | Out-Null
        $item.SubItems.Add([string]$e.Command) | Out-Null
        $item.SubItems.Add([string]$e.Location) | Out-Null
        $item.SubItems.Add($(if ($e.Flags.Count -gt 0) { $e.Flags -join "; " } else { "" })) | Out-Null

        if ($e.Flags.Count -gt 0) {
            $item.BackColor = $colorRowFlagged
            $item.ForeColor = $colorRed
        } elseif ($e.State -match "Disabled|Stopped") {
            $item.BackColor = $colorRowDisabled
            $item.ForeColor = $colorGray
        } else {
            $item.BackColor = $colorRowNormal
            $item.ForeColor = $colorText
        }
        $item.Tag = $e
        $listView.Items.Add($item) | Out-Null
    }
}

$listView.Add_SelectedIndexChanged({
    if ($listView.SelectedItems.Count -eq 1) {
        $e = $listView.SelectedItems[0].Tag
        $lines = @(
            "Source:   $($e.Source)"
            "Name:     $($e.Name)"
            "State:    $($e.State)"
            "Command:  $($e.Command)"
            "Location: $($e.Location)"
        )
        if ($e.Flags.Count -gt 0) { $lines += "FLAGS:    $($e.Flags -join ', ')" }
        $detailBox.Text = $lines -join "`r`n"
    }
})

function Set-RunKeyApproved($entry, $enable) {
    try {
        $bytes = New-Object byte[] 12
        $bytes[0] = if ($enable) { 2 } else { 3 }
        if (-not (Test-Path $entry.ApprovedPath)) {
            New-Item -Path $entry.ApprovedPath -Force | Out-Null
        }
        New-ItemProperty -Path $entry.ApprovedPath -Name $entry.Name -PropertyType Binary -Value $bytes -Force | Out-Null
        return $true
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to toggle $($entry.Name): $_", "Error", "OK", "Error")
        return $false
    }
}

$enableButton.Add_Click({
    foreach ($item in $listView.SelectedItems) {
        $e = $item.Tag
        switch ($e.Source) {
            "Registry Run"    { Set-RunKeyApproved $e $true | Out-Null }
            "Service"         { try { Set-Service -Name $e.ServiceName -StartupType Automatic -ErrorAction Stop; Start-Service -Name $e.ServiceName -ErrorAction SilentlyContinue } catch { [System.Windows.Forms.MessageBox]::Show("Failed: $_", "Error") } }
            "Scheduled Task"  { try { Enable-ScheduledTask -TaskName $e.TaskName -TaskPath $e.TaskFolder -ErrorAction Stop | Out-Null } catch { [System.Windows.Forms.MessageBox]::Show("Failed: $_", "Error") } }
            "Startup Folder"  { [System.Windows.Forms.MessageBox]::Show("Startup folder items are enabled by presence — nothing to toggle. Use Open Location or delete the shortcut to remove it.", "Info") }
        }
    }
    Load-Entries
})

$disableButton.Add_Click({
    foreach ($item in $listView.SelectedItems) {
        $e = $item.Tag
        switch ($e.Source) {
            "Registry Run"    { Set-RunKeyApproved $e $false | Out-Null }
            "Service"         { try { Stop-Service -Name $e.ServiceName -Force -ErrorAction SilentlyContinue; Set-Service -Name $e.ServiceName -StartupType Disabled -ErrorAction Stop } catch { [System.Windows.Forms.MessageBox]::Show("Failed: $_", "Error") } }
            "Scheduled Task"  { try { Disable-ScheduledTask -TaskName $e.TaskName -TaskPath $e.TaskFolder -ErrorAction Stop | Out-Null } catch { [System.Windows.Forms.MessageBox]::Show("Failed: $_", "Error") } }
            "Startup Folder"  { [System.Windows.Forms.MessageBox]::Show("Startup folder items can't be soft-disabled — delete the shortcut via Open Location to remove it.", "Info") }
        }
    }
    Load-Entries
})

$openButton.Add_Click({
    if ($listView.SelectedItems.Count -ne 1) { return }
    $e = $listView.SelectedItems[0].Tag
    switch ($e.Source) {
        "Startup Folder" { Start-Process explorer.exe -ArgumentList "/select,`"$($e.FilePath)`"" }
        "Registry Run"   { Start-Process explorer.exe -ArgumentList "/select,`"$env:WINDIR\regedit.exe`""; [System.Windows.Forms.MessageBox]::Show("Registry path:`n$($e.RegPath)`n`nCopy this into regedit's address bar.", "Registry Location") }
        "Service"        { Start-Process services.msc }
        "Scheduled Task" { Start-Process taskschd.msc }
    }
})

$refreshButton.Add_Click({ Load-Entries })
$searchBox.Add_TextChanged({ $searchHint.Visible = ($searchBox.Text.Length -eq 0); Render-List })
$searchBox.Add_Enter({ $searchHint.Visible = $false })
$searchBox.Add_Leave({ $searchHint.Visible = ($searchBox.Text.Length -eq 0) })
$sourceFilter.Add_SelectedIndexChanged({ Render-List })
$flaggedOnlyCheck.Add_CheckedChanged({ Render-List })
$enabledOnlyCheck.Add_CheckedChanged({ Render-List })

$exportButton.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv"
    $saveDialog.FileName = "autoruns-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:allEntries | Select-Object Source, Name, State, Command, Location,
            @{Name="Flags";Expression={$_.Flags -join "; "}} |
            Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        $statusLabel.Text = "Exported to $($saveDialog.FileName)"
    }
})

Load-Entries
[System.Windows.Forms.Application]::Run($form)
