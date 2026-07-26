# eventlog-viewer.ps1
# Forensic-style Event Log quick viewer: pre-filtered to security-relevant event IDs
# (logon failures, new accounts, service installs, cleared logs, PowerShell script blocks, etc.)
# Requires admin rights to read the Security log.

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

        DateTime dtX, dtY;
        int compareResult;
        if (DateTime.TryParse(textX, out dtX) && DateTime.TryParse(textY, out dtY))
        {
            compareResult = DateTime.Compare(dtX, dtY);
        }
        else
        {
            compareResult = ObjectCompare.Compare(textX, textY);
        }

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
$colorYellow      = [System.Drawing.Color]::FromArgb(250, 204, 21)
$colorAccent      = [System.Drawing.Color]::FromArgb(99, 102, 241)
$colorAccentHover = [System.Drawing.Color]::FromArgb(79, 82, 221)
$colorGrayBtn     = [System.Drawing.Color]::FromArgb(70, 73, 88)
$colorGrayBtnH    = [System.Drawing.Color]::FromArgb(90, 93, 110)
$colorDanger      = [System.Drawing.Color]::FromArgb(239, 68, 68)
$colorDangerHover = [System.Drawing.Color]::FromArgb(220, 38, 38)
$colorRowHigh     = [System.Drawing.Color]::FromArgb(58, 33, 33)
$colorRowMed      = [System.Drawing.Color]::FromArgb(58, 52, 26)
$colorRowNormal   = [System.Drawing.Color]::FromArgb(27, 29, 38)

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

# ============================================================
# EVENT CATEGORY DEFINITIONS
# LogName, EventIds, friendly label, severity (High/Medium/Info)
# ============================================================
$categoryDefs = @(
    @{ Key = "FailedLogon";   Label = "Failed logons (4625)";              LogName = "Security"; Ids = @(4625);        Severity = "Medium" }
    @{ Key = "SuccessLogon";  Label = "Successful logons (4624)";          LogName = "Security"; Ids = @(4624);        Severity = "Info" }
    @{ Key = "ExplicitCred";  Label = "Explicit credential logon (4648)";  LogName = "Security"; Ids = @(4648);        Severity = "Medium" }
    @{ Key = "AcctLocked";    Label = "Account lockouts (4740)";           LogName = "Security"; Ids = @(4740);        Severity = "Medium" }
    @{ Key = "UserCreated";   Label = "New user accounts (4720)";          LogName = "Security"; Ids = @(4720);        Severity = "High" }
    @{ Key = "GroupChange";   Label = "Security group membership change";  LogName = "Security"; Ids = @(4728,4732,4756); Severity = "High" }
    @{ Key = "PwReset";       Label = "Password reset attempts (4724)";    LogName = "Security"; Ids = @(4724);        Severity = "Medium" }
    @{ Key = "TaskCreated";   Label = "Scheduled task created (4698)";     LogName = "Security"; Ids = @(4698);        Severity = "Medium" }
    @{ Key = "ServiceInstall";Label = "New service installed (7045)";     LogName = "System";   Ids = @(7045);        Severity = "High" }
    @{ Key = "LogCleared";    Label = "Audit log cleared (1102)";          LogName = "Security"; Ids = @(1102);        Severity = "High" }
    @{ Key = "ProcessCreated";Label = "Process creation (4688)";           LogName = "Security"; Ids = @(4688);        Severity = "Info" }
    @{ Key = "PSScriptBlock"; Label = "PowerShell script blocks (4104)";   LogName = "Microsoft-Windows-PowerShell/Operational"; Ids = @(4104); Severity = "Info" }
)

# --- Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Event Log Quick Viewer"
$form.Size = New-Object System.Drawing.Size(1120, 740)
$form.StartPosition = "CenterScreen"
$form.BackColor = $colorBg
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$form.MinimumSize = New-Object System.Drawing.Size(950, 550)

# --- Header ---
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(1120, 64)
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.BackColor = $colorHeaderBg
$headerPanel.Anchor = "Top,Left,Right"
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Event Log Quick Viewer"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 15)
$titleLabel.ForeColor = $colorText
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(24, 12)
$headerPanel.Controls.Add($titleLabel)

$subLabel = New-Object System.Windows.Forms.Label
$subLabel.Text = "Pre-filtered to the event IDs analysts check first — pick categories, pick a time range, Load"
$subLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subLabel.ForeColor = $colorSubText
$subLabel.AutoSize = $true
$subLabel.Location = New-Object System.Drawing.Point(26, 38)
$headerPanel.Controls.Add($subLabel)

$chipTotal = New-Object System.Windows.Forms.Label
$chipTotal.AutoSize = $true
$chipTotal.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
$chipTotal.ForeColor = $colorText
$chipTotal.Location = New-Object System.Drawing.Point(940, 12)
$chipTotal.Anchor = "Top,Right"
$headerPanel.Controls.Add($chipTotal)

$chipHigh = New-Object System.Windows.Forms.Label
$chipHigh.AutoSize = $true
$chipHigh.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
$chipHigh.ForeColor = $colorRed
$chipHigh.Location = New-Object System.Drawing.Point(940, 34)
$chipHigh.Anchor = "Top,Right"
$headerPanel.Controls.Add($chipHigh)

# --- Category checkboxes (two columns) ---
$categoryPanel = New-Object System.Windows.Forms.Panel
$categoryPanel.Size = New-Object System.Drawing.Size(1080, 90)
$categoryPanel.Location = New-Object System.Drawing.Point(20, 72)
$categoryPanel.Anchor = "Top,Left,Right"
$form.Controls.Add($categoryPanel)

$script:categoryChecks = @{}
$colWidth = 350
for ($i = 0; $i -lt $categoryDefs.Count; $i++) {
    $def = $categoryDefs[$i]
    $col = [math]::Floor($i / 4)
    $row = $i % 4
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $def.Label
    $chk.ForeColor = $colorText
    $chk.Font = New-Object System.Drawing.Font("Segoe UI", 8.7)
    $chk.AutoSize = $true
    $chk.Location = New-Object System.Drawing.Point(($col * $colWidth), ($row * 22))
    $chk.Checked = ($def.Severity -ne "Info") -or ($def.Key -eq "PSScriptBlock")
    $categoryPanel.Controls.Add($chk)
    $script:categoryChecks[$def.Key] = $chk
}

# --- Time range + search bar ---
$controlBar = New-Object System.Windows.Forms.Panel
$controlBar.Size = New-Object System.Drawing.Size(1080, 34)
$controlBar.Location = New-Object System.Drawing.Point(20, 166)
$controlBar.Anchor = "Top,Left,Right"
$form.Controls.Add($controlBar)

$rangeLabel = New-Object System.Windows.Forms.Label
$rangeLabel.Text = "Time range:"
$rangeLabel.ForeColor = $colorSubText
$rangeLabel.AutoSize = $true
$rangeLabel.Location = New-Object System.Drawing.Point(0, 8)
$controlBar.Controls.Add($rangeLabel)

$rangeCombo = New-Object System.Windows.Forms.ComboBox
$rangeCombo.DropDownStyle = "DropDownList"
$rangeCombo.Size = New-Object System.Drawing.Size(140, 26)
$rangeCombo.Location = New-Object System.Drawing.Point(80, 4)
$rangeCombo.Items.AddRange(@("Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All (slow)"))
$rangeCombo.SelectedIndex = 1
$controlBar.Controls.Add($rangeCombo)

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Size = New-Object System.Drawing.Size(280, 26)
$searchBox.Location = New-Object System.Drawing.Point(240, 4)
$searchBox.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$searchBox.BackColor = $colorPanel
$searchBox.ForeColor = $colorText
$searchBox.BorderStyle = "FixedSingle"
$controlBar.Controls.Add($searchBox)

$searchHint = New-Object System.Windows.Forms.Label
$searchHint.Text = "🔍 Filter loaded results by user, message, source..."
$searchHint.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$searchHint.ForeColor = $colorGray
$searchHint.AutoSize = $true
$searchHint.Location = New-Object System.Drawing.Point(530, 8)
$controlBar.Controls.Add($searchHint)

$loadButton = New-StyledButton "Load Events" 850 2 110 28 $colorAccent $colorAccentHover
$loadButton.Anchor = "Top,Right"
$controlBar.Controls.Add($loadButton)

$exportButtonTop = New-StyledButton "Export CSV" 965 2 110 28 $colorDanger $colorDangerHover
$exportButtonTop.Anchor = "Top,Right"
$controlBar.Controls.Add($exportButtonTop)

# --- ListView ---
$listView = New-Object System.Windows.Forms.ListView
$listView.View = "Details"
$listView.FullRowSelect = $true
$listView.GridLines = $false
$listView.MultiSelect = $true
$listView.HideSelection = $false
$listView.Size = New-Object System.Drawing.Size(1080, 350)
$listView.Location = New-Object System.Drawing.Point(20, 208)
$listView.Anchor = "Top,Bottom,Left,Right"
$listView.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$listView.BackColor = $colorPanel
$listView.ForeColor = $colorText
$listView.BorderStyle = "FixedSingle"
$listView.Columns.Add("Time", 140) | Out-Null
$listView.Columns.Add("Event ID", 70) | Out-Null
$listView.Columns.Add("Category", 190) | Out-Null
$listView.Columns.Add("Log", 90) | Out-Null
$listView.Columns.Add("User / Subject", 150) | Out-Null
$listView.Columns.Add("Summary", 320) | Out-Null
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
$detailBox.Size = New-Object System.Drawing.Size(1080, 110)
$detailBox.Location = New-Object System.Drawing.Point(20, 566)
$detailBox.Anchor = "Bottom,Left,Right"
$detailBox.BackColor = $colorPanel
$detailBox.ForeColor = $colorSubText
$detailBox.Font = New-Object System.Drawing.Font("Consolas", 8.5)
$detailBox.BorderStyle = "FixedSingle"
$detailBox.Text = "Select an event above to see the full message."
$form.Controls.Add($detailBox)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Pick categories and a time range, then click Load Events."
$statusLabel.AutoSize = $true
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Italic)
$statusLabel.ForeColor = $colorSubText
$statusLabel.Location = New-Object System.Drawing.Point(20, 684)
$statusLabel.Anchor = "Bottom,Left"
$form.Controls.Add($statusLabel)

# ============================================================
# DATA LOADING
# ============================================================
$script:allEvents = @()

function Get-StartTime($rangeText) {
    switch ($rangeText) {
        "Last Hour"     { return (Get-Date).AddHours(-1) }
        "Last 24 Hours" { return (Get-Date).AddDays(-1) }
        "Last 7 Days"   { return (Get-Date).AddDays(-7) }
        "Last 30 Days"  { return (Get-Date).AddDays(-30) }
        default         { return $null }
    }
}

function Get-EventSummary($evt, $categoryLabel) {
    $user = ""
    $summary = ""
    try {
        switch ($evt.Id) {
            4625 { $user = $evt.Properties[5].Value; $summary = "Failed logon — reason code $($evt.Properties[7].Value), from workstation $($evt.Properties[13].Value)" }
            4624 { $user = $evt.Properties[5].Value; $summary = "Successful logon — type $($evt.Properties[8].Value)" }
            4648 { $user = $evt.Properties[1].Value; $summary = "Explicit creds used to run process as $($evt.Properties[5].Value)" }
            4740 { $user = $evt.Properties[0].Value; $summary = "Account locked out" }
            4720 { $user = $evt.Properties[0].Value; $summary = "New user account created" }
            4728 { $user = $evt.Properties[0].Value; $summary = "Member added to global security group" }
            4732 { $user = $evt.Properties[0].Value; $summary = "Member added to local security group" }
            4756 { $user = $evt.Properties[0].Value; $summary = "Member added to universal security group" }
            4724 { $user = $evt.Properties[0].Value; $summary = "Password reset was attempted" }
            4698 { $summary = "Scheduled task created: $($evt.Properties[1].Value)" }
            7045 { $summary = "Service installed: $($evt.Properties[0].Value) — image: $($evt.Properties[1].Value)" }
            1102 { $user = $evt.Properties[1].Value; $summary = "The audit log was cleared" }
            4688 { $user = $evt.Properties[1].Value; $summary = "New process: $($evt.Properties[5].Value)" }
            4104 { $summary = "Script block: $($evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length)) -replace '`r`n',' ')" }
            default { $summary = ($evt.Message -split "`r`n")[0] }
        }
    } catch {
        $summary = ($evt.Message -split "`r`n" | Select-Object -First 1)
    }
    if ([string]::IsNullOrWhiteSpace($summary)) { $summary = ($evt.Message -split "`r`n" | Select-Object -First 1) }
    return @{ User = $user; Summary = $summary }
}

function Load-Events {
    $selectedCats = $categoryDefs | Where-Object { $script:categoryChecks[$_.Key].Checked }
    if ($selectedCats.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select at least one category.", "Nothing to load")
        return
    }

    $startTime = Get-StartTime $rangeCombo.SelectedItem
    $statusLabel.Text = "Querying event logs..."
    [System.Windows.Forms.Application]::DoEvents()

    $results = @()
    # Group categories by log to minimize Get-WinEvent calls
    $byLog = $selectedCats | Group-Object { $_.LogName }
    foreach ($grp in $byLog) {
        $ids = $grp.Group | ForEach-Object { $_.Ids } | Select-Object -Unique
        $filter = @{ LogName = $grp.Name; Id = $ids }
        if ($startTime) { $filter["StartTime"] = $startTime }

        try {
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop
        } catch {
            continue  # log not found, no matching events, or access denied — skip quietly
        }

        foreach ($evt in $events) {
            $def = $grp.Group | Where-Object { $_.Ids -contains $evt.Id } | Select-Object -First 1
            $info = Get-EventSummary $evt $def.Label
            $results += [PSCustomObject]@{
                Time     = $evt.TimeCreated
                Id       = $evt.Id
                Category = $def.Label
                LogName  = $evt.LogName
                User     = $info.User
                Summary  = $info.Summary
                Severity = $def.Severity
                FullMessage = $evt.Message
            }
        }
    }

    $script:allEvents = $results | Sort-Object Time -Descending
    $chipTotal.Text = "$($results.Count) events loaded"
    $chipHigh.Text = "$(($results | Where-Object { $_.Severity -eq 'High' }).Count) high severity"
    Render-List
    $statusLabel.Text = "Loaded at $(Get-Date -Format 'HH:mm:ss') — $($results.Count) events across $($byLog.Count) log(s)"
}

function Render-List {
    $listView.Items.Clear()
    $filterText = $searchBox.Text.Trim().ToLower()

    foreach ($evt in $script:allEvents) {
        if ($filterText -and
            "$($evt.User) $($evt.Summary) $($evt.Category)".ToLower() -notmatch [regex]::Escape($filterText)) { continue }

        $item = New-Object System.Windows.Forms.ListViewItem([string]$evt.Time)
        $item.SubItems.Add([string]$evt.Id) | Out-Null
        $item.SubItems.Add([string]$evt.Category) | Out-Null
        $item.SubItems.Add([string]$evt.LogName) | Out-Null
        $item.SubItems.Add([string]$evt.User) | Out-Null
        $item.SubItems.Add([string]$evt.Summary) | Out-Null

        switch ($evt.Severity) {
            "High"   { $item.BackColor = $colorRowHigh; $item.ForeColor = $colorRed }
            "Medium" { $item.BackColor = $colorRowMed;  $item.ForeColor = $colorYellow }
            default  { $item.BackColor = $colorRowNormal; $item.ForeColor = $colorText }
        }
        $item.Tag = $evt
        $listView.Items.Add($item) | Out-Null
    }
}

$listView.Add_SelectedIndexChanged({
    if ($listView.SelectedItems.Count -eq 1) {
        $evt = $listView.SelectedItems[0].Tag
        $detailBox.Text = $evt.FullMessage
    }
})

$loadButton.Add_Click({ Load-Events })
$searchBox.Add_TextChanged({ $searchHint.Visible = ($searchBox.Text.Length -eq 0); Render-List })
$searchBox.Add_Enter({ $searchHint.Visible = $false })
$searchBox.Add_Leave({ $searchHint.Visible = ($searchBox.Text.Length -eq 0) })

$exportAction = {
    if ($script:allEvents.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nothing to export yet — load events first.", "No data")
        return
    }
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv"
    $saveDialog.FileName = "eventlog-export-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:allEvents | Select-Object Time, Id, Category, LogName, User, Summary, Severity |
            Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        $statusLabel.Text = "Exported to $($saveDialog.FileName)"
    }
}
$exportButtonTop.Add_Click($exportAction)

[System.Windows.Forms.Application]::Run($form)
