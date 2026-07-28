<#
.SYNOPSIS
    GameCheatForensicScanner - GUI forensic scanner for game cheat detection.
.DESCRIPTION
    Standalone Windows Forms application that performs comprehensive forensic
    analysis of a Windows system for game cheating artifacts. Features a
    progress-tracked GUI, expanded detection coverage, and categorized results.
.NOTES
    Run as Administrator for full artifact collection. No dependencies required
    beyond built-in .NET assemblies. Fully compatible with irm | iex execution.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$SessionHours = 4,

    [Parameter(Mandatory = $false)]
    [string[]]$GameProcessNames = @(
        'csgo', 'cs2', 'valorant', 'fortnite', 'apex',
        'r6', 'rainbow', 'siege', 'warzone', 'cod',
        'rocketleague', 'fivem', 'gta5', 'destiny2',
        'overwatch', 'league', 'lol', 'dota2', 'rust',
        'minecraft', 'terraria', 'roblox', 'battlefield',
        'escapefromtarkov', 'dayz', 'pubg', 'paladins',
        'smite', 'splitgate', 'thefinals', 'xdefiant'
    )
)

# ---------------------------------------------------------------
# Load required assemblies
# ---------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------
# Suspicious keyword database
# ---------------------------------------------------------------
$Script:SusKeywords = @(
    'cheat', 'hack', 'trainer', 'inject', 'bypass', 'loader',
    'hook', 'mapper', 'aimbot', 'wallhack', 'triggerbot', 'esp',
    'modmenu', 'dllinject', 'unknown', 'suspicious', 'crack',
    'keygen', 'mod', 'unlocker', 'stealth', 'memory', 'dumper',
    'extract', 'proxy', 'redirect', 'sniff', 'packet', 'console',
    'developer', 'godmode', 'noclip', 'flyhack', 'speedhack',
    'antivm', 'antidebug', 'vmp', 'themida', 'enigma', 'obsidian',
    'confuser', 'dnspy', 'de4dot', 'ildasm', 'dotpeek'
)

$Script:InjectKeywords = @(
    'inject', 'load', 'map', 'reflect', 'manual', 'allocate',
    'write', 'createremotethread', 'ntcreate', 'zwcreate',
    'openprocess', 'virtualallocex', 'writeprocessmemory',
    'readprocessmemory', 'setwindowshook', 'setwineventhook'
)

$Script:DnsMalPatterns = @(
    'cheat', 'hack', 'aimbot', 'wallhack', 'inject', 'crack',
    'keygen', 'mod', 'loader', 'bypass', 'unknown', '\.xyz',
    '\.top', '\.pw', '\.ru', '\.su', '\.cx', '\.click',
    '\.download', '\.date', '\.faith', '\.racing', '\.review',
    '\.stream', '\.trade', '\.win', '\.work'
)

$Script:HighRiskIPRanges = @(
    '^185\.', '^5\.',   '^94\.',  '^91\.', '^77\.',
    '^45\.',  '^31\.',  '^194\.', '^176\.','^46\.',
    '^2\.',   '^109\.', '^128\.', '^159\.','^212\.',
    '^213\.', '^217\.'
)

# Registry Run/MRU paths
$Script:RunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\*'
)

# Uninstall registry paths
$Script:UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# ---------------------------------------------------------------
# Session parameters
# ---------------------------------------------------------------
$Script:SessionStart = (Get-Date).AddHours(-$SessionHours)
$Script:SessionEnd   = (Get-Date)
$Script:Results      = [System.Collections.Generic.List[object]]::new()
$Script:ScanErrors   = [System.Collections.Generic.List[string]]::new()
$Script:CancelScan   = $false
$Script:ScanStart    = $null

# ---------------------------------------------------------------
# Form builder
# ---------------------------------------------------------------

function New-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text          = 'HackerAI - Game Cheat Forensic Scanner'
    $form.Size          = New-Object Drawing.Size(1100, 780)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize   = New-Object Drawing.Size(900, 600)
    # Safe icon assignment - works on all .NET versions
    try { $form.Icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command powershell).Source) } catch {}
    $form.BackColor     = [Drawing.Color]::FromArgb(30, 30, 30)
    $form.Font          = New-Object Drawing.Font('Consolas', 9.5)

    # ---- Header panel ----
    $header = New-Object Windows.Forms.Panel
    $header.Dock        = 'Top'
    $header.Height      = 80
    $header.BackColor   = [Drawing.Color]::FromArgb(20, 20, 20)
    $form.Controls.Add($header)

    $title = New-Object Windows.Forms.Label
    $title.Text    = '╔══ GAME CHEAT FORENSIC SCANNER v2.1 ══╗'
    $title.Font    = New-Object Drawing.Font('Consolas', 14, [Drawing.FontStyle]::Bold)
    $title.ForeColor = [Drawing.Color]::Cyan
    $title.Size    = New-Object Drawing.Size(700, 40)
    $title.Location = New-Object Drawing.Point(30, 8)
    $header.Controls.Add($title)

    $isAdmin = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $subtitle = New-Object Windows.Forms.Label
    $subtitle.Text = "Session: $($Script:SessionStart.ToString('yyyy-MM-dd HH:mm')) → $($Script:SessionEnd.ToString('HH:mm'))  |  Duration: $SessionHours hrs  |  $(if ($isAdmin) {'ADMIN'} else {'USER'})"
    $subtitle.Font = New-Object Drawing.Font('Consolas', 9)
    $subtitle.ForeColor = [Drawing.Color]::Gray
    $subtitle.Size = New-Object Drawing.Size(700, 20)
    $subtitle.Location = New-Object Drawing.Point(30, 48)
    $header.Controls.Add($subtitle)

    # ---- Status bar (bottom) ----
    $statusBar = New-Object Windows.Forms.StatusStrip
    $statusBar.BackColor = [Drawing.Color]::FromArgb(20, 20, 20)
    $statusBar.ForeColor = [Drawing.Color]::LightGray

    $statusLabel = New-Object Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text          = ' Ready'
    $statusLabel.ForeColor     = [Drawing.Color]::LightGreen
    $statusLabel.Font          = New-Object Drawing.Font('Consolas', 9)
    $statusLabel.AutoSize      = $true
    $statusBar.Items.Add($statusLabel) | Out-Null

    $statusCounter = New-Object Windows.Forms.ToolStripStatusLabel
    $statusCounter.Text        = '  |  0 artifacts found'
    $statusCounter.ForeColor   = [Drawing.Color]::Gray
    $statusCounter.Font        = New-Object Drawing.Font('Consolas', 9)
    $statusCounter.AutoSize    = $true
    $statusBar.Items.Add($statusCounter) | Out-Null

    $statusTime = New-Object Windows.Forms.ToolStripStatusLabel
    $statusTime.Text           = '  |  Elapsed: 0s'
    $statusTime.ForeColor      = [Drawing.Color]::Gray
    $statusTime.Font           = New-Object Drawing.Font('Consolas', 9)
    $statusTime.AutoSize       = $true
    $statusBar.Items.Add($statusTime) | Out-Null

    $form.Controls.Add($statusBar)

    # ---- Main split container ----
    $splitContainer = New-Object Windows.Forms.SplitContainer
    $splitContainer.Dock      = 'Fill'
    $splitContainer.Orientation = 'Horizontal'
    $splitContainer.SplitterDistance = 180
    $splitContainer.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)
    $form.Controls.Add($splitContainer)

    # ============================================================
    # TOP PANEL: Progress & controls
    # ============================================================
    $topPanel = $splitContainer.Panel1
    $topPanel.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)
    $topPanel.Padding   = New-Object Windows.Forms.Padding(10)

    # Progress bar
    $progressBar = New-Object Windows.Forms.ProgressBar
    $progressBar.Name      = 'progressBar'
    $progressBar.Location  = New-Object Drawing.Point(12, 12)
    $progressBar.Size      = New-Object Drawing.Size(920, 28)
    $progressBar.Minimum   = 0
    $progressBar.Maximum   = 100
    $progressBar.Style     = 'Continuous'
    $progressBar.ForeColor = [Drawing.Color]::Green
    $progressBar.BackColor = [Drawing.Color]::FromArgb(50, 50, 50)
    $topPanel.Controls.Add($progressBar)

    # Current stage label
    $stageLabel = New-Object Windows.Forms.Label
    $stageLabel.Name      = 'stageLabel'
    $stageLabel.Location  = New-Object Drawing.Point(12, 48)
    $stageLabel.Size      = New-Object Drawing.Size(920, 22)
    $stageLabel.Text      = 'Initializing...'
    $stageLabel.Font      = New-Object Drawing.Font('Consolas', 10, [Drawing.FontStyle]::Bold)
    $stageLabel.ForeColor = [Drawing.Color]::White
    $topPanel.Controls.Add($stageLabel)

    # Detail log (scrolling messages)
    $logBox = New-Object Windows.Forms.RichTextBox
    $logBox.Name        = 'logBox'
    $logBox.Location    = New-Object Drawing.Point(12, 76)
    $logBox.Size        = New-Object Drawing.Size(920, 70)
    $logBox.BackColor   = [Drawing.Color]::FromArgb(15, 15, 15)
    $logBox.ForeColor   = [Drawing.Color]::LightGray
    $logBox.Font        = New-Object Drawing.Font('Consolas', 8.5)
    $logBox.ReadOnly    = $true
    $logBox.BorderStyle = 'FixedSingle'
    $logBox.WordWrap    = $false
    $topPanel.Controls.Add($logBox)

    # Button row
    $btnStart = New-Object Windows.Forms.Button
    $btnStart.Name      = 'btnStart'
    $btnStart.Location  = New-Object Drawing.Point(12, 152)
    $btnStart.Size      = New-Object Drawing.Size(140, 30)
    $btnStart.Text      = '▶  Start Scan'
    $btnStart.BackColor = [Drawing.Color]::FromArgb(0, 120, 0)
    $btnStart.ForeColor = [Drawing.Color]::White
    $btnStart.FlatStyle = 'Flat'
    $btnStart.Font      = New-Object Drawing.Font('Consolas', 10, [Drawing.FontStyle]::Bold)
    $btnStart.UseVisualStyleBackColor = $false
    $topPanel.Controls.Add($btnStart)

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Name      = 'btnCancel'
    $btnCancel.Location  = New-Object Drawing.Point(162, 152)
    $btnCancel.Size      = New-Object Drawing.Size(100, 30)
    $btnCancel.Text      = '■ Cancel'
    $btnCancel.BackColor = [Drawing.Color]::FromArgb(120, 0, 0)
    $btnCancel.ForeColor = [Drawing.Color]::White
    $btnCancel.FlatStyle = 'Flat'
    $btnCancel.Font      = New-Object Drawing.Font('Consolas', 10)
    $btnCancel.Enabled   = $false
    $btnCancel.UseVisualStyleBackColor = $false
    $topPanel.Controls.Add($btnCancel)

    $btnExport = New-Object Windows.Forms.Button
    $btnExport.Name      = 'btnExport'
    $btnExport.Location  = New-Object Drawing.Point(272, 152)
    $btnExport.Size      = New-Object Drawing.Size(120, 30)
    $btnExport.Text      = '💾 Export Report'
    $btnExport.BackColor = [Drawing.Color]::FromArgb(50, 50, 120)
    $btnExport.ForeColor = [Drawing.Color]::White
    $btnExport.FlatStyle = 'Flat'
    $btnExport.Font      = New-Object Drawing.Font('Consolas', 10)
    $btnExport.Enabled   = $false
    $btnExport.UseVisualStyleBackColor = $false
    $topPanel.Controls.Add($btnExport)

    $btnWebReport = New-Object Windows.Forms.Button
    $btnWebReport.Name      = 'btnWebReport'
    $btnWebReport.Location  = New-Object Drawing.Point(940, 152)
    $btnWebReport.Size      = New-Object Drawing.Size(130, 30)
    $btnWebReport.Text      = '🌐 Web Report'
    $btnWebReport.BackColor = [Drawing.Color]::FromArgb(90, 40, 140)
    $btnWebReport.ForeColor = [Drawing.Color]::White
    $btnWebReport.FlatStyle = 'Flat'
    $btnWebReport.Font      = New-Object Drawing.Font('Consolas', 10)
    $btnWebReport.Enabled   = $false
    $btnWebReport.UseVisualStyleBackColor = $false
    $topPanel.Controls.Add($btnWebReport)

    $sessionNudLabel = New-Object Windows.Forms.Label
    $sessionNudLabel.Text     = 'Hours back:'
    $sessionNudLabel.ForeColor = [Drawing.Color]::Gray
    $sessionNudLabel.Font     = New-Object Drawing.Font('Consolas', 9)
    $sessionNudLabel.Location = New-Object Drawing.Point(420, 154)
    $sessionNudLabel.Size     = New-Object Drawing.Size(90, 20)
    $topPanel.Controls.Add($sessionNudLabel)

    $sessionNud = New-Object Windows.Forms.NumericUpDown
    $sessionNud.Name      = 'sessionNud'
    $sessionNud.Location  = New-Object Drawing.Point(510, 153)
    $sessionNud.Size      = New-Object Drawing.Size(60, 24)
    $sessionNud.Minimum   = 1
    $sessionNud.Maximum   = 72
    $sessionNud.Value     = $SessionHours
    $sessionNud.BackColor = [Drawing.Color]::FromArgb(50, 50, 50)
    $sessionNud.ForeColor = [Drawing.Color]::White
    $sessionNud.BorderStyle = 'FixedSingle'
    $topPanel.Controls.Add($sessionNud)

    $sessionApply = New-Object Windows.Forms.Button
    $sessionApply.Name      = 'sessionApply'
    $sessionApply.Location  = New-Object Drawing.Point(580, 152)
    $sessionApply.Size      = New-Object Drawing.Size(60, 26)
    $sessionApply.Text      = 'Set'
    $sessionApply.BackColor = [Drawing.Color]::FromArgb(60, 60, 60)
    $sessionApply.ForeColor = [Drawing.Color]::LightGray
    $sessionApply.FlatStyle = 'Flat'
    $sessionApply.Font      = New-Object Drawing.Font('Consolas', 9)
    $sessionApply.UseVisualStyleBackColor = $false
    $topPanel.Controls.Add($sessionApply)

    $adminLabel = New-Object Windows.Forms.Label
    $adminLabel.Name      = 'adminLabel'
    $adminLabel.Location  = New-Object Drawing.Point(670, 154)
    $adminLabel.Size      = New-Object Drawing.Size(260, 24)
    $adminLabel.Font      = New-Object Drawing.Font('Consolas', 9)
    if ($isAdmin) {
        $adminLabel.Text      = '✓ Running as Administrator'
        $adminLabel.ForeColor = [Drawing.Color]::LightGreen
    } else {
        $adminLabel.Text      = '⚠ Not Administrator (limited data)'
        $adminLabel.ForeColor = [Drawing.Color]::Orange
    }
    $topPanel.Controls.Add($adminLabel)

    # ============================================================
    # BOTTOM PANEL: Results TreeView + Details
    # ============================================================
    $bottomPanel = $splitContainer.Panel2
    $bottomPanel.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)
    $bottomPanel.Padding   = New-Object Windows.Forms.Padding(10)

    $resultSplit = New-Object Windows.Forms.SplitContainer
    $resultSplit.Dock             = 'Fill'
    $resultSplit.Orientation      = 'Vertical'
    $resultSplit.SplitterDistance = 380
    $resultSplit.BackColor        = [Drawing.Color]::FromArgb(30, 30, 30)
    $bottomPanel.Controls.Add($resultSplit)

    # ---- TreeView (left) ----
    $treePanel = $resultSplit.Panel1
    $treePanel.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)

    $treeHeader = New-Object Windows.Forms.Label
    $treeHeader.Text      = '  ARTIFACT CATEGORIES'
    $treeHeader.Font      = New-Object Drawing.Font('Consolas', 9, [Drawing.FontStyle]::Bold)
    $treeHeader.ForeColor = [Drawing.Color]::Cyan
    $treeHeader.Size      = New-Object Drawing.Size(360, 20)
    $treeHeader.Location  = New-Object Drawing.Point(0, 0)
    $treePanel.Controls.Add($treeHeader)

    $treeView = New-Object Windows.Forms.TreeView
    $treeView.Name       = 'treeView'
    $treeView.Location   = New-Object Drawing.Point(0, 22)
    $treeView.Size       = New-Object Drawing.Size(360, 320)
    $treeView.Anchor     = 'Top, Bottom, Left, Right'
    $treeView.BackColor  = [Drawing.Color]::FromArgb(20, 20, 20)
    $treeView.ForeColor  = [Drawing.Color]::LightGray
    $treeView.Font       = New-Object Drawing.Font('Consolas', 9)
    $treeView.BorderStyle = 'None'
    $treeView.HideSelection = $false
    $treeView.ImageList  = $null
    $treePanel.Controls.Add($treeView)

    # ---- Results details (right) ----
    $detailPanel = $resultSplit.Panel2
    $detailPanel.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)

    $detailHeader = New-Object Windows.Forms.Label
    $detailHeader.Text      = '  DETAILS'
    $detailHeader.Font      = New-Object Drawing.Font('Consolas', 9, [Drawing.FontStyle]::Bold)
    $detailHeader.ForeColor = [Drawing.Color]::Cyan
    $detailHeader.Size      = New-Object Drawing.Size(360, 20)
    $detailHeader.Location  = New-Object Drawing.Point(0, 0)
    $detailPanel.Controls.Add($detailHeader)

    $detailBox = New-Object Windows.Forms.RichTextBox
    $detailBox.Name       = 'detailBox'
    $detailBox.Location   = New-Object Drawing.Point(0, 22)
    $detailBox.Size       = New-Object Drawing.Size(680, 320)
    $detailBox.Anchor     = 'Top, Bottom, Left, Right'
    $detailBox.BackColor  = [Drawing.Color]::FromArgb(15, 15, 15)
    $detailBox.ForeColor  = [Drawing.Color]::LightGray
    $detailBox.Font       = New-Object Drawing.Font('Consolas', 8.5)
    $detailBox.ReadOnly   = $true
    $detailBox.BorderStyle = 'None'
    $detailBox.WordWrap   = $false
    $detailPanel.Controls.Add($detailBox)

    # ---- Return controls for event binding ----
    return @{
        Form         = $form
        ProgressBar  = $progressBar
        StageLabel   = $stageLabel
        LogBox       = $logBox
        TreeView     = $treeView
        DetailBox    = $detailBox
        StatusLabel  = $statusLabel
        StatusCounter= $statusCounter
        StatusTime   = $statusTime
        BtnStart     = $btnStart
        BtnCancel    = $btnCancel
        BtnExport    = $btnExport
        BtnWebReport = $btnWebReport
        SessionNud   = $sessionNud
        SessionApply = $sessionApply
        AdminLabel   = $adminLabel
    }
}

# ---------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------

function Update-UI {
    param(
        $Controls,
        [string]$StageText,
        [string]$LogMessage,
        [Nullable[int]]$ProgressPercent,
        [string]$StatusText,
        [string]$StatusColor = 'LightGreen'
    )

    if ($Script:CancelScan) { return }

    $Controls.Form.Invoke([Action]{
        if ($StageText)    { $Controls.StageLabel.Text    = $StageText }
        if ($LogMessage)   { 
            $Controls.LogBox.AppendText("$(Get-Date -Format 'HH:mm:ss') | $LogMessage`r`n")
            $Controls.LogBox.ScrollToCaret()
        }
        # FIX: only touch the progress bar when the caller actually passed a value,
        # otherwise it snapped back to 0 on every log-only Update-UI call.
        if ($null -ne $ProgressPercent -and $ProgressPercent -ge 0) { $Controls.ProgressBar.Value = [Math]::Min(100, $ProgressPercent) }
        if ($StatusText)   { 
            $Controls.StatusLabel.Text = " $StatusText"
            $Controls.StatusLabel.ForeColor = [Drawing.Color]::$StatusColor
        }
        # FIX: "Get-Date - $Script:ScanStart" parses Get-Date in command mode, where the
        # bare "-" is bound as an argument (e.g. to -Date) instead of being treated as
        # subtraction. Wrapping (Get-Date) forces it to evaluate as an expression first.
        $elapsed = if ($Script:ScanStart) { [math]::Round(((Get-Date) - $Script:ScanStart).TotalSeconds, 1) } else { 0 }
        $Controls.StatusTime.Text = "  |  Elapsed: ${elapsed}s"
        $Controls.StatusCounter.Text = "  |  $($Script:Results.Count) artifact categories"
    })
}

function Add-TreeNode {
    param(
        $TreeView,
        [string]$ParentName,
        [string]$NodeName,
        [string]$Category,
        [string]$Color = 'White'
    )

    $parentNode = $TreeView.Nodes | Where-Object { $_.Text -eq $ParentName }
    if (-not $parentNode) {
        $parentNode = New-Object Windows.Forms.TreeNode
        $parentNode.Text = $ParentName
        $parentNode.ForeColor = [Drawing.Color]::Cyan
        $TreeView.Nodes.Add($parentNode) | Out-Null
    }

    $node = New-Object Windows.Forms.TreeNode
    $node.Text = $NodeName
    $node.ForeColor = [Drawing.Color]::$Color
    # FIX: Tag must hold the plain Category (used for lookup in Show-Detail),
    # not the icon-prefixed display text, or details never resolve.
    $node.Tag = $Category
    $parentNode.Nodes.Add($node) | Out-Null
    $parentNode.Expand()
}

function Show-Detail {
    param($TreeView, $DetailBox, $Results)

    $node = $TreeView.SelectedNode
    if (-not $node -or -not $node.Tag) { return }

    $result = $Results | Where-Object { $_.Category -eq $node.Tag }
    if (-not $result) { return }

    $sb = [System.Text.StringBuilder]::new()
    $sb.AppendLine("══ $($result.Category) ══") | Out-Null
    $sb.AppendLine("Severity: $($result.Severity)") | Out-Null
    $sb.AppendLine("Found at: $($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))") | Out-Null
    $sb.AppendLine('') | Out-Null

    $data = $result.Data
    if ($data -is [array] -and $data.Count -gt 0) {
        $sb.AppendLine("Total items: $($data.Count)`n") | Out-Null
        # FIX: capture pipeline output to variable first to avoid irm|iex parser issue
        $formatted = $data | Format-Table -AutoSize -Wrap | Out-String -Width 200
        $sb.Append($formatted) | Out-Null
    } elseif ($data -is [string] -and $data.Length -gt 0) {
        $sb.AppendLine($data) | Out-Null
    } else {
        $sb.AppendLine('(No detail data available)') | Out-Null
    }

    $DetailBox.Text = $sb.ToString()
}

# ---------------------------------------------------------------
# Scan logic - expanded detection modules
# ---------------------------------------------------------------

function Start-ForensicScan {
    param($Controls)

    $Script:CancelScan  = $false
    $Script:Results.Clear()
    $Script:ScanErrors.Clear()
    # FIX: set ScanStart BEFORE any Update-UI call
    $Script:ScanStart   = Get-Date

    $Controls.TreeView.Nodes.Clear()
    $Controls.DetailBox.Clear()
    $Controls.LogBox.Clear()
    $Controls.BtnStart.Enabled   = $false
    $Controls.BtnCancel.Enabled  = $true
    $Controls.BtnExport.Enabled  = $false
    $Controls.SessionNud.Enabled = $false
    $Controls.SessionApply.Enabled = $false
    $Controls.ProgressBar.Value  = 0

    Update-UI -Controls $Controls -StageText 'Starting scan...' -LogMessage 'Forensic scanner initialized.' -ProgressPercent 0 -StatusText 'Scanning...' -StatusColor 'Yellow'

    try {
        $totalSteps = 16
        $currentStep = 0

        # Step 1
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Running / Suspicious Processes" -LogMessage 'Enumerating process list...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-ProcessArtifacts -Controls $Controls

        # Step 2
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Prefetch Artifact Analysis" -LogMessage 'Reading Prefetch directory...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-PrefetchArtifacts -Controls $Controls

        # Step 3
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Registry - Installed Software" -LogMessage 'Scanning uninstall keys...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-RegistryArtifacts -Controls $Controls

        # Step 4
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Registry - UserAssist & MRU" -LogMessage 'Checking UserAssist execution history...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-UserAssistArtifacts -Controls $Controls

        # Step 5
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Registry - Shim Database / AppCompat" -LogMessage 'Checking compatibility shims...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AppCompatArtifacts -Controls $Controls

        # Step 6
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Filesystem - Suspicious Files" -LogMessage 'Scanning directories for cheat files...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-FilesystemArtifacts -Controls $Controls

        # Step 7
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Filesystem - Recent Files / Jumplists" -LogMessage 'Checking recent file traces...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-RecentFileArtifacts -Controls $Controls

        # Step 8
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Event Log - Process Creation (4688)" -LogMessage 'Querying Security event log...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-Event4688 -Controls $Controls

        # Step 9
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Sysmon - Process (ID 1) & DLL (ID 7)" -LogMessage 'Checking Sysmon logs...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-SysmonArtifacts -Controls $Controls

        # Step 10
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Event Log - Anti-Cheat Errors" -LogMessage 'Scanning Application log for anti-cheat events...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AntiCheatErrors -Controls $Controls

        # Step 11
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Event Log - Service & Driver Loads" -LogMessage 'Checking service/driver installation events...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-ServiceDriverEvents -Controls $Controls

        # Step 12
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Anti-Cheat Data Directories" -LogMessage 'Browsing anti-cheat installation paths...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AntiCheatLogs -Controls $Controls

        # Step 13
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Network & DNS Artifacts" -LogMessage 'Checking DNS cache and TCP connections...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-NetworkArtifacts -Controls $Controls

        # Step 14
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Game Process Timeline" -LogMessage 'Building execution timelines...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-GameTimelines -Controls $Controls

        # Step 15
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Persistence - Tasks, Services, Autoruns" -LogMessage 'Checking persistence mechanisms...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-PersistenceArtifacts -Controls $Controls

        # Step 16
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] WMI & PowerShell History" -LogMessage 'Checking WMI and PS history persistence...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-WmiPowerShellArtifacts -Controls $Controls

        # Finalize
        Update-UI -Controls $Controls -StageText 'Scan Complete.' -LogMessage "Scan finished. $($Script:Results.Count) artifact categories collected." -ProgressPercent 100 -StatusText 'Scan Complete' -StatusColor 'LightGreen'

    } catch {
        Update-UI -Controls $Controls -LogMessage "ERROR: $($_.Exception.Message)" -StatusText 'Error during scan' -StatusColor 'Red'
        $Script:ScanErrors.Add($_.Exception.Message)
    }

    $Controls.BtnStart.Enabled    = $true
    $Controls.BtnCancel.Enabled   = $false
    $Controls.BtnExport.Enabled   = $true
    $Controls.BtnWebReport.Enabled = $true
    $Controls.SessionNud.Enabled  = $true
    $Controls.SessionApply.Enabled = $true

    # Populate tree
    foreach ($result in $Script:Results) {
        $color = switch ($result.Severity) {
            'Critical' { 'Red' }
            'High'     { 'Orange' }
            'Medium'   { 'Yellow' }
            'Low'      { 'White' }
            'Info'     { 'LightGray' }
            default    { 'White' }
        }
        $iconPrefix = switch ($result.Severity) {
            'Critical' { '⚠ ' }
            'High'     { '⚠ ' }
            'Medium'   { '• ' }
            'Low'      { '• ' }
            'Info'     { '  ' }
        }
        Add-TreeNode -TreeView $Controls.TreeView -ParentName $result.Severity -NodeName "${iconPrefix}$($result.Category)" -Category $result.Category -Color $color
    }
}

# ---------------------------------------------------------------
# Detection modules
# ---------------------------------------------------------------

function Get-ProcessArtifacts {
    param($Controls)

    # Suspicious named processes
    $suspicious = Get-Process | Where-Object {
        $_.ProcessName -match ($Script:SusKeywords -join '|')
    } | Select-Object ProcessName, Id,
        @{N='StartTime'; E={ try { $_.StartTime.ToLocalTime() } catch { $null } }},
        CPU, SessionId

    if ($suspicious) {
        Update-UI -Controls $Controls -LogMessage "  → Found $($suspicious.Count) suspicious processes."
        Add-Result -Category 'SuspiciousProcesses' -Severity High -Data $suspicious
    }

    # All processes with parent info
    $allProcs = Get-Process | ForEach-Object {
        $p = $_
        $parentId = try { (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction Stop).ParentProcessId } catch { $null }
        # FIX: protected/system processes (Idle, System, Secure System, Registry, etc.)
        # can throw or return null when reading StartTime/CPU, which crashed the whole
        # scan with "cannot call a method on a null-valued expression" on .ToLocalTime().
        $startTime = try { $p.StartTime.ToLocalTime() } catch { $null }
        $cpu       = try { [math]::Round($p.CPU, 2) } catch { $null }
        $ws        = try { [math]::Round($p.WorkingSet / 1MB, 1) } catch { $null }
        [PSCustomObject]@{
            ProcessName = $p.ProcessName
            PID         = $p.Id
            SessionId   = $p.SessionId
            StartTime   = $startTime
            ParentPID   = $parentId
            CPU         = $cpu
            WS          = $ws
        }
    }
    Add-Result -Category 'AllRunningProcesses' -Severity Info -Data $allProcs
}

function Get-PrefetchArtifacts {
    param($Controls)

    $pfDir = 'C:\Windows\Prefetch'
    if (-not (Test-Path $pfDir)) { return }

    # Suspicious prefetch hits
    $pfFiles = Get-ChildItem "$pfDir\*.pf" -ErrorAction SilentlyContinue
    $suspicious = $pfFiles | Where-Object {
        $_.Name -match ($Script:SusKeywords -join '|')
    } | Select-Object Name, Length, @{N='LastRun';E={$_.LastWriteTime}}

    if ($suspicious) {
        Update-UI -Controls $Controls -LogMessage "  → Found $($suspicious.Count) suspicious Prefetch entries."
        Add-Result -Category 'SuspiciousPrefetch' -Severity High -Data $suspicious
    }

    # All prefetch for timeline
    # FIX: "$_ -replace ..." operated on the FileInfo object itself (its ToString()
    # is the full path), producing a garbled path with a duplicated extension -
    # use $_.Name, and drop the pf hash suffix instead of appending another '.exe'.
    # Also sort on 'LastRun', the renamed property - 'LastWriteTime' no longer
    # exists on the projected objects, so the old sort silently did nothing.
    $allPf = $pfFiles | Select-Object Name, Length,
        @{N='LastRun';E={$_.LastWriteTime}},
        @{N='Executable';E={$_.Name -replace '-[0-9A-F]{8}\.pf$', ''}} |
        Sort-Object LastRun -Descending
    Add-Result -Category 'AllPrefetchEntries' -Severity Info -Data $allPf

    Update-UI -Controls $Controls -LogMessage "  → $($pfFiles.Count) total Prefetch entries."
}

function Get-RegistryArtifacts {
    param($Controls)

    $suspicious = @()
    foreach ($path in $Script:UninstallPaths) {
        $suspicious += Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match ($Script:SusKeywords -join '|') } |
            Select-Object @{N='Name';E={$_.DisplayName}}, DisplayVersion, Publisher, InstallDate
    }

    if ($suspicious) {
        Update-UI -Controls $Controls -LogMessage "  → Found $($suspicious.Count) suspicious installed programs."
        Add-Result -Category 'SuspiciousRegistry_Uninstall' -Severity High -Data $suspicious
    }
}

function Get-UserAssistArtifacts {
    param($Controls)

    $uaPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    $entries = @()
    Get-ChildItem $uaPath -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        $entries += Get-ItemProperty "${uaPath}\${guid}\Count" -ErrorAction SilentlyContinue
    }

    if ($entries) {
        Add-Result -Category 'UserAssistHistory' -Severity Info -Data $entries
        Update-UI -Controls $Controls -LogMessage "  → $($entries.Count) UserAssist entries captured."
    }
}

function Get-AppCompatArtifacts {
    param($Controls)

    $shimPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers',
        'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
    )

    $shimEntries = @()
    foreach ($path in $shimPaths) {
        $shimEntries += Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Select-Object * -ExcludeProperty PS*
    }

    if ($shimEntries) {
        Add-Result -Category 'AppCompatShims' -Severity Medium -Data $shimEntries
        Update-UI -Controls $Controls -LogMessage "  → $($shimEntries.Count) AppCompat/Layer entries found."
    }
}

function Get-FilesystemArtifacts {
    param($Controls)

    $targetDirs = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA",
                    "$env:PROGRAMDATA","$env:USERPROFILE\Downloads",
                    "$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents")
    # FIX: without the parens, "+ @(...)" attaches to the pipeline in a way that
    # does not reliably concatenate the two arrays as intended.
    $patterns = ($Script:SusKeywords | ForEach-Object { "*${_}*" }) + @('*.asi', '*.crack', '*.trainer')
    $found = @()

    foreach ($dir in $targetDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($pattern in $patterns) {
            $found += Get-ChildItem $dir -Filter $pattern -Depth 1 -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                Select-Object FullName, Length, CreationTime, LastWriteTime
        }
    }

    if ($found) {
        Update-UI -Controls $Controls -LogMessage "  → Found $($found.Count) suspicious files on disk."
        Add-Result -Category 'SuspiciousFiles_CheatPatterns' -Severity High -Data $found
    }

    # DLL scan in %TEMP% and %APPDATA%
    $dlls = Get-ChildItem "$env:TEMP" -Filter '*.dll' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 5120 } |
        Select-Object FullName, Length, LastWriteTime
    if ($dlls) {
        Add-Result -Category 'SuspiciousDLLs_InTemp' -Severity Medium -Data $dlls
        Update-UI -Controls $Controls -LogMessage "  → $($dlls.Count) suspicious DLLs in Temp/AppData."
    }

    # Check for memory dump files
    $dumps = Get-ChildItem "$env:TEMP" -Filter '*.dmp' -Depth 1 -ErrorAction SilentlyContinue
    if ($dumps) {
        Add-Result -Category 'MemoryDumps' -Severity Medium -Data $dumps
        Update-UI -Controls $Controls -LogMessage "  → $($dumps.Count) memory dump files found."
    }
}

function Get-RecentFileArtifacts {
    param($Controls)

    # Recent items
    $recentDocs = Get-ChildItem "$env:USERPROFILE\Recent" -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        Select-Object Name, Length, LastWriteTime

    if ($recentDocs) {
        Add-Result -Category 'RecentDocuments' -Severity Info -Data $recentDocs
        Update-UI -Controls $Controls -LogMessage "  → $($recentDocs.Count) recent document shortcuts."
    }

    # Jumplist (automatic destinations)
    $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    if (Test-Path $jumpListPath) {
        $jumpLists = Get-ChildItem $jumpListPath -ErrorAction SilentlyContinue
        if ($jumpLists) {
            Add-Result -Category 'Jumplists_AutomaticDestinations' -Severity Info -Data $jumpLists
            Update-UI -Controls $Controls -LogMessage "  → $($jumpLists.Count) jumplist files found."
        }
    }
}

function Get-Event4688 {
    param($Controls)

    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4688
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time           = $_.TimeCreated
                User           = $data['SubjectUserName']
                NewProc        = $data['NewProcessName']
                PID            = $data['NewProcessId']
                CmdLine        = $data['CommandLine']
                ParentProc     = $data['ParentProcessName']
                CreatorPID     = $data['CreatorProcessId']
            }
        }

        # Suspicious patterns
        $suspicious = $evts | Where-Object {
            $_.NewProc -match ($Script:SusKeywords -join '|') -or
            $_.CmdLine -match ($Script:SusKeywords -join '|') -or
            $_.CmdLine -match ($Script:InjectKeywords -join '|')
        }

        if ($suspicious) {
            Update-UI -Controls $Controls -LogMessage "  → $($suspicious.Count) suspicious process creations (4688)."
            Add-Result -Category 'Event4688_SuspiciousProcesses' -Severity High -Data $suspicious
        }

        Add-Result -Category 'Event4688_AllProcessCreations' -Severity Info -Data $evts
        Update-UI -Controls $Controls -LogMessage "  → $($evts.Count) total process creation events."

    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Cannot read Security log: $($_.Exception.Message)"
    }
}

function Get-SysmonArtifacts {
    param($Controls)

    $sysmonRunning = Get-Service -Name Sysmon -ErrorAction SilentlyContinue |
        Where-Object Status -EQ Running

    if (-not $sysmonRunning) {
        Update-UI -Controls $Controls -LogMessage '  → Sysmon not installed/running. Skipping.'
        return
    }

    # Event 1: Process creation
    try {
        $sysmon1 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            ID        = 1
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
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

        $sus1 = $sysmon1 | Where-Object {
            $_.Image -match ($Script:SusKeywords -join '|') -or
            $_.CmdLine -match ($Script:SusKeywords -join '|') -or
            $_.CmdLine -match ($Script:InjectKeywords -join '|')
        }

        if ($sus1) {
            Update-UI -Controls $Controls -LogMessage "  → $($sus1.Count) suspicious Sysmon process events."
            Add-Result -Category 'Sysmon1_SuspiciousProcess' -Severity High -Data $sus1
        }
        Add-Result -Category 'Sysmon1_AllProcesses' -Severity Info -Data $sysmon1
        Update-UI -Controls $Controls -LogMessage "  → $($sysmon1.Count) Sysmon process events."
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Sysmon Event 1 error: $($_.Exception.Message)"
    }

    # Event 7: DLL load
    try {
        $sysmon7 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            ID        = 7
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
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
                Desc     = $data['Description']
            }
        }

        $susDll = $sysmon7 | Where-Object {
            $_.Module -match ($Script:SusKeywords -join '|') -or
            ($_.Signed -eq 'false' -and $_.Module -notmatch 'microsoft|windows|system32|program files')
        }

        if ($susDll) {
            Update-UI -Controls $Controls -LogMessage "  → $($susDll.Count) suspicious DLL loads (unsigned/suspicious name)."
            Add-Result -Category 'Sysmon7_SuspiciousDLLLoad' -Severity Critical -Data $susDll
        }
        Add-Result -Category 'Sysmon7_AllDLLLoads' -Severity Info -Data $sysmon7
        Update-UI -Controls $Controls -LogMessage "  → $($sysmon7.Count) total DLL load events."
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Sysmon Event 7 error: $($_.Exception.Message)"
    }

    # Event 11: File creation (cheat file drops)
    try {
        $sysmon11 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            ID        = 11
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 3000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                Image   = $data['Image']
                Target  = $data['TargetFilename']
                PID     = $data['ProcessId']
            }
        }

        $susFileCreations = $sysmon11 | Where-Object {
            $_.Target -match ($Script:SusKeywords -join '|')
        }

        if ($susFileCreations) {
            Update-UI -Controls $Controls -LogMessage "  → $($susFileCreations.Count) suspicious file creations (Sysmon 11)."
            Add-Result -Category 'Sysmon11_SuspiciousFileDrop' -Severity High -Data $susFileCreations
        }
        Add-Result -Category 'Sysmon11_AllFileCreations' -Severity Info -Data $sysmon11
        Update-UI -Controls $Controls -LogMessage "  → $($sysmon11.Count) file creation events."
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Sysmon Event 11 error: $($_.Exception.Message)"
    }

    # Event 15: File stream creation (alternate data streams)
    try {
        $sysmon15 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            ID        = 15
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 1000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                Image   = $data['Image']
                Stream  = $data['Stream']
                Target  = $data['TargetFilename']
            }
        }

        if ($sysmon15) {
            Add-Result -Category 'Sysmon15_AlternateDataStreams' -Severity High -Data $sysmon15
            Update-UI -Controls $Controls -LogMessage "  → $($sysmon15.Count) ADS file creations (potential hidden cheat data)."
        }
    } catch {
        # Not all systems have this event type
    }

    # Event 22: DNS query (cheat C2)
    try {
        $sysmon22 = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            ID        = 22
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 1000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time       = $_.TimeCreated
                Process    = $data['Image']
                Query      = $data['QueryName']
                QueryStatus = $data['QueryStatus']
            }
        }

        $susDns = $sysmon22 | Where-Object {
            $_.Query -match ($Script:DnsMalPatterns -join '|')
        }

        if ($susDns) {
            Add-Result -Category 'Sysmon22_SuspiciousDNS' -Severity High -Data $susDns
            Update-UI -Controls $Controls -LogMessage "  → $($susDns.Count) suspicious DNS queries to cheat domains."
        }
        Add-Result -Category 'Sysmon22_AllDNSQueries' -Severity Info -Data $sysmon22
        Update-UI -Controls $Controls -LogMessage "  → $($sysmon22.Count) DNS query events."
    } catch {
        # Not all have Sysmon 22
    }
}

function Get-AntiCheatErrors {
    param($Controls)

    $acKeywords = @(
        'battleye', 'easyanticheat', 'easy anti-cheat', 'eac',
        'vanguard', 'faceit', 'punkbuster', 'vac', 'anti-cheat',
        'anticheat', 'anti cheat', 'valorant', 'fortnite',
        'cod', 'warzone', 'csgo', 'cs2', 'apex', 'r6', 'rainbow',
        'siege', 'destiny', 'overwatch', 'lol', 'league',
        'dota', 'rust', 'escapefromtarkov', 'fivem', 'minecraft'
    )

    try {
        $acEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 5000 -ErrorAction Stop | Where-Object {
            $msg = $_.Message.ToLower()
            ($acKeywords | Where-Object { $msg -match ( [regex]::Escape($_) ) }) -or
            $msg -match 'cheat|banned|kicked|blocked|violation|detected|suspicious|unauthorized|memory|injection|hook|permission denied|access denied'
        } | Select-Object TimeCreated, Id, LevelDisplayName,
            @{N='Source';E={$_.ProviderName}},
            @{N='Message';E={$_.Message.Substring(0, [math]::Min(250, $_.Message.Length))}}

        if ($acEvents) {
            Add-Result -Category 'AntiCheatErrors_ApplicationLog' -Severity Critical -Data $acEvents
            Update-UI -Controls $Controls -LogMessage "  → Found $($acEvents.Count) anti-cheat related events in Application log."
        } else {
            Update-UI -Controls $Controls -LogMessage '  → No anti-cheat error events found.'
        }
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Error reading Application log: $($_.Exception.Message)"
    }
}

function Get-ServiceDriverEvents {
    param($Controls)

    try {
        # Event 7034/7035/7045: Service install/start
        $svcEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            ID        = 7034, 7035, 7045
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $msg = $_.Message
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                ID      = $_.Id
                Message = $msg.Substring(0, [math]::Min(200, $msg.Length))
            }
        }

        $susSvc = $svcEvents | Where-Object {
            $_.Message -match ($Script:SusKeywords -join '|') -or
            $_.Message -match 'service installed|driver loaded|kernel'
        }

        if ($susSvc) {
            Add-Result -Category 'SystemEvent_ServiceDriverInstall' -Severity High -Data $susSvc
            Update-UI -Controls $Controls -LogMessage "  → $($susSvc.Count) service/driver events found."
        }

        # Event 6: Driver load (kernel-mode artifact)
        $driverEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            ID        = 6
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 1000 -ErrorAction Stop | ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                Message = $msg.Substring(0, [math]::Min(200, $msg.Length))
            }
        }

        $susDrv = $driverEvents | Where-Object {
            $_.Message -match ($Script:SusKeywords -join '|')
        }

        if ($susDrv) {
            Add-Result -Category 'SystemEvent_DriverLoad' -Severity Critical -Data $susDrv
            Update-UI -Controls $Controls -LogMessage "  → $($susDrv.Count) suspicious driver loads."
        }
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Error reading System log: $($_.Exception.Message)"
    }
}

function Get-AntiCheatLogs {
    param($Controls)

    $acPaths = @(
        "$env:PROGRAMDATA\EasyAntiCheat",
        "$env:PROGRAMDATA\BattlEye",
        "$env:PROGRAMDATA\FaceIt",
        "$env:APPDATA\Vanguard",
        "$env:LOCALAPPDATA\Riot Games",
        "$env:PROGRAMDATA\Electronic Arts\EA Desktop",
        "$env:PROGRAMDATA\Ubisoft",
        "$env:PROGRAMDATA\Rockstar Games",
        "$env:LOCALAPPDATA\FortniteGame",
        "$env:LOCALAPPDATA\Valorant"
    )

    foreach ($acPath in $acPaths) {
        if (Test-Path $acPath) {
            $files = Get-ChildItem $acPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer -and ($_.Extension -match '\.log|\.txt|\.dmp|\.json') } |
                Select-Object FullName, Length, LastWriteTime

            if ($files) {
                $dirName = [IO.Path]::GetFileName($acPath)
                Add-Result -Category "AntiCheatLog_${dirName}" -Severity Medium -Data $files
                Update-UI -Controls $Controls -LogMessage "  → $dirName : $($files.Count) files found."
            }
        }
    }
}

function Get-NetworkArtifacts {
    param($Controls)

    # DNS cache
    $dnsSuspicious = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Where-Object { $_.Entry -match ($Script:DnsMalPatterns -join '|') }

    if ($dnsSuspicious) {
        Add-Result -Category 'SuspiciousDNSCache' -Severity High -Data $dnsSuspicious
        Update-UI -Controls $Controls -LogMessage "  → $($dnsSuspicious.Count) suspicious DNS entries in cache."
    }

    # All DNS cache
    $allDns = Get-DnsClientCache -ErrorAction SilentlyContinue
    Add-Result -Category 'AllDNSCache' -Severity Info -Data $allDns
    Update-UI -Controls $Controls -LogMessage "  → $($allDns.Count) total DNS cache entries."

    # TCP connections
    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object State -EQ 'Established' |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
            @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
            @{N='PID';E={$_.OwningProcess}}

    # FIX: the old version emitted [$true, $false] on a match (or just [$false]
    # otherwise) - a non-empty array is always truthy in PowerShell regardless of
    # its contents, so every connection was being flagged as "high risk". Collapse
    # to a single boolean instead.
    $highRisk = $tcpConns | Where-Object {
        $conn = $_
        $isHighRisk = $false
        foreach ($pattern in $Script:HighRiskIPRanges) {
            if ($conn.RemoteAddress -match $pattern) { $isHighRisk = $true; break }
        }
        $isHighRisk
    }

    if ($highRisk) {
        Add-Result -Category 'HighRiskTCPConnections' -Severity High -Data $highRisk
        Update-UI -Controls $Controls -LogMessage "  → $($highRisk.Count) connections to high-risk IP ranges."
    }

    Add-Result -Category 'ActiveTCPConnections' -Severity Info -Data $tcpConns
    Update-UI -Controls $Controls -LogMessage "  → $($tcpConns.Count) established connections."

    # Windows Firewall log
    $fwLog = "$env:systemroot\System32\LogFiles\Firewall\pfirewall.log"
    if (Test-Path $fwLog) {
        $fwEntries = Get-Content $fwLog -Tail 200 -ErrorAction SilentlyContinue |
            Where-Object { $_ -notmatch '^\#' -and $_ -match $Script:SessionStart.ToString('yyyy-MM-dd') }
        if ($fwEntries) {
            # FIX: capture joined string to variable before passing to Add-Result
            $fwText = $fwEntries -join "`n"
            Add-Result -Category 'WindowsFirewallLog' -Severity Info -Data $fwText
            Update-UI -Controls $Controls -LogMessage "  → $($fwEntries.Count) firewall log entries for session period."
        }
    }

    # Browser history database locations
    $browsers = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )

    $browserHits = @()
    foreach ($browserPath in $browsers) {
        if (Test-Path $browserPath) {
            $browserHits += Get-ChildItem $browserPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'History|places\.sqlite' } |
                Select-Object FullName, Length, LastWriteTime
        }
    }

    if ($browserHits) {
        Add-Result -Category 'BrowserHistoryDatabases' -Severity Medium -Data $browserHits
        Update-UI -Controls $Controls -LogMessage "  → $($browserHits.Count) browser history databases available for analysis."
    }
}

function Get-GameTimelines {
    param($Controls)

    $gameTimelines = @()
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4688
            StartTime = $Script:SessionStart
            EndTime   = $Script:SessionEnd
        } -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time  = $_.TimeCreated
                Image = $data['NewProcessName']
                PID   = $data['NewProcessId']
                User  = $data['SubjectUserName']
            }
        }

        foreach ($game in $Script:GameProcessNames) {
            # FIX: "-match $game -replace ..." parsed as ($_.Image -match $game) -replace ...,
            # which turned the boolean into the string "True"/"False" (always truthy) and
            # matched every event to every game. Compute the pattern first, then match.
            # Also renamed from $matches to $gameMatches - $matches is PowerShell's automatic
            # variable and was being clobbered.
            $gamePattern = $game -replace '\.exe$', ''
            $gameMatches = $evts | Where-Object { $_.Image -match $gamePattern }
            if ($gameMatches) {
                $gameTimelines += [PSCustomObject]@{
                    Game    = $game
                    Launches = $gameMatches.Count
                    Events   = $gameMatches | Sort-Object Time
                }
            }
        }

        if ($gameTimelines) {
            foreach ($gt in $gameTimelines) {
                Add-Result -Category "GameTimeline_$($gt.Game)" -Severity Info -Data $gt.Events
            }
            Update-UI -Controls $Controls -LogMessage "  → $($gameTimelines.Count) games had process events in window."
        } else {
            Update-UI -Controls $Controls -LogMessage '  → No game process events found in session window.'
        }
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Error building game timelines: $($_.Exception.Message)"
    }
}

function Get-PersistenceArtifacts {
    param($Controls)

    # Scheduled tasks
    $schedTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object {
            $_.TaskName -match ($Script:SusKeywords -join '|') -or
            $_.TaskPath -match ($Script:SusKeywords -join '|')
        } | Select-Object TaskName, TaskPath, State, Author

    if ($schedTasks) {
        Add-Result -Category 'Persistence_ScheduledTasks' -Severity High -Data $schedTasks
        Update-UI -Controls $Controls -LogMessage "  → $($schedTasks.Count) suspicious scheduled tasks."
    }

    # All tasks for reference
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Select-Object TaskName, TaskPath, State, Author
    Add-Result -Category 'AllScheduledTasks' -Severity Info -Data $allTasks
    Update-UI -Controls $Controls -LogMessage "  → $($allTasks.Count) total scheduled tasks."

    # Services
    $svcs = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match ($Script:SusKeywords -join '|') } |
        Select-Object Name, DisplayName, Status, StartType

    if ($svcs) {
        Add-Result -Category 'Persistence_Services' -Severity High -Data $svcs
        Update-UI -Controls $Controls -LogMessage "  → $($svcs.Count) suspicious services."
    }

    # Registry Run keys
    $autoruns = @()
    foreach ($key in $Script:RunKeyPaths) {
        $autoruns += Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Select-Object * -ExcludeProperty PS*
    }
    if ($autoruns) {
        Add-Result -Category 'Persistence_RegistryRunKeys' -Severity Medium -Data $autoruns
        Update-UI -Controls $Controls -LogMessage "  → $($autoruns.Count) registry Run key entries."
    }

    # Startup folder
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $startupItems = @()
    foreach ($sp in $startupPaths) {
        $startupItems += Get-ChildItem $sp -ErrorAction SilentlyContinue
    }
    if ($startupItems) {
        Add-Result -Category 'Persistence_StartupFolder' -Severity Medium -Data $startupItems
        Update-UI -Controls $Controls -LogMessage "  → $($startupItems.Count) startup folder items."
    }
}

function Get-WmiPowerShellArtifacts {
    param($Controls)

    # WMI persistence (ActiveScriptEventConsumer / CommandLineEventConsumer)
    $wmiSuspects = @()
    try {
        $wmiBindings = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -ErrorAction SilentlyContinue
        $wmiConsumers = Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -ErrorAction SilentlyContinue

        if ($wmiBindings) {
            $susBindings = $wmiBindings | Where-Object {
                $_.Query -match ($Script:SusKeywords -join '|') -or
                $_.Name -match ($Script:SusKeywords -join '|')
            }
            if ($susBindings) {
                $wmiSuspects += $susBindings
            }
        }

        if ($wmiConsumers) {
            $susConsumers = $wmiConsumers | Where-Object {
                $_.Name -match ($Script:SusKeywords -join '|') -or
                $_.CommandLineTemplate -match ($Script:SusKeywords -join '|') -or
                $_.ScriptText -match ($Script:SusKeywords -join '|')
            }
            if ($susConsumers) {
                $wmiSuspects += $susConsumers
            }
        }

        if ($wmiSuspects) {
            Add-Result -Category 'WMI_Persistence' -Severity Critical -Data $wmiSuspects
            Update-UI -Controls $Controls -LogMessage "  → $($wmiSuspects.Count) WMI persistence bindings found."
        } else {
            Update-UI -Controls $Controls -LogMessage "  → No WMI persistence artifacts."
        }
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → WMI check error: $($_.Exception.Message)"
    }

    # PowerShell history
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistoryPath) {
        $psHistory = Get-Content $psHistoryPath -ErrorAction SilentlyContinue
        [System.Collections.Generic.List[string]]$susCommands = @()
        foreach ($line in $psHistory) {
            if ($line -match ($Script:SusKeywords -join '|') -or
                $line -match ($Script:InjectKeywords -join '|') -or
                $line -match 'download|webclient|invoke-expression|iex|start-process|bypass|hidden|windowstyle') {
                $susCommands.Add($line)
            }
        }
        if ($susCommands.Count -gt 0) {
            # FIX: capture joined string to variable before passing to Add-Result
            $susText = $susCommands -join "`n"
            Add-Result -Category 'PowerShellHistory_Suspicious' -Severity High -Data $susText
            Update-UI -Controls $Controls -LogMessage "  → $($susCommands.Count) suspicious PowerShell commands in history."
        }
        Add-Result -Category 'PowerShellHistory' -Severity Info -Data $psHistory
        Update-UI -Controls $Controls -LogMessage "  → $($psHistory.Count) total PowerShell history entries."
    } else {
        Update-UI -Controls $Controls -LogMessage "  → No PowerShell history file found."
    }
}

# ---------------------------------------------------------------
# Result management
# ---------------------------------------------------------------

function Add-Result {
    param($Category, $Severity, $Data)
    $Script:Results.Add([PSCustomObject]@{
        Category  = $Category
        Severity  = $Severity
        Data      = $Data
        Timestamp = (Get-Date)
    })
}

# ---------------------------------------------------------------
# Web (HTML) report
# ---------------------------------------------------------------

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function ConvertTo-DataHtml {
    # Renders a single result's Data payload as an HTML table (array of objects)
    # or a preformatted block (string), with every value escaped.
    param($Data)

    if ($Data -is [array] -or ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string])) {
        $items = @($Data)
        if ($items.Count -eq 0) { return '<p class="empty">No items.</p>' }

        # Collect a stable set of column names from the first few objects
        $propNames = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $items | Select-Object -First 25) {
            if ($item -is [PSObject]) {
                foreach ($p in $item.PSObject.Properties) {
                    if (-not $propNames.Contains($p.Name)) { $propNames.Add($p.Name) }
                }
            }
        }
        if ($propNames.Count -eq 0) {
            # Fallback: plain list of stringified items
            $rows = ($items | ForEach-Object { "<li>$(ConvertTo-HtmlSafe([string]$_))</li>" }) -join "`n"
            return "<ul class='plain-list'>$rows</ul>"
        }

        $sb = [System.Text.StringBuilder]::new()
        $sb.Append('<div class="table-wrap"><table><thead><tr>') | Out-Null
        foreach ($p in $propNames) { $sb.Append("<th>$(ConvertTo-HtmlSafe($p))</th>") | Out-Null }
        $sb.Append('</tr></thead><tbody>') | Out-Null

        $rowIndex = 0
        foreach ($item in $items) {
            $rowIndex++
            $delay = [Math]::Min($rowIndex * 0.02, 1.2)
            $sb.Append("<tr style='animation-delay: ${delay}s'>") | Out-Null
            foreach ($p in $propNames) {
                $val = ''
                if ($item -is [PSObject] -and $item.PSObject.Properties[$p]) {
                    $raw = $item.PSObject.Properties[$p].Value
                    $val = if ($null -eq $raw) { '' } else { [string]$raw }
                }
                $sb.Append("<td>$(ConvertTo-HtmlSafe($val))</td>") | Out-Null
            }
            $sb.Append('</tr>') | Out-Null
        }
        $sb.Append('</tbody></table></div>') | Out-Null
        return $sb.ToString()
    }
    elseif ($Data -is [string] -and $Data.Length -gt 0) {
        return "<pre class='raw-block'>$(ConvertTo-HtmlSafe($Data))</pre>"
    }
    else {
        return '<p class="empty">No detail data available.</p>'
    }
}

function New-HtmlReport {
    param($Results, [string]$OutFile)

    $isAdmin = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $ordered = $Results | Sort-Object { if ($severityRank.ContainsKey($_.Severity)) { $severityRank[$_.Severity] } else { 99 } }

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($r in $Results) {
        if ($counts.ContainsKey($r.Severity)) { $counts[$r.Severity]++ }
    }

    # ---- Build tab buttons + panels ----
    $tabButtons = [System.Text.StringBuilder]::new()
    $tabPanels  = [System.Text.StringBuilder]::new()
    $i = 0
    foreach ($result in $ordered) {
        $i++
        $tabId   = "tab-$i"
        $sevSlug = $result.Severity.ToString().ToLower()
        $safeCat = ConvertTo-HtmlSafe($result.Category)
        $itemCount = if ($result.Data -is [array]) { $result.Data.Count } elseif ($result.Data -is [string] -and $result.Data.Length -gt 0) { 1 } else { 0 }

        $tabButtons.Append(@"
<button class="tab-btn sev-$sevSlug" data-target="$tabId" style="animation-delay: $($i * 0.04)s">
  <span class="dot"></span>
  <span class="tab-label">$safeCat</span>
  <span class="tab-count">$itemCount</span>
</button>
"@) | Out-Null

        $dataHtml = ConvertTo-DataHtml -Data $result.Data

        $tabPanels.Append(@"
<section class="panel" id="$tabId">
  <div class="panel-head">
    <h2>$safeCat</h2>
    <span class="badge sev-$sevSlug">$($result.Severity)</span>
    <span class="timestamp">Detected $($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</span>
  </div>
  <div class="panel-body">
    $dataHtml
  </div>
</section>
"@) | Out-Null
    }

    if ($ordered.Count -eq 0) {
        $tabButtons.Append('<span class="empty">No categories to display.</span>') | Out-Null
        $tabPanels.Append('<section class="panel active"><p class="empty">No forensic artifacts were recorded in this scan.</p></section>') | Out-Null
    }

    $generatedAt = Get-Date
    $osCaption = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { 'Unknown' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Scan Report — $env:COMPUTERNAME</title>
<style>
  :root {
    --bg: #0c0c10;
    --panel: #15151b;
    --panel-alt: #1c1c24;
    --border: #2a2a34;
    --text: #e6e6ee;
    --muted: #8a8a9a;
    --accent: #7c5cff;
    --accent-2: #22d3ee;
    --crit: #ff4d6d;
    --high: #ff9f43;
    --med: #ffd166;
    --low: #9aa5ff;
    --info: #4fd1c5;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: 'Consolas', 'Cascadia Code', 'Segoe UI', monospace;
    background: radial-gradient(circle at 20% -10%, #1a1030 0%, var(--bg) 55%);
    color: var(--text);
    min-height: 100vh;
  }
  header {
    padding: 28px 36px 20px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(120deg, rgba(124,92,255,0.12), rgba(34,211,238,0.06));
    animation: fadeDown 0.5s ease both;
  }
  header h1 {
    margin: 0 0 6px;
    font-size: 22px;
    letter-spacing: 0.5px;
    background: linear-gradient(90deg, var(--accent), var(--accent-2));
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }
  header .meta { color: var(--muted); font-size: 12.5px; line-height: 1.6; }
  .summary {
    display: flex; gap: 12px; margin-top: 16px; flex-wrap: wrap;
  }
  .summary .chip {
    padding: 8px 14px; border-radius: 999px; font-size: 12px;
    border: 1px solid var(--border); background: var(--panel-alt);
    display: flex; align-items: center; gap: 8px;
    opacity: 0; animation: popIn 0.4s ease forwards;
  }
  .summary .chip b { font-size: 14px; }
  .summary .chip:nth-child(1){animation-delay:.05s}
  .summary .chip:nth-child(2){animation-delay:.1s}
  .summary .chip:nth-child(3){animation-delay:.15s}
  .summary .chip:nth-child(4){animation-delay:.2s}
  .summary .chip:nth-child(5){animation-delay:.25s}
  .swatch { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  main {
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 0;
    min-height: calc(100vh - 130px);
  }
  nav.tabs {
    border-right: 1px solid var(--border);
    padding: 18px 12px;
    display: flex; flex-direction: column; gap: 6px;
    overflow-y: auto;
    max-height: calc(100vh - 130px);
  }
  .tab-btn {
    all: unset;
    cursor: pointer;
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px; border-radius: 10px;
    color: var(--text); font-size: 12.5px;
    border: 1px solid transparent;
    opacity: 0; animation: slideIn 0.35s ease forwards;
    transition: background 0.2s ease, transform 0.15s ease, border-color 0.2s ease;
  }
  .tab-btn:hover { background: var(--panel-alt); transform: translateX(2px); }
  .tab-btn.active { background: var(--panel-alt); border-color: var(--border); box-shadow: inset 3px 0 0 var(--accent); }
  .tab-label { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tab-count {
    font-size: 10.5px; color: var(--muted); background: rgba(255,255,255,0.06);
    padding: 2px 7px; border-radius: 999px;
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .sev-critical .dot, .badge.sev-critical { background: var(--crit); }
  .sev-high .dot, .badge.sev-high { background: var(--high); }
  .sev-medium .dot, .badge.sev-medium { background: var(--med); color:#20140a; }
  .sev-low .dot, .badge.sev-low { background: var(--low); color:#101018; }
  .sev-info .dot, .badge.sev-info { background: var(--info); color:#08201d; }
  .badge { padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: bold; color: #1a0510; }

  section.panel {
    display: none;
    padding: 28px 34px;
    animation: fadeUp 0.4s ease both;
  }
  section.panel.active { display: block; }
  .panel-head {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding-bottom: 14px; margin-bottom: 18px; border-bottom: 1px solid var(--border);
  }
  .panel-head h2 { margin: 0; font-size: 17px; }
  .timestamp { color: var(--muted); font-size: 12px; margin-left: auto; }
  .table-wrap { overflow: auto; border: 1px solid var(--border); border-radius: 10px; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; }
  thead th {
    text-align: left; padding: 10px 12px; background: var(--panel-alt);
    color: var(--accent-2); position: sticky; top: 0; border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  tbody td { padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); white-space: nowrap; max-width: 420px; overflow: hidden; text-overflow: ellipsis; }
  tbody tr { opacity: 0; animation: rowIn 0.3s ease forwards; }
  tbody tr:hover { background: rgba(124,92,255,0.08); }
  .raw-block {
    background: var(--panel-alt); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-height: 60vh; overflow: auto;
  }
  .plain-list { font-size: 12px; line-height: 1.8; padding-left: 20px; }
  .empty { color: var(--muted); font-style: italic; }
  footer { padding: 16px 34px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); }

  @keyframes fadeDown { from { opacity: 0; transform: translateY(-8px);} to { opacity: 1; transform: translateY(0);} }
  @keyframes fadeUp { from { opacity: 0; transform: translateY(10px);} to { opacity: 1; transform: translateY(0);} }
  @keyframes slideIn { from { opacity: 0; transform: translateX(-8px);} to { opacity: 1; transform: translateX(0);} }
  @keyframes popIn { from { opacity: 0; transform: scale(0.9);} to { opacity: 1; transform: scale(1);} }
  @keyframes rowIn { from { opacity: 0; transform: translateY(4px);} to { opacity: 1; transform: translateY(0);} }

  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 999px; }
  ::-webkit-scrollbar-track { background: transparent; }
</style>
</head>
<body>
  <header>
    <h1>⟡ Game Cheat Forensic Report</h1>
    <div class="meta">
      Host: $(ConvertTo-HtmlSafe($env:COMPUTERNAME))  &nbsp;|&nbsp;
      OS: $(ConvertTo-HtmlSafe($osCaption))  &nbsp;|&nbsp;
      Generated: $($generatedAt.ToString('yyyy-MM-dd HH:mm:ss'))  &nbsp;|&nbsp;
      Privilege: $(if ($isAdmin) { 'Administrator' } else { 'Standard User' })
    </div>
    <div class="summary">
      <span class="chip"><span class="swatch" style="background:var(--crit)"></span>Critical <b>$($counts.Critical)</b></span>
      <span class="chip"><span class="swatch" style="background:var(--high)"></span>High <b>$($counts.High)</b></span>
      <span class="chip"><span class="swatch" style="background:var(--med)"></span>Medium <b>$($counts.Medium)</b></span>
      <span class="chip"><span class="swatch" style="background:var(--low)"></span>Low <b>$($counts.Low)</b></span>
      <span class="chip"><span class="swatch" style="background:var(--info)"></span>Info <b>$($counts.Info)</b></span>
    </div>
  </header>
  <main>
    <nav class="tabs">
      $($tabButtons.ToString())
    </nav>
    <div class="panels">
      $($tabPanels.ToString())
    </div>
  </main>
  <footer>Generated by HackerAI Forensics Scanner v2.1 — this file is self-contained and safe to share; no external scripts are loaded.</footer>

<script>
  const buttons = document.querySelectorAll('.tab-btn');
  const panels  = document.querySelectorAll('.panel');
  function activate(idx) {
    buttons.forEach((b, i) => b.classList.toggle('active', i === idx));
    panels.forEach((p, i) => p.classList.toggle('active', i === idx));
  }
  buttons.forEach((btn, idx) => btn.addEventListener('click', () => activate(idx)));
  if (buttons.length) activate(0);
</script>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($OutFile, $html, [System.Text.Encoding]::UTF8)
}

# ---------------------------------------------------------------
# Export
# ---------------------------------------------------------------

function Export-Report {
    param($Controls)

    $saveDlg = New-Object Windows.Forms.SaveFileDialog
    $saveDlg.Title    = 'Save Forensic Report'
    $saveDlg.Filter   = 'HTML Report (*.html)|*.html|Text Report (*.txt)|*.txt|CSV Summary (*.csv)|*.csv|All Files (*.*)|*.*'
    $saveDlg.FileName = "CheatForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $saveDlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')

    if ($saveDlg.ShowDialog() -ne 'OK') { return }

    if ([System.IO.Path]::GetExtension($saveDlg.FileName) -eq '.html') {
        try {
            New-HtmlReport -Results $Script:Results -OutFile $saveDlg.FileName
            Update-UI -Controls $Controls -LogMessage "HTML report exported to: $($saveDlg.FileName)" -StatusText 'Report Exported' -StatusColor 'LightGreen'
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Export Error', 'OK', 'Error')
        }
        return
    }

    try {
        $sb = [System.Text.StringBuilder]::new()
        $sb.AppendLine("=" * 80) | Out-Null
        $sb.AppendLine("  GAME CHEAT FORENSIC REPORT") | Out-Null
        $sb.AppendLine("  Generated: $(Get-Date)") | Out-Null
        $sb.AppendLine("  Analyst Tool: HackerAI Forensics Scanner v2.1") | Out-Null
        $sb.AppendLine("=" * 80) | Out-Null
        $sb.AppendLine("") | Out-Null
        $sb.AppendLine("Session Window : $($Script:SessionStart)  →  $($Script:SessionEnd)") | Out-Null
        $sb.AppendLine("Target System  : $env:COMPUTERNAME") | Out-Null
        $sb.AppendLine("OS             : $((Get-CimInstance Win32_OperatingSystem).Caption)") | Out-Null
        $sb.AppendLine("Artifacts Found: $($Script:Results.Count) categories") | Out-Null
        $sb.AppendLine("Errors         : $($Script:ScanErrors.Count)") | Out-Null
        $sb.AppendLine("") | Out-Null

        foreach ($result in $Script:Results) {
            $sb.AppendLine("[$($result.Severity)] $($result.Category)") | Out-Null
            $sb.AppendLine("-" * 60) | Out-Null
            if ($result.Data -is [array] -and $result.Data.Count -gt 0) {
                # FIX: capture pipeline to variable first
                $rawOutput = $result.Data | Format-Table -AutoSize -Wrap | Out-String -Width 120
                $indented = ($rawOutput -split "`r`n" | ForEach-Object { "  $_" }) -join "`r`n"
                $sb.AppendLine($indented) | Out-Null
            } elseif ($result.Data -is [string]) {
                $sb.AppendLine("  $($result.Data)") | Out-Null
            } else {
                $sb.AppendLine("  (data available in XML export)") | Out-Null
            }
            $sb.AppendLine("") | Out-Null
        }

        if ($Script:ScanErrors.Count -gt 0) {
            $sb.AppendLine("`n" + "=" * 60) | Out-Null
            $sb.AppendLine("  ERRORS ENCOUNTERED") | Out-Null
            $sb.AppendLine("=" * 60) | Out-Null
            foreach ($err in $Script:ScanErrors) {
                $sb.AppendLine("  ⚠ $err") | Out-Null
            }
        }

        $sb.AppendLine("`n" + "=" * 60) | Out-Null
        $sb.AppendLine("  END OF REPORT") | Out-Null
        $sb.AppendLine("=" * 60) | Out-Null

        [System.IO.File]::WriteAllText($saveDlg.FileName, $sb.ToString(), [System.Text.Encoding]::UTF8)
        Update-UI -Controls $Controls -LogMessage "Report exported to: $($saveDlg.FileName)" -StatusText 'Report Exported' -StatusColor 'LightGreen'
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Export Error', 'OK', 'Error')
    }
}

# ---------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------

$controls = New-MainForm

# ---- Wire up events ----
$controls.BtnStart.Add_Click({
    $h = $controls.SessionNud.Value
    $Script:SessionStart = (Get-Date).AddHours(-$h)
    $Script:SessionEnd   = (Get-Date)
    $controls.StageLabel.Text = "Session set: last $h hours"
    Start-ForensicScan -Controls $controls
})

$controls.BtnCancel.Add_Click({
    $Script:CancelScan = $true
    $controls.BtnCancel.Enabled = $false
    Update-UI -Controls $controls -StatusText 'Cancelling...' -StatusColor 'Yellow'
})

$controls.BtnExport.Add_Click({
    Export-Report -Controls $controls
})

$controls.BtnWebReport.Add_Click({
    try {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "CheatForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        New-HtmlReport -Results $Script:Results -OutFile $tempFile
        Start-Process $tempFile
        Update-UI -Controls $controls -LogMessage "Web report opened in browser: $tempFile" -StatusText 'Web Report Opened' -StatusColor 'LightGreen'
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Could not open web report: $($_.Exception.Message)", 'Web Report Error', 'OK', 'Error')
    }
})

$controls.SessionApply.Add_Click({
    $h = $controls.SessionNud.Value
    $Script:SessionStart = (Get-Date).AddHours(-$h)
    $Script:SessionEnd   = (Get-Date)
    $controls.StageLabel.Text = "Session: last $h hours  ($($Script:SessionStart.ToString('HH:mm')) → $($Script:SessionEnd.ToString('HH:mm')))"
    Update-UI -Controls $controls -LogMessage "Session window updated: last $h hours"
})

$controls.TreeView.Add_AfterSelect({
    Show-Detail -TreeView $controls.TreeView -DetailBox $controls.DetailBox -Results $Script:Results
})

# ---- Application start ----
$controls.Form.Add_Shown({
    $controls.StageLabel.Text = "Ready. Session: last $SessionHours hours  ($($Script:SessionStart.ToString('HH:mm')) → $($Script:SessionEnd.ToString('HH:mm')))"
})

[System.Windows.Forms.Application]::Run($controls.Form)
