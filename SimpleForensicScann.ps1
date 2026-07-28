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

$Script:RunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\*'
)

$Script:UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# ---------------------------------------------------------------
# Bypass keyword databases
# ---------------------------------------------------------------
$Script:AmsiBypassKeywords = @(
    'amsi', 'amsibuffer', 'amsiscanbuffer', 'amsiopen', 'amsiclose',
    'amsiuninitialize', 'patchamsi', 'disableamsi', 'bypassamsi',
    'amsipro', 'amsiutils', 'amsiprovider', 'featurebits'
)

$Script:InjectionTechniques = @(
    'createremotethread', 'ntcreatethread', 'rtlcreateuserthread',
    'queueuserapc', 'setwindowshookex', 'setwineventhook',
    'ntmapviewofsection', 'writeprocessmemory', 'virtualallocex',
    'ntallocatevirtualmemory', 'processhollowing', 'herpaderp',
    'reflectiveloader', 'manualmap', 'dllsideload', 'dllproxy',
    'atombombing', 'comhijack', 'dotnetinject', 'clrinjection'
)

$Script:KernelBypassKeywords = @(
    'kdmapper', 'kdu', 'gdrv', 'easysys', 'mapper', 'driver',
    'vuln.sys', 'capcom.sys', 'iqvw64.sys', 'dbk64.sys',
    'eacbypass', 'battleyebypass', 'vanguardbypass'
)

$Script:EvasionKeywords = @(
    'antivm', 'anti-debug', 'antidebug', 'antidbg', 'vbox',
    'vmware', 'vpc', 'qemu', 'sandbox', 'isdebuggerpresent',
    'checkremotedebugger', 'ntqueryinformationprocess',
    'hideprocess', 'obfuscation', 'confuserex', 'smartassembly',
    'themida', 'vmp', 'enigma', 'obsidium', 'execrypt',
    'runpehidden', 'hidewindow', 'windowstylehidden'
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
    try { $form.Icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command powershell).Source) } catch {}
    $form.BackColor     = [Drawing.Color]::FromArgb(30, 30, 30)
    $form.Font          = New-Object Drawing.Font('Consolas', 9.5)

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

    $statusBar = New-Object Windows.Forms.StatusStrip
    $statusBar.BackColor = [Drawing.Color]::FromArgb(20, 20, 20)
    $statusBar.ForeColor = [Drawing.Color]::LightGray

    $statusLabel = New-Object Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text      = ' Ready'
    $statusLabel.ForeColor = [Drawing.Color]::LightGreen
    $statusLabel.Font      = New-Object Drawing.Font('Consolas', 9)
    $statusLabel.AutoSize  = $true
    $statusBar.Items.Add($statusLabel) | Out-Null

    $statusCounter = New-Object Windows.Forms.ToolStripStatusLabel
    $statusCounter.Text      = '  |  0 artifacts found'
    $statusCounter.ForeColor = [Drawing.Color]::Gray
    $statusCounter.Font      = New-Object Drawing.Font('Consolas', 9)
    $statusCounter.AutoSize  = $true
    $statusBar.Items.Add($statusCounter) | Out-Null

    $statusTime = New-Object Windows.Forms.ToolStripStatusLabel
    $statusTime.Text      = '  |  Elapsed: 0s'
    $statusTime.ForeColor = [Drawing.Color]::Gray
    $statusTime.Font      = New-Object Drawing.Font('Consolas', 9)
    $statusTime.AutoSize  = $true
    $statusBar.Items.Add($statusTime) | Out-Null

    $form.Controls.Add($statusBar)

    $splitContainer = New-Object Windows.Forms.SplitContainer
    $splitContainer.Dock      = 'Fill'
    $splitContainer.Orientation = 'Horizontal'
    $splitContainer.SplitterDistance = 180
    $splitContainer.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)
    $form.Controls.Add($splitContainer)

    $topPanel = $splitContainer.Panel1
    $topPanel.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)
    $topPanel.Padding   = New-Object Windows.Forms.Padding(10)

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

    $stageLabel = New-Object Windows.Forms.Label
    $stageLabel.Name      = 'stageLabel'
    $stageLabel.Location  = New-Object Drawing.Point(12, 48)
    $stageLabel.Size      = New-Object Drawing.Size(920, 22)
    $stageLabel.Text      = 'Initializing...'
    $stageLabel.Font      = New-Object Drawing.Font('Consolas', 10, [Drawing.FontStyle]::Bold)
    $stageLabel.ForeColor = [Drawing.Color]::White
    $topPanel.Controls.Add($stageLabel)

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

    $bottomPanel = $splitContainer.Panel2
    $bottomPanel.BackColor = [Drawing.Color]::FromArgb(30, 30, 30)
    $bottomPanel.Padding   = New-Object Windows.Forms.Padding(10)

    $resultSplit = New-Object Windows.Forms.SplitContainer
    $resultSplit.Dock             = 'Fill'
    $resultSplit.Orientation      = 'Vertical'
    $resultSplit.SplitterDistance = 380
    $resultSplit.BackColor        = [Drawing.Color]::FromArgb(30, 30, 30)
    $bottomPanel.Controls.Add($resultSplit)

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
    param($Controls, [string]$StageText, [string]$LogMessage, [Nullable[int]]$ProgressPercent, [string]$StatusText, [string]$StatusColor = 'LightGreen')
    if ($Script:CancelScan) { return }
    $Controls.Form.Invoke([Action]{
        if ($StageText)    { $Controls.StageLabel.Text = $StageText }
        if ($LogMessage)   {
            $Controls.LogBox.AppendText("$(Get-Date -Format 'HH:mm:ss') | $LogMessage`r`n")
            $Controls.LogBox.ScrollToCaret()
        }
        if ($null -ne $ProgressPercent -and $ProgressPercent -ge 0) { $Controls.ProgressBar.Value = [Math]::Min(100, $ProgressPercent) }
        if ($StatusText)   {
            $Controls.StatusLabel.Text = " $StatusText"
            $Controls.StatusLabel.ForeColor = [Drawing.Color]::$StatusColor
        }
        $elapsed = if ($Script:ScanStart) { [math]::Round(((Get-Date) - $Script:ScanStart).TotalSeconds, 1) } else { 0 }
        $Controls.StatusTime.Text = "  |  Elapsed: ${elapsed}s"
        $Controls.StatusCounter.Text = "  |  $($Script:Results.Count) artifact categories"
    })
}

function Add-TreeNode {
    param($TreeView, [string]$ParentName, [string]$NodeName, [string]$Category, [string]$Color = 'White')
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
# Scan orchestrator
# ---------------------------------------------------------------
function Start-ForensicScan {
    param($Controls)

    $Script:CancelScan  = $false
    $Script:Results.Clear()
    $Script:ScanErrors.Clear()
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
        $totalSteps = 22
        $currentStep = 0

        # Step 1 - Suspicious Processes only (removed AllRunningProcesses dump)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Suspicious Processes" -LogMessage 'Enumerating process list...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-SuspiciousProcesses -Controls $Controls

        # Step 2 - Suspicious Prefetch only (removed AllPrefetchEntries dump)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Suspicious Prefetch Artifacts" -LogMessage 'Reading Prefetch directory...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-SuspiciousPrefetch -Controls $Controls

        # Step 3 - Registry installed software
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Registry - Installed Software" -LogMessage 'Scanning uninstall keys...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-RegistryArtifacts -Controls $Controls

        # Step 4 - UserAssist
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Registry - UserAssist & MRU" -LogMessage 'Checking UserAssist execution history...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-UserAssistArtifacts -Controls $Controls

        # Step 5 - AppCompat shims
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Registry - Shim Database" -LogMessage 'Checking compatibility shims...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AppCompatArtifacts -Controls $Controls

        # Step 6 - Suspicious files
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Filesystem - Suspicious Files" -LogMessage 'Scanning directories for cheat files...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-FilesystemArtifacts -Controls $Controls

        # Step 7 - Recent files
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Filesystem - Recent Files" -LogMessage 'Checking recent file traces...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-RecentFileArtifacts -Controls $Controls

        # Step 8 - Event 4688
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Event Log - Process Creation" -LogMessage 'Querying Security event log...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-Event4688 -Controls $Controls

        # Step 9 - Sysmon
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Sysmon Analysis" -LogMessage 'Checking Sysmon logs...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-SysmonArtifacts -Controls $Controls

        # Step 10 - Anti-cheat errors
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Anti-Cheat Errors" -LogMessage 'Scanning Application log for anti-cheat events...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AntiCheatErrors -Controls $Controls

        # Step 11 - Service & driver loads
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Service & Driver Loads" -LogMessage 'Checking service/driver installation events...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-ServiceDriverEvents -Controls $Controls

        # Step 12 - Anti-cheat directories
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Anti-Cheat Data Directories" -LogMessage 'Browsing anti-cheat installation paths...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AntiCheatLogs -Controls $Controls

        # Step 13 - Network & DNS
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Network & DNS Artifacts" -LogMessage 'Checking DNS cache and TCP connections...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-NetworkArtifacts -Controls $Controls

        # Step 14 - Game timelines
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Game Process Timeline" -LogMessage 'Building execution timelines...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-GameTimelines -Controls $Controls

        # Step 15 - Persistence
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Persistence Analysis" -LogMessage 'Checking persistence mechanisms...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-PersistenceArtifacts -Controls $Controls

        # Step 16 - WMI & PS History (suspicious only)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] WMI & Suspicious PS History" -LogMessage 'Checking WMI and PS history...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-WmiPowerShellArtifacts -Controls $Controls

        # NEW MODULE: File Activity Timeline (Step 17)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] File Activity Timeline" -LogMessage 'Building file activity timeline...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-FileActivityTimeline -Controls $Controls

        # NEW MODULE: Deleted File Artifacts (Step 18)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Deleted File Artifacts" -LogMessage 'Scanning for deleted file evidence...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-DeletedFileArtifacts -Controls $Controls

        # NEW MODULE: Execution History (Step 19)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Execution History" -LogMessage 'Analyzing execution records...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-ExecutionHistory -Controls $Controls

        # NEW MODULE: Recycle Bin Analysis (Step 20)
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Recycle Bin Analysis" -LogMessage 'Checking recycle bin status...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-RecycleBinAnalysis -Controls $Controls

        # Step 21 - AMSI/ETW bypass
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] AMSI & ETW Bypass Detection" -LogMessage 'Scanning for AMSI/ETW tampering...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-AMSIBypassArtifacts -Controls $Controls

        # Step 22 - Process injection & hollowing
        $currentStep++
        Update-UI -Controls $Controls -StageText "[$currentStep/$totalSteps] Process Injection & Hollowing" -LogMessage 'Analyzing for injection patterns...' -ProgressPercent ([int](($currentStep/$totalSteps)*100))
        Get-InjectionArtifacts -Controls $Controls

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

    foreach ($result in $Script:Results) {
        $color = switch ($result.Severity) {
            'Critical' { 'Red' }; 'High' { 'Orange' }; 'Medium' { 'Yellow' }
            'Low' { 'White' }; 'Info' { 'LightGray' }; default { 'White' }
        }
        $iconPrefix = switch ($result.Severity) {
            'Critical' { '⚠ ' }; 'High' { '⚠ ' }; 'Medium' { '• ' }
            'Low' { '• ' }; 'Info' { '  ' }
        }
        Add-TreeNode -TreeView $Controls.TreeView -ParentName $result.Severity -NodeName "${iconPrefix}$($result.Category)" -Category $result.Category -Color $color
    }
}

# ---------------------------------------------------------------
# Existing detection modules (cleaned - no full dumps)
# ---------------------------------------------------------------

function Get-SuspiciousProcesses {
    param($Controls)
    $suspicious = Get-Process | Where-Object {
        $_.ProcessName -match ($Script:SusKeywords -join '|')
    } | Select-Object ProcessName, Id,
        @{N='StartTime'; E={ try { $_.StartTime.ToLocalTime() } catch { $null } }},
        CPU, SessionId
    if ($suspicious) {
        Update-UI -Controls $Controls -LogMessage "  → Found $($suspicious.Count) suspicious processes."
        Add-Result -Category 'SuspiciousProcesses' -Severity High -Data $suspicious
    }
}

function Get-SuspiciousPrefetch {
    param($Controls)
    $pfDir = 'C:\Windows\Prefetch'
    if (-not (Test-Path $pfDir)) { return }
    $pfFiles = Get-ChildItem "$pfDir\*.pf" -ErrorAction SilentlyContinue
    $suspicious = $pfFiles | Where-Object {
        $_.Name -match ($Script:SusKeywords -join '|')
    } | Select-Object Name, Length, @{N='LastRun';E={$_.LastWriteTime}}
    if ($suspicious) {
        Update-UI -Controls $Controls -LogMessage "  → Found $($suspicious.Count) suspicious Prefetch entries."
        Add-Result -Category 'SuspiciousPrefetch' -Severity High -Data $suspicious
    }
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
        $shimEntries += Get-ItemProperty $path -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS*
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
    $dlls = Get-ChildItem "$env:TEMP" -Filter '*.dll' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 5120 } |
        Select-Object FullName, Length, LastWriteTime
    if ($dlls) {
        Add-Result -Category 'SuspiciousDLLs_InTemp' -Severity Medium -Data $dlls
        Update-UI -Controls $Controls -LogMessage "  → $($dlls.Count) suspicious DLLs in Temp/AppData."
    }
}

function Get-RecentFileArtifacts {
    param($Controls)
    $recentDocs = Get-ChildItem "$env:USERPROFILE\Recent" -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        Select-Object Name, Length, LastWriteTime
    if ($recentDocs) {
        Add-Result -Category 'RecentDocuments' -Severity Info -Data $recentDocs
        Update-UI -Controls $Controls -LogMessage "  → $($recentDocs.Count) recent document shortcuts."
    }
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
            LogName='Security'; ID=4688; StartTime=$Script:SessionStart; EndTime=$Script:SessionEnd
        } -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml(); $data = @{}
            $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
            [PSCustomObject]@{
                Time=$_.TimeCreated; User=$data['SubjectUserName']; NewProc=$data['NewProcessName']
                PID=$data['NewProcessId']; CmdLine=$data['CommandLine']; ParentProc=$data['ParentProcessName']
                CreatorPID=$data['CreatorProcessId']
            }
        }
        $suspicious = $evts | Where-Object {
            $_.NewProc -match ($Script:SusKeywords -join '|') -or
            $_.CmdLine -match ($Script:SusKeywords -join '|') -or
            $_.CmdLine -match ($Script:InjectKeywords -join '|')
        }
        if ($suspicious) {
            Update-UI -Controls $Controls -LogMessage "  → $($suspicious.Count) suspicious process creations (4688)."
            Add-Result -Category 'Event4688_SuspiciousProcesses' -Severity High -Data $suspicious
        }
        # Also keep process creations for timeline purposes (not full dump, but keep Count info)
        if ($evts) {
            Add-Result -Category 'Event4688_ProcessCreationSummary' -Severity Info -Data @{ Total=$evts.Count; Suspicious=$suspicious.Count }
            Update-UI -Controls $Controls -LogMessage "  → $($evts.Count) total process creations, $($suspicious.Count) flagged."
        }
    } catch {
        Update-UI -Controls $Controls -LogMessage "  → Cannot read Security log: $($_.Exception.Message)"
    }
}

function Get-SysmonArtifacts {
    param($Controls)
    $sysmonRunning = Get-Service -Name Sysmon -ErrorAction SilentlyContinue | Where-Object Status -EQ Running
    if (-not $sysmonRunning) { Update-UI -Controls $Controls -LogMessage '  → Sysmon not installed/running. Skipping.'; return }

    try {
        $sysmon1 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Image=$data['Image'];CmdLine=$data['CommandLine'];PID=$data['ProcessId'];Parent=$data['ParentImage'];Hashes=$data['Hashes'];User=$data['User']}
        }
        $sus1=$sysmon1|Where-Object{$_.Image -match ($Script:SusKeywords -join '|') -or $_.CmdLine -match ($Script:SusKeywords -join '|') -or $_.CmdLine -match ($Script:InjectKeywords -join '|')}
        if($sus1){Add-Result -Category 'Sysmon1_SuspiciousProcess' -Severity High -Data $sus1; Update-UI -Controls $Controls -LogMessage "  → $($sus1.Count) suspicious Sysmon process events."}
    } catch{}

    try {
        $sysmon7 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=7;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Process=$data['Image'];PID=$data['ProcessId'];Module=$data['ModuleLoaded'];Signed=$data['Signed']}
        }
        $susDll=$sysmon7|Where-Object{$_.Module -match ($Script:SusKeywords -join '|') -or ($_.Signed -eq 'false' -and $_.Module -notmatch 'microsoft|windows|system32|program files')}
        if($susDll){Add-Result -Category 'Sysmon7_SuspiciousDLLLoad' -Severity Critical -Data $susDll; Update-UI -Controls $Controls -LogMessage "  → $($susDll.Count) suspicious DLL loads."}
    } catch{}

    try {
        $sysmon11 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=11;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 3000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Image=$data['Image'];Target=$data['TargetFilename'];PID=$data['ProcessId']}
        }
        $susFileCreations=$sysmon11|Where-Object{$_.Target -match ($Script:SusKeywords -join '|')}
        if($susFileCreations){Add-Result -Category 'Sysmon11_SuspiciousFileDrop' -Severity High -Data $susFileCreations; Update-UI -Controls $Controls -LogMessage "  → $($susFileCreations.Count) suspicious file creations."}
    } catch{}

    try {
        $sysmon15 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=15;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 1000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Image=$data['Image'];Stream=$data['Stream'];Target=$data['TargetFilename']}
        }
        if($sysmon15){Add-Result -Category 'Sysmon15_AlternateDataStreams' -Severity High -Data $sysmon15; Update-UI -Controls $Controls -LogMessage "  → $($sysmon15.Count) ADS file creations."}
    } catch{}

    try {
        $sysmon22 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=22;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 1000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Process=$data['Image'];Query=$data['QueryName'];QueryStatus=$data['QueryStatus']}
        }
        $susDns=$sysmon22|Where-Object{$_.Query -match ($Script:DnsMalPatterns -join '|')}
        if($susDns){Add-Result -Category 'Sysmon22_SuspiciousDNS' -Severity High -Data $susDns; Update-UI -Controls $Controls -LogMessage "  → $($susDns.Count) suspicious DNS queries."}
    } catch{}
}

function Get-AntiCheatErrors {
    param($Controls)
    $acKeywords = @('battleye','easyanticheat','easy anti-cheat','eac','vanguard','faceit','punkbuster','vac','anti-cheat','anticheat','anti cheat')
    try {
        $acEvents = Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 5000 -ErrorAction Stop | Where-Object {
            $msg=$_.Message.ToLower()
            ($acKeywords|Where-Object{$msg -match [regex]::Escape($_)}) -or $msg -match 'cheat|banned|kicked|blocked|violation|detected|suspicious|unauthorized|memory|injection|hook|permission denied|access denied'
        } | Select-Object TimeCreated,Id,LevelDisplayName,@{N='Source';E={$_.ProviderName}},@{N='Message';E={$_.Message.Substring(0,[math]::Min(250,$_.Message.Length))}}
        if($acEvents){Add-Result -Category 'AntiCheatErrors_ApplicationLog' -Severity Critical -Data $acEvents; Update-UI -Controls $Controls -LogMessage "  → Found $($acEvents.Count) anti-cheat related events."}
    } catch {}
}

function Get-ServiceDriverEvents {
    param($Controls)
    try {
        $svcEvents = Get-WinEvent -FilterHashtable @{LogName='System';ID=7034,7035,7045;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{Time=$_.TimeCreated;ID=$_.Id;Message=$_.Message.Substring(0,[math]::Min(200,$_.Message.Length))}
        }
        $susSvc=$svcEvents|Where-Object{$_.Message -match ($Script:SusKeywords -join '|') -or $_.Message -match 'service installed|driver loaded|kernel'}
        if($susSvc){Add-Result -Category 'SystemEvent_ServiceDriverInstall' -Severity High -Data $susSvc; Update-UI -Controls $Controls -LogMessage "  → $($susSvc.Count) service/driver events."}
        $driverEvents = Get-WinEvent -FilterHashtable @{LogName='System';ID=6;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 1000 -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{Time=$_.TimeCreated;Message=$_.Message.Substring(0,[math]::Min(200,$_.Message.Length))}
        }
        $susDrv=$driverEvents|Where-Object{$_.Message -match ($Script:SusKeywords -join '|')}
        if($susDrv){Add-Result -Category 'SystemEvent_DriverLoad' -Severity Critical -Data $susDrv; Update-UI -Controls $Controls -LogMessage "  → $($susDrv.Count) suspicious driver loads."}
    } catch {}
}

function Get-AntiCheatLogs {
    param($Controls)
    $acPaths = @("$env:PROGRAMDATA\EasyAntiCheat","$env:PROGRAMDATA\BattlEye","$env:PROGRAMDATA\FaceIt","$env:APPDATA\Vanguard","$env:LOCALAPPDATA\Riot Games","$env:PROGRAMDATA\Electronic Arts\EA Desktop","$env:PROGRAMDATA\Ubisoft","$env:PROGRAMDATA\Rockstar Games")
    foreach ($acPath in $acPaths) {
        if (Test-Path $acPath) {
            $files = Get-ChildItem $acPath -Recurse -ErrorAction SilentlyContinue | Where-Object {-not $_.PSIsContainer -and ($_.Extension -match '\.log|\.txt|\.dmp|\.json')} | Select-Object FullName, Length, LastWriteTime
            if ($files) { $dirName=[IO.Path]::GetFileName($acPath); Add-Result -Category "AntiCheatLog_${dirName}" -Severity Medium -Data $files; Update-UI -Controls $Controls -LogMessage "  → $dirName : $($files.Count) files found." }
        }
    }
}

function Get-NetworkArtifacts {
    param($Controls)
    $dnsSuspicious = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match ($Script:DnsMalPatterns -join '|') }
    if($dnsSuspicious){Add-Result -Category 'SuspiciousDNSCache' -Severity High -Data $dnsSuspicious; Update-UI -Controls $Controls -LogMessage "  → $($dnsSuspicious.Count) suspicious DNS entries."}
    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object State -EQ 'Established' | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},@{N='PID';E={$_.OwningProcess}}
    $highRisk=$tcpConns|Where-Object{$c=$_;$r=$false;foreach($p in $Script:HighRiskIPRanges){if($c.RemoteAddress -match $p){$r=$true;break}};$r}
    if($highRisk){Add-Result -Category 'HighRiskTCPConnections' -Severity High -Data $highRisk; Update-UI -Controls $Controls -LogMessage "  → $($highRisk.Count) connections to high-risk IP ranges."}
}

function Get-GameTimelines {
    param($Controls)
    $gameTimelines=@()
    try {
        $evts=Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Image=$data['NewProcessName'];PID=$data['NewProcessId'];User=$data['SubjectUserName']}
        }
        foreach($game in $Script:GameProcessNames){$p=$game -replace '\.exe$','';$m=$evts|Where-Object{$_.Image -match $p};if($m){$gameTimelines+=[PSCustomObject]@{Game=$game;Launches=$m.Count;Events=$m|Sort-Object Time}}}
        if($gameTimelines){foreach($gt in $gameTimelines){Add-Result -Category "GameTimeline_$($gt.Game)" -Severity Info -Data $gt.Events}; Update-UI -Controls $Controls -LogMessage "  → $($gameTimelines.Count) games had process events."}
    } catch{}
}

function Get-PersistenceArtifacts {
    param($Controls)
    $schedTasks=Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{$_.TaskName -match ($Script:SusKeywords -join '|') -or $_.TaskPath -match ($Script:SusKeywords -join '|')}|Select-Object TaskName,TaskPath,State,Author
    if($schedTasks){Add-Result -Category 'Persistence_ScheduledTasks' -Severity High -Data $schedTasks; Update-UI -Controls $Controls -LogMessage "  → $($schedTasks.Count) suspicious scheduled tasks."}
    $svcs=Get-Service -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -match ($Script:SusKeywords -join '|')}|Select-Object Name,DisplayName,Status,StartType
    if($svcs){Add-Result -Category 'Persistence_Services' -Severity High -Data $svcs; Update-UI -Controls $Controls -LogMessage "  → $($svcs.Count) suspicious services."}
    $autoruns=@();foreach($key in $Script:RunKeyPaths){$autoruns+=Get-ItemProperty $key -ErrorAction SilentlyContinue|Select-Object * -ExcludeProperty PS*}
    if($autoruns){Add-Result -Category 'Persistence_RegistryRunKeys' -Severity Medium -Data $autoruns; Update-UI -Controls $Controls -LogMessage "  → $($autoruns.Count) registry Run key entries."}
    $startupItems=@();foreach($sp in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup")){$startupItems+=Get-ChildItem $sp -ErrorAction SilentlyContinue}
    if($startupItems){Add-Result -Category 'Persistence_StartupFolder' -Severity Medium -Data $startupItems; Update-UI -Controls $Controls -LogMessage "  → $($startupItems.Count) startup folder items."}
}

function Get-WmiPowerShellArtifacts {
    param($Controls)
    $wmiSuspects=@()
    try {
        $wmiBindings=Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -ErrorAction SilentlyContinue
        $wmiConsumers=Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -ErrorAction SilentlyContinue
        if($wmiBindings){$susBindings=$wmiBindings|Where-Object{$_.Query -match ($Script:SusKeywords -join '|') -or $_.Name -match ($Script:SusKeywords -join '|')};if($susBindings){$wmiSuspects+=$susBindings}}
        if($wmiConsumers){$susConsumers=$wmiConsumers|Where-Object{$_.Name -match ($Script:SusKeywords -join '|') -or $_.CommandLineTemplate -match ($Script:SusKeywords -join '|') -or $_.ScriptText -match ($Script:SusKeywords -join '|')};if($susConsumers){$wmiSuspects+=$susConsumers}}
        if($wmiSuspects){Add-Result -Category 'WMI_Persistence' -Severity Critical -Data $wmiSuspects; Update-UI -Controls $Controls -LogMessage "  → $($wmiSuspects.Count) WMI persistence bindings found."}
    } catch{}
    # Suspicious PS history only (no full dump)
    $psHistoryPath="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if(Test-Path $psHistoryPath){
        $psHistory=Get-Content $psHistoryPath -ErrorAction SilentlyContinue
        [System.Collections.Generic.List[string]]$susCommands=@()
        foreach($line in $psHistory){
            if($line -match ($Script:SusKeywords -join '|') -or $line -match ($Script:InjectKeywords -join '|') -or $line -match 'download|webclient|invoke-expression|iex|start-process|bypass|hidden|windowstyle'){
                $susCommands.Add($line)
            }
        }
        if($susCommands.Count -gt 0){
            $susText=$susCommands -join "`n"
            Add-Result -Category 'PowerShellHistory_Suspicious' -Severity High -Data $susText
            Update-UI -Controls $Controls -LogMessage "  → $($susCommands.Count) suspicious PowerShell commands in history."
        }
    }
}
# ================================================================
# NEW MODULE 1: File Activity Timeline
# ================================================================
function Get-FileActivityTimeline {
    param($Controls)

    $activity = [System.Collections.Generic.List[object]]::new()
    $activityPatterns = @($Script:SusKeywords) + @('exe','dll','ps1','bat','vbs','js','jar','sys','scr','zip','rar','7z')

    # 1a: Sysmon Event 11 file creations (if available)
    try {
        $sysmon11 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=11;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Action='File Created';Source=$data['Image'];Target=$data['TargetFilename'];PID=$data['ProcessId']}
        }
        if($sysmon11){$sysmon11|ForEach-Object{$activity.Add($_)}}
        Update-UI -Controls $Controls -LogMessage "  → Collected $($sysmon11.Count) file creation events from Sysmon."
    } catch {}

    # 1b: Sysmon Event 2 (file creation time changed - often a rename/move operation)
    try {
        $sysmon2 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=2;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Action='File Timestamp Modified';Source=$data['Image'];Target=$data['TargetFilename'];PID=$data['ProcessId']}
        }
        if($sysmon2){$sysmon2|ForEach-Object{$activity.Add($_)}}
    } catch {}

    # 1c: Sysmon Event 23 (file delete - via file delete logging if enabled)
    try {
        $sysmon23 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=23;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$data=@{};$xml.Event.EventData.Data|ForEach-Object{$data[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Action='File Deleted';Source=$data['Image'];Target=$data['TargetFilename'];PID=$data['ProcessId']}
        }
        if($sysmon23){$sysmon23|ForEach-Object{$activity.Add($_)}}
    } catch {}

    # 1d: Downloads from browser history databases (simplified - skip SQLite)
    # Since SQLite is not natively available, skip this part or use a simpler approach
    Update-UI -Controls $Controls -LogMessage "  → Browser download history check skipped (requires SQLite)."

    # 1e: Windows Event 4656 (file handle open - read/execute detection)
    try {
        $fileEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4656;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 5000 -ErrorAction Stop | Where-Object {
            $xml=[xml]$_.ToXml();$d=@{};$xml.Event.EventData.Data|ForEach-Object{$d[$_.Name]=$_.'#text'}
            $d['ObjectType'] -eq 'File' -and $d['FileName'] -match ($activityPatterns -join '|') -and -not ($d['FileName'] -match 'microsoft|windows|system32|programdata')
        } | ForEach-Object {
            $xml=[xml]$_.ToXml();$d=@{};$xml.Event.EventData.Data|ForEach-Object{$d[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Action='File Accessed/Opened';Source=$d['SubjectUserName'];Target=$d['FileName'];Access=$d['AccessMask']}
        }
        if($fileEvents){$fileEvents|ForEach-Object{$activity.Add($_)}}
        Update-UI -Controls $Controls -LogMessage "  → $($fileEvents.Count) file access events from Security log."
    } catch {}

    if($activity.Count -gt 0){
        # Filter to only show cheat-relevant activity
        $cheatActivity = $activity | Where-Object {
            $target = if($_.Target){$_.Target.ToLower()}else{''}
            $target -match ($Script:SusKeywords -join '|') -or
            $target -match '\.exe$|\.dll$|\.ps1$|\.bat$|\.vbs$|\.cmd$|\.scr$|\.sys$|\.asi$|\.crack$|\.trainer$' -or
            ($_.Action -eq 'File Downloaded' -and $_.URL -match ($Script:DnsMalPatterns -join '|'))
        } | Sort-Object Time -Descending

        if($cheatActivity){
            Add-Result -Category 'Forensics_FileActivityTimeline' -Severity High -Data $cheatActivity
            Update-UI -Controls $Controls -LogMessage "  → ⚠ $($cheatActivity.Count) cheat-related file activity events recorded (downloads, creations, deletions, renames)."
        } else {
            Update-UI -Controls $Controls -LogMessage "  → $($activity.Count) total file events, none flagged as cheat-related."
        }
    } else {
        Update-UI -Controls $Controls -LogMessage '  → No file activity events available (requires Sysmon/advanced audit).'
    }
}

# ================================================================
# NEW MODULE 2: Deleted File Artifacts
# ================================================================
function Get-DeletedFileArtifacts {
    param($Controls)

    $deletedEvidence = [System.Collections.Generic.List[object]]::new()

    # 2b: Prefetch files for now-deleted executables
    $pfDir = 'C:\Windows\Prefetch'
    if (Test-Path $pfDir) {
        $pfFiles = Get-ChildItem "$pfDir\*.pf" -ErrorAction SilentlyContinue
        $orphanedPrefetch = $pfFiles | Where-Object {
            # Extract base name without hash
            $baseName = $_.Name -replace '-[0-9A-F]{8}\.pf$', '' -replace '\.exe$', ''
            $exePath = Get-ChildItem -Path "$env:SYSTEMDRIVE\Program Files", "$env:SYSTEMDRIVE\Program Files (x86)", "$env:SYSTEMDRIVE\Windows", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:USERPROFILE\Downloads" -Filter "${baseName}.exe" -Recurse -ErrorAction SilentlyContinue
            -not $exePath -and $_.LastWriteTime -gt $Script:SessionStart
        } | Select-Object Name, @{N='LastRun';E={$_.LastWriteTime}}, @{N='Executable';E={$_ -replace '-[0-9A-F]{8}\.pf$', ''}}

        if ($orphanedPrefetch) {
            $orphanedPrefetch | ForEach-Object {
                $deletedEvidence.Add([PSCustomObject]@{
                    Artifact='Orphaned Prefetch (EXE deleted)'
                    File=$_.Name
                    Executable=$_.Executable
                    LastRun=$_.LastRun
                    Detail='Prefetch file exists but the executable is no longer on disk — indicates a now-deleted cheat/injector.'
                })
            }
            Update-UI -Controls $Controls -LogMessage "  → ⚠ $($orphanedPrefetch.Count) orphaned Prefetch files (deleted executables)."
        }
    }

    # 2c: Windows Event 4663 (attempted deletion via audit)
    try {
        $deleteAttempts = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 2000 -ErrorAction Stop | Where-Object {
            $xml=[xml]$_.ToXml();$d=@{};$xml.Event.EventData.Data|ForEach-Object{$d[$_.Name]=$_.'#text'}
            $d['AccessMask'] -match 'DELETE|0x10000' -and $d['FileName'] -match ($Script:SusKeywords -join '|')
        } | ForEach-Object {
            $xml=[xml]$_.ToXml();$d=@{};$xml.Event.EventData.Data|ForEach-Object{$d[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;Action='File Deleted (Audit)';User=$d['SubjectUserName'];File=$d['FileName'];Process=$d['ProcessName']}
        }
        if($deleteAttempts){$deleteAttempts|ForEach-Object{$deletedEvidence.Add($_)}; Update-UI -Controls $Controls -LogMessage "  → ⚠ $($deleteAttempts.Count) audited file deletions of cheat-named files."}
    } catch {}

    # 2d: Recent file shortcuts that point to now-missing locations
    try {
        $recentShortcuts = Get-ChildItem "$env:USERPROFILE\Recent" -Filter '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($_.FullName)
            $target = $shortcut.TargetPath
            if ($target -and -not (Test-Path $target) -and $target -match ($Script:SusKeywords -join '|')) {
                [PSCustomObject]@{
                    Artifact='Deleted File Shortcut'
                    Shortcut=$_.Name
                    Target=$target
                    Created=$_.CreationTime
                    Modified=$_.LastWriteTime
                }
            }
        }
        if ($recentShortcuts) { $recentShortcuts | ForEach-Object { $deletedEvidence.Add($_) }; Update-UI -Controls $Controls -LogMessage "  → ⚠ $($recentShortcuts.Count) shortcuts point to now-deleted cheat files." }
    } catch {}

    # 2e: UserAssist entries for now-deleted applications
    try {
        $uaPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
        Get-ChildItem $uaPath -ErrorAction SilentlyContinue | ForEach-Object {
            $guid = $_.PSChildName
            $uaData = Get-ItemProperty "${uaPath}\${guid}\Count" -ErrorAction SilentlyContinue
            if ($uaData) {
                $uaData.PSObject.Properties | Where-Object { $_.Name -notmatch 'PSPath|PSParentPath|PSChildName|PSDrive|PSProvider' } | ForEach-Object {
                    $name = $_.Name
                    # Decode ROT-13 in UserAssist
                    $decoded = ''
                    foreach ($c in $name.ToCharArray()) {
                        if ($c -ge 'a' -and $c -le 'z') { $decoded += [char]((([int]$c) - 97 + 13) % 26 + 97) }
                        elseif ($c -ge 'A' -and $c -le 'Z') { $decoded += [char]((([int]$c) - 65 + 13) % 26 + 65) }
                        else { $decoded += $c }
                    }
                    if ($decoded -match ($Script:SusKeywords -join '|')) {
                        # Check if the file still exists
                        $exeMatch = $decoded -match '([A-Za-z]:\\[^Z]+\.exe)'
                        if ($exeMatch -and -not (Test-Path $matches[1])) {
                            $deletedEvidence.Add([PSCustomObject]@{
                                Artifact='Deleted EXE in UserAssist'
                                Executable=$decoded
                                RunCount=$_.Value
                                Detail='This executable was run (tracked in UserAssist) but no longer exists on disk.'
                            })
                        }
                    }
                }
            }
        }
        Update-UI -Controls $Controls -LogMessage "  → Scanned UserAssist for deleted executable references."
    } catch {}

    # 2f: Known $Recycle.Bin indicators (files that passed through recycle bin)
    $recyclePath = "$env:SYSTEMDRIVE`$Recycle.Bin"
    if (Test-Path $recyclePath) {
        # Can't enumerate directly, but we can check size/change time
        $recycleInfo = Get-Item $recyclePath -ErrorAction SilentlyContinue
        if ($recycleInfo -and $recycleInfo.LastWriteTime -gt $Script:SessionStart) {
            $deletedEvidence.Add([PSCustomObject]@{
                Artifact='Recycle Bin Activity'
                LastModified=$recycleInfo.LastWriteTime
                Detail='Recycle Bin was modified within the session window — files may have been deleted through the Recycle Bin.'
            })
        }
    }

    if ($deletedEvidence.Count -gt 0) {
        Add-Result -Category 'Forensics_DeletedFileArtifacts' -Severity Critical -Data $deletedEvidence
        Update-UI -Controls $Controls -LogMessage "  → ⚠ $($deletedEvidence.Count) deleted file artifacts found."
    } else {
        Update-UI -Controls $Controls -LogMessage '  → No deleted file artifacts detected.'
    }
}

# ================================================================
# NEW MODULE 3: Execution History
# ================================================================
function Get-ExecutionHistory {
    param($Controls)

    $execHistory = [System.Collections.Generic.List[object]]::new()

    # 3b: UserAssist execution counts for cheat-named programs
    try {
        $uaPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
        Get-ChildItem $uaPath -ErrorAction SilentlyContinue | ForEach-Object {
            $guid = $_.PSChildName
            $uaData = Get-ItemProperty "${uaPath}\${guid}\Count" -ErrorAction SilentlyContinue
            if ($uaData) {
                $uaData.PSObject.Properties | Where-Object { $_.Name -notmatch 'PSPath|PSParentPath|PSChildName|PSDrive|PSProvider' } | ForEach-Object {
                    $name = $_.Name
                    $decoded = ''
                    foreach ($c in $name.ToCharArray()) {
                        if ($c -ge 'a' -and $c -le 'z') { $decoded += [char]((([int]$c) - 97 + 13) % 26 + 97) }
                        elseif ($c -ge 'A' -and $c -le 'Z') { $decoded += [char]((([int]$c) - 65 + 13) % 26 + 65) }
                        else { $decoded += $c }
                    }
                    if ($decoded -match ($Script:SusKeywords -join '|')) {
                        $execHistory.Add([PSCustomObject]@{
                            Artifact='UserAssist Execution Record'
                            Program=$decoded
                            Executions=$_.Value
                        })
                    }
                }
            }
        }
    } catch {}

    # 3d: Program Compatibility Assistant records
    try {
        $pcaEntries = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\PCA' -ErrorAction SilentlyContinue
        if ($pcaEntries) {
            $pcaEntries.PSObject.Properties | Where-Object { $_.Name -notmatch 'PSPath|PSParentPath|PSChildName|PSDrive|PSProvider' -and $_.Name -match ($Script:SusKeywords -join '|') } | ForEach-Object {
                $execHistory.Add([PSCustomObject]@{
                    Artifact='PCA Execution Record'
                    Program=$_.Name
                    Detail=$_.Value
                })
            }
        }
    } catch {}

    # 3e: AmCache (recently executed programs via registry)
    try {
        $amCachePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
        $amCache = Get-ItemProperty $amCachePath -ErrorAction SilentlyContinue
        if ($amCache) {
            # Check subkeys
            $amCacheSub = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache' -ErrorAction SilentlyContinue
            if ($amCacheSub) {
                $amCacheSub | ForEach-Object {
                    $cacheData = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if ($cacheData) {
                        $cacheData.PSObject.Properties | Where-Object { $_.Name -notmatch 'PSPath|PSParentPath|PSChildName|PSDrive|PSProvider' -and $_.Value -match ($Script:SusKeywords -join '|') } | ForEach-Object {
                            $execHistory.Add([PSCustomObject]@{
                                Artifact='AppCompatCache Entry'
                                Program=$_.Name
                                Detail='Executable recorded in Application Compatibility Cache'
                            })
                        }
                    }
                }
            } elseif ($amCache.'(default)') {
                # Try parsing binary data
                $amCacheData = $amCache.'(default)'
                if ($amCacheData -and $amCacheData.Length -gt 100) {
                    # Simple string extraction for executable paths
                    $strings = [System.Text.Encoding]::Unicode.GetString($amCacheData)
                    $exeMatches = [regex]::Matches($strings, '[A-Z]:\\[^\\]+(?:\\[^\\]+)*\.exe')
                    $exeMatches | Select-Object -Unique | ForEach-Object {
                        $exePath = $_.Value
                        if ($exePath -match ($Script:SusKeywords -join '|')) {
                            $execHistory.Add([PSCustomObject]@{
                                Artifact='AppCompatCache Entry'
                                Program=$exePath
                                Detail='Executable recorded in Application Compatibility Cache'
                            })
                        }
                    }
                }
            }
        }
    } catch {}

    # 3f: Jump List entries for cheat programs
    try {
        $jumpListPaths = @("$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations", "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations")
        foreach ($jlp in $jumpListPaths) {
            if (Test-Path $jlp) {
                Get-ChildItem $jlp -ErrorAction SilentlyContinue | ForEach-Object {
                    $execHistory.Add([PSCustomObject]@{
                        Artifact='Jump List'
                        File=$_.Name
                        Modified=$_.LastWriteTime
                        Detail='Jump list file found — indicates application was launched and pinned/recently used'
                    })
                }
            }
        }
    } catch {}

    # 3g: MUICache (recently run programs by name)
    try {
        $muiPaths = @('HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify')
        foreach ($mp in $muiPaths) {
            $muiData = Get-ItemProperty $mp -ErrorAction SilentlyContinue
            if ($muiData) {
                $muiData.PSObject.Properties | Where-Object { $_.Name -notmatch 'PSPath|PSParentPath|PSChildName|PSDrive|PSProvider' -and $_.Value -match ($Script:SusKeywords -join '|') } | ForEach-Object {
                    $execHistory.Add([PSCustomObject]@{
                        Artifact='MUICache / TrayNotify'
                        Name=$_.Name
                        Value=$_.Value
                    })
                }
            }
        }
    } catch {}

    if ($execHistory.Count -gt 0) {
        Add-Result -Category 'Forensics_ExecutionHistory' -Severity High -Data $execHistory
        Update-UI -Controls $Controls -LogMessage "  → ⚠ $($execHistory.Count) execution history records found (UserAssist, AppCompatCache, Jump Lists, MUICache)."
    } else {
        Update-UI -Controls $Controls -LogMessage '  → No suspicious execution history records found.'
    }
}

# ================================================================
# NEW MODULE 4: Recycle Bin Analysis
# ================================================================
function Get-RecycleBinAnalysis {
    param($Controls)

    $recycleFindings = [System.Collections.Generic.List[object]]::new()

    # 4a: Recycle Bin last emptied timestamp
    try {
        $emptyTimestamp = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket' -Name 'LastEmptyTime' -ErrorAction SilentlyContinue
        if ($emptyTimestamp -and $emptyTimestamp.LastEmptyTime) {
            $lastEmpty = $emptyTimestamp.LastEmptyTime
            $hoursAgo = [math]::Round(((Get-Date) - $lastEmpty).TotalHours, 1)
            $severity = 'Info'
            $note = ''
            if ($hoursAgo -le $SessionHours) {
                $severity = 'Critical'
                $note = ' — VERY RECENT (within scan session window)'
            } elseif ($hoursAgo -le 24) {
                $severity = 'High'
                $note = ' — recent (within last 24 hours)'
            } elseif ($hoursAgo -le 72) {
                $severity = 'Medium'
                $note = ' — within last 3 days'
            }
            $recycleFindings.Add([PSCustomObject]@{
                Artifact='Recycle Bin Emptied'
                LastEmpty=$lastEmpty
                HoursAgo=$hoursAgo
                Severity=$severity
                Detail="Recycle Bin was last emptied $hoursAgo hours ago ($($lastEmpty.ToString('yyyy-MM-dd HH:mm')))${note}."
            })
            Update-UI -Controls $Controls -LogMessage "  → ⚠ Recycle Bin last emptied $hoursAgo hours ago."
        } else {
            $recycleFindings.Add([PSCustomObject]@{
                Artifact='Recycle Bin Status'
                Detail='No "Last Empty" timestamp found — may never have been emptied, or key does not exist.'
            })
            Update-UI -Controls $Controls -LogMessage '  → No Recycle Bin empty record found.'
        }
    } catch {
        $recycleFindings.Add([PSCustomObject]@{
            Artifact='Recycle Bin Status'
            Detail='Could not read Recycle Bin empty timestamp.'
        })
    }

    # 4b: Recycle Bin file count and size
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.NameSpace(10)  # 10 = Recycle Bin
        $items = $recycleBin.Items()
        $itemCount = $items.Count
        $totalSize = 0
        $suspiciousItems = @()
        foreach ($item in $items) {
            $totalSize += $item.Size
            if ($item.Name -match ($Script:SusKeywords -join '|') -or $item.Name -match '\.exe$|\.dll$|\.ps1$|\.bat$|\.vbs$|\.sys$') {
                $suspiciousItems += [PSCustomObject]@{
                    Name=$item.Name
                    Size=$item.Size
                    DateDeleted=$item.ExtendedProperty('System.Recycle.DateDeleted')
                    OriginalLocation=$item.ExtendedProperty('System.Recycle.OriginalLocation')
                }
            }
        }

        $recycleFindings.Add([PSCustomObject]@{
            Artifact='Current Recycle Bin Contents'
            ItemCount=$itemCount
            TotalSizeMB=[math]::Round($totalSize / 1MB, 1)
            SuspiciousCount=$suspiciousItems.Count
            Detail="Currently $itemCount items in Recycle Bin ($([math]::Round($totalSize/1MB,1)) MB), $($suspiciousItems.Count) suspicious."
        })

        if ($suspiciousItems) {
            Add-Result -Category 'Forensics_RecycleBinSuspiciousFiles' -Severity Critical -Data $suspiciousItems
            Update-UI -Controls $Controls -LogMessage "  → ⚠ $($suspiciousItems.Count) suspicious files found in Recycle Bin."
        }

    } catch {
        $recycleFindings.Add([PSCustomObject]@{
            Artifact='Recycle Bin Query'
            Detail='Could not enumerate Recycle Bin contents via Shell API.'
        })
    }

    # 4c: Check if Recycle Bin has been cleared recently (by checking $Recycle.Bin folder date)
    try {
        $recyclePath = "$env:SYSTEMDRIVE`$Recycle.Bin"
        if (Test-Path $recyclePath) {
            $recycleDir = Get-Item $recyclePath -ErrorAction SilentlyContinue
            $daysSinceChange = [math]::Round(((Get-Date) - $recycleDir.LastWriteTime).TotalDays, 1)
            $recycleFindings.Add([PSCustomObject]@{
                Artifact='$Recycle.Bin Folder'
                LastModified=$recycleDir.LastWriteTime
                DaysSinceModification=$daysSinceChange
                Detail="`$Recycle.Bin folder last modified $daysSinceChange days ago."
            })
        }
    } catch {}

    if ($recycleFindings) {
        Add-Result -Category 'Forensics_RecycleBinAnalysis' -Severity Info -Data $recycleFindings
    }
}

# ================================================================
# BYPASS MODULES (abbreviated - kept from original)
# ================================================================

function Get-AMSIBypassArtifacts {
    param($Controls)
    $findings=@()
    $amsiPaths=@('HKLM:\SOFTWARE\Microsoft\AMSI\FeatureBits','HKCU:\SOFTWARE\Microsoft\AMSI\FeatureBits')
    foreach($p in $amsiPaths){
        $val=Get-ItemProperty $p -ErrorAction SilentlyContinue
        if($val -and $p -match 'FeatureBits' -and $val.FeatureBits -in 1,0x80,128){
            $findings+=[PSCustomObject]@{Artifact="AMSI Bypass (FeatureBits=$($val.FeatureBits))";Path=$p;Detail='AMSI scanning disabled via registry';Risk='Critical'}
        }
    }
    try{$etwDisable=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI' -Name 'DisableETW' -ErrorAction SilentlyContinue;if($etwDisable -and $etwDisable.DisableETW -eq 1){$findings+=[PSCustomObject]@{Artifact='ETW Globally Disabled';Detail='ETW tracing disabled (common cheat bypass)';Risk='Critical'}}}catch{}
    foreach($f in $findings){$sev=if($f.Risk -eq 'Critical'){'Critical'}else{'High'};Add-Result -Category "Bypass_$($f.Artifact -replace '[\s\(\)\/]','')" -Severity $sev -Data $f;Update-UI -Controls $Controls -LogMessage "  → ⚠ $($f.Artifact) — $($f.Detail)" -StatusColor 'Yellow'}
    if(-not $findings){Update-UI -Controls $Controls -LogMessage '  → No AMSI/ETW bypass detected.'}
}

function Get-InjectionArtifacts {
    param($Controls)
    $injections=@()
    try{
        $allProcs=Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688;StartTime=$Script:SessionStart;EndTime=$Script:SessionEnd} -MaxEvents 10000 -ErrorAction Stop | ForEach-Object{
            $xml=[xml]$_.ToXml();$d=@{};$xml.Event.EventData.Data|ForEach-Object{$d[$_.Name]=$_.'#text'}
            [PSCustomObject]@{Time=$_.TimeCreated;User=$d['SubjectUserName'];NewProc=$d['NewProcessName'];PID=$d['NewProcessId'];CmdLine=$d['CommandLine'];Parent=$d['ParentProcessName']}
        }
        $hollow=@('svchost.exe','rundll32.exe','regsvr32.exe','taskhostw.exe','wmiprvse.exe','dllhost.exe')
        $hollowed=$allProcs|Where-Object{$n=[IO.Path]::GetFileName($_.NewProc).ToLower();$p=[IO.Path]::GetFileName($_.Parent).ToLower();$n -in $hollow -and $p -notin @('winlogon.exe','svchost.exe','services.exe','smss.exe','lsass.exe') -and $_.CmdLine -match 'console|windowstyle hidden|hidden|-ep bypass|noprofile'}
        if($hollowed){$hollowed|ForEach-Object{$injections+=[PSCustomObject]@{Artifact='Process Hollowing Candidate';Process=$_.NewProc;PID=$_.PID;Parent=$_.Parent;Time=$_.Time.ToString('yyyy-MM-dd HH:mm')}}}
        $lolbins=$allProcs|Where-Object{$n=[IO.Path]::GetFileName($_.NewProc).ToLower();$n -in @('rundll32.exe','regsvr32.exe','mshta.exe','cscript.exe','wscript.exe','powershell.exe') -and $_.CmdLine -match '-embedded|-stub|javascript:|http:|https://|webclient|downloadstring|iex|invoke-expression'}
        if($lolbins){$lolbins|ForEach-Object{$injections+=[PSCustomObject]@{Artifact='LOLBin Injection';Process=[IO.Path]::GetFileName($_.NewProc);PID=$_.PID;CmdLine=$_.CmdLine;Time=$_.Time.ToString('yyyy-MM-dd HH:mm')}}}
        if($injections){Add-Result -Category 'Bypass_ProcessInjection' -Severity Critical -Data $injections;Update-UI -Controls $Controls -LogMessage "  → ⚠ $($injections.Count) process injection/hollowing artifacts found."}
        else{Update-UI -Controls $Controls -LogMessage '  → No injection artifacts.'}
    }catch{Update-UI -Controls $Controls -LogMessage "  → Injection check error: $($_.Exception.Message)"}
}

# ================================================================
# HTML Report, Export, and Entry Point
# ================================================================

function ConvertTo-HtmlSafe{param([string]$Text)if($null -eq $Text){return ''}return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')}

function ConvertTo-DataHtml{param($Data)
    if($Data -is [array] -or ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string])){
        $items=@($Data);if($items.Count -eq 0){return '<p class="empty">No items.</p>'}
        $propNames=[System.Collections.Generic.List[string]]::new()
        foreach($item in $items|Select-Object -First 25){if($item -is [PSObject]){foreach($p in $item.PSObject.Properties){if(-not $propNames.Contains($p.Name)){$propNames.Add($p.Name)}}}}
        if($propNames.Count -eq 0){$rows=($items|ForEach-Object{"<li>$(ConvertTo-HtmlSafe([string]$_))</li>"})-join "`n";return "<ul class='plain-list'>$rows</ul>"}
        $sb=[System.Text.StringBuilder]::new();$sb.Append('<div class="table-wrap"><table><thead><tr>')|Out-Null;foreach($p in $propNames){$sb.Append("<th>$(ConvertTo-HtmlSafe($p))</th>")|Out-Null};$sb.Append('</tr></thead><tbody>')|Out-Null
        $rowIndex=0;foreach($item in $items){$rowIndex++;$delay=[Math]::Min($rowIndex*0.02,1.2);$sb.Append("<tr style='animation-delay: ${delay}s'>")|Out-Null;foreach($p in $propNames){$val='';if($item -is [PSObject] -and $item.PSObject.Properties[$p]){$raw=$item.PSObject.Properties[$p].Value;$val=if($null -eq $raw){''}else{[string]$raw}};$sb.Append("<td>$(ConvertTo-HtmlSafe($val))</td>")|Out-Null};$sb.Append('</tr>')|Out-Null}
        $sb.Append('</tbody></table></div>')|Out-Null;return $sb.ToString()
    }elseif($Data -is [string] -and $Data.Length -gt 0){return "<pre class='raw-block'>$(ConvertTo-HtmlSafe($Data))</pre>"}else{return '<p class="empty">No detail data available.</p>'}
}

function New-HtmlReport{param($Results,[string]$OutFile)
    $isAdmin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $severityRank=@{Critical=0;High=1;Medium=2;Low=3;Info=4};$ordered=$Results|Sort-Object{if($severityRank.ContainsKey($_.Severity)){$severityRank[$_.Severity]}else{99}}
    $counts=@{Critical=0;High=0;Medium=0;Low=0;Info=0};foreach($r in $Results){if($counts.ContainsKey($r.Severity)){$counts[$r.Severity]++}}
    $tabButtons=[System.Text.StringBuilder]::new();$tabPanels=[System.Text.StringBuilder]::new();$i=0
    foreach($result in $ordered){$i++;$tabId="tab-$i";$sevSlug=$result.Severity.ToString().ToLower();$safeCat=ConvertTo-HtmlSafe($result.Category)
        $itemCount=if($result.Data -is [array]){$result.Data.Count}elseif($result.Data -is [string] -and $result.Data.Length -gt 0){1}else{0}
        $btnHtml=[string]::Format('<button class="tab-btn sev-{0}" data-target="{1}" style="animation-delay:{2}s"><span class="dot"></span><span class="tab-label">{3}</span><span class="tab-count">{4}</span></button>',$sevSlug,$tabId,($i*0.04),$safeCat,$itemCount)
        $tabButtons.AppendLine($btnHtml)|Out-Null
        $dataHtml=ConvertTo-DataHtml -Data $result.Data
        $panelHtml=[string]::Format('<section class="panel" id="{0}"><div class="panel-head"><h2>{1}</h2><span class="badge sev-{2}">{3}</span><span class="timestamp">Detected {4}</span></div><div class="panel-body">{5}</div></section>',$tabId,$safeCat,$sevSlug,$result.Severity,$result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'),$dataHtml)
        $tabPanels.AppendLine($panelHtml)|Out-Null
    }
    if($ordered.Count -eq 0){$tabButtons.Append('<span class="empty">No categories.</span>')|Out-Null;$tabPanels.Append('<section class="panel active"><p class="empty">No artifacts recorded.</p></section>')|Out-Null}
    $generatedAt=Get-Date;$osCaption=try{(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption}catch{'Unknown'}
    $summaryChips=[string]::Format('<span class="chip"><span class="swatch" style="background:var(--crit)"></span>Critical <b>{0}</b></span><span class="chip"><span class="swatch" style="background:var(--high)"></span>High <b>{1}</b></span><span class="chip"><span class="swatch" style="background:var(--med)"></span>Medium <b>{2}</b></span><span class="chip"><span class="swatch" style="background:var(--low)"></span>Low <b>{3}</b></span><span class="chip"><span class="swatch" style="background:var(--info)"></span>Info <b>{4}</b></span>',$counts.Critical,$counts.High,$counts.Medium,$counts.Low,$counts.Info)
    $privText=if($isAdmin){'Administrator'}else{'Standard User'}
    $metaLine=[string]::Format('Host: {0} &nbsp;|&nbsp; OS: {1} &nbsp;|&nbsp; Generated: {2} &nbsp;|&nbsp; Privilege: {3}',(ConvertTo-HtmlSafe($env:COMPUTERNAME)),(ConvertTo-HtmlSafe($osCaption)),$generatedAt.ToString('yyyy-MM-dd HH:mm:ss'),$privText)
    $html=@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Forensic Scan Report</title>
<style>
:root{--bg:#0c0c10;--panel:#15151b;--panel-alt:#1c1c24;--border:#2a2a34;--text:#e6e6ee;--muted:#8a8a9a;--accent:#7c5cff;--accent-2:#22d3ee;--crit:#ff4d6d;--high:#ff9f43;--med:#ffd166;--low:#9aa5ff;--info:#4fd1c5}
*{box-sizing:border-box}
body{margin:0;font-family:'Consolas','Cascadia Code','Segoe UI',monospace;background:radial-gradient(circle at 20% -10%,#1a1030 0%,var(--bg) 55%);color:var(--text);min-height:100vh}
header{padding:28px 36px 20px;border-bottom:1px solid var(--border);background:linear-gradient(120deg,rgba(124,92,255,0.12),rgba(34,211,238,0.06));animation:fadeDown .5s ease both}
header h1{margin:0 0 6px;font-size:22px;background:linear-gradient(90deg,var(--accent),var(--accent-2));-webkit-background-clip:text;background-clip:text;color:transparent}
header .meta{color:var(--muted);font-size:12.5px;line-height:1.6}
.summary{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}
.summary .chip{padding:8px 14px;border-radius:999px;font-size:12px;border:1px solid var(--border);background:var(--panel-alt);display:flex;align-items:center;gap:8px;opacity:0;animation:popIn .4s ease forwards}
.summary .chip b{font-size:14px}.swatch{width:9px;height:9px;border-radius:50%;display:inline-block}
main{display:grid;grid-template-columns:300px 1fr;gap:0;min-height:calc(100vh - 130px)}
nav.tabs{border-right:1px solid var(--border);padding:18px 12px;display:flex;flex-direction:column;gap:6px;overflow-y:auto;max-height:calc(100vh - 130px)}
.tab-btn{all:unset;cursor:pointer;display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;color:var(--text);font-size:12.5px;border:1px solid transparent;opacity:0;animation:slideIn .35s ease forwards;transition:background .2s ease,transform .15s ease,border-color .2s ease}
.tab-btn:hover{background:var(--panel-alt);transform:translateX(2px)}.tab-btn.active{background:var(--panel-alt);border-color:var(--border);box-shadow:inset 3px 0 0 var(--accent)}
.tab-label{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tab-count{font-size:10.5px;color:var(--muted);background:rgba(255,255,255,0.06);padding:2px 7px;border-radius:999px}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}.sev-critical .dot,.badge.sev-critical{background:var(--crit)}.sev-high .dot,.badge.sev-high{background:var(--high)}.sev-medium .dot,.badge.sev-medium{background:var(--med);color:#20140a}.sev-low .dot,.badge.sev-low{background:var(--low);color:#101018}.sev-info .dot,.badge.sev-info{background:var(--info);color:#08201d}
.badge{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:bold;color:#1a0510}
section.panel{display:none;padding:28px 34px;animation:fadeUp .4s ease both}section.panel.active{display:block}
.panel-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding-bottom:14px;margin-bottom:18px;border-bottom:1px solid var(--border)}
.panel-head h2{margin:0;font-size:17px}.timestamp{color:var(--muted);font-size:12px;margin-left:auto}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:10px}table{border-collapse:collapse;width:100%;font-size:12px}
thead th{text-align:left;padding:10px 12px;background:var(--panel-alt);color:var(--accent-2);position:sticky;top:0;border-bottom:1px solid var(--border);white-space:nowrap}
tbody td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.04);white-space:nowrap;max-width:420px;overflow:hidden;text-overflow:ellipsis}
tbody tr{opacity:0;animation:rowIn .3s ease forwards}tbody tr:hover{background:rgba(124,92,255,0.08)}
.raw-block{background:var(--panel-alt);border:1px solid var(--border);border-radius:10px;padding:16px;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:60vh;overflow:auto}
.plain-list{font-size:12px;line-height:1.8;padding-left:20px}.empty{color:var(--muted);font-style:italic}
footer{padding:16px 34px;color:var(--muted);font-size:11px;border-top:1px solid var(--border)}
@keyframes fadeDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
@keyframes popIn{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:scale(1)}}
@keyframes rowIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:var(--border);border-radius:999px}::-webkit-scrollbar-track{background:transparent}
</style></head><body>
<header><h1>⟡ Game Cheat Forensic Report</h1><div class="meta">$metaLine</div>
<div class="summary">$summaryChips</div></header>
<main><nav class="tabs">$($tabButtons.ToString())</nav><div class="panels">$($tabPanels.ToString())</div></main>
<footer>Generated by HackerAI Forensics Scanner v2.1</footer>
<script>
const b=document.querySelectorAll('.tab-btn'),p=document.querySelectorAll('.panel');
function a(i){b.forEach((x,j)=>x.classList.toggle('active',j===i));p.forEach((x,j)=>x.classList.toggle('active',j===i))}
b.forEach((x,i)=>x.addEventListener('click',()=>a(i)));if(b.length)a(0);
</script></body></html>
"@
    [System.IO.File]::WriteAllText($OutFile,$html,[System.Text.Encoding]::UTF8)
}

function Export-Report{param($Controls)
    $saveDlg=New-Object Windows.Forms.SaveFileDialog
    $saveDlg.Title='Save Forensic Report';$saveDlg.Filter='HTML Report (*.html)|*.html|Text Report (*.txt)|*.txt|All Files (*.*)|*.*'
    $saveDlg.FileName="CheatForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')";$saveDlg.InitialDirectory=[Environment]::GetFolderPath('Desktop')
    if($saveDlg.ShowDialog() -ne 'OK'){return}
    if([System.IO.Path]::GetExtension($saveDlg.FileName) -eq '.html'){
        try{New-HtmlReport -Results $Script:Results -OutFile $saveDlg.FileName;Update-UI -Controls $Controls -LogMessage "HTML report exported to: $($saveDlg.FileName)" -StatusText 'Report Exported' -StatusColor 'LightGreen'}catch{[System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)",'Export Error','OK','Error')}
        return
    }
    try{
        $sb=[System.Text.StringBuilder]::new()
        $sb.AppendLine("="*80)|Out-Null;$sb.AppendLine("  GAME CHEAT FORENSIC REPORT")|Out-Null;$sb.AppendLine("  Generated: $(Get-Date)")|Out-Null;$sb.AppendLine("  HackerAI Forensics Scanner v2.1")|Out-Null;$sb.AppendLine("="*80)|Out-Null;$sb.AppendLine("")|Out-Null
        foreach($result in $Script:Results){
            $sb.AppendLine("[$($result.Severity)] $($result.Category)")|Out-Null;$sb.AppendLine("-"*60)|Out-Null
            if($result.Data -is [array] -and $result.Data.Count -gt 0){$raw=$result.Data|Format-Table -AutoSize -Wrap|Out-String -Width 120;$indented=($raw -split "`r`n"|ForEach-Object{"  $_"})-join "`r`n";$sb.AppendLine($indented)|Out-Null}elseif($result.Data -is [string]){$sb.AppendLine("  $($result.Data)")|Out-Null}else{$sb.AppendLine("  (data available in HTML export)")|Out-Null}
            $sb.AppendLine("")|Out-Null
        }
        [System.IO.File]::WriteAllText($saveDlg.FileName,$sb.ToString(),[System.Text.Encoding]::UTF8);Update-UI -Controls $Controls -LogMessage "Report exported to: $($saveDlg.FileName)" -StatusText 'Report Exported' -StatusColor 'LightGreen'
    }catch{[System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)",'Export Error','OK','Error')}
}

# ---------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------
$controls = New-MainForm

$controls.BtnStart.Add_Click({
    $h=$controls.SessionNud.Value;$Script:SessionStart=(Get-Date).AddHours(-$h);$Script:SessionEnd=(Get-Date)
    $controls.StageLabel.Text="Session set: last $h hours";Start-ForensicScan -Controls $controls
})
$controls.BtnCancel.Add_Click({$Script:CancelScan=$true;$controls.BtnCancel.Enabled=$false;Update-UI -Controls $controls -StatusText 'Cancelling...' -StatusColor 'Yellow'})
$controls.BtnExport.Add_Click({Export-Report -Controls $controls})
$controls.BtnWebReport.Add_Click({try{$tempFile=Join-Path ([System.IO.Path]::GetTempPath()) "CheatForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').html";New-HtmlReport -Results $Script:Results -OutFile $tempFile;Start-Process $tempFile;Update-UI -Controls $controls -LogMessage "Web report opened: $tempFile" -StatusText 'Web Report Opened' -StatusColor 'LightGreen'}catch{[System.Windows.Forms.MessageBox]::Show("Could not open web report: $($_.Exception.Message)",'Web Report Error','OK','Error')}})
$controls.SessionApply.Add_Click({$h=$controls.SessionNud.Value;$Script:SessionStart=(Get-Date).AddHours(-$h);$Script:SessionEnd=(Get-Date);$controls.StageLabel.Text="Session: last $h hours";Update-UI -Controls $controls -LogMessage "Session window updated: last $h hours"})
$controls.TreeView.Add_AfterSelect({Show-Detail -TreeView $controls.TreeView -DetailBox $controls.DetailBox -Results $Script:Results})
$controls.Form.Add_Shown({$controls.StageLabel.Text="Ready. Session: last $SessionHours hours  ($($Script:SessionStart.ToString('HH:mm')) → $($Script:SessionEnd.ToString('HH:mm')))"})

[System.Windows.Forms.Application]::Run($controls.Form)