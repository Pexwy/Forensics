Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Data

# P/Invoke used to drag the borderless window from its header
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class AltDetectorNative {
    [DllImport("user32.DLL", EntryPoint = "ReleaseCapture")]
    public static extern void ReleaseCapture();
    [DllImport("user32.DLL", EntryPoint = "SendMessage")]
    public static extern void SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
}
"@

$startPath = "C:\Users"

if (-not (Test-Path $startPath)) {
    exit
}

# ============================================================
#  Theme
# ============================================================

$colorBg      = [System.Drawing.Color]::FromArgb(30, 30, 30)    # #1e1e1e
$colorPanel   = [System.Drawing.Color]::FromArgb(42, 42, 42)    # #2a2a2a
$colorTrack   = [System.Drawing.Color]::FromArgb(38, 38, 38)    # #262626
$colorBorder  = [System.Drawing.Color]::FromArgb(51, 51, 51)    # #333
$colorPink    = [System.Drawing.Color]::FromArgb(255, 102, 255) # #ff66ff
$colorPinkLt  = [System.Drawing.Color]::FromArgb(255, 153, 255) # #ff99ff
$colorGreen   = [System.Drawing.Color]::FromArgb(102, 255, 153) # #66ff99
$colorBlue    = [System.Drawing.Color]::FromArgb(159, 211, 255) # #9fd3ff
$colorSubtext = [System.Drawing.Color]::FromArgb(153, 153, 153) # #999
$colorText    = [System.Drawing.Color]::FromArgb(221, 221, 221) # #ddd

function New-RoundedRegion {
    param([int]$Width, [int]$Height, [int]$Radius)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $Radius * 2
    $path.AddArc(0, 0, $d, $d, 180, 90)
    $path.AddArc($Width - $d, 0, $d, $d, 270, 90)
    $path.AddArc($Width - $d, $Height - $d, $d, $d, 0, 90)
    $path.AddArc(0, $Height - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

function Enable-Drag {
    param($Control, $TargetForm)
    $Control.Add_MouseDown({
        param($s, $e)
        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            [AltDetectorNative]::ReleaseCapture()
            [AltDetectorNative]::SendMessage($TargetForm.Handle, 0xA1, 2, 0)
        }
    }.GetNewClosure())
}

# ============================================================
#  Window shell
# ============================================================

$formWidth  = 480
$formHeight = 220

$form = New-Object System.Windows.Forms.Form
$form.Text = "Alt Detector"
$form.Size = New-Object System.Drawing.Size($formWidth, $formHeight)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "None"
$form.BackColor = $colorBg
$form.TopMost = $true
$form.ShowInTaskbar = $true
$form.MinimumSize = New-Object System.Drawing.Size(360, 160)
$form.Region = New-Object System.Drawing.Region((New-RoundedRegion -Width $form.Width -Height $form.Height -Radius 14))

$script:cancelRequested = $false
$form.Add_FormClosing({ $script:cancelRequested = $true })

$form.Add_Paint({
    param($s, $e)
    $pen = New-Object System.Drawing.Pen($colorBorder, 1)
    $e.Graphics.DrawPath($pen, (New-RoundedRegion -Width ($form.Width - 1) -Height ($form.Height - 1) -Radius 14))
    $pen.Dispose()
})

# accent strip (also acts as a drag handle, since there's no title bar)
$accent = New-Object System.Windows.Forms.Panel
$accent.Size = New-Object System.Drawing.Size($form.Width, 4)
$accent.Location = New-Object System.Drawing.Point(0, 0)
$accent.Add_Paint({
    param($s, $e)
    $rect = New-Object System.Drawing.Rectangle(0, 0, $accent.Width, $accent.Height)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $colorPink, $colorGreen, 0.0)
    $e.Graphics.FillRectangle($brush, $rect)
    $brush.Dispose()
})
$form.Controls.Add($accent)

# close button (small "x", top-right)
$closeBtn = New-Object System.Windows.Forms.Label
$closeBtn.Text = "x"
$closeBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$closeBtn.ForeColor = $colorSubtext
$closeBtn.AutoSize = $false
$closeBtn.Size = New-Object System.Drawing.Size(28, 24)
$closeBtn.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$closeBtn.Location = New-Object System.Drawing.Point(($form.Width - 36), 12)
$closeBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$closeBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$closeBtn.Add_MouseEnter({ $closeBtn.ForeColor = $colorPink })
$closeBtn.Add_MouseLeave({ $closeBtn.ForeColor = $colorSubtext })
$closeBtn.Add_Click({ $form.Close() })
$form.Controls.Add($closeBtn)
$closeBtn.BringToFront()

# title
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Alt Detector"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = $colorPink
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(24, 20)
$form.Controls.Add($titleLabel)

Enable-Drag -Control $accent -TargetForm $form
Enable-Drag -Control $titleLabel -TargetForm $form
Enable-Drag -Control $form -TargetForm $form

# subtitle / status line
$subLabel = New-Object System.Windows.Forms.Label
$subLabel.Text = "Enumerating files under $startPath ..."
$subLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subLabel.ForeColor = $colorSubtext
$subLabel.AutoSize = $false
$subLabel.Size = New-Object System.Drawing.Size(400, 18)
$subLabel.Location = New-Object System.Drawing.Point(24, 54)
$form.Controls.Add($subLabel)

# current file label (progress phase only)
$fileLabel = New-Object System.Windows.Forms.Label
$fileLabel.Text = ""
$fileLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
$fileLabel.ForeColor = $colorBlue
$fileLabel.AutoSize = $false
$fileLabel.AutoEllipsis = $true
$fileLabel.Size = New-Object System.Drawing.Size(432, 16)
$fileLabel.Location = New-Object System.Drawing.Point(24, 76)
$form.Controls.Add($fileLabel)

# progress track (progress phase only)
$track = New-Object System.Windows.Forms.Panel
$track.Size = New-Object System.Drawing.Size(432, 18)
$track.Location = New-Object System.Drawing.Point(24, 106)
$track.BackColor = $colorTrack
$track.Region = New-Object System.Drawing.Region((New-RoundedRegion -Width $track.Width -Height $track.Height -Radius 9))
$form.Controls.Add($track)

$fill = New-Object System.Windows.Forms.Panel
$fill.Size = New-Object System.Drawing.Size(0, 18)
$fill.Location = New-Object System.Drawing.Point(0, 0)
$fill.Add_Paint({
    param($s, $e)
    if ($fill.Width -gt 0) {
        $rect = New-Object System.Drawing.Rectangle(0, 0, $fill.Width, $fill.Height)
        $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $colorPink, $colorGreen, 0.0)
        $e.Graphics.FillRectangle($brush, $rect)
        $brush.Dispose()
    }
})
$track.Controls.Add($fill)

$percentLabel = New-Object System.Windows.Forms.Label
$percentLabel.Text = "0%"
$percentLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$percentLabel.ForeColor = $colorText
$percentLabel.AutoSize = $true
$percentLabel.Location = New-Object System.Drawing.Point(380, 130)
$form.Controls.Add($percentLabel)

function Update-ProgressWindow {
    param(
        [string]$Status,
        [string]$CurrentFile,
        [int]$Percent
    )
    if ($PSBoundParameters.ContainsKey('Status'))      { $subLabel.Text = $Status }
    if ($PSBoundParameters.ContainsKey('CurrentFile')) { $fileLabel.Text = $CurrentFile }
    if ($PSBoundParameters.ContainsKey('Percent')) {
        $p = [math]::Max(0, [math]::Min(100, $Percent))
        $fill.Width = [int]($track.Width * ($p / 100))
        $fill.Invalidate()
        $percentLabel.Text = "$p%"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

$form.Show()
$form.Refresh()
[System.Windows.Forms.Application]::DoEvents()

# ============================================================
#  Scan logic
# ============================================================

$gzFiles = Get-ChildItem -Path $startPath -Recurse -Filter "*.gz" -File -Force -ErrorAction SilentlyContinue
Update-ProgressWindow -Status "Enumerating .log files under $startPath ..."
$logFiles = Get-ChildItem -Path $startPath -Recurse -Filter "*.log" -File -Force -ErrorAction SilentlyContinue
$allFiles = @($gzFiles) + @($logFiles)

$results = @()
$seenUsers = @{}

$totalFiles = $allFiles.Count
$fileIndex = 0
$lastPercent = -1

if ($totalFiles -eq 0) {
    Update-ProgressWindow -Status "No .gz or .log files found under $startPath." -Percent 100
    Start-Sleep -Milliseconds 900
    $form.Close()
    exit
}

Update-ProgressWindow -Status "Scanning $totalFiles file(s) for usernames ..." -Percent 0

foreach ($file in $allFiles) {
    if ($script:cancelRequested) { break }

    $fileIndex++
    $percent = [math]::Min(100, [int](($fileIndex / $totalFiles) * 100))

    if ($percent -ne $lastPercent -or ($fileIndex % 10 -eq 0)) {
        Update-ProgressWindow -CurrentFile "[$fileIndex / $totalFiles]  $($file.Name)" -Percent $percent -Status "Found $($seenUsers.Count) unique username(s) so far ..."
        $lastPercent = $percent
    }

    try {
        $content = $null
        $isGz = $file.Extension -eq ".gz"

        if ($isGz) {
            $tempFileName = "$($file.BaseName)_temp_$([guid]::NewGuid().ToString('N')).txt"
            $tempOutput = Join-Path $file.DirectoryName $tempFileName

            $inputStream = [System.IO.File]::OpenRead($file.FullName)
            $outputStream = [System.IO.File]::Create($tempOutput)
            $gzipStream = New-Object System.IO.Compression.GZipStream($inputStream, [System.IO.Compression.CompressionMode]::Decompress)

            $gzipStream.CopyTo($outputStream)

            $gzipStream.Close()
            $outputStream.Close()
            $inputStream.Close()

            $content = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
            Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
        } else {
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        }

        $pattern = "Setting user:\s*(\S+)"
        if ($content -and $content -match $pattern) {
            $username = $Matches[1]
            if (-not $seenUsers.ContainsKey($username)) {
                $seenUsers[$username] = $true
                $results += [PSCustomObject]@{
                    "Username" = $username
                    "Path" = $file.FullName
                }
            }
        }
    }
    catch {
        continue
    }
}

if ($script:cancelRequested) { exit }

Update-ProgressWindow -Status "Scan complete." -Percent 100 -CurrentFile ""
Start-Sleep -Milliseconds 300

# ============================================================
#  Results view (rendered inside the same window)
# ============================================================

$form.SuspendLayout()

# grow + recenter the window
$resultsWidth  = 760
$resultsHeight = 540
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.Location = New-Object System.Drawing.Point(
    [int](($screen.Width - $resultsWidth) / 2),
    [int](($screen.Height - $resultsHeight) / 2)
)
$form.Size = New-Object System.Drawing.Size($resultsWidth, $resultsHeight)
$form.Region = New-Object System.Drawing.Region((New-RoundedRegion -Width $form.Width -Height $form.Height -Radius 14))
$accent.Size = New-Object System.Drawing.Size($form.Width, 4)
$closeBtn.Location = New-Object System.Drawing.Point(($form.Width - 36), 12)

# hide progress-only controls
$fileLabel.Visible = $false
$track.Visible = $false
$percentLabel.Visible = $false

# repurpose the subtitle as the results summary line
if ($results.Count -gt 0) {
    $subLabel.Text = "$($results.Count) unique username(s) found"
    $subLabel.ForeColor = $colorGreen
} else {
    $subLabel.Text = "No usernames found."
    $subLabel.ForeColor = $colorSubtext
}
$subLabel.Size = New-Object System.Drawing.Size(500, 18)

if ($results.Count -gt 0) {

    # filter box
    $filterLabel = New-Object System.Windows.Forms.Label
    $filterLabel.Text = "Filter:"
    $filterLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $filterLabel.ForeColor = $colorSubtext
    $filterLabel.AutoSize = $true
    $filterLabel.Location = New-Object System.Drawing.Point(24, 80)
    $form.Controls.Add($filterLabel)

    $filterBox = New-Object System.Windows.Forms.TextBox
    $filterBox.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $filterBox.BackColor = $colorTrack
    $filterBox.ForeColor = $colorText
    $filterBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $filterBox.Size = New-Object System.Drawing.Size(300, 22)
    $filterBox.Location = New-Object System.Drawing.Point(70, 77)
    $filterBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
    $form.Controls.Add($filterBox)

    # build the backing data table
    $dataTable = New-Object System.Data.DataTable
    [void]$dataTable.Columns.Add("Username")
    [void]$dataTable.Columns.Add("Path")
    foreach ($r in $results) {
        [void]$dataTable.Rows.Add($r.Username, $r.Path)
    }

    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Location = New-Object System.Drawing.Point(24, 110)
    $dgv.Size = New-Object System.Drawing.Size(($form.Width - 48), ($form.Height - 170))
    $dgv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $dgv.BackgroundColor = $colorBg
    $dgv.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $dgv.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::None
    $dgv.RowHeadersVisible = $false
    $dgv.AllowUserToAddRows = $false
    $dgv.AllowUserToDeleteRows = $false
    $dgv.AllowUserToResizeRows = $false
    $dgv.ReadOnly = $true
    $dgv.MultiSelect = $false
    $dgv.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $dgv.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $dgv.GridColor = $colorBorder
    $dgv.EnableHeadersVisualStyles = $false
    $dgv.ColumnHeadersHeight = 34
    $dgv.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::None
    $dgv.ColumnHeadersDefaultCellStyle.BackColor = $colorPanel
    $dgv.ColumnHeadersDefaultCellStyle.ForeColor = $colorGreen
    $dgv.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $dgv.ColumnHeadersDefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    $dgv.RowTemplate.Height = 28
    $dgv.DefaultCellStyle.BackColor = $colorBg
    $dgv.DefaultCellStyle.ForeColor = $colorText
    $dgv.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $dgv.DefaultCellStyle.SelectionForeColor = $colorText
    $dgv.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(4, 4, 4, 4)
    $dgv.AlternatingRowsDefaultCellStyle.BackColor = $colorTrack
    $dgv.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $dgv.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing

    $dgv.DataSource = $dataTable.DefaultView
    $dgv.Columns["Username"].HeaderText = "Username"
    $dgv.Columns["Username"].FillWeight = 35
    $dgv.Columns["Username"].DefaultCellStyle.ForeColor = $colorPinkLt
    $dgv.Columns["Username"].DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $dgv.Columns["Path"].HeaderText = "Log Path"
    $dgv.Columns["Path"].FillWeight = 65
    $dgv.Columns["Path"].DefaultCellStyle.ForeColor = $colorBlue

    $form.Controls.Add($dgv)
    $dgv.BringToFront()
    $closeBtn.BringToFront()

    # double-click a row to copy its path to the clipboard
    $dgv.Add_CellDoubleClick({
        param($s, $e)
        if ($e.RowIndex -ge 0) {
            $path = $dgv.Rows[$e.RowIndex].Cells["Path"].Value
            if ($path) {
                [System.Windows.Forms.Clipboard]::SetText($path)
                $subLabel.Text = "Path copied to clipboard."
                $subLabel.ForeColor = $colorGreen
            }
        }
    })

    $filterBox.Add_TextChanged({
        $term = $filterBox.Text.Replace("'", "''")
        if ([string]::IsNullOrWhiteSpace($term)) {
            $dataTable.DefaultView.RowFilter = ""
        } else {
            $dataTable.DefaultView.RowFilter = "Username LIKE '%$term%' OR Path LIKE '%$term%'"
        }
    })
}

$form.ResumeLayout()
$form.Refresh()

[System.Windows.Forms.Application]::Run($form)
