$startPath = "C:\Users"

if (-not (Test-Path $startPath)) {
    exit
}

Write-Host "Finding usernames, It may take a few minutes..." -ForegroundColor Cyan

$gzFiles = Get-ChildItem -Path $startPath -Recurse -Filter "*.gz" -File -Force -ErrorAction SilentlyContinue
$logFiles = Get-ChildItem -Path $startPath -Recurse -Filter "*.log" -File -Force -ErrorAction SilentlyContinue
$allFiles = @($gzFiles) + @($logFiles)

$results = @()
$seenUsers = @{}

foreach ($file in $allFiles) {
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
                    "Usernames" = $username
                    "Path" = $file.FullName
                }
            }
        }
    }
    catch {
        continue
    }
}

if ($results.Count -gt 0) {

    # Build HTML rows
    $rows = ""
    foreach ($r in $results) {
        $rows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($r.Usernames))</td><td>$([System.Net.WebUtility]::HtmlEncode($r.Path))</td></tr>`n"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Alt-Detector Results</title>
<style>
    body {
        background: #1e1e1e;
        color: #ddd;
        font-family: Segoe UI, Arial, sans-serif;
        padding: 30px;
    }
    h1 {
        color: #ff66ff;
        font-size: 22px;
        margin-bottom: 4px;
    }
    .subtitle {
        color: #999;
        margin-bottom: 20px;
        font-size: 13px;
    }
    table {
        border-collapse: collapse;
        width: 100%;
        box-shadow: 0 0 10px rgba(0,0,0,0.5);
    }
    th, td {
        padding: 10px 14px;
        text-align: left;
        border-bottom: 1px solid #333;
        font-size: 14px;
    }
    th {
        background: #2a2a2a;
        color: #66ff99;
        position: sticky;
        top: 0;
    }
    tr:nth-child(even) {
        background: #262626;
    }
    tr:hover {
        background: #333;
    }
    td:first-child {
        color: #ff99ff;
        font-weight: 600;
        white-space: nowrap;
    }
    td:last-child {
        color: #9fd3ff;
        word-break: break-all;
    }
</style>
</head>
<body>
    <h1>Alt-Detector Results</h1>
    <div class="subtitle">$($results.Count) unique username(s) found</div>
    <table>
        <thead>
            <tr><th>Username</th><th>Log Path</th></tr>
        </thead>
        <tbody>
            $rows
        </tbody>
    </table>
</body>
</html>
"@

    $outputPath = Join-Path $env:TEMP "AltDetectorResults.html"
    $html | Out-File -FilePath $outputPath -Encoding UTF8
    Start-Process $outputPath
}
else {
    Write-Host "No usernames found." -ForegroundColor Yellow
}
