Write-Host "Running Services.ps1..." -ForegroundColor Cyan

Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/main/Services.ps1')

$choice = Read-Host "`nRun DoomsDayDetector.ps1? (Y/N)"

if ($choice -match '^[Yy]$') {
    Write-Host "Running DoomsDayDetector.ps1..." -ForegroundColor Cyan
    Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/main/DoomsDayDetector.ps1')
}
else {
    Write-Host "DoomsDayDetector skipped." -ForegroundColor Yellow
}

Write-Host "`nDone." -ForegroundColor Green
