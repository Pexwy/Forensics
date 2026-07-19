function Show-Menu {
    Clear-Host

    Write-Host ""
    Write-Host "========================================================" -ForegroundColor DarkCyan
    Write-Host "                PEXWY FORENSICS SCANNER" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  [1] Services" -ForegroundColor White
    Write-Host "  [2] DoomsDay Detector" -ForegroundColor White
    Write-Host "  [3] Tools Collector [MINECRAFT]" -ForegroundColor White
    Write-Host "  [4] Alt-Detector" -ForegroundColor White
    Write-Host ""
    Write-Host "  [0] Exit" -ForegroundColor DarkGray
    Write-Host ""
}

while ($true) {

    Show-Menu

    $choice = Read-Host "Select an option"

    switch ($choice) {

        "1" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching Services..." -ForegroundColor Green
            Write-Host ""

            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/Services.ps1')

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }

        "2" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching DoomsDay Detector..." -ForegroundColor Green
            Write-Host ""

            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/DoomsDayDetector.ps1')

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }

        "3" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching Tools Collector [MINECRAFT]..." -ForegroundColor Green
            Write-Host ""

            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/Tools%20Collector.ps1')

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }
        

        "4" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching Alt-Detecor..." -ForegroundColor Green
            Write-Host ""

            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/Alt-Detector.ps1')

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }

        "0" {
            Clear-Host
            Write-Host ""
            Write-Host "Thank you for using Pexwy Forensics Scanner!" -ForegroundColor Cyan
            Start-Sleep 1
            break
        }

        default {
            Write-Host ""
            Write-Host "[!] Invalid selection." -ForegroundColor Red
            Start-Sleep 1.5
        }
    }
}
