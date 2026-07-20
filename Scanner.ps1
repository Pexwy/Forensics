function Show-Menu {
    Clear-Host

    Write-Host ""
    Write-Host "========================================================" -ForegroundColor DarkCyan
    Write-Host "                ScreenShare Scripts " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  [1] Services Status" -ForegroundColor White
    Write-Host "  [2] DoomsDay Detector" -ForegroundColor White
    Write-Host "  [3] Tools Collector [MINECRAFT]" -ForegroundColor White
    Write-Host "  [4] Alt Detector" -ForegroundColor White
    Write-Host "  [5] Mod Analyzer" -ForegroundColor White
    Write-Host "  [6] Services Manager" -ForegroundColor White
    Write-Host "  [7] Faker Detector" -ForegroundColor White
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
            Write-Host "[+] Launching Alt Detecor..." -ForegroundColor Green
            Write-Host ""

            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/Alt-Detector.ps1')

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }
        
                "5" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching Mod Analyzer..." -ForegroundColor Green
            Write-Host ""

            powershell -Command "Set-ExecutionPolicy Bypass -Scope Process; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/HadronCollision/PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1')"

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }
        
               "6" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching Services Manager..." -ForegroundColor Green
            Write-Host ""

            powershell -NoProfile -ExecutionPolicy Bypass -Command "iex (iwr 'https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/Faker%20Detector' -UseBasicParsing)"

            Write-Host ""
            Read-Host "Press ENTER to return to the menu"
        }
        
            "7" {
            Clear-Host
            Write-Host ""
            Write-Host "[+] Launching Faker Detector..." -ForegroundColor Green
            Write-Host ""

            irm "https://raw.githubusercontent.com/Pexwy/Forensics/refs/heads/main/Faker%20Detector" | iex
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
