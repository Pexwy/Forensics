Clear-Host

while ($true) {
    Write-Host ""
    Write-Host "========== FORENSICS SCANNER ==========" -ForegroundColor Cyan
    Write-Host "1 - Services"
    Write-Host "2 - DoomsDayDetector"
    Write-Host "0 - Exit"
    Write-Host ""

    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1" {
            Clear-Host
            Write-Host "Running Services..." -ForegroundColor Green
            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/main/Services.ps1')
        }

        "2" {
            Clear-Host
            Write-Host "Running DoomsDayDetector..." -ForegroundColor Green
            Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Pexwy/Forensics/main/DoomsDayDetector.ps1')
        }

        "0" {
            Write-Host "Exiting..."
            break
        }

        default {
            Write-Host "Invalid option." -ForegroundColor Red
        }
    }

    Write-Host ""
    Read-Host "Press Enter to return to the menu"
    Clear-Host
}
