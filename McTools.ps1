# =======================
# TOOLS COLLECTOR
# =======================


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

cls
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "          TOOLS COLLECTOR            " -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " Made By Java | Ported from Unknown <3  " -ForegroundColor DarkGray
Write-Host ""


if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host "Restarting as administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList `
        "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    exit 0
}


$root = "C:\"
$name = "SS"
$i = 1
while (Test-Path "$root$name$i") { $i++ }
$folder = "$root$name$i"

New-Item -Path $folder -ItemType Directory -Force | Out-Null
Set-Location $folder
Write-Host "[+] Created folder: $folder" -ForegroundColor Cyan


function Add-DefenderExclusion {
    Write-Host "[*] Adding Windows Defender exclusion..." -ForegroundColor Cyan
    try {
        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            $prefs = (Get-MpPreference).ExclusionPath
            if ($prefs -notcontains $folder) {
                Add-MpPreference -ExclusionPath $folder
                Write-Host "[✓] Defender exclusion added" -ForegroundColor Green
            }
            return
        }
    } catch {}

    try {
        $reg = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
        if (Test-Path $reg) {
            New-ItemProperty -Path $reg -Name $folder -Value 0 -PropertyType DWORD -Force | Out-Null
            Write-Host "[✓] Defender exclusion added (registry)" -ForegroundColor Green
            return
        }
    } catch {}

    Write-Host "[!] Could not add Defender exclusion" -ForegroundColor Yellow
}
Add-DefenderExclusion


Add-Type -AssemblyName System.IO.Compression.FileSystem


function Download-File {
    param ([string]$Url)

    $fileName = Split-Path $Url -Leaf
    $dest = Join-Path $folder $fileName

    try {
        Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing
        Write-Host "[✓] Downloaded: $fileName" -ForegroundColor Green

        if ($fileName.ToLower().EndsWith(".zip")) {
            $outDir = Join-Path $folder ([IO.Path]::GetFileNameWithoutExtension($fileName))
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            [System.IO.Compression.ZipFile]::ExtractToDirectory($dest, $outDir, $true)
            Remove-Item $dest -Force
            Write-Host "    Extracted → $outDir" -ForegroundColor DarkCyan
        }
    }
    catch {
        Write-Host "[✗] Failed: $fileName" -ForegroundColor Red
    }
}

# -----------------------
# URLs
# -----------------------
$urls = @(
    'https://github.com/spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe',
    'https://github.com/spokwn/Tool/releases/download/v1.1.3/espouken.exe',
    'https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe',
    'https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe',
    'https://github.com/spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe',
    'https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe',
    'https://www.nirsoft.net/utils/winprefetchview-x64.zip',
    'https://github.com/winsiderss/si-builds/releases/download/3.2.25275.112/systeminformer-build-canary-setup.exe',
    'https://www.nirsoft.net/utils/usbdeview-x64.zip',
    'https://www.nirsoft.net/utils/networkusageview-x64.zip',
    'https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe',
    'https://github.com/Yamato-Security/hayabusa/releases/download/v3.6.0/hayabusa-3.6.0-win-x64.zip',
    'https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip',
    'https://www.nirsoft.net/utils/usbdrivelog.zip',
    'https://www.voidtools.com/Everything-1.4.1.1029.x64-Setup.exe',
    'https://www.nirsoft.net/utils/previousfilesrecovery-x64.zip',
    'https://github.com/Col-E/Recaf/releases/download/2.21.14/recaf-2.21.14-J8-jar-with-dependencies.jar',
    'https://github.com/Orbdiff/InjGen/releases/download/fork/InjGen.exe',
    'https://github.com/ItzIceHere/RedLotus-Mod-Analyzer/releases/download/RL/RedLotusModAnalyzer.exe',
    'https://github.com/RedLotus-Development/White-Lotus-Scanner/releases/download/forensics/WhiteLotus.exe',
    'https://download.ericzimmermanstools.com/net9/MFTECmd.zip',
    'https://download.ericzimmermanstools.com/net9/MFTExplorer.zip',
    'https://github.com/zedoonvm1/TasksParser/releases/download/1.1/Tasks.Parser.exe',
    'https://download.ericzimmermanstools.com/net9/PECmd.zip',
    'https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip',
    'https://github.com/Orbdiff/Fileless/releases/download/v1.1/Fileless.exe',
    'https://github.com/txvch/Screenshare-Collector/releases/download/tech/Technical.Utilities.exe',
    'https://github.com/ItzIceHere/RedLotusAltChecker/releases/download/RL/RedLotusAltChecker.exe',
    'https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.3/PrefetchView++.exe',
    'https://github.com/MeowTonynoh/MeowDoomsdayFucker/releases/download/V.1.1/MeowDoomsdayFucker.exe',
    'https://dl.echo.ac/tool/journal',
    'https://github.com/kacos2000/Win10LiveInfo/releases/download/v.1.0.23.0/WinLiveInfo.exe',
    'https://www.nirsoft.net/utils/regscanner.html',
    'https://github.com/moaistory/WinSearchDBAnalyzer/releases/download/1.0.0.6/WinSearchDBAnalyzer.exe',
    'https://www.nirsoft.net/utils/appaudioconfig-x64.zip',
    'https://github.com/zodiacon/AllTools/raw/master/NtfsStreams.zip',
    'https://api.anticheat.ac/dl/cli',
    'https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe',
    'https://github.com/Orbdiff/DPS-Analyzer',
    'https://github.com/Orbdiff/BAMReveal/releases/download/v1.3/BAMReveal.exe',
    'https://github.com/Orbdiff/CheckDeletedUSN/releases/download/v0.2.1/CheckDeletedUSN.exe',
    'https://github.com/Orbdiff/BAM-CheckRestart/releases/download/v2.0.2/BAMCheckRestart.exe'
    )


$counter = 0
$total = $urls.Count

foreach ($url in $urls) {
    $counter++
    Write-Host "`n[$counter/$total] $(Split-Path $url -Leaf)" -ForegroundColor Cyan
    Download-File $url
}

Start-Process explorer.exe $folder
Write-Host "`n[✓] Finished" -ForegroundColor Green
