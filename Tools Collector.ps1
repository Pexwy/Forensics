# Create the tools folder
$toolsFolder = "C:\tools"

if (!(Test-Path $toolsFolder)) {
    New-Item -ItemType Directory -Path $toolsFolder | Out-Null
    Write-Host "Created folder: $toolsFolder" -ForegroundColor Green
}
else {
    Write-Host "Folder already exists: $toolsFolder" -ForegroundColor Yellow
}

if (!(Test-Path $toolsFolder)) {
    New-Item -ItemType Directory -Path $toolsFolder | Out-Null
    Write-Host "Created folder: $toolsFolder" -ForegroundColor Green
} else {
    Write-Host "Folder already exists: $toolsFolder" -ForegroundColor Yellow
}

# Ask for confirmation
$response = Read-Host "Start downloading all tools? (Y/N)"

if ($response -notmatch '^[Yy]$') {
    Write-Host "Download cancelled."
    exit
}

# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# URLs
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
    'https://github.com/Orbdiff/DPS-Analyzer/releases/download/v1.1/dpsanalyzer.exe',
    'https://github.com/Orbdiff/BAMReveal/releases/download/v1.3/BAMReveal.exe',
    'https://github.com/Orbdiff/CheckDeletedUSN/releases/download/v0.2.1/CheckDeletedUSN.exe',
    'https://github.com/Orbdiff/BAM-CheckRestart/releases/download/v2.0.2/BAMCheckRestart.exe'
)

$total = $urls.Count

Write-Host ""
Write-Host "Downloading $total files..." -ForegroundColor Cyan
Write-Host ""

for ($i = 0; $i -lt $total; $i++) {

    $current = $i + 1
    $url = $urls[$i]

    try {
        $uri = [System.Uri]$url
        $fileName = [System.IO.Path]::GetFileName($uri.AbsolutePath)

        if ([string]::IsNullOrWhiteSpace($fileName)) {
            $fileName = "download_$current"
        }

        if ($fileName -notmatch '\.') {
            $fileName += ".html"
        }

        $destination = Join-Path $toolsFolder $fileName

        Write-Host "[$current/$total] Downloading $fileName..." -ForegroundColor Cyan

        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing

        Write-Host "[$current/$total] Complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[$current/$total] Failed: $fileName" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "        Download Finished!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Files saved to: $toolsFolder" -ForegroundColor Cyan
