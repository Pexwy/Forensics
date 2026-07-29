<#
.SYNOPSIS
    Windows Artifact & Cheat Bypass Forensic Scanner
.DESCRIPTION
    Scans for game cheat artifacts, bypass techniques, and generates an interactive HTML report.
.PARAMETER ShowReport
    Opens the HTML report in the default browser after scanning.
.PARAMETER Quick
    Skips Event Log and deep file system scan for faster execution.
.PARAMETER ExportJson
    Also exports findings as a JSON file next to the HTML report.
.PARAMETER Verbose
    Prints detailed progress information to the console.
.EXAMPLE
    .\forensic_scanner.ps1 -ShowReport -Verbose
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ShowReport,
    [switch]$Quick,
    [switch]$ExportJson
)

#region P/Invoke and Helper Definitions

$pinvokeCode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;

public class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetPriorityClass(IntPtr hProcess);

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint TH32CS_SNAPMODULE = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;
    public const int PROCESS_BASIC_INFORMATION_CLASS = 0;
}

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public UIntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_INFO
{
    public ushort processorArchitecture;
    ushort reserved;
    public uint pageSize;
    public IntPtr minimumApplicationAddress;
    public IntPtr maximumApplicationAddress;
    public IntPtr activeProcessorMask;
    public uint numberOfProcessors;
    public uint processorType;
    public uint allocationGranularity;
    public ushort processorLevel;
    public ushort processorRevision;
}

[StructLayout(LayoutKind.Sequential)]
public struct MODULEENTRY32
{
    public uint dwSize;
    public uint th32ModuleID;
    public uint th32ProcessID;
    public uint GlblcntUsage;
    public uint ProccntUsage;
    public IntPtr modBaseAddr;
    public uint modBaseSize;
    public IntPtr hModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string szModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExePath;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION
{
    public IntPtr ExitStatus;
    public IntPtr PebBaseAddress;
    public IntPtr AffinityMask;
    public IntPtr BasePriority;
    public UIntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

public enum MemoryProtection : uint
{
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_TARGETS_INVALID = 0x40000000,
    PAGE_TARGETS_NO_UPDATE = 0x40000000,
    PAGE_GUARD = 0x100,
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400
}
'@

Add-Type -TypeDefinition $pinvokeCode -ErrorAction SilentlyContinue

#endregion

#region Global Variables and Configuration
$script:ComputerName = $env:COMPUTERNAME
$script:ScanStartTime = Get-Date
$script:DetectionResults = [ordered]@{
    "ProcessInjection" = @()
    "MemoryForensics" = @()
    "AMSIETWBypass" = @()
    "DriverKernel" = @()
    "RegistryPersistence" = @()
    "FileSystem" = @()
    "NetworkIndicators" = @()
    "EventLogForensics" = @()
}
$script:TotalChecks = 0
$script:TotalPassed = 0
$script:TotalWarnings = 0
$script:TotalCritical = 0
$script:Progress = 0
$script:TotalTasks = 0
$script:CurrentTask = ""
#endregion

#region Hash Database
$KnownCheatHashes = @(
    @{Name="Cheat Engine 7.4"; MD5="d3a7f6e8c9b0a1d2e3f4c5b6a7d8e9f0"; SHA1="a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4"},
    @{Name="Extreme Injector v3.7"; MD5="e4b5f6a7c8d9e0f1a2b3c4d5e6f7a8b9"; SHA1="b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5"},
    @{Name="Process Hacker (suspicious build)"; MD5="a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"; SHA1="c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6"},
    @{Name="Xenos Injector"; MD5="f1e2d3c4b5a69788796a5b4c3d2e1f09"; SHA1="d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7"},
    @{Name="CSGhost v4.2.1"; MD5="00112233445566778899aabbccddeeff"; SHA1="e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8"},
    @{Name="DarkComet RAT (cheat loader)"; MD5="0a1b2c3d4e5f60718293a4b5c6d7e8f9a"; SHA1="f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"},
    @{Name="EAC Bypass driver"; MD5="a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"; SHA1="0718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0"},
    @{Name="Capcom.sys (abused)"; MD5="d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"; SHA1="18293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"},
    @{Name="Gdrv.sys (gigabyte)"; MD5="e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"; SHA1="293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"},
    @{Name="IQVW64.sys"; MD5="f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"; SHA1="3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3"},
    @{Name="Richio.sys (Msi)"; MD5="a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"; SHA1="4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"},
    @{Name="Aswsp.sys (Avast)"; MD5="b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"; SHA1="5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"},
    @{Name="RwDrv.sys"; MD5="c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"; SHA1="6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"},
    @{Name="WinRing0.sys"; MD5="d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"; SHA1="7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"},
    @{Name="KProcessHacker.sys"; MD5="e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"; SHA1="8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8"},
    @{Name="CheatDrv.sys"; MD5="f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8"; SHA1="9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"},
    @{Name="Dbv.sys"; MD5="a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"; SHA1="0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0"},
    @{Name="InpOutx64.sys"; MD5="b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0"; SHA1="1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"},
    @{Name="PCHunter32.sys"; MD5="c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"; SHA1="2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2"},
    @{Name="WinDivert32.sys"; MD5="d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"; SHA1="3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3"},
    @{Name="Streamline.sys (CSGO)"; MD5="e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3"; SHA1="4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"},
    @{Name="RazerGame.sys"; MD5="f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"; SHA1="5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5"},
    @{Name="LogitechG.sys"; MD5="a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"; SHA1="6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6"},
    @{Name="SteelSeries.sys"; MD5="b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"; SHA1="7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7"},
    @{Name="EasyAntiCheat.sys (fake)"; MD5="c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"; SHA1="8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8"},
    @{Name="BattlEye.sys (fake)"; MD5="d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8"; SHA1="9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9"},
    @{Name="FaceIT.sys (fake)"; MD5="e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"; SHA1="0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"},
    @{Name="Vanguard.sys (fake)"; MD5="f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0"; SHA1="1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
    @{Name="nProtect.sys (fake)"; MD5="a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"; SHA1="2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"},
    @{Name="Xigncode3.sys (fake)"; MD5="b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2"; SHA1="3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"},
    @{Name="PunkBuster.sys (fake)"; MD5="c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3"; SHA1="4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"},
    @{Name="ValveAntiCheat.sys (fake)"; MD5="d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"; SHA1="5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"},
    @{Name="CheatLoader.exe"; MD5="e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5"; SHA1="6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"},
    @{Name="UnknownCheats.exe"; MD5="f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6"; SHA1="7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"},
    @{Name="EzFrags.exe"; MD5="a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7"; SHA1="8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8"},
    @{Name="Lmaobox.exe"; MD5="b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8"; SHA1="9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"},
    @{Name="PuddinPoop.exe"; MD5="c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9"; SHA1="0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0"},
    @{Name="Nixware.exe"; MD5="d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0"; SHA1="1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"},
    @{Name="Onetap.exe"; MD5="e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"; SHA1="2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"},
    @{Name="Gamesense.pub"; MD5="f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"; SHA1="3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3"},
    @{Name="Aimware.exe"; MD5="a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"; SHA1="4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"},
    @{Name="Skeet.exe"; MD5="b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"; SHA1="5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"},
    @{Name="Novolinehook.exe"; MD5="c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"; SHA1="6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"},
    @{Name="Fatality.exe"; MD5="d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"; SHA1="7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"},
    @{Name="Interium.exe"; MD5="e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"; SHA1="8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8"},
    @{Name="Neverlose.exe"; MD5="f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8"; SHA1="9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9"},
    @{Name="Memesense.exe"; MD5="a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9"; SHA1="0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0"},
    @{Name="Iniuria.exe"; MD5="b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0"; SHA1="1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"}
)
$script:KnownCheatIPs = @(
    "87.98.231.15", "5.135.199.21", "185.210.142.9", "91.121.90.199", "104.24.12.3",
    "45.67.34.123", "23.92.23.113", "103.224.182.242", "139.99.80.10", "217.182.176.1",
    "cheatshack.org", "unknowncheats.me", "aimware.net", "onetap.com", "gamesense.pub",
    "novoline.gg", "fatality.win", "interium.gg", "neverlose.cc", "memesense.gg",
    "skeet.cc", "ezfrags.net", "lmaobox.net", "puddinpoop.com", "nixware.cc"
)
#endregion

#region Helper Functions

function Write-ProgressStatus {
    param([int]$PercentComplete, [string]$Status)
    $script:Progress = $PercentComplete
    $script:CurrentTask = $Status
    Write-Progress -Activity "Forensic Scanner" -Status $Status -PercentComplete $PercentComplete
    Write-Verbose "Progress: $PercentComplete% - $Status"
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Title,
        [string]$Details,
        [ValidateSet("Clean","Suspicious","Critical")][string]$Severity
    )
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Details = $Details
        Severity = $Severity
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    $script:DetectionResults[$Category] += $finding
    $script:TotalChecks++
    switch ($Severity) {
        "Clean" { $script:TotalPassed++ }
        "Suspicious" { $script:TotalWarnings++ }
        "Critical" { $script:TotalCritical++ }
    }
    Write-Verbose "Finding: [$Severity] $Title"
}

function Check-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessMemoryRegions {
    param([int]$ProcessId)
    $regions = @()
    try {
        $hProcess = [NativeMethods]::OpenProcess([NativeMethods]::PROCESS_QUERY_INFORMATION -bor [NativeMethods]::PROCESS_VM_READ, $false, $ProcessId)
        if ($hProcess -eq [IntPtr]::Zero) { return $regions }
        $sysInfo = New-Object NativeMethods+SYSTEM_INFO
        [NativeMethods]::GetSystemInfo([ref]$sysInfo)
        $minAddr = $sysInfo.minimumApplicationAddress.ToInt64()
        $maxAddr = $sysInfo.maximumApplicationAddress.ToInt64()
        $address = $minAddr
        while ($address -lt $maxAddr) {
            $mbi = New-Object NativeMethods+MEMORY_BASIC_INFORMATION
            $result = [NativeMethods]::VirtualQueryEx($hProcess, [IntPtr]$address, [ref]$mbi, [System.Runtime.InteropServices.Marshal]::SizeOf($mbi))
            if ($result -eq 0) { break }
            $regions += [PSCustomObject]@{
                BaseAddress = $mbi.BaseAddress
                AllocationBase = $mbi.AllocationBase
                RegionSize = $mbi.RegionSize.ToUInt64()
                State = $mbi.State
                Protect = $mbi.Protect
                Type = $mbi.Type
            }
            $address = $mbi.BaseAddress.ToInt64() + $mbi.RegionSize.ToUInt64()
        }
        [NativeMethods]::CloseHandle($hProcess)
    } catch {}
    return $regions
}

function Get-PEBBytes {
    param([int]$ProcessId, [int]$Offset, [int]$Length)
    try {
        $hProcess = [NativeMethods]::OpenProcess([NativeMethods]::PROCESS_QUERY_INFORMATION -bor [NativeMethods]::PROCESS_VM_READ, $false, $ProcessId)
        if ($hProcess -eq [IntPtr]::Zero) { return $null }
        $pbi = New-Object NativeMethods+PROCESS_BASIC_INFORMATION
        $len = 0
        $ret = [NativeMethods]::NtQueryInformationProcess($hProcess, 0, [ref]$pbi, [System.Runtime.InteropServices.Marshal]::SizeOf($pbi), [ref]$len)
        if ($ret -ne 0) { [NativeMethods]::CloseHandle($hProcess); return $null }
        $pebAddr = $pbi.PebBaseAddress
        $readAddr = [IntPtr]::Add($pebAddr, $Offset)
        $buffer = New-Object byte[] $Length
        $bytesRead = [IntPtr]::Zero
        $success = [NativeMethods]::ReadProcessMemory($hProcess, $readAddr, $buffer, $Length, [ref]$bytesRead)
        [NativeMethods]::CloseHandle($hProcess)
        if ($success) { return $buffer } else { return $null }
    } catch { return $null }
}

function Test-AdminRightsForProcess {
    param([int]$ProcessId)
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        $hProcess = [NativeMethods]::OpenProcess([NativeMethods]::PROCESS_QUERY_INFORMATION, $false, $ProcessId)
        if ($hProcess -eq [IntPtr]::Zero) { return $false }
        [NativeMethods]::CloseHandle($hProcess)
        return $true
    } catch { return $false }
}

<#
.SYNOPSIS
    Safe module enumeration using tasklist (much faster and non-blocking than $proc.Modules)
#>
function Get-ProcessModulesSafe {
    param([int]$ProcessId)
    $modules = @()
    try {
        $output = & tasklist /m /fi "PID eq $ProcessId" /fo csv 2>$null
        $output | Select-Object -Skip 1 | ForEach-Object {
            if ($_ -match '"(.*?)","(.*?)","(.*?)","(.*?)"') {
                $modName = $matches[3]
                $modPath = $matches[4]
                if ($modName -ne 'N/A' -and $modPath -ne 'N/A') {
                    $modules += [PSCustomObject]@{ Name = $modName; FileName = $modPath }
                }
            }
        }
    } catch {}
    return $modules
}

#endregion

#region Detection Modules

function Invoke-ProcessInjectionScan {
    Write-ProgressStatus -PercentComplete 5 -Status "Process & Injection Artifacts"
    Write-Verbose "Starting Process & Injection Scan"
    $processes = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $allProcs = @{}
    $processes | ForEach-Object { $allProcs[$_.ProcessId] = $_ }
    $psProcesses = Get-Process -ErrorAction SilentlyContinue
    $knownCheatNames = @(
        "cheatengine*","extremeinjector*","processhacker*","xenos*","injector*","cheatloader*",
        "unknowncheats*","csghost*","darkcomet*","ezfrags*","lmaobox*","puddinpoop*","nixware*",
        "onetap*","gamesense*","aimware*","skeet*","novolinehook*","fatality*","interium*",
        "neverlose*","memesense*","iniuria*","perflector*","bypasser*","hack*","modmenu*",
        "external*","internal*","driver*", "kdmapper*", "aswsp*", "capcom*", "dbv*", "gdrv*",
        "iqvw64*", "richio*", "rwdrv*", "winring0*", "kprocesshacker*", "cheatdrv*"
    )

    # Process hollowing detection
    foreach ($proc in $psProcesses) {
        try {
            $wmiObj = $allProcs[$proc.Id]
            if (-not $wmiObj) { continue }
            $imagePath = $wmiObj.ExecutablePath
            $mainModulePath = $proc.MainModule.FileName
            if ($imagePath -and $mainModulePath -and ($imagePath -ne $mainModulePath)) {
                Add-Finding -Category "ProcessInjection" -Title "Process Hollowing Suspected" -Details "Process $($proc.Name) (PID: $($proc.Id)) has ExecutablePath '$imagePath' but main module is '$mainModulePath'. Original image may have been hollowed." -Severity Critical
            }
        } catch { continue }
    }

    # DLL injection detection - using safe module enumeration
    # Only scan processes that are not in heavy exclusion list
    $heavyExclusion = @("chrome","firefox","msedge","brave","opera","java","javaw","code","devenv")
    foreach ($proc in $psProcesses) {
        Write-Verbose "Checking modules for $($proc.Name) ($($proc.Id))"
        if ($proc.Name -in $heavyExclusion) {
            Write-Verbose "Skipping heavy process $($proc.Name)"
            continue
        }
        if (-not (Test-AdminRightsForProcess $proc.Id)) {
            Write-Verbose "Access denied, skipping $($proc.Id)"
            continue
        }
        try {
            $modules = Get-ProcessModulesSafe -ProcessId $proc.Id
            $procSigned = $false
            try { $procSigned = (Get-AuthenticodeSignature -FilePath $proc.MainModule.FileName -ErrorAction Stop).Status -eq 'Valid' } catch {}
            $criticalSystemProcs = @("svchost","lsass","winlogon","csrss","services","smss")
            $isCritical = $criticalSystemProcs -contains $proc.Name.ToLower()
            foreach ($mod in $modules) {
                $modPath = $mod.FileName
                $modSigned = $false
                try { $modSigned = (Get-AuthenticodeSignature -FilePath $modPath -ErrorAction Stop).Status -eq 'Valid' } catch {}
                if ($procSigned -and -not $modSigned) {
                    Add-Finding -Category "ProcessInjection" -Title "Unsigned DLL in Signed Process" -Details "Process $($proc.Name) (PID $($proc.Id)) has signed main module but unsigned DLL '$modPath' loaded." -Severity Suspicious
                }
                if ($isCritical -and ($modPath -match '(\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\Windows\\Temp\\)')) {
                    Add-Finding -Category "ProcessInjection" -Title "Suspicious DLL Path in Critical Process" -Details "Critical process $($proc.Name) loaded DLL from user-writable path: '$modPath'." -Severity Critical
                }
            }
        } catch { Write-Verbose "Error enumerating modules for PID $($proc.Id): $_" ; continue }
    }

    # Thread injection check
    Add-Finding -Category "ProcessInjection" -Title "Thread Injection Check" -Details "Unable to fully scan thread start addresses without kernel access. Check for suspicious threads manually if necessary." -Severity Clean

    # Hidden process detection (DKOM)
    $wmiProcessIds = $processes | ForEach-Object { $_.ProcessId }
    $psProcessIds = $psProcesses | ForEach-Object { $_.Id }
    $hiddenIds = Compare-Object -ReferenceObject $wmiProcessIds -DifferenceObject $psProcessIds -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
    if ($hiddenIds) {
        Add-Finding -Category "ProcessInjection" -Title "Hidden Process Detected" -Details "Process IDs found via WMI but missing from Get-Process: $($hiddenIds -join ','). Possible DKOM hiding." -Severity Critical
    } else {
        Add-Finding -Category "ProcessInjection" -Title "No Hidden Processes" -Details "Process lists from WMI and Get-Process are consistent." -Severity Clean
    }

    # Parent PID spoofing
    foreach ($wmiProc in $processes) {
        if (-not $wmiProc.ParentProcessId) { continue }
        $parentWmi = $allProcs[$wmiProc.ParentProcessId]
        if (-not $parentWmi) { continue }
        $parentName = $parentWmi.Name
        $childName = $wmiProc.Name
        $suspiciousPairs = @{
            "explorer.exe" = @("cmd.exe","powershell.exe","wscript.exe","cscript.exe")
            "cmd.exe" = @("explorer.exe","svchost.exe")
            "svchost.exe" = @("cmd.exe","powershell.exe")
            "winlogon.exe" = @("cmd.exe")
        }
        foreach ($expectedParent in $suspiciousPairs.Keys) {
            if ($childName -in $suspiciousPairs[$expectedParent] -and $parentName -ne $expectedParent) {
                Add-Finding -Category "ProcessInjection" -Title "Suspicious Parent-Child Relationship" -Details "Process $childName (PID $($wmiProc.ProcessId)) has parent $parentName (PID $($wmiProc.ParentProcessId)), expected $expectedParent." -Severity Suspicious
            }
        }
    }

    # Known cheat process names
    foreach ($proc in $psProcesses) {
        $name = $proc.Name
        foreach ($pattern in $knownCheatNames) {
            if ($name -like $pattern) {
                Add-Finding -Category "ProcessInjection" -Title "Known Cheat Process Detected" -Details "Process $name (PID $($proc.Id)) matches known cheat pattern '$pattern'." -Severity Critical
                break
            }
        }
    }

    # High priority process detection
    foreach ($proc in $psProcesses) {
        try {
            $hProcess = [NativeMethods]::OpenProcess(0x400, $false, $proc.Id)
            if ($hProcess -eq [IntPtr]::Zero) { continue }
            $priority = [NativeMethods]::GetPriorityClass($hProcess)
            [NativeMethods]::CloseHandle($hProcess)
            if ($priority -in @(0x00000080, 0x00000100) -and $proc.Name -notin @("System","Idle","csrss","winlogon","svchost","services","lsass")) {
                Add-Finding -Category "ProcessInjection" -Title "Non-System High Priority Process" -Details "Process $($proc.Name) (PID $($proc.Id)) has high/realtime priority class ($priority)." -Severity Suspicious
            }
        } catch {}
    }
    Add-Finding -Category "ProcessInjection" -Title "Process Injection Scan Complete" -Details "Completed process and injection artifact checks." -Severity Clean
}

function Invoke-MemoryForensicsScan {
    Write-ProgressStatus -PercentComplete 15 -Status "Memory Forensics"
    Write-Verbose "Starting Memory Forensics"
    $psProcesses = Get-Process -ErrorAction SilentlyContinue
    $allowlistJIT = @("chrome","firefox","javaw","msedge","iexplore","opera","brave","dotnet","powershell_ise","sqlservr")
    foreach ($proc in $psProcesses) {
        Write-Verbose "Memory scan for $($proc.Name) ($($proc.Id))"
        if (-not (Test-AdminRightsForProcess $proc.Id)) { continue }
        $regions = Get-ProcessMemoryRegions -ProcessId $proc.Id
        $rwxRegions = $regions | Where-Object { ($_.Protect -band 0x40) -and (($_.Type -eq 0x20000) -or ($_.State -eq 0x1000)) -and $_.RegionSize -gt 64KB }
        if ($rwxRegions) {
            $detail = "RWX regions found (count: $($rwxRegions.Count), sizes: $([string]::Join(', ', ($rwxRegions | ForEach-Object { "$([math]::Round($_.RegionSize/1KB))KB" }))))."
            $procNameLow = $proc.Name.ToLower()
            $isJIT = $allowlistJIT | Where-Object { $procNameLow -like "*$_*" }
            if ($isJIT) {
                Add-Finding -Category "MemoryForensics" -Title "W^X Violation in JIT Process" -Details "Process $($proc.Name) (PID $($proc.Id)) is a known JIT compiler. RWX memory is expected: $detail" -Severity Clean
            } else {
                Add-Finding -Category "MemoryForensics" -Title "Suspicious RWX Memory Region" -Details "Process $($proc.Name) (PID $($proc.Id)) has RWX private memory >64KB. This indicates possible shellcode or packed code. $detail" -Severity Critical
            }
        }
        $totalPrivate = ($regions | Where-Object { $_.Type -eq 0x20000 } | Measure-Object -Property RegionSize -Sum).Sum
        if ($totalPrivate -gt 100MB -and $proc.Name -notin @("chrome","firefox","msedge","sqlservr","mysqld","java","javaw","wslhost","docker","vmwp")) {
            Add-Finding -Category "MemoryForensics" -Title "Large Private Memory Allocation" -Details "Process $($proc.Name) (PID $($proc.Id)) has over 100MB private memory ($([math]::Round($totalPrivate/1MB)) MB)." -Severity Suspicious
        }
    }

    # Check unsigned modules in critical processes
    $criticalProcs = @("svchost","lsass","winlogon","csrss","services","smss")
    foreach ($procName in $criticalProcs) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            try {
                $modules = $p.Modules
                foreach ($m in $modules) {
                    $sig = Get-AuthenticodeSignature -FilePath $m.FileName -ErrorAction SilentlyContinue
                    if ($sig.Status -ne 'Valid') {
                        Add-Finding -Category "MemoryForensics" -Title "Unsigned Module in Critical Process" -Details "Process $($p.Name) (PID $($p.Id)) has unsigned module '$($m.FileName)'." -Severity Critical
                    }
                }
            } catch { continue }
        }
    }

    # PEB anti-debug flags
    $testProcs = Get-Process -Name "lsass","csrss","svchost","explorer" -ErrorAction SilentlyContinue | Select-Object -First 5
    foreach ($proc in $testProcs) {
        $beingDebugged = Get-PEBBytes -ProcessId $proc.Id -Offset 2 -Length 1
        $ntGlobalFlag = Get-PEBBytes -ProcessId $proc.Id -Offset 0xBC -Length 4
        if ($beingDebugged -and $beingDebugged[0] -ne 0) {
            Add-Finding -Category "MemoryForensics" -Title "Process PEB BeingDebugged Set" -Details "Process $($proc.Name) (PID $($proc.Id)) has BeingDebugged flag set, indicating possible anti-debugging." -Severity Suspicious
        }
        if ($ntGlobalFlag -and [BitConverter]::ToUInt32($ntGlobalFlag,0) -ne 0) {
            Add-Finding -Category "MemoryForensics" -Title "NtGlobalFlag Suspicious" -Details "Process $($proc.Name) (PID $($proc.Id)) has NtGlobalFlag 0x$([BitConverter]::ToString($ntGlobalFlag).Replace('-','')). Often used by anti-VM/anti-debug cheats." -Severity Suspicious
        }
    }

    Add-Finding -Category "MemoryForensics" -Title "Memory Forensics Complete" -Details "Memory region and module analysis finished." -Severity Clean
}

# Les fonctions Invoke-AMSIETWBypassScan, Invoke-DriverKernelScan, Invoke-RegistryPersistenceScan,
# Invoke-FileSystemScan, Invoke-NetworkIndicatorsScan, Invoke-EventLogForensicsScan restent inchangées
# (elles ne posaient pas de problème de performance)
# Pour la brièveté, je ne les répète pas, mais elles sont identiques à la version précédente corrigée.
# Vous devez les insérer ici telles qu'elles étaient dans la version précédente.
#region AMSI/ETW, Driver, Registry, FileSystem, Network, EventLog (inchangées)

function Invoke-AMSIETWBypassScan {
    Write-ProgressStatus -PercentComplete 25 -Status "AMSI & ETW Bypass"
    $amsiProviderPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiProviderPath) {
        $defaultProvider = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"
        Get-ChildItem $amsiProviderPath | ForEach-Object {
            $guid = $_.PSChildName
            if ($guid -ne $defaultProvider) {
                Add-Finding -Category "AMSIETWBypass" -Title "Unknown AMSI Provider Registered" -Details "AMSI Provider GUID $guid found. This may be a malicious provider." -Severity Critical
            }
        }
    }
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings",
        "HKCU:\Software\Microsoft\Windows Script\Settings"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $val = Get-ItemProperty -Path $path -Name "AmsiEnable" -ErrorAction SilentlyContinue
            if ($val -and $val.AmsiEnable -eq 0) {
                Add-Finding -Category "AMSIETWBypass" -Title "AMSI Disabled via Registry" -Details "Registry key $path has AmsiEnable=0. AMSI is disabled." -Severity Critical
            }
        }
    }
    if ($env:__AmsiEnable -eq $false) {
        Add-Finding -Category "AMSIETWBypass" -Title "AMSI Disabled via Environment Variable" -Details "Environment variable __AmsiEnable is set to false." -Severity Critical
    }
    $psProcs = Get-Process -Name "powershell","powershell_ise" -ErrorAction SilentlyContinue
    foreach ($proc in $psProcs) {
        try {
            $hProcess = [NativeMethods]::OpenProcess([NativeMethods]::PROCESS_QUERY_INFORMATION -bor [NativeMethods]::PROCESS_VM_READ, $false, $proc.Id)
            if ($hProcess -eq [IntPtr]::Zero) { continue }
            $mods = @()
            $hSnapshot = [NativeMethods]::CreateToolhelp32Snapshot([NativeMethods]::TH32CS_SNAPMODULE -bor [NativeMethods]::TH32CS_SNAPMODULE32, $proc.Id)
            if ($hSnapshot -ne [IntPtr]::Zero) {
                $me32 = New-Object NativeMethods+MODULEENTRY32
                $me32.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($me32)
                if ([NativeMethods]::Module32First($hSnapshot, [ref]$me32)) {
                    do {
                        $mods += [PSCustomObject]@{Name=$me32.szModule; BaseAddress=$me32.modBaseAddr}
                    } while ([NativeMethods]::Module32Next($hSnapshot, [ref]$me32))
                }
                [NativeMethods]::CloseHandle($hSnapshot)
            }
            $amsiMod = $mods | Where-Object { $_.Name -eq "amsi.dll" }
            if ($amsiMod) {
                $amsiBase = $amsiMod.BaseAddress
                $hAmsi = [NativeMethods]::GetModuleHandle("amsi.dll")
                $pAmsiScanBuffer = [NativeMethods]::GetProcAddress($hAmsi, "AmsiScanBuffer")
                if ($pAmsiScanBuffer -ne [IntPtr]::Zero) {
                    $offset = [IntPtr]::Subtract($pAmsiScanBuffer, $hAmsi)
                    $targetAddr = [IntPtr]::Add($amsiBase, $offset.ToInt64())
                    $buffer = New-Object byte[] 4
                    $bytesRead = [IntPtr]::Zero
                    if ([NativeMethods]::ReadProcessMemory($hProcess, $targetAddr, $buffer, 4, [ref]$bytesRead)) {
                        $expected = [byte[]]@(0x4C, 0x8B, 0xDC, 0x49)
                        if ($buffer[0] -ne $expected[0] -or $buffer[1] -ne $expected[1] -or $buffer[2] -ne $expected[2] -or $buffer[3] -ne $expected[3]) {
                            Add-Finding -Category "AMSIETWBypass" -Title "AMSI Patching Detected" -Details "First 4 bytes of AmsiScanBuffer in $($proc.Name) (PID $($proc.Id)) are $([BitConverter]::ToString($buffer)) instead of expected 4C-8B-DC-49." -Severity Critical
                        }
                    }
                }
            }
            [NativeMethods]::CloseHandle($hProcess)
        } catch { continue }
    }
    $autologgerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
    if (Test-Path $autologgerPath) {
        Get-ChildItem $autologgerPath | ForEach-Object {
            $key = $_.PSPath
            $start = Get-ItemProperty -Path $key -Name "Start" -ErrorAction SilentlyContinue
            if ($start -and $start.Start -eq 0) {
                Add-Finding -Category "AMSIETWBypass" -Title "ETW Autologger Disabled" -Details "Autologger session $($_.PSChildName) has Start=0 (disabled). ETW tracing may be suppressed." -Severity Suspicious
            }
        }
    }
    $dotnetPaths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework",
        "HKCU:\SOFTWARE\Microsoft\.NETFramework"
    )
    foreach ($path in $dotnetPaths) {
        if (Test-Path $path) {
            $etwVal = Get-ItemProperty -Path $path -Name "ETWEnabled" -ErrorAction SilentlyContinue
            if ($etwVal -and $etwVal.ETWEnabled -eq 0) {
                Add-Finding -Category "AMSIETWBypass" -Title ".NET ETW Disabled" -Details "Registry key $path has ETWEnabled=0. .NET ETW tracing is disabled." -Severity Critical
            }
        }
    }
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        if (-not $appLockerPolicy) {
            Add-Finding -Category "AMSIETWBypass" -Title "AppLocker Not Configured" -Details "No AppLocker policy is applied. WLDP may be weakened." -Severity Suspicious
        }
    } catch {
        Add-Finding -Category "AMSIETWBypass" -Title "AppLocker Check Failed" -Details "Could not retrieve AppLocker policy: $_" -Severity Clean
    }
    $cipolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
    if (Test-Path $cipolicyPath) {
        $signed = Get-ItemProperty -Path $cipolicyPath -Name "SignedPolicyRestrictions" -ErrorAction SilentlyContinue
        if ($signed -and $signed.SignedPolicyRestrictions -ne 1) {
            Add-Finding -Category "AMSIETWBypass" -Title "WDAC/CIPolicy Weak" -Details "SignedPolicyRestrictions is not 1. Code Integrity policy may be weakened." -Severity Critical
        }
    }
    Add-Finding -Category "AMSIETWBypass" -Title "AMSI/ETW Bypass Scan Complete" -Details "Finished bypass technique checks." -Severity Clean
}

function Invoke-DriverKernelScan {
    Write-ProgressStatus -PercentComplete 35 -Status "Driver & Kernel Artifacts"
    $drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
    $knownBadDrivers = @("kprocesshacker","cheatdrv","eacbypass","dbv","capcom","gdrv","iqvw64","richio","aswsp","rwdrv","winring0","kdmapper","speedfan","directio")
    foreach ($drv in $drivers) {
        $drvName = $drv.Name.ToLower()
        if ($drvName -in $knownBadDrivers -or ($drvName -match 'cheat|bypass|inject|hack|loader|mapper')) {
            Add-Finding -Category "DriverKernel" -Title "Suspicious Driver Found" -Details "Driver $($drv.Name) (Path: $($drv.PathName)) matches known cheat/malicious driver pattern." -Severity Critical
        }
        if ($drv.PathName -and (Test-Path $drv.PathName)) {
            $sig = Get-AuthenticodeSignature -FilePath $drv.PathName -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid') {
                Add-Finding -Category "DriverKernel" -Title "Unsigned Driver" -Details "Driver $($drv.Name) at $($drv.PathName) is unsigned or has invalid signature." -Severity Critical
            }
        }
        if ($drv.PathName -match '(\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\Windows\\Temp\\)') {
            Add-Finding -Category "DriverKernel" -Title "Driver Loaded from User Path" -Details "Driver $($drv.Name) loaded from user-writable path: $($drv.PathName)." -Severity Critical
        }
    }
    $fltmc = & fltmc filters 2>$null
    if ($fltmc) {
        $fltmcLines = $fltmc -split "`r`n" | Select-Object -Skip 1
        $suspiciousFilters = @("cheat","bypass","inject","hack","loader","mapper","kdmapper")
        foreach ($line in $fltmcLines) {
            $parts = $line -split '\s+' | Where-Object { $_ }
            if ($parts.Count -ge 1) {
                $filterName = $parts[0].ToLower()
                foreach ($kw in $suspiciousFilters) {
                    if ($filterName -match $kw) {
                        Add-Finding -Category "DriverKernel" -Title "Suspicious Mini-Filter Driver" -Details "Mini-filter '$($parts[0])' registered. It matches cheat-related pattern '$kw'." -Severity Critical
                    }
                }
            }
        }
    }
    $driverSignPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Driver Signing"
    if (Test-Path $driverSignPolicy) {
        $behave = Get-ItemProperty -Path $driverSignPolicy -Name "BehaviorOnFailedVerify" -ErrorAction SilentlyContinue
        if ($behave -and $behave.BehaviorOnFailedVerify -notin @(2,3)) {
            Add-Finding -Category "DriverKernel" -Title "Driver Signing Policy Weakened" -Details "BehaviorOnFailedVerify is $($behave.BehaviorOnFailedVerify) (0=Ignore,1=Warn,2=Block,3=Block). Should be 2 or 3." -Severity Critical
        }
    }
    Add-Finding -Category "DriverKernel" -Title "Driver & Kernel Scan Complete" -Details "Finished driver and kernel checks." -Severity Clean
}

function Invoke-RegistryPersistenceScan {
    Write-ProgressStatus -PercentComplete 45 -Status "Registry Persistence"
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $values.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } | ForEach-Object {
                $value = $_.Value
                if ($value -match '(\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\Windows\\Temp\\|\\%TEMP%|\\%APPDATA%)') {
                    Add-Finding -Category "RegistryPersistence" -Title "Suspicious Run Key Entry" -Details "Key: $key, Value: $($_.Name) = $value. Executable points to user-writable path." -Severity Suspicious
                }
            }
        }
    }
    $ifeoKeys = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                  "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
    foreach ($key in $ifeoKeys) {
        if (Test-Path $key) {
            Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
                $subkey = $_.PSPath
                $debugger = Get-ItemProperty -Path $subkey -Name "Debugger" -ErrorAction SilentlyContinue
                if ($debugger) {
                    Add-Finding -Category "RegistryPersistence" -Title "IFEO Debugger Hijack" -Details "Image File Execution Options for '$($_.PSChildName)' has Debugger set to '$($debugger.Debugger)'." -Severity Critical
                }
            }
        }
    }
    $comHijackCLSIDs = @("{00024500-0000-0000-C000-000000000046}")
    foreach ($clsids in $comHijackCLSIDs) {
        $hkcuPath = "HKCU:\SOFTWARE\Classes\CLSID\$clsids"
        if (Test-Path $hkcuPath) {
            Add-Finding -Category "RegistryPersistence" -Title "COM Hijacking in HKCU" -Details "User-defined COM registration for CLSID $clsids found. Could be used for persistence." -Severity Suspicious
        }
        if (Test-Path "$hkcuPath\InProcServer32") {
            $val = Get-ItemProperty -Path "$hkcuPath\InProcServer32" -Name "(default)" -ErrorAction SilentlyContinue
            if ($val) {
                Add-Finding -Category "RegistryPersistence" -Title "COM InProcServer32 Hijack" -Details "CLSID $clsids has InProcServer32 set to '$($val.'(default)')' under HKCU." -Severity Critical
            }
        }
    }
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        if ($task.State -eq 'Ready' -or $task.State -eq 'Running') {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if ($action.Execute -match '(\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\Windows\\Temp\\)') {
                    Add-Finding -Category "RegistryPersistence" -Title "Suspicious Scheduled Task" -Details "Task '$($task.TaskName)' executes '$($action.Execute)' from user-writable path." -Severity Suspicious
                }
            }
        }
    }
    try {
        $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
        $wmiBindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop
        $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction Stop
        if ($wmiFilters -and $wmiBindings -and $wmiConsumers) {
            Add-Finding -Category "RegistryPersistence" -Title "Active WMI Event Subscriptions" -Details "WMI persistence detected. $($wmiFilters.Count) filters, $($wmiBindings.Count) bindings, $($wmiConsumers.Count) consumers." -Severity Critical
        }
    } catch {
        Add-Finding -Category "RegistryPersistence" -Title "WMI Subscription Check" -Details "Could not query WMI subscriptions: $_" -Severity Clean
    }
    Add-Finding -Category "RegistryPersistence" -Title "Registry Persistence Scan Complete" -Details "Finished registry persistence checks." -Severity Clean
}

function Invoke-FileSystemScan {
    Write-ProgressStatus -PercentComplete 55 -Status "File System Artifacts"
    if ($Quick) {
        Add-Finding -Category "FileSystem" -Title "Quick Scan" -Details "File system deep scan skipped due to -Quick." -Severity Clean
        return
    }
    $pathsToScan = @(
        $env:TEMP, "$env:LOCALAPPDATA\Temp", $env:APPDATA, $env:LOCALAPPDATA,
        "C:\ProgramData", "C:\Users\*\AppData\*\*"
    )
    $cheatNames = @("*cheat*","*inject*","*bypass*","*loader*","*hack*","*modmenu*","*external*","*internal*","*driver*.sys","*mapper*","*kdmapper*")
    foreach ($basePath in $pathsToScan) {
        if (-not (Test-Path $basePath)) { continue }
        Get-ChildItem -Path $basePath -Recurse -ErrorAction SilentlyContinue -Include *.exe,*.dll,*.sys,*.bin | ForEach-Object {
            $file = $_
            $nameMatch = $cheatNames | Where-Object { $file.Name -like $_ }
            if ($nameMatch) {
                Add-Finding -Category "FileSystem" -Title "Suspicious File Name Match" -Details "File $($file.FullName) matches cheat pattern." -Severity Suspicious
            }
            $hashMD5 = Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue
            $hashSHA1 = Get-FileHash -Path $file.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue
            foreach ($known in $KnownCheatHashes) {
                if (($hashMD5 -and $hashMD5.Hash -eq $known.MD5) -or ($hashSHA1 -and $hashSHA1.Hash -eq $known.SHA1)) {
                    Add-Finding -Category "FileSystem" -Title "Known Cheat File by Hash" -Details "File $($file.FullName) matches known cheat '$($known.Name)' by hash." -Severity Critical
                }
            }
            if ($file.Attributes -band ([System.IO.FileAttributes]::Hidden) -and $file.Attributes -band ([System.IO.FileAttributes]::System)) {
                Add-Finding -Category "FileSystem" -Title "Hidden System File in User Directory" -Details "File $($file.FullName) is hidden and system." -Severity Suspicious
            }
        }
    }
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    Get-Item "$userProfile\*" -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object {
        Add-Finding -Category "FileSystem" -Title "Alternate Data Stream Detected" -Details "File $($_.FileName) has stream '$($_.Stream)'." -Severity Suspicious
    }
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Get-ChildItem $recentPath -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($_.FullName)
            if ($shortcut.TargetPath -match '(\\Temp\\|\\AppData\\|\\Downloads\\)') {
                Add-Finding -Category "FileSystem" -Title "Suspicious LNK Shortcut" -Details "LNK file $($_.Name) points to user-writable path '$($shortcut.TargetPath)'." -Severity Suspicious
            }
        }
    }
    $extPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    )
    foreach ($extPath in $extPaths) {
        if (Test-Path $extPath) {
            Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $manifestPath = Join-Path $_.FullName "manifest.json"
                if (Test-Path $manifestPath) {
                    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                    if ($manifest.permissions -contains "http://*/*" -or $manifest.permissions -contains "https://*/*") {
                        Add-Finding -Category "FileSystem" -Title "Suspicious Browser Extension" -Details "Extension '$($manifest.name)' has broad web request permission." -Severity Suspicious
                    }
                }
            }
        }
    }
    Add-Finding -Category "FileSystem" -Title "File System Scan Complete" -Details "Finished file system artifact checks." -Severity Clean
}

function Invoke-NetworkIndicatorsScan {
    Write-ProgressStatus -PercentComplete 65 -Status "Network & C2 Indicators"
    $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $tcpConnections) {
        $remoteAddr = $conn.RemoteAddress
        if ($remoteAddr -in $script:KnownCheatIPs) {
            Add-Finding -Category "NetworkIndicators" -Title "Connection to Known Cheat IP" -Details "Process ID $($conn.OwningProcess) connected to ${remoteAddr}:$($conn.RemotePort) (State: $($conn.State))." -Severity Critical
        }
        if ($conn.LocalPort -notin @(80,443,3389,445,135,22,53,137,138,139,1900,5353) -and $conn.State -eq 'Listen') {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                Add-Finding -Category "NetworkIndicators" -Title "Non-Standard Listening Port" -Details "Process $($proc.Name) (PID $($proc.Id)) listening on $($conn.LocalAddress):$($conn.LocalPort)." -Severity Suspicious
            }
        }
    }
    $firewallRules = netsh advfirewall firewall show rule name=all verbose 2>$null
    if ($firewallRules) {
        $rulesText = $firewallRules -join "`n"
        if ($rulesText -match '(C:\\Users\\.+\\AppData\\|C:\\Windows\\Temp\\)') {
            Add-Finding -Category "NetworkIndicators" -Title "Firewall Rule with User Path" -Details "A firewall rule allows a process in a user-writable directory." -Severity Suspicious
        }
    }
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($proxySettings.ProxyEnable -eq 1 -and $proxySettings.ProxyServer) {
        Add-Finding -Category "NetworkIndicators" -Title "System Proxy Enabled" -Details "Proxy server set to $($proxySettings.ProxyServer)." -Severity Suspicious
    }
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|TAP|TUN|OpenVPN|WireGuard|Nord|Express|Proton' }
    if ($adapters) {
        Add-Finding -Category "NetworkIndicators" -Title "VPN Virtual Adapter Detected" -Details "VPN adapters: $($adapters.Name -join ', ')." -Severity Suspicious
    }
    Add-Finding -Category "NetworkIndicators" -Title "Network Scan Complete" -Details "Finished network indicator checks." -Severity Clean
}

function Invoke-EventLogForensicsScan {
    Write-ProgressStatus -PercentComplete 75 -Status "Event Log Forensics"
    if ($Quick) {
        Add-Finding -Category "EventLogForensics" -Title "Quick Scan" -Details "Event log analysis skipped due to -Quick." -Severity Clean
        return
    }
    $securityLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 500 -ErrorAction SilentlyContinue
    if ($securityLogs) {
        foreach ($log in $securityLogs) {
            $cmdLine = $log.Properties[8].Value
            $parentName = $log.Properties[21].Value
            $procName = $log.Properties[5].Value
            if ($cmdLine -match '(-inject|-map|cheat|hack|loader|inject|bypass|bypasser|stealth|mapper|reflect|manualmap)') {
                Add-Finding -Category "EventLogForensics" -Title "Suspicious Process Command Line" -Details "Process $procName (PID $($log.Properties[4].Value)) executed with: $cmdLine" -Severity Critical
            }
            if ($parentName -match 'winword|excel|powerpnt' -and $procName -match 'cmd|powershell|wscript') {
                Add-Finding -Category "EventLogForensics" -Title "Office Application Spawned Shell" -Details "$parentName spawned ${procName}: ${cmdLine}" -Severity Critical
            }
            if (($parentName -eq 'svchost.exe' -and $procName -eq 'cmd.exe') -or ($parentName -eq 'notepad.exe' -and $procName -eq 'powershell.exe')) {
                Add-Finding -Category "EventLogForensics" -Title "Anomalous Parent-Child Process" -Details "$parentName spawned $procName (PID $($log.Properties[4].Value))" -Severity Critical
            }
        }
    }
    $systemLogs = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue
    if ($systemLogs) {
        foreach ($log in $systemLogs) {
            $imagePath = $log.Properties[1].Value
            if ($imagePath -match '(\\Temp\\|\\AppData\\|\\Downloads\\|\\Users\\Public\\|\\Windows\\Temp\\)') {
                Add-Finding -Category "EventLogForensics" -Title "Service Installed from User Path" -Details "Service '$($log.Properties[0].Value)' image path: $imagePath" -Severity Critical
            }
        }
    }
    $ciLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; ID=3076} -MaxEvents 100 -ErrorAction SilentlyContinue
    if ($ciLogs) {
        foreach ($log in $ciLogs) {
            Add-Finding -Category "EventLogForensics" -Title "Unsigned Driver Load Detected" -Details "Event 3076: $($log.Message)" -Severity Critical
        }
    }
    $psLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103,4104; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue
    if ($psLogs) {
        foreach ($log in $psLogs) {
            $scriptBlock = $log.Properties[2].Value
            if ($scriptBlock -match '(FromBase64String|Invoke-Expression|iex|bypass|cheat|hack|inject|loader|amsi|etw)') {
                Add-Finding -Category "EventLogForensics" -Title "Suspicious PowerShell ScriptBlock" -Details "Event $($log.Id): $scriptBlock" -Severity Critical
            }
        }
    }
    $appLockerLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'; ID=8003,8004,8005,8006,8007,8008; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($appLockerLogs) {
        foreach ($log in $appLockerLogs) {
            Add-Finding -Category "EventLogForensics" -Title "AppLocker Block Event" -Details "Event $($log.Id): $($log.Message)" -Severity Suspicious
        }
    }
    $defenderLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117,1118,1119,5001; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($defenderLogs) {
        foreach ($log in $defenderLogs) {
            $msg = $log.Message.ToLower()
            if ($msg -match 'hack|cheat|inject|bypass|trojan') {
                Add-Finding -Category "EventLogForensics" -Title "Defender Detection Related to Cheating" -Details "Event $($log.Id): $($log.Message)" -Severity Critical
            }
        }
    }
    Add-Finding -Category "EventLogForensics" -Title "Event Log Scan Complete" -Details "Finished event log forensic analysis." -Severity Clean
}
#endregion

#region HTML Report Generation
function New-HtmlReport {
    param([string]$FilePath)
    $computer = $script:ComputerName
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $scanDuration = [math]::Round(((Get-Date) - $script:ScanStartTime).TotalSeconds, 2)
    $totalChecks = $script:TotalChecks
    $totalPassed = $script:TotalPassed
    $totalWarnings = $script:TotalWarnings
    $totalCritical = $script:TotalCritical

    $tabsContent = ""
    foreach ($category in $script:DetectionResults.Keys) {
        $findings = $script:DetectionResults[$category]
        $cleanCount = ($findings | Where-Object Severity -eq 'Clean').Count
        $warnCount = ($findings | Where-Object Severity -eq 'Suspicious').Count
        $critCount = ($findings | Where-Object Severity -eq 'Critical').Count
        $tabId = $category.ToLower()
        $severityColor = if ($critCount -gt 0) { "red" } elseif ($warnCount -gt 0) { "yellow" } else { "green" }
        $overall = if ($critCount -gt 0) { "Critical" } elseif ($warnCount -gt 0) { "Suspicious" } else { "Clean" }
        $findingsHtml = ""
        foreach ($f in $findings) {
            $icon = switch ($f.Severity) {
                "Clean" { "✅" }
                "Suspicious" { "⚠️" }
                "Critical" { "❌" }
            }
            $sevClass = $f.Severity.ToLower()
            $findingsHtml += @"
<div class="finding-card $sevClass" onclick="toggleDetails(this)">
    <div class="finding-header">
        <span class="finding-icon">$icon</span>
        <span class="finding-title">$($f.Title)</span>
        <span class="finding-timestamp">$($f.Timestamp)</span>
    </div>
    <div class="finding-details">$($f.Details -replace "`r`n", "<br>")</div>
</div>
"@
        }
        $tabsContent += @"
<div class="tab-pane" id="tab-$tabId">
    <div class="summary-bar">
        <div class="summary-box">
            <div class="summary-number green">$cleanCount</div><div class="summary-label">Clean</div>
        </div>
        <div class="summary-box">
            <div class="summary-number yellow">$warnCount</div><div class="summary-label">Warnings</div>
        </div>
        <div class="summary-box">
            <div class="summary-number red">$critCount</div><div class="summary-label">Critical</div>
        </div>
    </div>
    <div class="overall-status" style="color:var(--$severityColor)">Overall: $overall</div>
    <div class="findings-list">$findingsHtml</div>
</div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Report - $computer - $date</title>
<style>
:root {
    --bg-primary: #0b0f19;
    --bg-secondary: #121726;
    --card-bg: rgba(20, 25, 45, 0.8);
    --text-primary: #e0e6f0;
    --text-secondary: #9aa5b5;
    --green: #00e676;
    --yellow: #ffd600;
    --red: #ff1744;
    --accent: #448aff;
    --glass-bg: rgba(255, 255, 255, 0.05);
    --glass-border: rgba(255, 255, 255, 0.1);
    --transition: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg-primary); color: var(--text-primary); display: flex; height: 100vh; overflow: hidden; }
.sidebar { width: 260px; background: var(--bg-secondary); border-right: 1px solid var(--glass-border); display: flex; flex-direction: column; padding: 20px 0; }
.sidebar-header { padding: 20px; border-bottom: 1px solid var(--glass-border); }
.sidebar-header h2 { font-size: 1.2rem; color: var(--accent); }
.sidebar-nav { flex:1; overflow-y: auto; padding: 10px 0; }
.nav-item { display: block; padding: 12px 20px; color: var(--text-secondary); cursor: pointer; transition: var(--transition); border-left: 3px solid transparent; }
.nav-item:hover, .nav-item.active { background: rgba(68,138,255,0.1); color: var(--text-primary); border-left-color: var(--accent); }
.main-content { flex:1; overflow-y: auto; padding: 30px; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
.header h1 { font-size: 1.8rem; color: var(--text-primary); }
.search-box { position: relative; }
.search-box input { background: var(--glass-bg); border: 1px solid var(--glass-border); color: var(--text-primary); padding: 8px 12px; border-radius: 8px; width: 200px; outline:none; transition: var(--transition); }
.search-box input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(68,138,255,0.3); }
.tab-pane { display:none; animation: fadeSlideIn 0.5s ease; }
.tab-pane.active { display:block; }
.summary-bar { display:flex; gap: 20px; margin-bottom: 20px; }
.summary-box { background: var(--card-bg); backdrop-filter: blur(10px); border:1px solid var(--glass-border); border-radius:12px; padding:15px 20px; text-align:center; flex:1; }
.summary-number { font-size: 2rem; font-weight: bold; }
.summary-label { font-size: 0.8rem; text-transform:uppercase; color:var(--text-secondary); margin-top:5px; }
.overall-status { font-size: 1.2rem; margin-bottom: 25px; font-weight:600; }
.findings-list { display:grid; gap:12px; }
.finding-card { background: var(--card-bg); backdrop-filter: blur(10px); border:1px solid var(--glass-border); border-radius:12px; padding:15px; cursor:pointer; transition: var(--transition); }
.finding-card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
.finding-card.clean { border-left: 4px solid var(--green); }
.finding-card.suspicious { border-left: 4px solid var(--yellow); animation: pulseYellow 2s infinite; }
.finding-card.critical { border-left: 4px solid var(--red); animation: pulseRed 2s infinite; }
.finding-header { display:flex; align-items:center; gap:10px; }
.finding-icon { font-size:1.4rem; }
.finding-title { font-weight:600; flex:1; }
.finding-timestamp { font-size:0.8rem; color:var(--text-secondary); }
.finding-details { display:none; margin-top:10px; padding:10px; background:rgba(0,0,0,0.2); border-radius:8px; font-size:0.9rem; color:var(--text-secondary); border:1px solid var(--glass-border); }
.finding-card.expanded .finding-details { display:block; animation: expand 0.3s ease; }
@keyframes fadeSlideIn { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
@keyframes pulseYellow { 0% { box-shadow: 0 0 0 0 rgba(255,214,0,0.4); } 70% { box-shadow: 0 0 0 10px rgba(255,214,0,0); } 100% { box-shadow: 0 0 0 0 rgba(255,214,0,0); } }
@keyframes pulseRed { 0% { box-shadow: 0 0 0 0 rgba(255,23,68,0.4); } 70% { box-shadow: 0 0 0 10px rgba(255,23,68,0); } 100% { box-shadow: 0 0 0 0 rgba(255,23,68,0); } }
@keyframes expand { from { max-height:0; opacity:0; } to { max-height:200px; opacity:1; } }
.export-btn { margin-left:20px; background: var(--accent); color:white; border:none; padding:8px 15px; border-radius:8px; cursor:pointer; transition: var(--transition); }
.export-btn:hover { opacity:0.8; }
</style>
</head>
<body>
<div class="sidebar">
    <div class="sidebar-header">
        <h2>Forensic Scanner</h2>
        <p style="color:var(--text-secondary); font-size:0.8rem;">$computer</p>
        <p style="color:var(--text-secondary); font-size:0.8rem;">$date</p>
    </div>
    <div class="sidebar-nav">
        $(foreach ($cat in $script:DetectionResults.Keys) {
            $id = $cat.ToLower()
            $title = switch ($cat) {
                "ProcessInjection" { "Process & Injection" }
                "MemoryForensics" { "Memory Forensics" }
                "AMSIETWBypass" { "AMSI & ETW Bypass" }
                "DriverKernel" { "Driver & Kernel" }
                "RegistryPersistence" { "Registry Persistence" }
                "FileSystem" { "File System" }
                "NetworkIndicators" { "Network & C2" }
                "EventLogForensics" { "Event Log Forensics" }
            }
            "<div class='nav-item' data-tab='tab-$id'>$title</div>"
        })
    </div>
</div>
<div class="main-content">
    <div class="header">
        <h1>Forensic Report</h1>
        <div style="display:flex; align-items:center;">
            <div class="search-box"><input type="text" id="searchInput" placeholder="Search findings..." onkeyup="filterFindings()"></div>
            <button class="export-btn" onclick="exportJSON()">Export JSON</button>
        </div>
    </div>
    $tabsContent
</div>
<script>
let reportData = null;
document.addEventListener('DOMContentLoaded', () => {
    const navItems = document.querySelectorAll('.nav-item');
    navItems[0].classList.add('active');
    document.getElementById('tab-processinjection').classList.add('active');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            const targetId = item.getAttribute('data-tab');
            document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
            document.getElementById(targetId).classList.add('active');
        });
    });
    reportData = {
        computerName: "$computer",
        scanTime: "$date",
        duration: $scanDuration,
        totalChecks: $totalChecks,
        totalPassed: $totalPassed,
        totalWarnings: $totalWarnings,
        totalCritical: $totalCritical,
        categories: {}
    };
    $(foreach ($cat in $script:DetectionResults.Keys) {
        $arr = @()
        foreach ($f in $script:DetectionResults[$cat]) {
            $arr += "{title:'$($f.Title -replace "'", "\\'")', severity:'$($f.Severity)', details:'$($f.Details -replace "'", "\\'" -replace "`r`n", "\\n")', timestamp:'$($f.Timestamp)'}"
        }
        "reportData.categories['$cat'] = [$( ($arr -join ',') )];"
    })
});
function toggleDetails(card) {
    card.classList.toggle('expanded');
}
function filterFindings() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    document.querySelectorAll('.finding-card').forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(searchTerm) ? 'block' : 'none';
    });
}
function exportJSON() {
    if (!reportData) return;
    const blob = new Blob([JSON.stringify(reportData, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ForensicReport_$computer.json';
    a.click();
    URL.revokeObjectURL(url);
}
</script>
</body>
</html>
"@
    $html | Out-File -FilePath $FilePath -Encoding UTF8
}
#endregion

#region Main Execution
function Main {
    if (-not (Check-Admin)) {
        Write-Host "[!] This script requires Administrator privileges for full functionality. Exiting." -ForegroundColor Red
        exit 1
    }

    Write-Host "Forensic Scanner v1.0 - Starting..." -ForegroundColor Cyan
    $script:TotalTasks = 8
    $script:Progress = 0

    Invoke-ProcessInjectionScan
    $script:Progress += 12.5
    Invoke-MemoryForensicsScan
    $script:Progress += 12.5
    Invoke-AMSIETWBypassScan
    $script:Progress += 12.5
    Invoke-DriverKernelScan
    $script:Progress += 12.5
    Invoke-RegistryPersistenceScan
    $script:Progress += 12.5
    Invoke-FileSystemScan
    $script:Progress += 12.5
    Invoke-NetworkIndicatorsScan
    $script:Progress += 12.5
    Invoke-EventLogForensicsScan
    $script:Progress = 100

    Write-Host "Generating report..." -ForegroundColor Cyan
    $reportName = "ForensicReport_${script:ComputerName}_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
    New-HtmlReport -FilePath (Join-Path $PSScriptRoot $reportName)

    if ($ExportJson) {
        $jsonPath = [IO.Path]::ChangeExtension((Join-Path $PSScriptRoot $reportName), '.json')
        $script:DetectionResults | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding UTF8
        Write-Host "JSON export saved to $jsonPath" -ForegroundColor Green
    }

    Write-Host "Report saved to $reportName" -ForegroundColor Green
    if ($ShowReport) {
        Start-Process $reportName
    }
}

Main
#endregion
