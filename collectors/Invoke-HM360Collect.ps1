<#
.SYNOPSIS
  Collects machine health and installed software on THIS computer and writes one hm360 envelope to the inbox. Read-only.
.DESCRIPTION
  Reads only: OS build, uptime, pending reboot, installed updates, Defender status, BitLocker (system drive), Secure
  Boot, TPM, firewall profiles, fixed disks and installed programs. Nothing is installed, changed or restarted.
  Each part is optional: a part that fails is recorded in "errors" and the rest still gets written.
  BitLocker and Secure Boot need an elevated run; without it they show as "unknown" on the dashboard.
  Settings: collectors\hm360.config.json (copy of hm360.config.sample.json; holds no secrets).
  Works in Windows PowerShell 5.1 and PowerShell 7.
.EXAMPLE
  .\Invoke-HM360Collect.ps1
  .\Invoke-HM360Collect.ps1 -Inbox D:\hm360\inbox
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'hm360.config.json'),
    [string]$Inbox
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$config = @{}
if (Test-Path -LiteralPath $ConfigPath) { $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json }
if (-not $Inbox) {
    $Inbox = if ($config.PSObject.Properties['inbox']) { $config.inbox } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'data\inbox' }
}
$null = New-Item -ItemType Directory -Path $Inbox -Force

$errors = [System.Collections.Generic.List[string]]::new()
function Try-Part([string]$Name, [scriptblock]$Block) {
    try { & $Block } catch { $errors.Add("${Name}: $($_.Exception.Message)") }
}

$envelope = [ordered]@{
    schema      = 'hm360.envelope/1'
    collector   = 'windows'
    host        = $env:COMPUTERNAME
    collectedAt = (Get-Date).ToUniversalTime().ToString('o')
}

$envelope.os = Try-Part 'os' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $envelope.uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
    $envelope.lastBoot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    [ordered]@{ name = $os.Caption; version = $cv.DisplayVersion; build = "$($cv.CurrentBuildNumber).$($cv.UBR)"; edition = $cv.EditionID }
}

$envelope.pendingReboot = Try-Part 'pendingReboot' {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}

$envelope.hotfixes = @(Try-Part 'hotfixes' {
    Get-HotFix | Where-Object InstalledOn | ForEach-Object { [ordered]@{ id = $_.HotFixID; installedOn = $_.InstalledOn.ToString('yyyy-MM-dd') } }
})

$envelope.defender = Try-Part 'defender' {
    $mp = Get-MpComputerStatus
    [ordered]@{ enabled = [bool]$mp.AntivirusEnabled; realTime = [bool]$mp.RealTimeProtectionEnabled
        signatureAgeDays = [int]$mp.AntivirusSignatureAge; tamperProtected = [bool]$mp.IsTamperProtected }
}

$envelope.bitlocker = Try-Part 'bitlocker' {
    $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
    [ordered]@{ protection = "$($v.ProtectionStatus)"; method = "$($v.EncryptionMethod)" }
}

$envelope.secureBoot = Try-Part 'secureBoot' { [bool](Confirm-SecureBootUEFI) }

$envelope.tpm = Try-Part 'tpm' { $t = Get-Tpm; [ordered]@{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady } }

$envelope.firewall = Try-Part 'firewall' {
    $fw = [ordered]@{}
    Get-NetFirewallProfile | ForEach-Object { $fw[$_.Name.ToLower()] = [bool]$_.Enabled }
    $fw
}

$envelope.disks = @(Try-Part 'disks' {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{ drive = $_.DeviceID; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1) }
    }
})

$envelope.software = @(Try-Part 'software' {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    if (-not $config.PSObject.Properties['software'] -or $config.software.includePerUser) {
        $keys += 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -and -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) } |
        ForEach-Object {
            [ordered]@{ name = $_.DisplayName
                version = if ($_.PSObject.Properties['DisplayVersion']) { $_.DisplayVersion } else { $null }
                publisher = if ($_.PSObject.Properties['Publisher']) { $_.Publisher } else { $null } }
        } | Sort-Object { $_.name } -Unique
})

$envelope.errors = @($errors)

$file = Join-Path $Inbox ("windows-{0}.json" -f $env:COMPUTERNAME)
$tmp = "$file.tmp"
$envelope | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $tmp -Encoding UTF8
Move-Item -LiteralPath $tmp -Destination $file -Force
Write-Output ("hm360: wrote {0} ({1} programs, {2} updates, {3} errors)" -f $file, $envelope.software.Count, $envelope.hotfixes.Count, $errors.Count)
