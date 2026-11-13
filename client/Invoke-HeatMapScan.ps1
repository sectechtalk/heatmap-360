<#
.SYNOPSIS
  HeatMap 360 scanner: inventories THIS Windows computer, removes personal data, sends it to HeatMap 360 and saves
  the results as a PDF when they are ready. Read-only: it never installs, updates or changes anything.
.DESCRIPTION
  What is collected: Windows version, build and installed updates; installed programs and their versions (and winget
  package IDs, so newer versions can be looked up); hardware make, model, BIOS, motherboard, CPU, memory, disks and
  device drivers (network, display, storage, audio, Bluetooth, chipset); Defender, BitLocker, Secure Boot, TPM and
  firewall status.
  What is NOT collected: computer name, user names, domain, IP or MAC addresses, serial numbers, file paths or
  documents. The computer is identified only by a one-way hash of its Windows MachineGuid, so two scans of the same
  computer can be compared without revealing which computer it is.
  Use -SaveOnly to write the exact data to a file and read it before anything is sent.
  Works in Windows PowerShell 5.1 and PowerShell 7. Run it elevated to include BitLocker and Secure Boot.
.EXAMPLE
  .\Invoke-HeatMapScan.ps1                         # scan, upload, wait for the PDF
  .\Invoke-HeatMapScan.ps1 -SaveOnly               # scan and save the JSON only; nothing is sent
  .\Invoke-HeatMapScan.ps1 -Resume <scan id>       # fetch the PDF of an earlier scan
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [string]$Server = '__HEATMAP_URL__',
    [Parameter(ParameterSetName = 'Scan')][switch]$SaveOnly,
    [Parameter(ParameterSetName = 'Resume', Mandatory)][string]$Resume,
    [string]$OutputFolder = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'HeatMap360'),
    [int]$WaitMinutes = 15
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
$ClientVersion = '1.0.0'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$null = New-Item -ItemType Directory -Path $OutputFolder -Force

function Get-Prop($Object, [string]$Name) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { $Object.$Name } else { $null }
}
function Get-Day($Value) {
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd') }
    if ($Value) { try { return ([datetime]$Value).ToString('yyyy-MM-dd') } catch { } }
    $null
}

# ---------------------------------------------------------------- inventory
function Get-Inventory {
    $errors = [System.Collections.Generic.List[string]]::new()
    function Part([string]$Name, [scriptblock]$Block) { try { & $Block } catch { $errors.Add("${Name}: $($_.Exception.Message)") } }

    $guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("hm360:$guid"))
    $machineId = (-join ($hash | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)

    $inv = [ordered]@{
        schema        = 'hm360.inventory/1'
        clientVersion = $ClientVersion
        collectedAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        machineId     = $machineId
    }

    $inv.os = Part 'os' {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $os = Get-CimInstance Win32_OperatingSystem
        $inv.uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        [ordered]@{ name = $os.Caption; displayVersion = (Get-Prop $cv 'DisplayVersion'); build = [int]$cv.CurrentBuildNumber
            ubr = [int](Get-Prop $cv 'UBR'); edition = (Get-Prop $cv 'EditionID'); architecture = $os.OSArchitecture }
    }
    $inv.pendingReboot = Part 'pendingReboot' {
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    }
    $inv.updates = @(Part 'updates' {
        Get-HotFix | ForEach-Object { [ordered]@{ id = $_.HotFixID; description = $_.Description; installedOn = (Get-Day (Get-Prop $_ 'InstalledOn')) } }
    })

    $health = [ordered]@{}
    $health.defender = Part 'defender' {
        $mp = Get-MpComputerStatus
        [ordered]@{ enabled = [bool]$mp.AntivirusEnabled; realTime = [bool]$mp.RealTimeProtectionEnabled
            signatureAgeDays = [int]$mp.AntivirusSignatureAge; engineVersion = "$($mp.AMEngineVersion)" }
    }
    $health.bitlocker = Part 'bitlocker' { [ordered]@{ protection = "$((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus)" } }
    $health.secureBoot = Part 'secureBoot' { [bool](Confirm-SecureBootUEFI) }
    $health.tpm = Part 'tpm' {
        $t = Get-Tpm
        [ordered]@{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady; manufacturerVersion = "$(Get-Prop $t 'ManufacturerVersion')" }
    }
    $health.firewall = Part 'firewall' {
        $fw = [ordered]@{}
        Get-NetFirewallProfile | ForEach-Object { $fw[$_.Name.ToLower()] = [bool]$_.Enabled }
        $fw
    }
    $inv.health = $health

    $hw = [ordered]@{}
    $hw.system = Part 'system' { $cs = Get-CimInstance Win32_ComputerSystem; [ordered]@{ manufacturer = $cs.Manufacturer; model = $cs.Model; family = (Get-Prop $cs 'SystemFamily') } }
    $hw.memoryGB = Part 'memory' { [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1) }
    $hw.bios = Part 'bios' { $b = Get-CimInstance Win32_BIOS; [ordered]@{ vendor = $b.Manufacturer; version = $b.SMBIOSBIOSVersion; releaseDate = (Get-Day $b.ReleaseDate) } }
    $hw.baseboard = Part 'baseboard' { $m = Get-CimInstance Win32_BaseBoard; [ordered]@{ manufacturer = $m.Manufacturer; product = $m.Product; version = $m.Version } }
    $hw.cpu = @(Part 'cpu' { Get-CimInstance Win32_Processor | ForEach-Object { [ordered]@{ name = $_.Name.Trim(); manufacturer = $_.Manufacturer } } })
    $hw.disks = @(Part 'disks' {
        Get-PhysicalDisk | ForEach-Object { [ordered]@{ model = $_.FriendlyName; firmware = $_.FirmwareVersion; mediaType = "$($_.MediaType)"; busType = "$($_.BusType)"; sizeGB = [math]::Round($_.Size / 1GB) } }
    })
    $hw.volumes = @(Part 'volumes' {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ drive = $_.DeviceID; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1) } }
    })
    $classes = 'NET', 'DISPLAY', 'HDC', 'SCSIADAPTER', 'MEDIA', 'BLUETOOTH', 'SYSTEM', 'USB', 'CAMERA', 'BIOMETRIC', 'FIRMWARE'
    $hw.devices = @(Part 'devices' {
        Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -in $classes -and $_.DeviceName -and $_.DriverVersion } |
            Sort-Object DeviceClass, DeviceName -Unique | ForEach-Object {
                [ordered]@{ class = $_.DeviceClass; name = $_.DeviceName; manufacturer = $_.Manufacturer; driverProvider = $_.DriverProviderName
                    driverVersion = $_.DriverVersion; driverDate = (Get-Day $_.DriverDate) }
            }
    })
    $inv.hardware = $hw

    $inv.apps = @(Part 'apps' {
        $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
            Where-Object { (Get-Prop $_ 'DisplayName') -and (Get-Prop $_ 'SystemComponent') -ne 1 } |
            ForEach-Object { [ordered]@{ name = $_.DisplayName; version = (Get-Prop $_ 'DisplayVersion'); publisher = (Get-Prop $_ 'Publisher') } } |
            Sort-Object { $_.name } -Unique
    })
    # winget knows the package ID of each program it can update; the bot uses the ID to find the newest version.
    $inv.winget = @(Part 'winget' {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'winget is not installed' }
        $tmp = Join-Path $env:TEMP ("hm360-winget-{0}.json" -f [guid]::NewGuid())
        try {
            $null = & winget export -o $tmp --include-versions --accept-source-agreements --disable-interactivity 2>&1
            if (-not (Test-Path $tmp)) { throw 'winget export wrote nothing' }
            $doc = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
            foreach ($src in $doc.Sources) {
                foreach ($p in $src.Packages) {
                    [ordered]@{ id = $p.PackageIdentifier; version = (Get-Prop $p 'Version'); source = $src.SourceDetails.Name }
                }
            }
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    })
    $inv.errors = @($errors)
    $inv
}

# ---------------------------------------------------------------- anonymize
# Second line of defense after choosing fields: scrub this computer's and user's names from every string.
function Protect-Json([string]$Json) {
    $words = @($env:COMPUTERNAME, $env:USERNAME, $env:USERDOMAIN) | Where-Object { $_ -and $_.Length -ge 3 } | Sort-Object Length -Descending -Unique
    foreach ($w in $words) { $Json = [regex]::Replace($Json, "(?i)\b$([regex]::Escape($w))\b", 'redacted') }
    $Json = [regex]::Replace($Json, '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}', 'redacted@example.invalid')
    $Json = [regex]::Replace($Json, '(?i)(\\\\users\\\\)[^\\"]+', '$1redacted')
    $Json = [regex]::Replace($Json, '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '00-00-00-00-00-00')
    $Json
}

# ---------------------------------------------------------------- results
function Save-Report([string]$Id, [string]$Token) {
    $headers = @{ Authorization = "Bearer $Token" }
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    Write-Host "Waiting up to $WaitMinutes minutes for results (scan $Id)..."
    while ($true) {
        $status = Invoke-RestMethod -Uri "$Server/api/scans/$Id/status" -Headers $headers -UseBasicParsing
        if ($status.state -eq 'done') {
            $pdf = Join-Path $OutputFolder "HeatMap360-$Id.pdf"
            Invoke-WebRequest -Uri "$Server/api/scans/$Id/report.pdf" -Headers $headers -OutFile $pdf -UseBasicParsing
            Write-Host "Results saved: $pdf"
            return $pdf
        }
        if ((Get-Date) -gt $deadline) {
            Write-Host "Results are not ready yet (state: $($status.state)). Fetch them later with:"
            Write-Host "  .\Invoke-HeatMapScan.ps1 -Resume $Id"
            return $null
        }
        Start-Sleep -Seconds 30
    }
}

if ($Server -eq '__HEATMAP_URL__' -and -not $SaveOnly) { throw 'Pass -Server https://<your HeatMap 360 address> (or download the script from your HeatMap 360 page, which fills it in).' }
$Server = $Server.TrimEnd('/')

if ($PSCmdlet.ParameterSetName -eq 'Resume') {
    $ticket = Join-Path $OutputFolder "scan-$Resume.json"
    if (-not (Test-Path $ticket)) { throw "No saved ticket for scan $Resume in $OutputFolder." }
    $t = Get-Content -LiteralPath $ticket -Raw | ConvertFrom-Json
    $null = Save-Report -Id $t.id -Token $t.token
    return
}

Write-Host 'Scanning this computer (read-only)...'
$json = Protect-Json ((Get-Inventory) | ConvertTo-Json -Depth 8 -Compress)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$file = Join-Path $OutputFolder "inventory-$stamp.json"
[IO.File]::WriteAllText($file, $json, [Text.UTF8Encoding]::new($false))
Write-Host "Inventory saved: $file"
if ($SaveOnly) { Write-Host 'Nothing was sent (-SaveOnly).'; return }

$resp = Invoke-RestMethod -Method Post -Uri "$Server/api/scans" -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -UseBasicParsing
# The token is the only way to get this scan's PDF. Keep it with the inventory, readable by this user only.
$ticket = Join-Path $OutputFolder "scan-$($resp.id).json"
[ordered]@{ id = $resp.id; token = $resp.token; server = $Server; sentAt = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $ticket -Encoding UTF8
Write-Host "Sent. Scan ID: $($resp.id)"
$null = Save-Report -Id $resp.id -Token $resp.token
