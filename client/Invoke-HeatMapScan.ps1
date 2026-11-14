<#
.SYNOPSIS
  HeatMap 360 scanner: inventories THIS Windows computer, removes personal data, sends it to HeatMap 360 and saves
  the results as a PDF when they are ready. Read-only: it never installs, updates or changes anything.
.DESCRIPTION
  What is collected: Windows version, build and installed updates; installed programs and their versions (and winget
  package IDs, so newer versions can be looked up); hardware make, model, BIOS, motherboard, CPU, memory, disks and
  device drivers (network, display, storage, audio, Bluetooth, chipset); Defender, BitLocker, Secure Boot, TPM and
  firewall status; how many critical and error events each Windows component logged in the last 7 days (counts and
  event IDs only, never the message text); each physical network adapter's model, link speed, duplex, driver and
  power/offload settings, and the Wi-Fi signal strength, band and standard; disk health (wear, temperature,
  uncorrected errors) and battery health; network health: ping time and loss to this computer's gateway, connection
  time to the internet, DNS lookup time, and download/upload speed measured against Cloudflare's public speed test
  (speed.cloudflare.com, about 35 MB; skip it with -SkipSpeedTest).
  What is NOT collected: computer name, user names, domain, IP or MAC addresses, Wi-Fi network names, serial
  numbers, event log messages, the gateway's or any other address, file paths or documents. The computer is identified only by a one-way hash of its Windows MachineGuid, so two scans of the same
  computer can be compared without revealing which computer it is.
  Use -SaveOnly to write the exact data to a file and read it before anything is sent.
  Works in Windows PowerShell 5.1 and PowerShell 7. Run it elevated to include BitLocker and Secure Boot.
.EXAMPLE
  .\Invoke-HeatMapScan.ps1                         # scan, upload, wait for the PDF
  .\Invoke-HeatMapScan.ps1 -SaveOnly               # scan and save the JSON only; nothing is sent
  .\Invoke-HeatMapScan.ps1 -SkipSpeedTest          # leave out the download/upload speed test (about 35 MB)
  .\Invoke-HeatMapScan.ps1 -Resume <scan id>       # fetch the PDF of an earlier scan
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [string]$Server = '__HEATMAP_URL__',
    [Parameter(ParameterSetName = 'Scan')][switch]$SaveOnly,
    [Parameter(ParameterSetName = 'Scan')][switch]$SkipSpeedTest,
    [Parameter(ParameterSetName = 'Resume', Mandatory)][string]$Resume,
    [string]$OutputFolder = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'HeatMap360'),
    [int]$WaitMinutes = 15
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
$ClientVersion = '1.2.0'
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
        Get-PhysicalDisk | ForEach-Object {
            $d = [ordered]@{ model = $_.FriendlyName; firmware = $_.FirmwareVersion; mediaType = "$($_.MediaType)"; busType = "$($_.BusType)"; sizeGB = [math]::Round($_.Size / 1GB)
                health = "$($_.HealthStatus)" }
            # Reliability counters need administrator rights; without them the disk is listed without them.
            $rc = try { $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch { $null }
            if ($rc) {
                $d.wearPercent = Get-Prop $rc 'Wear'; $d.temperatureC = Get-Prop $rc 'Temperature'; $d.temperatureMaxC = Get-Prop $rc 'TemperatureMax'
                $d.readErrorsUncorrected = Get-Prop $rc 'ReadErrorsUncorrected'; $d.writeErrorsUncorrected = Get-Prop $rc 'WriteErrorsUncorrected'; $d.powerOnHours = Get-Prop $rc 'PowerOnHours'
            }
            $d
        }
    })
    $hw.battery = Part 'battery' {
        if (-not (Get-CimInstance Win32_Battery)) { return $null }
        # Capacities only; the battery's serial number in the same classes is not read.
        $design = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1).DesignedCapacity
        $full = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1).FullChargedCapacity
        $cycles = try { (Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount -ErrorAction Stop | Select-Object -First 1).CycleCount } catch { $null }
        [ordered]@{ designMWh = [double]$design; fullMWh = [double]$full; cycleCount = $(if ($cycles) { [int]$cycles } else { $null })
            healthPercent = $(if ($design -gt 0) { [math]::Round(100 * $full / $design, 1) } else { $null }) }
    }
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

    # Event log: counts per component and event ID for the last 7 days. The message text is never read, because it
    # can contain names and paths.
    $inv.eventLog = Part 'eventLog' {
        $since = (Get-Date).AddDays(-7)
        $queries = @(
            @{ LogName = 'System'; Level = 1, 2; StartTime = $since },
            @{ LogName = 'Application'; Level = 1, 2; StartTime = $since },
            @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Level = 3; StartTime = $since }
        )
        $levelName = @{ 1 = 'critical'; 2 = 'error'; 3 = 'warning' }
        $rows = foreach ($q in $queries) {
            try { $events = @(Get-WinEvent -FilterHashtable $q -MaxEvents 5000 -ErrorAction Stop) }
            catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue } throw }
            # Newest first, so the first event in each group is the latest one.
            foreach ($g in ($events | Group-Object ProviderName, Id, Level)) {
                $e = $g.Group[0]
                [ordered]@{ log = $q.LogName; provider = $e.ProviderName; eventId = [int]$e.Id; level = $levelName[[int]$e.Level]
                    count = $g.Count; lastSeen = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            }
        }
        [ordered]@{ days = 7; entries = @($rows | Sort-Object { $_['count'] } -Descending | Select-Object -First 150) }
    }

    # Network adapters: physical ones only. The adapter's name in Windows, its MAC address and its IP settings are not
    # read; advanced settings come only from this list (never "Network Address", which can hold a MAC).
    $inv.network = Part 'network' {
        $keep = '*SpeedDuplex', '*EEE', 'AdvancedEEE', 'EEELinkAdvertisement', 'EnableGreenEthernet', '*FlowControl',
                '*InterruptModeration', '*JumboPacket', '*RSS', '*LsoV2IPv4', '*LsoV2IPv6', '*WakeOnMagicPacket',
                '*WakeOnPattern', '*SelectiveSuspend', '*PMARPOffload', '*PMNSOffload', 'RoamAggressiveness',
                'RoamingPreferredBandType', 'PreferredBand', 'ThroughputBoosterEnabled', 'MIMOPowerSaveMode'
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.InterfaceDescription })
        $list = foreach ($a in ($adapters | Select-Object -First 16)) {
            $pm = try { $a | Get-NetAdapterPowerManagement -ErrorAction Stop } catch { $null }
            $adv = @(try { $a | Get-NetAdapterAdvancedProperty -ErrorAction Stop | Where-Object { $_.RegistryKeyword -in $keep } } catch { })
            [ordered]@{
                description = $a.InterfaceDescription; mediaType = "$(Get-Prop $a 'PhysicalMediaType')"; status = "$($a.Status)"
                linkSpeedMbps = $(if ($a.Speed) { [math]::Round([double]$a.Speed / 1e6, 1) } else { 0 })
                fullDuplex = $(if ($null -ne (Get-Prop $a 'FullDuplex')) { [bool]$a.FullDuplex } else { $null })
                driverVersion = "$(@((Get-Prop $a 'DriverVersionString'), (Get-Prop $a 'DriverVersion')) | Where-Object { $_ } | Select-Object -First 1)"; driverDate = (Get-Day (Get-Prop $a 'DriverDate')); driverProvider = "$(Get-Prop $a 'DriverProvider')"
                powerSaving = $(if ($pm) { "$(Get-Prop $pm 'AllowComputerToTurnOffDevice')" } else { $null })
                settings = @($adv | Select-Object -First 40 | ForEach-Object { [ordered]@{ keyword = $_.RegistryKeyword; name = $_.DisplayName; value = "$($_.DisplayValue)" } })
            }
        }
        $wifi = $null
        if ($adapters | Where-Object { (Get-Prop $_ 'PhysicalMediaType') -eq 'Native 802.11' -and "$($_.Status)" -eq 'Up' }) {
            # netsh is the only built-in source for signal strength. Only these lines are read: never SSID, BSSID or profile.
            $lines = @(netsh wlan show interfaces 2>$null)
            $field = { param($Key) foreach ($l in $lines) { if ($l -match "^\s*$Key\s*:\s*(.+?)\s*$") { return $Matches[1] } } $null }
            $number = { param($v) if ("$v" -match '^\d+(\.\d+)?') { [double]$Matches[0] } else { $null } }
            $signal = & $field 'Signal'
            if ($signal) {
                $wifi = [ordered]@{ radioType = (& $field 'Radio type'); band = (& $field 'Band'); channel = $(if (($c = & $number (& $field 'Channel'))) { [int]$c } else { $null })
                    signalPercent = [int](& $number $signal); receiveMbps = (& $number (& $field 'Receive rate \(Mbps\)')); transmitMbps = (& $number (& $field 'Transmit rate \(Mbps\)')) }
            } else { $errors.Add('wifi: Wi-Fi details are read from English netsh output only') }
        }
        [ordered]@{ adapters = @($list); wifi = $wifi }
    }

    # Network health. The gateway's address is used for the ping and never stored. Internet tests go only to
    # Cloudflare's public speed test (speed.cloudflare.com); DNS timing looks up www.microsoft.com.
    $inv.networkHealth = Part 'networkHealth' {
        $nh = [ordered]@{ via = $null; gateway = $null; internet = $null; dns = $null; speed = $null; speedSkipped = [bool]$SkipSpeedTest }
        function Get-LatencyStats([int]$Sent, $Times) {
            $t = @($Times)
            $st = [ordered]@{ sent = $Sent; received = $t.Count; lossPercent = [math]::Round(100 * ($Sent - $t.Count) / [math]::Max($Sent, 1), 1) }
            if ($t.Count) {
                $st.minMs = [double]($t | Measure-Object -Minimum).Minimum; $st.avgMs = [math]::Round(($t | Measure-Object -Average).Average, 1); $st.maxMs = [double]($t | Measure-Object -Maximum).Maximum
                $diffs = for ($i = 1; $i -lt $t.Count; $i++) { [math]::Abs($t[$i] - $t[$i - 1]) }
                $st.jitterMs = $(if (@($diffs).Count) { [math]::Round((@($diffs) | Measure-Object -Average).Average, 1) } else { 0 })
            }
            $st
        }
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object { [int](Get-Prop $_ 'RouteMetric') + [int](Get-Prop $_ 'InterfaceMetric') } | Select-Object -First 1
        if ($route) {
            $ad = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue
            $nh.via = switch ("$(Get-Prop $ad 'PhysicalMediaType')") { 'Native 802.11' { 'wifi' } '802.3' { 'wired' } default { 'other' } }
            $ping = [System.Net.NetworkInformation.Ping]::new()
            $times = [System.Collections.Generic.List[double]]::new()
            for ($i = 0; $i -lt 20; $i++) {
                try { $r = $ping.Send($route.NextHop, 1000); if ($r.Status -eq 'Success') { $times.Add([double]$r.RoundtripTime) } } catch { }
                Start-Sleep -Milliseconds 100
            }
            $nh.gateway = Get-LatencyStats 20 $times
        } else { $errors.Add('networkHealth: no default gateway') }

        $times = [System.Collections.Generic.List[double]]::new()
        for ($i = 0; $i -lt 10; $i++) {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try { if ($tcp.ConnectAsync('speed.cloudflare.com', 443).Wait(3000) -and $tcp.Connected) { $times.Add([math]::Round($sw.Elapsed.TotalMilliseconds, 1)) } } catch { } finally { $tcp.Dispose() }
        }
        $nh.internet = Get-LatencyStats 10 $times

        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ok = try { [bool](Resolve-DnsName -Name 'www.microsoft.com' -Type A -DnsOnly -ErrorAction Stop) } catch { $false }
        $nh.dns = [ordered]@{ ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1); ok = $ok }

        if (-not $SkipSpeedTest) {
            Add-Type -AssemblyName System.Net.Http
            $http = [System.Net.Http.HttpClient]::new()
            $http.Timeout = [TimeSpan]::FromSeconds(60)
            try {
                function Measure-Download([int]$Bytes) {
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    $resp = $http.GetAsync("https://speed.cloudflare.com/__down?bytes=$Bytes", [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                    $null = $resp.EnsureSuccessStatusCode()
                    $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                    $buf = New-Object byte[] 65536; $total = 0
                    while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) { $total += $n }
                    $stream.Dispose(); $sw.Stop()
                    @{ bytes = $total; mbps = [math]::Round($total * 8 / $sw.Elapsed.TotalSeconds / 1e6, 1) }
                }
                function Measure-Upload([int]$Bytes) {
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    $resp = $http.PostAsync('https://speed.cloudflare.com/__up', [System.Net.Http.ByteArrayContent]::new((New-Object byte[] $Bytes))).GetAwaiter().GetResult()
                    $null = $resp.EnsureSuccessStatusCode(); $sw.Stop()
                    @{ bytes = $Bytes; mbps = [math]::Round($Bytes * 8 / $sw.Elapsed.TotalSeconds / 1e6, 1) }
                }
                # A small transfer first: slow connections stop there instead of waiting on 25 MB.
                $down = Measure-Download 2000000
                if ($down.mbps -ge 10) { $down = Measure-Download 25000000 }
                $up = Measure-Upload 1000000
                if ($up.mbps -ge 5) { $up = Measure-Upload 10000000 }
                $nh.speed = [ordered]@{ downloadMbps = $down.mbps; uploadMbps = $up.mbps; bytesDown = $down.bytes; bytesUp = $up.bytes; server = 'speed.cloudflare.com' }
            } finally { $http.Dispose() }
        }
        $nh
    }

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
