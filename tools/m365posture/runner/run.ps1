# Runs inside the hm360-monkey365 container. Reads one line of JSON from stdin:
#   { tenantId, clientId, pfx (base64), password, services: [...], subscriptions: [...] }
# loads the app's certificate in memory only, runs Monkey365's read-only checks and writes to /out:
#   summary.json  { schema: hm360.m365posture/1, tool, engineVersion, tenantId, tenantName, generatedAt, runs, counts, rules }
#   report-microsoft365.html, report-azure.html   Monkey365's own reports (downloads on the page, never rendered in it)
# The certificate and its password are never written to disk or printed. The summary keeps one row per rule with how
# many resources failed it, never the resource names (those can name real mailboxes, users and sites).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Windows PowerShell pipes a byte order mark before the line and a CR after it, so take just the JSON object.
$line = [string][Console]::In.ReadLine()
$start = $line.IndexOf('{')
if ($start -lt 0) { throw 'No settings on stdin.' }
$in = $line.Substring($start).Trim() | ConvertFrom-Json
$line = $null
foreach ($k in 'tenantId', 'clientId', 'pfx', 'password') { if (-not $in.$k) { throw "$k is missing from the settings on stdin." } }
$bytes = [Convert]::FromBase64String($in.pfx)
$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, [string]$in.password, $flags)
[Array]::Clear($bytes, 0, $bytes.Length)
$in.pfx = $null; $in.password = $null
if (-not $cert.HasPrivateKey) { throw 'The certificate on stdin has no private key.' }

Import-Module monkey365
$engine = [string](Get-Module monkey365).Version
# SharePoint Online is left out on purpose: Monkey365 needs Sites.FullControl.All for it, which is not read-only.
$allowed = 'ExchangeOnline', 'MicrosoftTeams', 'Purview'
$services = @(@($in.services) | Where-Object { $allowed -contains $_ })
if (-not $services) { $services = @('ExchangeOnline', 'MicrosoftTeams', 'Purview') }
$subs = @(@($in.subscriptions) | Where-Object { "$_" -match '^[0-9a-fA-F-]{36}$' })

$jobs = @(@{ name = 'Microsoft365'; tag = 'microsoft365'; params = @{ Instance = 'Microsoft365'; Collect = $services } })
# Monkey365 1.0.5 takes one subscription per run (-Subscriptions is a single string), so Azure runs once per subscription.
$i = 0
foreach ($s in $subs) { $i++; $jobs += @{ name = 'Azure'; tag = "azure$i"; params = @{ Instance = 'Azure'; Collect = 'All'; Subscriptions = [string]$s } } }

$cut = { param($v, $n) $s = [string]$v; if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
$sevMap = @{ critical = 'Critical'; fatal = 'Critical'; high = 'High'; medium = 'Medium'; low = 'Low'; informational = 'Info'; info = 'Info' }
$statusOf = { param($code) switch -regex ([string]$code) { '^fail' { 'Failed' } '^pass' { 'Passed' } '^manual' { 'Manual' } default { 'Info' } } }
$rank = @{ Failed = 0; Manual = 1; Passed = 2; Info = 3 }
$rules = [ordered]@{}
$runs = [ordered]@{}
$tenantName = ''

foreach ($job in $jobs) {
  $out = "/tmp/monkey-$($job.tag)"
  New-Item -ItemType Directory -Force $out | Out-Null
  $p = $job.params + @{
    TenantId = [string]$in.tenantId; ClientId = [string]$in.clientId; ClientAssertionCertificate = $cert
    ExportTo = @('JSON', 'HTML'); OutDir = $out
  }
  # One record per area: Azure runs for several subscriptions add up into one.
  if (-not $runs.Contains($job.name)) { $runs[$job.name] = [ordered]@{ area = $job.name; ran = $false; findings = 0; error = '' } }
  $run = $runs[$job.name]
  try {
    Invoke-Monkey365 @p | Out-Null
    $files = @(Get-ChildItem -Recurse -File -Path $out -Filter *.json)
    if (-not $files) { throw 'Monkey365 wrote no JSON results.' }
    foreach ($f in $files) {
      # -AsHashtable: Monkey365's JSON can hold keys that differ only in case ("value" and "Value"), which plain
      # ConvertFrom-Json refuses. Hashtable keys are then case-sensitive, so the OCSF names below are spelt exactly.
      foreach ($x in @(Get-Content -Raw $f.FullName | ConvertFrom-Json -AsHashtable)) {
        if ($x -isnot [System.Collections.IDictionary]) { continue }
        if (-not $x.findingInfo) { continue }
        $run.findings++
        if (-not $tenantName -and $x.cloud.organization.name) { $tenantName = & $cut $x.cloud.organization.name 200 }
        $id = if ($x.unmapped.pluginId) { [string]$x.unmapped.pluginId } else { [string]$x.metadata.eventCode }
        if (-not $id) { continue }
        $key = "$($job.name):$id"
        $status = & $statusOf $x.statusCode
        if (-not $rules.Contains($key)) {
          $help = @($x.remediation.references | Where-Object { "$_" -match '^https://[^\s"<>]+$' }) | Select-Object -First 1
          $rules[$key] = [ordered]@{
            id       = (& $cut $id 120)
            code     = (& $cut $x.metadata.eventCode 120)
            title    = (& $cut $x.findingInfo.title 500)
            instance = $job.name
            area     = (& $cut $(if ($x.unmapped.provider) { $x.unmapped.provider } else { $job.name }) 80)
            severity = $(if ($sevMap.ContainsKey(([string]$x.severity).ToLower())) { $sevMap[([string]$x.severity).ToLower()] } else { '' })
            status   = $status
            failed   = 0
            helpUrl  = $(if ($help) { & $cut $help 500 } else { '' })
          }
        }
        $r = $rules[$key]
        if ($status -eq 'Failed') { $r.failed++ }
        if ($rank[$status] -lt $rank[$r.status]) { $r.status = $status }
      }
    }
    $html = Get-ChildItem -Recurse -File -Path $out -Filter *.html | Sort-Object Length -Descending | Select-Object -First 1
    $report = "/out/report-$($job.name.ToLower()).html"
    if ($html -and -not (Test-Path $report)) { Copy-Item $html.FullName $report }
    $run.ran = $true
  }
  catch { $run.error = & $cut "$(if ($run.error) { "$($run.error) " })$($_.Exception.Message)" 300 }
}
$runs = @($runs.Values)
$cert.Dispose(); $cert = $null

$list = @($rules.Values)
$count = { param($name) @($list | Where-Object { $_.status -eq $name }).Count }
$summary = [ordered]@{
  schema        = 'hm360.m365posture/1'
  tool          = 'Monkey365'
  engineVersion = $engine
  tenantId      = [string]$in.tenantId
  tenantName    = $tenantName
  generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
  runs          = $runs
  counts        = [ordered]@{ total = $list.Count; passed = (& $count 'Passed'); failed = (& $count 'Failed'); manual = (& $count 'Manual'); info = (& $count 'Info') }
  rules         = $list
}
# Written last, so the host never copies a summary without its reports. UTF-8 without a byte order mark.
[IO.File]::WriteAllText('/out/summary.json', ($summary | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
foreach ($r in $runs) { if ($r.error) { Write-Output "$($r.area) did not finish: $($r.error)" } }
Write-Output ("{0}: {1} passed, {2} failed, {3} to check by hand, of {4} rules." -f $tenantName, $summary.counts.passed, $summary.counts.failed, $summary.counts.manual, $summary.counts.total)
if (-not @($runs | Where-Object { $_.ran })) { exit 1 }
