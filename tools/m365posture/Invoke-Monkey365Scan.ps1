<#
.SYNOPSIS
  Runs Monkey365's CIS benchmark checks for Exchange Online, Microsoft Teams, Microsoft Purview and Azure in a container
  and saves the result for HeatMap 360's M365 & Azure posture page.

.DESCRIPTION
  Meant to run weekly as a Task Scheduler task on the computer that hosts HeatMap 360. The setup steps are on the
  "How to set up HeatMap 360" page (#setup).

  Read-only toward the tenant: the app made by New-Monkey365App.ps1 holds only read permissions (see that script).
  Entra ID itself is left to Maester on the Entra posture page, so this scan does not repeat it. Nothing is installed
  on this computer: Monkey365 lives in the hm360-monkey365 image (tools/m365posture/runner). This script:
    1. reads the tenant ID, client ID, certificate thumbprint and Azure subscriptions from
       %LOCALAPPDATA%\HeatMap360\monkey365.json,
    2. copies the app's certificate out of your Windows certificate store into memory as a PFX locked with a one-time
       random password (Monkey365 signs in to Exchange, Teams and Azure itself, so it needs the certificate, not a token),
    3. hands that to the container on stdin (never on disk, on a command line or in an environment variable), and
    4. copies the files of each run into -OutputDir: monkey365-<time>.json (the summary HeatMap 360 reads) and
       monkey365-<time>-microsoft365.html / -azure.html (Monkey365's own reports).
  The reports name real mailboxes, users and resources. Keep -OutputDir on a local disk: not a synced drive, not git.

  Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
  .\Invoke-Monkey365Scan.ps1
  Runs the checks now and saves data\m365posture\monkey365-<time>.json.
#>
[CmdletBinding()]
param(
  [string]$OutputDir,
  [string]$ConfigFile,
  [string]$Image = 'hm360-monkey365:1.0.5'
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir) { $OutputDir = Join-Path $here '..\..\data\m365posture' }
if (-not $ConfigFile) { $ConfigFile = Join-Path $env:LOCALAPPDATA 'HeatMap360\monkey365.json' }
if (-not (Test-Path $ConfigFile)) { throw "No $ConfigFile. Run tools\m365posture\New-Monkey365App.ps1 first." }
$config = Get-Content -Raw $ConfigFile | ConvertFrom-Json
foreach ($k in 'tenantId', 'clientId', 'thumbprint') { if (-not $config.$k) { throw "$k is missing from $ConfigFile. Run New-Monkey365App.ps1 again." } }
$cert = Get-Item "Cert:\CurrentUser\My\$($config.thumbprint)" -ErrorAction SilentlyContinue
if (-not $cert) { throw "Certificate $($config.thumbprint) is not in Cert:\CurrentUser\My. Run this as the Windows user who ran New-Monkey365App.ps1." }
if ($cert.NotAfter -lt (Get-Date)) { throw "The Monkey365 certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd')). Make a new one: see Renew on the How to set up page." }
if ($cert.NotAfter -lt (Get-Date).AddDays(30)) { Write-Warning "The Monkey365 certificate expires on $($cert.NotAfter.ToString('yyyy-MM-dd'))." }

# One-time password for the in-memory PFX; it exists only for this run.
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$buf = New-Object byte[] 32; $rng.GetBytes($buf)
$password = [Convert]::ToBase64String($buf); [Array]::Clear($buf, 0, $buf.Length)
try { $pfx = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password) }
catch { throw "Could not read the private key of certificate $($config.thumbprint) for this Windows user: $($_.Exception.Message)" }
$settings = @{
  tenantId      = [string]$config.tenantId
  clientId      = [string]$config.clientId
  pfx           = [Convert]::ToBase64String($pfx)
  password      = $password
  services      = @($config.services)
  subscriptions = @($config.subscriptions)
} | ConvertTo-Json -Compress
[Array]::Clear($pfx, 0, $pfx.Length); $pfx = $null; $password = $null

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$work = Join-Path $env:TEMP "hm360-monkey365-$stamp"
New-Item -ItemType Directory -Force -Path $work, $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
$container = "hm360-monkey365-$stamp"
try {
  # No bind mount: the files are copied out of the stopped container, like the Maester runner.
  & docker create -i --name $container $Image | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not create the Monkey365 container. Build it first: docker build -t $Image tools\m365posture\runner" }
  $settings | & docker start -ai $container 2>&1 | ForEach-Object { Write-Verbose "$_" }
  $code = $LASTEXITCODE
  $settings = $null
  & docker cp "${container}:/out/." $work 2>&1 | ForEach-Object { Write-Verbose "$_" }
  $summaryFile = Join-Path $work 'summary.json'
  if (-not (Test-Path $summaryFile)) { throw "Monkey365 produced no summary (exit code $code). Run with -Verbose to see its output." }
  $summary = Get-Content -Raw $summaryFile | ConvertFrom-Json
  $base = Join-Path $OutputDir "monkey365-$stamp"
  foreach ($area in 'microsoft365', 'azure') {
    $html = Join-Path $work "report-$area.html"
    if (Test-Path $html) { Copy-Item $html "$base-$area.html" }
  }
  # Written last, so the page never sees a summary without its reports.
  Copy-Item $summaryFile "$base.json"
  foreach ($r in @($summary.runs)) { if ($r.error) { Write-Warning "$($r.area) did not finish: $($r.error)" } }
  Write-Output ("{0}: {1} passed, {2} failed, {3} to check by hand, of {4} rules. Saved {5}.json" -f
    $summary.tenantName, $summary.counts.passed, $summary.counts.failed, $summary.counts.manual, $summary.counts.total, $base)
}
finally {
  $settings = $null
  & docker rm -f $container 2>&1 | Out-Null
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
