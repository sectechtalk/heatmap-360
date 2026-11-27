<#
.SYNOPSIS
  Runs Maester's Entra ID and Microsoft 365 security checks in a container and saves the result for HeatMap 360's
  Entra posture page.

.DESCRIPTION
  Meant to run weekly as a Task Scheduler task on the computer that hosts HeatMap 360. The setup steps are on the
  "How to set up HeatMap 360" page (#setup).

  Read-only toward the tenant: the app registration made by New-MaesterApp.ps1 holds only Microsoft Graph Read
  permissions. Nothing is installed on this computer: Maester, Pester and the Graph module live in the
  hm360-maester image (tools/entraposture/runner). This script:
    1. reads the tenant ID, client ID and certificate thumbprint from %LOCALAPPDATA%\HeatMap360\maester.json,
    2. signs a one-time sign-in request with that certificate (its private key never leaves the Windows certificate
       store) and gets a Microsoft Graph access token that expires within about an hour,
    3. hands the token to the container on stdin (never on a command line or in an environment variable), and
    4. copies two files per run into -OutputDir: maester-<time>.json (the summary HeatMap 360 reads) and
       maester-<time>.html (Maester's own report).
  The reports name real users, groups and policies. Keep -OutputDir on a local disk: not a synced drive, not git.

  Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
  .\Invoke-MaesterScan.ps1
  Runs the checks now and saves data\entraposture\maester-<time>.json.
#>
[CmdletBinding()]
param(
  [string]$OutputDir,
  [string]$ConfigFile,
  [string]$Image = 'hm360-maester:2.3.0'
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir) { $OutputDir = Join-Path $here '..\..\data\entraposture' }
if (-not $ConfigFile) { $ConfigFile = Join-Path $env:LOCALAPPDATA 'HeatMap360\maester.json' }
if (-not (Test-Path $ConfigFile)) { throw "No $ConfigFile. Run tools\entraposture\New-MaesterApp.ps1 first." }
$config = Get-Content -Raw $ConfigFile | ConvertFrom-Json
foreach ($k in 'tenantId', 'clientId', 'thumbprint') { if (-not $config.$k) { throw "$k is missing from $ConfigFile. Run New-MaesterApp.ps1 again." } }
$cert = Get-Item "Cert:\CurrentUser\My\$($config.thumbprint)" -ErrorAction SilentlyContinue
if (-not $cert) { throw "Certificate $($config.thumbprint) is not in Cert:\CurrentUser\My. Run this as the Windows user who ran New-MaesterApp.ps1." }
if ($cert.NotAfter -lt (Get-Date)) { throw "The Maester certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd')). Make a new one: see Renew on the How to set up page." }
if ($cert.NotAfter -lt (Get-Date).AddDays(30)) { Write-Warning "The Maester certificate expires on $($cert.NotAfter.ToString('yyyy-MM-dd'))." }

# --- Graph token with a certificate-signed client assertion (no module, no secret) ---
function ConvertTo-B64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
$tokenUrl = "https://login.microsoftonline.com/$($config.tenantId)/oauth2/v2.0/token"
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-B64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress
$claims = @{ aud = $tokenUrl; iss = $config.clientId; sub = $config.clientId; jti = [guid]::NewGuid().ToString(); nbf = $now - 60; exp = $now + 600 } | ConvertTo-Json -Compress
$unsigned = (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($claims)))
$key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if (-not $key) { throw "Certificate $($config.thumbprint) has no usable private key for this Windows user." }
$sig = $key.SignData([Text.Encoding]::ASCII.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$body = @{
  client_id             = $config.clientId
  scope                 = 'https://graph.microsoft.com/.default'
  grant_type            = 'client_credentials'
  client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  client_assertion      = "$unsigned.$(ConvertTo-B64Url $sig)"
}
try { $token = (Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing).access_token }
catch { throw "Entra refused the sign-in for app $($config.clientId): $($_.ErrorDetails.Message)" }
$body = $null

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$work = Join-Path $env:TEMP "hm360-maester-$stamp"
New-Item -ItemType Directory -Force -Path $work, $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
$container = "hm360-maester-$stamp"
try {
  # No bind mount: the files are copied out of the stopped container, like the BloodHound collector.
  & docker create -i --name $container $Image | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not create the Maester container. Build it first: docker build -t $Image tools\entraposture\runner" }
  $token | & docker start -ai $container 2>&1 | ForEach-Object { Write-Verbose "$_" }
  $code = $LASTEXITCODE
  $token = $null
  & docker cp "${container}:/out/." $work 2>&1 | ForEach-Object { Write-Verbose "$_" }
  $summaryFile = Join-Path $work 'summary.json'
  if (-not (Test-Path $summaryFile)) { throw "Maester produced no summary (exit code $code). Run with -Verbose to see its output." }
  $summary = Get-Content -Raw $summaryFile | ConvertFrom-Json
  $base = Join-Path $OutputDir "maester-$stamp"
  if (Test-Path (Join-Path $work 'report.html')) { Copy-Item (Join-Path $work 'report.html') "$base.html" }
  # Written last, so the page never sees a summary without its report.
  Copy-Item $summaryFile "$base.json"
  Write-Output ("{0}: {1} passed, {2} failed, {3} skipped of {4} checks. Saved {5}.json" -f
    $summary.tenantName, $summary.counts.passed, $summary.counts.failed, $summary.counts.skipped, $summary.counts.total, $base)
}
finally {
  $token = $null
  & docker rm -f $container 2>&1 | Out-Null
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
