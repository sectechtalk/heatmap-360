<#
.SYNOPSIS
  Runs a PingCastle health check of one Active Directory domain and saves it for HeatMap 360's AD posture page.

.DESCRIPTION
  Meant to run weekly as a Task Scheduler task on the computer that hosts HeatMap 360. The setup steps are on the
  "How to set up HeatMap 360" page (#setup).

  Read-only toward the domain: PingCastle's health check only reads Active Directory (LDAP and AD Web Services). This
  script changes nothing in the domain or on any computer. It writes only:
    - the saved credential file (with -SaveCredential), and
    - three files per run in -OutputDir: pingcastle-<time>.json (the summary HeatMap 360 reads), .html (PingCastle's
      report) and .xml (PingCastle's raw data).
  The reports name real accounts, groups and servers. Keep -OutputDir on a local disk: not a synced drive, not git.

  The domain account is a plain domain user (no admin rights). Its password is saved once with -SaveCredential, as a
  file only the same Windows user on the same computer can decrypt (Windows DPAPI). PingCastle takes the password on its
  command line, so local administrators of this computer could see it while the scan runs (a few minutes a week).

.EXAMPLE
  .\Invoke-PingCastleScan.ps1 -SaveCredential
  Asks for the domain account (CONTOSO\svc-hm360-scan) and its password, and saves them for the scheduled task.

.EXAMPLE
  .\Invoke-PingCastleScan.ps1 -Domain contoso.example
  Runs one scan now. -Server dc01.contoso.example picks a domain controller; by default the domain name is used.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
  [Parameter(ParameterSetName = 'Run', Mandatory)][ValidatePattern('^[A-Za-z0-9.-]+$')][string]$Domain,
  [Parameter(ParameterSetName = 'Run')][ValidatePattern('^[A-Za-z0-9.-]+$')][string]$Server,
  [Parameter(ParameterSetName = 'Run')][string]$PingCastleDir = 'C:\src\PingCastle',
  [Parameter(ParameterSetName = 'Run')][string]$OutputDir,
  [string]$CredentialFile,
  [Parameter(ParameterSetName = 'Save', Mandatory)][switch]$SaveCredential
)
$ErrorActionPreference = 'Stop'
# Defaults are filled in here, not in param(): Windows PowerShell 5.1 leaves $PSScriptRoot empty inside param() when
# the script is started with powershell.exe -File, which made Join-Path fail before anything ran.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir) { $OutputDir = Join-Path $here '..\..\data\adposture' }
if (-not $CredentialFile) { $CredentialFile = Join-Path $env:LOCALAPPDATA 'HeatMap360\pingcastle-credential.xml' }

if ($SaveCredential) {
  $cred = Get-Credential -Message 'Plain domain account PingCastle signs in with (DOMAIN\user). No admin rights needed.'
  if (-not $cred) { throw 'No credential entered.' }
  New-Item -ItemType Directory -Force -Path (Split-Path $CredentialFile) | Out-Null
  $cred | Export-Clixml -Path $CredentialFile
  Write-Output "Saved the credential for $($cred.UserName) to $CredentialFile (only this Windows user on this computer can read it)."
  return
}

$exe = Join-Path $PingCastleDir 'PingCastle.exe'
if (-not (Test-Path $exe)) { throw "PingCastle.exe not found in $PingCastleDir. Unzip PingCastle there, or pass -PingCastleDir." }
if (-not (Test-Path $CredentialFile)) { throw "No saved credential at $CredentialFile. Run this script once with -SaveCredential." }
if (-not $Server) { $Server = $Domain }
$cred = Import-Clixml -Path $CredentialFile
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$work = Join-Path $env:TEMP "hm360-pingcastle-$stamp"
New-Item -ItemType Directory -Force -Path $work, $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path

try {
  Push-Location $work
  # PingCastle writes ad_hc_<domain>.html and .xml into the current folder. The password is never printed.
  $pcArgs = @('--healthcheck', '--server', $Server, '--user', $cred.UserName, '--password', $cred.GetNetworkCredential().Password, '--level', 'Full')
  & $exe @pcArgs | Out-Null
  $code = $LASTEXITCODE
  Pop-Location
  $xmlFile = Get-ChildItem $work -Filter 'ad_hc_*.xml' | Select-Object -First 1
  $htmlFile = Get-ChildItem $work -Filter 'ad_hc_*.html' | Select-Object -First 1
  if (-not $xmlFile) { throw "PingCastle produced no report (exit code $code). Check the account, the password and that $Server is reachable on ports 389 and 9389." }

  [xml]$x = Get-Content -Raw -Encoding UTF8 $xmlFile.FullName
  $d = $x.HealthcheckData
  $num = { param($v) if ($null -ne $v -and "$v" -match '^\d+$') { [int]"$v" } else { 0 } }
  $priv = if ($d.PrivilegiedGroupScore) { $d.PrivilegiedGroupScore } else { $d.PrivilegedGroupScore } # PingCastle's own spelling first
  $rules = @(foreach ($r in @($d.RiskRules.HealthcheckRiskRule)) {
    if (-not $r) { continue }
    [ordered]@{ id = [string]$r.RiskId; category = [string]$r.Category; points = (& $num $r.Points); rationale = [string]$r.Rationale; model = [string]$r.Model }
  })
  $summary = [ordered]@{
    schema        = 'hm360.adposture/1'
    tool          = 'PingCastle'
    engineVersion = [string]$d.EngineVersion
    domain        = ([string]$d.DomainFQDN).ToLowerInvariant()
    generatedAt   = ([datetime]$d.GenerationDate).ToUniversalTime().ToString('o')
    maturityLevel = (& $num $d.MaturityLevel)
    scores        = [ordered]@{ global = (& $num $d.GlobalScore); staleObjects = (& $num $d.StaleObjectsScore); privilegedAccounts = (& $num $priv); trusts = (& $num $d.TrustScore); anomalies = (& $num $d.AnomalyScore) }
    rules         = $rules
  }
  $base = Join-Path $OutputDir "pingcastle-$stamp"
  Copy-Item $xmlFile.FullName "$base.xml"
  if ($htmlFile) { Copy-Item $htmlFile.FullName "$base.html" }
  # Written last, so the page never sees a summary without its report. UTF-8 without a byte order mark.
  [IO.File]::WriteAllText("$base.json", ($summary | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
  Write-Output ("{0}: score {1} (stale objects {2}, privileged accounts {3}, trusts {4}, anomalies {5}), {6} rules. Saved {7}.json" -f
    $summary.domain, $summary.scores.global, $summary.scores.staleObjects, $summary.scores.privilegedAccounts, $summary.scores.trusts, $summary.scores.anomalies, $rules.Count, $base)
}
finally {
  if ((Get-Location).Path -eq $work) { Pop-Location }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
