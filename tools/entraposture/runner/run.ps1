# Runs inside the hm360-maester container. Reads a Microsoft Graph access token from stdin, runs Maester's read-only
# checks and writes two files to /out:
#   summary.json  { schema: hm360.entraposture/1, tool, engineVersion, tenantId, tenantName, generatedAt, counts, tests }
#   report.html   Maester's own report (offered as a download on the Entra posture page, never rendered in it)
# The token is never written to disk or printed. Maester's telemetry and version check are turned off.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Windows PowerShell pipes a byte order mark before the line and a CR after it, so take just the token's characters.
$token = if ("$([Console]::In.ReadLine())" -match '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*') { $Matches[0] } else { $null }
if (-not $token) { throw 'No Graph access token on stdin.' }
Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
Remove-Variable token; $Matches = $null

$work = '/tmp/maester'
$params = @{
  Path = '/maester/tests'; OutputFolder = $work; OutputFolderFileName = 'maester'
  SkipGraphConnect = $true; NonInteractive = $true; DisableTelemetry = $true; SkipVersionCheck = $true; NoLogo = $true
}
Invoke-Maester @params | Out-Null
$json = Join-Path $work 'maester.json'
if (-not (Test-Path $json)) { throw 'Maester wrote no results.' }
$r = Get-Content -Raw $json | ConvertFrom-Json

$cut = { param($v, $n) $s = [string]$v; if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
$tests = @(foreach ($t in @($r.Tests)) {
  $id = if ($t.Id) { [string]$t.Id } else { [string]$t.Name }
  [ordered]@{
    id       = (& $cut $id 120)
    title    = (& $cut ($(if ($t.Title) { $t.Title } else { $t.Name })) 500)
    result   = [string]$t.Result
    severity = [string]$t.Severity
    block    = (& $cut $t.Block 200)
    helpUrl  = $(if ([string]$t.HelpUrl -match '^https://[^\s"<>]+$') { & $cut $t.HelpUrl 500 } else { '' })
  }
})
$count = { param($name) @($tests | Where-Object { $_.result -eq $name }).Count }
$summary = [ordered]@{
  schema        = 'hm360.entraposture/1'
  tool          = 'Maester'
  engineVersion = [string](Get-Module Maester).Version
  tenantId      = [string]$r.TenantId
  tenantName    = (& $cut $r.TenantName 200)
  generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
  counts        = [ordered]@{
    total = $tests.Count; passed = (& $count 'Passed'); failed = (& $count 'Failed'); skipped = (& $count 'Skipped')
    notRun = (& $count 'NotRun'); error = (& $count 'Error'); investigate = (& $count 'Investigate')
  }
  tests         = $tests
}
$html = Join-Path $work 'maester.html'
if (Test-Path $html) { Copy-Item $html /out/report.html }
# Written last, so the host never copies a summary without its report. UTF-8 without a byte order mark.
[IO.File]::WriteAllText('/out/summary.json', ($summary | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
Write-Output ("{0}: {1} passed, {2} failed, {3} skipped of {4} checks." -f $summary.tenantName, $summary.counts.passed, $summary.counts.failed, $summary.counts.skipped, $summary.counts.total)
