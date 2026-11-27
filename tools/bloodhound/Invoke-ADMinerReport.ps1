<#
.SYNOPSIS
  Builds an AD Miner report from the data the local BloodHound CE already holds and saves it for HeatMap 360's
  Attack paths page.

.DESCRIPTION
  Run it by hand whenever you want a fresh report, for example after a BloodHound collection. The setup steps are on
  the "How to set up HeatMap 360" page (#setup).

  It never contacts Active Directory: AD Miner (GPL-3.0, github.com/AD-Security/AD_Miner) only analyses the graph that
  BloodHound has already imported. AD Miner changes the database it analyses (it adds its own properties and
  relationships and deletes objects it cannot place, BloodHound's own bookkeeping record among them), so it never gets
  BloodHound's own database. This script:
    1. checks that BloodHound is idle, stops BloodHound and its Neo4j for about half a minute, copies the Neo4j data
       volume and starts both again,
    2. starts a throwaway Neo4j on the copy, with sign-in turned off and no network at all,
    3. runs AD Miner (image hm360-adminer, built from tools/bloodhound/adminer) inside that container's own loopback,
       so it can reach the copy and nothing else, with a time limit and a memory limit, and
    4. saves two files in -OutputDir: adminer-<time>.zip (the HTML report) and adminer-<time>.json (what the Attack
       paths page lists), then removes the copy, the containers and the volumes.
  The report names real accounts, groups and computers. Keep -OutputDir on a local disk: not a synced drive, not git.

  Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
  .\Invoke-ADMinerReport.ps1
  Builds a report now and saves data\attackpaths\adminer\adminer-<time>.zip.

.EXAMPLE
  .\Invoke-ADMinerReport.ps1 -ExtractDate 20261122
  Tells AD Miner the day the data was collected. By default it uses the newest sign-in date it finds in the data.
#>
[CmdletBinding()]
param(
  [string]$OutputDir,
  [string]$BloodHoundUrl = 'http://127.0.0.1:3461',
  [string]$EnvFile,
  [ValidatePattern('^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$')][string]$Image = 'hm360-adminer:1.9.0',
  [ValidatePattern('^[a-z0-9][a-z0-9_-]*$')][string]$ComposeProject = 'hm360-bloodhound',
  [ValidatePattern('^$|^[0-9]{8}$')][string]$ExtractDate,
  [ValidateRange(1, 3650)][int]$PasswordRenewalDays = 90,
  [ValidateRange(5, 1440)][int]$TimeLimitMinutes = 120,
  [ValidateRange(1, 1024)][int]$MemoryGB = 8
)
$ErrorActionPreference = 'Stop'
# Defaults are filled in here, not in param(): Windows PowerShell 5.1 leaves $PSScriptRoot empty inside param() when the
# script is started with powershell.exe -File.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir) { $OutputDir = Join-Path $here '..\..\data\attackpaths\adminer' }
if (-not $EnvFile) { $EnvFile = Join-Path $here '.env' }

# Runs docker and returns its output as plain lines; $LASTEXITCODE says whether it worked. Windows PowerShell 5.1 turns
# anything a program writes to stderr into a terminating error when $ErrorActionPreference is 'Stop', so the preference
# is relaxed inside this function only. Always pass one array, and no argument with a double quote in it: 5.1 does not
# hand those to a program intact.
function Invoke-Docker {
  param([Parameter(Mandatory)][string[]]$DockerArgs)
  $ErrorActionPreference = 'Continue'
  & docker @DockerArgs 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" } }
}
function Invoke-DockerChecked {
  param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][string[]]$DockerArgs)
  $out = @(Invoke-Docker $DockerArgs)
  if ($LASTEXITCODE -ne 0) { throw "Could not $What (docker exit code $LASTEXITCODE). $(($out | Select-Object -Last 3) -join ' ')" }
  $out
}
# One container of BloodHound's compose project, by its service name.
function Get-ComposeContainer([string]$Service) {
  @(Invoke-Docker @('ps', '-a', '--filter', "label=com.docker.compose.project=$ComposeProject", '--filter', "label=com.docker.compose.service=$Service", '--format', '{{.Names}}')) |
    Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9_.-]*$' } | Select-Object -First 1
}
function Test-Running([string]$Container) { (@(Invoke-Docker @('inspect', '--format', '{{.State.Running}}', $Container)) -join '') -eq 'true' }
# Everything a run creates carries this label, so a run that was cut short is cleaned up by the next one.
$Label = 'hm360.adminer'
function Remove-ADMinerLeftovers {
  foreach ($id in @(Invoke-Docker @('ps', '-aq', '--filter', "label=$Label"))) { if ($id -match '^[0-9a-f]+$') { Invoke-Docker @('rm', '-f', '-v', $id) | Out-Null } }
  foreach ($v in @(Invoke-Docker @('volume', 'ls', '-q', '--filter', "label=$Label"))) { if ($v -match '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { Invoke-Docker @('volume', 'rm', $v) | Out-Null } }
  Get-ChildItem $env:TEMP -Directory -Filter 'hm360-adminer-*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
# BloodHound's answer to "what are you doing?" ('idle' when nothing is being imported or analysed), plus the domains it
# has collected. Throws when BloodHound does not answer.
$api = $BloodHoundUrl.TrimEnd('/')
function Get-BloodHoundState {
  $login = Invoke-RestMethod -Method Post -Uri "$api/api/v2/login" -ContentType 'application/json' -UseBasicParsing `
    -Body (@{ login_method = 'secret'; username = 'admin'; secret = $adminPassword } | ConvertTo-Json)
  $auth = @{ Authorization = "Bearer $($login.data.session_token)" }
  [pscustomobject]@{
    Status    = "$((Invoke-RestMethod -Method Get -Uri "$api/api/v2/datapipe/status" -Headers $auth -UseBasicParsing).data.status)"
    Collected = @((Invoke-RestMethod -Method Get -Uri "$api/api/v2/available-domains" -Headers $auth -UseBasicParsing).data | Where-Object { $_.collected }).Count
  }
}
# Waits until BloodHound's Neo4j answers on its own HTTP port and BloodHound answers a sign-in. $false after 4 minutes.
function Wait-BloodHound([string]$GraphDb) {
  $deadline = (Get-Date).AddMinutes(2)
  do {
    Invoke-Docker @('exec', $GraphDb, 'wget', '-q', '-O', '/dev/null', 'http://localhost:7474') | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)
  $deadline = (Get-Date).AddMinutes(2)
  do {
    try { Get-BloodHoundState | Out-Null; return $true } catch { Start-Sleep -Seconds 3 }
  } while ((Get-Date) -lt $deadline)
  $false
}

if (-not (Test-Path $EnvFile)) { throw "No $EnvFile. Set up BloodHound first: see the How to set up page." }
$adminPassword = (Get-Content $EnvFile | Where-Object { $_ -like 'BH_ADMIN_PASSWORD=*' } | Select-Object -First 1) -replace '^BH_ADMIN_PASSWORD=', ''
if (-not $adminPassword) { throw "BH_ADMIN_PASSWORD is missing from $EnvFile." }
Invoke-Docker @('image', 'inspect', '--format', '{{.Id}}', $Image) | Out-Null
if ($LASTEXITCODE -ne 0) { throw "The $Image image is not there (or Docker is not running). Build it first: docker build -t $Image tools\bloodhound\adminer" }
$graphDb = Get-ComposeContainer 'graph-db'
$app = Get-ComposeContainer 'bloodhound'
if (-not $graphDb -or -not $app) { throw "BloodHound's containers were not found (compose project $ComposeProject). Set up BloodHound first: see the How to set up page." }
# The copy helper and the throwaway Neo4j use the very image BloodHound's Neo4j runs, by its ID, so they can read its
# files. --pull never everywhere: a missing image must stop the run, not fetch something from the internet.
$neoImage = (@(Invoke-DockerChecked 'read which Neo4j image BloodHound uses' @('inspect', '--format', '{{.Image}}', $graphDb)) -join '').Trim()
$mounts = (@(Invoke-DockerChecked "read the volumes of $graphDb" @('inspect', '--format', '{{json .Mounts}}', $graphDb)) -join '') | ConvertFrom-Json
$sourceVolume = (@($mounts) | Where-Object { $_.Destination -eq '/data' -and $_.Type -eq 'volume' } | Select-Object -First 1).Name
if ($neoImage -notmatch '^sha256:[0-9a-f]{64}$' -or "$sourceVolume" -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw "Could not find the Neo4j image and data volume of $graphDb." }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$dataVolume = "hm360-adminer-data-$stamp"     # the copy of BloodHound's Neo4j data
$reportVolume = "hm360-adminer-out-$stamp"    # where AD Miner writes
$copyDb = "hm360-adminer-db-$stamp"
$runner = "hm360-adminer-run-$stamp"
$work = Join-Path $env:TEMP "hm360-adminer-$stamp"
$marked = @('--pull', 'never', '--label', "$Label=$stamp")
$hardening = @('--cap-drop', 'ALL', '--security-opt', 'no-new-privileges')
# One answer column from the throwaway Neo4j, without the header line and the quotes cypher-shell puts around text.
function Invoke-CopyQuery([string]$Query) {
  $out = @(Invoke-Docker @('exec', $copyDb, 'cypher-shell', '-a', 'bolt://localhost:7687', '--format', 'plain', $Query))
  if ($LASTEXITCODE -eq 0) { $out | Select-Object -Skip 1 | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ } }
}
# A short-lived container of the AD Miner image, with no network, that works on the report volume. The report is
# listed, renamed and zipped there, so its hundreds of files never have to be unpacked on this computer.
function Invoke-ReportTool {
  param([Parameter(Mandatory)][string]$Program, [string[]]$ProgramArgs = @())
  Invoke-Docker (@('run', '--rm', '--network', 'none') + $marked + $hardening + @('-v', "${reportVolume}:/out", '-w', '/out', '--entrypoint', $Program, $Image) + $ProgramArgs)
}

# Docker's output is UTF-8; Windows PowerShell 5.1 reads it with the console's code page unless told otherwise.
$consoleEncoding = $null
try { $consoleEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { }
# One report at a time on this computer: every run stops BloodHound's database for a moment and cleans up after runs
# that were cut short, so two at once would trip over each other.
$lock = New-Object System.Threading.Mutex($false, 'Global\hm360-bloodhound')
$haveLock = $false
try {
  try {
    $haveLock = $lock.WaitOne(0)
    if (-not $haveLock) {
      Write-Output 'Another report is being built. Waiting up to 30 minutes for it to finish.'
      $haveLock = $lock.WaitOne([TimeSpan]::FromMinutes(30))
    }
  } catch [System.Threading.AbandonedMutexException] { $haveLock = $true } # the other run was cut short; the lock is ours now
  if (-not $haveLock) { throw 'Another report is still being built. Try again when it has finished.' }

  # A run that was cut short (window closed, computer restarted) may have left its copy behind and BloodHound stopped.
  Remove-ADMinerLeftovers
  if (-not (Test-Running $graphDb) -or -not (Test-Running $app)) {
    Write-Output 'BloodHound is stopped. Starting it.'
    Invoke-DockerChecked "start $graphDb" @('start', $graphDb) | Out-Null
    Invoke-DockerChecked "start $app" @('start', $app) | Out-Null
  }
  if (-not (Wait-BloodHound $graphDb)) { throw "BloodHound at $api does not answer. Check it with: docker compose ps (in tools\bloodhound)." }

  New-Item -ItemType Directory -Force -Path $work, $OutputDir | Out-Null
  $OutputDir = (Resolve-Path $OutputDir).Path
  foreach ($v in $dataVolume, $reportVolume) { Invoke-DockerChecked 'create a temporary volume' @('volume', 'create', '--label', "$Label=$stamp", $v) | Out-Null }

  # 1. Copy BloodHound's graph while BloodHound is stopped, then bring BloodHound back whatever happened. BloodHound
  #    must be idle (stopping its database in the middle of an import would spoil the import) and must hold a domain.
  $state = Get-BloodHoundState
  if ($state.Status -ne 'idle') { throw "BloodHound is busy ($($state.Status)). Try again when its import has finished." }
  if (-not $state.Collected) { throw 'BloodHound holds no collected domain yet. Run a collection first (Invoke-BloodHoundScan.ps1).' }
  Write-Output "Copying BloodHound's database. BloodHound is unavailable for about half a minute."
  try {
    Invoke-DockerChecked "stop $app" @('stop', $app) | Out-Null
    Invoke-DockerChecked "stop $graphDb" @('stop', '-t', '120', $graphDb) | Out-Null
    # A helper container with no network copies the volume. Neo4j is stopped, so the copy is a consistent database.
    Invoke-DockerChecked "copy the Neo4j volume $sourceVolume" (@('run', '--rm', '--network', 'none', '--user', '0') + $marked + @('--entrypoint', 'cp',
      '-v', "${sourceVolume}:/from:ro", '-v', "${dataVolume}:/to", $neoImage, '-a', '/from/.', '/to/')) | Out-Null
  }
  finally {
    Invoke-Docker @('start', $graphDb) | Out-Null
    $dbStarted = $LASTEXITCODE -eq 0
    $deadline = (Get-Date).AddMinutes(3)
    do {
      Start-Sleep -Seconds 2
      Invoke-Docker @('exec', $graphDb, 'wget', '-q', '-O', '/dev/null', 'http://localhost:7474') | Out-Null
    } while ($LASTEXITCODE -ne 0 -and (Get-Date) -lt $deadline)
    Invoke-Docker @('start', $app) | Out-Null
    if (-not $dbStarted -or $LASTEXITCODE -ne 0) { Write-Warning "BloodHound did not start again. Start it by hand: docker start $graphDb $app" }
  }

  # 2. A throwaway Neo4j on the copy, as Neo4j's own non-root user, with no network: nothing can reach it and it can
  #    reach nothing. Sign-in is off, so AD Miner never sees a real password. The hosts entry makes AD Miner's "is there
  #    a newer version?" request fail at once instead of waiting on a name lookup.
  Invoke-DockerChecked 'start the throwaway Neo4j' (@('run', '-d', '--name', $copyDb, '--network', 'none', '--hostname', 'localhost', '--add-host', 'www.ad-miner.com:127.0.0.1') +
    $marked + $hardening + @('--user', '7474:7474', '--pids-limit', '2048', '--memory', '3g', '-v', "${dataVolume}:/data", '-e', 'NEO4J_AUTH=none',
      '-e', 'NEO4J_dbms_memory_heap_initial__size=512m', '-e', 'NEO4J_dbms_memory_heap_max__size=1g', '-e', 'NEO4J_dbms_memory_pagecache_size=512m', $neoImage)) | Out-Null
  $objects = $null
  $deadline = (Get-Date).AddMinutes(5)
  do {
    Start-Sleep -Seconds 2
    $answer = @(Invoke-CopyQuery 'MATCH (n) RETURN count(n)')
    if ($answer.Count -and "$($answer[-1])" -match '^[0-9]+$') { $objects = [long]$answer[-1] }
  } while ($null -eq $objects -and (Get-Date) -lt $deadline -and (Test-Running $copyDb))
  if ($null -eq $objects) { throw "The throwaway Neo4j did not start on the copy. Its last lines: $((@(Invoke-Docker @('logs', '--tail', '5', $copyDb))) -join ' ')" }
  $domains = @(Invoke-CopyQuery 'MATCH (d:Domain) WHERE d.collected = true RETURN d.name ORDER BY d.name')
  if (-not $domains.Count) { $domains = @(Invoke-CopyQuery 'MATCH (d:Domain) RETURN d.name ORDER BY d.name') }
  $domains = @($domains | Where-Object { $_ -match '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$' -and $_ -notmatch '\.\.' } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
  if (-not $domains.Count) { throw 'The copy of BloodHound''s database holds no domain. Run a collection first (Invoke-BloodHoundScan.ps1).' }
  # AD Miner shows this name on the report's front page and uses it in file names.
  $prefix = if ($domains.Count -eq 1) { $domains[0] } else { 'active-directory' }
  $folder = "ADMiner-$prefix-$stamp"

  # 3. AD Miner joins the throwaway Neo4j's network namespace: it sees that container's loopback and nothing else. It
  #    runs as a non-root user with no extra rights and a memory limit, and "timeout" stops it if it hangs (AD Miner
  #    has no time limits of its own). PYTHONUNBUFFERED keeps its last lines when that happens. -Verbose shows its output.
  #    PYTHONHASHSEED=0 makes a report repeatable: AD Miner files an object that BloodHound lists under two kinds (a
  #    group managed service account is both a user and a computer) under whichever kind Python happens to list first,
  #    and without a fixed seed that changed from run to run, moving findings between checks (measured: five runs on
  #    identical copies gave two different sets of ratings).
  Write-Output "Running AD Miner on a copy of $objects objects ($($domains -join ', ')). This takes from seconds to many minutes, depending on the size of the domain."
  $minerArgs = @('create', '--name', $runner, '--network', "container:$copyDb", '--init') + $marked + $hardening + @('--pids-limit', '2048',
    '--memory', "${MemoryGB}g", '--memory-swap', "${MemoryGB}g", '-e', 'PYTHONUNBUFFERED=1', '-e', 'PYTHONHASHSEED=0', '-v', "${reportVolume}:/out",
    '--entrypoint', 'timeout', $Image, '-s', 'INT', '-k', '60', "${TimeLimitMinutes}m",
    'AD-miner', '-b', 'bolt://127.0.0.1:7687', '-u', 'neo4j', '-p', 'not-needed', '-cf', $prefix, '-r', "$PasswordRenewalDays")
  if ($ExtractDate) { $minerArgs += @('-e', $ExtractDate) }
  Invoke-DockerChecked 'create the AD Miner container' $minerArgs | Out-Null
  $colourCodes = [regex]"$([char]27)\[[0-9;]*m" # AD Miner colours its lines for a terminal
  $log = @(Invoke-Docker @('start', '-a', $runner) | ForEach-Object { $colourCodes.Replace($_, '') })
  $code = $LASTEXITCODE
  $log | ForEach-Object { Write-Verbose $_ }
  $tail = (@($log | Where-Object { $_.Trim() } | Select-Object -Last 4)) -join ' | '
  if ($code -ne 0) {
    $outOfMemory = (@(Invoke-Docker @('inspect', '--format', '{{.State.OOMKilled}}', $runner)) -join '') -eq 'true'
    if ($outOfMemory) { throw "AD Miner ran out of memory (limit $MemoryGB GB). Give it more with -MemoryGB. Its last lines: $tail" }
    if ($code -eq 124 -or $code -eq 137) { throw "AD Miner did not finish within $TimeLimitMinutes minutes and was stopped. Give it longer with -TimeLimitMinutes. Its last lines: $tail" }
    throw "AD Miner stopped with exit code $code. Its last lines: $tail"
  }
  Invoke-ReportTool 'test' @('-f', "/out/render_$prefix/html/index.html") | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "AD Miner finished but wrote no front page. Its last lines: $tail" }

  # 4. What the Attack paths page lists: the ratings AD Miner gave, taken from two small files of the report.
  #    AD Miner carries on when one of its database questions or checks fails, so those are noted too.
  $failedRequests = @($log | ForEach-Object { if ($_ -match 'No result found for request ([A-Za-z0-9_-]{1,80})\.') { $Matches[1] } } | Select-Object -Unique)
  $failedControls = @(@(for ($i = 0; $i -lt $log.Count - 1; $i++) {
    if ($log[$i] -match 'Error while running the following control') {
      $id = ($log[$i + 1] -replace '^\s*\[!\]\s*', '').Trim() # the next line names the check
      if ($id -match '^[A-Za-z0-9_.-]{1,80}$') { $id }
    }
  }) | Select-Object -Unique)
  $version = ($Image -split ':')[-1]
  $dataDate = $null
  $dataName = @(Invoke-ReportTool 'ls' @("/out/render_$prefix")) | Where-Object { $_ -match '^data_[A-Za-z0-9._-]+_[0-9]{8}\.json$' } | Select-Object -First 1
  if ($dataName) {
    Invoke-DockerChecked "copy AD Miner's summary numbers out" @('cp', "${runner}:/out/render_$prefix/$dataName", (Join-Path $work 'data.json')) | Out-Null
    $data = Get-Content -Raw -Encoding UTF8 (Join-Path $work 'data.json') | ConvertFrom-Json
    if ("$($data.AD_miner_version)" -match '^[0-9A-Za-z.+-]{1,40}$' -and "$($data.AD_miner_version)" -ne 'unknown') { $version = "$($data.AD_miner_version)" }
    if ("$($data.datetime)" -match '^([0-9]{2})/([0-9]{2})/([0-9]{4})$') { $dataDate = "$($Matches[3])-$($Matches[2])-$($Matches[1])" }
  }
  if ($dataDate -and [int]$dataDate.Substring(0, 4) -lt 2000) {
    throw "AD Miner could not tell when the data was collected (it chose $dataDate), so every age in the report would be wrong. Run again with -ExtractDate <yyyyMMdd>."
  }
  $controls = @()
  try {
    Invoke-DockerChecked "copy AD Miner's ratings out" @('cp', "${runner}:/out/render_$prefix/js/main_circle.js", (Join-Path $work 'main_circle.js')) | Out-Null
    # One line of that file is "var dico_entry = {...}": every check with its title, colour and area, as JSON.
    $line = Get-Content -Encoding UTF8 (Join-Path $work 'main_circle.js') | Where-Object { $_ -match '^\s*var dico_entry = \{' } | Select-Object -First 1
    $entries = ($line -replace '^\s*var dico_entry = ', '').Trim().TrimEnd(';') | ConvertFrom-Json
    $controls = @(foreach ($p in $entries.PSObject.Properties) {
      $rating = "$($p.Value.color)"
      if ($p.Name -notmatch '^[A-Za-z0-9_.-]{1,80}$' -or @('red', 'orange', 'yellow', 'green', 'grey') -notcontains $rating) { continue }
      $name = "$($p.Value.name)"
      if ($name.Length -gt 200) { $name = $name.Substring(0, 200) }
      $area = if ("$($p.Value.category)" -match '^[a-z_]{1,40}$') { "$($p.Value.category)" } else { '' }
      [ordered]@{ id = $p.Name; name = $name; rating = $rating; area = $area }
    })
  } catch { Write-Warning "Could not read AD Miner's ratings from the report, so the page will list the report without them: $($_.Exception.Message)" }

  # 5. One zip, with a folder name that says what it is, made inside a container and copied out as a single file.
  #    It is written before the details file, so the page never lists a report whose zip is not there yet.
  Invoke-ReportTool 'mv' @("/out/render_$prefix", "/out/$folder") | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not rename the report folder.' }
  $fileList = @(Invoke-ReportTool 'find' @("/out/$folder", '-type', 'f'))
  $files = $fileList.Count
  # AD Miner names some pages after directory objects. Windows cannot store a few characters those names may hold.
  $awkward = @($fileList | Where-Object { ($_ -replace '^.*/', '') -match '[<>:"|?*\\]' }).Count
  $zipLog = @(Invoke-ReportTool 'python' @('-m', 'zipfile', '-c', '/out/report.zip', "/out/$folder"))
  if ($LASTEXITCODE -ne 0) { throw "Could not zip the report. $(($zipLog | Select-Object -Last 2) -join ' ')" }
  $base = Join-Path $OutputDir "adminer-$stamp"
  Invoke-DockerChecked 'copy the report zip out' @('cp', "${runner}:/out/report.zip", "$base.zip") | Out-Null
  $details = [ordered]@{
    schema         = 'hm360.adminer/1'
    tool           = 'AD Miner'
    version        = $version
    domains        = $domains
    generatedAt    = (Get-Date).ToUniversalTime().ToString('o')
    dataDate       = $dataDate
    objects        = $objects
    files          = $files
    failedRequests = $failedRequests
    failedControls = $failedControls
    controls       = $controls
  }
  [IO.File]::WriteAllText("$base.json", ($details | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))

  $count = { param($rating) @($controls | Where-Object { $_.rating -eq $rating }).Count }
  $zipBytes = (Get-Item "$base.zip").Length
  Write-Output ("{0}: AD Miner {1} rated {2} checks immediate risk, {3} potential risk, {4} minor risk and {5} handled; {6} not evaluated. {7} files, {8:N1} MB zipped. Saved {9}.zip" -f
    ($domains -join ', '), $version, (& $count 'red'), (& $count 'orange'), (& $count 'yellow'), (& $count 'green'), (& $count 'grey'), $files, ($zipBytes / 1MB), $base)
  if ($failedRequests.Count) { Write-Warning "$($failedRequests.Count) of AD Miner's database questions failed, so parts of the report may be missing: $($failedRequests -join ', '). Run with -Verbose to see why." }
  if ($failedControls.Count) { Write-Warning "AD Miner's log reports $($failedControls.Count) of its checks failing on this data. The report shows a failed check as not evaluated: $($failedControls -join ', ')." }
  if ($awkward) { Write-Warning "$awkward pages of the report have names Windows cannot store (they come from object names in the directory). Those pages will be missing or renamed when the zip is unpacked on Windows." }
  if ($zipBytes -gt 2GB) { Write-Warning 'The zip is larger than 2 GB, which is more than the Attack paths page offers as a download. Open it from the folder instead.' }
  if (-not (Wait-BloodHound $graphDb)) { Write-Warning "BloodHound has not answered since it was restarted. Check it with: docker compose ps (in tools\bloodhound)." }
}
finally {
  # Nothing of the run is left behind: the copy of the directory data goes with the containers and the volumes.
  foreach ($c in $runner, $copyDb) { Invoke-Docker @('rm', '-f', '-v', $c) | Out-Null }
  foreach ($v in $dataVolume, $reportVolume) { Invoke-Docker @('volume', 'rm', $v) | Out-Null }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  if ($haveLock) { try { $lock.ReleaseMutex() } catch { } }
  $lock.Dispose()
  if ($consoleEncoding) { try { [Console]::OutputEncoding = $consoleEncoding } catch { } }
}
