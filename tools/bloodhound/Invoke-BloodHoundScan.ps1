<#
.SYNOPSIS
  Collects one Active Directory domain into the local BloodHound CE and saves an attack path summary for HeatMap 360.

.DESCRIPTION
  Meant to run weekly as a Task Scheduler task on the computer that hosts HeatMap 360, next to the BloodHound CE
  containers from tools/bloodhound/compose.yaml. The setup steps are on the "How to set up HeatMap 360" page (#setup).

  Read-only toward the domain. The collector (bloodhound-ce-python in a throwaway Linux container, built from
  tools/bloodhound/collector) only reads Active Directory over LDAP and, for sessions and local groups, asks computers
  over SMB the same questions any domain user may ask. Nothing is installed on any domain computer. This script writes:
    - the collector's zip and the summary in -OutputDir: bloodhound-<time>.zip and bloodhound-<time>.json, and
    - BloodHound's own database (it clears the previous import first, so the graph always shows the domain as it is now).
  The files name real accounts, groups and computers. Keep -OutputDir on a local disk: not a synced drive, not git.

  The domain account is a plain domain user (no admin rights). By default the script reuses the credential the AD
  posture scan saved (pingcastle-credential.xml); -SaveCredential saves a separate one. Either file can only be read by
  the same Windows user on the same computer (Windows DPAPI). The password reaches the collector as an environment
  variable, never on a command line.

.EXAMPLE
  .\Invoke-BloodHoundScan.ps1 -Domain contoso.example
  Runs one collection now and saves data\attackpaths\bloodhound-<time>.json.

.EXAMPLE
  .\Invoke-BloodHoundScan.ps1 -SaveCredential
  Asks for the domain account (CONTOSO\svc-hm360-scan) and its password, and saves them for this scan only.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
  [Parameter(ParameterSetName = 'Run', Mandatory)][ValidatePattern('^[A-Za-z0-9.-]+$')][string]$Domain,
  [Parameter(ParameterSetName = 'Run')][ValidatePattern('^[A-Za-z0-9.-]+$')][string]$Server,
  [Parameter(ParameterSetName = 'Run')][ValidateSet('All', 'DCOnly', 'Default')][string]$Collection = 'All',
  [Parameter(ParameterSetName = 'Run')][string]$OutputDir,
  [Parameter(ParameterSetName = 'Run')][string]$BloodHoundUrl = 'http://127.0.0.1:3461',
  [Parameter(ParameterSetName = 'Run')][string]$EnvFile,
  [string]$CredentialFile,
  [Parameter(ParameterSetName = 'Save', Mandatory)][switch]$SaveCredential
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutputDir) { $OutputDir = Join-Path $here '..\..\data\attackpaths' }
if (-not $EnvFile) { $EnvFile = Join-Path $here '.env' }
$own = Join-Path $env:LOCALAPPDATA 'HeatMap360\bloodhound-credential.xml'
if (-not $CredentialFile) {
  $CredentialFile = if ($SaveCredential -or (Test-Path $own)) { $own } else { Join-Path $env:LOCALAPPDATA 'HeatMap360\pingcastle-credential.xml' }
}
$CollectorImage = 'hm360-bhcollector:1.9.1'

if ($SaveCredential) {
  $cred = Get-Credential -Message 'Plain domain account the BloodHound collector signs in with (DOMAIN\user). No admin rights needed.'
  if (-not $cred) { throw 'No credential entered.' }
  New-Item -ItemType Directory -Force -Path (Split-Path $CredentialFile) | Out-Null
  $cred | Export-Clixml -Path $CredentialFile
  Write-Output "Saved the credential for $($cred.UserName) to $CredentialFile (only this Windows user on this computer can read it)."
  return
}

if (-not (Test-Path $CredentialFile)) { throw "No saved credential at $CredentialFile. Run this script once with -SaveCredential." }
if (-not (Test-Path $EnvFile)) { throw "No $EnvFile. Create it as the setup page says, then start BloodHound with docker compose." }
$adminPassword = (Get-Content $EnvFile | Where-Object { $_ -like 'BH_ADMIN_PASSWORD=*' } | Select-Object -First 1) -replace '^BH_ADMIN_PASSWORD=', ''
if (-not $adminPassword) { throw "BH_ADMIN_PASSWORD is missing from $EnvFile." }
if (-not $Server) { $Server = $Domain }
$cred = Import-Clixml -Path $CredentialFile
$user = $cred.UserName.Split([char]92)[-1] -replace '@.*$', ''
$dcIp = (Resolve-DnsName -Name $Server -Type A -ErrorAction Stop | Where-Object IPAddress | Select-Object -First 1).IPAddress
if (-not $dcIp) { throw "Could not resolve $Server. The collector needs the domain controller's address for DNS." }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$work = Join-Path $env:TEMP "hm360-bloodhound-$stamp"
New-Item -ItemType Directory -Force -Path $work, $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path

# --- BloodHound API helpers (local only) ---
$api = $BloodHoundUrl.TrimEnd('/')
function Invoke-Bh([string]$Method, [string]$Path, $Body, [string]$ContentType = 'application/json') {
  $p = @{ Method = $Method; Uri = "$api$Path"; Headers = $script:auth; UseBasicParsing = $true }
  # A FileInfo is sent as the raw file (an if-expression would unroll a byte array into numbers).
  if ($Body -is [IO.FileInfo]) { $p.InFile = $Body.FullName; $p.ContentType = $ContentType }
  elseif ($null -ne $Body) { $p.Body = $Body | ConvertTo-Json -Depth 6 -Compress; $p.ContentType = $ContentType }
  Invoke-RestMethod @p
}
function Get-BhNodes([string]$Query) {
  try { $r = Invoke-Bh POST '/api/v2/graphs/cypher' @{ query = $Query; include_properties = $true } }
  catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return @() } throw }
  if (-not $r.data.nodes) { return @() }
  @($r.data.nodes.PSObject.Properties | ForEach-Object { $_.Value })
}

try {
  # 1. Collect. Linux container, so Defender on this computer sees no collector executable.
  $env:HM360_BH_PW = $cred.GetNetworkCredential().Password
  # No bind mount: the zip is copied out of the stopped container, so a Docker Desktop file-sharing hiccup cannot break it.
  $container = "hm360-bhcollect-$stamp"
  $dockerArgs = @('create', '--name', $container, '-e', 'HM360_BH_PW', '--entrypoint', 'sh', $CollectorImage,
    '-c', 'exec bloodhound-ce-python -p "$HM360_BH_PW" "$@"', 'collector',
    '-u', $user, '-d', $Domain, '-dc', $Server, '-ns', $dcIp, '--dns-tcp', '--auth-method', 'ntlm', '-c', $Collection, '--zip')
  & docker @dockerArgs | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not create the collector container. Build it first: docker build -t $CollectorImage tools\bloodhound\collector" }
  Remove-Item Env:\HM360_BH_PW -ErrorAction SilentlyContinue
  & docker start -a $container 2>&1 | ForEach-Object { Write-Verbose "$_" }
  $code = $LASTEXITCODE
  & docker cp "${container}:/out/." $work 2>&1 | ForEach-Object { Write-Verbose "$_" }
  $zip = Get-ChildItem $work -Filter '*.zip' | Select-Object -First 1
  if (-not $zip) { throw "The collector produced no zip (exit code $code). Check the account, the password and that $Server is reachable on 53, 88 and 389. Run with -Verbose to see its output." }

  # 2. Sign in to the local BloodHound, clear the previous import, upload this one and wait for analysis.
  $login = Invoke-RestMethod -Method Post -Uri "$api/api/v2/login" -ContentType 'application/json' -UseBasicParsing `
    -Body (@{ login_method = 'secret'; username = 'admin'; secret = $adminPassword } | ConvertTo-Json)
  $script:auth = @{ Authorization = "Bearer $($login.data.session_token)" }
  Invoke-Bh POST '/api/v2/clear-database' @{ deleteCollectedGraphData = $true; deleteFileIngestHistory = $false; deleteDataQualityHistory = $false; deleteAssetGroupSelectors = @() } | Out-Null
  # The clear runs in the background and cancels any upload that is still ingesting, so wait until it is done.
  $cleared = (Get-Date).ToUniversalTime()
  $deadline = (Get-Date).AddMinutes(10)
  do {
    Start-Sleep -Seconds 5
    $dp = (Invoke-Bh GET '/api/v2/datapipe/status' $null).data
  } while (-not ($dp.status -eq 'idle' -and ([datetime]$dp.updated_at).ToUniversalTime() -gt $cleared) -and (Get-Date) -lt $deadline)
  $job = (Invoke-Bh POST '/api/v2/file-upload/start' @{}).data.id
  Invoke-Bh POST "/api/v2/file-upload/$job" $zip 'application/zip' | Out-Null
  Invoke-Bh POST "/api/v2/file-upload/$job/end" $null | Out-Null
  $deadline = (Get-Date).AddMinutes(30)
  do {
    Start-Sleep -Seconds 10
    $upload = (Invoke-Bh GET "/api/v2/file-upload?id=eq:$job" $null).data | Select-Object -First 1
    $pipe = (Invoke-Bh GET '/api/v2/datapipe/status' $null).data.status
    # Upload job status 2 = complete, 3/4/5 = cancelled/timed out/failed.
    if ($upload -and $upload.status -in 3, 4, 5) { throw "BloodHound could not ingest the upload (status $($upload.status): $($upload.status_message))." }
  } while (-not ($upload.status -eq 2 -and $pipe -eq 'idle') -and (Get-Date) -lt $deadline)
  if ($upload.status -ne 2 -or $pipe -ne 'idle') { throw 'BloodHound did not finish analysing the upload within 30 minutes.' }

  # 3. Ask BloodHound the questions the Attack paths page shows. Names only, never passwords or hashes.
  $name = { param($n) if ($n.properties.name) { [string]$n.properties.name } else { [string]$n.label } }
  $names = { param($nodes) @($nodes | ForEach-Object { & $name $_ } | Where-Object { $_ } | Sort-Object -Unique) }
  $da = "g.objectid ENDS WITH '-512'"
  $members = & $names (Get-BhNodes "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE $da RETURN u")
  $reach = & $names (Get-BhNodes "MATCH p=shortestPath((u:User)-[*1..]->(g:Group)) WHERE $da AND u.enabled = true AND u <> g RETURN u")
  $finding = { param($id, $items) $list = @($items | Where-Object { $_ }); [ordered]@{ id = $id; count = $list.Count; items = @($list | Select-Object -First 200) } }
  # Domain controllers legitimately have unconstrained delegation and DCSync, so they are left out of those two findings.
  $dcs = & $names (Get-BhNodes "MATCH (c:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' OR g.objectid ENDS WITH '-521' RETURN c")
  $notDc = { param($list) @($list | Where-Object { $dcs -notcontains $_ }) }
  $findings = @(
    (& $finding 'pathToDomainAdmins' @($reach | Where-Object { $members -notcontains $_ }))
    (& $finding 'domainAdminMembers' $members)
    (& $finding 'kerberoastable' (& $names (Get-BhNodes "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' RETURN u") | Where-Object { $_ -notmatch '\$@' }))   # gMSA and computer accounts have unguessable passwords
    (& $finding 'asrepRoastable' (& $names (Get-BhNodes 'MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u')))
    (& $finding 'unconstrainedDelegation' (& $notDc (& $names (Get-BhNodes 'MATCH (c:Computer) WHERE c.unconstraineddelegation = true RETURN c'))))
    (& $finding 'dcsync' (& $notDc (& $names (Get-BhNodes "MATCH (n)-[:DCSync]->(:Domain) WHERE NOT n.objectid ENDS WITH '-516' AND NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519' AND NOT n.objectid ENDS WITH '-544' AND NOT n.objectid ENDS WITH '-498' AND NOT n.objectid ENDS WITH '-9' RETURN n"))))
    (& $finding 'passwordNeverExpires' (& $names (Get-BhNodes 'MATCH (u:User) WHERE u.pwdneverexpires = true AND u.enabled = true RETURN u')))
  )
  $count = { param($label) @(Get-BhNodes "MATCH (n:$label) RETURN n").Count }
  $summary = [ordered]@{
    schema      = 'hm360.attackpaths/1'
    tool        = 'BloodHound CE'
    collector   = 'bloodhound-ce-python 1.9.1'
    collection  = $Collection
    domain      = $Domain.ToLowerInvariant()
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    counts      = [ordered]@{ users = (& $count 'User'); groups = (& $count 'Group'); computers = (& $count 'Computer') }
    findings    = $findings
  }
  $base = Join-Path $OutputDir "bloodhound-$stamp"
  Copy-Item $zip.FullName "$base.zip"
  # Written last, UTF-8 without a byte order mark.
  [IO.File]::WriteAllText("$base.json", ($summary | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
  Write-Output ("{0}: {1} users, {2} groups, {3} computers. {4}. Saved {5}.json" -f $summary.domain, $summary.counts.users, $summary.counts.groups, $summary.counts.computers,
    (($findings | ForEach-Object { "$($_.id) $($_.count)" }) -join ', '), $base)
}
finally {
  Remove-Item Env:\HM360_BH_PW -ErrorAction SilentlyContinue
  if ($container) { & docker rm -f $container 2>&1 | Out-Null }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}



