<#
.SYNOPSIS
  Creates the read-only Entra app registration that HeatMap 360's Monkey365 checks sign in with. Run once, by a Global
  Administrator, in PowerShell 7 on the computer that hosts HeatMap 360.

.DESCRIPTION
  What it does, in order:
    1. Makes a certificate in your own Windows certificate store (Cert:\CurrentUser\My), valid for 2 years. Unlike the
       Maester certificate its private key is exportable, because Monkey365 signs in to Exchange Online, Teams, Purview
       and Azure itself and so needs the certificate inside its container. The scan script copies it there in memory
       for each run only. Only the public half is sent to Entra. There is no client secret.
    2. Signs you in to Microsoft Graph in the browser, for the length of this script only, with three scopes:
       Application.ReadWrite.All (create the app), AppRoleAssignment.ReadWrite.All (admin consent) and
       RoleManagement.ReadWrite.Directory (give the app the Global Reader role).
    3. Creates the app registration "HeatMap 360 Monkey365 (read-only)", single tenant, with the certificate, and its
       service principal (enterprise app).
    4. Grants admin consent for:
         - the Microsoft Graph application permissions Monkey365 documents for app-only sign-in
           (docs/authentication/sp_authentication/getting_started.md), all Read permissions; the script refuses any
           Graph permission whose name is not "<Area>.Read.<Scope>" or "<Area>.ReadBasic.<Scope>";
         - Office 365 Exchange Online "Exchange.ManageAsApp", which lets the app open Exchange Online and Security &
           Compliance PowerShell. What it may do there is set by its Entra role, which is read-only (next line).
    5. Gives the app the Entra role Global Reader (read-only, everything Global Administrator can see, nothing it can
       change). Exchange Online and Purview use this role for app-only reads.
    6. With -SubscriptionId, gives the app the Azure role Reader on each subscription, with the Azure CLI (az) you are
       already signed in to. Reader can see resources and settings and change nothing.
    7. Saves the tenant ID, client ID, certificate thumbprint and subscriptions (none secret) to
       %LOCALAPPDATA%\HeatMap360\monkey365.json for tools\m365posture\Invoke-Monkey365Scan.ps1.

  Not granted, on purpose: SharePoint Online (Monkey365 needs Sites.FullControl.All and SharePoint Administrator for it,
  which can change sites), Microsoft Fabric, any write permission, and the Entra ID checks (Maester covers Entra ID).

  Run it as the same Windows user the weekly scan will run as: the certificate lives in that user's store.
  Safe to run again: it reuses the app and the certificate it made the first time and only adds what is missing.

.EXAMPLE
  pwsh -NoProfile -File .\New-Monkey365App.ps1 -TenantId contoso.example -SubscriptionId 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [string[]]$SubscriptionId = @(),
  [string]$DisplayName = 'HeatMap 360 Monkey365 (read-only)',
  [string]$ConfigFile
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this in PowerShell 7 (pwsh), where Microsoft.Graph.Authentication is installed.' }
if (-not $ConfigFile) { $ConfigFile = Join-Path $env:LOCALAPPDATA 'HeatMap360\monkey365.json' }
foreach ($s in $SubscriptionId) { if ($s -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw "Not a subscription ID: $s" } }
if ($SubscriptionId -and -not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'The Azure CLI (az) is needed to give the app Reader on a subscription. Sign in with az login first, or leave out -SubscriptionId.' }
Import-Module Microsoft.Graph.Authentication

# Monkey365's documented Graph application permissions for app-only sign-in, plus the Teams ones.
$permissions = @(
  'AccessReview.Read.All', 'Application.Read.All', 'AuditLog.Read.All', 'DeviceManagementConfiguration.Read.All',
  'DeviceManagementServiceConfig.Read.All', 'Directory.Read.All', 'Group.Read.All', 'GroupMember.Read.All',
  'IdentityRiskEvent.Read.All', 'Organization.Read.All', 'OrgSettings-AppsAndServices.Read.All', 'OrgSettings-Forms.Read.All',
  'Policy.Read.All', 'Policy.Read.AuthenticationMethod', 'PrivilegedEligibilitySchedule.Read.AzureADGroup',
  'PrivilegedAccess.Read.AzureADGroup', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.AzureADGroup',
  'SecurityEvents.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All',
  'AppCatalog.Read.All', 'Channel.ReadBasic.All', 'ChannelMember.Read.All', 'ChannelSettings.Read.All', 'TeamSettings.Read.All'
)
foreach ($p in $permissions) { if ($p -notmatch '^[A-Za-z-]+\.Read(Basic)?\.[A-Za-z]+$') { throw "Refusing to grant ${p}: not a read-only permission." } }
$graphAppId = '00000003-0000-0000-c000-000000000000'
$exoAppId = '00000002-0000-0ff1-ce00-000000000000'
$exoPermission = 'Exchange.ManageAsApp'
$globalReader = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'   # built-in role template ID, the same in every tenant

# 1. Certificate (reused when the saved config points at one that is still in the store).
$config = if (Test-Path $ConfigFile) { Get-Content -Raw $ConfigFile | ConvertFrom-Json } else { $null }
$cert = if ($config.thumbprint) { Get-Item "Cert:\CurrentUser\My\$($config.thumbprint)" -ErrorAction SilentlyContinue } else { $null }
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Subject "CN=$DisplayName" -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable `
    -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
  Write-Output "Made certificate $($cert.Thumbprint) in Cert:\CurrentUser\My (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))."
}

# 2. Sign in as you, for this script only.
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'RoleManagement.ReadWrite.Directory' -ContextScope Process -NoWelcome
try {
  $tenant = (Get-MgContext).TenantId
  $sp = { param($appId) @((Invoke-MgGraphRequest GET "/v1.0/servicePrincipals?`$filter=$([uri]::EscapeDataString("appId eq '$appId'"))&`$select=id,appRoles").value) | Select-Object -First 1 }
  $graph = & $sp $graphAppId
  $exo = & $sp $exoAppId
  if (-not $exo) { throw 'This tenant has no Office 365 Exchange Online service principal (no Exchange Online licence?).' }
  $roles = @{}
  foreach ($r in $graph.appRoles) { if ($r.allowedMemberTypes -contains 'Application') { $roles[$r.value] = $r.id } }
  $missing = @($permissions | Where-Object { -not $roles.ContainsKey($_) })
  if ($missing) { Write-Warning "Not offered by Microsoft Graph in this tenant, skipped: $($missing -join ', ')" }
  $wanted = @($permissions | Where-Object { $roles.ContainsKey($_) })
  $exoRole = @($exo.appRoles | Where-Object { $_.value -eq $exoPermission }) | Select-Object -First 1
  if (-not $exoRole) { throw "Office 365 Exchange Online does not offer $exoPermission in this tenant." }

  # 3. App registration and service principal.
  $filter = [uri]::EscapeDataString("displayName eq '$DisplayName'")
  $app = @((Invoke-MgGraphRequest GET "/v1.0/applications?`$filter=$filter&`$select=id,appId,keyCredentials").value) | Select-Object -First 1
  $access = @(
    @{ resourceAppId = $graphAppId; resourceAccess = @($wanted | ForEach-Object { @{ id = $roles[$_]; type = 'Role' } }) },
    @{ resourceAppId = $exoAppId; resourceAccess = @(@{ id = $exoRole.id; type = 'Role' }) }
  )
  if (-not $app) {
    $app = Invoke-MgGraphRequest POST '/v1.0/applications' -Body (@{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'
        notes                  = 'HeatMap 360: runs Monkey365 read-only CIS checks of Exchange Online, Teams, Purview and Azure weekly from a container. Read permissions, Global Reader, Azure Reader, certificate sign-in, no secret.'
        requiredResourceAccess = $access
        keyCredentials         = @(@{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = [Convert]::ToBase64String($cert.RawData); displayName = "CN=$DisplayName" })
      } | ConvertTo-Json -Depth 6)
    Write-Output "Created app registration '$DisplayName' (client ID $($app.appId))."
  }
  else {
    $thumbs = @($app.keyCredentials | ForEach-Object { $_.customKeyIdentifier })
    if ($thumbs -notcontains $cert.Thumbprint) { throw "An app named '$DisplayName' already exists without this computer's certificate. Delete it in Entra, or pass -DisplayName with a new name, and run this again." }
    Invoke-MgGraphRequest PATCH "/v1.0/applications/$($app.id)" -Body (@{ requiredResourceAccess = $access } | ConvertTo-Json -Depth 6) | Out-Null
    Write-Output "Reusing app registration '$DisplayName' (client ID $($app.appId))."
  }
  $me = & $sp $app.appId
  for ($i = 0; -not $me; $i++) {
    # A new app can take a few seconds to replicate before its service principal can be created.
    try { $me = Invoke-MgGraphRequest POST '/v1.0/servicePrincipals' -Body (@{ appId = $app.appId } | ConvertTo-Json) }
    catch { if ($i -ge 5) { throw }; Start-Sleep -Seconds 5 }
  }

  # 4. Admin consent: one app role assignment per permission, skipping any already there.
  $have = @((Invoke-MgGraphRequest GET "/v1.0/servicePrincipals/$($me.id)/appRoleAssignments").value | ForEach-Object { $_.appRoleId })
  $granted = 0
  $grants = @($wanted | ForEach-Object { @{ resource = $graph.id; role = $roles[$_] } }) + @(@{ resource = $exo.id; role = $exoRole.id })
  foreach ($g in $grants) {
    if ($have -contains $g.role) { continue }
    Invoke-MgGraphRequest POST "/v1.0/servicePrincipals/$($g.resource)/appRoleAssignedTo" -Body (@{ principalId = $me.id; resourceId = $g.resource; appRoleId = $g.role } | ConvertTo-Json) | Out-Null
    $granted++
  }
  Write-Output "Admin consent: $granted permission(s) granted now, $($grants.Count) in total (Graph read permissions and $exoPermission)."

  # 5. Global Reader (read-only directory role).
  $f = [uri]::EscapeDataString("principalId eq '$($me.id)' and roleDefinitionId eq '$globalReader'")
  if (-not @((Invoke-MgGraphRequest GET "/v1.0/roleManagement/directory/roleAssignments?`$filter=$f").value)) {
    Invoke-MgGraphRequest POST '/v1.0/roleManagement/directory/roleAssignments' -Body (@{ principalId = $me.id; roleDefinitionId = $globalReader; directoryScopeId = '/' } | ConvertTo-Json) | Out-Null
    Write-Output 'Gave the app the Global Reader role (read-only).'
  }
  else { Write-Output 'The app already has the Global Reader role.' }

  # 6. Azure Reader on each subscription given.
  foreach ($s in $SubscriptionId) {
    & az role assignment create --assignee-object-id $me.id --assignee-principal-type ServicePrincipal --role Reader --scope "/subscriptions/$s" --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "az could not give the app Reader on subscription $s. Are you signed in with az login as an Owner of it?" }
    Write-Output "Gave the app Reader on subscription $s."
  }

  # 7. Save what the scan needs (no secret: the private key stays in the certificate store).
  $subs = @(@($config.subscriptions) + $SubscriptionId | Where-Object { $_ } | Select-Object -Unique)
  New-Item -ItemType Directory -Force -Path (Split-Path $ConfigFile) | Out-Null
  [ordered]@{
    tenantId = $tenant; clientId = $app.appId; thumbprint = $cert.Thumbprint; certificateExpires = $cert.NotAfter.ToUniversalTime().ToString('o')
    services = @('ExchangeOnline', 'MicrosoftTeams', 'Purview'); subscriptions = $subs
  } | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding utf8
  Write-Output "Saved $ConfigFile. Next: build the runner image and run one scan (see the How to set up page)."
}
finally { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
