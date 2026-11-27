<#
.SYNOPSIS
  Creates the read-only Entra app registration that HeatMap 360's Maester checks sign in with. Run once, by a Global
  Administrator (or Privileged Role Administrator), in PowerShell 7 on the computer that hosts HeatMap 360.

.DESCRIPTION
  What it does, in order:
    1. Makes a certificate in your own Windows certificate store (Cert:\CurrentUser\My), valid for 2 years. Its private
       key is marked non-exportable: it cannot be copied off this computer. Only the public half is sent to Entra.
       There is no client secret.
    2. Signs you in to Microsoft Graph in the browser (Connect-MgGraph, from the Microsoft.Graph.Authentication module)
       with two scopes, for the length of this script only: Application.ReadWrite.All to create the app and
       AppRoleAssignment.ReadWrite.All to grant admin consent.
    3. Creates the app registration "HeatMap 360 Maester (read-only)", single tenant, with the certificate, and its
       service principal (enterprise app).
    4. Grants admin consent for the Microsoft Graph application permissions Maester documents
       (https://maester.dev/docs/installation, "Microsoft Graph permissions Maester uses"). Every one is a Read
       permission; the script refuses any permission whose name is not "<Area>.Read.<Scope>". It does not grant
       Maester's optional ReportSettings.ReadWrite.All, any Exchange, Teams or Azure role, or any Entra directory role.
    5. Saves the tenant ID, the app's client ID and the certificate thumbprint (none of them secret) to
       %LOCALAPPDATA%\HeatMap360\maester.json for tools\entraposture\Invoke-MaesterScan.ps1.

  Run it as the same Windows user the weekly scan will run as: the certificate lives in that user's store.
  Safe to run again: it reuses the app and the certificate it made the first time and only adds missing permissions.

.EXAMPLE
  pwsh -NoProfile -File .\New-MaesterApp.ps1 -TenantId contoso.example
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [string]$DisplayName = 'HeatMap 360 Maester (read-only)',
  [string]$ConfigFile
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this in PowerShell 7 (pwsh), where Microsoft.Graph.Authentication is installed.' }
if (-not $ConfigFile) { $ConfigFile = Join-Path $env:LOCALAPPDATA 'HeatMap360\maester.json' }
Import-Module Microsoft.Graph.Authentication

# Maester's documented Graph application permissions (maester.dev, sections/permissions.md), without the preview ones.
$permissions = @(
  'AccessReview.Read.All', 'AuditLog.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementConfiguration.Read.All',
  'DeviceManagementManagedDevices.Read.All', 'DeviceManagementRBAC.Read.All', 'DeviceManagementServiceConfig.Read.All',
  'Directory.Read.All', 'DirectoryRecommendations.Read.All', 'EntitlementManagement.Read.All', 'IdentityRiskEvent.Read.All',
  'NetworkAccess.Read.All', 'OnPremDirectorySynchronization.Read.All', 'OrgSettings-AppsAndServices.Read.All',
  'OrgSettings-Forms.Read.All', 'Policy.Read.All', 'Policy.Read.ConditionalAccess', 'Reports.Read.All', 'ReportSettings.Read.All',
  'RoleEligibilitySchedule.Read.Directory', 'RoleManagement.Read.All', 'RoleManagementAlert.Read.Directory',
  'SecurityIdentitiesSensors.Read.All', 'SecurityIdentitiesHealth.Read.All', 'SharePointTenantSettings.Read.All',
  'ThreatHunting.Read.All', 'UserAuthenticationMethod.Read.All'
)
foreach ($p in $permissions) { if ($p -notmatch '^[A-Za-z-]+\.Read\.[A-Za-z]+$') { throw "Refusing to grant ${p}: not a read-only permission." } }
$graphAppId = '00000003-0000-0000-c000-000000000000'

# 1. Certificate (reused when the saved config points at one that is still in the store).
$config = if (Test-Path $ConfigFile) { Get-Content -Raw $ConfigFile | ConvertFrom-Json } else { $null }
$cert = if ($config.thumbprint) { Get-Item "Cert:\CurrentUser\My\$($config.thumbprint)" -ErrorAction SilentlyContinue } else { $null }
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Subject "CN=$DisplayName" -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable `
    -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
  Write-Output "Made certificate $($cert.Thumbprint) in Cert:\CurrentUser\My (private key non-exportable, expires $($cert.NotAfter.ToString('yyyy-MM-dd')))."
}

# 2. Sign in as you, for this script only.
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -ContextScope Process -NoWelcome
try {
  $tenant = (Get-MgContext).TenantId
  $graph = Invoke-MgGraphRequest GET "/v1.0/servicePrincipals(appId='$graphAppId')?`$select=id,appRoles"
  $roles = @{}
  foreach ($r in $graph.appRoles) { if ($r.allowedMemberTypes -contains 'Application') { $roles[$r.value] = $r.id } }
  $missing = @($permissions | Where-Object { -not $roles.ContainsKey($_) })
  if ($missing) { Write-Warning "Not offered by Microsoft Graph in this tenant, skipped: $($missing -join ', ')" }
  $wanted = @($permissions | Where-Object { $roles.ContainsKey($_) })

  # 3. App registration and service principal.
  $filter = [uri]::EscapeDataString("displayName eq '$DisplayName'")
  $app = @((Invoke-MgGraphRequest GET "/v1.0/applications?`$filter=$filter&`$select=id,appId,keyCredentials").value) | Select-Object -First 1
  $access = @{ resourceAppId = $graphAppId; resourceAccess = @($wanted | ForEach-Object { @{ id = $roles[$_]; type = 'Role' } }) }
  if (-not $app) {
    $app = Invoke-MgGraphRequest POST '/v1.0/applications' -Body (@{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'
        notes                  = 'HeatMap 360: runs Maester read-only security checks weekly from a container. Read-only Graph application permissions, certificate sign-in, no secret.'
        requiredResourceAccess = @($access)
        keyCredentials         = @(@{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = [Convert]::ToBase64String($cert.RawData); displayName = "CN=$DisplayName" })
      } | ConvertTo-Json -Depth 6)
    Write-Output "Created app registration '$DisplayName' (client ID $($app.appId))."
  }
  else {
    $thumbs = @($app.keyCredentials | ForEach-Object { $_.customKeyIdentifier })
    if ($thumbs -notcontains $cert.Thumbprint) { throw "An app named '$DisplayName' already exists without this computer's certificate. Delete it in Entra, or pass -DisplayName with a new name, and run this again." }
    Invoke-MgGraphRequest PATCH "/v1.0/applications/$($app.id)" -Body (@{ requiredResourceAccess = @($access) } | ConvertTo-Json -Depth 6) | Out-Null
    Write-Output "Reusing app registration '$DisplayName' (client ID $($app.appId))."
  }
  $sp = @((Invoke-MgGraphRequest GET "/v1.0/servicePrincipals?`$filter=$([uri]::EscapeDataString("appId eq '$($app.appId)'"))&`$select=id").value) | Select-Object -First 1
  for ($i = 0; -not $sp; $i++) {
    # A new app can take a few seconds to replicate before its service principal can be created.
    try { $sp = Invoke-MgGraphRequest POST '/v1.0/servicePrincipals' -Body (@{ appId = $app.appId } | ConvertTo-Json) }
    catch { if ($i -ge 5) { throw }; Start-Sleep -Seconds 5 }
  }

  # 4. Admin consent: one app role assignment per permission, skipping any already there.
  $have = @((Invoke-MgGraphRequest GET "/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments").value | ForEach-Object { $_.appRoleId })
  $granted = 0
  foreach ($p in $wanted) {
    if ($have -contains $roles[$p]) { continue }
    Invoke-MgGraphRequest POST "/v1.0/servicePrincipals/$($graph.id)/appRoleAssignedTo" -Body (@{ principalId = $sp.id; resourceId = $graph.id; appRoleId = $roles[$p] } | ConvertTo-Json) | Out-Null
    $granted++
  }
  Write-Output "Admin consent: $granted permission(s) granted now, $($wanted.Count) in total, all read-only."

  # 5. Save what the scan needs (no secret: the private key stays in the certificate store).
  New-Item -ItemType Directory -Force -Path (Split-Path $ConfigFile) | Out-Null
  [ordered]@{ tenantId = $tenant; clientId = $app.appId; thumbprint = $cert.Thumbprint; certificateExpires = $cert.NotAfter.ToUniversalTime().ToString('o') } |
    ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding utf8
  Write-Output "Saved $ConfigFile. Next: build the runner image and run one scan (see the How to set up page)."
}
finally { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
