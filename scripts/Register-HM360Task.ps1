<#
.SYNOPSIS
  Registers the hourly "hm360 collect" scheduled task on THIS computer (runs elevated so BitLocker and Secure Boot
  can be read). Shows what it would do unless -Apply is given.
.EXAMPLE
  .\Register-HM360Task.ps1           # preview
  .\Register-HM360Task.ps1 -Apply    # run from an elevated prompt
#>
[CmdletBinding()]
param([switch]$Apply, [int]$EveryMinutes = 60)
$ErrorActionPreference = 'Stop'
$collector = Join-Path (Split-Path $PSScriptRoot -Parent) 'collectors\Invoke-HM360Collect.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$collector`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable
if (-not $Apply) {
    Write-Output "Would register task 'hm360 collect' as SYSTEM every $EveryMinutes minutes running:"
    Write-Output "  powershell.exe -File `"$collector`""
    Write-Output 'Run again with -Apply from an elevated prompt to register it.'
    return
}
Register-ScheduledTask -TaskName 'hm360 collect' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Output "Registered 'hm360 collect'. Run it now: Start-ScheduledTask -TaskName 'hm360 collect'"
