# Container runner for Monkey365 (silverhack/monkey365): CIS benchmark checks for Exchange Online, Microsoft Teams,
# Microsoft Purview and Azure subscriptions. Read-only, pinned. PowerShell 7 and the Monkey365 module live only in this
# image; nothing is installed on a computer. run.ps1 reads one line of JSON from stdin (tenant ID, client ID, the
# app's certificate as a password-protected PFX and its one-time password, subscriptions), runs the checks and writes
# summary.json and the HTML reports to /out. The line comes from tools/m365posture/Invoke-Monkey365Scan.ps1.
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04
SHELL ["pwsh", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN useradd --create-home --uid 10001 monkey; \
    New-Item -ItemType Directory /monkey, /out | Out-Null; chown -R monkey /monkey /out
USER monkey
# Installed for this user only: Monkey365 keeps its settings and cache beside the module, so the folder must be writable
# by the user that runs the checks.
RUN Set-PSRepository PSGallery -InstallationPolicy Trusted; \
    Install-Module monkey365 -RequiredVersion 1.0.5 -Scope CurrentUser
COPY run.ps1 /monkey/run.ps1
WORKDIR /monkey
ENV POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off
ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/monkey/run.ps1"]
