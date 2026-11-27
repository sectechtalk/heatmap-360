# Container runner for Maester (maester365/maester): Entra ID and Microsoft 365 security checks, read-only, pinned.
# PowerShell 7 and the Maester, Pester and Microsoft Graph modules live only in this image; nothing is installed on a computer.
# run.ps1 reads a short-lived Graph access token from stdin (never an argument or environment variable), runs the
# checks and writes summary.json and report.html to /out. The token comes from tools/entraposture/Invoke-MaesterScan.ps1.
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04
SHELL ["pwsh", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN Set-PSRepository PSGallery -InstallationPolicy Trusted; \
    Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.32.0 -Scope AllUsers; \
    Install-Module Pester -RequiredVersion 5.7.1 -Scope AllUsers -SkipPublisherCheck; \
    Install-Module Maester -RequiredVersion 2.3.0 -Scope AllUsers; \
    New-Item -ItemType Directory /maester | Out-Null; \
    Copy-Item -Recurse (Join-Path (Get-Module -ListAvailable Maester).ModuleBase 'maester-tests') /maester/tests; \
    Remove-Item -Recurse -Force /maester/tests/ad; \
    useradd --create-home --uid 10001 maester; \
    New-Item -ItemType Directory /out | Out-Null; chown -R maester /out /maester
COPY run.ps1 /maester/run.ps1
USER maester
WORKDIR /maester
ENV POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off
ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/maester/run.ps1"]
