# HeatMap 360 (hm360)

Scan any Windows computer and find out, from the vendors' own sources, whether it is up to date and whether anything
installed on it has a known problem.

* **Windows:** is the installed build the latest for its version, which updates are missing, is the version (for its
  edition) still getting updates, and which issues Microsoft has reported for this exact build.
* **Apps:** installed programs and, for every winget package, whether a newer version exists.
* **BIOS:** for HP and Lenovo, whether the vendor's update catalog has a newer BIOS; for other makers, the BIOS age
  and a link to the maker's support site.
* **Event log:** blue screens, hardware (WHEA) errors, disk errors, unexpected restarts, failed updates, crashes in
  the last 7 days, from counts per event ID (message text is never collected).
* **Network adapters:** link speed and duplex, old drivers, power and Energy Efficient Ethernet settings, Wi-Fi
  signal, band and standard (no addresses or network names).
* **Network health:** ping time and loss to the router, connection time to the internet, DNS lookup time, and
  download/upload speed against Cloudflare's public speed test (about 35 MB; `-SkipSpeedTest` leaves it out).
* **Disk and battery health:** disk wear, temperature and uncorrected errors (run as administrator), battery
  capacity versus new.
* **Hardware:** make, model, motherboard, CPU, memory, disks, device drivers.
* **Service health page:** Microsoft 365 (tenant service health from Microsoft Graph, read with the app's managed
  identity), Azure, AWS, Google Cloud, Google Workspace, GitHub and Cloudflare from their own status feeds.
* **Options page:** builds the scanner command (speed test on or off, save only, wait time).

HeatMap 360 reports findings only. It never fixes or changes anything; remediation belongs to Remediation 360.
* **Health:** Defender, BitLocker, Secure Boot, TPM, firewall, free space, restart pending.
* **Exploited in the wild:** CISA KEV entries that may apply (candidates to verify).

![Scan results page (fictional sample data)](docs/images/scan.png)

## How it works

```
 any Windows PC                     HeatMap 360 (Azure Container Apps)         hm-360-data (private GitHub repo)
 Invoke-HeatMapScan.ps1 ── HTTPS ──▶ POST /api/scans  ── contents API ──────▶ inbox/<id>.json
   (anonymized inventory)            validates, rate limits, scrubs                    │ push wakes the workflow
                                                                                       ▼
 PDF ◀── token ── GET /api/scans/<id>/report.pdf        admin desktop: self-hosted runner → bot/run.mjs
                                     ▲                    checks Microsoft release health, winget, CISA, HP/Lenovo
 admins (Entra + active PIM group) ──┘ results pages  ◀── results/<id>.json ◀────────────┘
```

1. **Scanner** (`client/Invoke-HeatMapScan.ps1`): anyone can run it; no account needed. It is read-only, leaves out
   names, addresses and serial numbers, and identifies the computer only by a hash of its MachineGuid. `-SaveOnly`
   writes the exact data to a file without sending it. It waits for the results and saves a PDF.
2. **HeatMap 360** (`server/`): an open upload endpoint with a 1 MB limit, per-IP and global rate limits, a strict
   schema (unknown fields rejected) and a second scrub for anything personal. It stores the upload in `hm-360-data`
   with only a hash of the uploader's one-time token. The GitHub token sits in the server, never on a client.
3. **Bot** (`bot/`): runs on the admin's desktop as a GitHub Actions self-hosted runner job (`bot/process.yml`), started
   by GitHub when an upload lands (and hourly to catch up). It writes `results/<id>.json`. Every lookup can fail on
   its own; that section then says "Not checked" with the reason, and the rest still completes.
4. **Results**: the uploader gets a PDF. People signed in with Entra who have **activated the HeatMap 360 PIM group**
   see every scan live; access ends when the activation ends (re-checked every 5 minutes).

Pages: **Scans** (all results), a page per scan, **Service health**, **Options** (scanner options), **Get the scanner** (public).

## Run it locally

```powershell
npm install
$env:HM360_DEV_ADMIN = '1'; npm start                        # http://localhost:3460, local data in data\exchange, no sign-in
.\client\Invoke-HeatMapScan.ps1 -Server http://localhost:3460 -WaitMinutes 1
node bot\run.mjs --repo data\exchange                        # process the upload; refresh the page
```

Or run the web app in a container (Docker Desktop). Same local dev mode, same `data\exchange` folder, port published on
127.0.0.1 only. The bot still runs on the host as above.

```powershell
docker compose up -d --build                                 # http://localhost:3460
docker compose logs -f hm360                                 # watch it
docker compose down                                          # stop
```

Hosted setup (Entra app, PIM group, data repo token, runner, Container Apps): [docs/SETUP.md](docs/SETUP.md).
Design and data formats: [docs/DESIGN.md](docs/DESIGN.md).

## Rules

* No secrets in git. Sign-in uses a managed identity; the data token is a Container Apps secret.
* The scanner and the bot only read. Nothing is installed, updated or changed on any computer.
* Official vendor sources only (Microsoft, winget, CISA, HP and Lenovo update catalogs). $0: Container Apps free grant, GitHub free, free public feeds.

## Tests

`npm test` and `npm run check`. Fixtures use fictional data (`contoso.example`, sample CVE IDs).
