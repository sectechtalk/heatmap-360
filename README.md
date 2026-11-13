# HeatMap 360 (hm360)

Scan any Windows computer and find out, from the vendors' own sources, whether it is up to date and whether anything
installed on it has a known problem.

* **Windows:** is the installed build the latest for its version, which updates are missing, is the version (for its
  edition) still getting updates, and which issues Microsoft has reported for this exact build.
* **Apps:** installed programs and, for every winget package, whether a newer version exists.
* **Hardware:** make, model, BIOS, motherboard, CPU, memory, disks, device drivers (vendor firmware lookups: next version).
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
                                     ▲                    checks Microsoft release health, winget, CISA
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

Pages: **Scans** (all results), a page per scan, **Actions** (planned on-demand tools), **Get the scanner** (public).

## Run it locally

```powershell
npm install
$env:HM360_DEV_ADMIN = '1'; npm start                        # http://localhost:3460, local data in data\exchange, no sign-in
.\client\Invoke-HeatMapScan.ps1 -Server http://localhost:3460 -WaitMinutes 1
node bot\run.mjs --repo data\exchange                        # process the upload; refresh the page
```

Hosted setup (Entra app, PIM group, data repo token, runner, Container Apps): [docs/SETUP.md](docs/SETUP.md).
Design and data formats: [docs/DESIGN.md](docs/DESIGN.md).

## Rules

* No secrets in git. Sign-in uses a managed identity; the data token is a Container Apps secret.
* The scanner and the bot only read. Nothing is installed, updated or changed on any computer.
* Official vendor sources only in v1. $0: Container Apps free grant, GitHub free, free public feeds.

## Tests

`npm test` and `npm run check`. Fixtures use fictional data (`contoso.example`, sample CVE IDs).
