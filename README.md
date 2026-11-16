# HeatMap 360 (hm360)

Scan any Windows computer and find out, from the vendors' own sources, whether it is up to date and whether anything
installed on it has a known problem or a vulnerability that is being exploited in the wild. Alongside the scans,
HeatMap 360 gathers cloud service health, security and patch news, and official vendor posts on one admin-friendly
dashboard.

HeatMap 360 reports findings only. It never installs, updates or changes anything on a computer, and it never posts
anywhere. Fixing things belongs to Remediation 360.

![Scan results page (fictional sample data)](docs/images/scan.png)

## What a scan checks

* **Windows:** is the installed build the latest for its version, which updates are missing, is the version (for its
  edition) still getting updates, and which issues Microsoft has reported for this exact build and for the installed
  updates.
* **Apps:** installed programs and, for every winget package, whether a newer version exists.
* **Known issues in apps:** "Known issues" / "Unresolved" sections from each publisher's release notes (linked from
  the winget catalog, and the app's own GitHub release), for the installed version and the available update.
* **Exploited in the wild:** installed programs and the Windows build matched against CISA's Known Exploited
  Vulnerabilities catalog, then checked against the affected version ranges in each official CVE record: "Vulnerable
  version", "Check version" (the record has no usable version data) or patched.
* **BIOS:** for HP and Lenovo, whether the vendor's update catalog has a newer BIOS; for other makers, the BIOS age
  and a link to the maker's support site.
* **Health:** Defender, BitLocker, Secure Boot, TPM, firewall, free space, restart pending.
* **Event log:** blue screens, hardware (WHEA) errors, disk errors, unexpected restarts, failed updates and crashes in
  the last 7 days, from counts per event ID (message text is never collected).
* **Network adapters:** link speed and duplex, old drivers, power and Energy Efficient Ethernet settings, Wi-Fi
  signal, band and standard (no addresses or network names).
* **Network health:** ping time and loss to the router, connection time to the internet, DNS lookup time, and
  download/upload speed against Cloudflare's public speed test (about 35 MB; `-SkipSpeedTest` leaves it out).
* **Disk and battery health:** disk wear, temperature and uncorrected errors (run as administrator), battery
  capacity versus new.
* **Hardware:** make, model, motherboard, CPU, memory, disks, device drivers.

Every lookup can fail on its own. That section then says "Not checked" with the reason, and the rest still completes.

## Pages

**Results** (admins with an active PIM elevation)

* **Scans:** every scan, newest first, and a page per scan with its grade and every finding. Each scan also has a PDF.
* **Internet - Cloud Services:** headlines from Azure updates, the AWS News Blog, the Google Cloud Blog, the Cloudflare
  Blog and The Register's cloud section.
* **Internet - Exploits:** CISA advisories, the Microsoft Security Update Guide, SANS Internet Storm Center,
  BleepingComputer, The Hacker News, SecurityWeek and Krebs on Security.
* **Internet - Patches:** 11 patch news feeds (BleepingComputer, Born's Tech and Windows World, Windows IT Pro Blog,
  Zero Day Initiative, Windows Latest, Neowin, The Register: Patches, Patch My PC, gHacks, Chrome Releases, Tenable).
* **x.com:** placeholder with four time windows; not populated yet.
* **Bluesky:** the latest posts from the top 50 official vendor accounts for patches, updates, security and service
  health, plus every official Microsoft account, read from Bluesky's free public API with no account. Last hour,
  4 hours, 24 hours or 7 days; newest first or by account; replies on demand with "Show replies".
* **Service health:** Microsoft 365 (tenant service health from Microsoft Graph, read with the app's managed
  identity), Azure, AWS, Google Cloud, Google Workspace, GitHub and Cloudflare from their own status feeds.

The news and Bluesky pages can filter by time window, sort by source or by time, and hide sources; headlines link to
the source. Feeds are cached for 30 minutes (Bluesky for 15).

**Tools**

* **Options:** builds the scanner command (speed test on or off, save only, wait time).
* **Settings** (Project 360 Admin group, PIM-activated): which Azure storage account and table hold the findings
  table, so the storage can move without a code change.

**Get started** (public, no sign-in)

* **How To Guide:** seven steps from downloading the scanner to reading the results, what HeatMap 360 does at each
  step, what each component is looked up against, what the result words mean, and troubleshooting.
* **Get the scanner:** download the scanner and upload a scan file.

## How it works

```
 any Windows PC                     HeatMap 360 (Azure Container Apps)         hm-360-data (private GitHub repo)
 Invoke-HeatMapScan.ps1 ── HTTPS ──▶ POST /api/scans  ── contents API ──────▶ inbox/<id>.json
   (anonymized inventory)            validates, rate limits, scrubs                    │ push wakes the workflow
                                                                                       ▼
 PDF ◀── ticket ── GET /api/scans/<id>/report.pdf       admin desktop: self-hosted runner → bot/run.mjs
                                     ▲                    checks Microsoft, winget, CISA, CVE, HP/Lenovo
 admins (Entra + active PIM group) ──┘ results pages  ◀── results/<id>.json ◀────────────┘
                                                                                       │
                                     findings table (Azure Table Storage) ◀── bot/findings.mjs (scheduled)
```

1. **Scanner** (`client/Invoke-HeatMapScan.ps1`): anyone can run it; no account needed. It is read-only, leaves out
   names, addresses and serial numbers, and identifies the computer only by a hash of its MachineGuid. Two steps: a
   scan only saves the anonymized file (nothing is sent); the user uploads it with the Upload button on the "Get the
   scanner" page or with `-Upload` (which waits for the results and saves a PDF). `-ScanAndUpload` does both, and
   `-Resume <scan id>` fetches the PDF of an earlier upload.
2. **HeatMap 360** (`server/`): an open upload endpoint with a 1 MB limit, per-IP and global rate limits, a strict
   schema (unknown fields rejected) and a second scrub for anything personal. It stores the upload in `hm-360-data`
   with only a hash of the uploader's one-time ticket. The GitHub token sits in the server, never on a client.
3. **Bot** (`bot/`): runs on the admin's desktop as a GitHub Actions self-hosted runner job (`bot/process.yml`), started
   by GitHub when an upload lands (and hourly to catch up). It writes `results/<id>.json`.
4. **Results**: the uploader gets a PDF. People signed in with Entra who have **activated the HeatMap 360 PIM group**
   see every scan live; access ends when the activation ends (re-checked every 5 minutes).
5. **Findings store** (`bot/findings.mjs`): every item from every scan goes into one Azure Table Storage table, one row
   per item per computer (keyed by the anonymous machine ID). A background job on the admin desktop looks each
   distinct item up again with the same official sources (rechecked about once a day), so a newly reported problem
   or a newly exploited vulnerability is flagged without a new scan. It signs in with Entra (the desktop's
   `az login`); no keys or connection strings. The storage account is created by hand in Azure, never by code; the
   job only creates the table inside it.

## Run it locally

```powershell
npm install
$env:HM360_DEV_ADMIN = '1'; npm start                        # http://localhost:3460, local data in data\exchange, no sign-in
.\client\Invoke-HeatMapScan.ps1 -Server http://localhost:3460 -ScanAndUpload -WaitMinutes 1
node bot\run.mjs --repo data\exchange                        # process the upload; refresh the page
node bot\findings.mjs --repo data\exchange --dry-run         # optional: fill the findings store in memory only
```

Dev admin mode treats the browser as an elevated admin. It only works on 127.0.0.1 and is refused in production or
when Entra or the GitHub data repo is configured. The Microsoft 365 card reads "Not connected" locally, because it
needs the Azure managed identity.

Or run the web app in a container (Docker Desktop). Same local dev mode, same `data\exchange` folder, port published on
127.0.0.1 only. The bot still runs on the host as above.

```powershell
docker compose up -d --build                                 # http://localhost:3460
docker compose logs -f hm360                                 # watch it
docker compose down                                          # stop
```

Hosted setup (Entra app, PIM groups, data repo token, runner, findings store, Container Apps, settings):
[docs/SETUP.md](docs/SETUP.md). Design and data formats: [docs/DESIGN.md](docs/DESIGN.md).

## Rules

* No secrets in git. Sign-in uses a managed identity (no client secret); the data token is a Container Apps secret.
  The findings job signs in with Entra; no storage keys.
* The scanner and the bot only read. Nothing is installed, updated or changed on any computer, and HeatMap 360 never
  posts to any site.
* Scan results use official sources only: Microsoft release health, the winget catalog and the publisher release notes
  it links, CISA KEV, CVE records, HP and Lenovo update catalogs. The Internet pages read the public RSS/Atom feeds
  listed in `server/news.mjs`; the Bluesky page reads Bluesky's free public API for the accounts in
  `server/bluesky.mjs`. No other scraping.
* $0: Container Apps free grant (scales to zero), GitHub free, free public feeds, Azure Table Storage at cents a month.

## Not built yet

* Matching scans against the news and social feeds, with a verdict per product (for example "Upgrade now: exploited"
  or "Watch for issues").
* AI-assisted lookups of known issues for each component (the How To Guide says this is coming).
* Posts on the x.com page.
* BIOS lookups for makers other than HP and Lenovo.

## Tests

`npm test` and `npm run check`. Fixtures use fictional data (`contoso.example`, sample CVE IDs). Every pull request
also runs a security gate (`.github/workflows/security.yml`): dependency audit, secret scan and the tests, with
Dependabot keeping dependencies current.

