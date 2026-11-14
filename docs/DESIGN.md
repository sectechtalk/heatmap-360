# hm360 design (v1.2)

## Data formats

* **Upload** (scanner → server): `hm360.inventory/1`, validated by `server/schema.mjs` (every field typed and bounded,
  unknown fields rejected). See `tests/fixtures/inventory.sample.json`.
* **Upload record** (server → `hm-360-data/inbox/<id>.json`): `{ schema: "hm360.upload/1", id, receivedAt, tokenHash, inventory }`.
  `id` = UTC `yyyyMMddHHmmss-<8 hex>`. The token is 32 random bytes returned once to the scanner; only its SHA-256 is stored.
* **Result** (bot → `hm-360-data/results/<id>.json`): `hm360.result/1` with `summary`, `windows`, `knownIssues`, `apps`,
  `health`, `exploited`, `eventLog`, `network`, `firmware`, `hardware` and the inventory (bot 1.1.0; results from bot
  1.0.0 lack the three new sections and the pages skip them). The bot deletes the inbox file. Rejected uploads get a result with `rejected`.

## Anonymization

The scanner never reads names, addresses or serials. It then scrubs this computer's name, user name and domain, email
addresses, `\Users\<name>` paths and MAC addresses from the JSON. The server scrubs emails and user paths again. The
machine ID is the first 16 hex characters of SHA-256("hm360:" + MachineGuid).

## Windows checks (official Microsoft pages)

* **Release information** (`windows11-release-information`, `release-information` for Windows 10): every build per
  version with KB and date from the release history tables (hotpatch calendar ignored), and end of updates per
  edition from the summary table. Status: `current`, `behind` (with the missing builds), `unsupported`, `unknown`.
* **Known issues** (`status-windows-<10|11>-<version>`): the summary table. For each issue: `not-affected` (machine
  older than the originating build), `affected` / `may-affect` (open), `fix-available` (resolved by a KB newer than
  the machine), `fixed-installed`.
* The readers only take table rows and headings; if the layout changes they return nothing and the section reads
  "Not checked", never a guess.

## App checks (winget catalog)

The scanner runs `winget export --include-versions` to get package IDs. The bot lists
`microsoft/winget-pkgs/manifests/<letter>/<Publisher>/<Name>/` through the GitHub API (the workflow's token) and takes
the highest version folder. Store apps, unknown versions and missing packages are listed as "not checked" with why.

## Machine checks (scanner 1.1.0, bot 1.1.0)

The new inventory fields are optional, so 1.0.0 scanners still validate; their results show the new areas as "Not checked".

* **Event log** (`bot/machine.mjs`): the scanner groups the last 7 days of critical and error events in System and
  Application (plus WHEA warnings) by provider, event ID and level, and sends only those keys, a count and the last
  time (at most 150 rows). Message text is never read. Rules turn known IDs into findings: blue screens (WER 1001),
  WHEA (bad if any uncorrected), disk/NTFS/storport errors (bad), unexpected restarts (Kernel-Power 41, EventLog
  6008; warn, bad at 3+), display driver resets, failed Windows Update installs, service failures, app crashes.
  DCOM 10010/10016 are counted as routine and never graded. Everything else is listed, not graded.
* **Network adapters** (`bot/machine.mjs`): `Get-NetAdapter -Physical` with model, media type, status, link speed,
  duplex, driver and power management, plus advanced settings from an allowlist (never "Network Address"). Wi-Fi
  signal, band, channel, standard and negotiated rates from English `netsh wlan show interfaces` (never SSID or
  BSSID). Findings on connected adapters: half duplex (bad), 10 Mbps (bad), gigabit adapter at 100 Mbps (warn),
  driver over 3 years old (warn), signal under 60% (warn) or 40% (bad), 802.11a/b/g/n (warn); EEE, forced speed,
  power saving and 2.4 GHz are notes.
* **BIOS** (`bot/firmware.mjs`): HP: the HP Image Assistant reference file
  `hpia.hpcloud.hp.com/ref/<platform>/<platform>_64_<10|11>.0.<version>.xml` (platform = motherboard product, 4 hex
  digits), newest `UpdateInfo` with a BIOS category. Lenovo: `download.lenovo.com/catalog/<type>_Win11.xml` (then
  Win10; type = first 4 characters of the model), then the BIOS package descriptor it points to (Lenovo host only).
  Compared by version in the vendor's numbering, else by release date with a 45-day margin. Other makers and failed
  lookups: "not checked" with the support site; a BIOS over 3 years old is a warning. Virtual machines are skipped.
  Only the strictly validated model code goes into a URL; the bot fetches vendor files only from those two hosts.

## Network, disk and battery health (scanner 1.2.0, bot 1.2.0)

* **Network health** (`bot/nethealth.mjs`): 20 pings to the default gateway (address used, never sent), 10 TCP
  connections to `speed.cloudflare.com:443`, one DNS lookup of `www.microsoft.com`, and a download/upload test
  against Cloudflare's public speed test (`/__down`, `/__up`): 2 MB down first, 25 MB only if that ran at 10 Mbps or
  more; 1 MB up, then 10 MB at 5 Mbps or more. Grades: gateway over 10 ms wired / 30 ms Wi-Fi, any loss or jitter
  over 30 ms warn, 100 ms or 10% loss bad; a router that ignores ping is "not checked"; internet over 100 ms warn,
  250 ms bad; DNS over 200 ms warn, 1 s or failure bad; download under 10 Mbps warn, 3 bad; upload under 3 warn, 1
  bad (the FCC 100/20 benchmark is shown as text). speedtest.net was not used because it needs its CLI installed.
* **Disk health** (`bot/health.mjs`): `HealthStatus` plus `Get-StorageReliabilityCounter` (wear, temperature,
  uncorrected errors, power-on hours). Unhealthy or any uncorrected error bad; wear 80% warn, 95% bad; 70 °C warn.
* **Battery**: `root\wmi` designed vs full-charge capacity and cycle count (never the serial). Under 80% warn, 50% bad.

## Service health (server, `server/services.mjs`)

The server reads public status feeds (no credentials) and caches them for 5 minutes; `/api/admin/services` is for
elevated admins. Azure RSS (every item is active), AWS RSS (newest post per service in 24 hours, active unless it says
operating normally/resolved), Google Cloud and Google Workspace `incidents.json` (no `end` = active, graded by
`status_impact`), GitHub and Cloudflare Statuspage `summary.json`. Links shown must be on the provider's own host.
Microsoft 365: tenant service health from Microsoft Graph `GET /v1.0/admin/serviceAnnouncement/issues?$filter=isResolved eq false`,
with a token from the app's managed identity (id-heatmap360) for `https://graph.microsoft.com`. id-heatmap360 needs the Graph
application permission `ServiceHealth.Read.All` (app role 79c261e0-fe76-4144-aad5-bdc68fbe4037), assigned to its
service principal. Without the identity (local runs) or the permission (401/403) it shows "Not connected" with why.
Advisories are notices, `serviceInterruption` is an outage, other open incidents are degraded.

## Grades

`ok` / `warn` / `bad` / `unknown` per area; overall = worst known grade. Windows: current ok, one release behind warn,
more or unsupported bad. Known issues: any open issue warn. Apps: any update warn. Health: worst check. Event log,
network: worst finding (notes don't count). BIOS: update available warn, current ok.

## Security

* Upload endpoint: 1 MB body, 5 per IP per 10 minutes, 20 per IP per day, 500 per day overall (env overrides),
  strict schema, scrub. Ingress client IP via `trust proxy`.
* Uploader access: bearer token compared by hash in constant time; unknown scan and wrong token both return 404.
* Admin access: Entra auth code + PKCE, confidential client with a managed-identity federated credential (no
  secret), `User.Read` only. Elevation = active member of `HM360_ADMIN_GROUP_ID` via `/me/transitiveMemberOf`.
* `hm-360-data` token: fine-grained, that repo only, Contents read/write, no Workflows permission, so the server can
  never change the workflow that runs on the desktop. The bot code runs from the desktop's hm-360 checkout.

## Roadmap

1. **v1:** inventory, Windows and app update status, results page + PDF.
2. **v1.1:** machine checks: event log errors, NIC settings, BIOS updates (HP, Lenovo) and BIOS age.
3. **v1.2 (this):** network health, disk and battery health, service health page, Options page.
4. Next: more vendor lookups (Dell, drivers, disk firmware),
   on-demand vulnerability check. Report only: no remediation (that is Remediation 360).
4. Wider research (non-official sources, tiered models) once a model budget is set.
