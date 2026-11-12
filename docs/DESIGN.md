# hm360 design

## Envelope (collector output), schema `hm360.envelope/1`

```json
{ "schema": "hm360.envelope/1", "collector": "windows", "host": "PC01", "collectedAt": "2026-11-01T12:00:00Z",
  "os": { "name": "Microsoft Windows 11 Pro", "version": "24H2", "build": "26100.2033", "edition": "Professional" },
  "uptimeHours": 500, "lastBoot": "...", "pendingReboot": true,
  "hotfixes": [ { "id": "KB5000001", "installedOn": "2026-10-01" } ],
  "defender": { "enabled": true, "realTime": true, "signatureAgeDays": 1, "tamperProtected": true },
  "bitlocker": { "protection": "On", "method": "XtsAes128" }, "secureBoot": true, "tpm": { "present": true, "ready": true },
  "firewall": { "domain": true, "private": true, "public": true },
  "disks": [ { "drive": "C:", "sizeGB": 476.3, "freeGB": 120.5 } ],
  "software": [ { "name": "Google Chrome", "version": "130.0.6723.92", "publisher": "Google LLC" } ],
  "errors": [] }
```

Every field except `schema`, `host` and `collectedAt` is optional. Missing data is graded **unknown**, never ok.

## Health checks

| Check | ok | warn | bad |
|---|---|---|---|
| Collector data | < 1.1 days old | 1.1 to 7 days | > 7 days |
| Uptime | <= 14 days | 15 to 30 | > 30 |
| Pending reboot | none | pending | |
| Last update installed | <= 35 days | 36 to 60 | > 60 |
| Defender real-time | on | | off |
| Defender signatures | <= 3 days | 4 to 7 | > 7 |
| BitLocker (system drive) | On | | Off |
| Secure Boot | on | off | |
| TPM | present and ready | otherwise | |
| Firewall profiles | all on | | any off |
| Disk free | >= 15% | < 15% | < 5% |

Disk thresholds come from `collectors/hm360.config.json`. Heat: ok 0, unknown 5, warn 12, bad 30 per check, capped at 100.

## Vulnerability matching

* **Source:** CISA Known Exploited Vulnerabilities (KEV), the list of CVEs exploited in the wild. EPSS (FIRST) adds
  the probability of exploitation in the next 30 days. Both are free and keyless; cached in `data/feeds/kev.json`.
* **Software:** a KEV entry is a candidate when the first significant word of its product appears in an installed
  program's name and its vendor appears in the program's name or publisher. Aliases cover names that differ
  (KEV `Google Chromium *` -> Chrome, Edge, Brave; KEV `Microsoft Office/Word/Excel/...` -> Microsoft Office / 365).
* **Windows:** KEV entries for Microsoft Windows / Win32k are candidates when they were added to KEV after the newest
  installed update. Cumulative updates make "patched after the entry was added" a good proxy for "fixed".
* Exposure heat: 10 per candidate, +10 if KEV marks known ransomware use, +10 if EPSS >= 0.5. Capped at 100.

## Roadmap

1. **Now:** Windows collector, local dashboard, KEV + EPSS.
2. Version-accurate matching: NVD CVE API CPE ranges for each candidate (free key raises the rate limit) and MSRC
   CVRF (KB per CVE per Windows build) so Windows candidates become "fixed by KBxxxx, installed / missing".
3. Linux and macOS collectors (same envelope).
4. Trend: daily snapshots so the heat map shows change over time.
5. Other computers post envelopes over HTTPS; Entra sign-in with app roles (like e360) before anything leaves 127.0.0.1.
