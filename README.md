# HeatMap 360 (hm360)

One heat map of **machine health** and the **known exploited vulnerabilities** that may affect each machine. Every
computer gets a row; every row gets three heat scores from 0 (cool) to 100 (hot):

| Score | Built from |
|---|---|
| **Health** | Defender real-time protection and signature age, BitLocker, Secure Boot, TPM, firewall profiles, free disk space, uptime |
| **Patching** | days since the newest installed update, pending reboot |
| **Exposure** | CISA KEV entries (exploited in the wild) that match installed software or postdate the newest Windows update, weighted by known ransomware use and FIRST EPSS score |

Select a machine to see each check and the list of KEV candidates with CVE links, EPSS and the CISA due date.

## How it works

```
 each Windows PC                                         the hm360 server
 collectors\Invoke-HM360Collect.ps1  ──writes──▶  data\inbox\windows-<COMPUTER>.json  ──▶  /api/machines  ──▶  dashboard
 (read-only, hourly scheduled task)                                                         (http://localhost:3460)
                                       CISA KEV + FIRST EPSS (daily, cached in data\feeds) ──▲
```

* **Collector**: PowerShell (5.1 or 7), read-only, writes one JSON envelope per computer. No remoting, WinRM or SSH,
  no inbound connections. A part that fails is recorded in the envelope's `errors` and shown on the dashboard.
* **Server**: Node 22 + Express, binds to 127.0.0.1. Keeps the newest envelope per computer, fetches the free CISA
  KEV catalog and EPSS scores at most once a day, and keeps working from the cache when a feed is down.
* **KEV matches are candidates, not findings.** KEV lists vendor and product, not version ranges, so the dashboard
  says *may apply* and links the CVE for you to check the version. Windows entries are compared with the date of the
  newest installed update (cumulative updates). See [docs/DESIGN.md](docs/DESIGN.md).

## Run it

```powershell
git clone https://github.com/sectechtalk/heatmap-360 C:\src\heatmap-360
cd C:\src\heatmap-360
npm install
npm start                                                            # http://localhost:3460
powershell -NoProfile -File collectors\Invoke-HM360Collect.ps1       # one collection now (elevated for BitLocker/Secure Boot)
powershell -NoProfile -File scripts\Register-HM360Task.ps1 -Apply    # hourly task, from an elevated prompt
```

Docker: `docker compose up -d --build`, then run the collector on the host (it writes to `data\inbox`, which the
container mounts). The scheduled task runs as SYSTEM, so per-user installed programs of signed-in users are not listed;
run the collector as the user too if you need them.

## Rules

* No secrets in git. The feeds need no keys.
* The collector only reads. It never installs, patches, reboots or changes a setting.
* $0: CISA KEV, FIRST EPSS and (next) NVD and MSRC are free.

## Tests

`npm test` and `npm run check`. Fixtures use fictional data (`PC01`, sample CVE IDs).
