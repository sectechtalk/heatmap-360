# hm360 design (v1)

## Data formats

* **Upload** (scanner → server): `hm360.inventory/1`, validated by `server/schema.mjs` (every field typed and bounded,
  unknown fields rejected). See `tests/fixtures/inventory.sample.json`.
* **Upload record** (server → `hm-360-data/inbox/<id>.json`): `{ schema: "hm360.upload/1", id, receivedAt, tokenHash, inventory }`.
  `id` = UTC `yyyyMMddHHmmss-<8 hex>`. The token is 32 random bytes returned once to the scanner; only its SHA-256 is stored.
* **Result** (bot → `hm-360-data/results/<id>.json`): `hm360.result/1` with `summary`, `windows`, `knownIssues`, `apps`,
  `health`, `exploited`, `hardware` and the inventory. The bot deletes the inbox file. Rejected uploads get a result with `rejected`.

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

## Grades

`ok` / `warn` / `bad` / `unknown` per area; overall = worst known grade. Windows: current ok, one release behind warn,
more or unsupported bad. Known issues: any open issue warn. Apps: any update warn. Health: worst check.

## Security

* Upload endpoint: 1 MB body, 5 per IP per 10 minutes, 20 per IP per day, 500 per day overall (env overrides),
  strict schema, scrub. Ingress client IP via `trust proxy`.
* Uploader access: bearer token compared by hash in constant time; unknown scan and wrong token both return 404.
* Admin access: Entra auth code + PKCE, confidential client with a managed-identity federated credential (no
  secret), `User.Read` only. Elevation = active member of `HM360_ADMIN_GROUP_ID` via `/me/transitiveMemberOf`.
* `hm-360-data` token: fine-grained, that repo only, Contents read/write, no Workflows permission, so the server can
  never change the workflow that runs on the desktop. The bot code runs from the desktop's hm-360 checkout.

## Roadmap (agreed with Aaron, 2026-11-13)

1. **v1 (this):** inventory, Windows and app update status, results page + PDF.
2. Firmware and driver updates from vendors' official sites (motherboard, NIC, GPU, disks), with vendor-reported problems.
3. Network health (speed test, host to gateway), NIC settings, event log errors, online service status pages.
4. Wider research (non-official sources, tiered models) once a model budget is set.
