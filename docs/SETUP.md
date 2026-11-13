# Hosted setup

Same pattern as e360 and r360: Azure Container Apps (consumption, scale to zero), a user-assigned managed identity for
sign-in (no client secret), image on GitHub Container Registry. Target cost $0.

## 1. GitHub

1. Repos: `hm-360` (private, code), `heatmap-360` (public, export only), `hm-360-data` (private, uploads and results).
2. Fine-grained token for HeatMap: **Repository access: only `hm-360-data`**; permissions **Contents: Read and write**
   (Metadata read is added automatically). Nothing else, in particular no Workflows. Store it only as the Container
   Apps secret `hm360-github-token`.
3. In `hm-360-data`, add `.github/workflows/process.yml` from `bot/process.yml`.

## 2. The bot on the admin desktop

1. `git clone https://github.com/sectechtalk/heatmap-360 C:\src\heatmap-360`, then `npm ci` there (Node 22+).
2. `hm-360-data` → Settings → Actions → Runners → New self-hosted runner (Windows). Follow GitHub's steps, add the
   label `hm360`, and install it as a service.
3. Set the machine environment variable `HM360_BOT_DIR=C:\src\heatmap-360` and restart the runner service.
4. Test: Actions → process scans → Run workflow. With an empty inbox it finishes with nothing to do.

When the desktop is off, uploads wait in `inbox/`; the hourly schedule and the next push pick them up.

## 3. Entra

1. Security group **HeatMap 360 Admins** (role-assignable not needed). Turn on PIM for Groups for it and make admins
   **eligible** members, with the activation length you want. Note the group object ID.
2. App registration **hm360-web**, single tenant. Redirect URI (Web): `https://<app fqdn>/auth/callback` (and
   `http://localhost:3460/auth/callback` for testing). API permission: Microsoft Graph delegated `User.Read` only.
3. User-assigned managed identity **id-hm360**. On hm360-web → Certificates & secrets → Federated credentials → add
   "Managed identity" → id-hm360 (audience `api://AzureADTokenExchange`). No client secret.

## 4. Container Apps

Container app `app-hm360` with id-hm360 assigned, external HTTPS ingress on port 3460, 0-1 replicas, 0.25 vCPU / 0.5 GiB,
image `ghcr.io/sectechtalk/heatmap-360:<tag>` built from this repo's Dockerfile.

| Variable | Value |
|---|---|
| `HM360_PUBLIC_URL` | `https://<app fqdn>` (also fills in the scanner download) |
| `HM360_DATA_REPO` | `sectechtalk/heatmap-360-data` |
| `HM360_GITHUB_TOKEN` | secret ref `hm360-github-token` |
| `HM360_TENANT_ID` | tenant ID |
| `HM360_CLIENT_ID` | hm360-web application (client) ID |
| `HM360_MI_CLIENT_ID` | id-hm360 client ID |
| `HM360_ADMIN_GROUP_ID` | HeatMap 360 Admins object ID |
| `HM360_UPLOADS_PER_10MIN`, `HM360_UPLOADS_PER_DAY`, `HM360_UPLOADS_GLOBAL_DAY` | optional, defaults 5 / 20 / 500 |

Check: `https://<app fqdn>/api/health` returns `{"ok":true}`; **Get the scanner** downloads a script with your address
filled in; signing in without an active PIM activation shows "Elevate to see scan results".
