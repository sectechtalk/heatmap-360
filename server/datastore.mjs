// Where uploads and results live. Production: the private GitHub repo hm-360-data (contents API, token with
// Contents read/write on that one repo only, no Workflows permission, so HeatMap can never change what the bot runs).
// Development and tests: a local folder with the same layout.
//
//   inbox/<id>.json     upload record { schema: hm360.upload/1, id, receivedAt, tokenHash, inventory }
//   results/<id>.json   bot output    { schema: hm360.result/1, ... }  (the bot deletes the inbox file)
//   settings/findings.json  where the findings table lives { schema: hm360.settings/1, findings: { account, table } },
//                       written by Project 360 Admins on the Settings page, read by bot/findings.mjs
import { mkdir, readFile, readdir, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';

const SAFE = /^((inbox|results)\/[0-9]{14}-[0-9a-f]{8}|settings\/findings)\.json$/;
function check(p) { if (!SAFE.test(p)) throw new Error(`refusing data path ${p}`); return p; }

export function createLocalStore(dir) {
  return {
    kind: 'local',
    async get(p) {
      try { return JSON.parse(await readFile(path.join(dir, check(p)), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    },
    async put(p, value) {
      const file = path.join(dir, check(p));
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(`${file}.tmp`, JSON.stringify(value, null, 1));
      await rename(`${file}.tmp`, file);
    },
    async list(folder) {
      try { return (await readdir(path.join(dir, folder))).filter(n => /^[0-9]{14}-[0-9a-f]{8}\.json$/.test(n)).sort(); } catch { return []; }
    },
  };
}

export function createGitHubStore({ owner, repo, branch = 'main', token, fetchImpl = (...a) => fetch(...a) }) {
  if (!owner || !repo || !token) throw new Error('GitHub data store needs owner, repo and token');
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents`;
  const headers = extra => ({ authorization: `Bearer ${token}`, 'x-github-api-version': '2022-11-28', 'user-agent': 'hm360', ...extra });
  const call = async (url, init = {}) => {
    const r = await fetchImpl(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(20_000) });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub data store: HTTP ${r.status}`);
    return r;
  };
  return {
    kind: 'github',
    async get(p) {
      const r = await call(`${base}/${check(p)}?ref=${encodeURIComponent(branch)}`, { headers: headers({ accept: 'application/vnd.github.raw+json' }) });
      return r ? JSON.parse(await r.text()) : null;
    },
    async put(p, value, message = `hm360: ${p}`) {
      const body = { message, branch, content: Buffer.from(JSON.stringify(value, null, 1)).toString('base64') };
      // Replacing a file (only settings/ ever is) needs its current sha.
      if (p.startsWith('settings/')) {
        const cur = await call(`${base}/${check(p)}?ref=${encodeURIComponent(branch)}`, { headers: headers({ accept: 'application/vnd.github+json' }) });
        if (cur) body.sha = (await cur.json()).sha;
      }
      const r = await call(`${base}/${check(p)}`, { method: 'PUT', headers: headers({ accept: 'application/vnd.github+json', 'content-type': 'application/json' }), body: JSON.stringify(body) });
      if (!r) throw new Error('GitHub data store: repository or branch not found');
    },
    async list(folder) {
      const r = await call(`${base}/${folder}?ref=${encodeURIComponent(branch)}`, { headers: headers({ accept: 'application/vnd.github+json' }) });
      if (!r) return [];
      return (await r.json()).map(e => e.name).filter(n => /^[0-9]{14}-[0-9a-f]{8}\.json$/.test(n)).sort();
    },
  };
}
