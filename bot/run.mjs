#!/usr/bin/env node
// HeatMap 360 bot. Runs on the admin's desktop as a GitHub Actions self-hosted runner job in hm-360-data (see
// bot/process.yml): GitHub starts it when HeatMap pushes an upload. It reads inbox/*.json, writes results/<id>.json,
// removes the processed inbox file and commits. Uploads are untrusted data: they are validated again here and
// nothing in them is executed or used to build a command or file path.
//
//   node bot/run.mjs --repo <hm-360-data checkout> [--commit] [--cache <folder>]
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from './analyze.mjs';
import { parseReleaseInfo, RELEASE_PAGES } from './windows.mjs';
import { createWingetLookup } from './apps.mjs';
import { createFeeds } from './kev.mjs';
import { createCveLookup } from './cve.mjs';
import { createReleaseNotesLookup, createGithubReleaseLookup } from './appissues.mjs';
import { checkInventory } from '../server/schema.mjs';

const ID = /^[0-9]{14}-[0-9a-f]{8}$/;
const UA = 'HeatMap360-bot/1.0 (+https://github.com/<your-account>/heatmap-360)';

async function page(url, fetchImpl, { missingOk = false } = {}) {
  const r = await fetchImpl(url, { headers: { 'user-agent': UA, accept: 'text/html, application/xml, text/xml' }, signal: AbortSignal.timeout(30_000) });
  if (missingOk && r.status === 404) return null;
  if (!r.ok) throw new Error(`${new URL(url).hostname} returned HTTP ${r.status}`);
  return r.text();
}
// Vendor firmware catalogs are fetched only from these hosts (bot/firmware.mjs builds the URLs).
const VENDOR_HOSTS = new Set(['hpia.hpcloud.hp.com', 'download.lenovo.com']);

export function createSources({ fetchImpl = (...a) => fetch(...a), cacheDir, githubToken = null }) {
  const memo = new Map();
  const once = (key, fn) => { if (!memo.has(key)) { const p = fn(); memo.set(key, p); p.catch(() => memo.delete(key)); } return memo.get(key); };
  const feeds = createFeeds({ dir: cacheDir, fetchImpl });
  return {
    releaseInfo: gen => once(`rel${gen}`, async () => {
      const info = parseReleaseInfo(await page(RELEASE_PAGES[gen], fetchImpl));
      if (!info.builds.size) throw new Error('Could not read the Windows release information page (layout changed?)');
      return info;
    }),
    knownIssuesPage: url => once(url, () => page(url, fetchImpl)),
    wingetLatest: createWingetLookup({ fetchImpl, token: githubToken }),
    vendorFile: url => {
      const u = new URL(url);
      if (u.protocol !== 'https:' || !VENDOR_HOSTS.has(u.hostname)) return Promise.reject(new Error(`${u.hostname} is not an allowed vendor source`));
      return once(url, () => page(url, fetchImpl, { missingOk: true }));
    },
    cveRecord: createCveLookup({ dir: cacheDir, fetchImpl }),
    releaseNotes: createReleaseNotesLookup({ fetchImpl }),
    githubReleaseNotes: createGithubReleaseLookup({ fetchImpl, token: githubToken }),
    kev: () => once('kev', async () => { const s = await feeds.refresh(); if (!s.kev) throw new Error(s.lastError || 'KEV catalog unavailable'); return s; }),
  };
}

export async function processRepo(repo, sources, { now = () => Date.now(), log = console.log } = {}) {
  const inbox = path.join(repo, 'inbox'), results = path.join(repo, 'results');
  await mkdir(results, { recursive: true });
  let names = [];
  try { names = (await readdir(inbox)).filter(n => ID.test(n.replace(/\.json$/, '')) && n.endsWith('.json')).sort(); } catch { /* empty inbox */ }
  const done = [];
  for (const name of names) {
    const id = name.slice(0, -5);
    try {
      const upload = JSON.parse(await readFile(path.join(inbox, name), 'utf8'));
      const ok = upload?.schema === 'hm360.upload/1' && upload.id === id && /^[0-9a-f]{64}$/.test(upload.tokenHash || '') ? checkInventory(upload.inventory) : { ok: false, error: 'not an hm360 upload record' };
      const result = ok.ok
        ? await analyze({ ...upload, inventory: ok.inventory }, sources, now())
        : { schema: 'hm360.result/1', id, receivedAt: upload?.receivedAt ?? null, processedAt: new Date(now()).toISOString(), tokenHash: upload?.tokenHash ?? null, rejected: ok.error };
      await writeFile(path.join(results, name), JSON.stringify(result, null, 1));
      await rm(path.join(inbox, name));
      done.push(id);
      log(`hm360 bot: ${id} ${result.rejected ? `rejected (${result.rejected})` : result.summary.overall}`);
    } catch (e) { log(`hm360 bot: ${id} failed: ${e.message}`); }
  }
  return done;
}

function git(repo, ...args) { return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim(); }

async function main(argv) {
  const arg = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
  const repo = path.resolve(arg('--repo') || '.');
  const cacheDir = path.resolve(arg('--cache') || path.join(os.homedir(), '.hm360-bot-cache'));
  await mkdir(cacheDir, { recursive: true });
  const sources = createSources({ cacheDir, githubToken: process.env.GITHUB_TOKEN || null });
  const done = await processRepo(repo, sources);
  if (!argv.includes('--commit') || !done.length) return;
  git(repo, 'add', '-A', 'inbox', 'results');
  git(repo, '-c', 'user.name=hm360-bot', '-c', 'user.email=hm360-bot@users.noreply.github.com', 'commit', '-q', '-m', `Results for ${done.length} scan${done.length > 1 ? 's' : ''}`);
  for (let attempt = 1; ; attempt++) {
    try { git(repo, 'push', '-q', 'origin', 'HEAD'); break; }
    catch (e) { if (attempt >= 4) throw e; git(repo, 'pull', '-q', '--rebase', 'origin', git(repo, 'rev-parse', '--abbrev-ref', 'HEAD')); }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(e => { console.error(e.message); process.exit(1); });
}
