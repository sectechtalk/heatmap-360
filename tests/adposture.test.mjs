// AD posture page: PingCastle summaries read from a local folder, checked strictly, served to admins only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAdPosture, checkSummary } from '../server/adposture.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const summary = (over = {}) => ({
  schema: 'hm360.adposture/1', tool: 'PingCastle', engineVersion: '3.3.0.1', domain: 'Contoso.Example', generatedAt: '2026-11-22T03:00:00Z', maturityLevel: 3,
  scores: { global: 40, staleObjects: 40, privilegedAccounts: 25, trusts: 0, anomalies: 30 },
  rules: [
    { id: 'P-Delegated', category: 'PrivilegedAccounts', points: 20, rationale: 'Admin accounts can be delegated', model: 'Kerberos' },
    { id: 'S-PwdNeverExpires', category: 'StaleObjects', points: 1, rationale: '3 accounts never expire', model: '' },
  ],
  ...over,
});
async function folder(files) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-ad-'));
  for (const [name, value] of Object.entries(files)) await writeFile(path.join(dir, name), typeof value === 'string' ? value : JSON.stringify(value));
  return dir;
}

test('checkSummary keeps a valid PingCastle summary, lower-cases the domain and sorts rules by points', () => {
  const s = checkSummary(summary({ rules: [...summary().rules].reverse() }), '20261122030000');
  assert.equal(s.domain, 'contoso.example');
  assert.equal(s.scores.global, 40);
  assert.deepEqual(s.rules.map(r => r.id), ['P-Delegated', 'S-PwdNeverExpires']);
});

test('checkSummary refuses anything that is not a clean PingCastle summary', () => {
  const bad = [
    null, {}, summary({ schema: 'x' }), summary({ tool: 'Other' }), summary({ domain: '../etc' }), summary({ generatedAt: 'soon' }),
    summary({ scores: { ...summary().scores, global: 101 } }), summary({ scores: { ...summary().scores, trusts: undefined } }),
    summary({ rules: [{ id: 'bad id', category: 'Trusts', points: 1 }] }), summary({ rules: [{ id: 'T-x', category: 'Unknown', points: 1 }] }),
    summary({ rules: Array.from({ length: 501 }, (_, i) => ({ id: `A-${i}`, category: 'Anomalies', points: 0 })) }),
  ];
  for (const b of bad) assert.equal(checkSummary(b, '20261122030000'), null, JSON.stringify(b)?.slice(0, 80));
});

test('list: oldest first, rules only for the newest two scans per domain, unreadable files counted and skipped', async () => {
  const dir = await folder({
    'pingcastle-20261101030000.json': summary({ generatedAt: '2026-11-01T03:00:00Z', scores: { ...summary().scores, global: 60 } }),
    'pingcastle-20261108030000.json': summary({ generatedAt: '2026-11-08T03:00:00Z' }),
    'pingcastle-20261108030000.html': '<html>report</html>',
    'pingcastle-20261115030000.json': `﻿${JSON.stringify(summary({ generatedAt: '2026-11-15T03:00:00Z' }))}`, // PowerShell BOM tolerated
    'pingcastle-20261116030000.json': '{ not json',
    'pingcastle-20261117030000.json': summary({ tool: 'Other' }),
    'notes.txt': 'ignored', 'ad_hc_contoso.example.xml': '<x/>',
  });
  const out = await createAdPosture({ dir }).list();
  assert.equal(out.configured, true);
  assert.equal(out.folderFound, true);
  assert.equal(out.skipped, 2);
  assert.deepEqual(out.scans.map(s => s.id), ['20261101030000', '20261108030000', '20261115030000']);
  assert.equal(out.scans[0].rules, undefined, 'older scans carry scores and a rule count only');
  assert.equal(out.scans[0].ruleCount, 2);
  assert.equal(out.scans[2].rules.length, 2);
  assert.deepEqual(out.scans.map(s => s.hasReport), [false, true, false]);
});

test('list and report: no folder, or no folder configured, is not an error', async () => {
  assert.deepEqual(await createAdPosture({}).list(), { configured: false, folderFound: false, scans: [], skipped: 0 });
  const missing = await createAdPosture({ dir: path.join(os.tmpdir(), 'hm360-ad-missing-x') }).list();
  assert.equal(missing.folderFound, false);
  assert.equal(await createAdPosture({}).report('20261108030000'), null);
});

test('report: only pingcastle-<14 digits>.html from the folder, nothing else', async () => {
  const dir = await folder({ 'pingcastle-20261108030000.html': '<html>report</html>', 'pingcastle-20261108030000.xml': '<x/>' });
  await mkdir(path.join(dir, 'sub'));
  const ad = createAdPosture({ dir });
  assert.equal(String(await ad.report('20261108030000')), '<html>report</html>');
  for (const id of ['../x', '2026110803000', '20261108030000.xml', 'sub']) assert.equal(await ad.report(id), null, id);
});

test('config: the AD posture folder is local only', () => {
  assert.match(loadConfig({}, '/app').adposture.dir.replace(/\\/g, '/'), /\/app\/data\/adposture$/);
  assert.equal(loadConfig({ HM360_DATA_REPO: 'owner/data', HM360_GITHUB_TOKEN: 't' }, '/app').adposture, null, 'a GitHub-backed copy has none by default');
  assert.match(loadConfig({ HM360_ADPOSTURE_DIR: '/data/adposture' }, '/app').adposture.dir.replace(/\\/g, '/'), /\/data\/adposture$/);
  const compose = readFileSync(new URL('../compose.yaml', import.meta.url), 'utf8');
  assert.match(compose, /HM360_ADPOSTURE_DIR: \/data\/adposture/);
  assert.match(compose, /- \.\/data\/adposture:\/data\/adposture:ro/, 'mounted read-only in the container');
});

test('API: admins only; summaries as JSON and the report as a download', async () => {
  const dir = await folder({ 'pingcastle-20261108030000.json': summary(), 'pingcastle-20261108030000.html': '<html>report</html>' });
  const data = await mkdtemp(path.join(os.tmpdir(), 'hm360-ad-data-'));
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: data, HM360_ADPOSTURE_DIR: dir, ...env });
    const server = createApp({ config, store: createLocalStore(data), auth: null }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const anon = await open({});
  try {
    assert.equal((await fetch(`${anon.base}/api/admin/adposture`)).status, 401);
    assert.equal((await fetch(`${anon.base}/api/admin/adposture/20261108030000/report.html`)).status, 401);
  } finally { anon.server.close(); }
  const dev = await open({ HM360_DEV_ADMIN: '1' });
  try {
    const j = await (await fetch(`${dev.base}/api/admin/adposture`)).json();
    assert.equal(j.scans[0].domain, 'contoso.example');
    const r = await fetch(`${dev.base}/api/admin/adposture/20261108030000/report.html`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-disposition'), /attachment; filename="?PingCastle-20261108030000\.html"?/);
    assert.equal((await fetch(`${dev.base}/api/admin/adposture/20261101030000/report.html`)).status, 404);
    assert.equal((await fetch(`${dev.base}/api/admin/adposture/..%2Fx/report.html`)).status, 404);
  } finally { dev.server.close(); }
});

test('UI: AD posture under Scans and How to set up under Tools, routed, and the setup page covers PingCastle end to end', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /href="#vulnscans"[^\n]*\n\s*<a class="nav-item sub" href="#adposture" data-route="adposture"><span data-nav-icon="shield-check"><\/span>AD posture<\/a>/);
  const tools = html.slice(html.indexOf('data-section="tools"'));
  assert.match(tools, /<a class="nav-item" href="#setup" data-route="setup"><span data-nav-icon="wrench"><\/span>How to set up<\/a>/);
  assert.match(app, /name === 'adposture' \? await viewAdPosture\(\)/);
  assert.match(app, /name === 'setup' \? viewSetup\(\)/);
  assert.match(app, /h\('h1', \{\}, 'How to set up HeatMap 360'\)/);
  const setup = app.slice(app.indexOf('function viewSetup'), app.indexOf('// ---------- Settings'));
  for (const s of ['Invoke-PingCastleScan.ps1', '-SaveCredential', 'Register-ScheduledTask', 'Unregister-ScheduledTask', 'contoso.example', 'data\\\\adposture', 'pingcastle.com', 'Never use a Domain Admin account'])
    assert.ok(setup.includes(s), s);
  assert.match(app.slice(app.indexOf('const OVERVIEW_NOT_BUILT')), /Entra posture page/);
});

test('the scan script is read-only toward the domain and never prints the password', () => {
  const ps = readFileSync(new URL('../tools/adposture/Invoke-PingCastleScan.ps1', import.meta.url), 'utf8');
  assert.match(ps, /'--healthcheck'/);
  assert.doesNotMatch(ps, /--(rebuild|carto|scanner|generatekey|upload|sendxml|api)/i, 'health check only, nothing sent anywhere');
  assert.doesNotMatch(ps, /Write-(Output|Host|Verbose)[^\n]*(Password|\$pcArgs)/i);
  assert.match(ps, /Export-Clixml/);
  const params = ps.slice(ps.indexOf('param('), ps.indexOf("$ErrorActionPreference"));
  assert.doesNotMatch(params, /\$PSScriptRoot|Join-Path/, 'Windows PowerShell 5.1 leaves $PSScriptRoot empty in param() under -File');
  assert.match(ps, /schema\s+= 'hm360\.adposture\/1'/);
  for (const k of ['GlobalScore', 'StaleObjectsScore', 'PrivilegiedGroupScore', 'TrustScore', 'AnomalyScore', 'RiskRules.HealthcheckRiskRule']) assert.ok(ps.includes(k), k);
});
