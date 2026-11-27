// Entra posture page: Maester summaries read from a local folder, checked strictly, served to admins only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createEntraPosture, checkSummary, passRate } from '../server/entraposture.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const TENANT = '00000000-0000-4000-8000-000000000001';
const summary = (over = {}) => ({
  schema: 'hm360.entraposture/1', tool: 'Maester', engineVersion: '2.3.0', tenantId: TENANT, tenantName: 'Contoso', generatedAt: '2026-11-22T05:00:00Z',
  counts: { total: 4, passed: 2, failed: 1, skipped: 1, notRun: 0, error: 0, investigate: 0 },
  tests: [
    { id: 'MT.1001', title: 'At least one Conditional Access policy is configured with device compliance', result: 'Passed', severity: 'High', block: 'Conditional Access Baseline Policies', helpUrl: 'https://maester.dev/docs/tests/MT.1001' },
    { id: 'MT.1005', title: 'All Conditional Access policies are configured to exclude at least one emergency account', result: 'Failed', severity: 'Critical', block: 'Conditional Access Baseline Policies', helpUrl: 'https://maester.dev/docs/tests/MT.1005' },
    { id: 'EIDSCA.AF01', title: 'Default Authentication Method Policy', result: 'Passed', severity: '', block: 'EIDSCA', helpUrl: '' },
    { id: 'CISA.MS.EXO.01.1', title: 'Automatic forwarding to external domains SHALL be disabled', result: 'Skipped', severity: 'High', block: 'CISA', helpUrl: 'javascript:alert(1)' },
  ],
  ...over,
});
async function folder(files) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-ep-'));
  for (const [name, value] of Object.entries(files)) await writeFile(path.join(dir, name), typeof value === 'string' ? value : JSON.stringify(value));
  return dir;
}

test('passRate counts only checks that passed or failed', () => {
  assert.equal(passRate({ passed: 3, failed: 1 }), 75);
  assert.equal(passRate({ passed: 0, failed: 0 }), null);
});

test('checkSummary keeps a valid Maester summary, keys it by tenant ID and drops unsafe links', () => {
  const s = checkSummary(summary(), '20261122050000');
  assert.equal(s.tenant, TENANT);
  assert.equal(s.tenantName, 'Contoso');
  assert.equal(s.passRate, 67);
  assert.equal(s.tests.length, 4);
  assert.equal(s.tests[3].helpUrl, '', 'only https links survive');
  assert.equal(s.tests[2].severity, '');
});

test('checkSummary refuses anything that is not a clean Maester summary', () => {
  const bad = [
    null, {}, summary({ schema: 'x' }), summary({ tool: 'Other' }), summary({ generatedAt: 'soon' }),
    summary({ counts: { ...summary().counts, failed: -1 } }), summary({ counts: { ...summary().counts, total: undefined } }),
    summary({ tests: [{ id: 'MT.1', result: 'Maybe' }] }), summary({ tests: [{ result: 'Passed' }] }), summary({ tests: 'none' }),
    summary({ tests: Array.from({ length: 3001 }, (_, i) => ({ id: `MT.${i}`, result: 'Passed' })) }),
  ];
  for (const b of bad) assert.equal(checkSummary(b, '20261122050000'), null, JSON.stringify(b)?.slice(0, 80));
});

test('list: oldest first, tests only for the newest two runs per tenant, unreadable files counted and skipped', async () => {
  const dir = await folder({
    'maester-20261108050000.json': summary({ generatedAt: '2026-11-08T05:00:00Z' }),
    'maester-20261115050000.json': summary({ generatedAt: '2026-11-15T05:00:00Z' }),
    'maester-20261115050000.html': '<html>report</html>',
    'maester-20261122050000.json': `﻿${JSON.stringify(summary())}`, // PowerShell BOM tolerated
    'maester-20261123050000.json': '{ not json',
    'maester-20261124050000.json': summary({ tool: 'Other' }),
    'notes.txt': 'ignored',
  });
  const out = await createEntraPosture({ dir }).list();
  assert.equal(out.configured, true);
  assert.equal(out.skipped, 2);
  assert.deepEqual(out.scans.map(s => s.id), ['20261108050000', '20261115050000', '20261122050000']);
  assert.equal(out.scans[0].tests, undefined, 'older runs carry counts only');
  assert.equal(out.scans[0].counts.failed, 1);
  assert.equal(out.scans[2].tests.length, 4);
  assert.deepEqual(out.scans.map(s => s.hasReport), [false, true, false]);
});

test('list and report: no folder, or no folder configured, is not an error; report ids are strict', async () => {
  assert.deepEqual(await createEntraPosture({}).list(), { configured: false, folderFound: false, scans: [], skipped: 0 });
  assert.equal((await createEntraPosture({ dir: path.join(os.tmpdir(), 'hm360-ep-missing-x') }).list()).folderFound, false);
  const dir = await folder({ 'maester-20261122050000.html': '<html>report</html>' });
  const ep = createEntraPosture({ dir });
  assert.equal(String(await ep.report('20261122050000')), '<html>report</html>');
  for (const id of ['../x', '2026112205000', '20261122050000.json']) assert.equal(await ep.report(id), null, id);
});

test('config: the Entra posture folder is local only and mounted read-only', () => {
  assert.match(loadConfig({}, '/app').entraposture.dir.replace(/\\/g, '/'), /\/app\/data\/entraposture$/);
  assert.equal(loadConfig({ HM360_DATA_REPO: 'owner/data', HM360_GITHUB_TOKEN: 't' }, '/app').entraposture, null);
  const compose = readFileSync(new URL('../compose.yaml', import.meta.url), 'utf8');
  assert.match(compose, /HM360_ENTRAPOSTURE_DIR: \/data\/entraposture/);
  assert.match(compose, /- \.\/data\/entraposture:\/data\/entraposture:ro/);
});

test('API: admins only; summaries as JSON and the report as a download', async () => {
  const dir = await folder({ 'maester-20261122050000.json': summary(), 'maester-20261122050000.html': '<html>report</html>' });
  const data = await mkdtemp(path.join(os.tmpdir(), 'hm360-ep-data-'));
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: data, HM360_ENTRAPOSTURE_DIR: dir, ...env });
    const server = createApp({ config, store: createLocalStore(data), auth: null }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const anon = await open({});
  try {
    assert.equal((await fetch(`${anon.base}/api/admin/entraposture`)).status, 401);
    assert.equal((await fetch(`${anon.base}/api/admin/entraposture/20261122050000/report.html`)).status, 401);
  } finally { anon.server.close(); }
  const dev = await open({ HM360_DEV_ADMIN: '1' });
  try {
    const j = await (await fetch(`${dev.base}/api/admin/entraposture`)).json();
    assert.equal(j.scans[0].tenantName, 'Contoso');
    const r = await fetch(`${dev.base}/api/admin/entraposture/20261122050000/report.html`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-disposition'), /attachment; filename="?Maester-20261122050000\.html"?/);
    assert.equal((await fetch(`${dev.base}/api/admin/entraposture/20261101050000/report.html`)).status, 404);
  } finally { dev.server.close(); }
});

test('UI: Entra posture under Scans, routed, and the setup page covers Maester end to end', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /href="#attackpaths"[^\n]*\n\s*<a class="nav-item sub" href="#entraposture" data-route="entraposture"><span data-nav-icon="badge-check"><\/span>Entra posture<\/a>/);
  assert.match(app, /name === 'entraposture' \? await viewEntraPosture\(\)/);
  const setup = app.slice(app.indexOf('function viewSetup'), app.indexOf('// ---------- Settings'));
  for (const s of ['New-MaesterApp.ps1', 'Invoke-MaesterScan.ps1', 'hm360-maester:2.3.0', 'Register-ScheduledTask', "'HeatMap 360 Maester'", 'contoso.example', 'data\\\\entraposture', 'setup-entraposture'])
    assert.ok(setup.includes(s), s);
});

test('scripts: the app gets the read-only Graph permissions Maester documents, and the setup page lists the same ones', () => {
  const ps = readFileSync(new URL('../tools/entraposture/New-MaesterApp.ps1', import.meta.url), 'utf8');
  const block = ps.slice(ps.indexOf('$permissions = @('), ps.indexOf(')', ps.indexOf('$permissions = @(') + 17));
  const perms = [...block.matchAll(/'([A-Za-z.-]+)'/g)].map(m => m[1]).sort();
  assert.equal(perms.length, 27);
  for (const p of perms) assert.match(p, /^[A-Za-z-]+\.Read\.[A-Za-z]+$/, p);
  assert.ok(!/ReadWrite/.test(block), 'no write permission');
  assert.match(ps, /KeyExportPolicy NonExportable/);
  assert.match(ps, /'AzureADMyOrg'/);
  // The setup page's list, rebuilt the way app.js builds it.
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const src = app.slice(app.indexOf('const mtPermissions'), app.indexOf(';', app.indexOf('const mtPermissions')));
  const mtPermissions = new Function(`${src}; return mtPermissions;`)();
  assert.deepEqual([...mtPermissions].sort(), perms);
});

test('scripts: the token goes to the container on stdin only, never printed, and Maester runs without telemetry', () => {
  const scan = readFileSync(new URL('../tools/entraposture/Invoke-MaesterScan.ps1', import.meta.url), 'utf8');
  assert.match(scan, /\$token \| & docker start -ai/);
  assert.doesNotMatch(scan, /docker (create|run)[^\n]*(-e |--env)/, 'no environment variables into the container');
  assert.doesNotMatch(scan, /Write-(Output|Host|Verbose)[^\n]*\$token/i);
  assert.doesNotMatch(scan, /client_secret/);
  const params = scan.slice(scan.indexOf('param('), scan.indexOf('$ErrorActionPreference'));
  assert.doesNotMatch(params, /\$PSScriptRoot|Join-Path/, 'Windows PowerShell 5.1 leaves $PSScriptRoot empty in param() under -File');
  const run = readFileSync(new URL('../tools/entraposture/runner/run.ps1', import.meta.url), 'utf8');
  for (const s of ['DisableTelemetry = $true', 'SkipVersionCheck = $true', "schema        = 'hm360.entraposture/1'", '[Console]::In.ReadLine()']) assert.ok(run.includes(s), s);
  assert.doesNotMatch(run, /ResultDetail/, 'the summary leaves out per-check details, which can name users');
  const docker = readFileSync(new URL('../tools/entraposture/runner/Dockerfile', import.meta.url), 'utf8');
  assert.match(docker, /Install-Module Maester -RequiredVersion 2\.3\.0/);
  assert.match(docker, /^USER maester$/m);
});
