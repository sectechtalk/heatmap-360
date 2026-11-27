// M365 & Azure posture page: Monkey365 summaries read from a local folder, checked strictly, served to admins only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createM365Posture, checkSummary, passRate } from '../server/m365posture.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const TENANT = '00000000-0000-4000-8000-000000000001';
const summary = (over = {}) => ({
  schema: 'hm360.m365posture/1', tool: 'Monkey365', engineVersion: '1.0.5', tenantId: TENANT, tenantName: 'Contoso', generatedAt: '2026-11-29T06:00:00Z',
  runs: [{ area: 'Microsoft365', ran: true, findings: 40, error: '' }, { area: 'Azure', ran: false, findings: 0, error: 'No subscription' }],
  counts: { total: 4, passed: 2, failed: 1, manual: 1, info: 0 },
  rules: [
    { id: 'exo0001', code: 'exo_forwarding', title: 'Ensure all forms of mail forwarding are blocked', instance: 'Microsoft365', area: 'ExchangeOnline', severity: 'High', status: 'Failed', failed: 3, helpUrl: 'https://learn.microsoft.com/exchange' },
    { id: 'teams0002', title: 'Ensure external access is restricted', instance: 'Microsoft365', area: 'MicrosoftTeams', severity: 'Medium', status: 'Passed', failed: 0, helpUrl: 'javascript:alert(1)' },
    { id: 'purview0001', title: 'Ensure audit log search is enabled', instance: 'Microsoft365', area: 'Purview', severity: 'Low', status: 'Passed', failed: 0, helpUrl: '' },
    { id: 'exo0009', title: 'Ensure the customer lockbox feature is enabled', instance: 'Microsoft365', area: 'ExchangeOnline', severity: 'Unknown', status: 'Manual', failed: 0, helpUrl: '' },
  ],
  ...over,
});
async function folder(files) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-mp-'));
  for (const [name, value] of Object.entries(files)) await writeFile(path.join(dir, name), typeof value === 'string' ? value : JSON.stringify(value));
  return dir;
}

test('passRate counts only rules that passed or failed', () => {
  assert.equal(passRate({ passed: 3, failed: 1 }), 75);
  assert.equal(passRate({ passed: 0, failed: 0 }), null);
});

test('checkSummary keeps a valid Monkey365 summary, keys it by tenant ID and drops unsafe links and unknown severities', () => {
  const s = checkSummary(summary(), '20261129060000');
  assert.equal(s.tenant, TENANT);
  assert.equal(s.passRate, 67);
  assert.equal(s.rules.length, 4);
  assert.equal(s.rules[1].helpUrl, '', 'only https links survive');
  assert.equal(s.rules[3].severity, '');
  assert.deepEqual(s.runs.map(r => [r.area, r.ran]), [['Microsoft365', true], ['Azure', false]]);
});

test('checkSummary refuses anything that is not a clean Monkey365 summary', () => {
  const bad = [
    null, {}, summary({ schema: 'x' }), summary({ tool: 'Maester' }), summary({ generatedAt: 'soon' }),
    summary({ counts: { ...summary().counts, failed: -1 } }), summary({ counts: { ...summary().counts, manual: undefined } }),
    summary({ rules: [{ id: 'x', status: 'Maybe', instance: 'Microsoft365' }] }), summary({ rules: [{ id: 'x', status: 'Passed', instance: 'Gcp' }] }),
    summary({ rules: [{ status: 'Passed', instance: 'Azure' }] }), summary({ rules: 'none' }), summary({ runs: [{ area: 'Other', ran: true }] }),
    summary({ rules: Array.from({ length: 3001 }, (_, i) => ({ id: `r${i}`, status: 'Passed', instance: 'Azure' })) }),
  ];
  for (const b of bad) assert.equal(checkSummary(b, '20261129060000'), null, JSON.stringify(b)?.slice(0, 80));
});

test('list: oldest first, rules only for the newest two runs per tenant, reports per area, unreadable files skipped', async () => {
  const dir = await folder({
    'monkey365-20261115060000.json': summary({ generatedAt: '2026-11-15T06:00:00Z' }),
    'monkey365-20261122060000.json': summary({ generatedAt: '2026-11-22T06:00:00Z' }),
    'monkey365-20261122060000-microsoft365.html': '<html>m365</html>',
    'monkey365-20261122060000-azure.html': '<html>azure</html>',
    'monkey365-20261129060000.json': `﻿${JSON.stringify(summary())}`,
    'monkey365-20261130060000.json': '{ not json',
    'monkey365-20261201060000.json': summary({ tool: 'Other' }),
    'monkey365-20261129060000-other.html': 'ignored',
  });
  const out = await createM365Posture({ dir }).list();
  assert.equal(out.skipped, 2);
  assert.deepEqual(out.scans.map(s => s.id), ['20261115060000', '20261122060000', '20261129060000']);
  assert.equal(out.scans[0].rules, undefined, 'older runs carry counts only');
  assert.equal(out.scans[2].rules.length, 4);
  assert.deepEqual(out.scans.map(s => s.reports), [[], ['microsoft365', 'azure'], []]);
});

test('list and report: no folder is not an error; report ids and areas are strict', async () => {
  assert.deepEqual(await createM365Posture({}).list(), { configured: false, folderFound: false, scans: [], skipped: 0 });
  assert.equal((await createM365Posture({ dir: path.join(os.tmpdir(), 'hm360-mp-missing-x') }).list()).folderFound, false);
  const dir = await folder({ 'monkey365-20261129060000-azure.html': '<html>azure</html>' });
  const mp = createM365Posture({ dir });
  assert.equal(String(await mp.report('20261129060000', 'azure')), '<html>azure</html>');
  assert.equal(await mp.report('20261129060000', 'microsoft365'), null);
  for (const [id, area] of [['../x', 'azure'], ['2026112906000', 'azure'], ['20261129060000', '../azure'], ['20261129060000', 'other']]) assert.equal(await mp.report(id, area), null, `${id} ${area}`);
});

test('config: the M365 posture folder is local only and mounted read-only', () => {
  assert.match(loadConfig({}, '/app').m365posture.dir.replace(/\\/g, '/'), /\/app\/data\/m365posture$/);
  assert.equal(loadConfig({ HM360_DATA_REPO: 'owner/data', HM360_GITHUB_TOKEN: 't' }, '/app').m365posture, null);
  const compose = readFileSync(new URL('../compose.yaml', import.meta.url), 'utf8');
  assert.match(compose, /HM360_M365POSTURE_DIR: \/data\/m365posture/);
  assert.match(compose, /- \.\/data\/m365posture:\/data\/m365posture:ro/);
});

test('API: admins only; summaries as JSON and each report as a download', async () => {
  const dir = await folder({ 'monkey365-20261129060000.json': summary(), 'monkey365-20261129060000-microsoft365.html': '<html>m365</html>' });
  const data = await mkdtemp(path.join(os.tmpdir(), 'hm360-mp-data-'));
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: data, HM360_M365POSTURE_DIR: dir, ...env });
    const server = createApp({ config, store: createLocalStore(data), auth: null }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const anon = await open({});
  try {
    assert.equal((await fetch(`${anon.base}/api/admin/m365posture`)).status, 401);
    assert.equal((await fetch(`${anon.base}/api/admin/m365posture/20261129060000/microsoft365.html`)).status, 401);
  } finally { anon.server.close(); }
  const dev = await open({ HM360_DEV_ADMIN: '1' });
  try {
    const j = await (await fetch(`${dev.base}/api/admin/m365posture`)).json();
    assert.equal(j.scans[0].tenantName, 'Contoso');
    const r = await fetch(`${dev.base}/api/admin/m365posture/20261129060000/microsoft365.html`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-disposition'), /attachment; filename="?Monkey365-20261129060000-microsoft365\.html"?/);
    assert.equal((await fetch(`${dev.base}/api/admin/m365posture/20261129060000/azure.html`)).status, 404);
  } finally { dev.server.close(); }
});

test('UI: M365 & Azure posture under Scans below Entra posture, routed, and the setup page covers Monkey365 end to end', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /Entra posture<\/a>\r?\n\s*<a class="nav-item sub" href="#cloudposture" data-route="cloudposture"><span data-nav-icon="cloud-cog"><\/span>M365 &amp; Azure posture<\/a>/);
  assert.match(app, /name === 'cloudposture' \? await viewM365Posture\(\)/);
  const setup = app.slice(app.indexOf('function viewSetup'), app.indexOf('// ---------- Settings'));
  for (const s of ['New-Monkey365App.ps1', 'Invoke-Monkey365Scan.ps1', 'hm360-monkey365:1.0.5', "'HeatMap 360 Monkey365'", 'contoso.example', 'data\\\\m365posture', 'setup-cloudposture', 'Global Reader', 'Sites.FullControl.All'])
    assert.ok(setup.includes(s), s);
});

test('scripts: only read permissions plus Exchange.ManageAsApp, Global Reader and Azure Reader; no SharePoint, no Entra ID scan', () => {
  const ps = readFileSync(new URL('../tools/m365posture/New-Monkey365App.ps1', import.meta.url), 'utf8');
  const block = ps.slice(ps.indexOf('$permissions = @('), ps.indexOf(')', ps.indexOf('$permissions = @(') + 17));
  const perms = [...block.matchAll(/'([A-Za-z.-]+)'/g)].map(m => m[1]).sort();
  assert.equal(perms.length, 26);
  for (const p of perms) assert.match(p, /^[A-Za-z-]+\.Read(Basic)?\.[A-Za-z]+$/, p);
  assert.ok(!/ReadWrite|FullControl/.test(block), 'no write permission');
  assert.match(ps, /\$globalReader = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'/);
  assert.match(ps, /--role Reader /);
  assert.doesNotMatch(ps.slice(ps.indexOf('#>')), /Sites\.(FullControl|Manage|ReadWrite)|f28a1f50-f6e7-4571-818b-6a12f2af6b6c/, 'no SharePoint write permission or SharePoint Administrator role');
  assert.match(ps, /'AzureADMyOrg'/);
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const src = app.slice(app.indexOf('const mkPermissions'), app.indexOf(';', app.indexOf('const mkPermissions')));
  assert.deepEqual([...new Function(`${src}; return mkPermissions;`)()].sort(), perms, 'the setup page lists the same permissions');
  const run = readFileSync(new URL('../tools/m365posture/runner/run.ps1', import.meta.url), 'utf8');
  assert.doesNotMatch(run, /IncludeEntraID/, 'Entra ID is left to Maester');
  assert.match(run, /^\$allowed = 'ExchangeOnline', 'MicrosoftTeams', 'Purview'$/m);
});

test('scripts: the certificate goes to the container on stdin only, never printed or saved, and the summary has no resource names', () => {
  const scan = readFileSync(new URL('../tools/m365posture/Invoke-Monkey365Scan.ps1', import.meta.url), 'utf8');
  assert.match(scan, /\$settings \| & docker start -ai/);
  assert.doesNotMatch(scan, /docker (create|run)[^\n]*(-e |--env|-v |--volume)/, 'no environment variables or mounts into the container');
  assert.doesNotMatch(scan, /Write-(Output|Host|Verbose|Warning)[^\n]*\$(settings|password|pfx)/i);
  assert.doesNotMatch(scan, /Set-Content|Out-File|WriteAll/, 'nothing secret written to disk');
  assert.doesNotMatch(scan, /client_secret/);
  const params = scan.slice(scan.indexOf('param('), scan.indexOf('$ErrorActionPreference'));
  assert.doesNotMatch(params, /\$PSScriptRoot|Join-Path/, 'Windows PowerShell 5.1 leaves $PSScriptRoot empty in param() under -File');
  const run = readFileSync(new URL('../tools/m365posture/runner/run.ps1', import.meta.url), 'utf8');
  for (const s of ["schema        = 'hm360.m365posture/1'", '[Console]::In.ReadLine()', 'EphemeralKeySet', 'ClientAssertionCertificate = $cert']) assert.ok(run.includes(s), s);
  // Found on the first real run (2026-11-27): Monkey365's JSON has keys that differ only in case, and 1.0.5 takes one
  // subscription per run.
  assert.match(run, /ConvertFrom-Json -AsHashtable/);
  assert.match(run, /Subscriptions = \[string\]\$s/);
  assert.doesNotMatch(run, /Subscriptions = \$subs/);
  assert.doesNotMatch(run, /resources\.name|\.resources\b/, 'the summary leaves out resource names, which can name users and mailboxes');
  const docker = readFileSync(new URL('../tools/m365posture/runner/Dockerfile', import.meta.url), 'utf8');
  assert.match(docker, /Install-Module monkey365 -RequiredVersion 1\.0\.5/);
  assert.match(docker, /^USER monkey$/m);
});
