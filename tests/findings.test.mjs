import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseReleaseInfo } from '../bot/windows.mjs';
import { analyze } from '../bot/analyze.mjs';
import { memoryStore, tableStore, createAzureStore, inventoryRows, rowKey, importResult, importFolder, dueGroups, runLookups, headline, CATEGORY } from '../bot/findings.mjs';

const fx = n => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const cve = id => JSON.parse(fx(`cve/${id}.json`));
const inv = JSON.parse(fx('inventory.sample.json'));
const info = parseReleaseInfo(fx('release-info.html'));
const NOW = Date.parse('2026-11-12T20:00:00Z');
const kev = { catalogVersion: 'x', vulnerabilities: [
  { cveID: 'CVE-2024-4671', vendorProject: 'Google', product: 'Chromium Visuals', vulnerabilityName: 'Chrome UAF', dateAdded: '2024-05-13', knownRansomwareCampaignUse: 'Unknown' },
  { cveID: 'CVE-2023-21608', vendorProject: 'Adobe', product: 'Acrobat and Reader', vulnerabilityName: 'Acrobat UAF', dateAdded: '2023-10-10', knownRansomwareCampaignUse: 'Unknown' } ] };
const sources = (over = {}) => ({
  releaseInfo: async () => info,
  knownIssuesPage: async () => fx('known-issues.html'),
  wingetLatest: async id => ({ 'Google.Chrome': '131.0.6778.86', '7zip.7zip': '24.08' })[id] ?? null,
  releaseNotes: async () => null,
  kev: async () => ({ kev, epss: {} }),
  cveRecord: async id => cve(id),
  vendorFile: async () => null,
  ...over,
});
const offline = sources({ wingetLatest: async () => { throw new Error('offline'); }, kev: async () => { throw new Error('offline'); }, releaseInfo: async () => { throw new Error('offline'); } });
const scanInv = { ...inv, apps: [{ name: 'Google Chrome', version: '120.0.6099.71', publisher: 'Google LLC' }, { name: 'Adobe Acrobat (64-bit)', version: '24.1', publisher: 'Adobe' }] };
const result = async (id, inventory = scanInv, src = sources()) =>
  analyze({ id, receivedAt: '2026-11-12T18:01:00Z', tokenHash: 'h'.repeat(64), inventory }, src, NOW);
const rowsOf = (store, where = () => true) => [...store.rows.values()].filter(where);
const one = (store, kind, name) => rowsOf(store, e => e.Kind === kind && e.Name === name)[0];

test('inventory rows: one row per item, every area of the scan, each with a category', () => {
  const rows = inventoryRows(inv);
  const count = k => rows.filter(r => r.kind === k).length;
  assert.equal(count('os'), 1);
  assert.equal(count('windows-update'), inv.updates.length);
  assert.equal(count('app'), inv.apps.length);
  assert.equal(count('winget-package'), inv.winget.length);
  assert.equal(count('bios'), 1);
  assert.equal(count('driver'), inv.hardware.devices.length);
  assert.equal(count('disk'), inv.hardware.disks.length);
  assert.equal(count('network-setting'), inv.network.adapters.reduce((n, a) => n + (a.settings?.length || 0), 0));
  assert.equal(count('event'), inv.eventLog.entries.length);
  assert.equal(count('security'), 5);
  assert.ok(rows.every(r => CATEGORY[r.kind]), 'every kind maps to a category');
  const disk = rows.find(r => r.kind === 'disk');
  assert.equal(disk.version, '3B2QGXA7', 'disk firmware is the version');
  assert.equal(rows.find(r => r.kind === 'driver').lookup_status, 'not-checked');
  assert.equal(rows.find(r => r.kind === 'windows-update').lookup_status, 'n/a');
});

test('row keys: safe for Table Storage, stable, distinct', () => {
  const k = rowKey('app', 'a/b\\c#d?e|pub');
  assert.doesNotMatch(k, /[/\\#?]/);
  assert.equal(k, rowKey('app', 'a/b\\c#d?e|pub'));
  assert.notEqual(rowKey('app', 'a/b'), rowKey('app', 'a_b'));
  assert.ok(rowKey('app', 'x'.repeat(2000)).length < 200);
});

test('import: one row per item per machine, prefilled with the bot\'s answers, plus a machine row', async () => {
  const store = memoryStore();
  const n = await importResult(store, await result('20261112180000-abcdef01'));
  assert.ok(n > 30);
  assert.ok(rowsOf(store).every(e => e.partitionKey === inv.machineId));
  const chrome = one(store, 'winget-package', 'Google.Chrome');
  assert.equal(chrome.Category, 'Application');
  assert.equal(chrome.Status, 'Outdated');
  assert.equal(chrome.LatestVersion, '131.0.6778.86');
  assert.equal(chrome.InstalledVersion, '130.0.1');
  const win = one(store, 'os', inv.os.name);
  assert.equal(win.Category, 'Windows');
  assert.equal(win.Status, 'Unsupported', 'Home/Pro 24H2 past end of updates in the fixture');
  assert.ok(win.KnownIssueCount >= 1);
  const app = one(store, 'app', 'Google Chrome');
  assert.equal(app.Status, 'Exploited');
  assert.equal(JSON.parse(app.ExploitedCVEs)[0].cve, 'CVE-2024-4671');
  assert.equal(one(store, 'app', 'Adobe Acrobat (64-bit)').ExploitedCount, 0, 'patched version is not a problem');
  assert.equal(one(store, 'driver', inv.hardware.devices[0].name).Status, 'Not checked');
  const m = store.rows.get(`${inv.machineId}\u0000machine`);
  assert.equal(m.Category, 'Machine');
  assert.equal(m.ScanId, '20261112180000-abcdef01');
  assert.ok(rowsOf(store).every(e => !('LatestVersion' in e) || e.LatestVersion !== null), 'empty values are not stored');
  assert.equal(await importResult(store, await result('20261112180000-abcdef01')), 0, 'same scan is not imported twice');
  assert.equal(await importResult(store, { ...(await result('20261112180000-abcdef02')), rejected: 'bad' }), 0);
});

test('import: a newer scan updates rows in place, keeps FirstSeen, flags removed items; older scans are ignored', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-f-'));
  await mkdir(path.join(dir, 'results'));
  await writeFile(path.join(dir, 'results', '20261112180000-abcdef01.json'), JSON.stringify(await result('20261112180000-abcdef01')));
  const later = { ...scanInv, collectedAt: '2026-11-13T18:00:00Z', winget: [{ id: 'Google.Chrome', version: '131.0.6778.86', source: 'winget' }] };
  await writeFile(path.join(dir, 'results', '20261113180000-abcdef02.json'), JSON.stringify(await result('20261113180000-abcdef02', later)));
  await writeFile(path.join(dir, 'results', '20261113180000-abcdef03.json'), '{ not json');
  await writeFile(path.join(dir, 'results', 'evil.json'), '{}');
  const store = memoryStore(), logs = [];
  const r = await importFolder(store, dir, { log: m => logs.push(m) });
  assert.equal(r.scans, 2);
  assert.match(logs[0], /abcdef03.*skipped/);
  const chrome = one(store, 'winget-package', 'Google.Chrome');
  assert.equal(rowsOf(store, e => e.Kind === 'winget-package' && e.Name === 'Google.Chrome').length, 1, 'updated in place, not a second row');
  assert.equal(chrome.InstalledVersion, '131.0.6778.86');
  assert.equal(chrome.Status, 'Current');
  assert.equal(chrome.FirstSeen, inv.collectedAt);
  assert.equal(chrome.LastSeen, '2026-11-13T18:00:00Z');
  assert.equal(one(store, 'winget-package', '7zip.7zip').Removed, true, 'no longer in the newest scan');
  assert.equal(await importResult(store, await result('20261112170000-abcdef04', { ...scanInv, collectedAt: '2026-11-12T17:00:00Z' })), 0, 'older scan ignored');
});

test('background job: one lookup per item across machines, answer on every row, failures isolated, recheck when due', async () => {
  const store = memoryStore();
  await importResult(store, await result('20261112180000-abcdef01', scanInv, offline));
  await importResult(store, await result('20261112180000-abcdef02', { ...scanInv, machineId: 'fedcba9876543210' }, offline));
  assert.ok(rowsOf(store, e => e.Status === 'Pending').length > 0);

  const calls = [];
  const src = sources({ wingetLatest: async id => { calls.push(id); if (id === '7zip.7zip') throw new Error('HTTP 502'); return id === 'Google.Chrome' ? '131.0.6778.86' : null; } });
  const r = await runLookups(store, src, { now: () => NOW });
  assert.equal(r.failed, 1);
  assert.equal(calls.filter(c => c === 'Google.Chrome').length, 1, 'one lookup for both machines');
  const chrome = rowsOf(store, e => e.Kind === 'winget-package' && e.Name === 'Google.Chrome');
  assert.equal(chrome.length, 2);
  assert.ok(chrome.every(e => e.Status === 'Outdated' && e.LatestVersion === '131.0.6778.86' && e.LastChecked));
  const zip = one(store, 'winget-package', '7zip.7zip');
  assert.equal(zip.Status, 'Lookup failed');
  assert.match(zip.Note, /HTTP 502/);
  const store9 = rowsOf(store, e => e.Kind === 'winget-package' && /msstore/.test(e.Detail || ''))[0];
  if (store9) { assert.equal(store9.Status, 'Not checked'); assert.ok(!calls.includes(store9.Name), 'store apps are not looked up in winget'); }
  assert.equal(one(store, 'app', 'Google Chrome').Status, 'Exploited');
  assert.equal(one(store, 'os', inv.os.name).Status, 'Unsupported');
  assert.equal(one(store, 'bios', 'Contoso Laptop 14').Status, 'Not checked', 'unknown maker: graceful');
  assert.equal(rowsOf(store, e => e.Status === 'Pending').length, 0);

  const all = [...store.rows.values()];
  assert.deepEqual(dueGroups(all, { now: NOW + 3_600_000 }).map(g => g.rows[0].Name), ['7zip.7zip'], 'only the failed lookup retries next hour');
  assert.ok(dueGroups(all, { now: NOW + 25 * 3_600_000 }).length > 1, 'everything again after 24 hours');
  assert.equal(dueGroups(all, { now: NOW + 25 * 3_600_000, limit: 2 }).length, 2);
});

test('background job: unverified KEV name matches are not stored as problems', async () => {
  const store = memoryStore();
  await importResult(store, await result('20261112180000-abcdef01', { ...scanInv, apps: [{ name: 'Chromium Visuals Helper', version: '1.0', publisher: 'Google LLC' }] }));
  await runLookups(store, sources({ cveRecord: async () => null }), { now: () => NOW + 25 * 3_600_000 });
  const app = rowsOf(store, e => e.Kind === 'app')[0];
  assert.equal(app.ExploitedCount, 0);
  assert.notEqual(app.Status, 'Exploited');
});

test('headline status: worst first', () => {
  assert.equal(headline({ lookup: 'outdated', exploitedCount: 1, issueCount: 2 }), 'Exploited');
  assert.equal(headline({ lookup: 'unsupported', issueCount: 2 }), 'Unsupported');
  assert.equal(headline({ lookup: 'current', issueCount: 1 }), 'Known problems');
  assert.equal(headline({ lookup: 'n/a' }), 'Info');
});

test('Azure table store: replace-upserts in transactions of at most 100 per partition, no system fields', async () => {
  const sent = [];
  const client = {
    async *listEntities() { yield { partitionKey: 'p', rowKey: 'r', etag: 'W/x', timestamp: 't', Name: 'n' }; },
    async submitTransaction(actions) { sent.push(actions); },
  };
  const t = tableStore(client);
  const [e] = await t.partition('p');
  await t.upsert([...Array.from({ length: 150 }, (_, i) => ({ ...e, rowKey: `r${i}`, Empty: null })), { partitionKey: 'q', rowKey: 'z' }]);
  assert.deepEqual(sent.map(a => a.length), [100, 50, 1]);
  assert.ok(sent.flat().every(([op, , mode]) => op === 'upsert' && mode === 'Replace'));
  assert.ok(sent.flat().every(([, ent]) => !('etag' in ent) && !('timestamp' in ent) && !('Empty' in ent)));
  await assert.rejects(createAzureStore({ account: 'Bad.Name' }), /storage account name/);
  await assert.rejects(createAzureStore({ account: 'stheatmap360', table: 'x/y' }), /Invalid table/);
});

test('table location: command line, then the Settings page file, then the environment', async () => {
  const { resolveLocation } = await import('../bot/findings.mjs');
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-loc-'));
  const env = { HM360_TABLES_ACCOUNT: 'stenv' };
  assert.equal((await resolveLocation({ repos: [dir], env })).account, 'stenv');
  await mkdir(path.join(dir, 'settings'));
  await writeFile(path.join(dir, 'settings', 'findings.json'), JSON.stringify({ schema: 'hm360.settings/1', findings: { account: 'stmoved', table: 'findings2' } }));
  const s = await resolveLocation({ repos: [dir], env });
  assert.deepEqual([s.account, s.table], ['stmoved', 'findings2']);
  assert.match(s.from, /Settings page/);
  assert.equal((await resolveLocation({ account: 'stcli', repos: [dir], env })).account, 'stcli');
  await writeFile(path.join(dir, 'settings', 'findings.json'), JSON.stringify({ schema: 'hm360.settings/1', findings: { account: 'Bad/Name' } }));
  assert.equal((await resolveLocation({ repos: [dir], env })).account, 'stenv', 'a bad file is ignored');
});

test('credential: az login by default, never a machine identity unless asked', async () => {
  const { makeCredential } = await import('../bot/findings.mjs');
  const id = await import('@azure/identity');
  assert.ok((await makeCredential()) instanceof id.ChainedTokenCredential);
  assert.ok((await makeCredential('managed-identity')) instanceof id.ManagedIdentityCredential);
  await assert.rejects(makeCredential('arc'), /--credential must be one of/);
});
