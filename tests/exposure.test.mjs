import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { latestPerMachine, botMatches, matchItem, createExposure, CALLS } from '../server/exposure.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const NOW = Date.parse('2026-11-26T20:00:00Z');
const inv = (machineId, apps, collectedAt = '2026-11-25T10:00:00Z', extra = {}) => ({
  machineId, collectedAt, os: { name: 'Microsoft Windows 11 Pro', displayVersion: '24H2', build: 26100, ubr: 9000 },
  updates: [{ kb: 'KB5000001', installedOn: '2026-11-12' }], hardware: { system: { manufacturer: 'Contoso', model: `Model ${machineId.slice(0, 2)}` } }, apps, ...extra });
const result = (id, inventory, exploited) => ({ schema: 'hm360.result/1', id, receivedAt: inventory.collectedAt, inventory, ...(exploited ? { exploited } : {}) });

// CVE record stub: Fabrikam Viewer fixed in 3.0; CVE-2026-3333 (news only) names Northwind Agent fixed in 5.1.
const RECORDS = {
  'CVE-2026-2222': { containers: { cna: { affected: [{ vendor: 'Fabrikam', product: 'Viewer', defaultStatus: 'unaffected', versions: [{ version: '0', lessThan: '3.0', status: 'affected', versionType: 'custom' }] }] } } },
  'CVE-2026-3333': { containers: { cna: { affected: [{ vendor: 'Northwind', product: 'Agent', defaultStatus: 'unaffected', versions: [{ version: '0', lessThan: '5.1', status: 'affected', versionType: 'custom' }] }] } } },
};
const cveRecord = async id => RECORDS[id] ?? null;
const kevItem = { id: 'kev:CVE-2026-2222', kind: 'exploit', level: 'high', cves: ['CVE-2026-2222'], title: 'Fabrikam Viewer: RCE', why: [], sources: [],
  kev: [{ cveID: 'CVE-2026-2222', vendorProject: 'Fabrikam', product: 'Viewer', dateAdded: '2026-11-24', knownRansomwareCampaignUse: 'Unknown' }] };

test('latestPerMachine keeps the newest processed scan of each computer and skips rejected ones', () => {
  const a1 = result('20261101000000-aaaaaaaa', inv('aaaaaaaaaaaaaaaa', [], '2026-11-01T00:00:00Z'));
  const a2 = result('20261120000000-aaaaaaab', inv('aaaaaaaaaaaaaaaa', [], '2026-11-20T00:00:00Z'));
  const b = result('20261110000000-bbbbbbbb', inv('bbbbbbbbbbbbbbbb', [], '2026-11-10T00:00:00Z'));
  const rej = { id: '20261125000000-cccccccc', rejected: 'bad' };
  assert.deepEqual(latestPerMachine([a1, b, a2, rej]).map(r => r.id), [a2.id, b.id]);
});

test('the bot’s own verdict for the CVE wins over matching again', () => {
  const r = result('20261125000000-aaaaaaaa', inv('aaaaaaaaaaaaaaaa', []), { status: 'checked', affected: [{ cveID: 'CVE-2026-2222', kind: 'app', app: 'Fabrikam Viewer', version: '2.1', why: 'In range', fixedIn: '3.0' }], unverified: [], patched: [] });
  assert.deepEqual(botMatches(r, ['CVE-2026-2222']), [{ cve: 'CVE-2026-2222', verdict: 'affected', product: 'Fabrikam Viewer 2.1', why: 'In range', fixedIn: '3.0', source: 'scan' }]);
  assert.equal(botMatches(r, ['CVE-2026-9999']), null);
});

test('an older scan is checked against a newly listed CVE: vulnerable, patched and clear computers', async () => {
  const scans = [
    result('20261125000000-aaaaaaaa', inv('aaaaaaaaaaaaaaaa', [{ name: 'Fabrikam Viewer', version: '2.4', publisher: 'Fabrikam' }])),
    result('20261125000000-bbbbbbbb', inv('bbbbbbbbbbbbbbbb', [{ name: 'Fabrikam Viewer', version: '3.2', publisher: 'Fabrikam' }])),
    result('20261125000000-cccccccc', inv('cccccccccccccccc', [{ name: '7-Zip', version: '24.08', publisher: 'Igor Pavlov' }], '2026-09-01T00:00:00Z')),
  ];
  const m = await matchItem(kevItem, scans, { kevById: new Map(), cveRecord, now: NOW });
  assert.equal(m.call, 'affected');
  assert.deepEqual(m.counts, { affected: 1, verify: 0, patched: 1, clear: 1, unknown: 0 });
  const [a, b, c] = m.machines;
  assert.equal(a.verdict, 'affected'); assert.equal(a.matches[0].source, 'recheck'); assert.equal(a.matches[0].fixedIn, '3.0');
  assert.equal(b.verdict, 'patched');
  assert.equal(c.verdict, 'clear'); assert.equal(c.stale, true, 'scan older than 30 days is marked old');
  assert.equal(a.computer, 'Contoso Model aa');
  assert.ok(!JSON.stringify(m).match(/userName|computerName/), 'no names');
});

test('critical + vulnerable = act now; a headline CVE not in the catalog uses its CVE record; no CVE cannot be checked', async () => {
  const scans = [result('20261125000000-aaaaaaaa', inv('aaaaaaaaaaaaaaaa', [{ name: 'Fabrikam Viewer', version: '1.0' }, { name: 'Northwind Agent', version: '5.0' }]))];
  assert.equal((await matchItem({ ...kevItem, level: 'critical' }, scans, { kevById: new Map(), cveRecord, now: NOW })).call, 'act-now');
  const news = { id: 'news:CVE-2026-3333', kind: 'exploit', level: 'high', cves: ['CVE-2026-3333'], kev: [], started: '2026-11-25T00:00:00Z' };
  const n = await matchItem(news, scans, { kevById: new Map(), cveRecord, now: NOW });
  assert.equal(n.call, 'affected');
  assert.equal(n.machines[0].matches[0].product, 'Northwind Agent 5.0');
  const none = await matchItem({ id: 'news:x', kind: 'exploit', level: 'high', cves: [] }, scans, { kevById: new Map(), cveRecord, now: NOW });
  assert.equal(none.call, 'cannot-check');
  const missing = await matchItem({ ...news, cves: ['CVE-2026-4444'] }, scans, { kevById: new Map(), cveRecord, now: NOW });
  assert.equal(missing.call, 'cannot-check'); assert.match(missing.note, /names no product/);
  assert.equal((await matchItem(kevItem, [], { kevById: new Map(), cveRecord, now: NOW })).call, 'no-scans');
  assert.ok(Object.keys(CALLS).includes('act-now'));
});

test('createExposure: only exploits are matched, worst first, cached', async () => {
  let reads = 0;
  const attention = async () => { reads++; return { checkedAt: 'x', sources: { kev: { status: 'checked' } }, items: [
    { id: 'news:none', kind: 'exploit', level: 'high', cves: [], title: 'Zero-day somewhere' },
    kevItem,
    { id: 'svc:a', kind: 'disruption', level: 'critical', title: 'Outage' },
  ] }; };
  const scans = [result('20261125000000-aaaaaaaa', inv('aaaaaaaaaaaaaaaa', [{ name: 'Fabrikam Viewer', version: '2.0' }]))];
  const get = createExposure({ attention, loadScans: async () => scans, cveRecord, now: () => NOW });
  const d = await get();
  assert.deepEqual(d.items.map(i => i.call), ['affected', 'cannot-check']);
  assert.equal(d.disruptionsSkipped, 1);
  assert.equal(d.machines.length, 1);
  await get(); assert.equal(reads, 1, 'cached');
  await get({ fresh: true }); assert.equal(reads, 2, 'Check again reads afresh');
});

test('GET /api/admin/exposure: admins only, reads the stored scans', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-exp-'));
  await mkdir(path.join(dir, 'results'), { recursive: true });
  const r = result('20261125000000-aaaaaaaa', inv('aaaaaaaaaaaaaaaa', [{ name: 'Fabrikam Viewer', version: '2.0' }]));
  await writeFile(path.join(dir, 'results', `${r.id}.json`), JSON.stringify(r));
  const attention = async () => ({ checkedAt: 'x', sources: {}, items: [kevItem] });
  const base = { config: { ...loadConfig({ HM360_DATA_DIR: dir, HM360_DEV_ADMIN: '1' }, dir) }, store: createLocalStore(dir), clientScript: '', attention };
  const { createExposure: mk } = await import('../server/exposure.mjs');
  const app = createApp({ ...base, exposure: mk({ attention, loadScans: async () => [r], cveRecord }) });
  const srv = app.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${srv.address().port}/api/admin/exposure`);
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.equal(body.items[0].call, 'affected');
  } finally { srv.close(); }
  const closed = createApp({ config: loadConfig({ HM360_DATA_DIR: dir }, dir), store: createLocalStore(dir), clientScript: '', attention });
  const srv2 = closed.listen(0);
  try { assert.notEqual((await fetch(`http://127.0.0.1:${srv2.address().port}/api/admin/exposure`)).status, 200); } finally { srv2.close(); }
});
