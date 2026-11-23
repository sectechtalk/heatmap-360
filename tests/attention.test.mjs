import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { RULES, describeRules, kevItems, headlineHits, mergeExploits, disruptionItems, rank, createAttention } from '../server/attention.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const NOW = Date.parse('2026-11-16T20:00:00Z');
const H = 3_600_000;
const at = hoursAgo => new Date(NOW - hoursAgo * H).toISOString();
const KEV = { vulnerabilities: [
  { cveID: 'CVE-2026-1111', vendorProject: 'Contoso', product: 'Gateway', vulnerabilityName: 'Contoso Gateway Auth Bypass', dateAdded: '2026-11-14', dueDate: '2026-12-05', knownRansomwareCampaignUse: 'Known', shortDescription: 'Lets an attacker in.' },
  { cveID: 'CVE-2026-2222', vendorProject: 'Fabrikam', product: 'Viewer', vulnerabilityName: 'Fabrikam Viewer RCE', dateAdded: '2026-11-15', knownRansomwareCampaignUse: 'Unknown' },
  { cveID: 'CVE-2025-0001', vendorProject: 'Old', product: 'Thing', vulnerabilityName: 'Old one', dateAdded: '2026-10-01' },
] };
const page = sources => ({ sources });
const src = (id, name, items) => ({ id, name, page: `https://${id}.contoso.example/`, status: 'checked', items });

test('KEV: only entries added in the last 7 days; ransomware use is noted', () => {
  const r = kevItems(KEV, NOW);
  assert.deepEqual(r.map(i => i.cves[0]), ['CVE-2026-1111', 'CVE-2026-2222']);
  assert.ok(r[0].ransomware && r[0].why.some(w => /ransomware/.test(w)));
  assert.match(r[0].sources[0].link, /^https:\/\/www\.cisa\.gov\/known-exploited-vulnerabilities-catalog\?/);
  assert.equal(r[0].sources[1].link, 'https://www.cve.org/CVERecord?id=CVE-2026-1111');
  assert.throws(() => kevItems({}, NOW), /no vulnerabilities array/);
});

test('headlines: only zero-day / exploited / emergency titles from the last 7 days, deduplicated across pages', () => {
  const a = src('bc', 'BleepingComputer', [
    { title: 'Microsoft fixes exploited zero-day in Windows (CVE-2026-2222)', link: 'https://bc.contoso.example/1', date: at(5) },
    { title: 'Chrome 140 released with new features', link: 'https://bc.contoso.example/2', date: at(2) },
    { title: 'Old zero-day story', link: 'https://bc.contoso.example/3', date: at(24 * 9) },
  ]);
  const b = src('shn', 'The Hacker News', [{ title: 'Hackers actively exploited Fabrikam bug', link: 'https://shn.contoso.example/x', date: at(3), summary: 'Tracked as CVE-2026-2222.' }]);
  const hits = headlineHits([page([a]), page([a, b])], NOW);
  assert.deepEqual(hits.map(x => x.link), ['https://bc.contoso.example/1', 'https://shn.contoso.example/x']);
  assert.deepEqual(hits[1].cves, ['CVE-2026-2222'], 'CVE found in the summary too');
  for (const t of ['Emergency patch for Contoso VPN', 'Out-of-band update fixes Exchange', 'Zero-days under attack', 'Bug exploited in the wild']) assert.match(t, RULES.headline);
  for (const t of ['Patch Tuesday preview', 'Windows 11 gets new Start menu', 'Update fixes 10 days of delays']) assert.doesNotMatch(t, RULES.headline);
});

test('merge: headlines join the KEV item with the same CVE; 3 feeds or ransomware make it critical', () => {
  const hits = [
    { source: 'A', title: 'Zero-day CVE-2026-2222', link: 'https://a.contoso.example/1', date: at(4), cves: ['CVE-2026-2222'] },
    { source: 'B', title: 'Exploited: CVE-2026-2222', link: 'https://b.contoso.example/1', date: at(3), cves: ['CVE-2026-2222'] },
    { source: 'C', title: 'Under attack CVE-2026-2222', link: 'https://c.contoso.example/1', date: at(2), cves: ['CVE-2026-2222'] },
    { source: 'D', title: 'Zero-day in Northwind router', link: 'https://d.contoso.example/1', date: at(1), cves: [] },
  ];
  const items = mergeExploits(kevItems(KEV, NOW), hits);
  const fab = items.find(i => i.id === 'kev:CVE-2026-2222');
  assert.equal(fab.level, 'critical');
  assert.equal(fab.sources.length, 5);
  assert.ok(fab.why.some(w => /Also in the news: 3 feeds/.test(w)));
  assert.equal(fab.seen, at(2));
  assert.equal(items.find(i => i.id === 'kev:CVE-2026-1111').level, 'critical', 'ransomware');
  const lone = items.find(i => i.id.startsWith('news:'));
  assert.equal(lone.level, 'high');
  assert.equal(lone.title, 'Zero-day in Northwind router');
  assert.equal(items.length, 3);
});

test('disruptions: outages always, degradations after 2 hours (critical after 8); notices left out', () => {
  const svc = { providers: [
    { id: 'gcp', name: 'Google Cloud', page: 'https://status.cloud.google.com/', incidents: [
      { title: 'BigQuery down', impact: 'bad', started: at(0.5) },
      { title: 'Slow console', impact: 'warn', started: at(1) },
      { title: 'Slow logs', impact: 'warn', started: at(3) },
      { title: 'Notice', impact: 'info', started: at(30) },
    ] },
    { id: 'm365', name: 'Microsoft 365', page: 'https://admin.microsoft.com/', incidents: [{ title: 'Exchange Online: mail delays', impact: 'warn', started: at(12), link: 'https://admin.microsoft.com/x' }] },
  ] };
  const r = disruptionItems(svc, NOW);
  assert.deepEqual(r.map(i => [i.title, i.level]), [['Google Cloud: BigQuery down', 'critical'], ['Google Cloud: Slow logs', 'high'], ['Microsoft 365: Exchange Online: mail delays', 'critical']]);
  assert.match(r[2].why[0], /degraded for 12 hours/);
  assert.ok(r.every(i => i.active));
});

test('rank: critical first, then newest; capped', () => {
  const r = rank([{ level: 'high', seen: at(1) }, { level: 'critical', seen: at(10) }, { level: 'high', seen: at(0) }], { ...RULES, maxItems: 2 });
  assert.deepEqual(r.map(i => [i.level, i.seen]), [['critical', at(10)], ['high', at(0)]]);
  assert.equal(describeRules().length, 4);
});

test('createAttention: KEV failure and a not-connected Microsoft 365 degrade gracefully; KEV cached', async () => {
  let calls = 0, fail = true, t = NOW;
  const fetchImpl = async () => { calls++; if (fail) return { ok: false, status: 503, headers: new Headers() }; return { ok: true, status: 200, headers: new Headers(), text: async () => JSON.stringify(KEV) }; };
  const news = kind => (kind === 'exploits' ? page([src('bc', 'BleepingComputer', [{ title: 'Zero-day in Northwind', link: 'https://bc.contoso.example/z', date: at(1) }])]) : null);
  const serviceHealth = async () => ({ providers: [{ id: 'm365', name: 'Microsoft 365', grade: 'unknown', summary: 'Not connected', note: 'Needs Azure.', incidents: [] }] });
  const get = createAttention({ news, serviceHealth, fetchImpl, now: () => t });
  let r = await get();
  assert.equal(r.sources.kev.status, 'unknown');
  assert.match(r.sources.kev.error, /HTTP 503/);
  assert.deepEqual(r.items.map(i => i.title), ['Zero-day in Northwind'], 'headlines still work without KEV');
  assert.deepEqual(r.sources.services, [{ name: 'Microsoft 365', status: 'not-connected', note: 'Needs Azure.' }]);
  fail = false;
  await get(); assert.equal(calls, 1, 'failure cached for a short time');
  t += 300_001; r = await get(); assert.equal(calls, 2, 'retried after 5 minutes');
  assert.equal(r.sources.kev.status, 'checked');
  assert.equal(r.items.length, 3);
  await get(); assert.equal(calls, 2, 'cached for an hour');
});

test('server: High impact is admin only', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-attn-'));
  const attention = async () => ({ checkedAt: at(0), rules: [], items: [], sources: {} });
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: dir, HM360_PUBLIC_URL: 'https://heatmap.contoso.example', ...env });
    const server = createApp({ config, store: createLocalStore(dir), auth: null, attention, news: () => null, serviceHealth: async () => ({ providers: [] }) }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const a = await open({});
  try { assert.equal((await fetch(`${a.base}/api/admin/attention`)).status, 401); } finally { a.server.close(); }
  const b = await open({ HM360_DEV_ADMIN: '1' });
  try { assert.deepEqual((await (await fetch(`${b.base}/api/admin/attention`)).json()).items, []); } finally { b.server.close(); }
});
