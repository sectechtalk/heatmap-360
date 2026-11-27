import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { CVE_FEEDS, parseCveFeed, createCves } from '../server/cves.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const ABOUT = 'https://radar.cloudflare.com/zero-wire/cves/feed/schema.json';
const entry = (id, date, cve = {}, extra = {}) => ({
  id: `https://radar.cloudflare.com/zero-wire/cves/${id}`, url: `https://radar.cloudflare.com/zero-wire/cves/${id}`,
  title: `${id}: Example product flaw`, summary: 'An example flaw.', date_published: date, tags: ['display text only'],
  _cve: { about: ABOUT, id, ...cve }, ...extra,
});
const feed = items => ({ version: 'https://jsonfeed.org/version/1.1', title: 'CVEs', items });

test('feeds: unfiltered plus one per severity, all on radar.cloudflare.com over https, JSON format', () => {
  assert.deepEqual(CVE_FEEDS.map(f => f.id), ['all', 'critical', 'high', 'medium', 'low']);
  for (const f of CVE_FEEDS) {
    const u = new URL(f.url);
    assert.equal(u.protocol, 'https:'); assert.equal(u.hostname, 'radar.cloudflare.com'); assert.equal(u.pathname, '/zero-wire/cves/feed');
    assert.equal(u.searchParams.get('format'), 'json');
  }
});

test('parseCveFeed: reads only _cve for severity, score and KEV; drops bad IDs and off-site links', () => {
  const items = parseCveFeed(feed([
    entry('CVE-2026-125294', '2026-11-21T19:16:31.403Z', { severity: 'CRITICAL', score: 9.8, cvss_version: '3.1', kev_added: '2026-11-21' }),
    entry('CVE-2026-94259', '2026-11-22T06:00:09Z', {}, { title: 'CVE-2026-94259', url: 'https://evil.example/x' }),
    entry('CVE-2026-1', '2026-11-22T06:00:09Z'),
    entry('CVE-2026-55555', '2026-11-22T06:00:09Z', { severity: 'SPICY', score: 42, kev_added: 'soon' }),
  ]));
  assert.equal(items.length, 3, 'CVE-2026-1 is not a valid ID');
  assert.deepEqual(items[0], { id: 'CVE-2026-125294', title: 'Example product flaw', summary: 'An example flaw.', date: '2026-11-21T19:16:31.403Z', severity: 'critical', score: 9.8, cvss: '3.1', kevAdded: '2026-11-21', link: 'https://radar.cloudflare.com/zero-wire/cves/CVE-2026-125294' });
  assert.equal(items[1].severity, 'unscored');
  assert.equal(items[1].title, null);
  assert.equal(items[1].link, 'https://radar.cloudflare.com/zero-wire/cves/CVE-2026-94259', 'off-site link replaced by the Cloudflare page');
  assert.equal(items[2].severity, 'unscored'); assert.equal(items[2].score, null); assert.equal(items[2].kevAdded, null);
  assert.throws(() => parseCveFeed({ nope: 1 }), /not a CVE JSON feed/);
});

test('createCves: merges feeds without duplicates, newest first; a failing feed is reported; cached 30 minutes', async () => {
  let calls = 0, t = 0;
  const bodies = {
    all: feed([entry('CVE-2026-1000', '2026-11-22T06:00:00Z'), entry('CVE-2026-2000', '2026-11-22T05:00:00Z', { severity: 'CRITICAL', score: 9.1 })]),
    critical: feed([entry('CVE-2026-2000', '2026-11-22T05:00:00Z', { severity: 'CRITICAL', score: 9.1 }), entry('CVE-2026-3000', '2026-11-19T05:00:00Z', { severity: 'CRITICAL', score: 10 })]),
    high: feed([entry('CVE-2026-4000', '2026-11-20T05:00:00Z', { severity: 'HIGH', score: 7.5 })]),
  };
  const fetchImpl = async url => {
    calls++;
    const sev = new URL(url).searchParams.get('severity') || 'all';
    if (sev === 'low') return { ok: false, status: 503, headers: new Headers(), text: async () => '' };
    if (sev === 'medium') return { ok: true, status: 200, headers: new Headers({ 'content-length': '9000000' }), text: async () => '' };
    return { ok: true, status: 200, headers: new Headers(), text: async () => JSON.stringify(bodies[sev]) };
  };
  const get = createCves({ fetchImpl, now: () => t });
  const r = await get();
  assert.deepEqual(r.items.map(i => i.id), ['CVE-2026-1000', 'CVE-2026-2000', 'CVE-2026-4000', 'CVE-2026-3000']);
  assert.equal(r.page, 'https://radar.cloudflare.com/zero-wire/cves');
  const f = Object.fromEntries(r.feeds.map(x => [x.id, x]));
  assert.equal(f.critical.count, 2); assert.equal(f.critical.oldest, '2026-11-19T05:00:00.000Z');
  assert.match(f.low.error, /HTTP 503/); assert.match(f.medium.error, /too large/);
  await get(); assert.equal(calls, 5, 'cached');
  t = 1_800_001; await get(); assert.equal(calls, 10, 'refreshed after 30 minutes');
});

test('server: Cloudflare Radar CVEs page is admin only', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-cves-'));
  const cves = async () => ({ title: 'Cloudflare Radar CVEs', checkedAt: '2026-11-22T00:00:00Z', feeds: [], items: [] });
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: dir, HM360_PUBLIC_URL: 'https://heatmap.contoso.example', ...env });
    const server = createApp({ config, store: createLocalStore(dir), auth: null, cves, news: () => null, serviceHealth: async () => ({ providers: [] }) }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const a = await open({});
  try { assert.equal((await fetch(`${a.base}/api/admin/cves`)).status, 401); } finally { a.server.close(); }
  const b = await open({ HM360_DEV_ADMIN: '1' });
  try { assert.equal((await (await fetch(`${b.base}/api/admin/cves`)).json()).title, 'Cloudflare Radar CVEs'); } finally { b.server.close(); }
});

test('UI: Cloudflare Radar CVEs sits under Internet - Exploits in Results and is routed', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /Internet - Exploits<\/a>\r?\n\s*<a class="nav-item sub" href="#cves" data-route="cves"><span data-nav-icon="shield-alert"><\/span>Cloudflare Radar CVEs<\/a>/);
  assert.match(app, /name === 'cves' \? await viewCves\(\)/);
  assert.match(app, /api\('\/api\/admin\/cves'\)/);
});
