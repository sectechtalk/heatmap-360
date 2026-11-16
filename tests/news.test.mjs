import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { NEWS, parseFeed, createNews } from '../server/news.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const HOSTS = ['news.contoso.example'];

test('RSS: titles, dates, summaries; newest first; links stay on the source site', () => {
  const xml = `<?xml version="1.0"?><rss version="2.0"><channel><title>Contoso</title>
    <item><title>Older &amp; fixed</title><link>https://news.contoso.example/a</link><pubDate>Wed, 11 Nov 2026 10:00:00 GMT</pubDate><description><![CDATA[<p>Patch <b>now</b>.</p>]]></description></item>
    <item><title>Newer</title><link>https://evil.example/b</link><pubDate>Thu, 12 Nov 2026 10:00:00 GMT</pubDate></item>
    <item><title>Plain http</title><link>http://news.contoso.example/c</link></item>
    <item><description>no title, skipped</description></item></channel></rss>`;
  const r = parseFeed(xml, HOSTS);
  assert.deepEqual(r.map(i => i.title), ['Newer', 'Older & fixed', 'Plain http']);
  assert.equal(r[0].link, null, 'outside link dropped');
  assert.equal(r[1].link, 'https://news.contoso.example/a');
  assert.equal(r[1].summary, 'Patch now.');
  assert.equal(r[2].link, null, 'only https links');
});

test('Atom: alternate link, published or updated date', () => {
  const xml = `<feed xmlns="http://www.w3.org/2005/Atom"><title>Contoso</title><link rel="self" href="https://news.contoso.example/feed.atom"/>
    <entry><title type="html">Cloud &lt;b&gt;outage&lt;/b&gt;</title><link rel="alternate" type="text/html" href="https://news.contoso.example/x"/><updated>2026-11-12T09:00:00Z</updated><summary>Region down</summary></entry>
    <entry><title>Second</title><link href='https://www.news.contoso.example/y'/><published>2026-11-12T10:00:00Z</published></entry></feed>`;
  const r = parseFeed(xml, HOSTS);
  assert.deepEqual(r.map(i => [i.title, i.link]), [['Second', 'https://www.news.contoso.example/y'], ['Cloud outage', 'https://news.contoso.example/x']]);
  assert.equal(r[1].summary, 'Region down');
  assert.throws(() => parseFeed('<html><body>Not a feed</body></html>', HOSTS), /not an RSS or Atom feed/);
});

test('sources: every listed feed and page is https and its own site is allowed for links', () => {
  for (const list of Object.values(NEWS)) {
    assert.ok(list.sources.length >= 5);
    for (const s of list.sources) {
      assert.match(s.feed, /^https:\/\//);
      assert.match(s.page, /^https:\/\//);
      assert.ok(s.hosts.some(h => new URL(s.page).hostname === h || new URL(s.page).hostname.endsWith(`.${h}`)), `${s.id} page host is allowed`);
    }
  }
});

test('patches page: lists the chosen patch news sources, each with a unique id', () => {
  const ids = NEWS.patches.sources.map(s => s.id);
  assert.equal(NEWS.patches.title, 'Internet - Patches');
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(!ids.includes('mozilla-advisories'), 'Mozilla removed its advisories feed (bug 504882), so it is not listed');
  for (const id of ['borncity', 'windows-itpro', 'zdi', 'windowslatest', 'neowin', 'register-patches', 'patchmypc', 'ghacks', 'chrome-releases', 'tenable']) assert.ok(ids.includes(id), id);
});

test('createNews: one failing source does not break the others; cached for 30 minutes', async () => {
  let calls = 0, t = 0;
  const lists = { cloud: { title: 'T', intro: 'I', sources: [
    { id: 'good', name: 'Good', about: '', page: 'https://news.contoso.example/', feed: 'https://news.contoso.example/rss', hosts: HOSTS },
    { id: 'bad', name: 'Bad', about: '', page: 'https://news.contoso.example/', feed: 'https://news.contoso.example/down', hosts: HOSTS },
    { id: 'big', name: 'Big', about: '', page: 'https://news.contoso.example/', feed: 'https://news.contoso.example/big', hosts: HOSTS },
  ] } };
  const fetchImpl = async url => {
    calls++;
    if (url.endsWith('/down')) return { ok: false, status: 503, headers: new Headers() };
    if (url.endsWith('/big')) return { ok: true, status: 200, headers: new Headers({ 'content-length': '9000000' }), text: async () => '' };
    return { ok: true, status: 200, headers: new Headers(), text: async () => '<rss><channel><item><title>Hi</title><link>https://news.contoso.example/1</link></item></channel></rss>' };
  };
  const news = createNews({ fetchImpl, now: () => t, lists });
  const r = await news('cloud');
  assert.equal(r.sources[0].status, 'checked');
  assert.equal(r.sources[0].items[0].title, 'Hi');
  assert.equal(r.sources[1].status, 'unknown');
  assert.match(r.sources[1].error, /HTTP 503/);
  assert.match(r.sources[2].error, /too large/);
  assert.equal(news('nope'), null);
  await news('cloud'); assert.equal(calls, 3, 'cached');
  t = 1_800_001; await news('cloud'); assert.equal(calls, 6, 'refreshed after 30 minutes');
});

test('server: Internet pages are admin only; unknown page is 404', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-news-'));
  const news = kind => ({ kind, title: 't', intro: 'i', checkedAt: '2026-11-12T00:00:00Z', sources: [] });
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: dir, HM360_PUBLIC_URL: 'https://heatmap.contoso.example', ...env });
    const server = createApp({ config, store: createLocalStore(dir), auth: null, news, serviceHealth: async () => ({ providers: [] }) }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const a = await open({});
  try { assert.equal((await fetch(`${a.base}/api/admin/news/cloud`)).status, 401); } finally { a.server.close(); }
  const b = await open({ HM360_DEV_ADMIN: '1' });
  try {
    assert.equal((await (await fetch(`${b.base}/api/admin/news/exploits`)).json()).kind, 'exploits');
    assert.equal((await (await fetch(`${b.base}/api/admin/news/patches`)).json()).kind, 'patches');
    assert.equal((await fetch(`${b.base}/api/admin/news/other`)).status, 404);
  } finally { b.server.close(); }
});
