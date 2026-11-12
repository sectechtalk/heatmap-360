import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server/index.mjs';
import { createFeeds, KEV_URL } from '../server/feeds.mjs';

const kevText = await readFile(new URL('./fixtures/kev.sample.json', import.meta.url), 'utf8');
const pcText = await readFile(new URL('./fixtures/windows-PC01.json', import.meta.url), 'utf8');

function fakeFetch(calls = []) {
  return async url => {
    calls.push(url);
    if (url === KEV_URL) return new Response(kevText, { status: 200 });
    if (url.startsWith('https://api.first.org/')) return Response.json({ data: [{ cve: 'CVE-2000-0001', epss: '0.91', percentile: '0.99' }] });
    return new Response('no', { status: 404 });
  };
}

async function start(fetchImpl = fakeFetch()) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-'));
  await writeFile(path.join(dir, 'windows-PC01.json'), '﻿' + pcText);
  await writeFile(path.join(dir, 'broken.json'), '{nope');
  const feeds = createFeeds({ dir: path.join(dir, 'feeds'), fetchImpl });
  const server = createApp({ inboxDir: dir, feeds, now: () => Date.parse('2026-11-01T18:00:00Z'), cfg: {} }).listen(0);
  return { server, dir, base: `http://127.0.0.1:${server.address().port}` };
}

test('serves machines with KEV + EPSS, rejects bad files, sets CSP', async () => {
  const { server, base } = await start();
  try {
    const data = await (await fetch(`${base}/api/machines`)).json();
    assert.equal(data.machines.length, 1);
    assert.equal(data.feeds.kevCount, 5);
    assert.equal(data.rejected[0].file, 'broken.json');
    const chrome = data.machines[0].candidates.find(c => c.cveID === 'CVE-2000-0001');
    assert.equal(chrome.epss, 0.91);
    assert.equal((await fetch(`${base}/api/machines/pc01`)).status, 200);
    assert.equal((await fetch(`${base}/api/machines/nope`)).status, 404);
    const page = await fetch(`${base}/`);
    assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(await page.text(), /HeatMap 360/);
  } finally { server.close(); }
});

test('feeds are cached on disk and fetched at most daily; failures keep the cache', async () => {
  const calls = [];
  const { server, dir, base } = await start(fakeFetch(calls));
  try {
    await fetch(`${base}/api/machines`);
    await fetch(`${base}/api/machines`);
    assert.equal(calls.filter(u => u === KEV_URL).length, 1);
    const cached = JSON.parse(await readFile(path.join(dir, 'feeds', 'kev.json'), 'utf8'));
    assert.equal(cached.kev.vulnerabilities.length, 5);
  } finally { server.close(); }
  const down = createFeeds({ dir: path.join(dir, 'feeds'), fetchImpl: async () => new Response('x', { status: 503 }), maxAgeMs: 0 });
  const s = await down.refresh();
  assert.equal(s.kev.vulnerabilities.length, 5);
  assert.match(s.lastError, /503/);
});
