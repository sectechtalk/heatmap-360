import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ACCOUNTS, parseAuthorFeed, parseThread, createBluesky, postLink } from '../server/bluesky.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const ME = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const OTHER = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
const uri = (did, rkey) => `at://${did}/app.bsky.feed.post/${rkey}`;
const post = (did, rkey, text, createdAt, extra = {}) => ({ uri: uri(did, rkey), author: { did, handle: 'x.contoso.example' }, record: { text, createdAt, ...extra.record }, replyCount: 2, repostCount: 3, likeCount: 4, ...extra.post });

test('accounts: top 50 ranked once each, pinned by DID, plus unranked official Microsoft accounts', () => {
  const ranked = ACCOUNTS.filter(a => a.rank);
  assert.equal(ranked.length, 50);
  assert.deepEqual(ranked.map(a => a.rank), Array.from({ length: 50 }, (_, i) => i + 1));
  assert.equal(new Set(ACCOUNTS.map(a => a.did)).size, ACCOUNTS.length, 'no duplicate accounts');
  assert.equal(new Set(ACCOUNTS.map(a => a.handle)).size, ACCOUNTS.length);
  for (const a of ACCOUNTS) {
    assert.match(a.did, /^did:plc:[a-z2-7]{24}$/, a.handle);
    assert.ok(['microsoft', 'vendor'].includes(a.group), a.handle);
  }
  for (const a of ACCOUNTS.filter(x => !x.rank)) assert.equal(a.group, 'microsoft', `${a.handle}: only Microsoft accounts are watched unranked`);
  for (const h of ['msrc.microsoft.com', 'threatintel.microsoft.com', 'azure.microsoft.com', 'microsoft365.microsoft.com', 'msftexchange.bsky.social']) assert.ok(ACCOUNTS.some(a => a.handle === h), h);
  assert.ok(!ACCOUNTS.some(a => a.handle === 'windowsinsider.bsky.social'), 'unofficial accounts are not listed');
});

test('parseAuthorFeed: own top-level posts only, newest first, links built from the DID', () => {
  const json = { feed: [
    { post: post(ME, '3aaaaaaaaaaaa', 'Older patch note', '2026-11-10T10:00:00Z') },
    { post: post(ME, '3bbbbbbbbbbbb', '  Newer\n\nsecurity   update ', '2026-11-12T10:00:00Z') },
    { post: post(OTHER, '3cccccccccccc', 'Reposted by the account', '2026-11-13T10:00:00Z'), reason: { $type: 'app.bsky.feed.defs#reasonRepost' } },
    { post: post(ME, '3dddddddddddd', 'A reply', '2026-11-14T10:00:00Z', { record: { reply: { parent: {} } } }) },
    { post: { ...post(ME, '3eeeeeeeeeeee', 'Bad uri', '2026-11-14T10:00:00Z'), uri: 'https://evil.example/x' } },
    { post: post(ME, '3ffffffffffff', 'Odd counts', 'not a date', { post: { replyCount: -1, likeCount: 'many', indexedAt: '2026-11-01T00:00:00Z' } }) },
  ] };
  const r = parseAuthorFeed(json, ME);
  assert.deepEqual(r.map(p => p.text), ['Newer security update', 'Older patch note', 'Odd counts']);
  assert.equal(r[0].link, `https://bsky.app/profile/${ME}/post/3bbbbbbbbbbbb`);
  assert.deepEqual([r[0].replies, r[0].reposts, r[0].likes], [2, 3, 4]);
  assert.equal(r[2].date, '2026-11-01T00:00:00.000Z', 'falls back to indexedAt');
  assert.deepEqual([r[2].replies, r[2].likes], [0, 0]);
  assert.deepEqual(parseAuthorFeed({}, ME), []);
  assert.equal(postLink('did:web:evil.example', '3aaaaaaaaaaaa'), null);
});

test('parseThread: replies most-liked first, plain text, clipped, capped', () => {
  const reply = (i, likes) => ({ post: { uri: uri(OTHER, `3r${String(i).padStart(11, 'a').replace(/\d/g, 'b')}`.slice(0, 13).padEnd(13, 'a')), author: { did: OTHER, handle: 'someone.contoso.example', displayName: 'Someone' }, record: { text: 'x'.repeat(900), createdAt: '2026-11-12T10:00:00Z' }, likeCount: likes } });
  const json = { thread: { post: {}, replies: [reply(1, 1), reply(2, 9), { post: { record: {} } }, ...Array.from({ length: 40 }, (_, i) => reply(i + 3, 0))] } };
  const r = parseThread(json);
  assert.equal(r.length, 30);
  assert.equal(r[0].likes, 9);
  assert.equal(r[0].author, 'Someone');
  assert.ok(r[0].text.length <= 600);
  assert.deepEqual(parseThread({}), []);
});

test('createBluesky: one failing account does not break the others; cached 15 minutes; replies only for listed accounts', async () => {
  let calls = 0, t = 0;
  const accounts = [{ id: 'a', rank: 1, handle: 'a.contoso.example', did: ME, name: 'A', company: 'Contoso', group: 'vendor' }, { id: 'b', rank: 2, handle: 'b.contoso.example', did: OTHER, name: 'B', company: 'Contoso', group: 'vendor' }];
  const seen = [];
  const fetchImpl = async url => {
    calls++; seen.push(url);
    assert.ok(url.startsWith('https://public.api.bsky.app/xrpc/'), 'only the public API');
    if (url.includes(encodeURIComponent(OTHER)) && url.includes('getAuthorFeed')) return { ok: false, status: 502 };
    if (url.includes('getPostThread')) return { ok: true, json: async () => ({ thread: { replies: [{ post: { uri: uri(OTHER, '3zzzzzzzzzzzz'), author: { did: OTHER, handle: 'b' }, record: { text: 'Same here', createdAt: '2026-11-12T10:00:00Z' }, likeCount: 1 } }] } }) };
    return { ok: true, json: async () => ({ feed: [{ post: post(ME, '3aaaaaaaaaaaa', 'Hello', '2026-11-12T10:00:00Z') }] }) };
  };
  const b = createBluesky({ fetchImpl, now: () => t, accounts });
  const r = await b.feed();
  assert.equal(r.accounts[0].status, 'checked');
  assert.equal(r.accounts[0].items[0].text, 'Hello');
  assert.equal(r.accounts[1].status, 'unknown');
  assert.match(r.accounts[1].error, /HTTP 502/);
  assert.ok(seen.every(u => !/createRecord|like|follow/i.test(u)), 'read only');
  await b.feed(); assert.equal(calls, 2, 'cached');
  t = 900_001; await b.feed(); assert.equal(calls, 4, 'refreshed after 15 minutes');
  const th = await b.thread(uri(ME, '3aaaaaaaaaaaa'));
  assert.equal(th.replies[0].text, 'Same here');
  assert.equal(await b.thread(uri('did:plc:cccccccccccccccccccccccc', '3aaaaaaaaaaaa')), null, 'not a listed account');
  assert.equal(await b.thread('https://evil.example/'), null);
  assert.equal(await b.thread(`${uri(ME, '3aaaaaaaaaaaa')}&x=1`), null);
});

test('server: Bluesky page and replies are admin only; bad post is 404', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-bsky-'));
  const bluesky = { feed: async () => ({ title: 'Bluesky', checkedAt: '2026-11-15T00:00:00Z', accounts: [] }), thread: async u => (u === uri(ME, '3aaaaaaaaaaaa') ? { uri: u, replies: [] } : null) };
  const open = async env => {
    const config = loadConfig({ HM360_DATA_DIR: dir, HM360_PUBLIC_URL: 'https://heatmap.contoso.example', ...env });
    const server = createApp({ config, store: createLocalStore(dir), auth: null, bluesky, news: () => null, serviceHealth: async () => ({ providers: [] }) }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const a = await open({});
  try {
    assert.equal((await fetch(`${a.base}/api/admin/bluesky`)).status, 401);
    assert.equal((await fetch(`${a.base}/api/admin/bluesky/thread?uri=x`)).status, 401);
  } finally { a.server.close(); }
  const b = await open({ HM360_DEV_ADMIN: '1' });
  try {
    assert.equal((await (await fetch(`${b.base}/api/admin/bluesky`)).json()).title, 'Bluesky');
    assert.equal((await fetch(`${b.base}/api/admin/bluesky/thread?uri=${encodeURIComponent(uri(ME, '3aaaaaaaaaaaa'))}`)).status, 200);
    assert.equal((await fetch(`${b.base}/api/admin/bluesky/thread?uri=nope`)).status, 404);
    assert.equal((await fetch(`${b.base}/api/admin/bluesky/thread`)).status, 404);
  } finally { b.server.close(); }
});
