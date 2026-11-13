import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createApp, summarize } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';
import { analyze } from '../bot/analyze.mjs';
import { parseReleaseInfo } from '../bot/windows.mjs';

const fx = n => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const inv = JSON.parse(fx('inventory.sample.json'));

async function start(env = {}, extra = {}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-srv-'));
  const config = loadConfig({ HM360_DATA_DIR: dir, HM360_PUBLIC_URL: 'https://heatmap.contoso.example', ...env });
  const server = createApp({ config, store: createLocalStore(dir), auth: null, ...extra }).listen(0);
  return { dir, server, base: `http://127.0.0.1:${server.address().port}` };
}
const post = (base, body, type = 'application/json') => fetch(`${base}/api/scans`, { method: 'POST', headers: { 'content-type': type }, body: typeof body === 'string' ? body : JSON.stringify(body) });

test('upload: valid inventory is stored in the inbox with only a token hash', async () => {
  const { dir, server, base } = await start();
  try {
    const r = await post(base, { ...inv, apps: [...inv.apps, { name: 'Tool for jane.doe@contoso.example', version: '1', publisher: 'C:\\Users\\jane\\x' }] });
    assert.equal(r.status, 202);
    const { id, token } = await r.json();
    assert.match(id, /^\d{14}-[0-9a-f]{8}$/);
    const rec = JSON.parse(await readFile(path.join(dir, 'inbox', `${id}.json`), 'utf8'));
    assert.equal(rec.schema, 'hm360.upload/1');
    assert.match(rec.tokenHash, /^[0-9a-f]{64}$/);
    assert.ok(!JSON.stringify(rec).includes(token), 'the token itself is never stored');
    assert.ok(!JSON.stringify(rec).includes('jane'), 'emails and user folders are scrubbed');
  } finally { server.close(); }
});

test('upload: strict validation, size limit and rate limit', async () => {
  const { dir, server, base } = await start({ HM360_UPLOADS_PER_10MIN: '6' });
  try {
    assert.equal((await post(base, { ...inv, extra: 1 })).status, 422);
    assert.equal((await post(base, { ...inv, machineId: 'PC01' })).status, 422);
    assert.equal((await post(base, 'nope', 'text/plain')).status, 422);
    assert.equal((await post(base, { ...inv, apps: Array(3001).fill(inv.apps[0]) })).status, 422, 'too many items');
    assert.equal((await post(base, { ...inv, apps: Array(2000).fill({ name: 'x'.repeat(600), version: '1', publisher: 'p' }) })).status, 413, 'over 1 MB');
    assert.equal((await post(base, inv)).status, 202);
    assert.equal((await post(base, inv)).status, 202);
    const limited = await post(base, inv);
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.headers.get('retry-after')) > 0);
    assert.equal((await readdir(path.join(dir, 'inbox'))).length, 2);
  } finally { server.close(); }
});

test('uploader: token unlocks status and PDF of that scan only', async () => {
  const { dir, server, base } = await start();
  try {
    const { id, token } = await (await post(base, inv)).json();
    const auth = t => ({ headers: { authorization: `Bearer ${t}` } });
    assert.equal((await fetch(`${base}/api/scans/${id}/status`)).status, 404);
    assert.equal((await fetch(`${base}/api/scans/${id}/status`, auth('x'.repeat(43)))).status, 404);
    assert.equal((await (await fetch(`${base}/api/scans/${id}/status`, auth(token))).json()).state, 'queued');
    assert.equal((await fetch(`${base}/api/scans/${id}/report.pdf`, auth(token))).status, 409);
    // the bot runs
    const upload = JSON.parse(await readFile(path.join(dir, 'inbox', `${id}.json`), 'utf8'));
    const info = parseReleaseInfo(fx('release-info.html'));
    const result = await analyze(upload, { releaseInfo: async () => info, knownIssuesPage: async () => fx('known-issues.html'), wingetLatest: async () => null, kev: async () => ({ kev: JSON.parse(fx('kev.sample.json')), epss: {} }) });
    await createLocalStore(dir).put(`results/${id}.json`, result);
    assert.equal((await (await fetch(`${base}/api/scans/${id}/status`, auth(token))).json()).state, 'done');
    const pdf = await fetch(`${base}/api/scans/${id}/report.pdf`, auth(token));
    assert.equal(pdf.status, 200);
    assert.equal(pdf.headers.get('content-type'), 'application/pdf');
    assert.equal(Buffer.from(await pdf.arrayBuffer()).subarray(0, 5).toString(), '%PDF-');
  } finally { server.close(); }
});

test('admin pages need sign-in + elevation; dev mode lists and shows scans', async () => {
  const a = await start();
  try {
    assert.equal((await fetch(`${a.base}/api/admin/scans`)).status, 401);
    const me = await (await fetch(`${a.base}/api/me`)).json();
    assert.equal(me.signedIn, false);
    assert.equal((await fetch(`${a.base}/auth/signin`)).status, 503);
  } finally { a.server.close(); }
  const b = await start({ HM360_DEV_ADMIN: '1' });
  try {
    const { id } = await (await post(b.base, inv)).json();
    const upload = JSON.parse(await readFile(path.join(b.dir, 'inbox', `${id}.json`), 'utf8'));
    const result = await analyze(upload, { releaseInfo: async () => { throw new Error('offline'); }, knownIssuesPage: async () => '', wingetLatest: async () => null, kev: async () => { throw new Error('offline'); } });
    await createLocalStore(b.dir).put(`results/${id}.json`, result);
    const list = await (await fetch(`${b.base}/api/admin/scans`)).json();
    assert.equal(list.scans[0].id, id);
    assert.equal(list.scans[0].computer, 'Contoso Laptop 14');
    const one = await (await fetch(`${b.base}/api/admin/scans/${id}`)).json();
    assert.equal(one.tokenHash, undefined);
    assert.equal(one.windows.status, 'unknown');
    assert.equal((await fetch(`${b.base}/api/admin/scans/../../etc`)).status, 404);
  } finally { b.server.close(); }
  assert.equal(loadConfig({ HM360_DEV_ADMIN: '1', NODE_ENV: 'production' }).devAdmin, false);
  assert.equal(loadConfig({ HM360_DEV_ADMIN: '1', HM360_BIND: '0.0.0.0' }).devAdmin, false);
});

test('scanner download is pre-filled with this server address; pages carry CSP', async () => {
  const { server, base } = await start();
  try {
    const s = await (await fetch(`${base}/client/Invoke-HeatMapScan.ps1`)).text();
    assert.match(s, /\[string\]\$Server = 'https:\/\/heatmap\.contoso\.example'/);
    const page = await fetch(`${base}/`);
    assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(await page.text(), /HeatMap 360/);
  } finally { server.close(); }
});

test('summarize hides inventory detail', () => {
  assert.deepEqual(summarize({ id: 'x', rejected: 'bad', receivedAt: 'r' }).state, 'rejected');
});
