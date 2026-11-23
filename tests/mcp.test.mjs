import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';
import { createMcp, checkBaseUrl, TOOLS } from '../mcp/server.mjs';

const NOW = Date.parse('2026-11-22T12:00:00Z');
const ago = h => new Date(NOW - h * 3_600_000).toISOString();
const ID = '20261121080000-0a1b2c3d';
const serverFile = fileURLToPath(new URL('../mcp/server.mjs', import.meta.url));

const fakes = {
  news: kind => (['cloud', 'exploits', 'patches'].includes(kind) ? { kind, title: kind, checkedAt: ago(0), sources: [
    { id: 'a', name: 'Source A', status: 'checked', items: [{ title: 'Zero-day in Contoso VPN', date: ago(2), summary: 'exploited' }, { title: 'Old news', date: ago(400) }] },
    { id: 'b', name: 'Source B', status: 'checked', items: [{ title: 'Patch Tuesday', date: ago(30) }] },
  ] } : null),
  serviceHealth: () => ({ providers: [{ name: 'Azure', grade: 'ok', summary: 'No active incidents', incidents: [] }] }),
  attention: () => ({ checkedAt: ago(0), rules: [], items: [{ id: 'kev:CVE-2026-0001', level: 'critical' }] }),
  cves: () => ({ title: 'Cloudflare Radar CVEs', page: 'https://radar.cloudflare.com/zero-wire/cves', checkedAt: ago(0), feeds: [], items: [
    { id: 'CVE-2026-0001', title: 'Contoso RCE', severity: 'critical', kevAdded: '2026-11-21', date: ago(1) },
    { id: 'CVE-2026-0002', title: 'Fabrikam XSS', severity: 'medium', kevAdded: null, date: ago(5) },
    { id: 'CVE-2026-0003', title: 'Old one', severity: 'critical', kevAdded: null, date: ago(300) },
  ] }),
  bluesky: { feed: () => ({ title: 'Bluesky', checkedAt: ago(0), accounts: [
    { name: 'Microsoft Security', handle: 'msft.example', company: 'Microsoft', status: 'checked', items: [{ uri: 'at://did:plc:x/app.bsky.feed.post/1', text: 'Out-of-band update', date: ago(3) }] },
    { name: 'Other Co', handle: 'other.example', company: 'Other', status: 'unknown', error: 'down', items: [] },
  ] }), thread: () => null },
};

async function startApp(env) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-mcp-'));
  await mkdir(path.join(dir, 'results'), { recursive: true });
  await writeFile(path.join(dir, 'results', `${ID}.json`), JSON.stringify({ schema: 'hm360.result/1', id: ID, receivedAt: ago(28), processedAt: ago(27), tokenHash: 'f'.repeat(64),
    inventory: { machineId: 'm-1', os: { name: 'Windows 11', build: 26100, ubr: 1 } }, summary: { overall: 'warn' }, windows: { status: 'current' }, apps: { status: 'checked', updates: [] } }));
  const config = loadConfig({ HM360_DATA_DIR: dir, HM360_PUBLIC_URL: 'http://localhost:3460', ...env });
  const server = createApp({ config, store: createLocalStore(dir), auth: null, clientScript: '#', ...fakes }).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

const text = r => JSON.parse(r.content[0].text);

test('mcp: only loopback HeatMap addresses are accepted', () => {
  assert.equal(checkBaseUrl('http://localhost:3460/'), 'http://localhost:3460');
  assert.equal(checkBaseUrl('http://127.0.0.1:3460'), 'http://127.0.0.1:3460');
  assert.throws(() => checkBaseUrl('https://app-heatmap360.contoso.example'), /loopback/);
  assert.throws(() => checkBaseUrl('http://192.168.1.10:3460'), /loopback/);
  assert.throws(() => checkBaseUrl('file:///etc/passwd'), /http/);
});

test('mcp: every tool is read only and has a strict input schema', () => {
  assert.equal(TOOLS.length, 8);
  for (const t of TOOLS) {
    assert.match(t.name, /^heatmap_[a-z_]+$/);
    assert.equal(t.annotations.readOnlyHint, true);
    assert.equal(t.annotations.destructiveHint, false);
    assert.equal(t.inputSchema.additionalProperties, false);
  }
  const src = readFileSync(serverFile, 'utf8');
  assert.ok(!/method:\s*'(POST|PUT|DELETE|PATCH)'/i.test(src), 'no writes to HeatMap');
});

test('mcp: tools read the local dev-admin copy and filter like the pages', async () => {
  const { server, base } = await startApp({ HM360_DEV_ADMIN: '1' });
  const mcp = createMcp({ baseUrl: base, now: () => NOW });
  try {
    const scans = text(await mcp.callTool('heatmap_list_scans', {}));
    assert.equal(scans.scans[0].id, ID);

    const scan = text(await mcp.callTool('heatmap_get_scan', { id: ID }));
    assert.equal(scan.summary.overall, 'warn');
    assert.equal(scan.inventory, undefined, 'raw inventory only on request');
    assert.equal(scan.tokenHash, undefined);
    const inv = text(await mcp.callTool('heatmap_get_scan', { id: ID, sections: ['inventory'] }));
    assert.equal(inv.inventory.machineId, 'm-1');
    assert.equal(inv.summary, undefined);

    const news = text(await mcp.callTool('heatmap_news', { page: 'exploits', hours: 8 }));
    assert.deepEqual(news.sources.map(s => s.count), [1, 0]);
    const searched = text(await mcp.callTool('heatmap_news', { page: 'patches', search: 'patch tuesday', sources: ['b'] }));
    assert.deepEqual(searched.sources.map(s => s.id), ['b']);
    assert.equal(searched.sources[0].count, 1);

    const cves = text(await mcp.callTool('heatmap_cloudflare_cves', { severity: ['critical'] }));
    assert.deepEqual(cves.items.map(i => i.id), ['CVE-2026-0001']);
    const kev = text(await mcp.callTool('heatmap_cloudflare_cves', { knownExploitedOnly: true, hours: 720 }));
    assert.deepEqual(kev.items.map(i => i.id), ['CVE-2026-0001']);

    const bsky = text(await mcp.callTool('heatmap_bluesky', { company: 'microsoft' }));
    assert.equal(bsky.total, 1);
    assert.equal(bsky.posts[0].account, 'Microsoft Security');
    const all = text(await mcp.callTool('heatmap_bluesky', {}));
    assert.deepEqual(all.problems, [{ account: 'Other Co', error: 'down' }]);

    assert.equal(text(await mcp.callTool('heatmap_high_impact', {})).items[0].level, 'critical');
    assert.equal(text(await mcp.callTool('heatmap_service_health', {})).providers[0].name, 'Azure');

    const notFound = await mcp.callTool('heatmap_bluesky_replies', { uri: 'at://did:plc:nobody/app.bsky.feed.post/1' });
    assert.equal(notFound.isError, true);
    assert.match(notFound.content[0].text, /Unknown post/);
  } finally { server.close(); }
});

test('mcp: bad arguments are refused before HeatMap is called', async () => {
  let calls = 0;
  const mcp = createMcp({ fetchImpl: async () => { calls++; throw new Error('no'); } });
  for (const [name, args] of [
    ['heatmap_get_scan', { id: '../../settings/findings' }],
    ['heatmap_get_scan', {}],
    ['heatmap_news', { page: 'other' }],
    ['heatmap_news', { page: 'cloud', hours: 0 }],
    ['heatmap_cloudflare_cves', { severity: ['urgent'] }],
    ['heatmap_list_scans', { extra: 1 }],
    ['heatmap_bluesky_replies', { uri: 'https://evil.example' }],
  ]) {
    const r = await mcp.callTool(name, args);
    assert.equal(r.isError, true, `${name} ${JSON.stringify(args)}`);
  }
  assert.equal(calls, 0);
  assert.equal(await mcp.callTool('heatmap_delete_everything', {}), null);
});

test('mcp: a signed-in copy keeps its gate (401 is reported, nothing leaks)', async () => {
  const { server, base } = await startApp({});
  const mcp = createMcp({ baseUrl: base });
  try {
    const r = await mcp.callTool('heatmap_list_scans', {});
    assert.equal(r.isError, true);
    assert.match(r.content[0].text, /signed-in, elevated admin/);
    assert.ok(!r.content[0].text.includes(ID));
  } finally { server.close(); }
});

test('mcp: HeatMap not running gives a clear message', async () => {
  const mcp = createMcp({ baseUrl: 'http://127.0.0.1:9', fetchImpl: async () => { throw new TypeError('fetch failed'); } });
  const r = await mcp.callTool('heatmap_high_impact', {});
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /not answering/);
});

test('mcp: stdio protocol end to end (initialize, tools/list, tools/call)', async () => {
  const { server, base } = await startApp({ HM360_DEV_ADMIN: '1' });
  const child = spawn(process.execPath, [serverFile], { env: { ...process.env, HM360_URL: base }, stdio: ['pipe', 'pipe', 'pipe'] });
  try {
    const replies = new Map();
    let buf = '';
    const waiters = new Map();
    child.stdout.on('data', d => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
        replies.set(m.id, m); waiters.get(m.id)?.(m);
      }
    });
    const ask = (id, method, params) => new Promise(resolve => { waiters.set(id, resolve); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`); });

    const init = await ask(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.equal(init.result.serverInfo.name, 'heatmap-360');
    assert.ok(init.result.capabilities.tools);
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);

    const list = await ask(2, 'tools/list', {});
    assert.equal(list.result.tools.length, 8);

    const call = await ask(3, 'tools/call', { name: 'heatmap_list_scans', arguments: {} });
    assert.equal(JSON.parse(call.result.content[0].text).scans[0].id, ID);

    assert.equal((await ask(4, 'nope', {})).error.code, -32601);
    assert.equal((await ask(5, 'tools/call', { name: 'nope', arguments: {} })).error.code, -32602);
    assert.deepEqual((await ask(6, 'ping')).result, {});
    assert.ok(!replies.has(undefined), 'notifications get no reply');
  } finally { child.kill(); server.close(); }
});
