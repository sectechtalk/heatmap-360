import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseReleaseInfo, windowsStatus, parseKnownIssues, evaluateIssues, knownIssuesUrl } from '../bot/windows.mjs';
import { appStatus, compareVersions, manifestPath, createWingetLookup } from '../bot/apps.mjs';
import { healthChecks, kevCandidates, softwareMatches } from '../bot/health.mjs';
import { analyze } from '../bot/analyze.mjs';
import { processRepo } from '../bot/run.mjs';

const fx = n => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const inv = JSON.parse(fx('inventory.sample.json'));
const kev = JSON.parse(fx('kev.sample.json'));
const info = parseReleaseInfo(fx('release-info.html'));
const NOW = Date.parse('2026-11-12T20:00:00Z');
const latestMap = { 'Google.Chrome': '131.0.6778.86', '7zip.7zip': '24.08' };
const sources = (over = {}) => ({
  releaseInfo: async () => info,
  knownIssuesPage: async () => fx('known-issues.html'),
  wingetLatest: async id => { if (id === 'Broken.Lookup') throw new Error('HTTP 502'); return latestMap[id] ?? null; },
  kev: async () => ({ kev, epss: { 'CVE-2000-0001': { epss: 0.9 } } }),
  ...over,
});

test('release information: builds per version, newest first, hotpatch calendar ignored', () => {
  const b = info.builds.get(26100);
  assert.deepEqual(b.map(x => x.ubr), [9974, 9725, 9711, 9550]);
  assert.equal(b[0].kb, '5132061');
  assert.equal(b[0].label, '2026-11 B');
  assert.equal(b[0].date, '2026-11-10', 'release date, not the version availability date');
  assert.equal(info.versions.get(26100).version, '24H2');
  assert.equal(info.versions.get(22631).endOfUpdates, true);
  assert.equal(info.editions.get('24H2').homePro, 'End of updates');
});

test('Windows status: edition-aware end of updates, behind, current, unknown', () => {
  const pro = windowsStatus(inv.os, info, 'src');
  assert.equal(pro.status, 'unsupported', 'Home/Pro 24H2 is past end of updates');
  const ent = windowsStatus({ ...inv.os, edition: 'Enterprise' }, info, 'src');
  assert.equal(ent.status, 'behind');
  assert.equal(ent.missingCount, 2);
  assert.match(ent.reason, /26100\.9974 \(KB5132061\)/);
  assert.equal(windowsStatus({ ...inv.os, edition: 'Enterprise', ubr: 9974 }, info).status, 'current');
  assert.equal(windowsStatus({ build: 12345, ubr: 1 }, info).status, 'unknown');
  assert.equal(knownIssuesUrl(inv.os, '24H2'), 'https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2');
});

test('known issues: only the summary table, applied to the exact build', () => {
  const issues = parseKnownIssues(fx('known-issues.html'));
  assert.equal(issues.length, 4);
  assert.equal(issues[0].title, 'SQL Server linked server connections might remain open');
  const r = evaluateIssues(issues, inv.os, info, 'src');
  const by = Object.fromEntries(r.issues.map(i => [i.title.split(' ')[0], i.applies]));
  assert.equal(by.SQL, 'affected');
  assert.equal(by.USB, 'fix-available');
  assert.equal(by.Old, 'fixed-installed');
  assert.equal(by['Future-only'], 'not-affected');
  assert.equal(r.open, 2);
});

test('versions compare numerically; manifest paths follow winget-pkgs layout', () => {
  assert.equal(compareVersions('131.0.6778.86', '130.0.1'), 1);
  assert.equal(compareVersions('1.10', '1.9'), 1);
  assert.equal(compareVersions('24.08', '24.08'), 0);
  assert.equal(compareVersions('1.0', '1.0-beta'), 1);
  assert.equal(manifestPath('Google.Chrome'), 'manifests/g/Google/Chrome');
});

test('winget lookup picks the highest version folder and skips sub-packages', async () => {
  const fetchImpl = async url => {
    assert.match(url, /microsoft\/winget-pkgs\/contents\/manifests\/g\/Google\/Chrome$/);
    return Response.json([{ type: 'dir', name: '130.0.1' }, { type: 'dir', name: '131.0.6778.86' }, { type: 'dir', name: 'Beta' }, { type: 'file', name: 'x.yaml' }]);
  };
  assert.equal(await createWingetLookup({ fetchImpl })('Google.Chrome'), '131.0.6778.86');
});

test('app status: updates, current, and graceful failures', async () => {
  const r = await appStatus(inv.winget, sources().wingetLatest);
  assert.deepEqual(r.updates.map(u => [u.id, u.latest]), [['Google.Chrome', '131.0.6778.86']]);
  assert.deepEqual(r.current.map(u => u.id), ['7zip.7zip']);
  const why = Object.fromEntries(r.unchecked.map(u => [u.id, u.reason]));
  assert.match(why['Broken.Lookup'], /502/);
  assert.match(why['9NBLGGH4NNS1'], /msstore/);
});

test('health checks and KEV candidates read the inventory', () => {
  const c = Object.fromEntries(healthChecks(inv, NOW).map(x => [x.id, x.status]));
  assert.equal(c.uptime, 'warn');
  assert.equal(c.reboot, 'warn');
  assert.equal(c.patch, 'ok');
  assert.equal(c.firewall, 'bad');
  assert.equal(c['disk:C:'], 'warn');
  const ids = kevCandidates(inv, kev).map(x => x.cveID);
  assert.ok(ids.includes('CVE-2000-0001') && ids.includes('CVE-2000-0002') && ids.includes('CVE-2000-0004'));
  assert.ok(!ids.includes('CVE-2000-0003') && !ids.includes('CVE-2000-0005'));
  assert.equal(softwareMatches({ vendorProject: 'Adobe', product: 'Acrobat' }, { name: 'Acrobat Clone', publisher: 'Other' }), false);
});

test('analyze: a failing source only marks its own section', async () => {
  const r = await analyze({ id: '20261112180000-abcdef01', receivedAt: 'x', tokenHash: 'h', inventory: inv },
    sources({ knownIssuesPage: async () => { throw new Error('learn.microsoft.com returned HTTP 503'); } }), NOW);
  assert.equal(r.windows.status, 'unsupported');
  assert.equal(r.knownIssues.status, 'unknown');
  assert.match(r.knownIssues.error, /503/);
  assert.equal(r.summary.grade.knownIssues, 'unknown');
  assert.equal(r.summary.appUpdates, 1);
  assert.equal(r.summary.overall, 'bad');
  const all = await analyze({ id: 'x', inventory: { ...inv, os: null } }, sources({ kev: async () => { throw new Error('down'); } }), NOW);
  assert.equal(all.windows.status, 'unknown');
  assert.equal(all.exploited.status, 'unknown');
});

test('bot processes the inbox into results and rejects bad uploads', async () => {
  const repo = await mkdtemp(path.join(os.tmpdir(), 'hm360-bot-'));
  await mkdir(path.join(repo, 'inbox'));
  const good = { schema: 'hm360.upload/1', id: '20261112180000-abcdef01', receivedAt: '2026-11-12T18:00:01Z', tokenHash: 'a'.repeat(64), inventory: inv };
  await writeFile(path.join(repo, 'inbox', `${good.id}.json`), JSON.stringify(good));
  await writeFile(path.join(repo, 'inbox', '20261112180001-abcdef02.json'), JSON.stringify({ ...good, id: '20261112180001-abcdef02', inventory: { ...inv, hacker: 1 } }));
  await writeFile(path.join(repo, 'inbox', '../escape.json'.replace('../', '')), '{}');
  const done = await processRepo(repo, sources(), { now: () => NOW, log: () => {} });
  assert.deepEqual(done, ['20261112180000-abcdef01', '20261112180001-abcdef02']);
  const ok = JSON.parse(await readFile(path.join(repo, 'results', `${good.id}.json`), 'utf8'));
  assert.equal(ok.schema, 'hm360.result/1');
  assert.equal(ok.tokenHash, good.tokenHash);
  const bad = JSON.parse(await readFile(path.join(repo, 'results', '20261112180001-abcdef02.json'), 'utf8'));
  assert.match(bad.rejected, /additional properties/);
  assert.deepEqual((await readdir(path.join(repo, 'inbox'))).sort(), ['escape.json'], 'unknown files are left alone');
});
