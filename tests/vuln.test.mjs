import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { cveRecordUrl, affectedEntries, ranges, versionVerdict, entriesForApp, windowsVerdict, verdictFor, verifyCandidates, createCveLookup } from '../bot/cve.mjs';
import { yamlValue, knownIssuesSection, githubRelease, createReleaseNotesLookup, appKnownIssues } from '../bot/appissues.mjs';
import { kevCandidates } from '../bot/health.mjs';
import { analyze } from '../bot/analyze.mjs';
import { parseReleaseInfo } from '../bot/windows.mjs';

const fx = n => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const cve = id => JSON.parse(fx(`cve/${id}.json`));

test('CVE record path follows the cvelistV5 layout', () => {
  assert.equal(cveRecordUrl('CVE-2024-21412'), 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/21xxx/CVE-2024-21412.json');
  assert.equal(cveRecordUrl('CVE-2024-4671'), 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/4xxx/CVE-2024-4671.json');
  assert.equal(cveRecordUrl('../../etc/passwd'), null);
});

test('app versions: Chrome, Firefox and ESR branches, Adobe "less than or equal" ranges', () => {
  const chrome = entriesForApp(affectedEntries(cve('CVE-2024-4671')), 'Google Chrome').flatMap(ranges);
  assert.equal(versionVerdict('124.0.6367.155', chrome).verdict, 'affected');
  assert.equal(versionVerdict('124.0.6367.155', chrome).fixedIn, '124.0.6367.201');
  assert.equal(versionVerdict('124.0.6367.201', chrome).verdict, 'patched');
  assert.equal(versionVerdict('131.0.6778.86', chrome).verdict, 'patched');

  const cnaOnly = ranges({ versions: [{ version: '134.0.6998.177', status: 'affected', lessThan: '134.0.6998.177' }] });
  assert.equal(versionVerdict('134.0.6998.100', cnaOnly).verdict, 'affected', 'a start equal to the fix means "everything before"');

  const ff = affectedEntries(cve('CVE-2024-9680'));
  assert.deepEqual([...new Set(entriesForApp(ff, 'Mozilla Firefox (x64 en-US)').map(e => e.product.toLowerCase()))], ['firefox']);
  assert.deepEqual([...new Set(entriesForApp(ff, 'Mozilla Firefox ESR (x64 en-US)').map(e => e.product.toLowerCase().replace('_', ' ')))], ['firefox esr']);
  const esr = entriesForApp(ff, 'Mozilla Firefox ESR').flatMap(ranges);
  assert.equal(versionVerdict('115.17.0', esr).verdict, 'patched', 'judged against the 115 branch fix, not 128');
  assert.equal(versionVerdict('115.15.0', esr).verdict, 'affected');
  assert.equal(versionVerdict('128.5.0', esr).verdict, 'patched');
  assert.equal(versionVerdict('131.0', entriesForApp(ff, 'Mozilla Firefox').flatMap(ranges)).verdict, 'affected');

  const reader = entriesForApp(affectedEntries(cve('CVE-2023-21608')), 'Adobe Acrobat (64-bit)').flatMap(ranges);
  assert.equal(versionVerdict('22.003.20282', reader).verdict, 'affected');
  assert.equal(versionVerdict('22.003.20310', reader).verdict, 'patched');
  assert.equal(versionVerdict('24.1', reader).verdict, 'patched');
  assert.equal(versionVerdict('unknown', reader).verdict, 'unverified');
});

test('relatives of the listed product compare major versions only', () => {
  const chrome = affectedEntries(cve('CVE-2024-4671'));
  const c = { kind: 'app', vendor: 'Google', app: 'Microsoft Edge', related: true };
  assert.equal(verdictFor({ ...c, version: '120.0.2210.91' }, { containers: { cna: { affected: chrome } } }, {}).verdict, 'affected');
  assert.equal(verdictFor({ ...c, version: '124.0.2478.97' }, { containers: { cna: { affected: chrome } } }, {}).verdict, 'unverified');
  assert.equal(verdictFor({ ...c, version: '130.0.2849.80' }, { containers: { cna: { affected: chrome } } }, {}).verdict, 'patched');
});

test('Windows builds against Microsoft\'s affected build lines', () => {
  const e = affectedEntries(cve('CVE-2024-21412'));
  assert.equal(windowsVerdict({ build: 22631, ubr: 3085 }, e).verdict, 'affected');
  assert.equal(windowsVerdict({ build: 22631, ubr: 3085 }, e).fixedIn, '10.0.22631.3155');
  assert.equal(windowsVerdict({ build: 22631, ubr: 3155 }, e).verdict, 'patched');
  assert.equal(windowsVerdict({ build: 19045, ubr: 4000 }, e).verdict, 'affected');
  assert.equal(windowsVerdict({ build: 26100, ubr: 1 }, e).verdict, 'patched', 'build not listed as affected');
  assert.equal(windowsVerdict({ build: 22631, ubr: 1 }, []).verdict, 'unverified');
});

test('verifyCandidates: a failed lookup only marks its own candidate', async () => {
  const inv = { os: { build: 22631, ubr: 3085 }, apps: [] };
  const list = await verifyCandidates([{ cveID: 'CVE-2024-21412', kind: 'os' }, { cveID: 'CVE-2024-9999', kind: 'os' }, { cveID: 'CVE-2024-4671', kind: 'app', app: 'Google Chrome', version: '1.0' }], inv,
    async id => { if (id === 'CVE-2024-9999') throw new Error('HTTP 503'); return id === 'CVE-2024-4671' ? null : cve(id); });
  assert.deepEqual(list.map(c => c.verdict), ['affected', 'unverified', 'unverified']);
  assert.match(list[1].why, /503/);
  assert.match(list[0].record, /cve\.org/);
});

test('CVE lookup caches on disk and keeps the stale copy when GitHub is down', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-cve-'));
  let t = 0, calls = 0, down = false;
  const fetchImpl = async url => { calls++; if (down) return new Response('x', { status: 503 }); assert.match(url, /^https:\/\/raw\.githubusercontent\.com\/CVEProject\//); return Response.json(cve('CVE-2024-21412')); };
  const a = createCveLookup({ dir, fetchImpl, now: () => t });
  assert.ok((await a('CVE-2024-21412')).containers.cna.affected.length);
  const b = createCveLookup({ dir, fetchImpl, now: () => t });
  await b('CVE-2024-21412');
  assert.equal(calls, 1, 'second process reads the disk cache');
  down = true; t = 30 * 86_400_000;
  const c = createCveLookup({ dir, fetchImpl, now: () => t });
  assert.ok(await c('CVE-2024-21412'), 'stale copy used');
  await assert.rejects(c('not-a-cve'));
});

test('KEV candidates: every matching program, relatives flagged, Windows judged from the build date', () => {
  const kev = { vulnerabilities: [
    { cveID: 'CVE-2024-4671', vendorProject: 'Google', product: 'Chromium Visuals', dateAdded: '2024-05-13' },
    { cveID: 'CVE-2024-21412', vendorProject: 'Microsoft', product: 'Windows', dateAdded: '2024-02-13' } ] };
  const inv = { apps: [{ name: 'Google Chrome', version: '124.0.6367.155' }, { name: 'Microsoft Edge', version: '124.0.2478.97' }], updates: [{ installedOn: '2025-01-01' }] };
  const c = kevCandidates(inv, kev, {}, { patchedThrough: '2024-01-09' });
  assert.deepEqual(c.map(x => [x.cveID, x.app ?? 'os', x.related ?? null]), [['CVE-2024-4671', 'Google Chrome', false], ['CVE-2024-4671', 'Microsoft Edge', true], ['CVE-2024-21412', 'os', null]]);
  assert.equal(kevCandidates(inv, kev).filter(x => x.kind === 'os').length, 0, 'without a build date the newest update date is used');
});

test('winget YAML values and publisher known-issue sections', () => {
  const y = fx('winget-locale-known-issues.yaml');
  assert.equal(yamlValue(y, 'ReleaseNotesUrl'), 'https://www.mozilla.org/firefox/132.0/releasenotes/');
  assert.equal(yamlValue(y, 'PackageVersion'), '132.0');
  assert.deepEqual(knownIssuesSection(yamlValue(y, 'ReleaseNotes')), [
    'Some users may see a blank window after restoring a session with many tabs. Restarting the browser restores the window.',
    'Printing to some network printers can stall at 0%.']);
  assert.deepEqual(knownIssuesSection('## What\'s new\n- Faster\n\n## Known issues\n- Crash when [docking](https://x) a window\n* `Sync` stalls\n\n## Fixed\n- Bug'), ['Crash when docking a window', 'Sync stalls']);
  assert.deepEqual(knownIssuesSection('**Known Issues:**\n- None\n\n**Bug fixes**\n- x'), []);
  assert.deepEqual(knownIssuesSection('Known issue: the installer needs a restart on ARM devices.'), ['the installer needs a restart on ARM devices.']);
  assert.deepEqual(knownIssuesSection('New\n- Known issues with old plugins are now fixed'), []);
  assert.deepEqual(githubRelease('https://github.com/microsoft/PowerToys/releases/tag/v0.86.0'), { owner: 'microsoft', repo: 'PowerToys', tag: 'v0.86.0' });
  assert.equal(githubRelease('https://evil.example/microsoft/PowerToys/releases/tag/v1'), null);
});

test('release notes lookup: en-US first, then the default locale, null when the version is missing', async () => {
  const seen = [];
  const files = {
    'https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/m/Mozilla/Firefox/132.0/Mozilla.Firefox.locale.en-US.yaml': fx('winget-locale-known-issues.yaml'),
    'https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/d/Dev/App/2.0/Dev.App.yaml': 'PackageIdentifier: Dev.App\nDefaultLocale: de-DE\n',
    'https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/d/Dev/App/2.0/Dev.App.locale.de-DE.yaml': 'ReleaseNotes: "Known issues:\\n- Absturz beim Start"\n',
  };
  const look = createReleaseNotesLookup({ fetchImpl: async url => { seen.push(url); return files[url] ? new Response(files[url]) : new Response('404', { status: 404 }); } });
  assert.match((await look('Mozilla.Firefox', '132.0')).notes, /Unresolved/);
  assert.deepEqual(knownIssuesSection((await look('Dev.App', '2.0')).notes), ['Absturz beim Start']);
  assert.equal(await look('Dev.App', '9.9'), null);
});

test('app known issues: installed and update versions, GitHub fallback, failures recorded', async () => {
  const apps = { updates: [{ id: 'Mozilla.Firefox', installed: '131.0', latest: '132.0' }], current: [{ id: 'Microsoft.PowerToys', installed: '0.86.0' }, { id: 'Broken.App', installed: '1.0' }, { id: 'Gone.App', installed: '1.0' }] };
  const notes = { 'Mozilla.Firefox@132.0': { notes: yamlValue(fx('winget-locale-known-issues.yaml'), 'ReleaseNotes'), url: 'https://www.mozilla.org/firefox/132.0/releasenotes/' },
    'Mozilla.Firefox@131.0': { notes: 'Fixed\n- Stuff', url: null }, 'Microsoft.PowerToys@0.86.0': { notes: null, url: 'https://github.com/microsoft/PowerToys/releases/tag/v0.86.0' } };
  const gh = [];
  const r = await appKnownIssues(apps, {
    releaseNotes: async (id, v) => { if (id === 'Broken.App') throw new Error('HTTP 500'); return notes[`${id}@${v}`] ?? null; },
    githubReleaseNotes: async rel => { gh.push(rel); return '## Known issues\n- Run window does not open after sleep'; } });
  assert.deepEqual(r.issues.map(i => [i.id, i.version, i.which, i.items.length]), [['Microsoft.PowerToys', '0.86.0', 'installed', 1], ['Mozilla.Firefox', '132.0', 'update', 2]]);
  assert.equal(gh.length, 1);
  assert.equal(r.grade, 'warn');
  assert.equal(r.checked, 3);
  assert.equal(r.notInCatalog, 1);
  assert.match(r.failed[0].reason, /500/);
  assert.match(r.reason, /read before updating/);
});

test('analyze: exploited section is version-checked and graded, app known issues added', async () => {
  const inv = JSON.parse(fx('inventory.sample.json'));
  const info = parseReleaseInfo(fx('release-info.html'));
  const kev = { catalogVersion: 'x', vulnerabilities: [
    { cveID: 'CVE-2024-4671', vendorProject: 'Google', product: 'Chromium Visuals', dateAdded: '2024-05-13', knownRansomwareCampaignUse: 'Unknown' },
    { cveID: 'CVE-2023-21608', vendorProject: 'Adobe', product: 'Acrobat and Reader', dateAdded: '2023-10-10', knownRansomwareCampaignUse: 'Unknown' } ] };
  const sources = { releaseInfo: async () => info, knownIssuesPage: async () => fx('known-issues.html'), wingetLatest: async id => (id === 'Google.Chrome' ? '131.0.6778.86' : null),
    kev: async () => ({ kev, epss: {} }), cveRecord: async id => cve(id), releaseNotes: async () => null };
  const r = await analyze({ id: 'x', inventory: { ...inv, apps: [{ name: 'Google Chrome', version: '120.0.6099.71' }, { name: 'Adobe Acrobat (64-bit)', version: '24.1' }] } }, sources, Date.parse('2026-11-12T20:00:00Z'));
  assert.deepEqual(r.exploited.affected.map(c => c.cveID), ['CVE-2024-4671']);
  assert.deepEqual(r.exploited.patched.map(c => c.cveID), ['CVE-2023-21608']);
  assert.equal(r.summary.grade.exploited, 'bad');
  assert.equal(r.summary.exploited, 1);
  assert.equal(r.appIssues.status, 'checked');
  assert.equal(r.summary.grade.appIssues, 'ok');
});
