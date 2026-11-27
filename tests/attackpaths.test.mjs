// Attack paths page: BloodHound CE summaries read from a local folder, checked strictly, served to admins only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAttackPaths, checkSummary, checkReport, FINDINGS } from '../server/attackpaths.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const summary = (over = {}) => ({
  schema: 'hm360.attackpaths/1', tool: 'BloodHound CE', collector: 'bloodhound-ce-python 1.9.1', collection: 'All',
  domain: 'Contoso.Example', generatedAt: '2026-11-22T04:00:00Z', counts: { users: 120, groups: 60, computers: 30 },
  findings: [
    { id: 'pathToDomainAdmins', count: 2, items: ['SVC-SYNC@CONTOSO.EXAMPLE', 'HELPDESK1@CONTOSO.EXAMPLE'] },
    { id: 'kerberoastable', count: 0, items: [] },
  ],
  ...over,
});
const check = (id, rating, name = id, area = 'permissions') => ({ id, name, rating, area });
const report = (over = {}) => ({
  schema: 'hm360.adminer/1', tool: 'AD Miner', version: '1.9.0', domains: ['Contoso.Example'], generatedAt: '2026-11-22T05:00:00Z', dataDate: '2026-11-22', objects: 900, files: 240,
  failedRequests: [], failedControls: ['fgpp'],
  controls: [check('smb_signing', 'green', 'SMB signing'), check('fgpp', 'grey', 'Users FGPP', 'misc'), check('kerberoastables', 'orange', 'Kerberoastable accounts', 'kerberos'),
    check('dangerous_paths', 'red', 'Attack paths choke points'), check('can_dcsync', 'red', 'Inadequate access to DCSync privileges'), check('never_expires', 'yellow', 'Users without password expiration', 'passwords')],
  ...over,
});
// Names may hold one folder ("adminer/..."); Buffers are written as they are, objects as JSON.
const folder = async files => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-ap-'));
  for (const [n, v] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(dir, n)), { recursive: true });
    await writeFile(path.join(dir, n), typeof v === 'string' || Buffer.isBuffer(v) ? v : JSON.stringify(v));
  }
  return dir;
};

test('checkSummary keeps known findings in page order, sorts names, and rejects anything else', () => {
  const s = checkSummary(summary(), '20261122040000');
  assert.equal(s.domain, 'contoso.example');
  assert.deepEqual(s.findings.map(f => f.id), ['pathToDomainAdmins', 'kerberoastable']);
  assert.deepEqual(s.findings[0].items, ['HELPDESK1@CONTOSO.EXAMPLE', 'SVC-SYNC@CONTOSO.EXAMPLE']);
  assert.equal(checkSummary(summary({ schema: 'x' }), 'a'), null);
  assert.equal(checkSummary(summary({ tool: 'SharpHound' }), 'a'), null);
  assert.equal(checkSummary(summary({ domain: '../etc' }), 'a'), null);
  assert.equal(checkSummary(summary({ counts: { users: -1, groups: 1, computers: 1 } }), 'a'), null);
  assert.equal(checkSummary(summary({ findings: [{ id: 'runThis', count: 1, items: [] }] }), 'a'), null);
  assert.equal(checkSummary(summary({ findings: [{ id: 'dcsync', count: 1, items: [{}] }] }), 'a'), null);
  assert.equal(checkSummary(summary({ findings: [{ id: 'dcsync', count: 1, items: Array(201).fill('x') }] }), 'a'), null);
  assert.ok(Object.keys(FINDINGS).length >= 7);
});

test('list: newest two per domain keep names, older ones only counts; junk files are skipped', async () => {
  const dir = await folder({
    'bloodhound-20261108040000.json': summary({ generatedAt: '2026-11-08T04:00:00Z' }),
    'bloodhound-20261115040000.json': summary({ generatedAt: '2026-11-15T04:00:00Z' }),
    'bloodhound-20261122040000.json': summary(),
    'bloodhound-20261123040000.json': '{not json',
    'bloodhound-20261122040000.zip': 'raw',
    'notes.txt': 'x',
  });
  const out = await createAttackPaths({ dir }).list();
  assert.equal(out.scans.length, 3);
  assert.equal(out.skipped, 1);
  assert.equal(out.scans[0].findings[0].items, undefined, 'oldest scan has counts only');
  assert.equal(out.scans[2].findings[0].items.length, 2);
  assert.deepEqual(out.reports, [], 'no adminer folder means no reports, not an error');
  assert.deepEqual(await createAttackPaths({}).list(), { configured: false, folderFound: false, scans: [], skipped: 0, reports: [], skippedReports: 0 });
  assert.equal((await createAttackPaths({ dir: path.join(os.tmpdir(), 'hm360-ap-missing-x') }).list()).folderFound, false);
});

test('checkReport accepts what the AD Miner script writes, worst rating first, and rejects anything else', () => {
  const r = checkReport(report({ domains: ['B.Contoso.Example', 'a.contoso.example', 'A.CONTOSO.EXAMPLE'] }), '20261122050000');
  assert.deepEqual({ ...r, controls: undefined }, { id: '20261122050000', generatedAt: '2026-11-22T05:00:00.000Z', version: '1.9.0', domains: ['a.contoso.example', 'b.contoso.example'],
    dataDate: '2026-11-22', objects: 900, files: 240, failedRequests: [], failedControls: ['fgpp'], controls: undefined });
  assert.deepEqual(r.controls.map(c => c.id), ['dangerous_paths', 'can_dcsync', 'kerberoastables', 'never_expires', 'smb_signing', 'fgpp']);
  assert.deepEqual(r.controls[0], { id: 'dangerous_paths', name: 'Attack paths choke points', rating: 'red', area: 'permissions' });
  // A report whose ratings the script could not read is still a report: no checks, no data date.
  const bare = checkReport({ schema: 'hm360.adminer/1', tool: 'AD Miner', version: '1.9.0', domains: ['contoso.example'], generatedAt: '2026-11-22T05:00:00Z', dataDate: null, files: 3, controls: [] }, 'b');
  assert.deepEqual([bare.dataDate, bare.objects, bare.controls, bare.failedRequests, bare.failedControls], [null, null, [], [], []]);
  assert.equal(checkReport(report({ controls: [check('x', 'green', '')] }), 'a').controls[0].name, 'x', 'a check without a title shows its id');
  for (const bad of [{ schema: 'hm360.attackpaths/1' }, { tool: 'BloodHound CE' }, { version: '1.9.0; rm' }, { version: 7 }, { domains: [] }, { domains: ['../x'] },
    { domains: 'contoso.example' }, { domains: Array(51).fill('contoso.example') }, { generatedAt: 'yesterday' }, { files: -1 }, { files: '240' }, { objects: -5 },
    { dataDate: '22/11/2026' }, { dataDate: '2026-13-45' }, { failedControls: 1 }, { failedRequests: ['ok', 'not ok'] }, { controls: 'none' }, { controls: Array(301).fill(check('a', 'green')) },
    { controls: [check('a', 'purple')] }, { controls: [check('a b', 'red')] }, { controls: [check('a', 'red', 'x'.repeat(201))] }, { controls: [check('a', 'red', 'A', 'Not An Area')] }, { controls: [null] }])
    assert.equal(checkReport(report(bad), 'a'), null, JSON.stringify(bad).slice(0, 80));
  assert.equal(checkReport(null, 'a'), null);
});

test('AD Miner reports: listed newest first with the zip size; one without details does not exist', async () => {
  const zip = Buffer.from('PK\u0003\u0004 not a real zip, only bytes to serve');
  const dir = await folder({
    'bloodhound-20261122040000.json': summary(),
    'adminer/adminer-20261115050000.json': report({ generatedAt: '2026-11-15T05:00:00Z' }),
    'adminer/adminer-20261115050000.zip': zip,
    'adminer/adminer-20261122050000.json': report(),
    'adminer/adminer-20261122050000.zip': Buffer.concat([zip, zip]),
    'adminer/adminer-20261123050000.json': report({ generatedAt: '2026-11-23T05:00:00Z' }), // its zip was deleted by hand
    'adminer/adminer-20261124050000.zip': zip,                                            // a run that never finished: no details
    'adminer/adminer-20261125050000.json': '{not json',
    'adminer/adminer-20261126050000.json': report({ tool: 'Something else' }),
    'adminer/notes.txt': 'x',
  });
  const ap = createAttackPaths({ dir });
  const out = await ap.list();
  assert.deepEqual(out.reports.map(r => [r.id, r.bytes]), [['20261123050000', 0], ['20261122050000', zip.length * 2], ['20261115050000', zip.length]]);
  assert.deepEqual(out.reports[0].ratings, { red: 2, orange: 1, yellow: 1, green: 1, grey: 1 }, 'every report says how many checks got each rating');
  assert.deepEqual(out.reports[0].controls.map(c => c.rating), ['red', 'red', 'orange', 'yellow', 'grey'], 'the newest report names every check that is not green');
  assert.equal(out.reports[1].controls, undefined, 'older reports carry the counts only');
  assert.deepEqual(out.reports[1].ratings, out.reports[0].ratings);
  assert.equal(out.skippedReports, 2);
  assert.equal(out.scans.length, 1, 'the collections are still listed');
  assert.equal((await ap.reportZip('20261122050000')).size, zip.length * 2);
  for (const id of ['20261123050000', '20261124050000', '20261125050000', '20261101050000', '../adminer-20261122050000', '20261122050000/..', '', null, 20261122050000])
    assert.equal(await ap.reportZip(id), null, String(id));
  assert.equal(await createAttackPaths({}).reportZip('20261122050000'), null);
  // A link in place of the zip is refused: the page only ever serves a plain file from this folder.
  const linked = path.join(dir, 'adminer', 'adminer-20261123050000.zip');
  const made = await symlink(path.join(dir, 'bloodhound-20261122040000.json'), linked).then(() => true, () => false); // needs a privilege on Windows
  if (made) assert.equal(await ap.reportZip('20261123050000'), null);
});

test('config and compose: local copy reads data/attackpaths read-only; a GitHub-backed copy has none', () => {
  assert.match(loadConfig({}, '/app').attackpaths.dir.replace(/\\/g, '/'), /\/app\/data\/attackpaths$/);
  assert.equal(loadConfig({ HM360_DATA_REPO: 'owner/data', HM360_GITHUB_TOKEN: 't' }, '/app').attackpaths, null);
  const compose = readFileSync(new URL('../compose.yaml', import.meta.url), 'utf8');
  assert.match(compose, /HM360_ATTACKPATHS_DIR: \/data\/attackpaths/);
  assert.match(compose, /- \.\/data\/attackpaths:\/data\/attackpaths:ro/);
  const bh = readFileSync(new URL('../tools/bloodhound/compose.yaml', import.meta.url), 'utf8');
  assert.match(bh, /127\.0\.0\.1:3461:8080/, 'BloodHound listens on loopback only');
  assert.doesNotMatch(bh, /7687:7687|7474:7474|5432:5432/, 'database ports are not published');
  assert.doesNotMatch(bh, /PASSWORD=[A-Za-z0-9]/, 'passwords come from .env, never the compose file');
});

test('API: admins only; the AD Miner report is a zip download and nothing else in the folder can be fetched', async () => {
  const zip = Buffer.from('PK\u0003\u0004 not a real zip, only bytes to serve');
  const dir = await folder({
    'bloodhound-20261122040000.json': summary(), 'bloodhound-20261122040000.zip': 'the collector data, never served',
    'adminer/adminer-20261122050000.json': report(), 'adminer/adminer-20261122050000.zip': zip,
    'adminer/adminer-20261123050000.zip': zip, // no details file
  });
  const data = await mkdtemp(path.join(os.tmpdir(), 'hm360-ap-data-'));
  const open = env => {
    const server = createApp({ config: loadConfig({ HM360_DATA_DIR: data, HM360_ATTACKPATHS_DIR: dir, ...env }), store: createLocalStore(data), auth: null }).listen(0);
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const anon = open({});
  try {
    assert.equal((await fetch(`${anon.base}/api/admin/attackpaths`)).status, 401);
    assert.equal((await fetch(`${anon.base}/api/admin/attackpaths/adminer/20261122050000/report.zip`)).status, 401);
  } finally { anon.server.close(); }
  const dev = open({ HM360_DEV_ADMIN: '1' });
  try {
    const list = await (await fetch(`${dev.base}/api/admin/attackpaths`)).json();
    assert.equal(list.scans[0].domain, 'contoso.example');
    assert.deepEqual(list.reports.map(r => [r.id, r.bytes, r.ratings.red]), [['20261122050000', zip.length, 2]]);
    const r = await fetch(`${dev.base}/api/admin/attackpaths/adminer/20261122050000/report.zip`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /^application\/zip/);
    assert.match(r.headers.get('content-disposition'), /attachment; filename="?ADMiner-20261122050000\.zip"?/);
    assert.equal(r.headers.get('content-length'), String(zip.length));
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.deepEqual(Buffer.from(await r.arrayBuffer()), zip);
    for (const id of ['20261123050000', '20261101050000', '..%2Fbloodhound-20261122040000', '..%2F..%2Fx', '20261122050000%2F..', 'x'])
      assert.equal((await fetch(`${dev.base}/api/admin/attackpaths/adminer/${id}/report.zip`)).status, 404, id);
    assert.equal((await fetch(`${dev.base}/api/admin/attackpaths/adminer/20261122050000/report.json`)).status, 404, 'only the zip has a route');
  } finally { dev.server.close(); }
});

test('UI and setup page: Attack paths under Results, routed, and BloodHound set up end to end', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /href="#adposture"[^\n]*\n\s*<a class="nav-item sub" href="#attackpaths" data-route="attackpaths">/);
  assert.match(app, /name === 'attackpaths' \? await viewAttackPaths\(\)/);
  assert.match(app, /api\('\/api\/admin\/attackpaths'\)/);
  for (const s of ['setup-attackpaths', 'Invoke-BloodHoundScan.ps1', 'docker compose up -d', 'hm360-bhcollector:1.9.1', 'Register-ScheduledTask', 'Unregister-ScheduledTask', 'docker compose down -v', 'data\\\\attackpaths', 'contoso.example'])
    assert.ok(app.includes(s), s);
});

test('UI and setup page: the AD Miner report is listed, downloaded through fetch with busy wording, and set up end to end', () => {
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(app, /download\(`\/api\/admin\/attackpaths\/adminer\/\$\{r\.id\}\/report\.zip`/, 'the zip goes through download(), which reports failure');
  assert.match(app, /busy: 'Downloading report…', done: 'Downloaded', fail: 'Download failed', onclick: \(\) => download\(`\/api\/admin\/attackpaths\/adminer/);
  assert.doesNotMatch(app, /<iframe|innerHTML[^\n]*adminer/i, 'the report is never rendered inside the page');
  for (const s of ['setup-adminer', 'Invoke-ADMinerReport.ps1', 'docker build -t hm360-adminer:1.9.0', 'GPL-3.0', 'data\\\\attackpaths\\\\adminer', 'label=hm360.adminer', 'docker image rm hm360-adminer:1.9.0',
    'no network at all', 'PYTHONHASHSEED=0', 'Immediate risk', 'Not evaluated'])
    assert.ok(app.includes(s), s);
});

test('AD Miner script: works on a throwaway copy with no network and no real password, and always cleans up', () => {
  const ps = readFileSync(new URL('../tools/bloodhound/Invoke-ADMinerReport.ps1', import.meta.url), 'utf8');
  assert.match(ps, /schema\s+= 'hm360\.adminer\/1'/);
  // BloodHound's own volume is only ever mounted read-only, into a helper that has no network.
  assert.match(ps, /'--network', 'none', '--user', '0'\) \+ \$marked \+ @\('--entrypoint', 'cp',\s+'-v', "\$\{sourceVolume\}:\/from:ro"/);
  assert.equal([...ps.matchAll(/\$\{?sourceVolume\}?:/g)].length, 1, 'no other container mounts BloodHound\'s volume');
  // The throwaway database has no network; AD Miner only joins that container's loopback.
  assert.match(ps, /'run', '-d', '--name', \$copyDb, '--network', 'none'/);
  assert.match(ps, /'create', '--name', \$runner, '--network', "container:\$copyDb"/);
  assert.match(ps, /'-b', 'bolt:\/\/127\.0\.0\.1:7687'/);
  assert.doesNotMatch(ps, /--network', '(bridge|host)'|'network', 'create'|'-p', '\d|--publish/, 'no other network and no published port');
  // No real secret reaches AD Miner: sign-in is off on the copy and BloodHound's Neo4j password is never read.
  assert.match(ps, /'NEO4J_AUTH=none'/);
  assert.doesNotMatch(ps, /NEO4J_SECRET|POSTGRES_PASSWORD/);
  assert.match(ps, /'-u', 'neo4j', '-p', 'not-needed'/);
  // Nothing here talks to Active Directory.
  assert.doesNotMatch(ps, /bloodhound-ce-python|bhcollector|ldap|Import-Clixml|Get-Credential|pingcastle/i);
  // Limits, repeatable output, never a pull from a registry, least privilege.
  for (const s of ["'--entrypoint', 'timeout'", "'PYTHONHASHSEED=0'", "'PYTHONUNBUFFERED=1'", "'--pull', 'never'", "'--cap-drop', 'ALL'", "'no-new-privileges'", "'--memory'", "'--user', '7474:7474'", "'--init'"])
    assert.ok(ps.includes(s), s);
  // BloodHound is started again and everything the run made is removed, whatever happened.
  assert.match(ps, /finally \{\s+Invoke-Docker @\('start', \$graphDb\)/);
  assert.match(ps, /finally \{\s+# Nothing of the run is left behind[^\n]*\n\s+foreach \(\$c in \$runner, \$copyDb\) \{ Invoke-Docker @\('rm', '-f', '-v', \$c\)/);
  assert.match(ps, /foreach \(\$v in \$dataVolume, \$reportVolume\) \{ Invoke-Docker @\('volume', 'rm', \$v\)/);
  // Windows PowerShell 5.1: docker only through the helper that survives stderr, and no argument with a double quote.
  assert.doesNotMatch(ps.replace(/function Invoke-Docker \{[^]*?\n\}/, ''), /& docker /, 'every docker call goes through Invoke-Docker');
  assert.doesNotMatch(ps, /'sh', '-c'|\{\{[^}\n]*"[^}\n]*\}\}/, 'no shell one-liner and no Go template with a double quote in it: 5.1 would mangle both');
  const docker = readFileSync(new URL('../tools/bloodhound/adminer/Dockerfile', import.meta.url), 'utf8');
  assert.match(docker, /ARG ADMINER_COMMIT=[0-9a-f]{40}\r?\n/, 'AD Miner is pinned to a commit');
  assert.match(docker, /-c \/tmp\/constraints\.txt/);
  assert.match(docker, /diff \/tmp\/pinned\.txt \/tmp\/installed\.txt/, 'the build fails when what was installed is not what is pinned');
  assert.match(docker, /USER adminer/);
  const pins = readFileSync(new URL('../tools/bloodhound/adminer/constraints.txt', import.meta.url), 'utf8').split(/\r?\n/).filter(l => l && !l.startsWith('#'));
  assert.ok(pins.length >= 9 && pins.every(l => /^[a-z0-9-]+==[0-9][0-9a-z.]*$/.test(l)), 'every dependency has an exact version');
});

test('scan script: read-only collector, password never on a command line, summary schema matches', () => {
  const ps = readFileSync(new URL('../tools/bloodhound/Invoke-BloodHoundScan.ps1', import.meta.url), 'utf8');
  assert.match(ps, /schema\s+= 'hm360\.attackpaths\/1'/);
  assert.match(ps, /'-e', 'HM360_BH_PW'/, 'password passed by environment variable name only');
  assert.match(ps, /exec bloodhound-ce-python -p "\$HM360_BH_PW"/);
  assert.match(ps, /docker rm -f \$container/, 'collector container is always removed');
  assert.doesNotMatch(ps, /bhe_enable_cypher_mutations|MERGE |CREATE |DELETE |SET /, 'queries only read the graph');
  for (const id of Object.keys(FINDINGS)) assert.ok(ps.includes(`'${id}'`), id);
  const docker = readFileSync(new URL('../tools/bloodhound/collector/Dockerfile', import.meta.url), 'utf8');
  assert.match(docker, /bloodhound-ce==1\.9\.1/);
  assert.match(docker, /USER collector/);
});
