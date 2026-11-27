// The inventory catalog's newer sources (approved 2026-11-27): Dell's .cab catalogs, NVD, the MSRC Security Update
// Guide and the Windows Update driver offers the scanner reports. No network: every source is faked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { cabFirstFile, decodeXml } from '../bot/cab.mjs';
import { nameTokens, scoreProduct, rankProducts, cveList, createNvd, matchProduct, productKey, searchWords } from '../bot/nvd.mjs';
import { openCves, windowsProductName, monthId } from '../bot/msrc.mjs';
import { firmwareStatus, dellModelPath, parseDellBios, DELL_INDEX } from '../bot/firmware.mjs';
import { memoryStore, importResult, runLookups, machineItems, offerFor } from '../bot/findings.mjs';
import { isCatalogRow, isHistoryRow } from '../bot/catalog.mjs';
import { checkInventory } from '../server/schema.mjs';

// A cabinet with one MSZIP folder of two blocks; the second block refers back to the first (as Dell's do).
function makeCab(text, name = 'Catalog.xml') {
  const data = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
  const half = Math.floor(data.length / 2);
  const blocks = [data.subarray(0, half), data.subarray(half)];
  const comp = [Buffer.concat([Buffer.from('CK'), deflateRawSync(blocks[0])]), Buffer.concat([Buffer.from('CK'), deflateRawSync(blocks[1], { dictionary: blocks[0] })])];
  const fileEntry = Buffer.concat([Buffer.alloc(16), Buffer.from(`${name}\0`, 'latin1')]);
  fileEntry.writeUInt32LE(data.length, 0); fileEntry.writeUInt32LE(0, 4); fileEntry.writeUInt16LE(0, 8);
  const coffFiles = 36 + 8, coffCabStart = coffFiles + fileEntry.length;
  const header = Buffer.alloc(36); header.write('MSCF', 0, 'latin1'); header.writeUInt32LE(coffFiles, 16); header.writeUInt16LE(1, 26); header.writeUInt16LE(1, 28); header.writeUInt16LE(0, 30);
  const folder = Buffer.alloc(8); folder.writeUInt32LE(coffCabStart, 0); folder.writeUInt16LE(2, 4); folder.writeUInt16LE(1, 6);
  const cfdata = comp.map((c, i) => { const h = Buffer.alloc(8); h.writeUInt16LE(c.length, 4); h.writeUInt16LE(blocks[i].length, 6); return Buffer.concat([h, c]); });
  const cab = Buffer.concat([header, folder, fileEntry, ...cfdata]);
  cab.writeUInt32LE(cab.length, 8);
  return cab;
}

test('cab: the first file of an MSZIP cabinet, UTF-16 decoded; other files refused', () => {
  const xml = `<?xml version="1.0" encoding="utf-16"?><Manifest>${'<SoftwareComponent vendorVersion="1.2.3"/>'.repeat(500)}</Manifest>`;
  assert.equal(decodeXml(cabFirstFile(makeCab(xml))), xml);
  assert.throws(() => cabFirstFile(Buffer.from('PK\x03\x04 not a cab at all, just some bytes......')), /not a cabinet/);
});

test('Dell: catalog index -> model catalog -> newest BIOS for the system ID', async () => {
  const index = '<ManifestIndex><GroupManifest><SupportedSystems><Brand><Model systemID="0A1B" systemIDType="BIOS"></Model></Brand></SupportedSystems><ManifestInformation id="x" path="FOLDER123M/1/Latitude_0A1B.cab" size="1"><Display/></ManifestInformation></GroupManifest></ManifestIndex>';
  const comp = (v, d) => `<SoftwareComponent releaseID="AB12C" releaseDate="${d}" vendorVersion="${v}"><Name><Display lang="en"><![CDATA[Dell Latitude 5440 System BIOS]]></Display></Name><ComponentType value="BIOS"><Display/></ComponentType><SupportedSystems><Brand><Model systemID="0A1B"/></Brand></SupportedSystems></SoftwareComponent>`;
  const model = `<Manifest>${comp('1.18.0', 'March 01, 2026')}${comp('1.21.1', 'October 02, 2026')}<SoftwareComponent vendorVersion="9.9"><ComponentType value="DRVR"/><Model systemID="0A1B"/></SoftwareComponent></Manifest>`;
  assert.equal(dellModelPath(index, '0A1B'), 'FOLDER123M/1/Latitude_0A1B.cab');
  assert.equal(dellModelPath(index, 'FFFF'), null);
  assert.deepEqual(parseDellBios(model, '0A1B').map(b => b.version), ['1.18.0', '1.21.1']);
  const asked = [];
  const get = async url => { asked.push(url); return url === DELL_INDEX ? index : url === 'https://downloads.dell.com/FOLDER123M/1/Latitude_0A1B.cab' ? model : null; };
  const inv = { hardware: { bios: { vendor: 'Dell Inc.', version: '1.18.0', releaseDate: '2026-03-01' }, system: { manufacturer: 'Dell Inc.', model: 'Latitude 5440', sku: '0A1B' } } };
  const f = await firmwareStatus(inv, get, Date.parse('2026-11-27'));
  assert.equal(f.status, 'update');
  assert.equal(f.latest.version, '1.21.1');
  assert.match(f.latest.link, /driverid=ab12c/);
  assert.equal(asked.length, 2);
  const noSku = await firmwareStatus({ hardware: { ...inv.hardware, system: { manufacturer: 'Dell Inc.', model: 'Latitude 5440' } } }, get, Date.parse('2026-11-27'));
  assert.equal(noSku.status, 'not-checked');
  assert.match(noSku.reason, /system ID/);
});

test('NVD product match: strong only when every product word and the vendor match; weaker ones are proposed', () => {
  assert.deepEqual(nameTokens('Intel(R) Wi-Fi 6 AX201 160MHz (64-bit) 23.1.0'), ['intel', 'wi-fi', '6', 'ax201', '160mhz']);
  assert.equal(searchWords('7-Zip 23.01 (x64)'), '7-zip');
  assert.equal(scoreProduct({ name: '7-Zip 23.01 (x64)', vendor: 'Igor Pavlov' }, '7-zip', '7-zip').strength, 'strong');
  assert.equal(scoreProduct({ name: 'Google Chrome', vendor: 'Google LLC' }, 'google', 'chrome').strength, 'strong');
  assert.equal(scoreProduct({ name: 'Chrome Remote Desktop Host', vendor: 'Google LLC' }, 'google', 'chrome').strength, 'proposed', 'a different Google product is not matched on its own');
  assert.equal(scoreProduct({ name: 'Notepad++', vendor: 'Notepad++ Team' }, 'microsoft', 'notepad').strength, 'none');
  const ranked = rankProducts({ name: 'Google Chrome', vendor: 'Google LLC' }, [{ part: 'a', vendor: 'google', product: 'chrome_remote_desktop' }, { part: 'a', vendor: 'google', product: 'chrome' }, { part: 'a', vendor: 'google', product: 'chrome' }]);
  assert.equal(ranked[0].product, 'chrome');
  assert.equal(ranked.length, 1, 'duplicates collapse; non-matches drop');
});

test('NVD client: spaced requests, exact-version CVE query, rate-limit retry, confirmed choices win', async () => {
  const urls = [], sleeps = [];
  let t = 0, fail = 1;
  const fetchImpl = async url => {
    urls.push(url);
    if (url.includes('cves/2.0') && fail-- > 0) return new Response('', { status: 503 });
    if (url.includes('cpes/2.0')) return Response.json({ products: [{ cpe: { cpeName: 'cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*', titles: [{ lang: 'en', title: '7-Zip 23.01' }] } }, { cpe: { cpeName: 'cpe:2.3:a:7-zip:7-zip:24.07:*:*:*:*:*:*:*', deprecated: true } }] });
    return Response.json({ totalResults: 1, vulnerabilities: [{ cve: { id: 'CVE-2025-0411', published: '2025-01-25T05:15:09', cisaExploitAdd: '2025-02-06', descriptions: [{ lang: 'en', value: 'Mark-of-the-Web bypass' }],
      metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 7, baseSeverity: 'HIGH' } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*', versionEndExcluding: '24.09' }] }] }] } }] });
  };
  const nvd = createNvd({ fetchImpl, now: () => t, sleep: async ms => { sleeps.push(ms); t += ms; } });
  const item = { kind: 'app', name: '7-Zip 23.01 (x64)', vendor: 'Igor Pavlov' };
  const m = await matchProduct(item, nvd);
  assert.deepEqual([m.status, m.vendor, m.product], ['strong', '7-zip', '7-zip']);
  const cves = await nvd.cves(m, '23.01');
  assert.deepEqual(cves.map(c => [c.cve, c.score, c.kev, c.fixedIn]), [['CVE-2025-0411', 7, true, '24.09']]);
  assert.match(urls.find(u => u.includes('cves/2.0')), /virtualMatchString=cpe%3A2.3%3Aa%3A7-zip%3A7-zip%3A23.01/);
  assert.ok(sleeps.length >= 2, 'requests are spaced and the 503 waited before retrying');
  await assert.rejects(nvd.cves({ part: 'a', vendor: 'x"y', product: 'z' }, '1'), /bad product/);
  const key = productKey('app', item.name, item.vendor);
  assert.equal((await matchProduct(item, nvd, { [key]: null })).status, 'rejected');
  assert.deepEqual(await matchProduct(item, nvd, { [key]: 'a:igor_pavlov:7zip' }).then(x => [x.status, x.vendor, x.product]), ['confirmed', 'igor_pavlov', '7zip']);
  assert.equal(cveList({ vulnerabilities: [{ cve: { id: 'CVE-1', vulnStatus: 'Rejected' } }] }, 'a', 'b').length, 0, 'rejected CVEs are dropped');
});

test('MSRC: CVEs fixed in a later build of the same Windows version are open; fixed or other lines are not', () => {
  assert.equal(windowsProductName({ build: 26100, displayVersion: '24H2', architecture: '64-bit' }), 'Windows 11 Version 24H2 for x64-based Systems');
  assert.equal(windowsProductName({ build: 19045, displayVersion: '22H2', architecture: 'ARM 64-bit Processor' }), 'Windows 10 Version 22H2 for ARM64-based Systems');
  assert.equal(monthId('2026-11-11T00:00:00Z'), '2026-Nov');
  const doc = { ProductTree: { FullProductName: [{ ProductID: '12390', Value: 'Windows 11 Version 24H2 for x64-based Systems' }] }, Vulnerability: [
    { CVE: 'CVE-2026-1', Title: { Value: 'Kernel EoP' }, ProductStatuses: [{ Type: 3, ProductID: ['12390'] }], CVSSScoreSets: [{ BaseScore: 7.8, ProductID: ['12390'] }],
      Threats: [{ Type: 1, Description: { Value: 'Publicly Disclosed:No;Exploited:Yes' }, ProductID: ['12390'] }, { Type: 3, Description: { Value: 'Important' }, ProductID: ['12390'] }],
      Remediations: [{ Type: 2, FixedBuild: '10.0.26100.9974', Description: { Value: '5132061' }, ProductID: ['12390'] }] },
    { CVE: 'CVE-2026-2', ProductStatuses: [{ Type: 3, ProductID: ['12390'] }], Remediations: [{ Type: 2, FixedBuild: '10.0.26100.4000', ProductID: ['12390'] }] },
    { CVE: 'CVE-2026-3', ProductStatuses: [{ Type: 3, ProductID: ['99999'] }], Remediations: [{ Type: 2, FixedBuild: '10.0.26100.9999', ProductID: ['99999'] }] } ] };
  const open = openCves(doc, 'Windows 11 Version 24H2 for x64-based Systems', '10.0.26100.6000');
  assert.deepEqual(open.map(c => [c.cve, c.kev, c.kb, c.severity, c.score]), [['CVE-2026-1', true, 'KB5132061', 'Important', 7.8]]);
});

test('scanner 1.4.0 fields: Dell system ID and Windows Update driver offers pass the upload schema', () => {
  const inv = JSON.parse(readFileSync(new URL('./fixtures/inventory.sample.json', import.meta.url), 'utf8'));
  const ok = checkInventory({ ...inv, clientVersion: '1.4.0', hardware: { ...inv.hardware, system: { ...inv.hardware.system, sku: '0A1B' } },
    driverUpdates: { checked: true, updates: [{ title: 'Intel - Net - 23.60.1.2', model: 'Intel(R) Wi-Fi 6 AX201 160MHz', manufacturer: 'Intel', provider: 'Intel', class: 'Net', date: '2026-10-01' }] } });
  assert.equal(ok.ok, true, ok.error);
  assert.equal(checkInventory({ ...inv, driverUpdates: { checked: true, updates: [{ title: 'x', command: 'rm -rf' }] } }).ok, false, 'unknown fields are refused');
});

test('drivers: a Windows Update offer marks that driver version outdated once, for every machine on it; NVD CVEs are added', async () => {
  const inv = JSON.parse(readFileSync(new URL('./fixtures/inventory.sample.json', import.meta.url), 'utf8'));
  const dev = inv.hardware.devices[0];
  assert.deepEqual(offerFor({ name: dev.name, version: dev.driverVersion }, [{ model: dev.name.toUpperCase(), title: `Contoso - Net - 999.0.0.1`, date: '2026-10-01' }]),
    { version: '999.0.0.1', date: '2026-10-01', title: 'Contoso - Net - 999.0.0.1' });
  assert.equal(offerFor({ name: dev.name, version: '999.0.0.1' }, [{ model: dev.name, title: 'Contoso - Net - 1.0.0.0' }]), null, 'older offers are ignored');
  const result = (id, machineId, updates) => ({ schema: 'hm360.result/1', id, receivedAt: '2026-11-12T18:01:00Z', processedAt: '2026-11-12T18:02:00Z',
    inventory: { ...inv, machineId, driverUpdates: { checked: true, updates } } });
  const store = memoryStore();
  await importResult(store, result('20261112180000-abcdef01', inv.machineId, [{ model: dev.name, title: 'Contoso - Net - 999.0.0.1', date: '2026-10-01' }]));
  await importResult(store, result('20261112180000-abcdef02', 'fedcba9876543210', []));
  const cves = [{ cve: 'CVE-2026-0001', score: 8.1, published: '2026-05-01', record: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001' }];
  const nvd = { products: async () => [{ part: 'a', vendor: String(dev.driverProvider || dev.manufacturer).toLowerCase().split(/\W+/)[0], product: nameTokens(dev.name).join('_') }], cves: async () => cves };
  await runLookups(store, { nvd, kev: async () => ({ kev: { vulnerabilities: [] }, epss: {} }), cveRecord: async () => null, vendorFile: async () => null,
    releaseInfo: async () => { throw new Error('offline'); }, knownIssuesPage: async () => '', wingetLatest: async () => null }, { now: () => Date.parse('2026-11-12T20:00:00Z'), limit: 500 });
  const rows = [...store.rows.values()].filter(e => isCatalogRow(e) && e.Kind === 'driver' && e.Name === dev.name);
  assert.equal(rows.length, 1, 'one catalog row for both machines');
  assert.equal(rows[0].LookupStatus, 'outdated');
  assert.equal(rows[0].LatestVersion, '999.0.0.1');
  for (const pk of [inv.machineId, 'fedcba9876543210']) assert.equal((await machineItems(store, pk)).find(e => e.Kind === 'driver' && e.Name === dev.name).LatestVersion, '999.0.0.1');
  assert.equal(rows[0].CpeMatch, 'strong');
  {
    assert.equal(rows[0].Status, 'Vulnerable');
    assert.equal(rows[0].CveCount, 1);
    assert.ok([...store.rows.values()].some(e => isHistoryRow(e) && /CVE/.test(e.Text || '')));
  }
});

test('product choices: confirming a proposed product rechecks its versions with that product', async () => {
  const inv = JSON.parse(readFileSync(new URL('./fixtures/inventory.sample.json', import.meta.url), 'utf8'));
  const store = memoryStore();
  await importResult(store, { schema: 'hm360.result/1', id: '20261112180000-abcdef01', receivedAt: '2026-11-12T18:01:00Z', inventory: { ...inv, apps: [{ name: 'Contoso Remote Helper', version: '2.0', publisher: 'Contoso' }] } });
  const asked = [];
  const nvd = { products: async () => [{ part: 'a', vendor: 'contoso', product: 'helper' }], cves: async (m, v) => { asked.push(`${m.vendor}:${m.product}:${v}`); return []; } };
  const src = { nvd, kev: async () => ({ kev: { vulnerabilities: [] }, epss: {} }), cveRecord: async () => null, vendorFile: async () => null, releaseInfo: async () => { throw new Error('offline'); }, knownIssuesPage: async () => '', wingetLatest: async () => null };
  const T = Date.parse('2026-11-12T20:00:00Z');
  await runLookups(store, src, { now: () => T, limit: 500 });
  const app = () => [...store.rows.values()].find(e => isCatalogRow(e) && e.Kind === 'app' && e.Name === 'Contoso Remote Helper');
  assert.equal(app().CpeMatch, 'proposed');
  assert.equal(asked.length, 0, 'a proposed product is not used for CVEs');
  await runLookups(store, src, { now: () => T + 3_600_000, limit: 500, confirmed: { [app().ProductKey]: 'a:contoso:remote_helper' } });
  assert.equal(app().CpeMatch, 'confirmed');
  assert.deepEqual(asked, ['contoso:remote_helper:2.0']);
  assert.ok([...store.rows.values()].some(e => isHistoryRow(e) && e.Change === 'product'));
});
