import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { eventLogChecks, networkChecks } from '../bot/machine.mjs';
import { firmwareStatus, parseHpReference, parseLenovoCatalog, parseLenovoPackage, installedBiosVersion, findVendor } from '../bot/firmware.mjs';
import { createSources } from '../bot/run.mjs';
import { checkInventory } from '../server/schema.mjs';

const fx = n => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const inv = JSON.parse(fx('inventory.sample.json'));
const NOW = Date.parse('2026-11-12T20:00:00Z');
const withHw = (hw, os = inv.os) => ({ ...inv, os, hardware: { ...inv.hardware, ...hw } });

test('event log: groups events into plain-language findings and ignores known noise', () => {
  const r = eventLogChecks(inv);
  assert.equal(r.status, 'checked');
  const by = Object.fromEntries(r.findings.map(f => [f.id, f]));
  assert.equal(by.unexpected.count, 4, 'Kernel-Power 41 and EventLog 6008 together');
  assert.equal(by.unexpected.status, 'bad');
  assert.equal(by.whea.status, 'info', 'a few corrected hardware errors are informational');
  assert.equal(by.appcrash.status, 'info');
  assert.equal(by.services.count, 1);
  assert.equal(r.grade, 'bad');
  assert.deepEqual(r.other.map(e => e.provider), ['Example Agent']);
  assert.equal(r.noiseCount, 40, 'DCOM 10016 is counted but never graded');
  assert.match(r.reason, /Unexpected restarts or power loss \(4\)/);
});

test('event log: clean, uncorrected hardware errors, and older scanners', () => {
  assert.equal(eventLogChecks({ eventLog: { days: 7, entries: [] } }).grade, 'ok');
  const whea = eventLogChecks({ eventLog: { days: 7, entries: [{ log: 'System', provider: 'Microsoft-Windows-WHEA-Logger', eventId: 18, level: 'error', count: 1 }] } });
  assert.equal(whea.grade, 'bad');
  const disk = eventLogChecks({ eventLog: { days: 7, entries: [{ log: 'System', provider: 'disk', eventId: 7, level: 'error', count: 1 }] } });
  assert.equal(disk.findings[0].id, 'storage');
  assert.equal(eventLogChecks({}).status, 'unknown');
});

test('network: slow gigabit link, old driver, Wi-Fi signal; disconnected adapters are not graded', () => {
  const r = networkChecks(inv, NOW);
  assert.equal(r.status, 'checked');
  const [eth, wlan, usb] = r.adapters;
  assert.deepEqual(eth.findings.map(f => [f.status, f.label]), [
    ['warn', 'Link speed 100 Mbps'], ['info', 'Energy Efficient Ethernet on'], ['info', 'Windows may turn this adapter off to save power'], ['warn', 'Old driver']]);
  assert.equal(eth.grade, 'warn');
  assert.equal(wlan.findings.length, 0, 'Wi-Fi link speed and power saving are not graded');
  assert.equal(usb.connected, false);
  assert.equal(usb.findings.length, 0);
  assert.equal(r.wifi.findings[0].status, 'warn');
  assert.equal(r.grade, 'warn');
  assert.match(r.reason, /Link speed 100 Mbps; Old driver; Fair Wi-Fi signal/);
});

test('network: half duplex is bad, weak signal is bad, older scanners are unknown', () => {
  const r = networkChecks({ network: { adapters: [{ description: 'X Ethernet', mediaType: '802.3', status: 'Up', linkSpeedMbps: 1000, fullDuplex: false, settings: [] }], wifi: { signalPercent: 30, radioType: '802.11n' } } }, NOW);
  assert.equal(r.adapters[0].findings[0].label, 'Half duplex');
  assert.equal(r.wifi.grade, 'bad');
  assert.equal(r.wifi.findings[1].label, 'Older Wi-Fi standard (802.11n)');
  assert.equal(networkChecks({}).status, 'unknown');
  assert.equal(networkChecks({ network: { adapters: [] } }).grade, 'unknown');
});

test('schema: new sections validate; MAC-like settings keywords and unknown fields are rejected', () => {
  assert.equal(checkInventory(inv).ok, true);
  const bad = structuredClone(inv);
  bad.network.adapters[0].settings.push({ keyword: 'Network Address', name: 'x', value: 'y' });
  assert.equal(checkInventory(bad).ok, false);
  const extra = structuredClone(inv);
  extra.network.adapters[0].macAddress = '00-11-22-33-44-55';
  assert.equal(checkInventory(extra).ok, false);
  const msg = structuredClone(inv);
  msg.eventLog.entries[0].message = 'text';
  assert.equal(checkInventory(msg).ok, false, 'event message text is never accepted');
});

test('HP and Lenovo catalog readers', () => {
  const hp = parseHpReference(fx('hp-reference.xml'));
  assert.deepEqual(hp.map(u => u.version), ['01.18.00', '01.21.00'], 'BIOS entries only');
  const lc = parseLenovoCatalog(fx('lenovo-catalog.xml'));
  assert.deepEqual(lc.map(p => p.location), ['https://download.lenovo.com/pccbbs/mobiles/x1bb02w_2_.xml'], 'BIOS only, Lenovo host only');
  assert.deepEqual(parseLenovoPackage(fx('lenovo-package.xml')), { version: '1.70', name: 'BIOS Update for Windows 11 (64-bit) - Example ThinkPad', date: '2026-07-01' });
  assert.equal(installedBiosVersion('lenovo', 'X1ET62W (1.62 )'), '1.62');
  assert.equal(installedBiosVersion('hp', 'T70 Ver. 01.18.00'), '01.18.00');
  assert.equal(findVendor('Hewlett-Packard').key, 'hp');
  assert.equal(findVendor('Micro-Star International Co., Ltd.').key, 'msi');
});

test('firmware: HP update found by version, URL built only from a valid platform ID', async () => {
  const urls = [];
  const get = async url => { urls.push(url); return fx('hp-reference.xml'); };
  const hp = withHw({ system: { manufacturer: 'HP', model: 'Example Laptop' }, baseboard: { manufacturer: 'HP', product: '8a5b' }, bios: { vendor: 'HP', version: 'T70 Ver. 01.18.00', releaseDate: '2026-03-02' } });
  const r = await firmwareStatus(hp, get, NOW);
  assert.equal(r.status, 'update');
  assert.equal(r.grade, 'warn');
  assert.equal(r.latest.version, '01.21.00');
  assert.equal(r.latest.link, 'https://ftp.hp.com/pub/softpaq/sp100001-100500/sp100003.html');
  assert.deepEqual(urls, ['https://hpia.hpcloud.hp.com/ref/8A5B/8A5B_64_11.0.24h2.xml']);
  const current = await firmwareStatus(withHw({ ...hp.hardware, bios: { version: 'T70 Ver. 01.21.00', releaseDate: '2026-09-01' } }), get, NOW);
  assert.equal(current.status, 'current');
  const evil = await firmwareStatus(withHw({ ...hp.hardware, baseboard: { manufacturer: 'HP', product: '../../x' } }), async () => assert.fail('no fetch'), NOW);
  assert.equal(evil.status, 'not-checked');
});

test('firmware: HP with no catalog says why (consumer model vs. missing Windows version)', async () => {
  const bios = { vendor: 'AMI', version: 'F.49', releaseDate: '2026-06-14' };
  const envy = await firmwareStatus(withHw({ system: { manufacturer: 'HP', model: 'HP ENVY Desktop Example', family: 'HP ENVY' }, baseboard: { manufacturer: 'HP', product: '894b' }, bios }), async () => null, NOW);
  assert.equal(envy.status, 'not-checked');
  assert.match(envy.reason, /business models only; consumer models/);
  assert.doesNotMatch(envy.reason, /Windows 11/);
  const biz = await firmwareStatus(withHw({ system: { manufacturer: 'HP', model: 'Example Laptop' }, baseboard: { manufacturer: 'HP', product: '8a5b' }, bios }), async () => null, NOW);
  assert.match(biz.reason, /no entry for platform 8A5B on Windows 11 24H2/);
});

test('firmware: Lenovo via catalog then package; falls back to Windows 10 catalog', async () => {
  const urls = [];
  const get = async url => {
    urls.push(url);
    if (url.endsWith('_Win11.xml')) return null;
    if (url.endsWith('_Win10.xml')) return fx('lenovo-catalog.xml');
    return fx('lenovo-package.xml');
  };
  const len = withHw({ system: { manufacturer: 'LENOVO', model: '21AB00XXUS' }, bios: { vendor: 'LENOVO', version: 'X1ET62W (1.62 )', releaseDate: '2026-01-10' } });
  const r = await firmwareStatus(len, get, NOW);
  assert.equal(r.status, 'update');
  assert.equal(r.comparedBy, 'version');
  assert.deepEqual(urls, ['https://download.lenovo.com/catalog/21AB_Win11.xml', 'https://download.lenovo.com/catalog/21AB_Win10.xml', 'https://download.lenovo.com/pccbbs/mobiles/x1bb02w_2_.xml']);
});

test('firmware: other makers get age and a support link; failures and VMs are graceful', async () => {
  const dell = await firmwareStatus(withHw({ system: { manufacturer: 'Dell Inc.', model: 'Example 7000' }, bios: { version: '1.2.3', releaseDate: '2021-01-01' } }), null, NOW);
  assert.equal(dell.status, 'not-checked');
  assert.equal(dell.grade, 'warn', 'over 3 years old');
  assert.equal(dell.support, 'https://www.dell.com/support/home');
  const custom = await firmwareStatus(withHw({ system: { manufacturer: 'System manufacturer', model: 'System Product Name' }, baseboard: { manufacturer: 'ASUSTeK COMPUTER INC.', product: 'EXAMPLE-B650' }, bios: { version: '1801', releaseDate: '2026-01-01' } }), null, NOW);
  assert.equal(custom.vendor, 'ASUS');
  assert.equal(custom.grade, 'unknown');
  const down = await firmwareStatus(withHw({ system: { manufacturer: 'HP' }, baseboard: { product: '8A5B' }, bios: { version: 'T70 Ver. 01.18.00' } }), async () => { throw new Error('HTTP 503'); }, NOW);
  assert.match(down.reason, /HP catalog: HTTP 503/);
  const vm = await firmwareStatus(withHw({ system: { manufacturer: 'Microsoft Corporation', model: 'Virtual Machine' } }), null, NOW);
  assert.equal(vm.status, 'virtual');
});

test('bot sources fetch vendor files only from the allowed hosts', async () => {
  const seen = [];
  const s = createSources({ cacheDir: '/nonexistent', fetchImpl: async url => { seen.push(url); return new Response('missing', { status: 404 }); } });
  assert.equal(await s.vendorFile('https://download.lenovo.com/catalog/21AB_Win11.xml'), null);
  await assert.rejects(s.vendorFile('https://evil.example/x.xml'), /not an allowed vendor source/);
  await assert.rejects(s.vendorFile('http://download.lenovo.com/x.xml'), /not an allowed/);
  assert.deepEqual(seen, ['https://download.lenovo.com/catalog/21AB_Win11.xml']);
});
