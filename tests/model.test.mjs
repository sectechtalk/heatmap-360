import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildMachines, healthChecks, kevCandidates, softwareMatches } from '../server/model.mjs';

const kev = JSON.parse(readFileSync(new URL('./fixtures/kev.sample.json', import.meta.url)));
const pc = JSON.parse(readFileSync(new URL('./fixtures/windows-PC01.json', import.meta.url)));
const NOW = Date.parse('2026-11-01T18:00:00Z');
const status = (checks, id) => checks.find(c => c.id === id)?.status;

test('health checks grade each signal', () => {
  const c = healthChecks(pc, NOW);
  assert.equal(status(c, 'fresh'), 'ok');
  assert.equal(status(c, 'uptime'), 'warn');      // ~21 days
  assert.equal(status(c, 'reboot'), 'warn');
  assert.equal(status(c, 'patch'), 'ok');         // 31 days
  assert.equal(status(c, 'av'), 'ok');
  assert.equal(status(c, 'bitlocker'), 'ok');
  assert.equal(status(c, 'firewall'), 'bad');     // public profile off
  assert.equal(status(c, 'disk:C:'), 'warn');     // 8% free
});

test('missing signals are unknown, not ok', () => {
  const c = healthChecks({ host: 'X', collectedAt: '2026-10-01T00:00:00Z' }, NOW);
  assert.equal(status(c, 'fresh'), 'bad');
  assert.equal(status(c, 'av'), 'unknown');
  assert.equal(status(c, 'bitlocker'), 'unknown');
  assert.equal(status(c, 'patch'), 'unknown');
});

test('KEV candidates: software by vendor+product, Windows by patch date', () => {
  const ids = kevCandidates(pc, kev).map(c => c.cveID);
  assert.ok(ids.includes('CVE-2000-0001'), 'Chromium V8 -> Google Chrome');
  assert.ok(ids.includes('CVE-2000-0002'), 'Acrobat and Reader -> Adobe Acrobat');
  assert.ok(ids.includes('CVE-2000-0004'), 'Win32k added after the newest update');
  assert.ok(!ids.includes('CVE-2000-0003'), 'Windows entry older than the newest update');
  assert.ok(!ids.includes('CVE-2000-0005'), 'FortiOS is not installed');
  assert.equal(kevCandidates(pc, kev)[0].cveID, 'CVE-2000-0002', 'ransomware-linked first');
});

test('matching needs the vendor too', () => {
  assert.equal(softwareMatches({ vendorProject: 'Adobe', product: 'Acrobat' }, { name: 'Acrobat Clone', publisher: 'Other Co' }), false);
  assert.equal(softwareMatches({ vendorProject: 'Microsoft', product: 'Office' }, { name: 'Microsoft 365 Apps for business' }), true);
});

test('heat scores and ordering', () => {
  const quiet = { ...pc, host: 'PC02', uptimeHours: 5, pendingReboot: false, firewall: { domain: true, private: true, public: true },
    disks: [{ drive: 'C:', sizeGB: 100, freeGB: 60 }], software: [], hotfixes: [{ id: 'KB1', installedOn: '2026-10-30' }] };
  const { machines, feeds } = buildMachines([quiet, pc], { kev }, NOW);
  assert.deepEqual(machines.map(m => m.host), ['PC01', 'PC02']);
  assert.equal(machines[1].heat.overall, 0);
  assert.ok(machines[0].heat.exposure >= 40);
  assert.equal(feeds.kevCount, 5);
});
