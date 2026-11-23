import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { networkHealthChecks } from '../bot/nethealth.mjs';
import { healthChecks } from '../bot/health.mjs';
import { checkInventory } from '../server/schema.mjs';

const inv = JSON.parse(readFileSync(new URL('./fixtures/inventory.sample.json', import.meta.url), 'utf8'));
const NOW = Date.parse('2026-11-12T20:00:00Z');

test('network health: slow, lossy Wi-Fi to the router; speeds graded against plain thresholds', () => {
  const r = networkHealthChecks(inv);
  const by = Object.fromEntries(r.checks.map(c => [c.id, c]));
  assert.equal(by.gateway.status, 'warn');
  assert.match(by.gateway.detail, /38\.5 ms average, 24\.1 ms jitter, 5% lost of 20 pings over Wi-Fi\. .*weak Wi-Fi/);
  assert.equal(by.internet.status, 'ok');
  assert.equal(by.dns.status, 'ok');
  assert.equal(by.download.status, 'ok');
  assert.equal(by.upload.status, 'ok');
  assert.match(by.upload.detail, /below the FCC broadband benchmark of 20 Mbps/);
  assert.equal(r.grade, 'warn');
  assert.equal(r.reason, 'Computer to router (gateway) needs attention.');
});

test('network health: router that ignores ping, skipped speed test, no internet, older scanners', () => {
  const r = networkHealthChecks({ networkHealth: { via: 'wired', gateway: { sent: 20, received: 0, lossPercent: 100 }, internet: { sent: 10, received: 0, lossPercent: 100 }, dns: { ms: 3000, ok: false }, speed: null, speedSkipped: true } });
  const by = Object.fromEntries(r.checks.map(c => [c.id, c]));
  assert.equal(by.gateway.status, 'unknown');
  assert.equal(by.internet.status, 'bad');
  assert.equal(by.dns.status, 'bad');
  assert.match(by.speed.detail, /Skipped/);
  assert.equal(r.grade, 'bad');
  assert.equal(networkHealthChecks({}).status, 'unknown');
  const fast = networkHealthChecks({ networkHealth: { via: 'wired', gateway: { sent: 20, received: 20, lossPercent: 0, avgMs: 0.6, jitterMs: 0.2 }, speed: { downloadMbps: 940, uploadMbps: 930 } } });
  assert.equal(fast.grade, 'ok');
  assert.match(fast.reason, /940 Mbps down, 930 Mbps up/);
});

test('disk and battery health join the health checks', () => {
  const c = Object.fromEntries(healthChecks(inv, NOW).map(x => [x.id, x]));
  assert.equal(c['diskhealth:0'].status, 'warn');
  assert.match(c['diskhealth:0'].detail, /84% of rated life used.*12,034 hours/);
  assert.equal(c.battery.status, 'warn');
  assert.match(c.battery.detail, /72\.8% .* 412 charge cycles/);
  const failing = healthChecks({ hardware: { disks: [{ model: 'Old HDD', health: 'Unhealthy', readErrorsUncorrected: 3 }] } }, NOW).find(x => x.id === 'diskhealth:0');
  assert.equal(failing.status, 'bad');
  assert.match(failing.detail, /unhealthy; 3 uncorrected/);
  assert.equal(healthChecks({ hardware: { disks: [{ model: 'No counters' }] } }, NOW).some(x => x.id.startsWith('diskhealth')), false, 'no data, no check');
});

test('schema accepts network health without addresses and rejects anything extra', () => {
  assert.equal(checkInventory(inv).ok, true);
  const extra = structuredClone(inv);
  extra.networkHealth.gateway.address = '192.0.2.1';
  assert.equal(checkInventory(extra).ok, false);
  const via = structuredClone(inv);
  via.networkHealth.via = 'my-home-network';
  assert.equal(checkInventory(via).ok, false);
});
