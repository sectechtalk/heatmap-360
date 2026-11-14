import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PROVIDERS, readAzure, readAws, readGoogle, readStatuspage, createServiceHealth } from '../server/services.mjs';

const P = id => PROVIDERS.find(p => p.id === id);
const NOW = Date.parse('2026-11-12T20:00:00Z');

test('Azure RSS: every item is an active incident; links stay on Microsoft sites', () => {
  const xml = `<rss><channel><title>Azure Status</title>
    <item><title>Virtual Machines - West US 3 - Degraded</title><link>https://azure.status.microsoft/en-us/status/history/</link><pubDate>Thu, 12 Nov 2026 18:00:00 GMT</pubDate><description><![CDATA[<p>Customers may see <b>errors</b>.</p>]]></description></item>
    <item><title>Other</title><link>https://evil.example/</link><pubDate>Thu, 12 Nov 2026 18:30:00 GMT</pubDate></item></channel></rss>`;
  const r = readAzure(xml, P('azure'));
  assert.equal(r.grade, 'warn');
  assert.equal(r.incidents[0].detail, 'Customers may see errors.');
  assert.equal(r.incidents[1].link, P('azure').page, 'outside link replaced by the status page');
  assert.equal(readAzure('<rss><channel></channel></rss>', P('azure')).grade, 'ok');
});

test('AWS RSS: newest post per service in the last 24 hours; resolved posts close it', () => {
  const item = (title, guid, date) => `<item><title>${title}</title><guid>${guid}</guid><pubDate>${date}</pubDate><description>x</description></item>`;
  const xml = `<rss><channel>
    ${item('Increased Error Rates', 'https://status.aws.amazon.com/#ec2-us-east-1_1', 'Thu, 12 Nov 2026 15:00:00 GMT')}
    ${item('Service is operating normally: [RESOLVED] Increased Error Rates', 'https://status.aws.amazon.com/#ec2-us-east-1_2', 'Thu, 12 Nov 2026 17:00:00 GMT')}
    ${item('Informational message: Delayed metrics', 'https://status.aws.amazon.com/#cloudwatch-us-west-2_3', 'Thu, 12 Nov 2026 19:00:00 GMT')}
    ${item('Old outage', 'https://status.aws.amazon.com/#s3-us-east-1_4', 'Mon, 09 Nov 2026 10:00:00 GMT')}
  </channel></rss>`;
  const r = readAws(xml, P('aws'), NOW);
  assert.deepEqual(r.incidents.map(i => i.title), ['Informational message: Delayed metrics']);
  assert.equal(r.grade, 'info');
});

test('Google incidents.json: open incidents only, graded by impact', () => {
  const r = readGoogle([
    { external_desc: 'BigQuery errors', begin: '2026-11-12T10:00:00Z', status_impact: 'SERVICE_OUTAGE', uri: 'incidents/abc123', most_recent_update: { text: 'Mitigation in progress' }, affected_products: [{ title: 'BigQuery' }] },
    { external_desc: 'Old', begin: '2026-11-01T10:00:00Z', end: '2026-11-01T12:00:00Z', status_impact: 'SERVICE_OUTAGE', uri: 'incidents/old' },
  ], P('gcp'));
  assert.equal(r.grade, 'bad');
  assert.equal(r.incidents.length, 1);
  assert.equal(r.incidents[0].link, 'https://status.cloud.google.com/incidents/abc123');
  assert.deepEqual(r.incidents[0].products, ['BigQuery']);
  assert.throws(() => readGoogle({}, P('gcp')), /format/);
});

test('Statuspage summary: indicator, unresolved incidents and maintenance in progress', () => {
  const r = readStatuspage({ status: { indicator: 'minor', description: 'Minor Service Outage' },
    incidents: [{ name: 'Actions delayed', status: 'investigating', impact: 'minor', created_at: '2026-11-12T19:00:00Z', shortlink: 'https://stspg.io/abc' }, { name: 'Done', status: 'resolved' }],
    scheduled_maintenances: [{ name: 'DB upgrade', status: 'in_progress', shortlink: 'https://evil.example/' }] }, P('github'));
  assert.equal(r.grade, 'warn');
  assert.equal(r.summary, 'Minor Service Outage');
  assert.deepEqual(r.incidents.map(i => [i.title, i.impact]), [['Actions delayed', 'warn'], ['DB upgrade', 'info']]);
  assert.equal(r.incidents[1].link, P('github').page);
});

test('service health: each feed is independent, cached for 5 minutes, Microsoft 365 marked not connected', async () => {
  let calls = 0, t = NOW;
  const fetchImpl = async url => {
    calls++;
    if (url.includes('githubstatus')) return Response.json({ status: { indicator: 'none', description: 'All Systems Operational' }, incidents: [] });
    if (url.includes('cloudflarestatus')) throw new Error('getaddrinfo ENOTFOUND');
    if (url.includes('incidents.json')) return Response.json([]);
    if (url.includes('aws')) return new Response('nope', { status: 503 });
    return new Response('<rss><channel></channel></rss>');
  };
  const get = createServiceHealth({ fetchImpl, now: () => t });
  const r = await get();
  const by = Object.fromEntries(r.providers.map(p => [p.id, p]));
  assert.equal(by.github.grade, 'ok');
  assert.equal(by.azure.grade, 'ok');
  assert.equal(by.gcp.grade, 'ok');
  assert.equal(by.cloudflare.grade, 'unknown');
  assert.match(by.cloudflare.error, /ENOTFOUND/);
  assert.match(by.aws.error, /HTTP 503/);
  assert.equal(by.m365.summary, 'Not connected');
  assert.equal(calls, 6);
  await get(); assert.equal(calls, 6, 'cached');
  t += 301_000; await get(); assert.equal(calls, 12, 'refreshed after 5 minutes');
});

test('Microsoft 365 via Graph: managed identity token, open issues graded, missing permission is "Not connected"', async () => {
  const issues = { value: [
    { id: 'EX1001', service: 'Exchange Online', feature: 'E-Mail and calendar access', title: 'Users cannot send mail', classification: 'incident', status: 'serviceInterruption', isResolved: false, startDateTime: '2026-11-12T18:00:00Z', impactDescription: 'Users may be unable to send email.' },
    { id: 'TM2002', service: 'Microsoft Teams', title: 'Delayed chat messages', classification: 'advisory', status: 'serviceDegradation', isResolved: false },
    { id: 'SP3003', service: 'SharePoint Online', title: 'Old', classification: 'incident', status: 'serviceRestored', isResolved: true },
  ] };
  const seen = [];
  const only = PROVIDERS.filter(p => p.id === 'm365');
  const get = createServiceHealth({ providers: only, graphToken: async res => { assert.equal(res, 'https://graph.microsoft.com'); return 'tok'; },
    fetchImpl: async (url, init) => { seen.push([url, init.headers.authorization]); return Response.json(issues); } });
  const [m] = (await get()).providers;
  assert.equal(m.grade, 'bad');
  assert.equal(m.summary, '1 active incident, 1 advisory');
  assert.deepEqual(m.incidents.map(i => [i.title, i.impact]), [['Exchange Online: Users cannot send mail', 'bad'], ['Microsoft Teams: Delayed chat messages', 'info']]);
  assert.match(seen[0][0], /^https:\/\/graph\.microsoft\.com\/v1\.0\/admin\/serviceAnnouncement\/issues\?\$filter=isResolved%20eq%20false/);
  assert.equal(seen[0][1], 'Bearer tok');

  const denied = createServiceHealth({ providers: only, graphToken: async () => 'tok', fetchImpl: async () => new Response('{}', { status: 403 }) });
  const [d] = (await denied()).providers;
  assert.equal(d.summary, 'Not connected');
  assert.match(d.note, /ServiceHealth\.Read\.All/);
  const tokenFails = createServiceHealth({ providers: only, graphToken: async () => { throw new Error('Managed identity token failed: HTTP 400'); }, fetchImpl: async () => assert.fail('no call') });
  assert.match((await tokenFails()).providers[0].error, /HTTP 400/);
});
