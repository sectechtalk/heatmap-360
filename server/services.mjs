// Online service health from each provider's own public status feed. The server reads them (they are public and
// need no credentials), keeps them for 5 minutes, and shows them on the Service health page. Every provider is
// independent: a feed that fails or changes shape shows as "Not checked" with the reason.
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
const decode = s => String(s).replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e) =>
  e[0] === '#' ? String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()] ?? m);
const plain = s => decode(s).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').replace(/\s+([.,;:!?])/g, '$1').trim();
const blocks = (xml, tag) => [...String(xml).matchAll(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'gi'))].map(m => m[1]);
const field = (xml, tag) => { const m = String(xml).match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'i')); return m ? plain(m[1]) : null; };
const iso = s => { const t = Date.parse(s); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const clip = (s, n = 400) => (s && s.length > n ? `${s.slice(0, n - 1)}…` : s ?? null);
// Links shown on the page must point at the provider's own site.
const safeLink = (url, hosts) => { try { const u = new URL(url); return u.protocol === 'https:' && hosts.some(h => u.hostname === h || u.hostname.endsWith(`.${h}`)) ? u.href : null; } catch { return null; } };
const RANK = { ok: 0, info: 1, warn: 2, bad: 3 };

export function parseRss(xml) {
  return blocks(xml, 'item').map(i => ({ title: field(i, 'title'), link: field(i, 'link'), guid: field(i, 'guid'), date: iso(field(i, 'pubDate')), text: clip(field(i, 'description')) }));
}

// Azure's feed lists only incidents that are active now.
export function readAzure(xml, p) {
  const incidents = parseRss(xml).map(i => ({ title: i.title, started: i.date, updated: i.date, impact: 'warn', detail: i.text, link: safeLink(i.link, p.hosts) || p.page }));
  return { grade: incidents.length ? 'warn' : 'ok', summary: incidents.length ? `${incidents.length} active incident${incidents.length > 1 ? 's' : ''}` : 'No active incidents', incidents };
}

// AWS's feed keeps recent history. Each service/region keeps its newest post from the last 24 hours; it is active
// unless that post says the service is operating normally or resolved.
export function readAws(xml, p, now = Date.now()) {
  const latest = new Map();
  for (const i of parseRss(xml)) {
    if (!i.date || now - Date.parse(i.date) > 86_400_000) continue;
    const key = (i.guid || i.title || '').replace(/_\d+$/, '');
    if (!latest.has(key) || latest.get(key).date < i.date) latest.set(key, i);
  }
  const incidents = [...latest.values()].filter(i => !/operating normally|\[resolved\]/i.test(`${i.title} ${i.text}`))
    .map(i => ({ title: i.title, started: i.date, updated: i.date, impact: /informational/i.test(i.title || '') ? 'info' : 'warn', detail: i.text, link: p.page }));
  const grade = incidents.reduce((g, i) => (RANK[i.impact] > RANK[g] ? i.impact : g), 'ok');
  return { grade, summary: incidents.length ? `${incidents.length} active event${incidents.length > 1 ? 's' : ''}` : 'No active events in the last 24 hours', incidents };
}

// Google Cloud and Google Workspace publish the same incidents.json format; an incident without an end is active.
const GOOGLE_IMPACT = { SERVICE_OUTAGE: 'bad', SERVICE_DISRUPTION: 'warn', SERVICE_INFORMATION: 'info' };
export function readGoogle(json, p) {
  if (!Array.isArray(json)) throw new Error('unexpected incidents.json format');
  const incidents = json.filter(i => i && !i.end).map(i => ({
    title: clip(i.external_desc, 200), started: iso(i.begin), updated: iso(i.modified || i.most_recent_update?.when),
    impact: GOOGLE_IMPACT[i.status_impact] || 'warn', detail: clip(i.most_recent_update?.text), products: (i.affected_products || []).map(x => x?.title).filter(Boolean).slice(0, 10),
    link: safeLink(new URL(String(i.uri || ''), p.page).href, p.hosts) || p.page }));
  const grade = incidents.reduce((g, i) => (RANK[i.impact] > RANK[g] ? i.impact : g), 'ok');
  return { grade, summary: incidents.length ? `${incidents.length} active incident${incidents.length > 1 ? 's' : ''}` : 'No active incidents', incidents };
}

// Atlassian Statuspage summary.json (GitHub, Cloudflare, ...).
const SP_GRADE = { none: 'ok', minor: 'warn', major: 'bad', critical: 'bad', maintenance: 'info' };
export function readStatuspage(json, p) {
  if (!json?.status) throw new Error('unexpected summary.json format');
  const incidents = (json.incidents || []).filter(i => i.status !== 'resolved' && i.status !== 'postmortem').map(i => ({
    title: i.name, started: iso(i.started_at || i.created_at), updated: iso(i.updated_at), impact: SP_GRADE[i.impact] || 'warn',
    detail: clip(i.incident_updates?.[0]?.body), link: safeLink(i.shortlink, p.hosts.concat('stspg.io')) || p.page }));
  const maint = (json.scheduled_maintenances || []).filter(m => m.status === 'in_progress').map(m => ({ title: m.name, started: iso(m.scheduled_for), updated: iso(m.updated_at), impact: 'info', detail: 'Scheduled maintenance in progress', link: safeLink(m.shortlink, p.hosts.concat('stspg.io')) || p.page }));
  return { grade: SP_GRADE[json.status.indicator] || 'warn', summary: json.status.description || 'Unknown', incidents: [...incidents, ...maint] };
}

const GRAPH = 'https://graph.microsoft.com';
const M365_ADMIN = 'https://admin.microsoft.com/Adminportal/Home#/servicehealth';
// Microsoft 365 issues from Graph (/admin/serviceAnnouncement/issues): advisories are notices, interruptions outages.
export function readM365(json) {
  if (!Array.isArray(json?.value)) throw new Error('unexpected Microsoft Graph response');
  const incidents = json.value.filter(i => i && !i.isResolved).map(i => ({
    title: clip(`${i.service ? `${i.service}: ` : ''}${i.title || i.id || 'Issue'}`, 200), started: iso(i.startDateTime), updated: iso(i.lastModifiedDateTime),
    impact: i.classification === 'advisory' ? 'info' : i.status === 'serviceInterruption' ? 'bad' : 'warn',
    detail: clip(i.impactDescription), products: [i.service, i.feature].filter(Boolean), link: M365_ADMIN }))
    .sort((a, b) => RANK[b.impact] - RANK[a.impact]);
  const grade = incidents.reduce((g, i) => (RANK[i.impact] > RANK[g] ? i.impact : g), 'ok');
  const n = incidents.filter(i => i.impact !== 'info').length, adv = incidents.length - n;
  return { grade, summary: incidents.length ? [n && `${n} active incident${n > 1 ? 's' : ''}`, adv && `${adv} advisor${adv > 1 ? 'ies' : 'y'}`].filter(Boolean).join(', ') : 'No active issues', incidents };
}
const NOT_CONNECTED = {
  local: 'Microsoft 365 health is read with HeatMap 360\'s managed identity, so it works only when hosted in Azure.',
  denied: 'HeatMap 360\'s managed identity (id-heatmap360) does not have the Microsoft Graph application permission ServiceHealth.Read.All yet.',
};

export const PROVIDERS = [
  // Tenant service health from Microsoft Graph, read with the app's managed identity (application permission
  // ServiceHealth.Read.All on id-heatmap360). Without the identity or the permission it shows "Not connected".
  { id: 'm365', name: 'Microsoft 365', page: M365_ADMIN, feed: `${GRAPH}/v1.0/admin/serviceAnnouncement/issues?$filter=isResolved%20eq%20false&$top=100`,
    hosts: ['admin.microsoft.com'], read: readM365, type: 'json', graph: true },
  { id: 'azure', name: 'Microsoft Azure', page: 'https://azure.status.microsoft/en-us/status', feed: 'https://azure.status.microsoft/en-us/status/feed/', hosts: ['azure.status.microsoft', 'azure.microsoft.com'], read: readAzure, type: 'xml' },
  { id: 'aws', name: 'Amazon Web Services', page: 'https://health.aws.amazon.com/health/status', feed: 'https://status.aws.amazon.com/rss/all.rss', hosts: ['health.aws.amazon.com', 'status.aws.amazon.com'], read: readAws, type: 'xml' },
  { id: 'gcp', name: 'Google Cloud', page: 'https://status.cloud.google.com/', feed: 'https://status.cloud.google.com/incidents.json', hosts: ['status.cloud.google.com'], read: readGoogle, type: 'json' },
  { id: 'workspace', name: 'Google Workspace', page: 'https://www.google.com/appsstatus/dashboard/', feed: 'https://www.google.com/appsstatus/dashboard/incidents.json', hosts: ['www.google.com'], read: readGoogle, type: 'json' },
  { id: 'github', name: 'GitHub', page: 'https://www.githubstatus.com/', feed: 'https://www.githubstatus.com/api/v2/summary.json', hosts: ['www.githubstatus.com', 'githubstatus.com'], read: readStatuspage, type: 'json' },
  { id: 'cloudflare', name: 'Cloudflare', page: 'https://www.cloudflarestatus.com/', feed: 'https://www.cloudflarestatus.com/api/v2/summary.json', hosts: ['www.cloudflarestatus.com', 'cloudflarestatus.com'], read: readStatuspage, type: 'json' },
];

// graphToken(resource) -> access token from the managed identity, or null when not hosted.
export function createServiceHealth({ fetchImpl = (...a) => fetch(...a), now = () => Date.now(), ttlMs = 300_000, providers = PROVIDERS, graphToken = null } = {}) {
  let cache = null;
  async function one(p) {
    const base = { id: p.id, name: p.name, page: p.page };
    const notConnected = note => ({ ...base, grade: 'unknown', summary: 'Not connected', note, incidents: [] });
    if (p.graph && !graphToken) return notConnected(NOT_CONNECTED.local);
    try {
      const headers = { 'user-agent': 'HeatMap360/1.0', accept: p.type === 'json' ? 'application/json' : 'application/rss+xml, application/xml, text/xml' };
      if (p.graph) headers.authorization = `Bearer ${await graphToken(GRAPH)}`;
      const r = await fetchImpl(p.feed, { headers, redirect: p.graph ? 'error' : 'follow', signal: AbortSignal.timeout(10_000) });
      if (p.graph && (r.status === 401 || r.status === 403)) return notConnected(NOT_CONNECTED.denied);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const body = p.type === 'json' ? await r.json() : await r.text();
      const out = p.read(body, p, now());
      return { ...base, ...out, incidents: out.incidents.slice(0, 20) };
    } catch (e) {
      return { ...base, grade: 'unknown', summary: 'Not checked', error: `Could not read the ${p.name} status feed: ${String(e.message || e).slice(0, 200)}`, incidents: [] };
    }
  }
  return function get() {
    if (cache && now() - cache.at < ttlMs) return cache.value;
    const at = now();
    cache = { at, value: Promise.all(providers.map(one)).then(list => ({ checkedAt: new Date(at).toISOString(), providers: list })) };
    return cache.value;
  };
}
