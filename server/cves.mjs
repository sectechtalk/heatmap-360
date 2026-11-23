// Cloudflare Radar CVEs page: newly published CVEs from Cloudflare Radar's free public "Zero Wire" CVE JSON Feed
// (added by the owner 2026-11-22). Cloudflare builds the list from the CVE List and NVD, with CISA's Known Exploited
// Vulnerabilities dates. No account, no key, no cost. Each feed holds the newest 100 CVEs, so the server reads the
// unfiltered feed plus one feed per severity and merges them: that keeps several days of Critical and High CVEs even
// though the unfiltered feed only covers about the last hour. Kept for 30 minutes. Report only.
import { iso, clip, safeLink } from './services.mjs';

export const CVE_PAGE = 'https://radar.cloudflare.com/zero-wire/cves';
const FEED = 'https://radar.cloudflare.com/zero-wire/cves/feed?format=json';
const HOSTS = ['radar.cloudflare.com'];
const MAX_BYTES = 4_000_000;
// Feeds read: the unfiltered one and one per severity Cloudflare offers. Order sets the severity filter order on the page.
export const CVE_FEEDS = [
  { id: 'all', name: 'Newest of any severity', url: FEED },
  { id: 'critical', name: 'Critical', url: `${FEED}&severity=critical` },
  { id: 'high', name: 'High', url: `${FEED}&severity=high` },
  { id: 'medium', name: 'Medium', url: `${FEED}&severity=medium` },
  { id: 'low', name: 'Low', url: `${FEED}&severity=low` },
];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none', 'unscored'];
const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

// Reads one JSON Feed. Uses only the structured _cve object (Cloudflare says tags and content_text are display text).
export function parseCveFeed(json) {
  if (!json || !Array.isArray(json.items)) throw new Error('not a CVE JSON feed');
  return json.items.flatMap(i => {
    const c = i?._cve || {};
    const id = String(c.id || '').toUpperCase();
    if (!CVE_ID.test(id)) return [];
    const sev = String(c.severity || '').toLowerCase();
    const title = String(i.title || id);
    return [{
      id,
      title: clip(title.startsWith(`${id}: `) ? title.slice(id.length + 2) : title === id ? null : title, 220),
      summary: clip(String(i.summary || '').trim() || null, 400),
      date: iso(i.date_published),
      severity: SEVERITIES.includes(sev) ? sev : 'unscored',
      score: Number.isFinite(c.score) && c.score >= 0 && c.score <= 10 ? c.score : null,
      cvss: typeof c.cvss_version === 'string' ? clip(c.cvss_version, 8) : null,
      kevAdded: /^\d{4}-\d{2}-\d{2}$/.test(c.kev_added || '') ? c.kev_added : null,
      link: safeLink(i.url, HOSTS) || `${CVE_PAGE}/${id}`,
    }];
  });
}

export function createCves({ fetchImpl = (...a) => fetch(...a), now = () => Date.now(), ttlMs = 1_800_000, feeds = CVE_FEEDS } = {}) {
  let hit = null;
  async function one(f) {
    try {
      const r = await fetchImpl(f.url, { headers: { 'user-agent': 'HeatMap360/1.0', accept: 'application/feed+json, application/json' }, redirect: 'follow', signal: AbortSignal.timeout(10_000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      if (Number(r.headers?.get?.('content-length') || 0) > MAX_BYTES) throw new Error('feed is too large');
      const body = await r.text();
      if (body.length > MAX_BYTES) throw new Error('feed is too large');
      return { id: f.id, name: f.name, status: 'checked', items: parseCveFeed(JSON.parse(body)) };
    } catch (e) {
      return { id: f.id, name: f.name, status: 'unknown', error: `Could not read the ${f.name} feed: ${String(e.message || e).slice(0, 200)}`, items: [] };
    }
  }
  return function get() {
    if (hit && now() - hit.at < ttlMs) return hit.value;
    const at = now();
    const value = Promise.all(feeds.map(one)).then(read => {
      const byId = new Map();
      for (const f of read) for (const it of f.items) if (!byId.has(it.id)) byId.set(it.id, it);
      const items = [...byId.values()].sort((a, b) => (b.date || '').localeCompare(a.date || ''));
      return {
        title: 'Cloudflare Radar CVEs', page: CVE_PAGE, checkedAt: new Date(at).toISOString(),
        feeds: read.map(f => ({ id: f.id, name: f.name, status: f.status, error: f.error || null, count: f.items.length, oldest: f.items.map(i => i.date).filter(Boolean).sort()[0] || null })),
        items,
      };
    });
    hit = { at, value };
    return value;
  };
}
