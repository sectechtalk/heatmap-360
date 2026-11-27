// High impact page: one short list of what deserves attention right now, built only from data HeatMap 360 already
// reads for free. Exploits come from CISA's Known Exploited Vulnerabilities catalog (KEV) plus zero-day / actively
// exploited headlines on the Internet - Exploits and Internet - Patches feeds. Disruptions come from the Service health
// feeds (outages, and degradations that last for hours). Report only: it never changes anything and never posts.
// It tracks what is happening in the wild; server/exposure.mjs ("Are we affected?") matches the exploit items against
// the scanned computers.
//
// The bar is deliberately high so the page stays short. Every rule is in RULES below so it can be tuned in one place.
import { iso, clip } from './services.mjs';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEV_PAGE = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
const MAX_BYTES = 8_000_000;
const HOUR = 3_600_000, DAY = 24 * HOUR;

export const RULES = {
  kevDays: 7, // CISA added it to KEV in the last 7 days
  headlineDays: 7, // headline published in the last 7 days
  headlineKinds: ['exploits', 'patches'], // which Internet pages' feeds are read for headlines
  // A headline makes the cut only when its title says the flaw is already being used or the fix is an emergency.
  headline: /\bzero[- ]?days?\b|\b0[- ]?days?\b|actively exploited|exploited in (?:the )?wild|in-the-wild|under (?:active )?attack|mass[- ]exploit|emergency (?:patch|update|fix|security update)|out[- ]of[- ]band/i,
  manySources: 3, // the same CVE reported by this many feeds is critical
  degradedHours: 2, // a degradation lasting this long makes the cut
  longDegradedHours: 8, // ... and this long makes it critical
  maxItems: 40,
};

// Plain-language version of RULES, shown on the page so admins can see why the list is what it is.
export function describeRules(r = RULES) {
  return [
    `Exploits: every vulnerability CISA added to its Known Exploited Vulnerabilities catalog in the last ${r.kevDays} days. Critical when CISA says ransomware gangs use it, or when ${r.manySources} or more news feeds also report it.`,
    `Zero-days: headlines from the Internet - Exploits and Internet - Patches feeds in the last ${r.headlineDays} days whose title says zero-day, actively exploited, exploited in the wild, under attack, emergency patch or out-of-band. Headlines naming the same CVE are merged into one item.`,
    `Disruptions: any outage on a Service health feed, and any degradation that has lasted ${r.degradedHours} hours or more. Critical for an outage, or a degradation of ${r.longDegradedHours} hours or more. Notices, advisories and scheduled maintenance are left out.`,
    `Critical items are listed first, then the most recent. At most ${r.maxItems} items.`,
  ];
}

const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const cvesIn = text => [...new Set((String(text || '').match(CVE) || []).map(c => c.toUpperCase()))];
const cveLink = id => `https://www.cve.org/CVERecord?id=${id}`;
const kevLink = id => `${KEV_PAGE}?search_api_fulltext=${id}`;
const hoursText = ms => { const hrs = Math.floor(ms / HOUR); return hrs >= 48 ? `${Math.floor(hrs / 24)} days` : `${hrs} hour${hrs === 1 ? '' : 's'}`; };
const latest = dates => dates.filter(Boolean).sort().pop() || null;

// KEV entries added in the last kevDays. dateAdded is a date only (no time).
export function kevItems(kev, now, r = RULES) {
  if (!Array.isArray(kev?.vulnerabilities)) throw new Error('KEV feed has no vulnerabilities array');
  return kev.vulnerabilities
    .filter(v => v?.cveID && v.dateAdded && now - Date.parse(`${v.dateAdded}T00:00:00Z`) <= r.kevDays * DAY + DAY)
    .map(v => {
      const id = String(v.cveID).toUpperCase();
      const ransomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
      return {
        id: `kev:${id}`, kind: 'exploit', cves: [id], ransomware,
        title: clip(`${v.vendorProject || ''} ${v.product || ''}: ${v.vulnerabilityName || id}`.trim(), 220),
        detail: clip(v.shortDescription, 400), started: iso(`${v.dateAdded}T00:00:00Z`), dueDate: v.dueDate || null,
        why: [`Exploited in the wild: CISA added ${id} to the Known Exploited Vulnerabilities catalog on ${v.dateAdded}.`, ransomware ? 'CISA says ransomware campaigns are known to use it.' : null].filter(Boolean),
        sources: [{ name: 'CISA KEV catalog', link: kevLink(id) }, { name: `CVE record ${id}`, link: cveLink(id) }],
        // The catalog entry itself, so "Are we affected?" can match it against scanned computers.
        kev: [{ cveID: id, vendorProject: v.vendorProject || '', product: v.product || '', vulnerabilityName: v.vulnerabilityName || '', dateAdded: v.dateAdded, knownRansomwareCampaignUse: v.knownRansomwareCampaignUse || '' }],
      };
    });
}

// Zero-day / actively exploited headlines from the news pages, deduplicated by link and title.
export function headlineHits(pages, now, r = RULES) {
  const seen = new Set(), hits = [];
  for (const page of pages) for (const s of page?.sources || []) for (const it of s.items || []) {
    if (!it?.title || !r.headline.test(it.title)) continue;
    if (!it.date || now - Date.parse(it.date) > r.headlineDays * DAY) continue;
    const key = it.link || `${s.id}:${it.title.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({ source: s.name, title: it.title, link: it.link || s.page, date: it.date, cves: cvesIn(`${it.title} ${it.summary || ''}`), summary: it.summary || null });
  }
  return hits;
}

// Merge headlines into KEV items (same CVE) or into each other (shared CVE); headlines without a CVE stay single.
export function mergeExploits(kev, hits, r = RULES) {
  const items = kev.map(k => ({ ...k, why: [...k.why], sources: [...k.sources], news: [] }));
  const byCve = new Map();
  for (const it of items) for (const c of it.cves) byCve.set(c, it);
  for (const hit of hits) {
    let item = hit.cves.map(c => byCve.get(c)).find(Boolean);
    if (!item) {
      item = { id: `news:${hit.cves[0] || hit.link}`, kind: 'exploit', cves: [], kev: [], ransomware: false, title: clip(hit.title, 220), detail: clip(hit.summary, 400), started: hit.date, why: [], sources: [], news: [] };
      items.push(item);
    }
    for (const c of hit.cves) if (!item.cves.includes(c)) { item.cves.push(c); byCve.set(c, item); }
    item.news.push(hit);
  }
  for (const it of items) {
    const outlets = [...new Set(it.news.map(n => n.source))];
    if (it.news.length) {
      it.started = [it.started, ...it.news.map(n => n.date)].filter(Boolean).sort()[0] || null;
      it.seen = latest([it.started, ...it.news.map(n => n.date)]);
      it.why.push(it.id.startsWith('kev:')
        ? `Also in the news: ${outlets.length} feed${outlets.length === 1 ? '' : 's'} (${outlets.join(', ')}).`
        : `${outlets.length === 1 ? 'A news headline says' : `${outlets.length} news feeds say`} it is a zero-day, exploited or an emergency fix (${outlets.join(', ')}).`);
      for (const n of it.news) it.sources.push({ name: n.source, link: n.link, title: n.title, date: n.date });
    } else it.seen = it.started;
    if (!it.id.startsWith('kev:')) for (const c of it.cves) it.sources.push({ name: `CVE record ${c}`, link: cveLink(c) });
    it.level = it.ransomware || outlets.length >= r.manySources ? 'critical' : 'high';
    delete it.news;
  }
  return items;
}

// Outages and long degradations from the Service health feeds. Feeds only list incidents that are still open.
export function disruptionItems(services, now, r = RULES) {
  const items = [];
  for (const p of services?.providers || []) for (const i of p.incidents || []) {
    if (i.impact !== 'bad' && i.impact !== 'warn') continue;
    const since = i.started ? now - Date.parse(i.started) : null;
    if (i.impact === 'warn' && !(since >= r.degradedHours * HOUR)) continue;
    const long = i.impact === 'warn' && since >= r.longDegradedHours * HOUR;
    items.push({
      id: `svc:${p.id}:${i.title}`, kind: 'disruption', provider: p.name, level: i.impact === 'bad' || long ? 'critical' : 'high',
      title: clip(`${p.name}: ${i.title || 'Incident'}`, 220), detail: clip(i.detail, 400), started: i.started || null, seen: i.updated || i.started || null, active: true,
      why: [i.impact === 'bad' ? `${p.name} reports an outage${since != null ? ` that started ${hoursText(since)} ago` : ''}.` : `${p.name} has reported this as degraded for ${hoursText(since)}.`],
      products: i.products || [], sources: [{ name: `${p.name} status`, link: i.link || p.page }],
    });
  }
  return items;
}

const LEVEL = { critical: 0, high: 1 };
export function rank(items, r = RULES) {
  return items.sort((a, b) => LEVEL[a.level] - LEVEL[b.level] || (b.seen || '').localeCompare(a.seen || '')).slice(0, r.maxItems);
}

// news(kind) and serviceHealth() are the same cached readers the Internet and Service health pages use.
export function createAttention({ news, serviceHealth, fetchImpl = (...a) => fetch(...a), now = () => Date.now(), kevTtlMs = HOUR, rules = RULES } = {}) {
  let kevCache = null;
  async function readKev() {
    const r = await fetchImpl(KEV_URL, { headers: { 'user-agent': 'HeatMap360/1.0', accept: 'application/json' }, redirect: 'follow', signal: AbortSignal.timeout(15_000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    if (Number(r.headers?.get?.('content-length') || 0) > MAX_BYTES) throw new Error('feed is too large');
    const text = await r.text();
    if (text.length > MAX_BYTES) throw new Error('feed is too large');
    return JSON.parse(text);
  }
  function kev() {
    if (kevCache && now() - kevCache.at < kevTtlMs) return kevCache.value;
    const at = now();
    const value = readKev().then(data => ({ ok: true, data }), e => ({ ok: false, error: `Could not read the CISA KEV catalog: ${String(e.message || e).slice(0, 200)}` }));
    kevCache = { at, value };
    // A failed read is retried after 5 minutes, not after the full hour.
    value.then(v => { if (!v.ok && kevCache?.value === value) kevCache.at = at - kevTtlMs + 300_000; });
    return value;
  }
  async function get() {
    const t = now();
    const [k, pages, svc] = await Promise.all([
      kev(),
      Promise.all(rules.headlineKinds.map(kind => Promise.resolve(news(kind)).catch(() => null))),
      Promise.resolve(serviceHealth()).catch(() => null),
    ]);
    let kevList = [], kevError = k.ok ? null : k.error;
    if (k.ok) { try { kevList = kevItems(k.data, t, rules); } catch (e) { kevError = `Could not read the CISA KEV catalog: ${e.message}`; } }
    const items = rank([...mergeExploits(kevList, headlineHits(pages, t, rules), rules), ...disruptionItems(svc, t, rules)], rules);
    const feeds = new Map();
    for (const page of pages) for (const s of page?.sources || []) if (!feeds.has(s.id)) feeds.set(s.id, { name: s.name, status: s.status, error: s.error || null });
    return {
      checkedAt: new Date(t).toISOString(),
      rules: describeRules(rules),
      items,
      sources: {
        kev: { name: 'CISA Known Exploited Vulnerabilities', page: KEV_PAGE, status: kevError ? 'unknown' : 'checked', error: kevError, total: k.ok ? k.data?.vulnerabilities?.length ?? null : null },
        news: [...feeds.values()],
        services: (svc?.providers || []).map(p => ({ name: p.name, status: p.summary === 'Not connected' ? 'not-connected' : p.grade === 'unknown' ? 'unknown' : 'checked', note: p.note || p.error || null })),
        servicesError: svc ? null : 'Could not read the Service health feeds.',
      },
    };
  }
  // The whole catalog (same hourly cache), for matching news items whose CVE CISA added before the 7-day window.
  get.kevCatalog = () => kev().then(k => (k.ok ? k.data : null));
  return get;
}
