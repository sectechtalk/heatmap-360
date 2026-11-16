// Internet pages: the latest headlines from well-known sources, read from each source's own public RSS or Atom feed.
// "Cloud services" covers the state of cloud platforms (provider update feeds and cloud news); "Exploits" covers
// vulnerabilities and attacks outside the cloud (CISA advisories, security news); "Patches" covers new Windows, Office,
// browser and app updates and the problems people report with them (sources chosen by the owner 2026-11-15). No credentials, no paid service,
// no model: the server reads the public feeds on request, keeps them for 30 minutes, and every source is independent
// (a feed that fails or changes shape shows as "Not checked" with the reason). Report only.
import { blocks, field, iso, clip, safeLink } from './services.mjs';

const MAX_BYTES = 4_000_000;
const PER_SOURCE = 15;

// Atom <link href="..."> (prefer rel="alternate" or no rel); RSS <link>text</link>.
function atomLink(entry) {
  const links = [...String(entry).matchAll(/<link\b([^>]*?)\/?>/gi)].map(m => m[1]);
  const attr = (a, n) => a.match(new RegExp(`\\b${n}\\s*=\\s*"([^"]*)"`, 'i'))?.[1] ?? a.match(new RegExp(`\\b${n}\\s*=\\s*'([^']*)'`, 'i'))?.[1] ?? null;
  const pick = links.find(a => !attr(a, 'rel') || attr(a, 'rel') === 'alternate') ?? links[0];
  return pick ? attr(pick, 'href') : null;
}

// Reads RSS 2.0 or Atom. Returns [{ title, link, date, summary }], newest first. Links must stay on the source's site.
export function parseFeed(xml, hosts) {
  const text = String(xml);
  const isAtom = !/<item\b/i.test(text) && /<entry\b/i.test(text);
  const items = isAtom
    ? blocks(text, 'entry').map(e => ({ title: field(e, 'title'), link: atomLink(e), date: iso(field(e, 'published') || field(e, 'updated')), summary: field(e, 'summary') || field(e, 'content') }))
    : blocks(text, 'item').map(i => ({ title: field(i, 'title'), link: field(i, 'link') || field(i, 'guid'), date: iso(field(i, 'pubDate') || field(i, 'dc:date')), summary: field(i, 'description') }));
  if (!items.length && !/<(rss|feed|rdf:RDF)\b/i.test(text)) throw new Error('not an RSS or Atom feed');
  return items
    .filter(i => i.title)
    .map(i => ({ title: clip(i.title, 220), link: safeLink(i.link, hosts), date: i.date, summary: clip(i.summary, 240) }))
    .sort((a, b) => (b.date || '').localeCompare(a.date || ''));
}

export const NEWS = {
  cloud: {
    title: 'Internet - Cloud Services',
    intro: 'The latest posts about the state of cloud services, from the providers’ own update feeds and well-known cloud news sites.',
    sources: [
      { id: 'azure-updates', name: 'Azure updates', about: 'Microsoft’s feed of Azure changes, retirements and new features.', page: 'https://azure.microsoft.com/en-us/updates/', feed: 'https://www.microsoft.com/releasecommunications/api/v2/azure/rss', hosts: ['azure.microsoft.com', 'microsoft.com'] },
      { id: 'aws-news', name: 'AWS News Blog', about: 'Amazon Web Services announcements and changes.', page: 'https://aws.amazon.com/blogs/aws/', feed: 'https://aws.amazon.com/blogs/aws/feed/', hosts: ['aws.amazon.com', 'amazon.com'] },
      { id: 'gcp-blog', name: 'Google Cloud Blog', about: 'Google Cloud product news and changes.', page: 'https://cloud.google.com/blog', feed: 'https://cloudblog.withgoogle.com/rss/', hosts: ['cloud.google.com', 'cloudblog.withgoogle.com'] },
      { id: 'cloudflare-blog', name: 'Cloudflare Blog', about: 'Cloudflare engineering posts, including post-incident reports and internet disruption summaries.', page: 'https://blog.cloudflare.com/', feed: 'https://blog.cloudflare.com/rss/', hosts: ['blog.cloudflare.com', 'cloudflare.com'] },
      { id: 'register-cloud', name: 'The Register: Cloud', about: 'Independent news on cloud outages, pricing and platform changes.', page: 'https://www.theregister.com/off_prem/', feed: 'https://www.theregister.com/off_prem/headlines.atom', hosts: ['theregister.com'] },
    ],
  },
  exploits: {
    title: 'Internet - Exploits',
    intro: 'The latest posts about vulnerabilities and attacks outside the cloud, from CISA and well-known security news sites.',
    sources: [
      { id: 'cisa-advisories', name: 'CISA advisories', about: 'US Cybersecurity and Infrastructure Security Agency alerts and advisories.', page: 'https://www.cisa.gov/news-events/cybersecurity-advisories', feed: 'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml', hosts: ['cisa.gov'] },
      { id: 'msrc-sug', name: 'Microsoft Security Update Guide', about: 'New and revised Microsoft CVEs from the Microsoft Security Response Center.', page: 'https://msrc.microsoft.com/update-guide/', feed: 'https://api.msrc.microsoft.com/update-guide/rss', hosts: ['msrc.microsoft.com', 'microsoft.com'] },
      { id: 'sans-isc', name: 'SANS Internet Storm Center', about: 'Daily handler diaries on active threats.', page: 'https://isc.sans.edu/', feed: 'https://isc.sans.edu/rssfeed_full.xml', hosts: ['isc.sans.edu', 'sans.edu'] },
      { id: 'bleepingcomputer', name: 'BleepingComputer', about: 'News on exploited vulnerabilities, ransomware and patches.', page: 'https://www.bleepingcomputer.com/', feed: 'https://www.bleepingcomputer.com/feed/', hosts: ['bleepingcomputer.com'] },
      { id: 'hackernews', name: 'The Hacker News', about: 'Cybersecurity news and vulnerability reports.', page: 'https://thehackernews.com/', feed: 'https://feeds.feedburner.com/TheHackersNews', hosts: ['thehackernews.com'] },
      { id: 'securityweek', name: 'SecurityWeek', about: 'Security industry news, vulnerabilities and incidents.', page: 'https://www.securityweek.com/', feed: 'https://www.securityweek.com/feed/', hosts: ['securityweek.com'] },
      { id: 'krebs', name: 'Krebs on Security', about: 'Investigative security reporting.', page: 'https://krebsonsecurity.com/', feed: 'https://krebsonsecurity.com/feed/', hosts: ['krebsonsecurity.com'] },
    ],
  },
  patches: {
    title: 'Internet - Patches',
    intro: 'The latest posts about new Windows, browser and app updates and the problems people report with them, from vendor feeds and the sites admins rely on.',
    sources: [
      { id: 'bleepingcomputer', name: 'BleepingComputer', about: 'Fast independent news on new Windows updates, broken updates and fixes.', page: 'https://www.bleepingcomputer.com/', feed: 'https://www.bleepingcomputer.com/feed/', hosts: ['bleepingcomputer.com'] },
      { id: 'borncity', name: 'Born’s Tech and Windows World', about: 'Patch problems reported by admins, often before Microsoft confirms them.', page: 'https://borncity.com/win/', feed: 'https://borncity.com/win/feed/', hosts: ['borncity.com'] },
      { id: 'windows-itpro', name: 'Windows IT Pro Blog', about: 'Microsoft’s own posts on Windows servicing, update policy and Autopatch.', page: 'https://techcommunity.microsoft.com/category/windows/blog/windows-itpro-blog', feed: 'https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Windows-ITPro-blog', hosts: ['techcommunity.microsoft.com'] },
      { id: 'zdi', name: 'Zero Day Initiative', about: 'The most-cited monthly Patch Tuesday review, CVE by CVE.', page: 'https://www.zerodayinitiative.com/blog', feed: 'https://www.zerodayinitiative.com/blog?format=rss', hosts: ['zerodayinitiative.com'] },
      { id: 'windowslatest', name: 'Windows Latest', about: 'Every new Windows update, what it changes and its install errors.', page: 'https://www.windowslatest.com/', feed: 'https://www.windowslatest.com/feed/', hosts: ['windowslatest.com'] },
      { id: 'neowin', name: 'Neowin', about: 'Daily news on Windows, Office and driver updates.', page: 'https://www.neowin.net/', feed: 'https://www.neowin.net/news/rss/', hosts: ['neowin.net'] },
      { id: 'register-patches', name: 'The Register: Patches', about: 'Independent coverage of bad patches and vendor responses.', page: 'https://www.theregister.com/security/patches/', feed: 'https://www.theregister.com/security/patches/headlines.atom', hosts: ['theregister.com'] },
      { id: 'patchmypc', name: 'Patch My PC', about: 'Third-party app patch catalog releases and Windows servicing deep dives.', page: 'https://patchmypc.com/blog', feed: 'https://patchmypc.com/feed', hosts: ['patchmypc.com'] },
      { id: 'ghacks', name: 'gHacks', about: 'Monthly Windows security update overview with known issues.', page: 'https://www.ghacks.net/', feed: 'https://www.ghacks.net/feed/', hosts: ['ghacks.net'] },
      { id: 'chrome-releases', name: 'Chrome Releases', about: 'Google’s announcements of every Chrome stable and security update.', page: 'https://chromereleases.googleblog.com/', feed: 'https://chromereleases.googleblog.com/feeds/posts/default', hosts: ['chromereleases.googleblog.com'] },
      { id: 'tenable', name: 'Tenable blog', about: 'Patch Tuesday analysis with notes on which flaws are being exploited.', page: 'https://www.tenable.com/blog', feed: 'https://www.tenable.com/blog/feed', hosts: ['tenable.com'] },
    ],
  },
};

export function createNews({ fetchImpl = (...a) => fetch(...a), now = () => Date.now(), ttlMs = 1_800_000, lists = NEWS } = {}) {
  const cache = new Map();
  async function one(s) {
    const base = { id: s.id, name: s.name, about: s.about, page: s.page };
    try {
      const r = await fetchImpl(s.feed, { headers: { 'user-agent': 'HeatMap360/1.0', accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' }, redirect: 'follow', signal: AbortSignal.timeout(10_000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      if (Number(r.headers?.get?.('content-length') || 0) > MAX_BYTES) throw new Error('feed is too large');
      const body = await r.text();
      if (body.length > MAX_BYTES) throw new Error('feed is too large');
      const items = parseFeed(body, s.hosts).slice(0, PER_SOURCE);
      return { ...base, status: 'checked', items };
    } catch (e) {
      return { ...base, status: 'unknown', error: `Could not read the ${s.name} feed: ${String(e.message || e).slice(0, 200)}`, items: [] };
    }
  }
  return function get(kind) {
    const list = lists[kind];
    if (!list) return null;
    const hit = cache.get(kind);
    if (hit && now() - hit.at < ttlMs) return hit.value;
    const at = now();
    const value = Promise.all(list.sources.map(one)).then(sources => ({ kind, title: list.title, intro: list.intro, checkedAt: new Date(at).toISOString(), sources }));
    cache.set(kind, { at, value });
    return value;
  };
}
