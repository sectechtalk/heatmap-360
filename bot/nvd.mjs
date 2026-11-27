// NVD (National Vulnerability Database) CVE and CPE API 2.0, free and without a key (approved by the owner 2026-11-27).
//
// Two steps per item:
//   1. Product match: the name Windows reports ("Google Chrome", "Intel(R) Wi-Fi 6 AX201") is matched once to NVD's
//      product name (CPE vendor:product) with the CPE keyword search. A strong match is used at once; a weaker one is
//      only PROPOSED and shown on the Inventory catalog page with a Confirm button, so a wrong product never produces
//      CVE findings. An admin's confirm or reject always wins.
//   2. CVEs for that product AND version: virtualMatchString=cpe:2.3:<part>:<vendor>:<product>:<version>. NVD applies
//      its own version ranges, so only CVEs that include this exact version come back.
// Without a key NVD allows about 5 requests per 30 seconds; requests here are spaced 6.5 s apart.
const API = 'https://services.nvd.nist.gov/rest/json';
const UA = 'HeatMap360-bot/1.0 (+https://github.com/<your-account>/heatmap-360)';
export const CPE_PART = /^[aoh]$/;
export const CPE_ID = /^[a-z0-9][a-z0-9._\-~%!+\\/]{0,99}$/i;

// ---------- name matching ----------

const NOISE = new Set(['the', 'for', 'and', 'of', 'x64', 'x86', 'amd64', 'arm64', '64', '32', 'bit', '64bit', '32bit', '64-bit', '32-bit', 'version', 'edition', 'update', 'updater', 'driver',
  'drivers', 'device', 'controller', 'windows', 'win', 'win10', 'win11', 'inc', 'corp', 'corporation', 'llc', 'ltd', 'co', 'gmbh', 'en', 'us', 'r', 'tm', 'c']);
// "Intel(R) Wi-Fi 6 AX201 160MHz (64-bit) 23.1" -> ['intel', 'wi-fi', '6', 'ax201', '160mhz']
export function nameTokens(s) {
  return String(s ?? '').toLowerCase().replace(/\((r|tm|c)\)|[®™©]/g, ' ').replace(/\(([^)]*)\)/g, ' $1 ')
    .replace(/\b\d+(\.\d+){1,}\b/g, ' ').split(/[^a-z0-9+#-]+/).map(t => t.replace(/^-+|-+$/g, '')).filter(t => t && !NOISE.has(t));
}
const VENDOR_ALIASES = { 'google llc': 'google', 'microsoft corporation': 'microsoft', 'adobe inc.': 'adobe', 'adobe systems incorporated': 'adobe', 'igor pavlov': '7-zip',
  'mozilla': 'mozilla', 'oracle corporation': 'oracle', 'realtek semiconductor corp.': 'realtek', 'advanced micro devices, inc.': 'amd', 'nvidia': 'nvidia', 'intel corporation': 'intel' };
export function vendorTokens(v) {
  const s = String(v ?? '').trim().toLowerCase();
  return [...new Set([VENDOR_ALIASES[s], ...nameTokens(s)].filter(Boolean))];
}
// The words to search NVD's product dictionary with: the first few meaningful words of the name.
export function searchWords(name) { return nameTokens(name).filter(t => !/^\d+$/.test(t)).slice(0, 3).join(' '); }

// Score one NVD vendor:product against an item. strong: every product word is in the name and the vendor matches.
export function scoreProduct(item, vendor, product) {
  const name = nameTokens(item.name), vt = vendorTokens(item.vendor);
  const prod = String(product).toLowerCase().split(/[_\-\\/]+/).filter(t => t && !NOISE.has(t));
  const ven = String(vendor).toLowerCase().replace(/\\/g, '');
  if (!prod.length) return { score: 0, strength: 'none' };
  const hay = new Set([...name, ...name.flatMap(t => t.split('-'))]);
  const hits = prod.filter(t => hay.has(t)).length;
  const vendorHit = vt.some(t => t === ven || ven.split(/[_-]/).includes(t)) || name.includes(ven) || hay.has(ven);
  const cover = hits / prod.length, share = hits / Math.max(1, name.length);
  const score = Math.round((cover * 0.6 + share * 0.2 + (vendorHit ? 0.2 : 0)) * 100) / 100;
  const strength = cover === 1 && vendorHit && share >= 0.5 ? 'strong' : cover >= 0.5 && (vendorHit || cover === 1) ? 'proposed' : 'none';
  return { score, strength };
}

// products: [{ part, vendor, product, title }] from the CPE search. Best first; the top one decides.
export function rankProducts(item, products) {
  const seen = new Map();
  for (const p of products) {
    const k = `${p.part}:${p.vendor}:${p.product}`;
    if (!seen.has(k)) seen.set(k, { ...p, ...scoreProduct(item, p.vendor, p.product) });
  }
  const order = { strong: 0, proposed: 1, none: 2 };
  return [...seen.values()].filter(p => p.strength !== 'none').sort((a, b) => order[a.strength] - order[b.strength] || b.score - a.score).slice(0, 5);
}

export function parseCpe(name) {
  const p = String(name).split(':');
  return p.length >= 6 && p[0] === 'cpe' ? { part: p[2], vendor: p[3], product: p[4], version: p[5] } : null;
}

// The part of a CPE is "a" (application), "o" (operating system, which is how NVD lists most drivers' firmware) or "h".
const PART_FOR = { app: ['a'], 'winget-package': ['a'], driver: ['a', 'o'], 'network-adapter': ['a', 'o'], bios: ['o', 'a'], disk: ['o'], tpm: ['o'], security: ['a', 'o'] };

// ---------- CVE answer ----------

const metric = c => {
  const m = c.metrics || {};
  const x = (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || []).find(v => v.type === 'Primary') || (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
  return x ? { score: x.cvssData?.baseScore ?? null, severity: x.cvssData?.baseSeverity || x.baseSeverity || null } : { score: null, severity: null };
};
// The first fixed version NVD names for this product, when it gives a range ending before a fix.
const fixedIn = (c, vendor, product) => {
  for (const cfg of c.configurations || []) for (const n of cfg.nodes || []) for (const m of n.cpeMatch || []) {
    const p = parseCpe(m.criteria);
    if (m.vulnerable && p && p.vendor === vendor && p.product === product && m.versionEndExcluding) return m.versionEndExcluding;
  }
  return null;
};
export function cveList(json, vendor, product) {
  return (json?.vulnerabilities || []).map(v => v.cve).filter(c => c?.id && c.vulnStatus !== 'Rejected').map(c => ({
    cve: c.id, ...metric(c), published: String(c.published || '').slice(0, 10) || null, fixedIn: fixedIn(c, vendor, product),
    kev: Boolean(c.cisaExploitAdd), title: (c.descriptions || []).find(d => d.lang === 'en')?.value?.slice(0, 200) || null,
    record: `https://nvd.nist.gov/vuln/detail/${c.id}` }));
}
export const sortCves = list => [...list].sort((a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? -1) - (a.score ?? -1) || String(b.published).localeCompare(String(a.published)));

// ---------- the client ----------

export function createNvd({ fetchImpl = (...a) => fetch(...a), spacingMs = 6500, sleep = ms => new Promise(r => setTimeout(r, ms)), now = () => Date.now() } = {}) {
  let last = 0;
  async function get(path, params) {
    const wait = last + spacingMs - now();
    if (wait > 0) await sleep(wait);
    last = now();
    const url = `${API}/${path}?${new URLSearchParams(params)}`;
    for (let attempt = 1; ; attempt++) {
      const r = await fetchImpl(url, { headers: { 'user-agent': UA, accept: 'application/json' }, signal: AbortSignal.timeout(60_000) });
      if (r.ok) return r.json();
      // 403/429/503 = NVD's rate limit or a busy moment: wait once and try again, then give up for this run.
      if (attempt < 2 && [403, 429, 503].includes(r.status)) { await sleep(spacingMs * 2); last = now(); continue; }
      throw new Error(`NVD returned HTTP ${r.status}`);
    }
  }
  return {
    // [{ part, vendor, product, title }] for the search words.
    async products(words) {
      if (!words) return [];
      const j = await get('cpes/2.0', { keywordSearch: words, resultsPerPage: '500' });
      return (j.products || []).map(p => p.cpe).filter(c => c && !c.deprecated).map(c => ({ ...parseCpe(c.cpeName), title: c.titles?.find(t => t.lang === 'en')?.title || null }))
        .filter(p => p.part && CPE_ID.test(p.vendor) && CPE_ID.test(p.product));
    },
    // CVEs that include this exact version.
    async cves({ part, vendor, product }, version) {
      if (!CPE_PART.test(part) || !CPE_ID.test(vendor) || !CPE_ID.test(product)) throw new Error('bad product name');
      const v = String(version ?? '').trim().replace(/[^A-Za-z0-9._\-+~]/g, '_');
      if (!v) throw new Error('no version to check');
      const out = [];
      for (let start = 0; start < 4000; start += 2000) {
        const j = await get('cves/2.0', { virtualMatchString: `cpe:2.3:${part}:${vendor}:${product}:${v}`, resultsPerPage: '2000', startIndex: String(start) });
        out.push(...cveList(j, vendor, product));
        if (start + 2000 >= (j.totalResults || 0)) break;
      }
      return out;
    },
  };
}

// Item -> { match, cves } where match = { status: confirmed|strong|proposed|rejected|none, part, vendor, product, candidates }.
// confirmed: the admin's choices (settings/products.json), keyed by productKey().
export const productKey = (kind, name, vendor) => `${kind === 'winget-package' ? 'app' : kind}|${nameTokens(name).join(' ')}|${vendorTokens(vendor)[0] || ''}`.slice(0, 200);
export async function matchProduct(item, nvd, confirmed = {}) {
  const key = productKey(item.kind, item.name, item.vendor);
  const choice = confirmed[key];
  if (choice === null) return { key, status: 'rejected', candidates: [] };
  if (typeof choice === 'string') { const [part, vendor, product] = choice.split(':'); return { key, status: 'confirmed', part, vendor, product, candidates: [] }; }
  const words = searchWords(item.name);
  if (!words) return { key, status: 'none', candidates: [] };
  const parts = PART_FOR[item.kind] || ['a'];
  const ranked = rankProducts(item, (await nvd.products(words)).filter(p => parts.includes(p.part)));
  const top = ranked[0];
  if (!top) return { key, status: 'none', candidates: [] };
  return { key, status: top.strength, part: top.part, vendor: top.vendor, product: top.product, candidates: ranked.map(({ part, vendor, product, title, score }) => ({ cpe: `${part}:${vendor}:${product}`, title, score })) };
}
