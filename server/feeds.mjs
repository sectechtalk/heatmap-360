// Free vulnerability feeds, cached on disk so the dashboard works offline and the feeds are fetched at most daily.
//   kev   CISA Known Exploited Vulnerabilities: CVEs exploited in the wild (no key needed).
//   epss  FIRST EPSS scores: probability of exploitation in the next 30 days, looked up for KEV CVEs only.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = 'https://api.first.org/data/v1/epss';
const DAY = 86_400_000;

async function readJson(file) { try { return JSON.parse(await readFile(file, 'utf8')); } catch { return null; } }

export function createFeeds({ dir, fetchImpl = (...a) => fetch(...a), now = () => Date.now(), maxAgeMs = DAY } = {}) {
  const state = { kev: null, epss: {}, lastError: null, fetchedAt: null };
  const kevFile = path.join(dir, 'kev.json');

  async function refresh({ force = false } = {}) {
    if (!state.kev) {
      const cached = await readJson(kevFile);
      if (cached) { state.kev = cached.kev; state.epss = cached.epss || {}; state.fetchedAt = cached.fetchedAt; }
    }
    if (!force && state.fetchedAt && now() - Date.parse(state.fetchedAt) < maxAgeMs) return state;
    try {
      const r = await fetchImpl(KEV_URL, { headers: { accept: 'application/json' } });
      if (!r.ok) throw new Error(`KEV feed returned HTTP ${r.status}`);
      const kev = await r.json();
      if (!Array.isArray(kev.vulnerabilities)) throw new Error('KEV feed has no vulnerabilities array');
      state.kev = { catalogVersion: kev.catalogVersion, dateReleased: kev.dateReleased, vulnerabilities: kev.vulnerabilities };
      state.epss = await epssFor(kev.vulnerabilities.map(v => v.cveID)).catch(() => state.epss);
      state.fetchedAt = new Date(now()).toISOString();
      state.lastError = null;
      await mkdir(dir, { recursive: true });
      await writeFile(kevFile, JSON.stringify({ fetchedAt: state.fetchedAt, kev: state.kev, epss: state.epss }));
    } catch (err) { state.lastError = err.message; }
    return state;
  }

  // EPSS accepts up to ~100 CVEs per request.
  async function epssFor(cves) {
    const out = {};
    for (let i = 0; i < cves.length; i += 100) {
      const r = await fetchImpl(`${EPSS_URL}?cve=${cves.slice(i, i + 100).join(',')}`);
      if (!r.ok) throw new Error(`EPSS returned HTTP ${r.status}`);
      for (const row of (await r.json()).data || []) out[row.cve] = { epss: Number(row.epss), percentile: Number(row.percentile) };
    }
    return out;
  }

  return { state, refresh };
}
