// Microsoft Security Update Guide (MSRC CVRF API v3.0), free and without a key (approved by the owner 2026-11-27).
// For a Windows build it lists every CVE Microsoft fixed in a later build of the same Windows version: the CVEs this
// computer is still open to until it installs the newest cumulative update. Each monthly document is fetched once and
// kept on disk until Microsoft revises it.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { compareVersions } from './apps.mjs';

const API = 'https://api.msrc.microsoft.com/cvrf/v3.0';
const UA = 'HeatMap360-bot/1.0 (+https://github.com/<your-account>/heatmap-360)';
const MONTH = /^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const monthIndex = id => { const [y, m] = id.split('-'); return Number(y) * 12 + MONTHS.indexOf(m); };
export const monthId = iso => { const d = new Date(iso); return `${d.getUTCFullYear()}-${MONTHS[d.getUTCMonth()]}`; };

// "Windows 11 Version 24H2 for x64-based Systems", as the Security Update Guide names it.
export function windowsProductName({ build, displayVersion, architecture }) {
  const dv = String(displayVersion || '').toUpperCase();
  if (!/^\d{2}H\d$/.test(dv) || !build) return null;
  const arch = /arm/i.test(architecture || '') ? 'ARM64' : /32|x86/i.test(architecture || '') && !/64/.test(architecture || '') ? '32-bit' : 'x64';
  return `Windows ${build >= 22000 ? 11 : 10} Version ${dv} for ${arch === '32-bit' ? '32-bit Systems' : `${arch}-based Systems`}`;
}

// One monthly document -> the CVEs still open on `installed` (e.g. "10.0.26100.4061") for that product.
export function openCves(doc, productName, installed) {
  const prod = (doc?.ProductTree?.FullProductName || []).find(p => p.Value === productName);
  if (!prod) return [];
  const id = prod.ProductID, out = [];
  for (const v of doc.Vulnerability || []) {
    if (!(v.ProductStatuses || []).some(s => s.Type === 3 && (s.ProductID || []).includes(id))) continue;
    const fixes = (v.Remediations || []).filter(r => r.Type === 2 && r.FixedBuild && (r.ProductID || []).includes(id) && /^\d+\.\d+\.\d+\.\d+$/.test(r.FixedBuild));
    const sameLine = fixes.filter(r => r.FixedBuild.split('.').slice(0, 3).join('.') === installed.split('.').slice(0, 3).join('.'));
    if (!sameLine.length) continue;
    const fix = sameLine.sort((a, b) => compareVersions(a.FixedBuild, b.FixedBuild))[0];
    if (compareVersions(fix.FixedBuild, installed) <= 0) continue; // already fixed on this computer
    const threats = (v.Threats || []).filter(t => !t.ProductID?.length || t.ProductID.includes(id));
    const exploited = threats.some(t => t.Type === 1 && /Exploited:Yes/i.test(t.Description?.Value || ''));
    const severity = threats.find(t => t.Type === 3)?.Description?.Value || null;
    const score = (v.CVSSScoreSets || []).find(s => (s.ProductID || []).includes(id))?.BaseScore ?? null;
    out.push({ cve: v.CVE, score, severity, kev: exploited, fixedIn: fix.FixedBuild, kb: /^\d+$/.test(fix.Description?.Value || '') ? `KB${fix.Description.Value}` : null,
      published: String(v.RevisionHistory?.[0]?.Date || '').slice(0, 10) || null, title: v.Title?.Value?.slice(0, 200) || null,
      record: `https://msrc.microsoft.com/update-guide/vulnerability/${v.CVE}` });
  }
  return out;
}

export function createMsrc({ dir, fetchImpl = (...a) => fetch(...a) }) {
  const json = async url => {
    const r = await fetchImpl(url, { headers: { 'user-agent': UA, accept: 'application/json' }, signal: AbortSignal.timeout(180_000) });
    if (!r.ok) throw new Error(`MSRC returned HTTP ${r.status}`);
    return r.json();
  };
  let index = null;
  async function months() {
    index ??= json(`${API}/updates`).then(j => (j.value || []).filter(u => MONTH.test(u.ID || '')).map(u => ({ id: u.ID, revised: u.CurrentReleaseDate || '' })));
    index.catch(() => { index = null; });
    return index;
  }
  async function month(m) {
    const file = path.join(dir, 'msrc', `${m.id}.json`);
    try { const c = JSON.parse(await readFile(file, 'utf8')); if (c.revised === m.revised) return c.doc; } catch { /* not cached */ }
    const full = await json(`${API}/cvrf/${m.id}`);
    // Keep only what openCves reads, so the cache stays small.
    const doc = { ProductTree: { FullProductName: (full.ProductTree?.FullProductName || []).filter(p => /^Windows /.test(p.Value || '')) },
      Vulnerability: (full.Vulnerability || []).map(v => ({ CVE: v.CVE, Title: v.Title, ProductStatuses: v.ProductStatuses, Threats: v.Threats, CVSSScoreSets: v.CVSSScoreSets,
        RevisionHistory: (v.RevisionHistory || []).slice(0, 1), Remediations: (v.Remediations || []).filter(r => r.Type === 2) })) };
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({ revised: m.revised, doc }));
    return doc;
  }
  return {
    // CVEs open on this Windows build: months from the build's release month (one earlier, for late revisions) to now.
    async windowsCves(osInfo, { patchedThrough = null, maxMonths = 18 } = {}) {
      const product = windowsProductName(osInfo);
      if (!product) throw new Error('The Windows version is not known, so the Security Update Guide cannot be matched.');
      const installed = `10.0.${osInfo.build}.${osInfo.ubr ?? 0}`;
      const all = (await months()).sort((a, b) => monthIndex(a.id) - monthIndex(b.id));
      const from = patchedThrough ? monthIndex(monthId(patchedThrough)) - 1 : monthIndex(all.at(-1).id) - maxMonths;
      const seen = new Map();
      for (const m of all.filter(x => monthIndex(x.id) >= from).slice(-maxMonths)) for (const c of openCves(await month(m), product, installed)) if (!seen.has(c.cve)) seen.set(c.cve, c);
      return { product, installed, cves: [...seen.values()] };
    },
  };
}
