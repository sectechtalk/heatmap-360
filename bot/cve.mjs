// Version check for CISA KEV candidates. CISA's catalog names a vendor and product but no versions, so on its own
// every match is only a candidate. The official CVE record (CVE Program, published as cvelistV5 on GitHub) carries the
// affected version ranges from the vendor that issued the CVE (Microsoft, Google, Mozilla, Adobe...) and from CISA's
// own enrichment. Comparing the installed version with those ranges turns a candidate into one of:
//   affected    the installed version is inside a vulnerable range
//   patched     the vendor lists ranges and the installed version is outside all of them
//   unverified  the record has no usable version data, or the program is a relative of the listed product (Edge for
//               Chromium) with its own version numbers
// Pure functions except createCveLookup.
import { compareVersions } from './apps.mjs';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

export const CVE_RAW = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves';
const CVE_ID = /^CVE-(\d{4})-(\d{4,7})$/;
export const cveRecordUrl = id => { const m = CVE_ID.exec(String(id)); return m ? `${CVE_RAW}/${m[1]}/${Math.floor(Number(m[2]) / 1000)}xxx/${id}.json` : null; };
export const cvePage = id => `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;

const norm = s => String(s ?? '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const tokens = s => norm(s).split(' ').filter(Boolean);
const isVer = v => typeof v === 'string' && /^\d+(\.\d+)*([.\-+_]?[0-9a-z]+)*$/i.test(v.trim());
const major = v => Number(String(v).split('.')[0]);

// Every "affected" block from the vendor (CNA) and from CISA's enrichment (ADP).
export function affectedEntries(record) {
  const c = record?.containers || {};
  const blocks = [...(c.cna?.affected || []), ...(Array.isArray(c.adp) ? c.adp : []).flatMap(a => a?.affected || [])];
  return blocks.filter(a => a && typeof a === 'object' && Array.isArray(a.versions))
    .map(a => ({ vendor: String(a.vendor ?? ''), product: String(a.product ?? ''), defaultStatus: a.defaultStatus ?? null, versions: a.versions.filter(v => v && typeof v === 'object') }));
}

// Affected ranges of one block: { start|null, lt|null, lte|null } or { exact }.
export function ranges(entry) {
  const out = [];
  for (const v of entry.versions) {
    if ((v.status ?? entry.defaultStatus) !== 'affected') continue;
    let start = isVer(v.version) && !/^0+$/.test(v.version) ? v.version.trim() : null;
    const lt = isVer(v.lessThan) ? v.lessThan.trim() : null;
    const lte = isVer(v.lessThanOrEqual) ? v.lessThanOrEqual.trim() : null;
    // Some vendors repeat the fixed version as the start ("version 134.0.6998.177, lessThan 134.0.6998.177"): an
    // empty range like that means "everything before".
    if (start && ((lt && compareVersions(start, lt) >= 0) || (lte && compareVersions(start, lte) > 0))) start = null;
    if (lt || lte) out.push({ start, lt, lte });
    else if (start) out.push({ exact: start });
  }
  return out;
}

const inside = (v, r) => (!r.start || compareVersions(v, r.start) >= 0) && (r.lt ? compareVersions(v, r.lt) < 0 : compareVersions(v, r.lte) <= 0);
const fixText = r => (r.lt ? r.lt : `newer than ${r.lte}`);

// Installed version against a list of ranges. Vendors list one open-ended range per release branch ("Firefox ESR
// < 128.3.1" and "< 115.16.1"): an open-ended range only applies to the nearest branch at or above the installed
// major version, so 115.17 is judged against 115.16.1 and not against 128.3.1.
export function versionVerdict(installed, list, { majorOnly = false } = {}) {
  if (!isVer(installed)) return { verdict: 'unverified', why: 'The installed version is not a plain version number.' };
  const bounded = list.filter(r => r.lt || r.lte);
  const exact = list.filter(r => r.exact);
  if (!bounded.length) {
    if (exact.some(r => compareVersions(installed, r.exact) === 0)) return { verdict: 'affected', why: `Version ${installed} is listed as affected.` };
    return { verdict: 'unverified', why: exact.length ? 'The CVE record lists single affected versions only; compare by hand.' : 'The CVE record has no affected version numbers.' };
  }
  if (majorOnly) {
    const fix = [...new Set(bounded.map(r => r.lt || r.lte))].sort(compareVersions);
    const m = major(installed);
    if (fix.every(f => major(f) < m)) return { verdict: 'patched', why: `Version ${installed} is a newer major release than every fixed version (${fix.join(', ')}).` };
    if (fix.every(f => major(f) > m)) return { verdict: 'affected', why: `Version ${installed} is an older major release than the fix (${fix[0]}).` };
    return { verdict: 'unverified', why: `Same major version as the fix (${fix.join(', ')}); this program numbers its builds differently, so compare its own release notes.` };
  }
  const anchored = bounded.filter(r => r.start);
  const open = bounded.filter(r => !r.start).sort((a, b) => compareVersions(a.lt || a.lte, b.lt || b.lte));
  const first = open.find(r => major(r.lt || r.lte) >= major(installed));
  const branch = first ? open.filter(r => major(r.lt || r.lte) === major(first.lt || first.lte)) : [];
  const hit = [...anchored, ...branch].find(r => inside(installed, r)) || (exact.find(r => compareVersions(installed, r.exact) === 0) && { exact: true });
  if (hit) return { verdict: 'affected', fixedIn: hit.exact ? null : fixText(hit), why: hit.exact ? `Version ${installed} is listed as affected.` : `Version ${installed} is in the affected range; fixed in ${fixText(hit)}.` };
  return { verdict: 'patched', why: `Version ${installed} is outside every affected range the vendor lists.` };
}

// Blocks in the record that describe this program: the most specific product name wins (Firefox ESR over Firefox for
// "Mozilla Firefox ESR", Firefox over Firefox ESR for "Mozilla Firefox").
export function entriesForApp(entries, appName) {
  const name = new Set(tokens(appName));
  const scored = entries.map(e => {
    const t = tokens(e.product).filter(x => x !== 'and');
    const hit = t.filter(x => name.has(x)).length;
    return { e, full: t.length > 0 && hit === t.length, hit, share: t.length ? hit / t.length : 0 };
  }).filter(s => s.hit > 0);
  if (!scored.length) return [];
  scored.sort((a, b) => (b.full - a.full) || (b.hit - a.hit) || (b.share - a.share));
  const best = scored[0];
  return scored.filter(s => s.full === best.full && s.hit === best.hit && s.share === best.share).map(s => s.e);
}

// Windows: Microsoft lists every affected build line as 10.0.<build>.0 up to 10.0.<build>.<fixed revision>.
export function windowsVerdict(os, entries) {
  if (!os?.build) return { verdict: 'unverified', why: 'The scan did not report the Windows build.' };
  const installed = `10.0.${os.build}.${os.ubr ?? 0}`;
  let sawBuilds = false;
  for (const e of entries.filter(x => /windows/i.test(x.product))) {
    for (const r of ranges(e)) {
      const bound = r.lt || r.lte;
      const m = bound && /^10\.0\.(\d+)\.\d+$/.exec(bound);
      if (!m) continue;
      sawBuilds = true;
      if (Number(m[1]) !== os.build) continue;
      return inside(installed, r)
        ? { verdict: 'affected', fixedIn: bound, why: `Build ${os.build}.${os.ubr ?? 0} is affected; fixed in ${bound} (${e.product}).` }
        : { verdict: 'patched', why: `Build ${os.build}.${os.ubr ?? 0} includes the fix (${bound}, ${e.product}).` };
    }
  }
  return sawBuilds ? { verdict: 'patched', why: `Microsoft does not list build ${os.build} as affected.` }
    : { verdict: 'unverified', why: 'The CVE record has no Windows build numbers.' };
}

export function verdictFor(candidate, record, inv) {
  if (!record) return { verdict: 'unverified', why: 'No CVE record was found for this ID.' };
  const entries = affectedEntries(record);
  if (candidate.kind === 'os') return windowsVerdict(inv.os, entries);
  const mine = entriesForApp(entries, candidate.app);
  if (mine.length) return versionVerdict(candidate.version, mine.flatMap(ranges));
  // A relative of the listed product (Edge or Brave for a Chromium CVE): only the major version is comparable.
  const kin = entries.filter(e => tokens(e.vendor).some(t => norm(candidate.vendor).includes(t)));
  if (kin.length && candidate.related) return versionVerdict(candidate.version, kin.flatMap(ranges), { majorOnly: true });
  return { verdict: 'unverified', why: `The CVE record does not name ${candidate.app}.` };
}

// Looks up candidates `concurrency` at a time; a failed lookup marks only that candidate unverified.
export async function verifyCandidates(candidates, inv, cveRecord, { concurrency = 8, limit = 400 } = {}) {
  const out = [];
  async function one(c, i) {
    if (i >= limit) return (out[i] = { ...c, verdict: 'unverified', why: 'Over the per-scan lookup limit.' });
    try { out[i] = { ...c, ...verdictFor(c, await cveRecord(c.cveID), inv) }; }
    catch (e) { out[i] = { ...c, verdict: 'unverified', why: `CVE record lookup failed: ${String(e.message || e).slice(0, 120)}` }; }
  }
  for (let i = 0; i < candidates.length; i += concurrency) await Promise.all(candidates.slice(i, i + concurrency).map((c, k) => one(c, i + k)));
  return out.map(c => ({ ...c, record: cvePage(c.cveID) }));
}

// Disk-cached CVE records (they change rarely): refreshed after `maxAgeMs`, the stale copy is used if GitHub is down.
export function createCveLookup({ dir, fetchImpl = (...a) => fetch(...a), now = () => Date.now(), maxAgeMs = 7 * 86_400_000 } = {}) {
  const memo = new Map();
  return id => {
    const url = cveRecordUrl(id);
    if (!url) return Promise.reject(new Error(`${String(id).slice(0, 30)} is not a CVE ID`));
    if (memo.has(id)) return memo.get(id);
    const file = dir ? path.join(dir, 'cve', `${id}.json`) : null;
    const p = (async () => {
      let cached = null;
      if (file) { try { cached = JSON.parse(await readFile(file, 'utf8')); } catch { /* not cached */ } }
      if (cached && now() - Date.parse(cached.fetchedAt) < maxAgeMs) return cached.record;
      try {
        const r = await fetchImpl(url, { headers: { 'user-agent': 'hm360-bot' }, signal: AbortSignal.timeout(20_000) });
        if (r.status === 404) return null;
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const full = await r.json();
        const c = full.containers || {};
        // Keep only what the version check reads.
        const record = { cveMetadata: { cveId: full.cveMetadata?.cveId }, containers: { cna: { affected: c.cna?.affected || [] }, adp: (c.adp || []).map(a => ({ affected: a.affected || [] })).filter(a => a.affected.length) } };
        if (file) { await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, JSON.stringify({ fetchedAt: new Date(now()).toISOString(), record })); }
        return record;
      } catch (e) { if (cached) return cached.record; throw e; }
    })();
    memo.set(id, p);
    p.catch(() => memo.delete(id));
    return p;
  };
}
