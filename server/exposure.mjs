// "Are we affected?": matches every exploit on the High impact list against the newest scan of each scanned computer.
// Report only: it never changes anything, never contacts a computer and never posts. Fixing belongs to Remediation 360.
//
// For each exploit item and each computer:
//   1. If the bot already judged that CVE for that scan (results/<id>.json, section "exploited"), its verdict is used.
//   2. Otherwise the CVE is matched here, with the same code the bot uses (bot/health.mjs kevCandidates, then
//      bot/cve.mjs version ranges from the official CVE record). So a scan taken before CISA listed the CVE is still
//      checked against it, without a new scan.
// The product names come from CISA's catalog entry; a headline whose CVE is not in the catalog uses the vendor and
// product names in its CVE record. A headline that names no CVE cannot be matched and says so.
//
// Verdicts per computer: affected (vulnerable version installed), verify (a matching program is installed but the
// version cannot be judged from the record), patched (matching program, fixed version), clear (nothing installed
// matches, or Windows has updates newer than the listing).
import { kevCandidates } from '../bot/health.mjs';
import { verifyCandidates, affectedEntries, createCveLookup } from '../bot/cve.mjs';

const MIN = 60_000, DAY = 86_400_000;
export const STALE_DAYS = 30; // a scan older than this is flagged: the computer may have changed since

// The newest processed scan of each computer (by anonymous machine id), newest first.
export function latestPerMachine(results) {
  const best = new Map();
  for (const r of results) {
    if (!r || r.rejected || !r.inventory?.machineId) continue;
    const at = r.inventory.collectedAt || r.receivedAt || '';
    const cur = best.get(r.inventory.machineId);
    if (!cur || at > (cur.inventory.collectedAt || cur.receivedAt || '')) best.set(r.inventory.machineId, r);
  }
  return [...best.values()].sort((a, b) => String(b.inventory.collectedAt || b.receivedAt).localeCompare(String(a.inventory.collectedAt || a.receivedAt)));
}

export function machineOf(r, now = Date.now()) {
  const inv = r.inventory, sys = inv.hardware?.system || {};
  const scannedAt = inv.collectedAt || r.receivedAt || null;
  return { machineId: inv.machineId, scanId: r.id, scannedAt,
    computer: [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'Unknown computer',
    windows: inv.os ? `${inv.os.name || 'Windows'} ${inv.os.displayVersion || ''}`.trim() : null,
    stale: Boolean(scannedAt) && now - Date.parse(scannedAt) > STALE_DAYS * DAY };
}

const VERDICT = { affected: 'affected', unverified: 'verify', patched: 'patched' };
const what = c => (c.kind === 'os' ? 'Windows' : [c.app, c.version].filter(Boolean).join(' ')) || c.product || 'Installed program';

// The bot's own verdicts for these CVEs in this scan, or null when the bot did not list any of them.
export function botMatches(result, cves) {
  const ex = result.exploited;
  if (!ex || ex.status !== 'checked') return null;
  const hits = ['affected', 'unverified', 'patched'].flatMap(k => (ex[k] || []).filter(c => cves.includes(String(c.cveID).toUpperCase())).map(c => ({ ...c, verdict: VERDICT[k] })));
  return hits.length ? hits.map(c => ({ cve: c.cveID, verdict: c.verdict, product: what(c), why: c.why || c.reason || null, fixedIn: c.fixedIn || null, source: 'scan' })) : null;
}

// Catalog-shaped entries for the item: CISA's own entries first, then the CVE record's vendor/product names.
export async function entriesFor(item, { kevById, cveRecord }) {
  const out = [], failed = [];
  for (const cve of item.cves || []) {
    const k = (item.kev || []).find(e => e.cveID === cve) || kevById.get(cve);
    if (k) { out.push(k); continue; }
    try {
      const record = await cveRecord(cve);
      const names = record ? affectedEntries(record).filter(e => e.vendor && e.product && !/^n\/?a$/i.test(e.product)) : [];
      const seen = new Set();
      for (const e of names) {
        const key = `${e.vendor}|${e.product}`.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ cveID: cve, vendorProject: e.vendor, product: e.product, vulnerabilityName: '', dateAdded: (item.started || '').slice(0, 10) || null, knownRansomwareCampaignUse: '' });
      }
      if (!names.length) failed.push(`${cve}: the CVE record names no product`);
    } catch (e) { failed.push(`${cve}: CVE record lookup failed (${String(e.message || e).slice(0, 80)})`); }
  }
  return { entries: out, failed };
}

// Every computer's verdict for one item.
export async function matchItem(item, scans, { kevById, cveRecord, now = Date.now() }) {
  const cves = (item.cves || []).map(c => c.toUpperCase());
  const machines = [];
  if (!cves.length) return { call: scans.length ? 'cannot-check' : 'no-scans', note: 'The headline names no CVE, so it cannot be matched to installed programs. Read the sources.', machines, counts: count([]) };
  const { entries, failed } = await entriesFor(item, { kevById, cveRecord });
  for (const r of scans) {
    const m = machineOf(r, now);
    let hits = botMatches(r, cves);
    if (!hits && entries.length) {
      const candidates = kevCandidates(r.inventory, { vulnerabilities: entries });
      hits = candidates.length
        ? (await verifyCandidates(candidates, r.inventory, cveRecord)).map(c => ({ cve: c.cveID, verdict: VERDICT[c.verdict] || 'verify', product: what(c), why: c.why || c.reason || null, fixedIn: c.fixedIn || null, source: 'recheck' }))
        : [];
    }
    if (!hits) hits = [];
    const worst = ['affected', 'verify', 'patched'].find(v => hits.some(x => x.verdict === v)) || (entries.length ? 'clear' : 'unknown');
    machines.push({ ...m, verdict: worst, matches: hits,
      why: worst === 'clear' ? 'Nothing installed matches the product, or Windows has updates newer than the listing.' : worst === 'unknown' ? 'Could not tell which product this CVE is about.' : null });
  }
  const counts = count(machines);
  const critical = item.level === 'critical';
  const call = !scans.length ? 'no-scans'
    : counts.affected ? (critical ? 'act-now' : 'affected')
      : counts.verify ? 'verify'
        : !entries.length ? 'cannot-check'
          : 'clear';
  return { call, note: failed.length ? `Not fully checked: ${failed.join('; ')}.` : null, machines, counts };
}

function count(machines) {
  const c = { affected: 0, verify: 0, patched: 0, clear: 0, unknown: 0 };
  for (const m of machines) c[m.verdict]++;
  return c;
}

export const CALLS = {
  'act-now': 'Act now: a vulnerable version is installed and the exploit is critical (ransomware use or widely reported).',
  affected: 'Affected: a vulnerable version is installed on at least one scanned computer.',
  verify: 'Check by hand: a matching program is installed, but the CVE record does not say whether this version is fixed.',
  'cannot-check': 'Cannot check: the item does not name a product HeatMap 360 can match.',
  clear: 'Not affected: no scanned computer has a vulnerable version.',
  'no-scans': 'No scans yet: upload a scan to check.',
};
const ORDER = Object.keys(CALLS);

export function describeExposureRules() {
  return [
    'Every exploit on the High impact list is checked against the newest scan of each scanned computer. Disruptions are cloud outages, not software on a computer, so they are not matched.',
    'If the bot already judged that CVE when it processed the scan, its verdict is used. Otherwise HeatMap 360 matches it now with the same rules: the product names from CISA’s catalog (or from the CVE record), then the affected version ranges in the official CVE record.',
    `Act now = a vulnerable version is installed and the item is critical. A scan older than ${STALE_DAYS} days is marked old, because the computer may have been updated since.`,
    'Fixing is out of scope here: Remediation 360 owns changes to computers.',
  ];
}

// attention() is the High impact reader; loadScans() returns the processed results to consider.
export function createExposure({ attention, loadScans, cveRecord = createCveLookup({}), now = () => Date.now(), ttlMs = 15 * MIN } = {}) {
  let cache = null;
  async function build() {
    const t = now();
    const [att, results, catalog] = await Promise.all([attention(), loadScans(), attention.kevCatalog ? attention.kevCatalog().catch(() => null) : null]);
    const kevById = new Map((catalog?.vulnerabilities || []).map(v => [String(v.cveID).toUpperCase(), v]));
    const scans = latestPerMachine(results);
    const exploits = att.items.filter(i => i.kind === 'exploit');
    const items = [];
    for (const it of exploits) {
      const m = await matchItem(it, scans, { kevById, cveRecord, now: t });
      items.push({ id: it.id, title: it.title, level: it.level, cves: it.cves, started: it.started, seen: it.seen, ransomware: Boolean(it.ransomware), why: it.why, sources: it.sources, ...m });
    }
    items.sort((a, b) => ORDER.indexOf(a.call) - ORDER.indexOf(b.call) || (a.level === b.level ? 0 : a.level === 'critical' ? -1 : 1) || String(b.seen || '').localeCompare(String(a.seen || '')));
    return {
      checkedAt: new Date(t).toISOString(), highImpactCheckedAt: att.checkedAt,
      machines: scans.map(r => machineOf(r, t)),
      items, calls: CALLS, rules: describeExposureRules(),
      disruptionsSkipped: att.items.length - exploits.length,
      kev: att.sources?.kev || null,
    };
  }
  return async function get({ fresh = false } = {}) {
    if (!fresh && cache && now() - cache.at < ttlMs) return cache.value;
    const value = build();
    cache = { at: now(), value };
    value.catch(() => { if (cache?.value === value) cache = null; });
    return value;
  };
}
