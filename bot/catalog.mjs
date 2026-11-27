// HeatMap 360 inventory catalog: every inventoried item (software, driver, firmware, Windows build...) stored ONCE per
// version, in the same findings table as the machine rows (bot/findings.mjs), so nothing is stored twice.
//
//   catalog-<kind> / <item + version>     one row per distinct item and version across all machines: name, vendor,
//                                         version, the lookup answer (Status, LatestVersion, KnownIssues, ExploitedCVEs,
//                                         Note, Source, LastChecked), FirstSeen and LastSeen anywhere.
//   <machine id>   / <kind>|<item>|<hash> one small pointer per item per machine (CatalogRK, InstalledVersion, dates);
//                                         no lookup answer is copied onto it.
//   <machine id>   / install|...          install history: an item installed, changed version or removed on a machine.
//                                         Written only when something changes, never once per scan.
//   history-<kind> / <catalog row>|<time> check history: what changed in an item version's answer and when (first
//                                         check, newly exploited CVE, new known problem, update available...).
//
// Each version keeps its own catalog row: several versions side by side are shown, never merged.
import { createHash } from 'node:crypto';
import { compareVersions } from './apps.mjs';

// Kinds that are things with a version, kept in the catalog. Measurements (events, network health, volumes, settings)
// and installed Windows updates stay as per-machine rows: they describe one computer, so they are not duplicates.
export const CATALOG_KINDS = new Set(['os', 'app', 'winget-package', 'bios', 'driver', 'network-adapter', 'disk', 'baseboard', 'cpu', 'security']);
// Only security items that are software or firmware with a version (not BitLocker or firewall settings).
const SECURITY_ITEMS = new Set(['defender', 'tpm']);
export const isCatalogItem = r => CATALOG_KINDS.has(r.kind) && (r.kind !== 'security' || SECURITY_ITEMS.has(r.item_key));

// Which parts of an item's detail describe the item version itself (stored once in the catalog) and which describe one
// computer (uptime, disk health, link speed: kept on that machine's pointer row).
const CATALOG_DETAIL = { os: ['displayVersion', 'edition', 'architecture', 'build', 'ubr'], bios: ['system', 'baseboard'], 'winget-package': ['source'], driver: ['class', 'manufacturer'] };
export function splitDetail(kind, detail) {
  const d = detail ? JSON.parse(detail) : null;
  if (!d) return { catalog: null, machine: null };
  const keep = CATALOG_DETAIL[kind] || [];
  const pick = names => { const o = Object.fromEntries(Object.entries(d).filter(([k]) => names(k))); return Object.keys(o).length ? JSON.stringify(o) : null; };
  return { catalog: pick(k => keep.includes(k)), machine: pick(k => !keep.includes(k)) };
}

export const CATALOG_PREFIX = 'catalog-';
export const HISTORY_PREFIX = 'history-';
export const INSTALL_PREFIX = 'install|';
const safe = v => String(v).replace(/[/\\#?\u0000-\u001f\u007f-\u009f]/g, '_');
const hash = (...parts) => createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 10);

// Where an item version lives in the catalog. The readable part is for people browsing the table; the hash keeps two
// items that clean up alike apart.
export function catalogRef(kind, itemKey, version) {
  const base = String(itemKey).replace(/#\d+$/, ''); // a second identical disk is the same catalog item
  return { partitionKey: `${CATALOG_PREFIX}${kind}`, rowKey: `${safe(base).slice(0, 120)}|${safe(version ?? '').slice(0, 60)}|${hash(kind, base, version ?? '')}` };
}

export const isCatalogRow = e => String(e.partitionKey).startsWith(CATALOG_PREFIX);
export const isHistoryRow = e => String(e.partitionKey).startsWith(HISTORY_PREFIX);
export const isInstallRow = e => String(e.rowKey).startsWith(INSTALL_PREFIX);

export function installRow(pk, { pointerRK, itemKey, kind, change, from = null, to = null, at, scanId }) {
  return { partitionKey: pk, rowKey: `${INSTALL_PREFIX}${at}|${hash(pointerRK, change, from ?? '', to ?? '')}`, Category: 'History', Kind: 'install-history',
    ItemKind: kind, ItemKey: itemKey, PointerRK: pointerRK, Change: change, FromVersion: from, ToVersion: to, At: at, ScanId: scanId,
    FromCatalogRK: from != null ? catalogRef(kind, itemKey, from).rowKey : null, ToCatalogRK: to != null ? catalogRef(kind, itemKey, to).rowKey : null };
}

// ---------- check history ----------

const parse = s => { try { return s ? JSON.parse(s) : []; } catch { return []; } };
// What changed between two lookup answers (table columns), as dated history lines. Nothing is written for an unchanged
// answer or a failed lookup.
export function answerChanges(prev, next, version) {
  if (!next.LastChecked || next.LookupStatus === 'failed') return [];
  const out = [];
  const add = (change, text, source = next.Source ?? null) => out.push({ change, text, source });
  if (!prev?.LastChecked) {
    const bits = [next.Status];
    if (next.LatestVersion && version && compareVersions(next.LatestVersion, version) > 0) bits.push(`newest is ${next.LatestVersion}`);
    if (next.ExploitedCount) bits.push(`${next.ExploitedCount} exploited CVE${next.ExploitedCount > 1 ? 's' : ''}`);
    if (next.KnownIssueCount) bits.push(`${next.KnownIssueCount} known problem${next.KnownIssueCount > 1 ? 's' : ''}`);
    if (next.CveCount) bits.push(`${next.CveCount} CVE${next.CveCount > 1 ? 's' : ''} (${next.CveSource})`);
    add('first-check', `First check: ${bits.join(', ')}.`);
    for (const c of parse(next.ExploitedCVEs)) add('exploited', `Actively exploited: ${c.cve}${c.name ? ` (${c.name})` : ''}${c.ransomware ? ', used by ransomware' : ''}.`, c.record || next.Source);
    for (const i of parse(next.KnownIssues)) add('known-problem', `Known problem: ${i.title}`, i.source || next.Source);
    return out;
  }
  const cves = list => new Map(parse(list).map(c => [c.cve, c]));
  const [pc, nc] = [cves(prev.ExploitedCVEs), cves(next.ExploitedCVEs)];
  for (const [id, c] of nc) if (!pc.has(id)) add('exploited', `Newly exploited: ${id}${c.name ? ` (${c.name})` : ''}${c.ransomware ? ', used by ransomware' : ''}.`, c.record || next.Source);
  for (const id of pc.keys()) if (!nc.has(id)) add('exploited-cleared', `No longer matched: ${id}.`);
  const issues = list => new Map(parse(list).map(i => [i.title, i]));
  const [pi, ni] = [issues(prev.KnownIssues), issues(next.KnownIssues)];
  for (const [t, i] of ni) if (!pi.has(t)) add('known-problem', `Known problem reported: ${t}`, i.source || next.Source);
  for (const t of pi.keys()) if (!ni.has(t)) add('known-problem-cleared', `Known problem resolved or no longer listed: ${t}`);
  if (next.LatestVersion && next.LatestVersion !== prev.LatestVersion && version && compareVersions(next.LatestVersion, version) > 0)
    add('update', `Update available: ${next.LatestVersion}${next.LatestDate ? ` (${String(next.LatestDate).slice(0, 10)})` : ''}.`);
  if (next.LookupStatus === 'unsupported' && prev.LookupStatus !== 'unsupported') add('unsupported', 'No longer supported by the vendor.');
  // CVEs: one line per new CVE, or one summary line when a source adds many at once (a Windows build can gain dozens).
  const cveIds = list => new Map(parse(list).map(c => [c.cve, c]));
  const [pv, nv] = [cveIds(prev.Cves), cveIds(next.Cves)];
  const added = [...nv.values()].filter(c => !pv.has(c.cve));
  const grew = (next.CveCount ?? 0) - (prev.CveCount ?? 0);
  if (added.length && added.length <= 5) for (const c of added) add('cve', `New CVE: ${c.cve}${c.score != null ? ` (CVSS ${c.score})` : ''}${c.title ? `: ${c.title}` : ''}`, c.record || next.Source);
  else if (added.length || grew > 0) add('cve', `${Math.max(added.length, grew)} new CVEs from ${next.CveSource || 'the CVE sources'}; now ${next.CveCount ?? 0} in total. Highest: ${[...nv.values()][0]?.cve || 'n/a'}.`);
  if ((prev.CveCount ?? 0) > 0 && !next.CveCount && next.CveSource) add('cve-cleared', 'No CVE matches this version any more.');
  if (next.CpeMatch && next.CpeMatch !== prev.CpeMatch && ['confirmed', 'rejected'].includes(next.CpeMatch)) add('product', next.CpeMatch === 'confirmed' ? `Product confirmed as ${next.Cpe}.` : 'Product match rejected; no NVD CVEs are checked for it.');
  return out;
}

export function historyRows(catalogRow, changes, at) {
  return changes.map((c, i) => ({ partitionKey: `${HISTORY_PREFIX}${catalogRow.Kind}`, rowKey: `${catalogRow.rowKey}|${at}|${String(i).padStart(2, '0')}`,
    Category: 'History', Kind: 'check-history', ItemKind: catalogRow.Kind, ItemKey: catalogRow.ItemKey, CatalogRK: catalogRow.rowKey, Name: catalogRow.Name,
    Version: catalogRow.Version, At: at, Change: c.change, Text: String(c.text).slice(0, 1000), Source: c.source }));
}

// ---------- snapshot for the Inventory catalog page ----------

const MACHINE = /^[0-9a-f]{16}$/;
const MAX_HISTORY = 100;
// Everything in the table -> one JSON the web app shows: items, each with its versions (newest first), the machines on
// each version (anonymous ids), the check history and the install history. Pure: no I/O.
export function buildSnapshot(entities, { now = Date.now(), choices = {} } = {}) {
  const items = new Map();
  const itemOf = (kind, itemKey) => {
    const k = `${kind}\u0000${String(itemKey).replace(/#\d+$/, '')}`;
    if (!items.has(k)) items.set(k, { kind, itemKey: String(itemKey).replace(/#\d+$/, ''), name: null, vendor: null, category: null, versions: [], history: [], installs: [], product: null });
    return items.get(k);
  };
  const versionByRK = new Map();
  for (const e of entities.filter(isCatalogRow)) {
    const it = itemOf(e.Kind, e.ItemKey);
    it.name ??= e.Name; it.vendor ??= e.Vendor; it.category ??= e.Category;
    const v = { catalogKey: e.rowKey, version: e.Version ?? null, itemDate: e.ItemDate ?? null, status: e.Status ?? 'Pending', lookup: e.LookupStatus ?? null,
      latest: e.LatestVersion ?? null, latestDate: e.LatestDate ?? null, note: e.Note ?? null, source: e.Source ?? null, lastChecked: e.LastChecked ?? null,
      issues: parse(e.KnownIssues), exploited: parse(e.ExploitedCVEs), firstSeen: e.FirstSeen ?? null, lastSeen: e.LastSeen ?? null, machines: [],
      cveCount: e.CveCount ?? 0, cveMax: e.CveMaxScore ?? null, cves: parse(e.Cves), cveSource: e.CveSource ?? null, lookupFailed: e.LookupFailed === true };
    if (e.ProductKey && !it.product) it.product = { key: e.ProductKey, status: e.CpeMatch ?? null, cpe: e.Cpe ?? null, candidates: parse(e.CpeCandidates) };
    it.versions.push(v);
    versionByRK.set(`${e.Kind}\u0000${e.rowKey}`, v);
  }
  for (const e of entities) {
    if (!MACHINE.test(e.partitionKey || '') || !e.CatalogRK || e.Removed) continue;
    const v = versionByRK.get(`${e.Kind}\u0000${e.CatalogRK}`);
    if (v && !v.machines.includes(e.partitionKey)) v.machines.push(e.partitionKey);
  }
  for (const e of entities.filter(isHistoryRow)) {
    const it = items.get(`${e.ItemKind}\u0000${e.ItemKey}`);
    if (it) it.history.push({ at: e.At, version: e.Version ?? null, change: e.Change, text: e.Text, source: e.Source ?? null });
  }
  for (const e of entities.filter(isInstallRow)) {
    const it = items.get(`${e.ItemKind}\u0000${String(e.ItemKey).replace(/#\d+$/, '')}`);
    if (it) it.installs.push({ at: e.At, machine: e.partitionKey, change: e.Change, from: e.FromVersion ?? null, to: e.ToVersion ?? null });
  }
  const RANK = { Exploited: 0, Unsupported: 1, Vulnerable: 2, 'Known problems': 3, Outdated: 4, 'Lookup failed': 5, Pending: 6, 'Not checked': 7, Info: 8, Current: 9 };
  const out = [...items.values()].filter(it => it.versions.length).map(it => {
    it.versions.sort((a, b) => compareVersions(b.version || '0', a.version || '0'));
    it.history.sort((a, b) => b.at.localeCompare(a.at)); it.history = it.history.slice(0, MAX_HISTORY);
    it.installs.sort((a, b) => b.at.localeCompare(a.at)); it.installs = it.installs.slice(0, MAX_HISTORY);
    if (it.product && Object.hasOwn(choices, it.product.key)) it.product.choice = choices[it.product.key];
    const live = it.versions.filter(v => v.machines.length);
    it.status = (live.length ? live : it.versions).map(v => v.status).sort((a, b) => (RANK[a] ?? 9) - (RANK[b] ?? 9))[0];
    return it;
  }).sort((a, b) => (RANK[a.status] ?? 9) - (RANK[b.status] ?? 9) || String(a.name).localeCompare(String(b.name)));
  const machines = new Set(entities.filter(e => MACHINE.test(e.partitionKey || '') && e.rowKey === 'machine').map(e => e.partitionKey));
  return { schema: 'hm360.catalog/1', generatedAt: new Date(now).toISOString(), machines: machines.size,
    versions: out.reduce((n, it) => n + it.versions.length, 0), items: out };
}
