#!/usr/bin/env node
// HeatMap 360 findings store, in ONE Azure Table Storage table (`findings`).
//
//   PartitionKey = the scanner's anonymous machine id (16 hex).
//   RowKey       = <Kind>|<readable item id>|<8-hex hash>, so each item has exactly one row per machine. Every new scan
//                  of that machine updates the row (LastSeen, version...). Items gone from the newest scan get Removed=true.
//   One extra row per machine (RowKey "machine", Category "Machine") holds the newest scan's summary.
//
// Items with a version (software, drivers, firmware, the Windows build, disks, CPUs...) are de-duplicated: the machine
// row is only a pointer (CatalogRK + InstalledVersion), and the item version itself, with its lookup answer, is stored
// once in the inventory catalog (partition catalog-<kind>, see bot/catalog.mjs). Install history (installed, changed
// version, removed) and check history (newly exploited, new known problem, update available...) are kept as rows too,
// written only when something changes.
//
// Category is the coarse group for filtering (Windows, Patch, Application, Firmware, Driver, Hardware, Disk, Network,
// Security, Events, Scan); Kind is the exact type (os, windows-update, app, winget-package, bios, ...).
//
// A background job looks each catalog row (one item version, across all machines) up with the official sources the bot
// already uses (Microsoft release health, winget catalog and publisher release notes, CISA KEV checked against CVE
// records, HP/Lenovo catalogs) and writes the answer onto that one row: Status, LatestVersion, KnownIssues,
// ExploitedCVEs. Rechecked after `maxAgeHours`, capped per run; a failed lookup keeps the last good answer.
// After each run it writes catalog/catalog.json (the Inventory catalog page) into --snapshot, else the first --repo.
//
// Reads the bot's results/*.json (each holds the scan's inventory and the bot's verdicts). Read-only toward computers
// and the data repositories. Sign-in: Entra (`--credential cli`, the default: the desktop's `az login`, never a machine
// identity such as Azure Arc's; `--credential managed-identity` when the job runs in Azure), role "Storage Table
// Data Contributor" on the storage account. No keys or connection strings.
//
//   node bot/findings.mjs --repo <folder with results/> [--repo ...] [--account <name>] [--table findings] [--credential cli]
//                         [--import-only|--lookup-only] [--limit 40] [--max-age-hours 24] [--cache <folder>]
//                         [--snapshot <folder>|--no-snapshot]
// Where the table lives: --account/--table if given, else settings/findings.json in the first --repo that has one
// (set by Settings Admins on the Settings page, so the storage can move without a code change), else
// HM360_TABLES_ACCOUNT / HM360_TABLES_TABLE. The storage account itself is created by hand in Azure, never by code;
// the job only creates the table inside it when missing.
import { readFile, readdir, mkdir, writeFile, rename } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareVersions, WINGET_REPO, manifestPath } from './apps.mjs';
import { windowsStatus, windowsGeneration, knownIssuesUrl, parseKnownIssues, evaluateIssues, RELEASE_PAGES } from './windows.mjs';
import { firmwareStatus } from './firmware.mjs';
import { kevCandidates } from './health.mjs';
import { verifyCandidates } from './cve.mjs';
import { knownIssuesSection } from './appissues.mjs';
import { sortCves, productKey, matchProduct, createNvd } from './nvd.mjs';
import { createMsrc } from './msrc.mjs';
import { CATALOG_PREFIX, catalogRef, isCatalogItem, isCatalogRow, isInstallRow, splitDetail, installRow, answerChanges, historyRows, buildSnapshot } from './catalog.mjs';

const ID = /^[0-9]{14}-[0-9a-f]{8}$/;
const MACHINE = /^[0-9a-f]{16}$/;
const ACCOUNT = /^[a-z0-9]{3,24}$/;
const TABLE = /^[A-Za-z][A-Za-z0-9]{2,62}$/;

// ---------- stores ----------

// Azure Table Storage. Only the account NAME is configured; the URL is built here, so nothing else can be targeted.
// Which Entra sign-in the job uses. "cli" is the default on purpose: on a desktop enrolled in Azure Arc,
// DefaultAzureCredential would pick the machine's managed identity first, which has no role on the storage account.
export const CREDENTIALS = ['cli', 'managed-identity', 'default'];
export async function makeCredential(kind = 'cli') {
  if (!CREDENTIALS.includes(kind)) throw new Error(`--credential must be one of ${CREDENTIALS.join(', ')}`);
  const id = await import('@azure/identity');
  if (kind === 'cli') return new id.ChainedTokenCredential(new id.AzureCliCredential(), new id.AzurePowerShellCredential());
  if (kind === 'managed-identity') return new id.ManagedIdentityCredential(process.env.AZURE_CLIENT_ID ? { clientId: process.env.AZURE_CLIENT_ID } : undefined);
  return new id.DefaultAzureCredential();
}

export async function createAzureStore({ account, table = 'findings', credential = null }) {
  if (!ACCOUNT.test(account || '')) throw new Error('Set the storage account name with --account or HM360_TABLES_ACCOUNT (3-24 lowercase letters and digits).');
  if (!TABLE.test(table)) throw new Error(`Invalid table name ${table}`);
  const { TableClient } = await import('@azure/data-tables');
  if (!credential || typeof credential === 'string') credential = await makeCredential(credential || 'cli');
  const client = new TableClient(`https://${account}.table.core.windows.net`, table, credential);
  await client.createTable().catch(e => { if (e.statusCode !== 409) throw e; }); // 409 = already there
  return tableStore(client, `${account}/${table}`);
}

// Full rows only: system fields and empty values are dropped and the row is replaced, so a stale value never survives.
export const clean = e => Object.fromEntries(Object.entries(e).filter(([k, v]) => v !== null && v !== undefined && k !== 'etag' && k !== 'timestamp' && !k.startsWith('odata')));

export function tableStore(client, label = 'table') {
  const esc = v => String(v).replace(/'/g, "''");
  const all = async filter => { const out = []; for await (const e of client.listEntities(filter ? { queryOptions: { filter } } : {})) out.push(e); return out; };
  return {
    label,
    partition: pk => all(`PartitionKey eq '${esc(pk)}'`),
    query: filter => all(filter),
    // Replace-upserts, up to 100 per transaction (one partition per transaction, as Table Storage requires).
    async upsert(entities) {
      const byPk = new Map();
      for (const e of entities.map(clean)) { if (!byPk.has(e.partitionKey)) byPk.set(e.partitionKey, []); byPk.get(e.partitionKey).push(e); }
      for (const list of byPk.values())
        for (let i = 0; i < list.length; i += 100) await client.submitTransaction(list.slice(i, i + 100).map(e => ['upsert', e, 'Replace']));
    },
  };
}

// In-memory store with the same behaviour, for tests and --dry-run.
export function memoryStore() {
  const rows = new Map();
  const k = e => `${e.partitionKey}\u0000${e.rowKey}`;
  return {
    label: 'memory', rows,
    partition: async pk => [...rows.values()].filter(e => e.partitionKey === pk).map(e => ({ ...e })),
    query: async () => [...rows.values()].map(e => ({ ...e })),
    async upsert(entities) { for (const e of entities.map(clean)) rows.set(k(e), e); },
  };
}

// ---------- inventory -> rows ----------

const s = v => (v === undefined || v === null || v === '' ? null : String(v));
const lower = v => String(v ?? '').trim().toLowerCase();
const key = (...parts) => parts.map(lower).join('|');
const json = o => {
  const clean = Object.fromEntries(Object.entries(o || {}).filter(([, v]) => v !== undefined && v !== null && v !== ''));
  return Object.keys(clean).length ? JSON.stringify(clean).slice(0, 30_000) : null;
};
const omit = (o, ...names) => Object.fromEntries(Object.entries(o || {}).filter(([k]) => !names.includes(k)));

export const CATEGORY = {
  os: 'Windows', 'windows-update': 'Patch', app: 'Application', 'winget-package': 'Application', bios: 'Firmware',
  driver: 'Driver', baseboard: 'Hardware', cpu: 'Hardware', memory: 'Hardware', battery: 'Hardware', disk: 'Disk', volume: 'Disk',
  'network-adapter': 'Network', 'network-setting': 'Network', wifi: 'Network', 'network-health': 'Network',
  security: 'Security', event: 'Events', 'scan-error': 'Scan',
};
// Kinds the background job can look up with an official source. Everything else is a measurement or inventory that the
// scan's own results page grades ("n/a"), or hardware with no official lookup yet ("not-checked").
export const LOOKUP = new Set(['os', 'winget-package', 'app', 'bios', 'driver', 'network-adapter']);
const NO_SOURCE_YET = new Set(['disk', 'cpu', 'baseboard']);
// Kinds whose CVEs come from NVD (product match + exact version). Windows itself uses the Security Update Guide (MSRC);
// winget packages are the same software as the 'app' rows, so they are not checked twice.
export const NVD_KINDS = new Set(['app', 'bios', 'driver', 'network-adapter']);
// Versions answered before the CVE sources existed (or only from the bot's scan answer) get their CVE check next run.
const CVE_KINDS = new Set([...NVD_KINDS, 'os']);
const NOTE = {
  'windows-update': 'Covered by the Windows row: every cumulative update includes the earlier ones.',
  noSource: 'No official vendor lookup for this yet; it is stored for when one is added.',
  measurement: 'A measurement from the scan; the scan\'s results page grades it.',
};

// One row per item in the inventory. Pure: no I/O.
export function inventoryRows(inv) {
  const rows = [];
  const add = (kind, item_key, { name = null, vendor = null, version = null, item_date = null, detail = null } = {}) => {
    const lookup_status = LOOKUP.has(kind) ? 'pending' : NO_SOURCE_YET.has(kind) ? 'not-checked' : 'n/a';
    const lookup_note = lookup_status === 'pending' ? null : kind === 'windows-update' ? NOTE['windows-update'] : lookup_status === 'not-checked' ? NOTE.noSource : NOTE.measurement;
    rows.push({ kind, item_key, name: s(name), vendor: s(vendor), version: s(version), item_date: s(item_date), detail: json(detail), lookup_status, lookup_note });
  };
  const o = inv.os;
  if (o?.build || o?.name) {
    add('os', key('windows', o.build, o.edition, o.architecture), { name: o.name, vendor: 'Microsoft', version: o.build ? `${o.build}.${o.ubr ?? 0}` : null,
      detail: { displayVersion: o.displayVersion, edition: o.edition, architecture: o.architecture, build: o.build, ubr: o.ubr,
        uptimeHours: inv.uptimeHours, pendingReboot: inv.pendingReboot } });
  }
  for (const u of inv.updates || []) if (u?.id) add('windows-update', key(u.id), { name: u.id, vendor: 'Microsoft', item_date: u.installedOn, detail: { description: u.description } });
  for (const a of inv.apps || []) if (a?.name) add('app', key(a.name, a.publisher), { name: a.name, vendor: a.publisher, version: a.version });
  for (const w of inv.winget || []) if (w?.id) add('winget-package', key(w.id), { name: w.id, version: w.version, detail: { source: w.source } });

  const hw = inv.hardware || {};
  if (hw.bios?.version || hw.bios?.releaseDate) {
    const sys = hw.system || {}, board = hw.baseboard || {};
    add('bios', key(sys.manufacturer, sys.model, board.product), { name: [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'BIOS', vendor: hw.bios.vendor,
      version: hw.bios.version, item_date: hw.bios.releaseDate, detail: { system: sys, baseboard: board } });
  }
  if (hw.baseboard?.product) add('baseboard', key(hw.baseboard.manufacturer, hw.baseboard.product), { name: hw.baseboard.product, vendor: hw.baseboard.manufacturer, version: hw.baseboard.version });
  for (const c of hw.cpu || []) if (c?.name) add('cpu', key(c.name), { name: c.name, vendor: c.manufacturer });
  if (hw.memoryGB != null) add('memory', 'memory', { name: 'Memory', detail: { memoryGB: hw.memoryGB } });
  for (const d of hw.disks || []) if (d?.model) add('disk', key(d.model), { name: d.model, version: d.firmware, detail: omit(d, 'model', 'firmware') });
  for (const v of hw.volumes || []) if (v?.drive) add('volume', key(v.drive), { name: v.drive, detail: omit(v, 'drive') });
  if (hw.battery) add('battery', 'battery', { name: 'Battery', detail: hw.battery });
  for (const d of hw.devices || []) if (d?.name) add('driver', key(d.class, d.name), { name: d.name, vendor: d.driverProvider || d.manufacturer, version: d.driverVersion, item_date: d.driverDate, detail: { class: d.class, manufacturer: d.manufacturer } });

  for (const a of inv.network?.adapters || []) {
    if (!a?.description) continue;
    add('network-adapter', key(a.description), { name: a.description, vendor: a.driverProvider, version: a.driverVersion, item_date: a.driverDate, detail: omit(a, 'description', 'driverProvider', 'driverVersion', 'driverDate', 'settings') });
    for (const st of a.settings || []) if (st?.keyword) add('network-setting', key(a.description, st.keyword), { name: st.name || st.keyword, version: st.value, detail: { adapter: a.description, keyword: st.keyword } });
  }
  if (inv.network?.wifi) add('wifi', 'wifi', { name: 'Wi-Fi link', detail: inv.network.wifi });

  const h = inv.health || {};
  if (h.defender) add('security', 'defender', { name: 'Microsoft Defender', vendor: 'Microsoft', version: h.defender.engineVersion, detail: omit(h.defender, 'engineVersion') });
  if (h.bitlocker) add('security', 'bitlocker', { name: 'BitLocker', vendor: 'Microsoft', detail: h.bitlocker });
  if (h.secureBoot != null) add('security', 'secure-boot', { name: 'Secure Boot', detail: { enabled: h.secureBoot } });
  if (h.tpm) add('security', 'tpm', { name: 'TPM', version: h.tpm.manufacturerVersion, detail: omit(h.tpm, 'manufacturerVersion') });
  if (h.firewall) add('security', 'firewall', { name: 'Windows Firewall', vendor: 'Microsoft', detail: h.firewall });

  for (const e of inv.eventLog?.entries || []) add('event', key(e.log, e.provider, e.eventId), { name: `${e.provider || e.log} ${e.eventId}`, item_date: e.lastSeen?.slice(0, 10),
    detail: { log: e.log, provider: e.provider, eventId: e.eventId, level: e.level, count: e.count, lastSeen: e.lastSeen, days: inv.eventLog.days } });
  const nh = inv.networkHealth;
  if (nh) for (const [k, v] of Object.entries(nh)) if (v != null && k !== 'via') add('network-health', key(k), { name: k, detail: typeof v === 'object' ? { via: nh.via, ...v } : { via: nh.via, value: v } });
  for (const err of inv.errors || []) add('scan-error', key(String(err).split(':')[0]), { name: String(err).slice(0, 200) });
  return rows;
}

// Table keys may not contain / \ # ? or control characters; the hash keeps two items that clean up alike apart.
export function rowKey(kind, itemKey) {
  const readable = String(itemKey).replace(/[/\\#?\u0000-\u001f\u007f-\u009f]/g, '_').slice(0, 150);
  return `${kind}|${readable}|${createHash('sha256').update(`${kind}\u0000${itemKey}`).digest('hex').slice(0, 8)}`;
}

// What the bot already answered when it processed the scan, so rows are useful before the job's first run.
// Keyed `${kind}\u0000${item_key}\u0000${version}`.
const gk = (kind, itemKey, version) => `${kind}\u0000${itemKey}\u0000${version ?? ''}`;
export function lookupsFromResult(result, rows) {
  const out = new Map(), at = result.processedAt ?? null;
  const os = rows.find(r => r.kind === 'os');
  const w = result.windows;
  if (os && w && w.status && w.status !== 'unknown') {
    const affected = (result.knownIssues?.issues || []).filter(i => ['affected', 'may-affect', 'fix-available'].includes(i.applies));
    out.set(gk(os.kind, os.item_key, os.version), { ...windowsLookup(w), ...issueFields(affected.map(i => ({ title: i.title, status: i.applies, source: result.knownIssues.source }))),
      ...exploitedFields((result.exploited?.affected || []).filter(c => c.kind === 'os')), checked: at });
  }
  const notes = new Map((result.appIssues?.issues || []).filter(i => i.which === 'installed').map(i => [`${i.id}\u0000${i.version}`, i]));
  for (const r of rows.filter(x => x.kind === 'winget-package')) {
    const hit = [...(result.apps?.updates || []), ...(result.apps?.current || [])].find(u => lower(u.id) === r.item_key && u.installed === r.version);
    if (!hit) continue;
    const n = notes.get(`${hit.id}\u0000${hit.installed}`);
    out.set(gk(r.kind, r.item_key, r.version), { ...wingetLookup(hit.id, r.version, hit.latest),
      ...(result.appIssues?.status === 'checked' ? issueFields((n?.items || []).map(t => ({ title: t, status: 'publisher', source: n.source }))) : {}), checked: at });
  }
  if (result.exploited?.status === 'checked') {
    for (const r of rows.filter(x => x.kind === 'app')) {
      const mine = (result.exploited.affected || []).filter(c => c.kind === 'app' && c.app === r.name && (c.version ?? null) === r.version);
      out.set(gk(r.kind, r.item_key, r.version), { lookup: 'n/a', note: appNote(mine), source: KEV_PAGE, ...exploitedFields(mine), checked: at });
    }
  }
  const bios = rows.find(r => r.kind === 'bios');
  if (bios && result.firmware && ['update', 'current'].includes(result.firmware.status)) out.set(gk(bios.kind, bios.item_key, bios.version), { ...biosLookup(result.firmware), checked: at });
  return out;
}

// ---------- lookup answers ----------

const KEV_PAGE = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
function windowsLookup(w) {
  const lookup = { current: 'current', behind: 'outdated', unsupported: 'unsupported' }[w.status] ?? (w.status === 'unknown' ? 'not-found' : 'failed');
  return { lookup, latest: w.latest?.build ?? null, latestDate: w.latest?.date ?? null, note: w.reason ?? null, source: w.source ?? null };
}
function wingetLookup(id, installed, latest) {
  if (!latest) return { lookup: 'not-found', note: 'Not found in the winget catalog.', source: WINGET_REPO };
  const newer = compareVersions(latest, installed) > 0;
  return { lookup: newer ? 'outdated' : 'current', latest,
    note: newer ? `Version ${latest} is available (installed ${installed}).` : `${installed} is the newest version in the winget catalog.`,
    source: `${WINGET_REPO}/tree/master/${manifestPath(id)}/${encodeURIComponent(latest)}` };
}
function biosLookup(f) {
  const lookup = { update: 'outdated', current: 'current', virtual: 'n/a' }[f.status] ?? 'not-checked';
  return { lookup, latest: f.latest?.version ?? null, latestDate: f.latest?.date ?? null, note: f.reason ?? null, source: f.latest?.link || f.source || f.support || null };
}
const issueFields = list => ({ issueCount: list.length, issues: list.length ? JSON.stringify(list.slice(0, 20)) : null });
const exploitedFields = list => ({ exploitedCount: list.length,
  exploited: list.length ? JSON.stringify(list.slice(0, 20).map(c => ({ cve: c.cveID, name: c.name, ransomware: Boolean(c.ransomware), record: c.record ?? null }))) : null });
const appNote = affected => affected.length
  ? `${affected.length} actively exploited vulnerabilit${affected.length > 1 ? 'ies' : 'y'} (CISA KEV) affect this version.`
  : 'No CISA KEV vulnerability is confirmed for this version. Newer versions are checked on the winget package row.';

// One headline per row, worst first.
export function headline(l) {
  if (l.exploitedCount > 0) return 'Exploited';
  if (l.lookup === 'unsupported') return 'Unsupported';
  if (l.cveCount > 0) return 'Vulnerable';
  if (l.issueCount > 0) return 'Known problems';
  return { outdated: 'Outdated', current: 'Current', pending: 'Pending', failed: 'Lookup failed', 'not-checked': 'Not checked', 'not-found': 'Not checked' }[l.lookup] ?? 'Info';
}

// Lookup answer -> table columns (every column written, so a stale value never survives a new answer).
const lookupColumns = l => ({
  Status: headline(l), LookupStatus: l.lookup, LatestVersion: l.latest ?? null, LatestDate: l.latestDate ?? null,
  KnownIssueCount: l.issueCount ?? null, KnownIssues: l.issues ?? null, ExploitedCount: l.exploitedCount ?? null, ExploitedCVEs: l.exploited ?? null,
  Note: l.note ?? null, Source: l.source ?? null, LastChecked: l.checked ?? null,
  CveCount: l.cveCount ?? null, CveMaxScore: l.cveMax ?? null, Cves: l.cves ?? null, CveSource: l.cveSource ?? null,
  CvesChecked: l.cvesChecked ?? null, ProductKey: l.productKey ?? null, Cpe: l.cpe ?? null, CpeMatch: l.cpeMatch ?? null, CpeCandidates: l.cpeCandidates ?? null,
});
const columnsLookup = e => ({ lookup: e.LookupStatus, latest: e.LatestVersion, latestDate: e.LatestDate, issueCount: e.KnownIssueCount, issues: e.KnownIssues,
  exploitedCount: e.ExploitedCount, exploited: e.ExploitedCVEs, note: e.Note, source: e.Source, checked: e.LastChecked,
  cveCount: e.CveCount, cveMax: e.CveMaxScore, cves: e.Cves, cveSource: e.CveSource, cvesChecked: e.CvesChecked, productKey: e.ProductKey, cpe: e.Cpe, cpeMatch: e.CpeMatch, cpeCandidates: e.CpeCandidates });

// ---------- import ----------

// result: one results/<id>.json written by the bot. Updates that machine's rows when the scan is newer than what the
// table has. Catalog items (software, drivers, firmware, Windows...) become a small pointer on the machine plus one
// shared catalog row per item version (bot/catalog.mjs); a version change, a new item or a removed item adds an
// install history row. Returns the number of rows written (0 when skipped).
// The Windows Update driver offer for an installed device: same model name, and newer than what is installed (by the
// version in the offer's title when there is one, else by date).
export function offerFor(row, updates) {
  const name = lower(row.name);
  for (const u of updates) {
    if (!u?.model || lower(u.model) !== name) continue;
    const version = (String(u.title || '').match(/(\d+(?:\.\d+){1,})\s*$/) || [])[1] || null;
    const newer = version && row.version ? compareVersions(version, row.version) > 0 : u.date && row.item_date ? u.date > row.item_date : true;
    if (newer) return { version, date: u.date || null, title: u.title ? String(u.title).slice(0, 200) : null };
  }
  return null;
}
export const ROWS_VERSION = 2; // 2 = catalog layout; older machine rows are rewritten once from their newest scan
export async function importResult(store, result) {
  if (result?.schema !== 'hm360.result/1' || !ID.test(result.id || '') || result.rejected || !result.inventory) return 0;
  const inv = result.inventory, pk = inv.machineId;
  if (!MACHINE.test(pk || '')) return 0;
  const seen = s(inv.collectedAt) || s(result.receivedAt);
  const existing = new Map((await store.partition(pk)).map(e => [e.rowKey, e]));
  const machine = existing.get('machine');
  const migrating = machine && machine.RowsVersion !== ROWS_VERSION;
  if (machine && (machine.LastSeen > seen || (!migrating && (machine.ScanId === result.id || (machine.LastSeen === seen && machine.ScanId > result.id))))) return 0;
  const firstScan = !machine;
  const sameScan = machine?.ScanId === result.id;

  const rows = inventoryRows(inv);
  // Same item twice in one scan (two identical disks): number the extra ones.
  const used = new Map();
  for (const r of rows) { const n = (used.get(`${r.kind}\u0000${r.item_key}`) || 0) + 1; used.set(`${r.kind}\u0000${r.item_key}`, n); if (n > 1) r.item_key += `#${n}`; }
  const known = lookupsFromResult(result, rows);
  const catalog = new Map((await store.query(`PartitionKey ge '${CATALOG_PREFIX}' and PartitionKey lt '${CATALOG_PREFIX.slice(0, -1)}.'`))
    .filter(isCatalogRow).map(e => [`${e.partitionKey}\u0000${e.rowKey}`, e]));

  const out = [], keys = new Set(), catalogOut = new Map(), history = [];
  for (const r of rows) {
    const rk = rowKey(r.kind, r.item_key), prev = existing.get(rk), g = gk(r.kind, r.item_key, r.version);
    keys.add(rk);
    const base = { partitionKey: pk, rowKey: rk, Category: CATEGORY[r.kind] ?? 'Other', Kind: r.kind, ItemKey: r.item_key, InstalledVersion: r.version,
      FirstSeen: prev?.FirstSeen || seen, LastSeen: seen, ScanId: result.id, Removed: false };
    if (!isCatalogItem(r)) {
      // A fact about this one computer: kept on its own row, as before.
      out.push({ ...base, Name: r.name, Vendor: r.vendor, ItemDate: r.item_date, Detail: r.detail, ...lookupColumns({ lookup: r.lookup_status, note: r.lookup_note }) });
      continue;
    }
    const ref = catalogRef(r.kind, r.item_key, r.version), ck = `${ref.partitionKey}\u0000${ref.rowKey}`;
    const detail = splitDetail(r.kind, r.detail);
    out.push({ ...base, CatalogRK: ref.rowKey, ItemDate: r.item_date, Detail: detail.machine });
    if (!firstScan && !sameScan) {
      if (!prev || prev.Removed) history.push(installRow(pk, { pointerRK: rk, itemKey: r.item_key, kind: r.kind, change: 'installed', to: r.version, at: seen, scanId: result.id }));
      else if ((prev.InstalledVersion ?? null) !== (r.version ?? null)) history.push(installRow(pk, { pointerRK: rk, itemKey: r.item_key, kind: r.kind, change: 'changed', from: prev.InstalledVersion ?? null, to: r.version, at: seen, scanId: result.id }));
    }
    // The shared catalog row: created once, then only its dates move. The answer comes from the newest of: what the
    // catalog already has, what the bot answered for this scan, and (once, when moving to this layout) the answer an
    // older machine row carried.
    let row = catalogOut.get(ck) || catalog.get(ck);
    if (!row) {
      row = { ...ref, Category: CATEGORY[r.kind] ?? 'Other', Kind: r.kind, ItemKey: String(r.item_key).replace(/#\d+$/, ''), Name: r.name, Vendor: r.vendor, Version: r.version,
        ItemDate: r.item_date, Detail: detail.catalog, FirstSeen: seen, LastSeen: seen, ...lookupColumns({ lookup: r.lookup_status, note: r.lookup_note }) };
    } else row = { ...row, FirstSeen: row.FirstSeen && row.FirstSeen < seen ? row.FirstSeen : seen, LastSeen: row.LastSeen && row.LastSeen > seen ? row.LastSeen : seen };
    const older = prev && prev.LastChecked && (prev.InstalledVersion ?? null) === (r.version ?? null) ? columnsLookup(prev) : null;
    for (const cand of [known.get(g), older]) {
      if (!cand?.checked || (row.LastChecked && cand.checked <= row.LastChecked)) continue;
      const next = { ...row, ...lookupColumns(cand) };
      history.push(...historyRows(row, answerChanges(row, next, row.Version), cand.checked));
      row = next;
    }
    if ((r.kind === 'driver' || r.kind === 'network-adapter') && inv.driverUpdates?.checked) {
      // Computers on the same driver version normally get the same offer. An offer is kept (the newest one wins); "no
      // offer" clears it only when it comes from a scan newer than the one that saw the offer.
      const o = offerFor(r, inv.driverUpdates.updates || []);
      const had = row.OfferedVersion || row.OfferedDate;
      let cols = null;
      if (o && (!had || (o.version && row.OfferedVersion ? compareVersions(o.version, row.OfferedVersion) > 0 : (o.date || '') > (row.OfferedDate || '')))) cols = { OfferedVersion: o.version, OfferedDate: o.date, OfferedTitle: o.title };
      else if (!o && had && seen > (row.OfferCheckedAt || '')) cols = { OfferedVersion: null, OfferedDate: null, OfferedTitle: null };
      const first = !row.OfferCheckedAt;
      row = { ...row, ...(cols || {}), OfferCheckedAt: row.OfferCheckedAt && row.OfferCheckedAt > seen ? row.OfferCheckedAt : seen, ...(cols || first ? { NeedsCheck: true } : {}) };
    }
    catalogOut.set(ck, row);
  }
  for (const [rk, e] of existing) {
    if (rk === 'machine' || isInstallRow(e) || keys.has(rk) || e.Removed) continue;
    out.push({ ...e, Removed: true });
    if (e.CatalogRK && !sameScan) history.push(installRow(pk, { pointerRK: rk, itemKey: e.ItemKey, kind: e.Kind, change: 'removed', from: e.InstalledVersion ?? null, at: seen, scanId: result.id }));
  }
  const sys = inv.hardware?.system || {};
  out.push({ partitionKey: pk, rowKey: 'machine', Category: 'Machine', Kind: 'machine', ItemKey: 'machine', Name: [sys.manufacturer, sys.model].filter(Boolean).join(' ') || null,
    InstalledVersion: inv.os?.build ? `${inv.os.build}.${inv.os.ubr ?? 0}` : null, Status: result.summary?.overall ?? null,
    Detail: json({ summary: result.summary, clientVersion: inv.clientVersion, botVersion: result.botVersion, receivedAt: result.receivedAt }),
    FirstSeen: machine?.FirstSeen || seen, LastSeen: seen, ScanId: result.id, Removed: false, RowsVersion: ROWS_VERSION });
  await store.upsert([...catalogOut.values(), ...history, ...out]);
  return out.length + catalogOut.size + history.length;
}

// A machine's items with their catalog answers joined in, for reading (tests, the MCP server, reports).
export async function machineItems(store, pk) {
  const rows = (await store.partition(pk)).filter(e => e.rowKey !== 'machine' && !isInstallRow(e));
  const catalog = new Map((await store.query(`PartitionKey ge '${CATALOG_PREFIX}' and PartitionKey lt '${CATALOG_PREFIX.slice(0, -1)}.'`))
    .filter(isCatalogRow).map(e => [`${e.Kind}\u0000${e.rowKey}`, e]));
  return rows.map(e => {
    const c = e.CatalogRK ? catalog.get(`${e.Kind}\u0000${e.CatalogRK}`) : null;
    if (!c) return e;
    const { partitionKey, rowKey: crk, FirstSeen, LastSeen, ...shared } = c;
    return { ...shared, ...e, Detail: e.Detail ?? c.Detail, CatalogFirstSeen: FirstSeen, CatalogLastSeen: LastSeen };
  });
}

export async function importFolder(store, folder, { log = () => {} } = {}) {
  let names = [];
  try { names = (await readdir(path.join(folder, 'results'))).filter(n => n.endsWith('.json') && ID.test(n.slice(0, -5))).sort(); } catch { return { scans: 0, rows: 0 }; }
  let scans = 0, rows = 0;
  for (const n of names) {
    try {
      const added = await importResult(store, JSON.parse(await readFile(path.join(folder, 'results', n), 'utf8')));
      if (added) { scans++; rows += added; }
    } catch (e) { log(`findings: ${n} skipped: ${String(e.message || e).slice(0, 200)}`); }
  }
  return { scans, rows };
}

// ---------- background lookups ----------

// Catalog rows (one per item version) still installed on some machine and due for a lookup: never checked, failed
// last time, or older than maxAgeHours. Oldest answer first. Each entry is { rows: [catalog row], checked, failed }.
export function dueGroups(entities, { now = Date.now(), maxAgeHours = 24, limit = 40 } = {}) {
  const cutoff = new Date(now - maxAgeHours * 3_600_000).toISOString();
  const live = new Set(entities.filter(e => e.CatalogRK && !e.Removed && !isCatalogRow(e)).map(e => `${e.Kind}\u0000${e.CatalogRK}`));
  return entities
    .filter(e => isCatalogRow(e) && LOOKUP.has(e.Kind) && live.has(`${e.Kind}\u0000${e.rowKey}`))
    .map(e => ({ rows: [e], checked: e.LastChecked || '', failed: e.LookupFailed === true || e.NeedsCheck === true || (CVE_KINDS.has(e.Kind) && !e.CvesChecked) || e.LookupStatus === 'failed' || e.LookupStatus === 'pending' }))
    .filter(g => !g.checked || g.failed || g.checked < cutoff)
    .sort((a, b) => a.checked.localeCompare(b.checked))
    .slice(0, limit);
}

const KEV_STATUSES = new Set(['current', 'outdated', 'unsupported']);

// sources: the bot's createSources() (bot/run.mjs). Each lookup is independent and may fail on its own.
async function baseLookup(e, sources) {
  const d = e.Detail ? JSON.parse(e.Detail) : {};
  if (e.Kind === 'winget-package') {
    if (d.source && !/^winget$/i.test(d.source)) return { lookup: 'not-checked', note: `${d.source} apps update through their own store.` };
    if (!e.InstalledVersion || /unknown/i.test(e.InstalledVersion) || /^[<>]/.test(e.InstalledVersion)) return { lookup: 'not-checked', note: 'The installed version is unknown.' };
    const v = await sources.wingetLatest(e.Name);
    const l = wingetLookup(e.Name, e.InstalledVersion, v);
    if (v && sources.releaseNotes) {
      try {
        const rn = await sources.releaseNotes(e.Name, e.InstalledVersion);
        const items = rn ? knownIssuesSection(rn.notes) : [];
        Object.assign(l, issueFields(items.map(t => ({ title: t, status: 'publisher', source: rn?.url || l.source }))));
      } catch (err) { l.note += ` Release notes could not be read: ${String(err.message || err).slice(0, 120)}`; }
    }
    return l;
  }
  if (e.Kind === 'os') {
    const osInfo = { name: e.Name, build: d.build, ubr: d.ubr, edition: d.edition, displayVersion: d.displayVersion };
    if (!osInfo.build) return { lookup: 'not-found', note: 'The scan did not report the Windows build.' };
    const gen = windowsGeneration(osInfo.build);
    const info = await sources.releaseInfo(gen);
    const w = windowsStatus(osInfo, info, RELEASE_PAGES[gen]);
    const l = windowsLookup(w);
    const url = knownIssuesUrl(osInfo, w.version);
    if (url) {
      try {
        const ev = evaluateIssues(parseKnownIssues(await sources.knownIssuesPage(url)), osInfo, info, url);
        Object.assign(l, issueFields(ev.issues.filter(i => ['affected', 'may-affect', 'fix-available'].includes(i.applies)).map(i => ({ title: i.title, status: i.applies, source: url }))));
      } catch (err) { l.note += ` Known issues could not be read: ${String(err.message || err).slice(0, 120)}`; }
    }
    if (KEV_STATUSES.has(l.lookup)) {
      try {
        const f = await sources.kev();
        const build = (info.builds.get(osInfo.build) || []).find(b => b.ubr === (osInfo.ubr ?? 0));
        const inv = { os: osInfo, apps: [] };
        const all = await verifyCandidates(kevCandidates(inv, f.kev, f.epss, { patchedThrough: build?.date ?? null }), inv, sources.cveRecord);
        Object.assign(l, exploitedFields(all.filter(c => c.verdict === 'affected')));
      } catch (err) { l.note += ` CISA KEV could not be checked: ${String(err.message || err).slice(0, 120)}`; }
    }
    return l;
  }
  if (e.Kind === 'app') {
    // Only CONFIRMED matches count (the CVE record's version ranges include this version). Unverified name matches are
    // not stored as problems, so this table never adds to the "verify by hand" noise.
    const f = await sources.kev();
    const inv = { apps: [{ name: e.Name, version: e.InstalledVersion, publisher: e.Vendor }] };
    const all = await verifyCandidates(kevCandidates(inv, f.kev, f.epss), inv, sources.cveRecord);
    const affected = all.filter(c => c.verdict === 'affected');
    return { lookup: 'n/a', note: appNote(affected), source: KEV_PAGE, ...exploitedFields(affected) };
  }
  if (e.Kind === 'bios') {
    const inv = { hardware: { bios: { vendor: e.Vendor, version: e.InstalledVersion, releaseDate: e.ItemDate }, system: d.system || {}, baseboard: d.baseboard || {} } };
    return biosLookup(await firmwareStatus(inv, sources.vendorFile));
  }
  if (e.Kind === 'driver' || e.Kind === 'network-adapter') return driverLookup(e);
  return { lookup: 'n/a', note: NOTE.measurement };
}

// Drivers: what Windows Update offered the computers that run this driver version (scanner 1.4.0, stored on the
// catalog row at import), so this works for every brand.
export function driverLookup(e) {
  const wu = null; // Windows Update itself, on the computer: there is no public page per offer
  if (e.OfferedVersion || e.OfferedDate) {
    const what = e.OfferedVersion || `a driver dated ${e.OfferedDate}`;
    return { lookup: 'outdated', latest: e.OfferedVersion || null, latestDate: e.OfferedDate || null, source: wu,
      note: `Windows Update offers ${what}${e.OfferedTitle ? ` ("${e.OfferedTitle}")` : ''}. Install it through Windows Update or the maker's tool.` };
  }
  if (e.OfferCheckedAt) return { lookup: 'current', source: wu, note: `Windows Update offered no newer driver for this device when it was last asked (${String(e.OfferCheckedAt).slice(0, 10)}). The maker may still have a newer one on its own site.` };
  return { lookup: 'not-checked', note: 'Scanner 1.4.0 or later asks Windows Update for driver updates; scan again with it.' };
}

const MAX_CVES = 30;
const cveFields = (list, source) => {
  const top = sortCves(list).slice(0, MAX_CVES).map(c => ({ cve: c.cve, score: c.score ?? null, severity: c.severity ?? null, kev: Boolean(c.kev), fixedIn: c.fixedIn ?? null, kb: c.kb ?? null,
    published: c.published ?? null, title: c.title ? String(c.title).slice(0, 160) : null, record: c.record ?? null }));
  return { cveCount: list.length, cveMax: list.reduce((m, c) => Math.max(m, c.score ?? 0), 0) || null, cves: list.length ? JSON.stringify(top) : null, cveSource: source };
};

// The kind's own answer (latest version, known problems, CISA KEV), then every CVE for this exact version: NVD for
// apps, drivers and BIOS (once the product is matched), the Security Update Guide for Windows. A CVE source that fails
// adds a note but keeps the rest of the answer.
export async function lookupItem(e, sources) {
  const l = await baseLookup(e, sources);
  if (CVE_KINDS.has(e.Kind)) l.cvesChecked = true;
  if (e.Kind === 'os' && sources.msrc) {
    try {
      const d = e.Detail ? JSON.parse(e.Detail) : {};
      let patchedThrough = null;
      try { const info = await sources.releaseInfo(windowsGeneration(d.build)); patchedThrough = (info.builds.get(d.build) || []).find(b => b.ubr === (d.ubr ?? 0))?.date ?? null; } catch { /* use the default window */ }
      const r = await sources.msrc.windowsCves({ build: d.build, ubr: d.ubr, displayVersion: d.displayVersion, architecture: d.architecture }, { patchedThrough });
      Object.assign(l, cveFields(r.cves, 'Microsoft Security Update Guide'));
    } catch (err) { l.note = `${l.note ? `${l.note} ` : ''}Security Update Guide could not be checked: ${String(err.message || err).slice(0, 120)}`; }
  }
  if (NVD_KINDS.has(e.Kind) && sources.nvd && sources.productMatch) {
    try {
      const m = await sources.productMatch({ kind: e.Kind, name: e.Name, vendor: e.Vendor });
      Object.assign(l, { productKey: m.key, cpeMatch: m.status, cpe: m.vendor ? `${m.part}:${m.vendor}:${m.product}` : null, cpeCandidates: m.candidates?.length ? JSON.stringify(m.candidates) : null });
      if ((m.status === 'strong' || m.status === 'confirmed') && e.InstalledVersion) Object.assign(l, cveFields(await sources.nvd.cves(m, e.InstalledVersion), 'NVD'));
    } catch (err) { l.note = `${l.note ? `${l.note} ` : ''}NVD could not be checked: ${String(err.message || err).slice(0, 120)}`; }
  }
  return l;
}

// One lookup per catalog row (item version), whatever the number of machines running it. A changed answer adds check
// history rows. A failed lookup keeps the last good answer (marked LookupFailed, retried next run) so a flaky source
// never makes history say a CVE went away and came back.
// confirmed: an admin's product choices from the Inventory catalog page (settings/products.json): productKey ->
// "a:vendor:product", or null for "not this product". A changed choice rechecks the versions it covers at once.
export async function runLookups(store, sources, { now = () => Date.now(), maxAgeHours = 24, limit = 40, log = () => {}, confirmed = {} } = {}) {
  const filter = [...LOOKUP].map(k => `Kind eq '${k}'`).join(' or ');
  const entities = await store.query(filter);
  for (const e of entities) {
    if (!isCatalogRow(e) || !e.ProductKey || !Object.hasOwn(confirmed, e.ProductKey)) continue;
    const want = confirmed[e.ProductKey];
    if (want === null ? e.CpeMatch !== 'rejected' : (e.Cpe !== want || e.CpeMatch !== 'confirmed')) e.NeedsCheck = true;
  }
  const groups = dueGroups(entities, { now: now(), maxAgeHours, limit });
  const tally = { checked: 0, failed: 0, items: groups.length };
  // Product matches are made once per product (not per version) and kept 30 days in the "product" partition.
  const products = new Map((groups.length ? await store.query("PartitionKey eq 'product'") : []).filter(e => e.partitionKey === 'product').map(e => [e.ProductKey, e]));
  const fresh = new Date(now() - 30 * 86_400_000).toISOString(), memo = new Map();
  const productMatch = sources.nvd ? async item => {
    const key = productKey(item.kind, item.name, item.vendor);
    if (Object.hasOwn(confirmed, key)) return matchProduct(item, sources.nvd, confirmed);
    if (memo.has(key)) return memo.get(key);
    const c = products.get(key);
    let m;
    if (c && c.CheckedAt > fresh) m = { key, status: c.Status, part: c.Part ?? undefined, vendor: c.CpeVendor ?? undefined, product: c.CpeProduct ?? undefined, candidates: c.Candidates ? JSON.parse(c.Candidates) : [] };
    else {
      m = await matchProduct(item, sources.nvd, confirmed);
      await store.upsert([{ partitionKey: 'product', rowKey: rowKey('product', key), Category: 'Product', Kind: 'product-match', ProductKey: key, ItemKind: item.kind, Name: item.name, Vendor: item.vendor,
        Status: m.status, Part: m.part ?? null, CpeVendor: m.vendor ?? null, CpeProduct: m.product ?? null, Candidates: m.candidates?.length ? JSON.stringify(m.candidates) : null, CheckedAt: new Date(now()).toISOString() }]);
    }
    memo.set(key, m);
    return m;
  } : null;
  const src = { ...sources, productMatch };
  for (const g of groups) {
    const row = g.rows[0], at = new Date(now()).toISOString();
    let next;
    try {
      const l = await lookupItem({ ...row, InstalledVersion: row.Version }, src);
      tally.checked++;
      next = { ...row, ...lookupColumns({ ...l, checked: at }), LookupFailed: null, LastError: null, NeedsCheck: null };
    } catch (err) {
      tally.failed++;
      const msg = `Lookup failed: ${String(err.message || err).slice(0, 200)}`;
      next = row.LastChecked && row.LookupStatus !== 'failed' && row.LookupStatus !== 'pending'
        ? { ...row, LookupFailed: true, LastError: msg, LastErrorAt: at }
        : { ...row, ...lookupColumns({ lookup: 'failed', note: msg, checked: at }), LookupFailed: null, LastError: msg, LastErrorAt: at };
    }
    await store.upsert([next, ...historyRows(next, answerChanges(row, next, row.Version), at)]);
  }
  if (groups.length) log(`findings: looked up ${groups.length} item version${groups.length > 1 ? 's' : ''} (${tally.failed} failed)`);
  return tally;
}

// The Inventory catalog page reads this file (catalog/catalog.json in the local data folder).
export async function writeSnapshot(store, folder, { now = () => Date.now(), choices = {} } = {}) {
  const snap = buildSnapshot(await store.query(null), { now: now(), choices });
  const file = path.join(folder, 'catalog', 'catalog.json');
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(`${file}.tmp`, JSON.stringify(snap));
  await rename(`${file}.tmp`, file);
  return { file, items: snap.items.length, versions: snap.versions };
}

// ---------- where the table lives ----------

export async function readSettings(repos) {
  for (const r of repos) {
    try {
      const s = JSON.parse(await readFile(path.join(r, 'settings', 'findings.json'), 'utf8'));
      if (s?.schema === 'hm360.settings/1' && ACCOUNT.test(s.findings?.account || '')) return { account: s.findings.account, table: TABLE.test(s.findings.table || '') ? s.findings.table : 'findings', from: r };
    } catch { /* none here */ }
  }
  return null;
}

// Product choices made on the Inventory catalog page (settings/products.json in the first --repo that has one).
export async function readProductChoices(repos) {
  for (const r of repos) {
    try {
      const s = JSON.parse(await readFile(path.join(r, 'settings', 'products.json'), 'utf8'));
      if (s?.schema === 'hm360.products/1' && s.choices && typeof s.choices === 'object') return s.choices;
    } catch { /* none here */ }
  }
  return {};
}

export async function resolveLocation({ account = null, table = null, repos = [], env = process.env }) {
  const s = account ? null : await readSettings(repos);
  return { account: account || s?.account || env.HM360_TABLES_ACCOUNT || null, table: table || s?.table || env.HM360_TABLES_TABLE || 'findings',
    from: account ? 'command line' : s ? `Settings page (${path.join(s.from, 'settings', 'findings.json')})` : env.HM360_TABLES_ACCOUNT ? 'HM360_TABLES_ACCOUNT' : null };
}

// ---------- command line ----------

async function main(argv) {
  const arg = (n, d = null) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
  const repos = argv.flatMap((a, i) => (a === '--repo' ? [path.resolve(argv[i + 1])] : []));
  let store;
  if (argv.includes('--dry-run')) store = memoryStore();
  else {
    const loc = await resolveLocation({ account: arg('--account'), table: arg('--table'), repos });
    store = await createAzureStore({ ...loc, credential: arg('--credential') || process.env.HM360_TABLES_CREDENTIAL || 'cli' });
    console.log(`findings: table ${store.label} (from ${loc.from})`);
  }
  if (!argv.includes('--lookup-only')) {
    for (const r of repos) { const n = await importFolder(store, r, { log: console.log }); console.log(`findings: ${r}: ${n.scans} new scan${n.scans === 1 ? '' : 's'}, ${n.rows} rows written`); }
  }
  if (!argv.includes('--import-only')) {
    const { createSources } = await import('./run.mjs');
    const cacheDir = path.resolve(arg('--cache') || path.join(os.homedir(), '.hm360-bot-cache'));
    await mkdir(cacheDir, { recursive: true });
    const sources = { ...createSources({ cacheDir, githubToken: process.env.GITHUB_TOKEN || null }), nvd: createNvd(), msrc: createMsrc({ dir: cacheDir }) };
    const r = await runLookups(store, sources, { limit: Number(arg('--limit', 40)), maxAgeHours: Number(arg('--max-age-hours', 24)), log: console.log, confirmed: await readProductChoices(repos) });
    if (!r.items) console.log('findings: nothing due for lookup');
  }
  const snapDir = arg('--snapshot') || repos[0];
  if (snapDir && !argv.includes('--no-snapshot')) { const w = await writeSnapshot(store, path.resolve(snapDir), { choices: await readProductChoices(repos) }); console.log(`findings: catalog snapshot ${w.file} (${w.items} items, ${w.versions} versions)`); }
  console.log(`findings: done (${store.label})`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(e => { console.error(e.message); process.exit(1); });
}
