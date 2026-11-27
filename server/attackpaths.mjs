// Attack paths page: who can reach Domain Admins and other risky Active Directory settings, from BloodHound CE.
//
// tools/bloodhound/Invoke-BloodHoundScan.ps1 runs as a weekly scheduled task on the computer that hosts HeatMap 360. It
// collects the domain with a throwaway collector container, imports it into the local BloodHound CE containers
// (tools/bloodhound/compose.yaml), asks BloodHound a fixed set of questions and saves per run in the attack paths folder:
//   bloodhound-<yyyyMMddHHmmss>.json   summary { schema: hm360.attackpaths/1, tool, domain, generatedAt, counts, findings }
//   bloodhound-<yyyyMMddHHmmss>.zip    the collector's raw data (kept for re-import into BloodHound, never served)
// The summaries name real accounts and computers, so the folder is local only: never written to the GitHub data store
// and never exported. The server only reads it, checks every summary, and ignores anything else.
//
// tools/bloodhound/Invoke-ADMinerReport.ps1 builds an AD Miner report from the data BloodHound already holds, on demand,
// and saves it in the "adminer" subfolder of the same folder:
//   adminer-<yyyyMMddHHmmss>.json   what the page lists { schema: hm360.adminer/1, tool, version, domains, generatedAt, files }
//   adminer-<yyyyMMddHHmmss>.zip    AD Miner's HTML report. It is a folder of pages with their own scripts, so it is only
//                                   offered as a download and never rendered by this site.
import { lstat, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const FILE = /^bloodhound-([0-9]{14})\.json$/;
const MAX_SUMMARY = 2 * 1024 * 1024, MAX_SCANS = 260, MAX_ITEMS = 200;
const REPORT_FILE = /^adminer-([0-9]{14})\.json$/;
export const REPORT_ID = /^[0-9]{14}$/;
const MAX_REPORT_DETAILS = 256 * 1024, MAX_REPORTS = 104, MAX_REPORT_ZIP = 2 * 1024 ** 3, MAX_DOMAINS = 50, MAX_CHECKS = 300;
// Windows PowerShell writes UTF-8 files with a byte order mark; JSON.parse does not accept one.
const parseJson = text => JSON.parse(text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text);
// The questions the scan script asks, in the order the page shows them.
export const FINDINGS = {
  pathToDomainAdmins: 'Path to Domain Admins',
  domainAdminMembers: 'Domain Admins members',
  dcsync: 'Can DCSync (not domain controllers or admin groups)',
  kerberoastable: 'Kerberoastable users',
  asrepRoastable: 'AS-REP roastable users',
  unconstrainedDelegation: 'Unconstrained delegation (not domain controllers)',
  passwordNeverExpires: 'Password never expires',
};
const COUNT_KEYS = ['users', 'groups', 'computers'];

const str = (v, max) => (typeof v === 'string' && v.length <= max ? v : null);
const count = v => (Number.isInteger(v) && v >= 0 && v <= 10_000_000 ? v : null);

// Returns a clean summary, or null when the file is not a summary this page understands.
export function checkSummary(raw, id) {
  if (!raw || typeof raw !== 'object' || raw.schema !== 'hm360.attackpaths/1' || raw.tool !== 'BloodHound CE') return null;
  const domain = str(raw.domain, 255);
  const generatedAt = str(raw.generatedAt, 40);
  if (!domain || !/^[A-Za-z0-9.-]+$/.test(domain) || !generatedAt || Number.isNaN(Date.parse(generatedAt))) return null;
  const counts = {};
  for (const k of COUNT_KEYS) { counts[k] = count(raw.counts?.[k]); if (counts[k] === null) return null; }
  if (!Array.isArray(raw.findings) || raw.findings.length > 50) return null;
  const byId = {};
  for (const f of raw.findings) {
    if (!f || !Object.hasOwn(FINDINGS, f.id) || count(f.count) === null || !Array.isArray(f.items) || f.items.length > MAX_ITEMS) return null;
    const items = f.items.map(i => str(i, 300));
    if (items.some(i => i === null)) return null;
    byId[f.id] = { id: f.id, count: f.count, items: [...new Set(items)].sort() };
  }
  const findings = Object.keys(FINDINGS).filter(k => byId[k]).map(k => byId[k]);
  return { id, domain: domain.toLowerCase(), generatedAt: new Date(generatedAt).toISOString(), collector: str(raw.collector, 80), collection: str(raw.collection, 20), counts, findings };
}

// AD Miner rates every check with a colour: red is an immediate risk, orange a potential risk, yellow a minor risk,
// green is handled and grey was not evaluated. Worst first.
export const RATINGS = ['red', 'orange', 'yellow', 'green', 'grey'];
const CHECK_ID = /^[A-Za-z0-9_.-]{1,80}$/;
const idList = v => (Array.isArray(v) && v.length <= MAX_CHECKS && v.every(i => typeof i === 'string' && CHECK_ID.test(i)) ? [...new Set(v)] : null);

// Returns clean AD Miner report details, or null when the file is not one the report script wrote.
export function checkReport(raw, id) {
  if (!raw || typeof raw !== 'object' || raw.schema !== 'hm360.adminer/1' || raw.tool !== 'AD Miner') return null;
  const generatedAt = str(raw.generatedAt, 40), version = str(raw.version, 40);
  if (!generatedAt || Number.isNaN(Date.parse(generatedAt)) || !version || !/^[0-9A-Za-z.+-]+$/.test(version)) return null;
  if (!Array.isArray(raw.domains) || !raw.domains.length || raw.domains.length > MAX_DOMAINS) return null;
  const domains = raw.domains.map(d => str(d, 255));
  if (domains.some(d => !d || !/^[A-Za-z0-9.-]+$/.test(d))) return null;
  // The day the data is from, as AD Miner worked it out. Missing when the script could not read it.
  const dataDate = raw.dataDate == null ? null : str(raw.dataDate, 10);
  if (raw.dataDate != null && (!dataDate || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(dataDate) || Number.isNaN(Date.parse(dataDate)))) return null;
  const files = count(raw.files), objects = raw.objects == null ? null : count(raw.objects);
  if (files === null || (raw.objects != null && objects === null)) return null;
  // Database questions and checks AD Miner could not run. It finishes anyway, so the report says less than it looks.
  const failedRequests = idList(raw.failedRequests ?? []), failedControls = idList(raw.failedControls ?? []);
  const list = raw.controls ?? [];
  if (!failedRequests || !failedControls || !Array.isArray(list) || list.length > MAX_CHECKS) return null;
  const controls = [];
  for (const c of list) {
    const name = str(c?.name, 200), area = str(c?.area, 40);
    if (!c || typeof c.id !== 'string' || !CHECK_ID.test(c.id) || name === null || !RATINGS.includes(c.rating) || area === null || !/^[a-z_]*$/.test(area)) return null;
    controls.push({ id: c.id, name: name || c.id, rating: c.rating, area });
  }
  controls.sort((a, b) => RATINGS.indexOf(a.rating) - RATINGS.indexOf(b.rating) || a.name.localeCompare(b.name));
  return { id, generatedAt: new Date(generatedAt).toISOString(), version, domains: [...new Set(domains.map(d => d.toLowerCase()))].sort(), dataDate, objects, files, failedRequests, failedControls, controls };
}

export function createAttackPaths({ dir } = {}) {
  const reportDir = dir ? path.join(dir, 'adminer') : null;
  // The zip of one report, only when it is a plain file (not a link) of a sensible size.
  async function zipOf(id) {
    try {
      const file = path.join(reportDir, `adminer-${id}.zip`);
      const s = await lstat(file);
      return s.isFile() && s.size > 0 && s.size <= MAX_REPORT_ZIP ? { file, size: s.size } : null;
    } catch { return null; }
  }
  async function detailsOf(id) {
    const file = path.join(reportDir, `adminer-${id}.json`);
    if ((await stat(file)).size > MAX_REPORT_DETAILS) return null;
    return checkReport(parseJson(await readFile(file, 'utf8')), id);
  }
  // AD Miner reports, newest first. A report counts once its details file is there (the script writes it last).
  async function reports() {
    let names;
    try { names = await readdir(reportDir); } catch (e) { if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return { reports: [], skippedReports: 0 }; throw e; }
    const ids = names.map(n => n.match(REPORT_FILE)?.[1]).filter(Boolean).sort().slice(-MAX_REPORTS);
    const list = [];
    let skippedReports = 0;
    for (const id of ids) {
      try {
        const r = await detailsOf(id);
        if (r) list.push({ ...r, bytes: (await zipOf(id))?.size || 0 }); else skippedReports++;
      } catch { skippedReports++; }
    }
    list.sort((a, b) => b.generatedAt.localeCompare(a.generatedAt) || b.id.localeCompare(a.id));
    // Every report with how many checks got each rating; the checks themselves (all but the green ones) only for the
    // newest report, which is the one the page spells out.
    const reports = list.map(({ controls, ...r }, i) => ({
      ...r,
      ratings: Object.fromEntries(RATINGS.map(rating => [rating, controls.filter(c => c.rating === rating).length])),
      ...(i === 0 ? { controls: controls.filter(c => c.rating !== 'green') } : {}),
    }));
    return { reports, skippedReports };
  }
  return {
    configured: Boolean(dir),
    // Every scan with its counts; the names only for the newest two per domain (enough for "new" and "gone").
    // Also every AD Miner report that can be downloaded.
    async list() {
      if (!dir) return { configured: false, folderFound: false, scans: [], skipped: 0, reports: [], skippedReports: 0 };
      let names;
      try { names = await readdir(dir); } catch (e) { if (e.code === 'ENOENT') return { configured: true, folderFound: false, scans: [], skipped: 0, reports: [], skippedReports: 0 }; throw e; }
      const ids = names.map(n => n.match(FILE)?.[1]).filter(Boolean).sort().slice(-MAX_SCANS);
      const scans = [];
      let skipped = 0;
      for (const id of ids) {
        const file = path.join(dir, `bloodhound-${id}.json`);
        try {
          if ((await stat(file)).size > MAX_SUMMARY) { skipped++; continue; }
          const s = checkSummary(parseJson(await readFile(file, 'utf8')), id);
          if (s) scans.push(s); else skipped++;
        } catch { skipped++; }
      }
      scans.sort((a, b) => a.generatedAt.localeCompare(b.generatedAt) || a.id.localeCompare(b.id));
      const keep = new Set(), seen = {};
      for (const s of [...scans].reverse()) { seen[s.domain] = (seen[s.domain] || 0) + 1; if (seen[s.domain] <= 2) keep.add(s.id); }
      return {
        configured: true, folderFound: true, skipped,
        scans: scans.map(s => (keep.has(s.id) ? s : { ...s, findings: s.findings.map(({ id, count: c }) => ({ id, count: c })) })),
        ...(await reports()),
      };
    },
    // Where one AD Miner report zip is and how big, or null. Only for a report whose details file checks out.
    async reportZip(id) {
      if (!dir || typeof id !== 'string' || !REPORT_ID.test(id)) return null;
      try { if (!(await detailsOf(id))) return null; } catch { return null; }
      return zipOf(id);
    },
  };
}
