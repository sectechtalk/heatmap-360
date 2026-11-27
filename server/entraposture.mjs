// Entra posture page: Entra ID and Microsoft 365 security checks from Maester, tracked over time.
//
// tools/entraposture/Invoke-MaesterScan.ps1 runs Maester (read-only Graph permissions) in a container as a scheduled
// task on the computer that hosts HeatMap 360 and saves two files per run in the Entra posture folder:
//   maester-<yyyyMMddHHmmss>.json   summary { schema: hm360.entraposture/1, tool, tenantName, generatedAt, counts, tests }
//   maester-<yyyyMMddHHmmss>.html   Maester's own report (offered as a download, never rendered in the page)
// The reports name real users, groups and policies, so the folder is local only: it is never written to the GitHub
// data store and never exported. The server only reads it, checks every summary, and ignores anything else.
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const FILE = /^maester-([0-9]{14})\.json$/;
export const REPORT_ID = /^[0-9]{14}$/;
const MAX_SUMMARY = 4 * 1024 * 1024, MAX_REPORT = 50 * 1024 * 1024, MAX_SCANS = 260, MAX_TESTS = 3000;
export const RESULTS = ['Passed', 'Failed', 'Skipped', 'NotRun', 'Error', 'Investigate'];
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const COUNT_KEYS = ['total', 'passed', 'failed', 'skipped', 'notRun', 'error', 'investigate'];
// Results that need a look, in the order the page lists them.
export const OPEN = new Set(['Failed', 'Error', 'Investigate']);

const str = (v, max) => (typeof v === 'string' && v.length <= max ? v : null);
const count = v => (Number.isInteger(v) && v >= 0 && v <= 100000 ? v : null);
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Share of the checks that ran (passed + failed) that passed, 0 to 100, or null when none ran.
export function passRate(c) {
  const ran = c.passed + c.failed;
  return ran ? Math.round((c.passed / ran) * 100) : null;
}

// Returns a clean summary, or null when the file is not a summary this page understands.
export function checkSummary(raw, id) {
  if (!raw || typeof raw !== 'object' || raw.schema !== 'hm360.entraposture/1' || raw.tool !== 'Maester') return null;
  const generatedAt = str(raw.generatedAt, 40);
  if (!generatedAt || Number.isNaN(Date.parse(generatedAt))) return null;
  const tenantId = str(raw.tenantId, 36);
  const tenantName = str(raw.tenantName, 200) || '';
  const counts = {};
  for (const k of COUNT_KEYS) { counts[k] = count(raw.counts?.[k]); if (counts[k] === null) return null; }
  if (!Array.isArray(raw.tests) || raw.tests.length > MAX_TESTS) return null;
  const tests = [];
  for (const t of raw.tests) {
    const testId = str(t?.id, 120);
    if (!testId || !RESULTS.includes(t.result)) return null;
    const helpUrl = str(t.helpUrl, 500);
    tests.push({
      id: testId, title: str(t.title, 500) || testId, result: t.result,
      severity: SEVERITIES.includes(t.severity) ? t.severity : '',
      block: str(t.block, 200) || '',
      helpUrl: helpUrl && /^https:\/\/[^\s"<>]+$/.test(helpUrl) ? helpUrl : '',
    });
  }
  const tenant = tenantId && GUID.test(tenantId) ? tenantId.toLowerCase() : null;
  return {
    id, tenant: tenant || tenantName.toLowerCase() || 'tenant', tenantName: tenantName || 'Tenant',
    generatedAt: new Date(generatedAt).toISOString(), engineVersion: str(raw.engineVersion, 40), counts, passRate: passRate(counts), tests,
  };
}

export function createEntraPosture({ dir } = {}) {
  async function load() {
    let names;
    try { names = await readdir(dir); } catch (e) { if (e.code === 'ENOENT') return { folderFound: false, scans: [] }; throw e; }
    const ids = names.map(n => n.match(FILE)?.[1]).filter(Boolean).sort().slice(-MAX_SCANS);
    const html = new Set(names.filter(n => /^maester-[0-9]{14}\.html$/.test(n)).map(n => n.slice(8, 22)));
    const scans = [];
    let skipped = 0;
    for (const id of ids) {
      const file = path.join(dir, `maester-${id}.json`);
      try {
        if ((await stat(file)).size > MAX_SUMMARY) { skipped++; continue; }
        const s = checkSummary(JSON.parse((await readFile(file, 'utf8')).replace(/^﻿/, '')), id);
        if (s) scans.push({ ...s, hasReport: html.has(id) }); else skipped++;
      } catch { skipped++; }
    }
    scans.sort((a, b) => a.generatedAt.localeCompare(b.generatedAt) || a.id.localeCompare(b.id));
    return { folderFound: true, scans, skipped };
  }
  return {
    configured: Boolean(dir),
    // Every scan with its counts; tests only for the newest two per tenant (enough for "new" and "fixed" since last time).
    async list() {
      if (!dir) return { configured: false, folderFound: false, scans: [], skipped: 0 };
      const { folderFound, scans, skipped = 0 } = await load();
      const keep = new Set();
      const seen = {};
      for (const s of [...scans].reverse()) { seen[s.tenant] = (seen[s.tenant] || 0) + 1; if (seen[s.tenant] <= 2) keep.add(s.id); }
      return { configured: true, folderFound, skipped, scans: scans.map(s => (keep.has(s.id) ? s : { ...s, tests: undefined })) };
    },
    // Maester's HTML report for one scan, as a Buffer, or null.
    async report(id) {
      if (!dir || !REPORT_ID.test(id)) return null;
      const file = path.join(dir, `maester-${id}.html`);
      try {
        if ((await stat(file)).size > MAX_REPORT) return null;
        return await readFile(file);
      } catch { return null; }
    },
  };
}
