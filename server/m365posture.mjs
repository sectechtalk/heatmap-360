// M365 & Azure posture page: CIS benchmark checks of Exchange Online, Microsoft Teams, Microsoft Purview and Azure from
// Monkey365, tracked over time. Entra ID itself is on the Entra posture page (Maester), so this page does not repeat it.
//
// tools/m365posture/Invoke-Monkey365Scan.ps1 runs Monkey365 (read-only permissions) in a container as a scheduled task
// on the computer that hosts HeatMap 360 and saves these files per run in the M365 posture folder:
//   monkey365-<yyyyMMddHHmmss>.json               summary { schema: hm360.m365posture/1, tool, tenantName, generatedAt, runs, counts, rules }
//   monkey365-<yyyyMMddHHmmss>-microsoft365.html  Monkey365's own report for Exchange, Teams and Purview (download only)
//   monkey365-<yyyyMMddHHmmss>-azure.html         Monkey365's own report for Azure (download only)
// The reports name real mailboxes, users and resources, so the folder is local only: it is never written to the GitHub
// data store and never exported. The server only reads it, checks every summary, and ignores anything else.
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const FILE = /^monkey365-([0-9]{14})\.json$/;
const HTML = /^monkey365-([0-9]{14})-(microsoft365|azure)\.html$/;
export const REPORT_ID = /^[0-9]{14}$/;
export const AREAS = ['microsoft365', 'azure'];
const MAX_SUMMARY = 4 * 1024 * 1024, MAX_REPORT = 80 * 1024 * 1024, MAX_SCANS = 260, MAX_RULES = 3000;
export const STATUSES = ['Failed', 'Manual', 'Passed', 'Info'];
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
export const INSTANCES = ['Microsoft365', 'Azure'];
const COUNT_KEYS = ['total', 'passed', 'failed', 'manual', 'info'];

const str = (v, max) => (typeof v === 'string' && v.length <= max ? v : null);
const count = v => (Number.isInteger(v) && v >= 0 && v <= 100000 ? v : null);
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Share of the rules that were decided (passed + failed) that passed, 0 to 100, or null when none were.
export function passRate(c) {
  const ran = c.passed + c.failed;
  return ran ? Math.round((c.passed / ran) * 100) : null;
}

// Returns a clean summary, or null when the file is not a summary this page understands.
export function checkSummary(raw, id) {
  if (!raw || typeof raw !== 'object' || raw.schema !== 'hm360.m365posture/1' || raw.tool !== 'Monkey365') return null;
  const generatedAt = str(raw.generatedAt, 40);
  if (!generatedAt || Number.isNaN(Date.parse(generatedAt))) return null;
  const tenantId = str(raw.tenantId, 36);
  const tenantName = str(raw.tenantName, 200) || '';
  const counts = {};
  for (const k of COUNT_KEYS) { counts[k] = count(raw.counts?.[k]); if (counts[k] === null) return null; }
  if (!Array.isArray(raw.rules) || raw.rules.length > MAX_RULES) return null;
  if (!Array.isArray(raw.runs) || raw.runs.length > INSTANCES.length) return null;
  const runs = [];
  for (const r of raw.runs) {
    if (!INSTANCES.includes(r?.area) || typeof r.ran !== 'boolean') return null;
    runs.push({ area: r.area, ran: r.ran, findings: count(r.findings) ?? 0, error: str(r.error, 300) || '' });
  }
  const rules = [];
  for (const t of raw.rules) {
    const ruleId = str(t?.id, 120);
    if (!ruleId || !STATUSES.includes(t.status) || !INSTANCES.includes(t.instance)) return null;
    const helpUrl = str(t.helpUrl, 500);
    rules.push({
      id: ruleId, title: str(t.title, 500) || ruleId, status: t.status, instance: t.instance,
      area: str(t.area, 80) || t.instance,
      severity: SEVERITIES.includes(t.severity) ? t.severity : '',
      failed: count(t.failed) ?? 0,
      helpUrl: helpUrl && /^https:\/\/[^\s"<>]+$/.test(helpUrl) ? helpUrl : '',
    });
  }
  const tenant = tenantId && GUID.test(tenantId) ? tenantId.toLowerCase() : null;
  return {
    id, tenant: tenant || tenantName.toLowerCase() || 'tenant', tenantName: tenantName || 'Tenant',
    generatedAt: new Date(generatedAt).toISOString(), engineVersion: str(raw.engineVersion, 40), runs, counts, passRate: passRate(counts), rules,
  };
}

export function createM365Posture({ dir } = {}) {
  async function load() {
    let names;
    try { names = await readdir(dir); } catch (e) { if (e.code === 'ENOENT') return { folderFound: false, scans: [] }; throw e; }
    const ids = names.map(n => n.match(FILE)?.[1]).filter(Boolean).sort().slice(-MAX_SCANS);
    const reports = {};
    for (const n of names) { const m = n.match(HTML); if (m) (reports[m[1]] ||= []).push(m[2]); }
    const scans = [];
    let skipped = 0;
    for (const id of ids) {
      const file = path.join(dir, `monkey365-${id}.json`);
      try {
        if ((await stat(file)).size > MAX_SUMMARY) { skipped++; continue; }
        const s = checkSummary(JSON.parse((await readFile(file, 'utf8')).replace(/^﻿/, '')), id);
        if (s) scans.push({ ...s, reports: AREAS.filter(a => reports[id]?.includes(a)) }); else skipped++;
      } catch { skipped++; }
    }
    scans.sort((a, b) => a.generatedAt.localeCompare(b.generatedAt) || a.id.localeCompare(b.id));
    return { folderFound: true, scans, skipped };
  }
  return {
    configured: Boolean(dir),
    // Every scan with its counts; rules only for the newest two per tenant (enough for "new" and "fixed" since last time).
    async list() {
      if (!dir) return { configured: false, folderFound: false, scans: [], skipped: 0 };
      const { folderFound, scans, skipped = 0 } = await load();
      const keep = new Set();
      const seen = {};
      for (const s of [...scans].reverse()) { seen[s.tenant] = (seen[s.tenant] || 0) + 1; if (seen[s.tenant] <= 2) keep.add(s.id); }
      return { configured: true, folderFound, skipped, scans: scans.map(s => (keep.has(s.id) ? s : { ...s, rules: undefined })) };
    },
    // Monkey365's HTML report for one scan and area, as a Buffer, or null.
    async report(id, area) {
      if (!dir || !REPORT_ID.test(id) || !AREAS.includes(area)) return null;
      const file = path.join(dir, `monkey365-${id}-${area}.html`);
      try {
        if ((await stat(file)).size > MAX_REPORT) return null;
        return await readFile(file);
      } catch { return null; }
    },
  };
}
