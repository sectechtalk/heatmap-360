// AD posture page: Active Directory risk scores from PingCastle health checks, tracked over time.
//
// tools/adposture/Invoke-PingCastleScan.ps1 runs PingCastle (read-only toward the domain) as a scheduled task on the
// computer that hosts HeatMap 360 and saves three files per run in the AD posture folder:
//   pingcastle-<yyyyMMddHHmmss>.json   summary { schema: hm360.adposture/1, tool, domain, generatedAt, scores, rules }
//   pingcastle-<yyyyMMddHHmmss>.html   PingCastle's own report (offered as a download, never rendered in the page)
//   pingcastle-<yyyyMMddHHmmss>.xml    PingCastle's raw data (kept for later re-reading, not served)
// These reports name real accounts, groups and servers, so the folder is local only: it is never written to the GitHub
// data store and never exported. The server only reads it, checks every summary, and ignores anything else.
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const FILE = /^pingcastle-([0-9]{14})\.json$/;
export const REPORT_ID = /^[0-9]{14}$/;
const MAX_SUMMARY = 2 * 1024 * 1024, MAX_REPORT = 25 * 1024 * 1024, MAX_SCANS = 260, MAX_RULES = 500;
export const CATEGORIES = { StaleObjects: 'Stale objects', PrivilegedAccounts: 'Privileged accounts', Trusts: 'Trusts', Anomalies: 'Anomalies' };
const SCORE_KEYS = ['global', 'staleObjects', 'privilegedAccounts', 'trusts', 'anomalies'];

const str = (v, max) => (typeof v === 'string' && v.length <= max ? v : null);
const score = v => (Number.isInteger(v) && v >= 0 && v <= 100 ? v : null);

// Returns a clean summary, or null when the file is not a summary this page understands.
export function checkSummary(raw, id) {
  if (!raw || typeof raw !== 'object' || raw.schema !== 'hm360.adposture/1' || raw.tool !== 'PingCastle') return null;
  const domain = str(raw.domain, 255);
  const generatedAt = str(raw.generatedAt, 40);
  if (!domain || !/^[A-Za-z0-9.-]+$/.test(domain) || !generatedAt || Number.isNaN(Date.parse(generatedAt))) return null;
  const scores = {};
  for (const k of SCORE_KEYS) { scores[k] = score(raw.scores?.[k]); if (scores[k] === null) return null; }
  if (!Array.isArray(raw.rules) || raw.rules.length > MAX_RULES) return null;
  const rules = [];
  for (const r of raw.rules) {
    const ruleId = str(r?.id, 80);
    if (!ruleId || !/^[A-Za-z0-9_.-]+$/.test(ruleId) || !Object.hasOwn(CATEGORIES, r.category) || score(r.points) === null) return null;
    rules.push({ id: ruleId, category: r.category, points: r.points, rationale: str(r.rationale, 2000) || '', model: str(r.model, 120) || '' });
  }
  rules.sort((a, b) => b.points - a.points || a.id.localeCompare(b.id));
  const maturity = Number.isInteger(raw.maturityLevel) && raw.maturityLevel >= 1 && raw.maturityLevel <= 5 ? raw.maturityLevel : null;
  return { id, domain: domain.toLowerCase(), generatedAt: new Date(generatedAt).toISOString(), engineVersion: str(raw.engineVersion, 40), maturityLevel: maturity, scores, rules };
}

export function createAdPosture({ dir } = {}) {
  async function load() {
    let names;
    try { names = await readdir(dir); } catch (e) { if (e.code === 'ENOENT') return { folderFound: false, scans: [] }; throw e; }
    const ids = names.map(n => n.match(FILE)?.[1]).filter(Boolean).sort().slice(-MAX_SCANS);
    const html = new Set(names.filter(n => /^pingcastle-[0-9]{14}\.html$/.test(n)).map(n => n.slice(11, 25)));
    const scans = [];
    let skipped = 0;
    for (const id of ids) {
      const file = path.join(dir, `pingcastle-${id}.json`);
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
    // Every scan with its scores; rules only for the newest two per domain (enough for "new" and "fixed" since last time).
    async list() {
      if (!dir) return { configured: false, folderFound: false, scans: [], skipped: 0 };
      const { folderFound, scans, skipped = 0 } = await load();
      const keep = new Set();
      const seen = {};
      for (const s of [...scans].reverse()) { seen[s.domain] = (seen[s.domain] || 0) + 1; if (seen[s.domain] <= 2) keep.add(s.id); }
      return { configured: true, folderFound, skipped, scans: scans.map(s => (keep.has(s.id) ? s : { ...s, rules: undefined, ruleCount: s.rules.length })).map(s => ({ ...s, ruleCount: s.ruleCount ?? s.rules.length })) };
    },
    // PingCastle's HTML report for one scan, as a Buffer, or null.
    async report(id) {
      if (!dir || !REPORT_ID.test(id)) return null;
      const file = path.join(dir, `pingcastle-${id}.html`);
      try {
        if ((await stat(file)).size > MAX_REPORT) return null;
        return await readFile(file);
      } catch { return null; }
    },
  };
}
