// Windows update status from Microsoft's official release information pages (learn.microsoft.com release health):
// every servicing build per version with its KB and date, and which versions are past end of updates per edition.
import { tables, text, kbOf } from './html.mjs';

export const RELEASE_PAGES = {
  11: 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information',
  10: 'https://learn.microsoft.com/en-us/windows/release-health/release-information',
};
export const windowsGeneration = build => (build >= 22000 ? 11 : 10);

const BUILD = /^(\d{5})\.(\d{1,6})$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

export function parseReleaseInfo(html) {
  // The hotpatch calendar lists hotpatch-only builds that most devices never get: stop before it.
  const cut = String(html).search(/hotpatch calendar/i);
  const page = cut > 0 ? String(html).slice(0, cut) : String(html);
  const builds = new Map();
  const editions = new Map(); // "24H2" -> { homePro: 'End of updates' | date, enterprise: ... }
  for (const t of tables(page)) {
    for (const cells of t.rows) {
      const texts = cells.map(c => c.text);
      if (/^\d{2}H\d/.test(texts[0] || '') && /General Availability/i.test(texts[1] || '') && texts.length >= 5)
        editions.set(texts[0].replace(/\W.*$/, ''), { homePro: texts[3], enterprise: texts[4] });
      // Summary rows ("24H2 | General Availability Channel | ...") mix availability and revision dates: builds come
      // from the release history rows only.
      if (/^(\d{2}H\d|\d{4})\b/.test(texts[0] || '')) continue;
      const bi = texts.findIndex(x => BUILD.test(x));
      if (bi < 0) continue;
      const [, major, ubr] = texts[bi].match(BUILD);
      const date = texts.find(x => DAY.test(x)) || null;
      const kb = cells.map(kbOf).find(Boolean) || null;
      const label = texts.find(x => /^\d{4}-\d{2} (B|C|D|OOB)\b/.test(x)) || null;
      const list = builds.get(Number(major)) || [];
      if (!list.some(b => b.ubr === Number(ubr))) list.push({ build: texts[bi], major: Number(major), ubr: Number(ubr), date, kb, label });
      builds.set(Number(major), list);
    }
  }
  for (const list of builds.values()) list.sort((a, b) => b.ubr - a.ubr);
  const versions = new Map(); // major build -> { version, endOfUpdatesAll }
  for (const m of text(page).matchAll(/Version (\w+) \(OS build (\d{5})\)( - End of (?:updates|servicing))?/g))
    if (!versions.has(Number(m[2]))) versions.set(Number(m[2]), { version: m[1], endOfUpdates: Boolean(m[3]) });
  return { builds, versions, editions };
}

const ENTERPRISE = /enterprise|education|iot|server/i;

export function windowsStatus(os, info, source) {
  if (!os || !os.build) return { status: 'unknown', reason: 'The scan did not report the Windows build.', source };
  const installed = `${os.build}.${os.ubr ?? 0}`;
  const list = info.builds.get(os.build);
  const ver = info.versions.get(os.build);
  const base = { version: ver?.version ?? os.displayVersion ?? null, installedBuild: installed, source };
  if (!list?.length) return { ...base, status: 'unknown', reason: `Microsoft's release information does not list OS build ${os.build}.` };
  const ed = info.editions.get(base.version);
  const edEnd = ed ? (ENTERPRISE.test(os.edition || '') ? ed.enterprise : ed.homePro) : null;
  const endOfUpdates = Boolean(ver?.endOfUpdates || /end of (updates|servicing)/i.test(edEnd || ''));
  const latest = list[0];
  const missing = list.filter(b => b.ubr > (os.ubr ?? 0));
  const status = endOfUpdates ? 'unsupported' : missing.length ? 'behind' : 'current';
  return { ...base, status, endOfUpdates, latest, missing: missing.slice(0, 12), missingCount: missing.length,
    reason: endOfUpdates ? `Windows ${windowsGeneration(os.build)} ${base.version} no longer gets updates for the ${os.edition || 'installed'} edition. Upgrade to a supported version.`
      : missing.length ? `${missing.length} newer update${missing.length > 1 ? 's' : ''} available. Latest is ${latest.build}${latest.kb ? ` (KB${latest.kb})` : ''}${latest.date ? `, released ${latest.date}` : ''}.`
      : `Up to date: ${installed} is the latest build.` };
}

// Microsoft's known-issues page for the installed version, e.g. status-windows-11-24h2.
export const knownIssuesUrl = (os, version) => version && os?.build
  ? `https://learn.microsoft.com/en-us/windows/release-health/status-windows-${windowsGeneration(os.build)}-${String(version).toLowerCase()}` : null;

export function parseKnownIssues(html) {
  const t = tables(html).find(x => x.header.some(h => /originating update/i.test(h)) && x.header.some(h => /^summary/i.test(h)));
  if (!t) return [];
  const col = name => t.header.findIndex(h => new RegExp(name, 'i').test(h));
  const [cs, co, cst, cu] = [col('^summary'), col('originating'), col('^status'), col('last updated')];
  return t.rows.map(cells => {
    const orig = cells[co]?.text || '';
    const bm = orig.match(/(\d{5})\.(\d{1,6})/);
    const st = cells[cst]?.text || '';
    return {
      title: cells[cs]?.strong || cells[cs]?.text?.slice(0, 160) || 'Untitled issue',
      originatingBuild: bm ? `${bm[1]}.${bm[2]}` : null,
      originatingKb: cells[co] ? kbOf(cells[co]) : null,
      status: (st.match(/^(Confirmed|Mitigated(?: External)?|Investigating|Resolved(?: External)?|Reported)/i) || [st.split(' ')[0] || 'Unknown'])[0],
      resolvedKb: /^resolved/i.test(st) && cells[cst] ? kbOf(cells[cst]) : null,
      lastUpdated: cells[cu]?.text || null,
    };
  });
}

// Which issues apply to this exact build. Fixes are matched to builds through the release information list.
export function evaluateIssues(issues, os, info, source) {
  const ubr = os?.ubr ?? 0;
  const builds = info.builds.get(os?.build) || [];
  const out = issues.map(i => {
    const om = i.originatingBuild?.match(/^(\d{5})\.(\d+)$/);
    const origUbr = om && Number(om[1]) === os?.build ? Number(om[2]) : null;
    const fix = i.resolvedKb ? builds.find(b => b.kb === i.resolvedKb) : null;
    let applies;
    if (origUbr !== null && ubr < origUbr) applies = 'not-affected';
    else if (/^resolved/i.test(i.status)) applies = fix && ubr >= fix.ubr ? 'fixed-installed' : (fix || i.resolvedKb ? 'fix-available' : 'resolved');
    else applies = origUbr === null ? 'may-affect' : 'affected';
    return { ...i, fixBuild: fix?.build ?? null, applies };
  });
  return { source, issues: out, open: out.filter(i => ['affected', 'may-affect', 'fix-available'].includes(i.applies)).length };
}
