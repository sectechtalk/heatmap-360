// Turns one upload into one result. Every section is independent: a lookup that fails marks only its own section
// "unknown" with the reason, and the rest of the result is still produced.
import { windowsStatus, evaluateIssues, parseKnownIssues, knownIssuesUrl, RELEASE_PAGES, windowsGeneration } from './windows.mjs';
import { appStatus } from './apps.mjs';
import { healthChecks, kevCandidates } from './health.mjs';

export const BOT_VERSION = '1.0.0';
const RANK = { ok: 0, unknown: 1, warn: 2, bad: 3 };
const worst = list => list.reduce((w, s) => (RANK[s] > RANK[w] ? s : w), 'ok');

async function section(fn) {
  try { return await fn(); } catch (e) { return { status: 'unknown', error: String(e.message || e).slice(0, 300) }; }
}

// sources: { releaseInfo(generation) -> parsed, knownIssuesPage(url) -> html, wingetLatest(id) -> version|null, kev() -> { kev, epss } }
export async function analyze(upload, sources, now = Date.now()) {
  const inv = upload.inventory;
  const os = inv.os || null;
  let info = null;
  const windows = await section(async () => {
    if (!os?.build) return { status: 'unknown', reason: 'The scan did not report the Windows build.' };
    const gen = windowsGeneration(os.build);
    info = await sources.releaseInfo(gen);
    return windowsStatus(os, info, RELEASE_PAGES[gen]);
  });
  const knownIssues = await section(async () => {
    const url = knownIssuesUrl(os, windows.version);
    if (!url || !info) return { status: 'unknown', reason: 'Needs the Windows version from the release information first.', issues: [], open: 0 };
    const issues = parseKnownIssues(await sources.knownIssuesPage(url));
    return { status: 'checked', ...evaluateIssues(issues, os, info, url) };
  });
  const apps = await section(async () => ({ status: 'checked', ...(await appStatus(inv.winget || [], sources.wingetLatest)) }));
  const exploited = await section(async () => { const f = await sources.kev(); return { status: 'checked', candidates: kevCandidates(inv, f.kev, f.epss), catalogVersion: f.kev?.catalogVersion ?? null }; });
  const health = healthChecks(inv, now);
  const hardware = { status: 'inventory', note: 'Firmware and driver update lookups with each vendor are planned for a later version. This scan lists what is installed.' };

  const grade = {
    windows: { current: 'ok', behind: (windows.missingCount ?? 0) > 1 ? 'bad' : 'warn', unsupported: 'bad' }[windows.status] ?? 'unknown',
    knownIssues: knownIssues.status === 'checked' ? ((knownIssues.issues || []).some(i => i.applies === 'affected') ? 'warn' : knownIssues.open ? 'warn' : 'ok') : 'unknown',
    apps: apps.status === 'checked' ? (apps.updates.length ? 'warn' : 'ok') : 'unknown',
    health: worst(health.map(c => c.status).filter(s => s !== 'unknown')),
    exploited: exploited.status === 'checked' ? (exploited.candidates.length ? 'warn' : 'ok') : 'unknown',
  };
  const overall = worst(Object.values(grade).filter(s => s !== 'unknown'));
  return {
    schema: 'hm360.result/1', id: upload.id, receivedAt: upload.receivedAt, processedAt: new Date(now).toISOString(), botVersion: BOT_VERSION,
    tokenHash: upload.tokenHash, inventory: inv,
    summary: { overall, grade, windowsUpdates: windows.missingCount ?? null, openIssues: knownIssues.open ?? null,
      appUpdates: apps.updates?.length ?? null, healthProblems: health.filter(c => c.status === 'bad' || c.status === 'warn').length, exploited: exploited.candidates?.length ?? null },
    windows, knownIssues, apps, health, exploited, hardware,
  };
}
