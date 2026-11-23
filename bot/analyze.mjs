// Turns one upload into one result. Every section is independent: a lookup that fails marks only its own section
// "unknown" with the reason, and the rest of the result is still produced.
import { windowsStatus, evaluateIssues, parseKnownIssues, knownIssuesUrl, RELEASE_PAGES, windowsGeneration } from './windows.mjs';
import { appStatus } from './apps.mjs';
import { healthChecks, kevCandidates } from './health.mjs';
import { eventLogChecks, networkChecks } from './machine.mjs';
import { firmwareStatus } from './firmware.mjs';
import { networkHealthChecks } from './nethealth.mjs';
import { verifyCandidates } from './cve.mjs';
import { appKnownIssues } from './appissues.mjs';

export const BOT_VERSION = '1.3.0';
const RANK = { ok: 0, info: 0, unknown: 1, warn: 2, bad: 3 };
const worst = list => list.reduce((w, s) => (RANK[s] > RANK[w] ? s : w), 'ok');

async function section(fn) {
  try { return await fn(); } catch (e) { return { status: 'unknown', error: String(e.message || e).slice(0, 300) }; }
}

// sources: { releaseInfo(generation) -> parsed, knownIssuesPage(url) -> html, wingetLatest(id) -> version|null, kev() -> { kev, epss },
//            vendorFile(url) -> text|null (null = 404), cveRecord(id) -> CVE JSON|null,
//            releaseNotes(id, version) -> { notes, url }|null, githubReleaseNotes({ owner, repo, tag }) -> text|null }
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
  const appIssues = await section(async () => {
    if (apps.status !== 'checked') return { status: 'unknown', reason: 'Needs the app update check first.' };
    if (!sources.releaseNotes) return { status: 'unknown', reason: 'Release notes lookup is not available.' };
    return appKnownIssues(apps, sources);
  });
  const exploited = await section(async () => {
    const f = await sources.kev();
    const build = os?.build && info ? (info.builds.get(os.build) || []).find(b => b.ubr === (os.ubr ?? 0)) : null;
    const candidates = kevCandidates(inv, f.kev, f.epss, { patchedThrough: build?.date ?? null });
    const all = sources.cveRecord ? await verifyCandidates(candidates, inv, sources.cveRecord)
      : candidates.map(c => ({ ...c, verdict: 'unverified', why: 'Version check is not available.' }));
    const affected = all.filter(c => c.verdict === 'affected'), unverified = all.filter(c => c.verdict === 'unverified'), patched = all.filter(c => c.verdict === 'patched');
    return { status: 'checked', catalogVersion: f.kev?.catalogVersion ?? null, affected, unverified, patched,
      // Kept for older pages: everything still open (affected first, then to verify).
      candidates: [...affected, ...unverified],
      reason: affected.length || unverified.length
        ? [affected.length && `${affected.length} vulnerable version${affected.length > 1 ? 's' : ''} installed`, unverified.length && `${unverified.length} to verify by hand`].filter(Boolean).join(', ') + `; ${patched.length} checked and patched.`
        : patched.length ? `All ${patched.length} matches are patched versions.` : 'Nothing installed matches the catalog.' };
  });
  const health = healthChecks(inv, now);
  const eventLog = await section(async () => eventLogChecks(inv));
  const nics = await section(async () => networkChecks(inv, now));
  const firmware = await section(async () => firmwareStatus(inv, sources.vendorFile, now));
  const netHealth = await section(async () => networkHealthChecks(inv));
  const hardware = { status: 'inventory', note: 'Driver and disk firmware update lookups with each vendor are planned. The BIOS is checked above.' };

  const grade = {
    windows: { current: 'ok', behind: (windows.missingCount ?? 0) > 1 ? 'bad' : 'warn', unsupported: 'bad' }[windows.status] ?? 'unknown',
    knownIssues: knownIssues.status === 'checked' ? ((knownIssues.issues || []).some(i => i.applies === 'affected') ? 'warn' : knownIssues.open ? 'warn' : 'ok') : 'unknown',
    apps: apps.status === 'checked' ? (apps.updates.length ? 'warn' : 'ok') : 'unknown',
    health: worst(health.map(c => c.status).filter(s => s !== 'unknown')),
    exploited: exploited.status === 'checked' ? (exploited.affected.length ? 'bad' : exploited.unverified.length ? 'warn' : 'ok') : 'unknown',
    appIssues: appIssues.status === 'checked' ? appIssues.grade : 'unknown',
    events: eventLog.status === 'checked' ? eventLog.grade : 'unknown',
    network: nics.status === 'checked' ? nics.grade : 'unknown',
    firmware: firmware.grade ?? 'unknown',
    netHealth: netHealth.status === 'checked' ? netHealth.grade : 'unknown',
  };
  const overall = worst(Object.values(grade).filter(s => s !== 'unknown'));
  return {
    schema: 'hm360.result/1', id: upload.id, receivedAt: upload.receivedAt, processedAt: new Date(now).toISOString(), botVersion: BOT_VERSION,
    tokenHash: upload.tokenHash, inventory: inv,
    summary: { overall, grade, windowsUpdates: windows.missingCount ?? null, openIssues: knownIssues.open ?? null,
      appUpdates: apps.updates?.length ?? null, healthProblems: health.filter(c => c.status === 'bad' || c.status === 'warn').length, exploited: exploited.affected?.length ?? null, exploitedToVerify: exploited.unverified?.length ?? null, appIssues: appIssues.onInstalled ?? null,
      eventProblems: eventLog.findings?.filter(f => f.status === 'warn' || f.status === 'bad').length ?? null, firmware: firmware.status ?? null,
      downloadMbps: inv.networkHealth?.speed?.downloadMbps ?? null },
    windows, knownIssues, apps, appIssues, health, exploited, eventLog, network: nics, networkHealth: netHealth, firmware, hardware,
  };
}
