// Turns collector envelopes + vulnerability feeds into one row per machine with health checks, KEV candidates and
// heat scores (0 = cool, 100 = hot). Pure functions: no I/O, so it is easy to test.

const DAY = 86_400_000;
const STATUS_HEAT = { ok: 0, unknown: 5, warn: 12, bad: 30 };

const norm = s => String(s ?? '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const tokens = s => new Set(norm(s).split(' ').filter(Boolean));
const days = (from, to) => (to - from) / DAY;

function check(id, label, status, detail) { return { id, label, status, detail }; }

export function healthChecks(env, now, cfg = {}) {
  const warnFree = cfg.diskWarnPercentFree ?? 15, badFree = cfg.diskBadPercentFree ?? 5;
  const out = [];
  const age = days(Date.parse(env.collectedAt), now);
  out.push(check('fresh', 'Collector data', age > 7 ? 'bad' : age > 1.1 ? 'warn' : 'ok', `collected ${age.toFixed(1)} days ago`));

  if (typeof env.uptimeHours === 'number') {
    const d = env.uptimeHours / 24;
    out.push(check('uptime', 'Uptime', d > 30 ? 'bad' : d > 14 ? 'warn' : 'ok', `${d.toFixed(1)} days since last boot`));
  }
  if (typeof env.pendingReboot === 'boolean') out.push(check('reboot', 'Pending reboot', env.pendingReboot ? 'warn' : 'ok', env.pendingReboot ? 'a reboot is pending' : 'none'));

  const last = lastPatchDate(env);
  if (last) {
    const d = days(last, now);
    out.push(check('patch', 'Last update installed', d > 60 ? 'bad' : d > 35 ? 'warn' : 'ok', `${Math.floor(d)} days ago (${new Date(last).toISOString().slice(0, 10)})`));
  } else out.push(check('patch', 'Last update installed', 'unknown', 'no update history reported'));

  const df = env.defender;
  if (df) {
    const on = df.enabled && df.realTime;
    out.push(check('av', 'Defender real-time protection', on ? 'ok' : 'bad', on ? 'on' : 'off'));
    if (typeof df.signatureAgeDays === 'number')
      out.push(check('sig', 'Defender signatures', df.signatureAgeDays > 7 ? 'bad' : df.signatureAgeDays > 3 ? 'warn' : 'ok', `${df.signatureAgeDays} days old`));
  } else out.push(check('av', 'Defender real-time protection', 'unknown', 'not reported'));

  const bl = env.bitlocker?.protection;
  out.push(check('bitlocker', 'BitLocker (system drive)', bl === 'On' ? 'ok' : bl === 'Off' ? 'bad' : 'unknown', bl ?? 'not reported (collector needs to run elevated)'));
  out.push(check('secureboot', 'Secure Boot', env.secureBoot === true ? 'ok' : env.secureBoot === false ? 'warn' : 'unknown', env.secureBoot == null ? 'not reported' : env.secureBoot ? 'on' : 'off'));
  if (env.tpm) out.push(check('tpm', 'TPM', env.tpm.present && env.tpm.ready ? 'ok' : 'warn', env.tpm.present ? (env.tpm.ready ? 'present and ready' : 'present, not ready') : 'not present'));
  if (env.firewall) {
    const off = Object.entries(env.firewall).filter(([, v]) => v === false).map(([k]) => k);
    out.push(check('firewall', 'Firewall profiles', off.length ? 'bad' : 'ok', off.length ? `off: ${off.join(', ')}` : 'all on'));
  }
  for (const d of env.disks || []) {
    if (!d.sizeGB) continue;
    const pct = (d.freeGB / d.sizeGB) * 100;
    out.push(check(`disk:${d.drive}`, `Disk ${d.drive}`, pct < badFree ? 'bad' : pct < warnFree ? 'warn' : 'ok', `${pct.toFixed(0)}% free (${d.freeGB} of ${d.sizeGB} GB)`));
  }
  return out;
}

export function lastPatchDate(env) {
  const ts = (env.hotfixes || []).map(h => Date.parse(h.installedOn)).filter(Number.isFinite);
  return ts.length ? Math.max(...ts) : null;
}

// KEV products that name the OS itself are matched against the patch date, not against installed software.
const isWindowsEntry = v => norm(v.vendorProject) === 'microsoft' && /\bwindows\b|\bwin32k\b/.test(norm(v.product));

const STOP = new Set(['and', 'or', 'the', 'for', 'multiple', 'products']);
// KEV names some products differently from how Windows lists the installed program.
const ALIASES = [
  { vendor: 'google', product: /^chromium\b/, software: /\b(google chrome|microsoft edge|brave|chromium)\b/ },
  { vendor: 'microsoft', product: /^(office|word|excel|outlook|powerpoint|publisher)\b/, software: /\bmicrosoft (office|365)\b/ },
];

export function softwareMatches(v, s) {
  const vendor = norm(v.vendorProject), product = norm(v.product), name = norm(s.name);
  const alias = ALIASES.find(a => a.vendor === vendor && a.product.test(product));
  if (alias) return alias.software.test(name);
  const first = product.split(' ').find(t => t && !STOP.has(t));
  if (!first) return false;
  const nameT = s.nameT ?? tokens(s.name), pubT = s.pubT ?? tokens(s.publisher);
  return nameT.has(first) && vendor.split(' ').some(t => nameT.has(t) || pubT.has(t));
}

// KEV has vendor + product but no version ranges, so a match is a CANDIDATE to verify, never a confirmed finding.
export function kevCandidates(env, kev, epss = {}) {
  const list = kev?.vulnerabilities || [];
  const software = (env.software || []).map(s => ({ ...s, nameT: tokens(s.name), pubT: tokens(s.publisher) }));
  const lastPatch = lastPatchDate(env);
  const out = [];
  for (const v of list) {
    const base = { cveID: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName,
      dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse === 'Known',
      epss: epss[v.cveID]?.epss ?? null };
    if (isWindowsEntry(v)) {
      // Cumulative updates: a machine patched after the KEV entry was added has very likely received the fix.
      if (!lastPatch || Date.parse(v.dateAdded) > lastPatch)
        out.push({ ...base, kind: 'os', reason: lastPatch ? 'added to KEV after the newest installed update' : 'no update history reported' });
      continue;
    }
    const hit = software.find(s => softwareMatches(v, s));
    if (hit) out.push({ ...base, kind: 'software', software: hit.name, version: hit.version ?? null, reason: 'installed product name matches; verify the version' });
  }
  return out.sort((a, b) => (b.ransomware - a.ransomware) || ((b.epss ?? 0) - (a.epss ?? 0)) || String(b.dateAdded).localeCompare(String(a.dateAdded)));
}

export function heat(checks, candidates) {
  const h = ids => Math.min(100, checks.filter(c => ids(c.id)).reduce((n, c) => n + STATUS_HEAT[c.status], 0));
  const health = h(id => !['patch', 'fresh'].includes(id));
  const patching = h(id => id === 'patch' || id === 'reboot');
  const exposure = Math.min(100, candidates.reduce((n, c) => n + 10 + (c.ransomware ? 10 : 0) + ((c.epss ?? 0) >= 0.5 ? 10 : 0), 0));
  const fresh = checks.find(c => c.id === 'fresh')?.status;
  return { health, patching, exposure, overall: Math.max(health, patching, exposure), stale: fresh !== 'ok' };
}

export function buildMachines(envelopes, feeds = {}, now = Date.now(), cfg = {}) {
  const machines = envelopes.map(env => {
    const checks = healthChecks(env, now, cfg);
    const candidates = kevCandidates(env, feeds.kev, feeds.epss);
    return { host: env.host, collectedAt: env.collectedAt, os: env.os ?? null, checks, candidates,
      heat: heat(checks, candidates), errors: env.errors || [] };
  }).sort((a, b) => b.heat.overall - a.heat.overall || a.host.localeCompare(b.host));
  return { generatedAt: new Date(now).toISOString(), machines,
    feeds: { kevVersion: feeds.kev?.catalogVersion ?? null, kevCount: feeds.kev?.vulnerabilities?.length ?? 0, fetchedAt: feeds.fetchedAt ?? null, lastError: feeds.lastError ?? null } };
}
