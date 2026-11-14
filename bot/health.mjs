// Health checks and known-exploited (CISA KEV) candidates for one scanned machine. Pure functions, no I/O.
const DAY = 86_400_000;
const norm = s => String(s ?? '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const tokens = s => new Set(norm(s).split(' ').filter(Boolean));
const days = (from, to) => (to - from) / DAY;
const check = (id, label, status, detail) => ({ id, label, status, detail });

export function lastUpdateDate(inv) {
  const ts = (inv.updates || []).map(u => Date.parse(u?.installedOn)).filter(Number.isFinite);
  return ts.length ? Math.max(...ts) : null;
}

export function healthChecks(inv, now = Date.now(), cfg = {}) {
  const warnFree = cfg.diskWarnPercentFree ?? 15, badFree = cfg.diskBadPercentFree ?? 5;
  const h = inv.health || {};
  const out = [];
  if (typeof inv.uptimeHours === 'number') {
    const d = inv.uptimeHours / 24;
    out.push(check('uptime', 'Time since restart', d > 30 ? 'bad' : d > 14 ? 'warn' : 'ok', `${d.toFixed(1)} days`));
  }
  if (typeof inv.pendingReboot === 'boolean') out.push(check('reboot', 'Restart pending', inv.pendingReboot ? 'warn' : 'ok', inv.pendingReboot ? 'A restart is needed to finish installing updates' : 'No'));
  const last = lastUpdateDate(inv);
  out.push(last
    ? check('patch', 'Last update installed', days(last, now) > 60 ? 'bad' : days(last, now) > 35 ? 'warn' : 'ok', `${Math.floor(days(last, now))} days ago (${new Date(last).toISOString().slice(0, 10)})`)
    : check('patch', 'Last update installed', 'unknown', 'Not reported'));
  if (h.defender) {
    const on = h.defender.enabled && h.defender.realTime;
    out.push(check('av', 'Defender real-time protection', on ? 'ok' : 'bad', on ? 'On' : 'Off'));
    if (typeof h.defender.signatureAgeDays === 'number')
      out.push(check('sig', 'Defender signatures', h.defender.signatureAgeDays > 7 ? 'bad' : h.defender.signatureAgeDays > 3 ? 'warn' : 'ok', `${h.defender.signatureAgeDays} days old`));
  } else out.push(check('av', 'Defender real-time protection', 'unknown', 'Not reported (another antivirus may be in use)'));
  const bl = h.bitlocker?.protection;
  out.push(check('bitlocker', 'BitLocker on the system drive', bl === 'On' ? 'ok' : bl === 'Off' ? 'bad' : 'unknown', bl ?? 'Not reported (run the scanner as administrator)'));
  out.push(check('secureboot', 'Secure Boot', h.secureBoot === true ? 'ok' : h.secureBoot === false ? 'warn' : 'unknown', h.secureBoot == null ? 'Not reported (run the scanner as administrator)' : h.secureBoot ? 'On' : 'Off'));
  if (h.tpm) out.push(check('tpm', 'TPM', h.tpm.present && h.tpm.ready ? 'ok' : 'warn', h.tpm.present ? (h.tpm.ready ? 'Present and ready' : 'Present, not ready') : 'Not present'));
  if (h.firewall) {
    const off = Object.entries(h.firewall).filter(([, v]) => v === false).map(([k]) => k);
    out.push(check('firewall', 'Firewall', off.length ? 'bad' : 'ok', off.length ? `Off for: ${off.join(', ')}` : 'On for all profiles'));
  }
  for (const v of inv.hardware?.volumes || []) {
    if (!v?.sizeGB) continue;
    const pct = (v.freeGB / v.sizeGB) * 100;
    out.push(check(`disk:${v.drive}`, `Free space on ${v.drive}`, pct < badFree ? 'bad' : pct < warnFree ? 'warn' : 'ok', `${pct.toFixed(0)}% free (${v.freeGB} of ${v.sizeGB} GB)`));
  }
  for (const [n, d] of (inv.hardware?.disks || []).entries()) {
    if (!d) continue;
    const name = d.model || `Disk ${n + 1}`;
    const bad = [], warn = [];
    if (/unhealthy/i.test(d.health || '')) bad.push('Windows reports it as unhealthy');
    else if (/warning/i.test(d.health || '')) warn.push('Windows reports a health warning');
    if ((d.readErrorsUncorrected ?? 0) + (d.writeErrorsUncorrected ?? 0) > 0) bad.push(`${(d.readErrorsUncorrected ?? 0) + (d.writeErrorsUncorrected ?? 0)} uncorrected read/write errors`);
    if (typeof d.wearPercent === 'number') (d.wearPercent >= 95 ? bad : d.wearPercent >= 80 ? warn : []).push(`${d.wearPercent}% of rated life used`);
    if (typeof d.temperatureC === 'number' && d.temperatureC >= 70) warn.push(`${d.temperatureC} °C`);
    const known = d.health || typeof d.wearPercent === 'number' || d.readErrorsUncorrected != null;
    if (!known) continue;
    const parts = [...bad, ...warn];
    const facts = [typeof d.wearPercent === 'number' && `${d.wearPercent}% worn`, typeof d.temperatureC === 'number' && `${d.temperatureC} °C`, typeof d.powerOnHours === 'number' && `${Math.round(d.powerOnHours).toLocaleString('en-US')} hours powered on`].filter(Boolean);
    out.push(check(`diskhealth:${n}`, `Disk health: ${name}`, bad.length ? 'bad' : warn.length ? 'warn' : 'ok',
      `${parts.length ? `${parts.join('; ')}. Back up this disk and plan to replace it.` : 'Healthy.'}${facts.length ? ` (${facts.join(', ')})` : ''}`));
  }
  const b = inv.hardware?.battery;
  if (b && typeof b.healthPercent === 'number') {
    const pct = Math.min(b.healthPercent, 100);
    out.push(check('battery', 'Battery health', pct < 50 ? 'bad' : pct < 80 ? 'warn' : 'ok',
      `Holds ${pct}% of its original charge${b.cycleCount ? ` after ${b.cycleCount} charge cycles` : ''}.${pct < 80 ? ' Expect shorter run time; consider a replacement battery.' : ''}`));
  }
  return out;
}

const STOP = new Set(['and', 'or', 'the', 'for', 'multiple', 'products']);
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
  const nameT = tokens(s.name), pubT = tokens(s.publisher);
  return nameT.has(first) && vendor.split(' ').some(t => nameT.has(t) || pubT.has(t));
}
const isWindowsEntry = v => norm(v.vendorProject) === 'microsoft' && /\bwindows\b|\bwin32k\b/.test(norm(v.product));

// KEV lists vendor + product, not versions: every match is a CANDIDATE to verify. Windows entries only count when
// they were added after the newest installed update (cumulative updates).
export function kevCandidates(inv, kev, epss = {}) {
  const apps = inv.apps || [];
  const last = lastUpdateDate(inv);
  const out = [];
  for (const v of kev?.vulnerabilities || []) {
    const base = { cveID: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, dateAdded: v.dateAdded,
      dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse === 'Known', epss: epss[v.cveID]?.epss ?? null };
    if (isWindowsEntry(v)) {
      if (!last || Date.parse(v.dateAdded) > last) out.push({ ...base, kind: 'os', reason: last ? 'Added after the newest installed update' : 'No update history reported' });
      continue;
    }
    const hit = apps.find(a => a?.name && softwareMatches(v, a));
    if (hit) out.push({ ...base, kind: 'app', app: hit.name, version: hit.version ?? null, reason: 'Installed program matches; check its version against the CVE' });
  }
  return out.sort((a, b) => (b.ransomware - a.ransomware) || ((b.epss ?? 0) - (a.epss ?? 0)) || String(b.dateAdded).localeCompare(String(a.dateAdded)));
}
