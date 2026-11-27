// One scan result for the person who uploaded it, as a single .mhtml file (a web page archive that Edge and Chrome
// open offline). Everything in it comes from an anonymous upload or the bot, so every value is HTML-escaped, the page
// carries no script, and a Content-Security-Policy blocks anything that is not inline style.
import { randomBytes } from 'node:crypto';

const WORD = { ok: 'Good', warn: 'Needs attention', bad: 'Action needed', unknown: 'Not checked' };
const ISSUE = { affected: 'Affects this PC', 'may-affect': 'May affect this PC', 'fix-available': 'Fixed by a newer update', 'fixed-installed': 'Fixed (installed)', resolved: 'Resolved', 'not-affected': 'Not affected' };
const VERDICT = { affected: 'Vulnerable version', unverified: 'Check version', patched: 'Patched' };

const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Only plain https links become clickable; anything else is shown as text.
const link = u => /^https:\/\/[^\s"'<>]+$/i.test(String(u ?? '')) ? `<a href="${esc(u)}" rel="noreferrer">${esc(u)}</a>` : esc(u);
const gradeOf = g => (WORD[g] ? g : 'unknown');

const CSS = `
body{font:14px/1.45 "Segoe UI",system-ui,sans-serif;color:#142026;background:#fff;margin:0;padding:32px;max-width:1000px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;color:#0b6e69;margin:28px 0 8px;border-bottom:1px solid #d9e0e3;padding-bottom:4px}
.muted{color:#56666e}.small{font-size:12px}table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th,td{text-align:left;vertical-align:top;padding:5px 6px;border-bottom:1px solid #d9e0e3}th{color:#56666e;font-weight:600}
.badge{display:inline-block;font-weight:700;margin-right:8px}.ok{color:#1d7a3e}.warn{color:#9a6200}.bad{color:#b3261e}.unknown{color:#56666e}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:8px 0}dt{color:#56666e;font-weight:600}dd{margin:0}
ul{margin:4px 0 8px 18px;padding:0}a{color:#0b6e69;word-break:break-all}footer{margin-top:32px}
@media print{body{padding:0}}`;

export function renderReportHtml(result, { now = new Date() } = {}) {
  const out = [];
  const h2 = t => out.push(`<h2>${esc(t)}</h2>`);
  const p = (t, cls = '') => out.push(`<p${cls ? ` class="${cls}"` : ''}>${esc(t)}</p>`);
  const badge = (grade, label) => out.push(`<p><span class="badge ${gradeOf(grade)}">${esc(WORD[grade] || grade || 'Not checked')}</span>${esc(label)}</p>`);
  const kv = rows => out.push(`<dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v ?? 'Not reported')}</dd>`).join('')}</dl>`);
  const table = (head, rows) => out.push(`<table><thead><tr>${head.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`);
  const source = s => { if (s) out.push(`<p class="muted small">Source: ${link(s)}</p>`); };

  const inv = result.inventory || {};
  out.push('<h1>HeatMap 360 scan results</h1>');
  p(`Scan ${result.id}  ·  scanned ${inv.collectedAt || 'unknown'}  ·  checked ${result.processedAt || 'unknown'}  ·  file made ${now.toISOString()}`, 'muted small');

  if (result.rejected) { out.push(`<p class="bad">${esc(`This upload could not be checked: ${result.rejected}`)}</p>`); return page(result, out); }
  const s = result.summary || { grade: {} };
  s.grade ||= {};
  badge(s.overall, 'Overall');
  const sys = inv.hardware?.system || {};
  kv([['Computer', [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'Not reported'],
    ['Windows', inv.os ? `${inv.os.name || 'Windows'} ${inv.os.displayVersion || ''} (build ${inv.os.build}.${inv.os.ubr ?? 0})` : null],
    ['Anonymous computer ID', inv.machineId]]);

  h2('Windows updates');
  const w = result.windows || {};
  badge(s.grade.windows, w.reason || w.error || 'Could not check');
  if (w.missing?.length) table(['Update', 'Build', 'Released', 'KB'], w.missing.map(m => [m.label || '', m.build, m.date || '', m.kb ? `KB${m.kb}` : '']));
  source(w.source);

  h2('Known Windows issues reported by Microsoft');
  const ki = result.knownIssues || {};
  const shown = (ki.issues || []).filter(i => i.applies !== 'not-affected');
  if (ki.error || ki.reason) p(ki.error || ki.reason, 'muted');
  else if (!shown.length) p('Microsoft lists no open issue that applies to this build.');
  else table(['Issue', 'For this PC', 'Microsoft status', 'From update'], shown.map(i => [i.title, ISSUE[i.applies] || i.applies, (i.status || '') + (i.resolvedKb ? ` (KB${i.resolvedKb})` : ''), i.originatingKb ? `KB${i.originatingKb}` : i.originatingBuild || '']));
  source(ki.source);

  h2('App updates');
  const a = result.apps || {};
  if (a.error) p(`Could not check: ${a.error}`, 'muted');
  else {
    p(`${a.checked ?? 0} apps checked against the winget catalog; ${a.updates?.length ?? 0} have a newer version. ${a.unchecked?.length ?? 0} could not be checked.`);
    if (a.updates?.length) table(['App (winget ID)', 'Installed', 'Newest'], a.updates.map(u => [u.id, u.installed, u.latest]));
  }

  h2('Health checks');
  table(['Check', 'Result', 'Detail'], (result.health || []).map(c => [c.label, WORD[c.status] || c.status, c.detail]));

  const ev = result.eventLog;
  if (ev) {
    h2('Event log (last 7 days)');
    if (ev.status !== 'checked') p(ev.reason || ev.error || 'Not checked', 'muted');
    else {
      badge(ev.grade, ev.reason);
      if (ev.findings?.length) table(['What happened', 'Times', 'Result', 'What to do'], ev.findings.map(f => [f.label, f.count, f.status === 'info' ? 'Note' : WORD[f.status] || f.status, f.advice]));
      p('Counts only: event messages are never collected.', 'muted small');
    }
  }

  const nh = result.networkHealth;
  if (nh) {
    h2('Network health');
    if (nh.status !== 'checked') p(nh.reason || nh.error || 'Not checked', 'muted');
    else {
      badge(nh.grade, nh.reason);
      table(['Check', 'Result', 'Detail'], (nh.checks || []).map(c => [c.label, WORD[c.status] || c.status, c.detail]));
      p('Speed measured against Cloudflare\'s public speed test. No addresses are collected.', 'muted small');
    }
  }

  const net = result.network;
  if (net) {
    h2('Network adapters');
    if (net.status !== 'checked') p(net.reason || net.error || 'Not checked', 'muted');
    else {
      badge(net.grade, net.reason);
      const adapters = net.adapters || [];
      const rows = adapters.map(x => [x.description, x.connected ? `${x.linkSpeedMbps ?? '?'} Mbps${x.fullDuplex === false ? ' half duplex' : ''}` : x.status || 'Not connected',
        [x.driverVersion, x.driverDate && `(${x.driverDate})`].filter(Boolean).join(' '), (x.findings || []).filter(f => f.status !== 'ok').map(f => f.label).join('; ')]);
      if (rows.length) table(['Adapter', 'Link', 'Driver', 'Findings'], rows);
      if (net.wifi) kv([['Wi-Fi', [net.wifi.signalPercent != null && `signal ${net.wifi.signalPercent}%`, net.wifi.radioType, net.wifi.band].filter(Boolean).join(', ')]]);
      const notes = [...adapters.flatMap(x => x.findings || []), ...(net.wifi?.findings || [])].filter(x => x.status === 'warn' || x.status === 'bad');
      if (notes.length) out.push(`<ul>${notes.map(f => `<li>${esc(`${f.label}: ${f.detail}`)}</li>`).join('')}</ul>`);
    }
  }

  const ex = result.exploited || {};
  const open = ex.affected ? [...ex.affected, ...(ex.unverified || [])] : (ex.candidates || []);
  if (ex.status === 'checked' || open.length) {
    h2('Vulnerabilities exploited in the wild (CISA KEV)');
    if (ex.reason) badge(s.grade.exploited, ex.reason);
    if (!ex.affected && open.length) p('Candidates: this result was made before the version check was added. Check the installed version against each CVE.', 'muted');
    if (open.length) table(['CVE', 'Installed', 'For this PC', 'Fixed in', 'CISA due'], open.slice(0, 40).map(c => [c.cveID, c.app ? `${c.app}${c.version ? ` ${c.version}` : ''}` : `${c.vendor} ${c.product}`,
      VERDICT[c.verdict] || 'Check version', c.fixedIn || '', c.dueDate || '']));
    if (ex.patched?.length) p(`${ex.patched.length} other matches are already patched versions.`, 'muted');
    p('Versions are compared with the affected ranges in each official CVE record (cve.org).', 'muted small');
  }

  const ai = result.appIssues;
  if (ai) {
    h2('Known issues in apps (publisher release notes)');
    if (ai.status !== 'checked') p(ai.reason || ai.error || 'Not checked', 'muted');
    else {
      badge(ai.grade, ai.reason);
      for (const i of (ai.issues || []).slice(0, 20)) {
        out.push(`<p><strong>${esc(`${i.id} ${i.version}`)}</strong> ${esc(`(${i.which === 'installed' ? 'installed' : 'available update'})`)}</p>`);
        out.push(`<ul>${(i.items || []).slice(0, 5).map(t => `<li>${esc(t)}</li>`).join('')}</ul>`);
        source(i.source);
      }
    }
  }

  h2('Hardware');
  const fw = result.firmware;
  if (fw) {
    badge(fw.grade || 'unknown', `BIOS: ${fw.reason || fw.error || ''}`);
    if (fw.latest?.link) out.push(`<p class="muted small">Details: ${link(fw.latest.link)}</p>`);
    else if (fw.support) out.push(`<p class="muted small">${esc(fw.vendor)} support: ${link(fw.support)}</p>`);
  }
  if (result.hardware?.note) p(result.hardware.note, 'muted');
  const hw = inv.hardware || {};
  kv([['BIOS', hw.bios ? `${hw.bios.vendor || ''} ${hw.bios.version || ''} (${hw.bios.releaseDate || 'date unknown'})` : null],
    ['Motherboard', hw.baseboard ? `${hw.baseboard.manufacturer || ''} ${hw.baseboard.product || ''} ${hw.baseboard.version || ''}`.trim() : null],
    ['Processor', (hw.cpu || []).map(c => c.name).join('; ') || null],
    ['Memory', hw.memoryGB != null ? `${hw.memoryGB} GB` : null]]);
  if (hw.disks?.length) table(['Disk', 'Firmware', 'Type', 'Size'], hw.disks.map(d => [d.model, d.firmware, [d.mediaType, d.busType].filter(Boolean).join(' / '), d.sizeGB != null ? `${d.sizeGB} GB` : '']));
  if (hw.devices?.length) table(['Device', 'Class', 'Driver', 'Driver date'], hw.devices.slice(0, 60).map(d => [d.name, d.class, d.driverVersion, d.driverDate || '']));

  return page(result, out);
}

function page(result, out) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(`HeatMap 360 scan ${result.id}`)}</title><style>${CSS}</style></head>
<body>
${out.join('\n')}
<footer class="muted small">HeatMap 360 reads only official sources (Microsoft release health, the winget catalog and publisher release notes, CISA, CVE records, and HP and Lenovo update catalogs). Lookups that fail are shown as "Not checked" instead of guessed. The scan contains no computer name, user name, address, network name, serial number or event message.</footer>
</body></html>
`;
}

// Wrap the page as MHTML (RFC 2557 multipart/related, one base64 text/html part), which Edge and Chrome open directly.
// Served as message/rfc822, the registered type for .mhtml, which Express sets from the file name.
export function toMhtml(html, { title, now = new Date(), boundary = `----=_HeatMap360_${randomBytes(12).toString('hex')}` } = {}) {
  const b64 = Buffer.from(html, 'utf8').toString('base64').replace(/.{1,76}/g, '$&\r\n');
  const subject = /^[\x20-\x7e]*$/.test(title || '') ? title : `=?utf-8?B?${Buffer.from(title, 'utf8').toString('base64')}?=`;
  return Buffer.from([
    'From: <Saved by HeatMap 360>',
    `Subject: ${subject || 'HeatMap 360'}`,
    `Date: ${now.toUTCString()}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/related; type="text/html"; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset="utf-8"',
    'Content-Transfer-Encoding: base64',
    'Content-Location: https://heatmap360.invalid/scan.html',
    '',
    b64 + `--${boundary}--`,
    '',
  ].join('\r\n'), 'utf8');
}

export function renderReport(result, { now = new Date() } = {}) {
  return toMhtml(renderReportHtml(result, { now }), { title: `HeatMap 360 scan ${result.id}`, now });
}
