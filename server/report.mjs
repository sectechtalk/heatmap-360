// PDF of one scan result for the person who uploaded it (built-in fonts, no external resources).
import PDFDocument from 'pdfkit';

const C = { ink: '#142026', muted: '#56666e', line: '#d9e0e3', accent: '#0b6e69', ok: '#1d7a3e', warn: '#9a6200', bad: '#b3261e', unknown: '#56666e' };
const WORD = { ok: 'Good', warn: 'Needs attention', bad: 'Action needed', unknown: 'Not checked' };
const ISSUE = { affected: 'Affects this PC', 'may-affect': 'May affect this PC', 'fix-available': 'Fixed by a newer update', 'fixed-installed': 'Fixed (installed)', resolved: 'Resolved', 'not-affected': 'Not affected' };

export function renderReport(result, { now = new Date() } = {}) {
  const doc = new PDFDocument({ size: 'LETTER', margin: 48, info: { Title: `HeatMap 360 scan ${result.id}`, Author: 'HeatMap 360' } });
  const chunks = [];
  doc.on('data', c => chunks.push(c));
  const done = new Promise(res => doc.on('end', () => res(Buffer.concat(chunks))));
  const W = doc.page.width - 96;

  const h1 = t => doc.font('Helvetica-Bold').fontSize(20).fillColor(C.ink).text(t);
  const h2 = t => { if (doc.y > doc.page.height - 140) doc.addPage(); doc.moveDown(0.8).font('Helvetica-Bold').fontSize(13).fillColor(C.accent).text(t).moveDown(0.3); };
  const p = (t, color = C.ink, size = 10) => doc.font('Helvetica').fontSize(size).fillColor(color).text(String(t ?? ''), { width: W });
  const kv = (k, v) => doc.font('Helvetica-Bold').fontSize(10).fillColor(C.muted).text(`${k}: `, { continued: true }).font('Helvetica').fillColor(C.ink).text(String(v ?? 'Not reported'));
  const badge = (grade, label) => doc.font('Helvetica-Bold').fontSize(10).fillColor(C[grade] || C.unknown).text(`${WORD[grade] || grade}  `, { continued: true }).font('Helvetica').fillColor(C.ink).text(label);
  function table(head, rows, widths) {
    const total = widths.reduce((a, b) => a + b, 0);
    const ws = widths.map(w => (w / total) * W);
    const row = (cells, bold) => {
      const hgt = Math.max(...cells.map((c, i) => doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(9).heightOfString(String(c ?? ''), { width: ws[i] - 6 }))) + 6;
      if (doc.y + hgt > doc.page.height - 48) { doc.addPage(); }
      const y = doc.y;
      let x = 48;
      cells.forEach((c, i) => { doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(9).fillColor(bold ? C.muted : C.ink).text(String(c ?? ''), x + 3, y + 3, { width: ws[i] - 6 }); x += ws[i]; });
      doc.moveTo(48, y + hgt).lineTo(48 + W, y + hgt).strokeColor(C.line).lineWidth(0.5).stroke();
      doc.x = 48; doc.y = y + hgt;
    };
    row(head, true);
    rows.forEach(r => row(r, false));
    doc.moveDown(0.3);
  }

  const inv = result.inventory || {};
  h1('HeatMap 360 scan results');
  p(`Scan ${result.id}  ·  scanned ${inv.collectedAt || 'unknown'}  ·  checked ${result.processedAt || 'unknown'}  ·  PDF made ${now.toISOString()}`, C.muted, 9);
  doc.moveDown(0.6);

  if (result.rejected) { p(`This upload could not be checked: ${result.rejected}`, C.bad, 11); doc.end(); return done; }
  const s = result.summary;
  badge(s.overall, 'Overall');
  doc.moveDown(0.3);
  const sys = inv.hardware?.system || {};
  kv('Computer', [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'Not reported');
  kv('Windows', inv.os ? `${inv.os.name || 'Windows'} ${inv.os.displayVersion || ''} (build ${inv.os.build}.${inv.os.ubr ?? 0})` : null);
  kv('Anonymous computer ID', inv.machineId);

  h2('Windows updates');
  const w = result.windows || {};
  badge(s.grade.windows, w.reason || w.error || 'Could not check');
  if (w.missing?.length) table(['Update', 'Build', 'Released', 'KB'], w.missing.map(m => [m.label || '', m.build, m.date || '', m.kb ? `KB${m.kb}` : '']), [2, 2, 2, 2]);
  if (w.source) p(`Source: ${w.source}`, C.muted, 8);

  h2('Known Windows issues reported by Microsoft');
  const ki = result.knownIssues || {};
  const shown = (ki.issues || []).filter(i => i.applies !== 'not-affected');
  if (ki.error || ki.reason) p(ki.error || ki.reason, C.muted);
  else if (!shown.length) p('Microsoft lists no open issue that applies to this build.');
  else table(['Issue', 'For this PC', 'Microsoft status', 'From update'], shown.map(i => [i.title, ISSUE[i.applies] || i.applies, i.status + (i.resolvedKb ? ` (KB${i.resolvedKb})` : ''), i.originatingKb ? `KB${i.originatingKb}` : i.originatingBuild || '']), [5, 2, 2, 1.5]);
  if (ki.source) p(`Source: ${ki.source}`, C.muted, 8);

  h2('App updates');
  const a = result.apps || {};
  if (a.error) p(`Could not check: ${a.error}`, C.muted);
  else {
    p(`${a.checked ?? 0} apps checked against the winget catalog; ${a.updates?.length ?? 0} have a newer version. ${a.unchecked?.length ?? 0} could not be checked.`);
    if (a.updates?.length) table(['App (winget ID)', 'Installed', 'Newest'], a.updates.map(u => [u.id, u.installed, u.latest]), [4, 2, 2]);
  }

  h2('Health checks');
  table(['Check', 'Result', 'Detail'], (result.health || []).map(c => [c.label, WORD[c.status] || c.status, c.detail]), [3, 2, 4]);

  const ev = result.eventLog;
  if (ev) {
    h2('Event log (last 7 days)');
    if (ev.status !== 'checked') p(ev.reason || ev.error || 'Not checked', C.muted);
    else {
      badge(ev.grade, ev.reason);
      if (ev.findings?.length) table(['What happened', 'Times', 'Result', 'What to do'], ev.findings.map(f => [f.label, f.count, f.status === 'info' ? 'Note' : WORD[f.status] || f.status, f.advice]), [3, 1, 1.5, 5]);
      p('Counts only: event messages are never collected.', C.muted, 8);
    }
  }

  const nh = result.networkHealth;
  if (nh) {
    h2('Network health');
    if (nh.status !== 'checked') p(nh.reason || nh.error || 'Not checked', C.muted);
    else {
      badge(nh.grade, nh.reason);
      table(['Check', 'Result', 'Detail'], nh.checks.map(c => [c.label, WORD[c.status] || c.status, c.detail]), [3, 1.5, 5.5]);
      p('Speed measured against Cloudflare\'s public speed test. No addresses are collected.', C.muted, 8);
    }
  }

  const net = result.network;
  if (net) {
    h2('Network adapters');
    if (net.status !== 'checked') p(net.reason || net.error || 'Not checked', C.muted);
    else {
      badge(net.grade, net.reason);
      const rows = net.adapters.map(a => [a.description, a.connected ? `${a.linkSpeedMbps ?? '?'} Mbps${a.fullDuplex === false ? ' half duplex' : ''}` : a.status || 'Not connected',
        [a.driverVersion, a.driverDate && `(${a.driverDate})`].filter(Boolean).join(' '), a.findings.filter(f => f.status !== 'ok').map(f => f.label).join('; ')]);
      if (rows.length) table(['Adapter', 'Link', 'Driver', 'Findings'], rows, [4, 2, 2.5, 3.5]);
      if (net.wifi) kv('Wi-Fi', [net.wifi.signalPercent != null && `signal ${net.wifi.signalPercent}%`, net.wifi.radioType, net.wifi.band].filter(Boolean).join(', '));
      for (const f of [...net.adapters.flatMap(a => a.findings), ...(net.wifi?.findings || [])].filter(x => x.status === 'warn' || x.status === 'bad')) p(`• ${f.label}: ${f.detail}`, C.ink, 9);
    }
  }

  const ex = result.exploited || {};
  const open = ex.affected ? [...ex.affected, ...ex.unverified] : (ex.candidates || []);
  if (ex.status === 'checked' || open.length) {
    h2('Vulnerabilities exploited in the wild (CISA KEV)');
    if (ex.reason) badge(s.grade.exploited, ex.reason);
    if (!ex.affected && open.length) p('Candidates: this result was made before the version check was added. Check the installed version against each CVE.', C.muted, 9);
    const VERDICT = { affected: 'Vulnerable version', unverified: 'Check version', patched: 'Patched' };
    if (open.length) table(['CVE', 'Installed', 'For this PC', 'Fixed in', 'CISA due'], open.slice(0, 40).map(c => [c.cveID, c.app ? `${c.app}${c.version ? ` ${c.version}` : ''}` : `${c.vendor} ${c.product}`,
      VERDICT[c.verdict] || 'Check version', c.fixedIn || '', c.dueDate || '']), [2, 3.5, 2, 2, 1.5]);
    if (ex.patched?.length) p(`${ex.patched.length} other matches are already patched versions.`, C.muted, 9);
    p('Versions are compared with the affected ranges in each official CVE record (cve.org).', C.muted, 8);
  }

  const ai = result.appIssues;
  if (ai) {
    h2('Known issues in apps (publisher release notes)');
    if (ai.status !== 'checked') p(ai.reason || ai.error || 'Not checked', C.muted);
    else {
      badge(ai.grade, ai.reason);
      for (const i of ai.issues.slice(0, 20)) {
        p(`${i.id} ${i.version} (${i.which === 'installed' ? 'installed' : 'available update'}):`, C.ink, 9);
        for (const t of i.items.slice(0, 5)) p(`• ${t}`, C.ink, 8.5);
        p(`Source: ${i.source}`, C.muted, 8);
      }
    }
  }

  h2('Hardware');
  const fw = result.firmware;
  if (fw) {
    badge(fw.grade || 'unknown', `BIOS: ${fw.reason || fw.error || ''}`);
    if (fw.latest?.link) p(`Details: ${fw.latest.link}`, C.muted, 8);
    else if (fw.support) p(`${fw.vendor} support: ${fw.support}`, C.muted, 8);
    doc.moveDown(0.3);
  }
  p(result.hardware?.note || '', C.muted, 9);
  const hw = inv.hardware || {};
  kv('BIOS', hw.bios ? `${hw.bios.vendor || ''} ${hw.bios.version || ''} (${hw.bios.releaseDate || 'date unknown'})` : null);
  kv('Motherboard', hw.baseboard ? `${hw.baseboard.manufacturer || ''} ${hw.baseboard.product || ''} ${hw.baseboard.version || ''}`.trim() : null);
  kv('Processor', (hw.cpu || []).map(c => c.name).join('; ') || null);
  kv('Memory', hw.memoryGB != null ? `${hw.memoryGB} GB` : null);
  if (hw.disks?.length) table(['Disk', 'Firmware', 'Type', 'Size'], hw.disks.map(d => [d.model, d.firmware, [d.mediaType, d.busType].filter(Boolean).join(' / '), d.sizeGB != null ? `${d.sizeGB} GB` : '']), [4, 2, 2, 1]);
  if (hw.devices?.length) table(['Device', 'Class', 'Driver', 'Driver date'], hw.devices.slice(0, 60).map(d => [d.name, d.class, d.driverVersion, d.driverDate || '']), [5, 1.5, 2, 1.5]);

  doc.moveDown(1);
  p('HeatMap 360 reads only official sources (Microsoft release health, the winget catalog and publisher release notes, CISA, CVE records, and HP and Lenovo update catalogs). Lookups that fail are shown as "Not checked" instead of guessed. The scan contains no computer name, user name, address, network name, serial number or event message.', C.muted, 8);
  doc.end();
  return done;
}
