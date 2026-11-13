// HeatMap 360 UI. Plain DOM (CSP: script-src 'self'), hash routes: #scans, #scan/<id>, #actions, #scanner.
'use strict';
const $ = s => document.querySelector(s);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (k in e && k !== 'list') e[k] = v; else e.setAttribute(k, v);
  }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k instanceof Node ? k : String(k));
  return e;
}
const WORD = { ok: 'Good', warn: 'Needs attention', bad: 'Action needed', unknown: 'Not checked' };
const chip = (grade, label) => h('span', { class: `chip ${grade || 'unknown'}` }, label || WORD[grade] || grade);
const when = iso => (iso ? new Date(iso).toLocaleString() : '');
const table = (head, rows, empty = 'Nothing to show.') => rows.length
  ? h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, head.map(t => h('th', {}, t)))), h('tbody', {}, rows)))
  : h('p', { class: 'muted' }, empty);
const panel = (title, sub, ...body) => h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', {}, title), sub ? h('span', { class: 'sub' }, sub) : null), body);
const link = (href, text) => h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);
function toast(msg) { const t = h('div', { class: 'toast', role: 'status' }, msg); document.body.append(t); setTimeout(() => t.remove(), 3500); }

let me = null;
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { ...(opts.headers || {}), ...(me?.csrf ? { 'x-csrf': me.csrf } : {}) } });
  const body = r.headers.get('content-type')?.includes('json') ? await r.json() : null;
  if (!r.ok) throw Object.assign(new Error(body?.error || `HTTP ${r.status}`), { status: r.status });
  return body;
}

function renderAccount() {
  const a = $('#account');
  a.replaceChildren();
  if (!me) return;
  if (me.signedIn) {
    a.append(h('div', { class: 'who' }, me.user?.name || 'Signed in'), me.elevated ? chip('ok', 'Elevated') : chip('warn', 'Not elevated'));
    if (!me.dev) a.append(h('button', { class: 'btn sm', onclick: async () => { await api('/auth/signout', { method: 'POST' }); location.hash = '#scanner'; await boot(); } }, 'Sign out'));
  } else if (me.authConfigured) a.append(h('a', { class: 'btn sm primary', href: '/auth/signin' }, 'Sign in'));
  if (me.dev) a.append(h('span', { class: 'small' }, 'Local development mode'));
}

// ---------- gate for admin pages ----------
function gate() {
  if (!me.signedIn) return h('div', { class: 'empty' },
    h('h2', {}, 'Sign in to see scan results'),
    h('p', { class: 'muted' }, 'Results are for HeatMap 360 admins. Sign in with your work account, then activate your HeatMap 360 PIM group.'),
    me.authConfigured ? h('a', { class: 'btn primary', href: '/auth/signin' }, 'Sign in with Microsoft') : h('p', { class: 'callout warn' }, 'Sign-in is not configured on this server yet.'),
    h('a', { href: '#scanner' }, 'Just want to scan a computer? Get the scanner'));
  return h('div', { class: 'empty' },
    h('h2', {}, 'Elevate to see scan results'),
    h('p', { class: 'muted' }, 'You are signed in, but your HeatMap 360 group membership is not active. Activate it in Privileged Identity Management, then check again.'),
    h('div', { class: 'row' },
      h('a', { class: 'btn primary', href: me.activateUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Open PIM to activate'),
      h('button', { class: 'btn', onclick: async e => {
        e.target.disabled = true;
        try { const r = await api('/api/me/recheck', { method: 'POST' }); if (r.elevated) { toast('Elevated.'); await boot(); } else toast('Still not active. Activation can take a minute.'); }
        catch (err) { toast(err.message); } finally { e.target.disabled = false; }
      } }, 'I activated it, check again')));
}

// ---------- Scans ----------
async function viewScans() {
  if (!me.elevated) return [h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scans'))), gate()];
  const data = await api('/api/admin/scans');
  const s = data.scans.filter(x => x.state === 'done');
  const count = f => s.filter(f).length;
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scans'), h('p', {}, 'Every computer that ran the scanner, newest first. Select a scan for the full results.'))),
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, s.length), h('span', { class: 'l' }, 'Scans')),
      h('div', {}, h('span', { class: 'n' }, count(x => x.summary.overall === 'bad')), h('span', { class: 'l' }, 'Need action')),
      h('div', {}, h('span', { class: 'n' }, count(x => x.summary.grade.windows !== 'ok')), h('span', { class: 'l' }, 'Windows not current')),
      h('div', {}, h('span', { class: 'n' }, s.reduce((n, x) => n + (x.summary.appUpdates || 0), 0)), h('span', { class: 'l' }, 'App updates waiting'))),
    data.queued.length ? h('p', { class: 'callout' }, `${data.queued.length} scan${data.queued.length > 1 ? 's are' : ' is'} waiting for the bot. Results appear here when it has run.`) : null,
    table(['Result', 'Computer', 'Windows', 'Windows updates', 'App updates', 'Known issues', 'Scanned'],
      data.scans.map(x => x.state === 'rejected'
        ? h('tr', {}, h('td', {}, chip('bad', 'Rejected')), h('td', { colSpan: 5 }, x.reason), h('td', { class: 'nowrap' }, when(x.receivedAt)))
        : h('tr', { class: 'link', tabIndex: 0, onclick: () => { location.hash = `#scan/${x.id}`; }, onkeydown: e => { if (e.key === 'Enter') location.hash = `#scan/${x.id}`; } },
          h('td', {}, chip(x.summary.overall)),
          h('td', {}, x.computer || h('span', { class: 'muted' }, 'Unknown'), h('div', { class: 'muted small' }, `ID ${x.machineId}`)),
          h('td', {}, x.windows || '', h('div', { class: 'muted small' }, x.build || '')),
          h('td', {}, chip(x.summary.grade.windows, x.summary.windowsUpdates ? `${x.summary.windowsUpdates} behind` : WORD[x.summary.grade.windows])),
          h('td', { class: 'num' }, x.summary.appUpdates ?? '–'),
          h('td', { class: 'num' }, x.summary.openIssues ?? '–'),
          h('td', { class: 'nowrap' }, when(x.collectedAt || x.receivedAt)))),
      'No scans yet. Share the scanner from "Get the scanner".'),
  ];
}

// ---------- One scan ----------
const ISSUE = { affected: ['bad', 'Affects this PC'], 'may-affect': ['warn', 'May affect this PC'], 'fix-available': ['warn', 'Fixed by a newer update'],
  'fixed-installed': ['ok', 'Fixed, installed'], resolved: ['ok', 'Resolved'], 'not-affected': ['ok', 'Not affected'] };

async function viewScan(id) {
  if (!me.elevated) return [gate()];
  const r = await api(`/api/admin/scans/${encodeURIComponent(id)}`);
  const inv = r.inventory || {}, s = r.summary, w = r.windows || {}, ki = r.knownIssues || {}, a = r.apps || {}, ex = r.exploited || {}, hw = inv.hardware || {};
  const sys = hw.system || {};
  const area = (grade, title, detail, target) => h('div', { class: 'area' }, h('span', { class: `bar ${grade}` }), h('div', {}, h('strong', {}, title), h('div', { class: 'muted small' }, detail)), target ? h('a', { href: `#scan/${id}`, onclick: e => { e.preventDefault(); document.getElementById(target)?.scrollIntoView({ behavior: 'smooth' }); } }, 'Details') : null);
  const issues = (ki.issues || []).filter(i => i.applies !== 'not-affected');
  return [
    h('div', { class: 'page-head' },
      h('div', {}, h('a', { href: '#scans', class: 'small' }, '← All scans'), h('h1', {}, [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'Scanned computer'),
        h('p', {}, `Anonymous ID ${inv.machineId} · scanned ${when(inv.collectedAt)} · checked ${when(r.processedAt)}`)),
      h('a', { class: 'btn', href: `/api/admin/scans/${encodeURIComponent(id)}/report.pdf` }, 'Download PDF')),
    h('section', { class: 'panel' },
      h('div', { class: 'verdict' }, h('span', { class: `dot ${s.overall}` }), h('div', {}, h('h2', {}, WORD[s.overall]), h('p', { class: 'muted' }, 'Each area below is checked against the vendor’s official source. Anything that could not be checked says so.'))),
      h('div', { style: '' },
        area(s.grade.windows, 'Windows updates', w.reason || w.error || 'Not checked', 'sec-windows'),
        area(s.grade.knownIssues, 'Known Windows issues', ki.error || ki.reason || (ki.open ? `${ki.open} issue${ki.open > 1 ? 's' : ''} reported by Microsoft may apply` : 'No reported issue applies to this build'), 'sec-issues'),
        area(s.grade.apps, 'App updates', a.error || `${a.updates?.length ?? 0} of ${a.checked ?? 0} checked apps have a newer version`, 'sec-apps'),
        area(s.grade.health, 'Health', `${s.healthProblems} check${s.healthProblems === 1 ? '' : 's'} need attention`, 'sec-health'),
        area(s.grade.exploited, 'Exploited in the wild (CISA)', ex.error || `${ex.candidates?.length ?? 0} candidate${ex.candidates?.length === 1 ? '' : 's'} to verify`, 'sec-kev'),
        area('unknown', 'Hardware and firmware', 'Inventory listed below; vendor update lookups come in a later version', 'sec-hw'))),
    h('div', { id: 'sec-windows' }, panel('Windows updates', inv.os ? `${inv.os.name || 'Windows'} ${inv.os.displayVersion || ''} · build ${w.installedBuild || ''}` : '',
      h('p', {}, chip(s.grade.windows), ' ', w.reason || w.error || 'Not checked'),
      w.missing?.length ? table(['Update', 'Build', 'Released', 'KB'], w.missing.map(m => h('tr', {}, h('td', {}, m.label || ''), h('td', {}, m.build), h('td', { class: 'nowrap' }, m.date || ''),
        h('td', {}, m.kb ? link(`https://support.microsoft.com/help/${m.kb}`, `KB${m.kb}`) : '')))) : null,
      w.source ? h('p', { class: 'muted small' }, 'Source: ', link(w.source, 'Microsoft release information')) : null)),
    h('div', { id: 'sec-issues' }, panel('Known Windows issues', 'Reported by Microsoft for this Windows version',
      ki.error || ki.reason ? h('p', { class: 'muted' }, ki.error || ki.reason)
        : table(['Issue', 'For this PC', 'Microsoft status', 'Started with'], issues.map(i => h('tr', {}, h('td', {}, i.title), h('td', {}, chip(...(ISSUE[i.applies] || ['unknown', i.applies]))),
          h('td', {}, i.status, i.resolvedKb ? h('div', { class: 'small' }, link(`https://support.microsoft.com/help/${i.resolvedKb}`, `Fix: KB${i.resolvedKb}`)) : null),
          h('td', {}, i.originatingKb ? link(`https://support.microsoft.com/help/${i.originatingKb}`, `KB${i.originatingKb}`) : i.originatingBuild || ''))), 'Microsoft lists no issue that applies to this build.'),
      ki.source ? h('p', { class: 'muted small' }, 'Source: ', link(ki.source, 'Windows release health')) : null)),
    h('div', { id: 'sec-apps' }, panel('App updates', 'Newest versions from the winget catalog',
      a.error ? h('p', { class: 'muted' }, a.error) : [
        table(['App (winget ID)', 'Installed', 'Newest'], (a.updates || []).map(u => h('tr', {}, h('td', {}, link(u.link, u.id)), h('td', {}, u.installed), h('td', {}, h('strong', {}, u.latest)))), 'Every checked app is on its newest version.'),
        a.current?.length ? h('details', {}, h('summary', {}, `${a.current.length} apps up to date`), table(['App', 'Version'], a.current.map(u => h('tr', {}, h('td', {}, u.id), h('td', {}, u.installed))))) : null,
        a.unchecked?.length ? h('details', {}, h('summary', {}, `${a.unchecked.length} apps not checked`), table(['App', 'Installed', 'Why'], a.unchecked.map(u => h('tr', {}, h('td', {}, u.id), h('td', {}, u.installed ?? ''), h('td', { class: 'muted' }, u.reason))))) : null,
        h('details', {}, h('summary', {}, `All ${inv.apps?.length ?? 0} installed programs`), table(['Program', 'Version', 'Publisher'], (inv.apps || []).map(p => h('tr', {}, h('td', {}, p.name), h('td', {}, p.version ?? ''), h('td', { class: 'muted' }, p.publisher ?? ''))))),
      ])),
    h('div', { id: 'sec-health' }, panel('Health', null, table(['Check', 'Result', 'Detail'], (r.health || []).map(c => h('tr', {}, h('td', {}, c.label), h('td', {}, chip(c.status)), h('td', { class: 'muted' }, c.detail)))))),
    h('div', { id: 'sec-kev' }, panel('Exploited in the wild', 'CISA Known Exploited Vulnerabilities',
      ex.error ? h('p', { class: 'muted' }, ex.error) : [
        h('p', { class: 'muted small' }, 'Candidates, not confirmed findings: the catalog names products, not versions. Check the installed version against each CVE.'),
        table(['CVE', 'Product', 'Why', 'Ransomware', 'CISA due'], (ex.candidates || []).map(c => h('tr', {}, h('td', { class: 'nowrap' }, link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cveID)}`, c.cveID)),
          h('td', {}, c.app ? `${c.app}${c.version ? ` ${c.version}` : ''}` : `${c.vendor} ${c.product}`), h('td', { class: 'muted' }, c.reason), h('td', {}, c.ransomware ? chip('bad', 'Known') : ''), h('td', { class: 'nowrap' }, c.dueDate || ''))), 'No candidates.')])),
    h('div', { id: 'sec-hw' }, panel('Hardware and firmware', r.hardware?.note || '',
      h('dl', { class: 'kv' },
        h('dt', {}, 'Computer'), h('dd', {}, [sys.manufacturer, sys.model, sys.family && `(${sys.family})`].filter(Boolean).join(' ') || 'Not reported'),
        h('dt', {}, 'BIOS'), h('dd', {}, hw.bios ? `${hw.bios.vendor || ''} ${hw.bios.version || ''}${hw.bios.releaseDate ? `, ${hw.bios.releaseDate}` : ''}` : 'Not reported'),
        h('dt', {}, 'Motherboard'), h('dd', {}, hw.baseboard ? [hw.baseboard.manufacturer, hw.baseboard.product, hw.baseboard.version].filter(Boolean).join(' ') : 'Not reported'),
        h('dt', {}, 'Processor'), h('dd', {}, (hw.cpu || []).map(c => c.name).join('; ') || 'Not reported'),
        h('dt', {}, 'Memory'), h('dd', {}, hw.memoryGB != null ? `${hw.memoryGB} GB` : 'Not reported'),
        h('dt', {}, 'TPM'), h('dd', {}, inv.health?.tpm ? `${inv.health.tpm.present ? 'Present' : 'Not present'}${inv.health.tpm.manufacturerVersion ? `, firmware ${inv.health.tpm.manufacturerVersion}` : ''}` : 'Not reported')),
      h('h3', {}, 'Disks'),
      table(['Disk', 'Firmware', 'Type', 'Size'], (hw.disks || []).map(d => h('tr', {}, h('td', {}, d.model), h('td', {}, d.firmware ?? ''), h('td', {}, [d.mediaType, d.busType].filter(Boolean).join(' / ')), h('td', { class: 'num' }, d.sizeGB != null ? `${d.sizeGB} GB` : ''))), 'Not reported.'),
      h('h3', {}, 'Devices and drivers'),
      table(['Device', 'Class', 'Driver', 'Driver date', 'Provider'], (hw.devices || []).map(d => h('tr', {}, h('td', {}, d.name), h('td', {}, d.class), h('td', {}, d.driverVersion), h('td', { class: 'nowrap' }, d.driverDate ?? ''), h('td', { class: 'muted' }, d.driverProvider ?? ''))), 'Not reported.'))),
    inv.errors?.length ? panel('What the scanner could not read', null, h('ul', {}, inv.errors.map(e => h('li', { class: 'muted' }, e)))) : null,
  ];
}

// ---------- Actions ----------
function viewActions() {
  const soon = (title, text) => h('section', { class: 'panel stack' }, h('div', { class: 'row' }, h('h2', {}, title), chip('info', 'Planned')), h('p', { class: 'muted' }, text), h('button', { class: 'btn', disabled: true }, 'Not available yet'));
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Actions'), h('p', {}, 'On-demand tools for admins. These are being designed and will appear here as they are built.'))),
    me.elevated ? null : h('p', { class: 'callout warn' }, 'Actions will need an active HeatMap 360 PIM group membership.'),
    h('div', { class: 'grid-3' },
      soon('Vulnerability scan', 'Run an on-demand vulnerability check on a scanned computer.'),
      soon('Hardware diagnostics', 'Check disks, memory and batteries, and look up firmware updates with each vendor.'),
      soon('Network health', 'Measure internet speed and the link between the computer and its gateway, and check the network adapter settings.')),
  ];
}

// ---------- Scanner (public) ----------
function viewScanner() {
  const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File .\\Invoke-HeatMapScan.ps1';
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scan a Windows computer'), h('p', {}, 'The scanner lists what is installed, sends it to HeatMap 360 without anything that identifies you or the computer, and saves your results as a PDF.'))),
    h('div', { class: 'grid-2' },
      panel('Three steps', null, h('ol', { class: 'steps-list' },
        h('li', {}, h('strong', {}, 'Download the scanner'), h('div', {}, h('a', { class: 'btn primary', href: me.scannerUrl, download: 'Invoke-HeatMapScan.ps1' }, 'Download Invoke-HeatMapScan.ps1'))),
        h('li', {}, h('strong', {}, 'Run it in PowerShell'), h('p', { class: 'muted small' }, 'Open PowerShell as administrator (so BitLocker and Secure Boot can be read) in the folder where you saved it:'),
          h('pre', { class: 'code' }, cmd), h('button', { class: 'btn sm', onclick: () => navigator.clipboard?.writeText(cmd).then(() => toast('Copied')) }, 'Copy')),
        h('li', {}, h('strong', {}, 'Get your PDF'), h('p', { class: 'muted small' }, 'The scanner waits for the results and saves them in Documents\\HeatMap360. If they take longer, it tells you how to fetch them later.')))),
      panel('What is sent', null,
        h('p', {}, h('strong', {}, 'Sent: '), 'Windows version, build and installed updates; installed programs and versions; computer make and model, BIOS, motherboard, processor, memory, disks and device drivers; Defender, BitLocker, Secure Boot, TPM and firewall status.'),
        h('p', {}, h('strong', {}, 'Never sent: '), 'computer name, user names, domain, IP or MAC addresses, serial numbers, files or documents.'),
        h('p', { class: 'muted small' }, 'Want to read it first? Add ', h('code', {}, '-SaveOnly'), ' and the scanner writes the exact data to a file without sending anything.'))),
  ];
}

// ---------- router ----------
async function route() {
  const hash = location.hash.slice(1) || (me?.elevated ? 'scans' : 'scanner');
  const [name, arg] = hash.split('/');
  document.querySelectorAll('.nav-item').forEach(a => a.setAttribute('aria-current', a.dataset.route === (name === 'scan' ? 'scans' : name) ? 'page' : 'false'));
  const view = $('#view');
  try {
    const content = name === 'scan' ? await viewScan(arg) : name === 'actions' ? viewActions() : name === 'scanner' ? viewScanner() : await viewScans();
    view.replaceChildren(...[content].flat().filter(Boolean));
  } catch (e) {
    if (e.status === 401 || e.status === 403) { await boot(false); return; }
    view.replaceChildren(h('p', { class: 'callout bad' }, `Could not load this page: ${e.message}`));
  }
  window.scrollTo(0, 0);
}

async function boot(doRoute = true) {
  me = await api('/api/me').catch(() => ({ signedIn: false, authConfigured: false, scannerUrl: '/client/Invoke-HeatMapScan.ps1' }));
  renderAccount();
  if (doRoute) await route(); else { $('#view').replaceChildren(gate()); }
}
window.addEventListener('hashchange', route);
boot();
