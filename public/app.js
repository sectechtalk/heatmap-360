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
        r.eventLog ? area(s.grade.events, 'Event log (last 7 days)', r.eventLog.reason || r.eventLog.error || 'Not checked', 'sec-events') : null,
        r.networkHealth ? area(s.grade.netHealth || 'unknown', 'Network health', r.networkHealth.reason || r.networkHealth.error || 'Not checked', 'sec-nethealth') : null,
        r.network ? area(s.grade.network, 'Network adapters', r.network.reason || r.network.error || 'Not checked', 'sec-network') : null,
        area(s.grade.firmware || 'unknown', 'BIOS / firmware', r.firmware?.reason || r.firmware?.error || 'Inventory listed below', 'sec-hw'))),
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
    r.eventLog ? h('div', { id: 'sec-events' }, eventsPanel(r.eventLog)) : null,
    r.networkHealth ? h('div', { id: 'sec-nethealth' }, panel('Network health', 'Measured by the scanner: router ping, connection time, DNS and speed (Cloudflare speed test)',
      r.networkHealth.status === 'checked' ? [h('p', {}, chip(r.networkHealth.grade), ' ', r.networkHealth.reason),
        table(['Check', 'Result', 'Detail'], r.networkHealth.checks.map(c => h('tr', {}, h('td', {}, c.label), h('td', {}, chip(c.status)), h('td', { class: 'muted' }, c.detail))))]
        : h('p', { class: 'muted' }, r.networkHealth.reason || r.networkHealth.error || 'Not checked'))) : null,
    r.network ? h('div', { id: 'sec-network' }, networkPanel(r.network)) : null,
    h('div', { id: 'sec-hw' }, panel('Hardware and firmware', r.hardware?.note || '',
      r.firmware ? firmwareBlock(r.firmware) : null,
      r.firmware ? h('h3', {}, 'Inventory') : null,
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

const findingRows = list => list.map(f => h('tr', {}, h('td', {}, chip(f.status === 'info' ? 'info' : f.status, f.status === 'info' ? 'Note' : undefined)), h('td', {}, h('strong', {}, f.label)), h('td', { class: 'muted' }, f.detail || '')));

function eventsPanel(ev) {
  if (ev.status !== 'checked') return panel('Event log', null, h('p', { class: 'muted' }, ev.reason || ev.error || 'Not checked'));
  return panel('Event log', `Critical and error events, last ${ev.days} days (counts only; message text is never collected)`,
    h('p', {}, chip(ev.grade), ' ', ev.reason),
    table(['Result', 'What happened', 'Times', 'Last seen', 'What to do'], ev.findings.map(f => h('tr', {},
      h('td', {}, chip(f.status === 'info' ? 'info' : f.status, f.status === 'info' ? 'Note' : undefined)), h('td', {}, h('strong', {}, f.label), h('div', { class: 'muted small' }, f.events.join(', '))),
      h('td', { class: 'num' }, f.count), h('td', { class: 'nowrap' }, when(f.lastSeen)), h('td', { class: 'muted' }, f.advice))), 'No events point to a hardware or stability problem.'),
    ev.other?.length ? h('details', {}, h('summary', {}, `${ev.other.length} other error sources`),
      table(['Log', 'Source', 'Event ID', 'Level', 'Times', 'Last seen'], ev.other.map(e => h('tr', {}, h('td', {}, e.log), h('td', {}, e.provider), h('td', { class: 'num' }, e.eventId), h('td', {}, e.level), h('td', { class: 'num' }, e.count), h('td', { class: 'nowrap' }, when(e.lastSeen)))))) : null,
    ev.noiseCount ? h('p', { class: 'muted small' }, `${ev.noiseCount} routine events that Windows logs on healthy computers (such as DCOM 10016) were left out.`) : null);
}

function networkPanel(net) {
  if (net.status !== 'checked') return panel('Network adapters', null, h('p', { class: 'muted' }, net.reason || net.error || 'Not checked'));
  const adapter = a => h('div', { class: 'stack' },
    h('h3', {}, a.description || 'Network adapter', ' ', a.connected ? chip(a.grade) : chip('unknown', a.status || 'Not connected')),
    h('dl', { class: 'kv' },
      h('dt', {}, 'Type'), h('dd', {}, a.mediaType === '802.3' ? 'Wired (Ethernet)' : /802\.11/.test(a.mediaType || '') ? 'Wi-Fi' : a.mediaType || 'Unknown'),
      a.connected ? [h('dt', {}, 'Link'), h('dd', {}, `${a.linkSpeedMbps ?? '?'} Mbps${a.fullDuplex === false ? ', half duplex' : a.fullDuplex ? ', full duplex' : ''}`)] : null,
      h('dt', {}, 'Driver'), h('dd', {}, [a.driverVersion, a.driverDate && `(${a.driverDate})`, a.driverProvider && `from ${a.driverProvider}`].filter(Boolean).join(' ') || 'Not reported'),
      a.powerSaving ? [h('dt', {}, 'Power saving'), h('dd', {}, a.powerSaving === 'Enabled' ? 'Windows may turn it off to save power' : a.powerSaving)] : null),
    a.findings.length ? table(['Result', 'Finding', 'Detail'], findingRows(a.findings)) : null,
    a.settings?.length ? h('details', {}, h('summary', {}, `${a.settings.length} adapter settings`), table(['Setting', 'Value'], a.settings.map(x => h('tr', {}, h('td', {}, x.name || x.keyword), h('td', {}, x.value ?? ''))))) : null);
  const w = net.wifi;
  return panel('Network adapters', 'Physical adapters only; no addresses or network names are collected',
    h('p', {}, chip(net.grade), ' ', net.reason),
    w ? h('div', { class: 'stack' }, h('h3', {}, 'Wi-Fi connection ', chip(w.grade)),
      h('dl', { class: 'kv' }, h('dt', {}, 'Signal'), h('dd', {}, w.signalPercent != null ? `${w.signalPercent}%` : 'Not reported'),
        h('dt', {}, 'Standard'), h('dd', {}, w.radioType || 'Not reported'), h('dt', {}, 'Band and channel'), h('dd', {}, [w.band, w.channel && `channel ${w.channel}`].filter(Boolean).join(', ') || 'Not reported'),
        h('dt', {}, 'Rate'), h('dd', {}, w.receiveMbps != null ? `${w.receiveMbps} Mbps down / ${w.transmitMbps ?? '?'} Mbps up (negotiated)` : 'Not reported')),
      w.findings.filter(f => f.status !== 'ok').length ? table(['Result', 'Finding', 'Detail'], findingRows(w.findings.filter(f => f.status !== 'ok'))) : null) : null,
    net.adapters.map(adapter));
}

function firmwareBlock(fw) {
  const i = fw.installed || {};
  return h('div', { class: 'stack' },
    h('p', {}, chip(fw.grade || 'unknown', fw.status === 'update' ? 'BIOS update available' : fw.status === 'current' ? 'BIOS current' : undefined), ' ', fw.reason || fw.error || ''),
    h('dl', { class: 'kv' },
      h('dt', {}, 'Installed BIOS'), h('dd', {}, [i.version, i.date && `(${i.date})`, i.ageYears != null && `${i.ageYears} years old`].filter(Boolean).join(' ') || 'Not reported'),
      fw.latest ? [h('dt', {}, `Newest from ${fw.vendor}`), h('dd', {}, [fw.latest.version, fw.latest.date && `(${fw.latest.date})`].filter(Boolean).join(' '), fw.latest.link ? [' ', link(fw.latest.link, 'Details')] : null)] : null,
      fw.support ? [h('dt', {}, 'Support site'), h('dd', {}, link(fw.support, `${fw.vendor} drivers and firmware`))] : null),
    fw.source ? h('p', { class: 'muted small' }, 'Source: ', link(fw.source, `${fw.vendor} update catalog`)) : null);
}

// ---------- Service health ----------
const IMPACT = { ok: 'Operational', info: 'Notice', warn: 'Degraded', bad: 'Outage', unknown: 'Not checked' };
async function viewServices() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Service health'), h('p', {}, 'Online services, from each provider’s own public status feed. Refreshed every 5 minutes.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/services');
  const card = p => h('section', { class: 'panel stack' },
    h('div', { class: 'row' }, h('h2', {}, p.name), chip(p.grade === 'info' ? 'info' : p.grade, p.grade === 'unknown' ? p.summary : IMPACT[p.grade])),
    h('p', { class: 'muted' }, p.error || p.note || p.summary),
    p.incidents.length ? h('ul', { class: 'incidents' }, p.incidents.map(i => h('li', {},
      chip(i.impact === 'info' ? 'info' : i.impact, IMPACT[i.impact]), ' ', i.link ? link(i.link, i.title || 'Incident') : i.title,
      h('div', { class: 'muted small' }, [i.products?.length && i.products.join(', '), i.started && `since ${when(i.started)}`, i.updated && i.updated !== i.started && `updated ${when(i.updated)}`].filter(Boolean).join(' · ')),
      i.detail ? h('div', { class: 'small' }, i.detail) : null))) : null,
    h('p', { class: 'small' }, link(p.page, `Open the ${p.name} status page`)));
  const bad = d.providers.filter(p => p.grade === 'warn' || p.grade === 'bad').length;
  return [head,
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, d.providers.filter(p => p.grade === 'ok').length), h('span', { class: 'l' }, 'Operational')),
      h('div', {}, h('span', { class: 'n' }, bad), h('span', { class: 'l' }, 'With incidents')),
      h('div', {}, h('span', { class: 'n' }, d.providers.filter(p => p.grade === 'unknown').length), h('span', { class: 'l' }, 'Not checked'))),
    h('div', { class: 'grid-2' }, d.providers.map(card)),
    h('p', { class: 'muted small' }, `Checked ${when(d.checkedAt)}. HeatMap 360 only reports what each provider publishes; it does not change anything.`)];
}

// ---------- Options ----------
function viewOptions() {
  const opts = { speed: true, saveOnly: false, wait: 15 };
  const out = h('pre', { class: 'code' });
  const render = () => {
    const args = [opts.saveOnly && '-SaveOnly', !opts.speed && '-SkipSpeedTest', !opts.saveOnly && opts.wait !== 15 && `-WaitMinutes ${opts.wait}`].filter(Boolean);
    out.textContent = ['powershell -NoProfile -ExecutionPolicy Bypass -File .\\Invoke-HeatMapScan.ps1', ...args].join(' ');
  };
  const box = (key, label, help) => h('label', { class: 'option' }, h('input', { type: 'checkbox', checked: opts[key], onchange: e => { opts[key] = e.target.checked; render(); } }), h('span', {}, h('strong', {}, label), h('span', { class: 'muted small' }, help)));
  render();
  const what = [
    ['Windows and updates', 'Version, build, installed updates, end of support, known issues Microsoft reports for the build.'],
    ['Apps', 'Installed programs; winget package IDs to look up newer versions.'],
    ['Hardware and firmware', 'Make, model, BIOS (HP and Lenovo looked up with the vendor), motherboard, CPU, memory, drivers.'],
    ['Disk and battery health', 'Disk wear, temperature and uncorrected errors (run as administrator); battery capacity versus new.'],
    ['Event log', 'Counts of critical and error events per Windows component, last 7 days. Never the message text.'],
    ['Network adapters', 'Link speed, duplex, drivers, power and offload settings, Wi-Fi signal. No addresses or network names.'],
    ['Network health', 'Ping to the router, connection time and DNS lookup time, and download/upload speed against Cloudflare’s public speed test (about 35 MB).'],
    ['Security', 'Defender, BitLocker, Secure Boot, TPM, firewall; exploited-in-the-wild candidates from CISA.'],
  ];
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Options'), h('p', {}, 'Choose what the scanner does, then run the command on the computer. HeatMap 360 reports what it finds; it never changes a computer.'))),
    h('div', { class: 'grid-2' },
      panel('Scanner options', null,
        h('div', { class: 'stack' },
          box('speed', 'Measure internet speed', 'Downloads and uploads about 35 MB to Cloudflare’s speed test. Turn off on metered connections.'),
          box('saveOnly', 'Save only, do not send', 'Writes the exact data to Documents\\HeatMap360 so you can read it first.'),
          h('label', { class: 'option' }, h('span', {}, h('strong', {}, 'Wait for results (minutes)'), h('span', { class: 'muted small' }, 'How long the scanner waits for the PDF before telling you how to fetch it later.')),
            h('input', { type: 'number', min: 1, max: 120, value: opts.wait, class: 'num-input', oninput: e => { opts.wait = Math.min(120, Math.max(1, Number(e.target.value) || 15)); render(); } }))),
        h('h3', {}, 'Command'), out,
        h('div', { class: 'row' }, h('button', { class: 'btn sm', onclick: () => navigator.clipboard?.writeText(out.textContent).then(() => toast('Copied')) }, 'Copy'),
          h('a', { class: 'btn sm primary', href: me.scannerUrl, download: 'Invoke-HeatMapScan.ps1' }, 'Download the scanner'))),
      panel('What a scan checks', null, h('dl', { class: 'kv' }, what.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])))),
    h('section', { class: 'panel stack' }, h('div', { class: 'row' }, h('h2', {}, 'On-demand vulnerability check'), chip('info', 'Planned')),
      h('p', { class: 'muted' }, 'Check a scanned computer’s installed versions against published vulnerabilities on request. Report only.'), h('button', { class: 'btn', disabled: true }, 'Not available yet')),
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
        h('p', {}, h('strong', {}, 'Sent: '), 'Windows version, build and installed updates; installed programs and versions; computer make and model, BIOS, motherboard, processor, memory, disks and device drivers; Defender, BitLocker, Secure Boot, TPM and firewall status; how many critical and error events Windows logged in the last 7 days (counts only); network adapter models, link speed, drivers and settings, and Wi-Fi signal strength; disk and battery health; ping time to your router, DNS time and internet speed (Cloudflare speed test, about 35 MB; see Options to turn it off).'),
        h('p', {}, h('strong', {}, 'Never sent: '), 'computer name, user names, domain, IP or MAC addresses, Wi-Fi network names, serial numbers, event log messages, files or documents.'),
        h('p', { class: 'muted small' }, 'Want to read it first? Add ', h('code', {}, '-SaveOnly'), ' and the scanner writes the exact data to a file without sending anything.'))),
  ];
}

// ---------- router ----------
async function route() {
  const hash = location.hash.slice(1) || (me?.elevated ? 'scans' : 'scanner');
  const [name, arg] = hash.split('/');
  document.querySelectorAll('.nav-item').forEach(a => a.setAttribute('aria-current', a.dataset.route === (name === 'scan' ? 'scans' : name === 'actions' ? 'options' : name) ? 'page' : 'false'));
  const view = $('#view');
  try {
    const content = name === 'scan' ? await viewScan(arg) : name === 'options' || name === 'actions' ? viewOptions() : name === 'services' ? await viewServices() : name === 'scanner' ? viewScanner() : await viewScans();
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
