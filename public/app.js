// HeatMap 360 UI. Plain DOM (CSP: script-src 'self'), hash routes: #scans, #scan/<id>, #pentests, #vulnscans, #attention, #cloud, #exploits, #cves, #patches, #x, #bluesky, #services, #options, #settings, #overview, #guide, #scanner.
'use strict';
const $ = s => document.querySelector(s);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'busy' || k === 'done' || k === 'fail') continue; // busy feedback wording, used below
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), withBusy(e, tag, k, v, props)); else if (k in e && k !== 'list') e[k] = v; else e.setAttribute(k, v);
  }
  // A link-button with busy wording and no click handler of its own: a new tab (PIM) or a page change (sign-in).
  if (tag === 'a' && props?.busy && !props.onclick) e.addEventListener('click', () => busy(e, props.busy, () => (e.target === '_blank' ? sleep(1500) : new Promise(() => {})), props));
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

// ---------- busy feedback: every button, link-button and form says what it is doing ----------
// One mechanism for the whole app, wired by h(). Give a button its wording with `busy` (and optionally `done` and
// `fail`) next to its onclick, for example { busy: 'Saving…', done: 'Saved', onclick }. A button without wording still
// shows "Working…", so a new button gets feedback by default. A form with `busy` puts it on its submit button. While the
// action runs, the control shows a spinner and the wording and ignores further presses, and the status bar at the top
// of the page says the same. It clears when the action ends; a failure turns both red and gives the reason.
// Page loads (rail links, in-page links, rows) go through route(), which shows "Loading <page>…" the same way.
const sleep = ms => new Promise(r => setTimeout(r, ms));
const CANCELLED = Symbol('cancelled'); // an action returns this when the user backed out (no file chosen)
const activity = (() => {
  let bar = null, text = null, jobs = 0, since = 0, timer = null;
  const show = (msg, state) => {
    if (!bar) { bar = h('div', { class: 'activity', role: 'status', 'aria-live': 'polite' }, h('span', { class: 'activity-bar', 'aria-hidden': 'true' }), text = h('span', { class: 'activity-text' })); document.body.append(bar); }
    clearTimeout(timer); bar.className = `activity on ${state}`; text.textContent = msg;
  };
  const hide = after => { clearTimeout(timer); timer = setTimeout(() => { if (!jobs) bar.className = 'activity'; }, after); };
  const start = msg => {
    jobs++; since = Date.now(); show(msg, 'busy');
    let open = true;
    const finish = () => { if (!open) return false; open = false; jobs = Math.max(0, jobs - 1); return true; };
    // Shown for at least 600 ms, so even an instant action is seen.
    return {
      done(msg2) { if (!finish() || jobs) return; const left = Math.max(0, 600 - (Date.now() - since)); if (msg2) { show(msg2, 'ok'); hide(Math.max(left, 1800)); } else hide(left); },
      fail(msg2) { if (!finish()) return; show(msg2, 'fail'); hide(6000); },
    };
  };
  return { start, flash: msg => start(msg).done() };
})();
function setLook(el, cls, ...kids) { el.classList.remove('is-busy', 'is-done', 'is-failed'); if (cls) el.classList.add(cls); el.replaceChildren(...kids); }
// After the action: "Saved" or "Failed" on the control for a moment, then its own label again.
function mark(el, text, cls) {
  if (!el.isConnected) return;
  setLook(el, cls, text);
  el._mark = setTimeout(() => { if (el.getAttribute('aria-busy') !== 'true') setLook(el, null, ...el._idle); }, 2000);
}
async function busy(el, label, work, { done, fail } = {}) {
  if (!el || el.getAttribute('aria-busy') === 'true') return undefined; // already running: ignore the extra press
  clearTimeout(el._mark);
  el._idle ??= [...el.childNodes];
  const isButton = el.tagName === 'BUTTON';
  el.style.minWidth = `${el.offsetWidth}px`; // keep the layout still while the wording changes
  el.setAttribute('aria-busy', 'true'); if (isButton) el.disabled = true; else el.setAttribute('aria-disabled', 'true');
  const say = text => setLook(el, 'is-busy', h('span', { class: 'spinner', 'aria-hidden': 'true' }), text);
  say(label);
  const act = activity.start(label), t0 = Date.now();
  let result, error = null;
  try { result = await work(next => { say(next); activity.start(next).done(); }); } catch (err) { error = err; }
  if (!error && el.isConnected) await sleep(Math.max(0, 400 - (Date.now() - t0)));
  el.removeAttribute('aria-busy'); el.style.minWidth = ''; if (isButton) el.disabled = false; else el.removeAttribute('aria-disabled');
  setLook(el, null, ...el._idle);
  if (error) { const word = fail || 'Failed'; mark(el, word, 'is-failed'); act.fail(`${word}: ${error.message}`); return undefined; }
  if (result === CANCELLED) { act.done('Nothing was chosen'); return undefined; }
  if (done) mark(el, done, 'is-done');
  act.done(done);
  return result;
}
// h() calls this for every on* handler: clicks on buttons (and on anything given busy wording) and form submits run
// through busy(); other events (change, keydown) are left as they are.
function withBusy(el, tag, key, fn, props) {
  if (key === 'onsubmit' && props.busy) return ev => { ev.preventDefault(); busy(ev.submitter || el.querySelector('[type="submit"]'), props.busy, say => fn(ev, say), props); };
  if (key === 'onclick' && (tag === 'button' || props.busy)) return ev => busy(el, props.busy || 'Working…', say => fn(ev, say), props);
  return fn;
}
// Copy to the clipboard, failing visibly where the browser does not allow it.
async function copyText(text) {
  if (!navigator.clipboard) throw new Error('This browser does not allow copying here. Select the text and copy it by hand.');
  await navigator.clipboard.writeText(text);
}
// Download through fetch so the button can say "Building PDF…" until the file has arrived, and show a failure.
async function download(url, name, headers) {
  const r = await fetch(url, { headers });
  if (!r.ok) throw Object.assign(new Error((await r.json().catch(() => null))?.error || `HTTP ${r.status}`), { status: r.status });
  saveFile(name, await r.blob());
}

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
    if (!me.dev) a.append(h('button', { class: 'btn sm', busy: 'Signing out…', onclick: signOut }, 'Sign out'));
  } else if (me.authConfigured) a.append(h('a', { class: 'btn sm primary', href: '/auth/signin', busy: 'Opening sign-in…' }, 'Sign in'));
  if (me.signedIn && me.projectAdmin) a.append(chip('ok', 'Settings Admin'));
  if (me.dev) a.append(h('span', { class: 'small' }, 'Local development mode'));
  $('.nav-item[data-route="settings"]')?.classList.toggle('is-hidden', !me.signedIn);
}

// Always ends signed out on the page, even if the server call fails (for example the session was already gone).
async function signOut() {
  try { await api('/auth/signout', { method: 'POST' }); } catch (err) { toast(`Signed out on this page (${err.message}).`); }
  history.replaceState(null, '', '#scanner'); // no hashchange, so boot() routes once
  await boot();
}

// ---------- gate for admin pages ----------
const pimLink = () => h('a', { class: 'btn primary', href: me.activateUrl, target: '_blank', rel: 'noopener noreferrer', busy: 'Opening PIM…', done: 'Opened in a new tab' }, 'Open PIM to activate');
function gate() {
  if (!me.signedIn) return h('div', { class: 'empty' },
    h('h2', {}, 'Sign in to see scan results'),
    h('p', { class: 'muted' }, 'Results are for HeatMap admins. Sign in with your work account, then activate your HeatMap 360 PIM group.'),
    me.authConfigured ? h('a', { class: 'btn primary', href: '/auth/signin', busy: 'Opening Microsoft sign-in…' }, 'Sign in with Microsoft') : h('p', { class: 'callout warn' }, 'Sign-in is not configured on this server yet.'),
    h('a', { href: '#scanner' }, 'Just want to scan a computer? Get the scanner'));
  return h('div', { class: 'empty' },
    h('h2', {}, 'Elevate to see scan results'),
    me.elevationError === 'check'
      ? h('p', { class: 'callout warn' }, 'The membership check with Microsoft failed, so HeatMap 360 could not tell whether you are elevated. Check again in a minute.')
      : h('p', { class: 'muted' }, 'You are signed in, but your HeatMap 360 group membership is not active. Activate it in Privileged Identity Management (activations last 8 hours), then check again.'),
    h('div', { class: 'row' },
      pimLink(),
      h('button', { class: 'btn', busy: 'Checking with Microsoft…', fail: 'Not active yet', onclick: async () => {
        let r;
        try { r = await api('/api/me/recheck', { method: 'POST' }); }
        catch (err) { if (err.status === 401 || err.status === 403) { toast('Your session ended. Sign in again.'); await boot(); return; } throw err; }
        if (!r.elevated) throw new Error('Activation can take a minute. Check again shortly.');
        toast('Elevated.'); await boot();
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
        : h('tr', { class: 'link', tabIndex: 0, onclick: e => { pressedLink = e.currentTarget; location.hash = `#scan/${x.id}`; }, onkeydown: e => { if (e.key === 'Enter') { pressedLink = e.currentTarget; location.hash = `#scan/${x.id}`; } } },
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
  const inv = r.inventory || {}, s = r.summary, w = r.windows || {}, ki = r.knownIssues || {}, a = r.apps || {}, ai = r.appIssues, ex = r.exploited || {}, hw = inv.hardware || {};
  const sys = hw.system || {};
  const area = (grade, title, detail, target) => h('div', { class: 'area' }, h('span', { class: `bar ${grade}` }), h('div', {}, h('strong', {}, title), h('div', { class: 'muted small' }, detail)), target ? h('a', { href: `#scan/${id}`, 'data-jump': '', onclick: e => { e.preventDefault(); document.getElementById(target)?.scrollIntoView({ behavior: 'smooth' }); } }, 'Details') : null);
  const issues = (ki.issues || []).filter(i => i.applies !== 'not-affected');
  return [
    h('div', { class: 'page-head' },
      h('div', {}, h('a', { href: '#scans', class: 'small' }, '← All scans'), h('h1', {}, [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'Scanned computer'),
        h('p', {}, `Anonymous ID ${inv.machineId} · scanned ${when(inv.collectedAt)} · checked ${when(r.processedAt)}`)),
      h('button', { class: 'btn', busy: 'Building PDF…', done: 'Downloaded', fail: 'PDF failed', onclick: () => download(`/api/admin/scans/${encodeURIComponent(id)}/report.pdf`, `HeatMap360-${id}.pdf`) }, 'Download PDF')),
    h('section', { class: 'panel' },
      h('div', { class: 'verdict' }, h('span', { class: `dot ${s.overall}` }), h('div', {}, h('h2', {}, WORD[s.overall]), h('p', { class: 'muted' }, 'Each area below is checked against the vendor’s official source. Anything that could not be checked says so.'))),
      h('div', { style: '' },
        area(s.grade.windows, 'Windows updates', w.reason || w.error || 'Not checked', 'sec-windows'),
        area(s.grade.knownIssues, 'Known Windows issues', ki.error || ki.reason || (ki.open ? `${ki.open} issue${ki.open > 1 ? 's' : ''} reported by Microsoft may apply` : 'No reported issue applies to this build'), 'sec-issues'),
        area(s.grade.apps, 'App updates', a.error || `${a.updates?.length ?? 0} of ${a.checked ?? 0} checked apps have a newer version`, 'sec-apps'),
        ai ? area(s.grade.appIssues || 'unknown', 'Known issues in apps', ai.error || ai.reason || 'Not checked', 'sec-appissues') : null,
        area(s.grade.health, 'Health', `${s.healthProblems} check${s.healthProblems === 1 ? '' : 's'} need attention`, 'sec-health'),
        area(s.grade.exploited, 'Exploited in the wild (CISA)', ex.error || ex.reason || `${ex.candidates?.length ?? 0} candidate${ex.candidates?.length === 1 ? '' : 's'} to verify`, 'sec-kev'),
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
    ai ? h('div', { id: 'sec-appissues' }, appIssuesPanel(ai)) : null,
    h('div', { id: 'sec-health' }, panel('Health', null, table(['Check', 'Result', 'Detail'], (r.health || []).map(c => h('tr', {}, h('td', {}, c.label), h('td', {}, chip(c.status)), h('td', { class: 'muted' }, c.detail)))))),
    h('div', { id: 'sec-kev' }, kevPanel(ex)),
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

const VERDICT = { affected: ['bad', 'Vulnerable version'], unverified: ['warn', 'Check version'], patched: ['ok', 'Patched'] };
const cveLink = c => link(c.record || `https://www.cve.org/CVERecord?id=${encodeURIComponent(c.cveID)}`, c.cveID);
const kevRows = list => list.map(c => h('tr', {}, h('td', { class: 'nowrap' }, cveLink(c), h('div', { class: 'muted small' }, c.name || '')),
  h('td', {}, c.app ? `${c.app}${c.version ? ` ${c.version}` : ''}` : `${c.vendor} ${c.product}`),
  h('td', {}, chip(...(VERDICT[c.verdict] || ['unknown', 'Check version'])), h('div', { class: 'muted small' }, c.why || c.reason || '')),
  h('td', { class: 'nowrap' }, c.fixedIn || ''), h('td', {}, c.ransomware ? chip('bad', 'Known') : ''), h('td', { class: 'nowrap' }, c.dueDate || '')));
const KEV_HEAD = ['CVE', 'Installed', 'For this PC', 'Fixed in', 'Ransomware', 'CISA due'];

function kevPanel(ex) {
  if (ex.error) return panel('Exploited in the wild', 'CISA Known Exploited Vulnerabilities', h('p', { class: 'muted' }, ex.error));
  // Results from bot 1.2 and older have candidates only, without a version check.
  const open = ex.affected ? [...ex.affected, ...ex.unverified] : (ex.candidates || []);
  return panel('Exploited in the wild', 'CISA Known Exploited Vulnerabilities, checked against the version ranges in each official CVE record',
    ex.reason ? h('p', {}, chip(ex.affected?.length ? 'bad' : open.length ? 'warn' : 'ok'), ' ', ex.reason) : null,
    table(KEV_HEAD, kevRows(open), 'No vulnerability exploited in the wild applies to the installed software.'),
    ex.patched?.length ? h('details', {}, h('summary', {}, `${ex.patched.length} matched and already patched`), table(KEV_HEAD, kevRows(ex.patched))) : null,
    h('p', { class: 'muted small' }, '"Vulnerable version": the installed version is inside a range the vendor lists as affected. "Check version": the CVE record has no usable version numbers for this program, so compare by hand. Sources: ',
      link('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CISA KEV'), ', ', link('https://www.cve.org/', 'CVE records'), '.'));
}

function appIssuesPanel(ai) {
  if (ai.status !== 'checked') return panel('Known issues in apps', null, h('p', { class: 'muted' }, ai.reason || ai.error || 'Not checked'));
  return panel('Known issues in apps', 'From each publisher\'s release notes (winget catalog and the app\'s GitHub releases)',
    h('p', {}, chip(ai.grade), ' ', ai.reason),
    table(['App (winget ID)', 'Version', 'Which', 'Known issues the publisher lists'], ai.issues.map(i => h('tr', {}, h('td', {}, i.id), h('td', {}, i.version),
      h('td', {}, chip(i.which === 'installed' ? 'warn' : 'info', i.which === 'installed' ? 'Installed' : 'Available update')),
      h('td', {}, h('ul', { class: 'tight' }, i.items.map(t => h('li', {}, t))), link(i.source, 'Release notes')))), 'No publisher lists a known issue for these versions.'),
    ai.failed?.length ? h('details', {}, h('summary', {}, `${ai.failed.length} lookups failed`), table(['App', 'Version', 'Why'], ai.failed.map(f => h('tr', {}, h('td', {}, f.id), h('td', {}, f.version), h('td', { class: 'muted' }, f.reason))))) : null,
    h('p', { class: 'muted small' }, `${ai.checked} app versions had release notes in the winget catalog${ai.notInCatalog ? `; ${ai.notInCatalog} versions are not in the catalog` : ''}. Only sections the publisher titles "Known issues" (or "Unresolved") are shown.`));
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

// ---------- per-viewer preferences (browser storage may be missing; the page works without it) ----------
const prefs = {
  get(key, fallback) { try { const v = localStorage.getItem(`hm360.${key}`); return v == null ? fallback : JSON.parse(v); } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem(`hm360.${key}`, JSON.stringify(value)); } catch { /* not available */ } },
};

// Left pane of checkboxes: a checked item is displayed. hidden is a Set of ids; onChange re-renders the right side.
function pickPane(title, items, hidden, onChange, extra) {
  const countEls = new Map();
  const boxes = items.map(it => h('label', { class: 'pick' },
    h('input', { type: 'checkbox', checked: !hidden.has(it.id), onchange: e => { activity.flash(`${e.target.checked ? 'Showing' : 'Hiding'} ${it.name}…`); if (e.target.checked) hidden.delete(it.id); else hidden.add(it.id); onChange(); } }),
    it.dot ? h('span', { class: `dot ${it.dot}` }) : null, h('span', {}, it.name),
    countEls.set(it.id, h('span', { class: 'pick-count muted small' })).get(it.id)));
  const setAll = show => { items.forEach(it => (show ? hidden.delete(it.id) : hidden.add(it.id))); boxes.forEach(b => { b.querySelector('input').checked = show; }); onChange(); };
  const pane = h('aside', { class: 'panel pane' },
    h('div', { class: 'pane-head' }, h('h2', {}, title), h('div', { class: 'row' }, h('button', { class: 'btn sm', busy: 'Showing all…', onclick: () => setAll(true) }, 'All'), h('button', { class: 'btn sm', busy: 'Hiding all…', onclick: () => setAll(false) }, 'None'))),
    h('div', { class: 'stack tight' }, boxes), extra || null);
  // counts: Map of id -> number of articles/posts on screen. Ids left out (unticked, not read) show no number.
  pane.setCounts = counts => countEls.forEach((el, id) => {
    const n = counts.get(id);
    el.textContent = n == null ? '' : String(n);
    el.title = n == null ? '' : `${n} shown for this timeframe`;
  });
  return pane;
}

// ---------- Service health ----------
const IMPACT = { ok: 'Operational', info: 'Notice', warn: 'Degraded', bad: 'Outage', unknown: 'Not checked' };
// Operational = grade ok. With incidents = any other known status (notice, degraded, outage). Not checked = unknown.
const COLUMN = g => (g === 'ok' ? 'ok' : g === 'unknown' || !g ? 'unknown' : 'incidents');
async function viewServices() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Service health'), h('p', {}, 'Online services, from each provider’s own public status feed. Refreshed every 5 minutes. Tick a service on the left to show it; select a service to open or close it.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/services');
  const hidden = new Set(prefs.get('services.hidden', []));
  const cardsEl = new Map();
  const card = p => h('details', { class: 'panel svc', open: COLUMN(p.grade) === 'incidents' },
    h('summary', {}, h('span', { class: 'svc-title' }, h('strong', {}, p.name), chip(p.grade === 'info' ? 'info' : p.grade, p.grade === 'unknown' ? p.summary : IMPACT[p.grade])),
      h('span', { class: 'muted small' }, p.error || p.note || p.summary)),
    h('div', { class: 'stack svc-body' },
      p.incidents.length ? h('ul', { class: 'incidents' }, p.incidents.map(i => h('li', {},
        chip(i.impact === 'info' ? 'info' : i.impact, IMPACT[i.impact]), ' ', i.link ? link(i.link, i.title || 'Incident') : i.title,
        h('div', { class: 'muted small' }, [i.products?.length && i.products.join(', '), i.started && `since ${when(i.started)}`, i.updated && i.updated !== i.started && `updated ${when(i.updated)}`].filter(Boolean).join(' · ')),
        i.detail ? h('div', { class: 'small' }, i.detail) : null))) : null,
      h('p', { class: 'small' }, link(p.page, `Open the ${p.name} status page`))));
  d.providers.forEach(p => cardsEl.set(p.id, card(p)));
  const cols = [['ok', 'Operational'], ['incidents', 'With incidents'], ['unknown', 'Not checked']];
  const colsEl = h('div', { class: 'svc-cols' });
  const render = () => {
    prefs.set('services.hidden', [...hidden]);
    colsEl.replaceChildren(...cols.map(([key, label]) => {
      const list = d.providers.filter(p => COLUMN(p.grade) === key && !hidden.has(p.id));
      return h('section', { class: `svc-col ${key}` },
        h('div', { class: 'svc-col-head' }, h('span', { class: 'n' }, list.length), h('span', { class: 'l' }, label)),
        list.length ? list.map(p => cardsEl.get(p.id)) : h('p', { class: 'muted small svc-none' }, 'None'));
    }));
  };
  const toggleAll = open => cardsEl.forEach(c => { c.open = open; });
  render();
  return [head,
    h('div', { class: 'with-pane' },
      pickPane('Services', d.providers.map(p => ({ id: p.id, name: p.name, dot: COLUMN(p.grade) === 'incidents' ? (p.grade === 'info' ? 'info' : p.grade) : p.grade })), hidden, render,
        h('div', { class: 'row pane-foot' }, h('button', { class: 'btn sm', busy: 'Expanding…', onclick: () => toggleAll(true) }, 'Expand all'), h('button', { class: 'btn sm', busy: 'Collapsing…', onclick: () => toggleAll(false) }, 'Collapse all'))),
      colsEl),
    h('p', { class: 'muted small' }, `Checked ${when(d.checkedAt)}. HeatMap 360 only reports what each provider publishes; it does not change anything.`)];
}

// ---------- Internet - Cloud Services / Internet - Exploits / Internet - Patches ----------
const NEWS_TITLES = { cloud: 'Internet - Cloud Services', exploits: 'Internet - Exploits', patches: 'Internet - Patches' };
// Timeframes shared by the news, Bluesky and x.com pages. Default: Last 7 days (a saved choice that no longer exists falls back to it).
const TIMEFRAMES = [['week', 'Last 7 days', 7 * 86_400_000], ['3d', 'Last 3 days', 3 * 86_400_000], ['8h', 'Last 8 hours', 8 * 3_600_000], ['4h', 'Last 4 hours', 4 * 3_600_000], ['hour', 'Last hour', 3_600_000]];
const savedTimeframe = key => { const v = prefs.get(key, 'week'); return TIMEFRAMES.some(t => t[0] === v) ? v : 'week'; };
const inTimeframe = (win, it) => { const ms = TIMEFRAMES.find(t => t[0] === win)?.[2] ?? TIMEFRAMES[0][2]; return Boolean(it.date) && Date.now() - Date.parse(it.date) <= ms; };
// Number on screen per source: in "Newest first" only the listed items count, so the numbers match what is shown.
// Wording for the timeframe, sort and group buttons: "Showing last 3 days…", "Sorting newest first…".
const segBusy = (key, label) => (key === 'by' ? `Sorting ${label.toLowerCase()}…` : key === 'win' ? `Showing ${label.toLowerCase()}…` : `Showing ${label === 'All' ? 'everything' : label.toLowerCase()}…`);
const countBy = (ids, pairs, key) => { const m = new Map(ids.map(id => [id, 0])); for (const p of pairs) m.set(key(p), (m.get(key(p)) || 0) + 1); return m; };
async function viewNews(kind) {
  const d = await (me.elevated ? api(`/api/admin/news/${kind}`) : null);
  const head = title => h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, title), d ? h('p', {}, d.intro) : null));
  if (!me.elevated) return [head(NEWS_TITLES[kind]), gate()];
  const hidden = new Set(prefs.get(`news.${kind}.hidden`, []));
  const state = { win: savedTimeframe('news.window'), by: prefs.get('news.by', 'source') };
  const body = h('div', { class: 'stack wide-gap' });
  const inWindow = it => inTimeframe(state.win, it);
  const headline = (it, source) => h('li', {},
    it.link ? link(it.link, it.title) : h('span', {}, it.title),
    h('div', { class: 'muted small' }, [source, it.date && when(it.date)].filter(Boolean).join(' · ')),
    it.summary ? h('div', { class: 'small' }, it.summary) : null);
  const seg = (key, options) => h('div', { class: 'seg', role: 'group' }, options.map(([v, label]) => h('button', { class: `btn sm${state[key] === v ? ' on' : ''}`, 'aria-pressed': String(state[key] === v), busy: segBusy(key, label), onclick: () => { state[key] = v; prefs.set(`news.${key === 'win' ? 'window' : 'by'}`, v); render(); } }, label)));
  const render = () => {
    prefs.set(`news.${kind}.hidden`, [...hidden]);
    const shown = d.sources.filter(s => !hidden.has(s.id));
    const controls = h('div', { class: 'row spread' }, seg('win', TIMEFRAMES.map(w => [w[0], w[1]])), seg('by', [['source', 'By source'], ['time', 'Newest first']]));
    const readIds = shown.filter(s => s.status === 'checked').map(s => s.id);
    let content;
    if (!shown.length) { content = h('p', { class: 'muted' }, 'No source is ticked. Tick one on the left.'); pane.setCounts(new Map()); }
    else if (state.by === 'time') {
      const all = shown.flatMap(s => s.items.filter(inWindow).map(it => ({ it, s: s.name, id: s.id }))).sort((a, b) => (b.it.date || '').localeCompare(a.it.date || ''));
      const listed = all.slice(0, 150);
      pane.setCounts(countBy(readIds, listed, x => x.id));
      content = h('section', { class: 'panel' }, listed.length ? h('ul', { class: 'headlines' }, listed.map(x => headline(x.it, x.s))) : h('p', { class: 'muted' }, 'Nothing in this time window.'),
        all.length > listed.length ? h('p', { class: 'muted small' }, `Showing the newest ${listed.length} of ${all.length}. Choose a shorter timeframe or By source to see the rest.`) : null,
        shown.some(s => s.status !== 'checked') ? h('p', { class: 'muted small' }, `Not checked: ${shown.filter(s => s.status !== 'checked').map(s => s.name).join(', ')}.`) : null);
    } else {
      pane.setCounts(new Map(readIds.map(id => [id, d.sources.find(s => s.id === id).items.filter(inWindow).length])));
      content = h('div', { class: 'grid-2' }, shown.map(s => {
        const items = s.items.filter(inWindow);
        return h('details', { class: 'panel svc', open: true },
          h('summary', {}, h('span', { class: 'svc-title' }, h('strong', {}, s.name), s.status === 'checked' ? chip('info', `${items.length} post${items.length === 1 ? '' : 's'}`) : chip('unknown', 'Not checked')),
            h('span', { class: 'muted small' }, s.about)),
          h('div', { class: 'stack svc-body' },
            s.error ? h('p', { class: 'muted small' }, s.error)
              : items.length ? h('ul', { class: 'headlines' }, items.map(it => headline(it))) : h('p', { class: 'muted small' }, 'Nothing in this time window.'),
            h('p', { class: 'small' }, link(s.page, `Open ${s.name}`))));
      }));
    }
    body.replaceChildren(controls, content);
  };
  const pane = pickPane('Sources', d.sources.map(s => ({ id: s.id, name: s.name, dot: s.status === 'checked' ? 'ok' : 'unknown' })), hidden, () => render());
  render();
  return [head(d.title),
    h('div', { class: 'with-pane' }, pane, body),
    h('p', { class: 'muted small' }, `Read from each source’s public feed at ${when(d.checkedAt)} and kept for 30 minutes. Headlines link to the source; HeatMap 360 only reports them.`)];
}

// ---------- Cloudflare Radar CVEs (free public JSON feeds, read only) ----------
// server/cves.mjs reads the newest 100 CVEs of each severity and merges them; filtering happens here, on what was read.
const CVE_SEV = [['critical', 'Critical', 'bad'], ['high', 'High', 'warn'], ['medium', 'Medium', 'info'], ['low', 'Low', 'ok'], ['none', 'None (score 0)', 'unknown'], ['unscored', 'Not scored yet', 'unknown']];
async function viewCves() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Cloudflare Radar CVEs'),
    h('p', {}, 'Newly published CVEs from Cloudflare Radar, built from the CVE List and NVD with CISA’s known-exploited dates. Filter by severity on the left, by timeframe, and search by CVE ID or keyword.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/cves');
  const hidden = new Set(prefs.get('cves.hidden', ['none', 'unscored']));
  const state = { win: savedTimeframe('cves.window'), kev: prefs.get('cves.kev', false), q: '' };
  const list = h('div', { class: 'stack' });
  const sevOf = Object.fromEntries(CVE_SEV.map(([id, label, grade]) => [id, { label, grade }]));
  const item = it => h('li', {},
    h('div', { class: 'row' }, link(it.link, it.id), chip(sevOf[it.severity].grade, it.score != null ? `${sevOf[it.severity].label} ${it.score}` : sevOf[it.severity].label),
      it.kevAdded ? chip('bad', `Known exploited (CISA ${it.kevAdded})`) : null),
    h('div', { class: 'muted small' }, [it.date && when(it.date), it.cvss && `CVSS ${it.cvss}`].filter(Boolean).join(' · ')),
    it.title ? h('div', {}, it.title) : null,
    it.summary ? h('div', { class: 'small' }, it.summary) : null);
  const seg = (key, pref, options) => {
    const btns = options.map(([v, label]) => h('button', { class: `btn sm${state[key] === v ? ' on' : ''}`, 'aria-pressed': String(state[key] === v), busy: segBusy(key, label), onclick: () => {
      state[key] = v; prefs.set(pref, v);
      btns.forEach((b, i) => { const on = options[i][0] === v; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); });
      render();
    } }, label));
    return h('div', { class: 'seg', role: 'group' }, btns);
  };
  const search = h('input', { class: 'cve-search', type: 'search', placeholder: 'Search CVE ID or keyword', 'aria-label': 'Search CVEs', maxlength: '100', oninput: e => { activity.flash('Searching…'); state.q = e.target.value.trim().toLowerCase(); render(); } });
  const controls = h('div', { class: 'row spread' }, seg('win', 'cves.window', TIMEFRAMES.map(w => [w[0], w[1]])),
    h('div', { class: 'row' }, search, seg('kev', 'cves.kev', [[false, 'All'], [true, 'Known exploited only']])));
  const matches = it => !state.q || it.id.toLowerCase().includes(state.q) || (it.title || '').toLowerCase().includes(state.q) || (it.summary || '').toLowerCase().includes(state.q);
  const render = () => {
    prefs.set('cves.hidden', [...hidden]);
    const base = d.items.filter(it => inTimeframe(state.win, it) && (!state.kev || it.kevAdded) && matches(it));
    pane.setCounts(countBy(CVE_SEV.map(s => s[0]), base, it => it.severity));
    const all = base.filter(it => !hidden.has(it.severity));
    const listed = all.slice(0, 200);
    list.replaceChildren(h('section', { class: 'panel' },
      h('p', { class: 'muted small' }, `${plural(all.length, 'CVE')} match.`),
      listed.length ? h('ul', { class: 'headlines' }, listed.map(item)) : h('p', { class: 'muted' }, hidden.size === CVE_SEV.length ? 'No severity is ticked. Tick one on the left.' : 'Nothing matches. Try a longer timeframe, more severities or another search.'),
      all.length > listed.length ? h('p', { class: 'muted small' }, `Showing the newest ${listed.length} of ${all.length}. Narrow the timeframe, severity or search to see the rest.`) : null));
  };
  const pane = pickPane('Severity', CVE_SEV.map(([id, name, grade]) => ({ id, name, dot: grade })), hidden, render);
  render();
  const down = d.feeds.filter(f => f.status !== 'checked');
  const reach = d.feeds.filter(f => f.status === 'checked' && f.oldest).map(f => `${f.name} back to ${when(f.oldest)}`);
  return [head,
    h('div', { class: 'with-pane' }, pane, h('div', { class: 'stack wide-gap' }, controls, list)),
    down.length ? h('p', { class: 'callout' }, down.map(f => f.error).join(' ')) : null,
    h('p', { class: 'muted small' }, `Cloudflare’s feeds hold the newest 100 CVEs each, so this page covers recent CVEs only: ${reach.join('; ')}. Search covers what was read, not every CVE; for older ones use `, link(d.page, 'Cloudflare Radar'), '.'),
    h('p', { class: 'muted small' }, `Read from Cloudflare Radar’s free public feeds at ${when(d.checkedAt)} and kept for 30 minutes. HeatMap 360 only reports them.`)];
}

// ---------- High impact (exploits and disruptions that deserve attention) ----------
// One short list built by server/attention.mjs from CISA KEV, the exploit and patch headlines and the service health
// feeds. The rules that decide what makes the cut come from the server and are shown on the page.
const ATTN_WINDOWS = [['week', 'Last 7 days', 7 * 86_400_000], ['3d', 'Last 3 days', 3 * 86_400_000], ['8h', 'Last 8 hours', 8 * 3_600_000], ['4h', 'Last 4 hours', 4 * 3_600_000], ['hour', 'Last hour', 3_600_000]];
const LEVEL_CHIP = { critical: ['bad', 'Critical'], high: ['warn', 'High'] };
async function viewAttention() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'High impact'),
    h('p', {}, 'Zero-days, vulnerabilities attackers have just started using, and long or severe cloud outages, in one short list. Each item says why it made the cut. Kept short on purpose: everything else stays on the Internet and Service health pages.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/attention');
  const state = { win: prefs.get('attention.window', 'week'), kind: prefs.get('attention.kind', 'all') };
  if (!ATTN_WINDOWS.some(w => w[0] === state.win)) state.win = 'week';
  const body = h('div', { class: 'stack wide-gap' });
  // Disruptions on the list are still open, so they always show; exploits follow the time window.
  const inWindow = it => { if (it.active) return true; const ms = ATTN_WINDOWS.find(w => w[0] === state.win)[2]; return Boolean(it.seen) && Date.now() - Date.parse(it.seen) <= ms; };
  const seg = (key, pref, options) => h('div', { class: 'seg', role: 'group' }, options.map(([v, label]) => h('button', { class: `btn sm${state[key] === v ? ' on' : ''}`, 'aria-pressed': String(state[key] === v), busy: segBusy(key, label), onclick: () => { state[key] = v; prefs.set(pref, v); render(); } }, label)));
  const item = it => h('section', { class: `panel attn ${it.level}` },
    h('div', { class: 'attn-head' }, chip(...LEVEL_CHIP[it.level]), chip('info', it.kind === 'disruption' ? 'Disruption' : 'Exploit'),
      h('strong', { class: 'attn-title' }, it.title)),
    h('ul', { class: 'attn-why' }, it.why.map(w => h('li', {}, w))),
    it.detail ? h('p', { class: 'small' }, it.detail) : null,
    h('div', { class: 'muted small' }, [it.kind === 'disruption' ? (it.started ? `Started ${when(it.started)}` : 'Start time not given') : it.started ? `First reported ${new Date(it.started).toLocaleDateString()}` : null,
      it.seen && it.seen !== it.started ? `last update ${when(it.seen)}` : null, it.products?.length ? it.products.join(', ') : null, it.dueDate ? `CISA fix-by date for US agencies: ${it.dueDate}` : null].filter(Boolean).join(' · ')),
    h('div', { class: 'row attn-links' }, it.sources.map(s => link(s.link, s.name))));
  const render = () => {
    const list = d.items.filter(it => (state.kind === 'all' || it.kind === state.kind) && inWindow(it));
    const count = (f) => list.filter(f).length;
    body.replaceChildren(
      h('div', { class: 'statline' },
        h('div', {}, h('span', { class: 'n' }, count(i => i.level === 'critical')), h('span', { class: 'l' }, 'Critical')),
        h('div', {}, h('span', { class: 'n' }, count(i => i.level === 'high')), h('span', { class: 'l' }, 'High')),
        h('div', {}, h('span', { class: 'n' }, count(i => i.kind === 'exploit')), h('span', { class: 'l' }, 'Exploits')),
        h('div', {}, h('span', { class: 'n' }, count(i => i.kind === 'disruption')), h('span', { class: 'l' }, 'Disruptions happening now'))),
      h('div', { class: 'row spread' }, seg('win', 'attention.window', ATTN_WINDOWS.map(w => [w[0], w[1]])),
        seg('kind', 'attention.kind', [['all', 'All'], ['exploit', 'Exploits'], ['disruption', 'Disruptions']])),
      list.length ? h('div', { class: 'stack' }, list.map(item)) : h('p', { class: 'callout' }, 'Nothing high impact in this time window. That is the normal state.'));
  };
  render();
  const src = d.sources;
  const svcNote = src.services.filter(s => s.status !== 'checked');
  const newsDown = src.news.filter(s => s.status !== 'checked');
  return [head, body,
    h('div', { class: 'grid-2' },
      panel('What makes the cut', 'Rules HeatMap 360 applies, in plain words', h('ul', { class: 'stack tight' }, d.rules.map(r => h('li', { class: 'small' }, r)))),
      panel('Sources', 'All free and read only',
        h('ul', { class: 'stack tight' },
          h('li', { class: 'small' }, src.kev.status === 'checked' ? chip('ok', 'Checked') : chip('unknown', 'Not checked'), ' ', link(src.kev.page, src.kev.name), src.kev.error ? h('div', { class: 'muted' }, src.kev.error) : src.kev.total ? h('span', { class: 'muted' }, ` (${src.kev.total} entries in the catalog)`) : null),
          h('li', { class: 'small' }, newsDown.length ? chip('warn', `${src.news.length - newsDown.length} of ${src.news.length} read`) : chip('ok', `${src.news.length} read`), ' News feeds from Internet - Exploits and Internet - Patches',
            newsDown.length ? h('div', { class: 'muted' }, `Not read: ${newsDown.map(s => s.name).join(', ')}.`) : null),
          h('li', { class: 'small' }, svcNote.length ? chip('warn', `${src.services.length - svcNote.length} of ${src.services.length} checked`) : chip('ok', `${src.services.length} checked`), ' Service health feeds',
            src.servicesError ? h('div', { class: 'muted' }, src.servicesError) : null,
            svcNote.map(s => h('div', { class: 'muted' }, `${s.name}: ${s.status === 'not-connected' ? 'Not connected' : 'Not checked'}${s.note ? `. ${s.note}` : ''}`)))))),
    h('p', { class: 'muted small' }, `Checked ${when(d.checkedAt)}. This page tracks what is happening in the wild. It does not yet check whether your scanned computers are affected; that matching is planned work. HeatMap 360 only reports; it never changes anything.`)];
}

// ---------- Bluesky (official vendor accounts, free public API, read only) ----------
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
async function viewBluesky() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Bluesky'),
    h('p', {}, 'The latest posts from official vendor accounts on Bluesky: the top 50 for patches, updates, security and service health, plus every official Microsoft account.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/bluesky');
  const hidden = new Set(prefs.get('bsky.hidden', []));
  const state = { win: savedTimeframe('bsky.window'), by: prefs.get('bsky.by', 'time'), group: prefs.get('bsky.group', 'all') };
  const body = h('div', { class: 'stack wide-gap' });
  const inWindow = it => inTimeframe(state.win, it);
  const seg = (key, pref, options) => h('div', { class: 'seg', role: 'group' }, options.map(([v, label]) => h('button', { class: `btn sm${state[key] === v ? ' on' : ''}`, 'aria-pressed': String(state[key] === v), busy: segBusy(key, label), onclick: () => { state[key] = v; prefs.set(pref, v); render(); } }, label)));
  const repliesBox = it => {
    const box = h('div', { class: 'bsky-replies' });
    if (!it.replies) return box;
    const btn = h('button', { class: 'btn sm', busy: 'Reading replies…', fail: 'Could not read replies', onclick: async () => {
      const t = await api(`/api/admin/bluesky/thread?uri=${encodeURIComponent(it.uri)}`);
      {
        box.replaceChildren(t.replies.length
          ? h('ul', { class: 'headlines bsky-reply-list' }, t.replies.map(r => h('li', {},
            h('div', { class: 'muted small' }, [r.author, r.date && when(r.date), r.likes ? plural(r.likes, 'like') : null].filter(Boolean).join(' · ')),
            h('div', { class: 'small bsky-text' }, r.text),
            r.link ? h('div', { class: 'small' }, link(r.link, 'Open reply')) : null)))
          : h('p', { class: 'muted small' }, 'No replies could be read.'),
          h('p', { class: 'muted small' }, 'Replies are written by anyone on Bluesky. Shown as plain text, not checked.'));
      }
    } }, `Show replies (${it.replies})`);
    box.append(btn);
    return box;
  };
  const post = (it, a) => h('li', {},
    h('div', { class: 'muted small' }, [a && a.name, it.date && when(it.date)].filter(Boolean).join(' · ')),
    h('div', { class: 'bsky-text' }, it.text),
    h('div', { class: 'row muted small' }, h('span', {}, [plural(it.replies, 'reply', 'replies'), plural(it.reposts, 'repost'), plural(it.likes, 'like')].join(' · ')),
      it.link ? link(it.link, 'Open on Bluesky') : null),
    repliesBox(it));
  const render = () => {
    prefs.set('bsky.hidden', [...hidden]);
    const shown = d.accounts.filter(a => !hidden.has(a.id) && (state.group === 'all' || a.group === state.group));
    const controls = h('div', { class: 'row spread' }, seg('win', 'bsky.window', TIMEFRAMES.map(w => [w[0], w[1]])),
      h('div', { class: 'row' }, seg('group', 'bsky.group', [['all', 'All'], ['microsoft', 'Microsoft'], ['vendor', 'Other vendors']]), seg('by', 'bsky.by', [['time', 'Newest first'], ['account', 'By account']])));
    const readIds = shown.filter(a => a.status === 'checked').map(a => a.id);
    let content;
    if (!shown.length) { content = h('p', { class: 'muted' }, 'No account is ticked. Tick one on the left.'); pane.setCounts(new Map()); }
    else if (state.by === 'time') {
      const all = shown.flatMap(a => a.items.filter(inWindow).map(it => ({ it, a }))).sort((x, y) => (y.it.date || '').localeCompare(x.it.date || ''));
      const listed = all.slice(0, 200);
      pane.setCounts(countBy(readIds, listed, x => x.a.id));
      content = h('section', { class: 'panel' }, listed.length ? h('ul', { class: 'headlines' }, listed.map(x => post(x.it, x.a))) : h('p', { class: 'muted' }, 'Nothing in this time window.'),
        all.length > listed.length ? h('p', { class: 'muted small' }, `Showing the newest ${listed.length} of ${all.length}. Choose a shorter timeframe or By account to see the rest.`) : null,
        shown.some(a => a.status !== 'checked') ? h('p', { class: 'muted small' }, `Not checked: ${shown.filter(a => a.status !== 'checked').map(a => a.name).join(', ')}.`) : null);
    } else {
      pane.setCounts(new Map(readIds.map(id => [id, d.accounts.find(a => a.id === id).items.filter(inWindow).length])));
      content = h('div', { class: 'grid-2' }, shown.map(a => {
        const items = a.items.filter(inWindow);
        return h('details', { class: 'panel svc', open: items.length > 0 },
          h('summary', {}, h('span', { class: 'svc-title' }, h('strong', {}, a.rank ? `${a.rank}. ${a.name}` : a.name), a.status === 'checked' ? chip('info', plural(items.length, 'post')) : chip('unknown', 'Not checked')),
            h('span', { class: 'muted small' }, `${a.company} · @${a.handle}${a.rank ? '' : ' · official, has not posted yet'}`)),
          h('div', { class: 'stack svc-body' },
            a.error ? h('p', { class: 'muted small' }, a.error)
              : items.length ? h('ul', { class: 'headlines' }, items.map(it => post(it))) : h('p', { class: 'muted small' }, 'Nothing in this time window.'),
            h('p', { class: 'small' }, link(a.page, `Open @${a.handle}`))));
      }));
    }
    body.replaceChildren(controls, content);
  };
  const pane = pickPane('Accounts', d.accounts.map(a => ({ id: a.id, name: a.rank ? `${a.rank}. ${a.name}` : `${a.name} (not ranked)`, dot: a.status === 'checked' ? 'ok' : 'unknown' })), hidden, () => render());
  render();
  const silent = d.accounts.filter(a => !a.rank && a.status === 'checked' && !a.items.length).map(a => a.name);
  return [head,
    h('div', { class: 'with-pane' }, pane, body),
    silent.length ? h('p', { class: 'muted small' }, `Official Microsoft accounts with no posts yet: ${silent.join(', ')}. Their posts will show here once they start.`) : null,
    h('p', { class: 'muted small' }, `Read from Bluesky’s free public API at ${when(d.checkedAt)} and kept for 15 minutes. HeatMap 360 only reads; it never signs in or posts.`)];
}

// ---------- Pen tests (reading list) and Vulnerability scans (not built yet) ----------
// Informational only: a synopsis and a link per write-up. HeatMap 360 never runs these tools. Add new entries to the top.
const PEN_TESTS = [
  { title: 'Artificial Intelligence (AI) in Cybersecurity, Part 28: Using ADStrike to Compromise Active Directory',
    url: 'https://hackers-arise.com/artificial-intelligence-ai-in-cybersecurity-part-28-using-adstrike-to-compromise-active-directory/',
    source: 'Hackers-Arise', author: 'Co11ateral', date: '2026-10-12', target: 'Active Directory',
    synopsis: 'A walk-through of ADStrike, a free, open-source Active Directory penetration testing tool with 52 attack modules and selectable OPSEC (stealth) levels. Its optional AI mode hands the test to a local model run through Ollama (the author used Qwen 2.5-Coder 7B; any model that supports tool calls works): the model reads the result of each step and decides which tool to run next. The test starts from an ordinary domain user account with no special rights.',
    points: [
      'Setup: clone the tool from GitHub on Kali Linux and run its installer (about 5 minutes), then enter the domain details, which are saved to a config file. Menu option 53 starts the AI-run test; the author kept the default OPSEC level.',
      'The AI starts at reconnaissance and picks only the phases and steps that fit the domain, skipping attacks the environment cannot support.',
      'LAPS was not set up in the lab domain. Without it the local Administrator password can be the same on every computer, which makes moving from one machine to the next easy. The author suggests telling the client to fix it.',
      'Kerberoasting found a few service accounts whose password hashes could be requested; cracking them depends on how strong the passwords are against the wordlist used.',
      'Timeroasting pulled computer account hashes. Those are close to impossible to crack, but the tool also checks for "Pre2k" computer accounts whose password is just the computer name, using NetExec.',
      'It collects BloodHound data with SharpHound and has the AI look for attack paths and valuable accounts.',
      'At the end it writes a report in several formats; the HTML report maps the findings to MITRE ATT&CK and details each one.',
    ],
    verdict: 'The author finds ADStrike promising and easy to use. The AI is optional: the tool works without it, and you can use the AI for planning only if you do not want it running commands in your environment.',
    defend: [
      'Turn on Windows LAPS so every computer has its own local Administrator password.',
      'Give service accounts with SPNs long random passwords, or use group managed service accounts, so Kerberoasting yields nothing crackable.',
      'Find and reset computer accounts created as "pre-Windows 2000 compatible", whose password may still be the computer name.',
      'Run BloodHound against your own domain to see the attack paths an attacker would see.',
    ] },
];
function viewPenTests() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Pen tests'), h('p', {}, 'Penetration testing write-ups worth knowing about, each with a short synopsis and a link to the original.')));
  if (!me.elevated) return [head, gate()];
  const bullets = items => h('ul', {}, items.map(t => h('li', {}, t)));
  return [head,
    h('p', { class: 'callout' }, 'For reading only. HeatMap 360 does not run any of these tools. Only test systems you own or have written permission to test.'),
    ...PEN_TESTS.map(p => h('section', { class: 'panel' },
      h('div', { class: 'panel-head' }, h('h2', {}, p.title), h('span', { class: 'sub' }, `${p.source} · ${p.author} · ${p.date} · ${p.target}`)),
      h('div', { class: 'stack' },
        h('p', {}, p.synopsis),
        h('h3', {}, 'What the article covers'), bullets(p.points),
        h('h3', {}, 'Verdict'), h('p', {}, p.verdict),
        h('h3', {}, 'What to check in your own domain'), bullets(p.defend),
        h('p', {}, link(p.url, `Read the full article on ${p.source}`)))))];
}
function viewVulnScans() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Vulnerability scans'), h('p', {}, 'Results of vulnerability scans of your computers.')));
  if (!me.elevated) return [head, gate()];
  return [head,
    h('p', { class: 'callout' }, 'Not built yet. This section is a placeholder for vulnerability scan results.'),
    h('section', { class: 'panel' }, h('p', { class: 'muted' }, 'No vulnerability scans yet.'))];
}

// ---------- x.com (not populated yet) ----------
function viewX() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'x.com'), h('p', {}, 'Latest news from x.com for five timeframes.')));
  if (!me.elevated) return [head, gate()];
  return [head,
    h('p', { class: 'callout' }, 'Not populated yet. How this page gets its posts is still being decided.'),
    h('div', { class: 'grid-2' }, TIMEFRAMES.map(([, t]) =>
      h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', {}, t)), h('p', { class: 'muted' }, 'No posts yet.'))))];
}

// ---------- Options ----------
function viewOptions() {
  const opts = { speed: true, upload: false, wait: 15 };
  const out = h('pre', { class: 'code' });
  const render = () => {
    const args = [opts.upload && '-ScanAndUpload', !opts.speed && '-SkipSpeedTest', opts.upload && opts.wait !== 15 && `-WaitMinutes ${opts.wait}`].filter(Boolean);
    out.textContent = ['powershell -NoProfile -ExecutionPolicy Bypass -File .\\Invoke-HeatMapScan.ps1', ...args].join(' ');
  };
  const box = (key, label, help) => h('label', { class: 'option' }, h('input', { type: 'checkbox', checked: opts[key], onchange: e => { activity.flash('Updating the command…'); opts[key] = e.target.checked; render(); } }), h('span', {}, h('strong', {}, label), h('span', { class: 'muted small' }, help)));
  render();
  const what = [
    ['Windows and updates', 'Version, build, installed updates, end of support, known issues Microsoft reports for the build.'],
    ['Apps', 'Installed programs; winget package IDs to look up newer versions.'],
    ['Hardware and firmware', 'Make, model, BIOS (HP and Lenovo looked up with the vendor), motherboard, CPU, memory, drivers.'],
    ['Disk and battery health', 'Disk wear, temperature and uncorrected errors (run as administrator); battery capacity versus new.'],
    ['Event log', 'Counts of critical and error events per Windows component, last 7 days. Never the message text.'],
    ['Network adapters', 'Link speed, duplex, drivers, power and offload settings, Wi-Fi signal. No addresses or network names.'],
    ['Network health', 'Ping to the router, connection time and DNS lookup time, and download/upload speed against Cloudflare’s public speed test (about 35 MB).'],
    ['Security', 'Defender, BitLocker, Secure Boot, TPM, firewall; vulnerabilities exploited in the wild (CISA), version-checked against official CVE records.'],
  ];
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Options'), h('p', {}, 'Choose what the scanner does, then run the command on the computer. HeatMap 360 reports what it finds; it never changes a computer.'))),
    h('div', { class: 'grid-2' },
      panel('Scanner options', null,
        h('div', { class: 'stack' },
          box('speed', 'Measure internet speed', 'Downloads and uploads about 35 MB to Cloudflare’s speed test. Turn off on metered connections.'),
          box('upload', 'Upload right after the scan', 'Off: the scan only saves the anonymized file to Documents\\HeatMap360, and you upload it as a second step. On: scan and upload in one go.'),
          h('label', { class: 'option' }, h('span', {}, h('strong', {}, 'Wait for results (minutes)'), h('span', { class: 'muted small' }, 'When uploading from the scanner: how long it waits for the PDF before telling you how to fetch it later.')),
            h('input', { type: 'number', min: 1, max: 120, value: opts.wait, class: 'num-input', oninput: e => { opts.wait = Math.min(120, Math.max(1, Number(e.target.value) || 15)); render(); }, onchange: () => activity.flash('Updating the command…') }))),
        h('h3', {}, 'Command'), out,
        h('div', { class: 'row' }, copyButton(() => out.textContent), scannerButton('btn sm primary', 'Download the scanner'))),
      panel('What a scan checks', null, h('dl', { class: 'kv' }, what.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])))),
    h('section', { class: 'panel stack' }, h('div', { class: 'row' }, h('h2', {}, 'On-demand vulnerability check'), chip('info', 'Planned')),
      h('p', { class: 'muted' }, 'Check a scanned computer’s installed versions against published vulnerabilities on request. Report only.'), h('button', { class: 'btn', disabled: true, title: 'Planned. This button does nothing until the check is built.' }, 'Not available yet')),
  ];
}

// ---------- Scanner (public) ----------
// Step 2 in the browser: send a file the scanner saved. The server returns a scan ID and a token; the token is the
// only way to fetch that scan's PDF, so it stays in this browser (and in a ticket file the user can save).
const MAX_UPLOAD = 1024 * 1024;
const tickets = { list: () => prefs.get('uploads', []), save(list) { prefs.set('uploads', list.slice(0, 10)); } };
let poller = null;
function stopPolling() { if (poller) { clearInterval(poller); poller = null; } }
function saveFile(name, blob) { const url = URL.createObjectURL(blob); const a = h('a', { href: url, download: name }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10_000); }
async function uploaderFetch(t, what) {
  const r = await fetch(`/api/scans/${encodeURIComponent(t.id)}/${what}`, { headers: { authorization: `Bearer ${t.token}` } });
  if (!r.ok) throw Object.assign(new Error((await r.json().catch(() => null))?.error || `HTTP ${r.status}`), { status: r.status });
  return r;
}

function uploadsPanel() {
  const listEl = h('div', { class: 'stack' });
  const row = t => {
    const state = h('span', {}, chip('unknown', t.state === 'done' ? 'Ready' : t.state === 'rejected' ? 'Rejected' : 'Waiting for results'));
    const actions = h('div', { class: 'row' });
    const paint = () => {
      state.replaceChildren(t.state === 'done' ? chip('ok', 'Results ready') : t.state === 'rejected' ? chip('bad', 'Rejected') : t.state === 'gone' ? chip('unknown', 'Not found') : chip('warn', 'Waiting for results'));
      actions.replaceChildren(...[
        t.state === 'done' ? h('button', { class: 'btn sm primary', busy: 'Building PDF…', done: 'Downloaded', fail: 'PDF failed', onclick: async () => {
          saveFile(`HeatMap360-${t.id}.pdf`, await (await uploaderFetch(t, 'report.pdf')).blob());
        } }, 'Download PDF') : null,
        h('button', { class: 'btn sm', busy: 'Saving ticket…', done: 'Ticket saved', title: 'Save scan-<id>.json in Documents\\HeatMap360, then run the scanner with -Resume <id> to fetch the PDF later.', onclick: () =>
          saveFile(`scan-${t.id}.json`, new Blob([JSON.stringify({ id: t.id, token: t.token, server: location.origin, sentAt: t.sentAt }, null, 2)], { type: 'application/json' })) }, 'Save ticket'),
        h('button', { class: 'btn sm', busy: 'Forgetting…', onclick: () => { tickets.save(tickets.list().filter(x => x.id !== t.id)); render(); } }, 'Forget')].filter(Boolean));
    };
    t.paint = paint; paint();
    return h('div', { class: 'upload-row' }, h('div', {}, h('strong', {}, `Scan ${t.id}`), h('div', { class: 'muted small' }, [t.file, `sent ${when(t.sentAt)}`, t.reason].filter(Boolean).join(' · '))), state, actions);
  };
  let live = [];
  const refresh = async () => {
    let changed = false;
    for (const t of live.filter(x => x.state === 'queued')) {
      try { const s = await (await uploaderFetch(t, 'status')).json(); if (s.state !== t.state) { t.state = s.state; t.reason = s.reason; changed = true; t.paint(); } }
      catch (e) { if (e.status === 404) { t.state = 'gone'; changed = true; t.paint(); } }
    }
    if (changed) tickets.save(live.map(({ paint, ...x }) => x));
    if (!live.some(x => x.state === 'queued')) stopPolling();
  };
  const render = () => {
    stopPolling();
    live = tickets.list();
    listEl.replaceChildren(...(live.length ? live.map(row) : [h('p', { class: 'muted small' }, 'No uploads from this browser yet.')]));
    if (live.some(x => x.state === 'queued')) { refresh(); poller = setInterval(refresh, 20_000); }
  };
  // The button stays busy from the press until the upload ends: choosing the file, checking it, uploading it.
  let picked = null;
  const choose = () => new Promise(resolve => {
    picked = f => { picked = null; resolve(f); };
    // Browsers without the cancel event: the window gets focus back when the file dialog closes.
    window.addEventListener('focus', () => setTimeout(() => picked?.(null), 1000), { once: true });
    input.click();
  });
  const input = h('input', { type: 'file', accept: '.json,application/json', class: 'visually-hidden',
    onchange: e => { const f = e.target.files?.[0]; e.target.value = ''; picked?.(f || null); }, oncancel: () => picked?.(null) });
  const btn = h('button', { class: 'btn primary', busy: 'Choose the scan file…', done: 'Uploaded', fail: 'Upload failed', onclick: async (e, say) => {
    const f = await choose();
    if (!f) return CANCELLED;
    say('Checking the file…');
    if (f.size > MAX_UPLOAD) throw new Error('That file is larger than 1 MB. Choose an inventory-<time>.json file the scanner saved.');
    const text = await f.text();
    let doc; try { doc = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new Error('That file is not JSON. Choose an inventory-<time>.json file the scanner saved.'); }
    if (doc?.schema !== 'hm360.inventory/1') throw new Error('That file is not a HeatMap 360 scan. Choose an inventory-<time>.json file the scanner saved.');
    say('Uploading…');
    const r = await api('/api/scans', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(doc) });
    tickets.save([{ id: r.id, token: r.token, file: f.name, sentAt: new Date().toISOString(), state: 'queued' }, ...tickets.list()]);
    toast('Uploaded. Results usually take a few minutes.');
    render();
  } }, 'Choose a scan file and upload');
  render();
  return { button: h('div', { class: 'row' }, btn, input), list: listEl };
}

// The scanner download fetches the script (the server writes this site's address into it), then saves it.
const scannerButton = (cls, label) => h('button', { class: cls, busy: 'Preparing the scanner…', done: 'Downloaded', fail: 'Download failed', onclick: () => download(me.scannerUrl, 'Invoke-HeatMapScan.ps1') }, label);
const copyButton = text => h('button', { class: 'btn sm', busy: 'Copying…', done: 'Copied', fail: 'Copy failed', onclick: () => copyText(text()) }, 'Copy');
function viewScanner() {
  const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File .\\Invoke-HeatMapScan.ps1';
  const up = uploadsPanel();
  const copy = text => copyButton(() => text);
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scan a Windows computer'), h('p', {}, 'The scanner lists what is installed and saves it without anything that identifies you or the computer. Nothing is sent until you upload the file. Your results come back as a PDF.'),
      h('p', { class: 'small' }, 'First time? ', h('a', { href: '#guide' }, 'Read the How To Guide'), ' for every step and what happens behind it.'))),
    h('div', { class: 'grid-2' },
      panel('Four steps', null, h('ol', { class: 'steps-list' },
        h('li', {}, h('strong', {}, 'Download the scanner'), h('div', {}, scannerButton('btn', 'Download Invoke-HeatMapScan.ps1'))),
        h('li', {}, h('strong', {}, 'Scan: run it in PowerShell'), h('p', { class: 'muted small' }, 'Open PowerShell as administrator (so BitLocker and Secure Boot can be read) in the folder where you saved it. It saves the anonymized scan as Documents\\HeatMap360\\inventory-<time>.json and sends nothing. Open the file to read exactly what would be sent.'),
          h('pre', { class: 'code' }, cmd), copy(cmd)),
        h('li', {}, h('strong', {}, 'Upload the saved file'), h('p', { class: 'muted small' }, 'Choose the inventory file. Only that file is sent.'), up.button,
          h('p', { class: 'muted small' }, 'Or upload from PowerShell, which also waits for the PDF and saves it next to the scan:'), h('pre', { class: 'code' }, `${cmd} -Upload`), copy(`${cmd} -Upload`)),
        h('li', {}, h('strong', {}, 'Get your PDF'), h('p', { class: 'muted small' }, 'Your uploads appear below. When the results are ready, download the PDF. If you close this page, save the ticket first; run the scanner with -Resume <scan ID> to fetch the PDF later.')))),
      panel('What is sent', null,
        h('p', {}, h('strong', {}, 'Sent: '), 'Windows version, build and installed updates; installed programs and versions; computer make and model, BIOS, motherboard, processor, memory, disks and device drivers; Defender, BitLocker, Secure Boot, TPM and firewall status; how many critical and error events Windows logged in the last 7 days (counts only); network adapter models, link speed, drivers and settings, and Wi-Fi signal strength; disk and battery health; ping time to your router, DNS time and internet speed (Cloudflare speed test, about 35 MB; see Options to turn it off).'),
        h('p', {}, h('strong', {}, 'Never sent: '), 'computer name, user names, domain, IP or MAC addresses, Wi-Fi network names, serial numbers, event log messages, files or documents.'),
        h('p', { class: 'muted small' }, 'Want both steps at once? Add ', h('code', {}, '-ScanAndUpload'), ' and the scanner uploads right after it saves the file.'))),
    panel('Your uploads', 'From this browser', up.list),
  ];
}

// ---------- Overview (public) ----------
// New hire: the page a new owner of HeatMap 360 reads first, and the page visitors land on before they sign in.
// Static content only (no API calls). Describe only what is built; planned work goes in OVERVIEW_NOT_BUILT.
const OVERVIEW_FLOW = [
  ['Scan', 'Someone runs the scanner on a Windows computer. It reads the computer, leaves out anything that identifies it, and saves a file. Nothing is sent yet.', '#scanner'],
  ['Upload', 'They upload that one file from Get the scanner (or with -Upload). No account is needed; uploads are size and rate limited.', '#scanner'],
  ['Check', 'HeatMap 360 accepts only a genuine scan file, scrubs it again and hands it to the processing bot.', '#guide'],
  ['Look up', 'The bot looks up each component against official sources: Microsoft, the winget catalog, CISA, CVE records and the HP and Lenovo catalogs.', '#guide'],
  ['Report', 'The uploader gets a PDF. Admins see every scan, with its grade and every finding, on the Scans page.', '#scans'],
  ['Keep watching', 'Every item goes into one findings table. A background job looks each item up again about once a day, so a new problem shows up without a new scan.', '#scans'],
];
const OVERVIEW_AREAS = [
  ['New hire', 'Open to everyone, no sign-in.', [
    ['Overview', 'This page.', '#overview'],
    ['How To Guide', 'One scan end to end: each step, what happens behind it, what the result words mean, and troubleshooting.', '#guide'],
    ['Get the scanner', 'Download the scanner, upload a scan file and fetch your PDF.', '#scanner'],
  ]],
  ['Results', 'Admins with an active PIM elevation.', [
    ['Scans', 'Every scan, newest first. Each one opens to its grade, every finding and a PDF.', '#scans'],
    ['Pen tests', 'Penetration testing write-ups, each with a short synopsis and a link to the original. For reading only.', '#pentests'],
    ['Vulnerability scans', 'Placeholder for vulnerability scan results, not built yet.', '#vulnscans'],
    ['High impact', 'One short list of what deserves attention now: vulnerabilities CISA just confirmed are exploited, zero-day headlines, and long or severe cloud outages. Each item says why it made the cut.', '#attention'],
    ['Internet - Cloud Services', 'Headlines from the big cloud providers’ own blogs and update pages.', '#cloud'],
    ['Internet - Exploits', 'Security advisories and news: CISA, the Microsoft Security Update Guide, SANS and others.', '#exploits'],
    ['Cloudflare Radar CVEs', 'Newly published CVEs from Cloudflare Radar, filtered by severity, timeframe, known exploited and search.', '#cves'],
    ['Internet - Patches', 'Patch news feeds, so you hear about a bad update before it reaches your computers.', '#patches'],
    ['x.com', 'Five timeframes, not populated yet.', '#x'],
    ['Bluesky', 'Latest posts from official vendor accounts about patches, security and service health, with replies on demand.', '#bluesky'],
    ['Service health', 'Microsoft 365 health for your tenant, plus Azure, AWS, Google Cloud, Google Workspace, GitHub and Cloudflare.', '#services'],
  ]],
  ['Tools', 'Options is open to everyone; Settings needs Settings Admin.', [
    ['Options', 'Builds the scanner command: speed test on or off, save only or scan and upload, wait time.', '#options'],
    ['Settings', 'Settings Admins only: which storage account and table hold the findings table.', '#settings'],
  ]],
];
const OVERVIEW_FIRST_STEPS = [
  ['Scan a computer yourself', 'Follow the [How To Guide] once from start to finish on your own computer. It takes about five minutes and shows you exactly what users see.'],
  ['Read your PDF', 'Note which items are Good, Needs attention, Action needed and Not checked, and why. Not checked means the lookup could not tell; nothing is assumed.'],
  ['Get elevated', 'Sign in with your work account and activate your HeatMap Admins membership in Privileged Identity Management. It lasts 8 hours. Then open [Scans] and find your scan.'],
  ['Read the news pages', 'Start with [High impact], then spend ten minutes on [Internet - Exploits], [Internet - Patches] and [Service health]. That is where you hear about a problem before a scan shows it.'],
  ['Know what HeatMap 360 will not do', 'It reports; it never fixes. Fixing what it finds is done with your normal tools, outside HeatMap 360.'],
];
const OVERVIEW_TERMS = [
  ['Scan', 'One run of the scanner on one computer, saved as an inventory-<time>.json file.'],
  ['Anonymous machine ID', 'A one-way code made from Windows’ own ID. Two scans of the same computer match, but the code does not reveal which computer it is.'],
  ['Finding', 'One item from a scan (an app, an update, a driver, a setting) with its verdict.'],
  ['KEV', 'CISA’s Known Exploited Vulnerabilities list: vulnerabilities attackers are using in the wild right now. A match here is Action needed.'],
  ['CVE', 'The public ID of a vulnerability (CVE-year-number), from the CVE Program. HeatMap 360 uses the official records to match versions.'],
  ['Release health', 'Microsoft’s official page of supported Windows builds and the known issues Microsoft reports for each update.'],
  ['winget catalog', 'Microsoft’s public catalog of Windows apps. HeatMap 360 reads the newest version of each app from it.'],
  ['PIM', 'Privileged Identity Management. Admin access in HeatMap 360 is never permanent: you activate it when you need it, and it ends after 8 hours.'],
];
const OVERVIEW_NOT_BUILT = [
  'Matching scans against the news and social feeds, with a verdict per product.',
  'AI-assisted lookups of known issues for each component.',
  'Posts on the x.com page.',
  'Vulnerability scan results.',
  'BIOS lookups for makers other than HP and Lenovo.',
];
function viewOverview() {
  // [Page name] in the copy above becomes a link to that page.
  const pages = Object.fromEntries(OVERVIEW_AREAS.flatMap(([, , items]) => items.map(([name, , href]) => [name, href])));
  const rich = text => text.split(/\[([^\]]+)\]/).map((part, i) => (i % 2 && pages[part] ? h('a', { href: pages[part] }, part) : part));
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Welcome to HeatMap 360'),
      h('p', { class: 'overview-lead' }, 'HeatMap 360 shows how healthy each Windows computer is and whether anything on it is outdated, has a known problem, or is being attacked in the wild. It reads, looks things up and reports. It never installs, updates or changes anything on a computer.'))),
    h('div', { class: 'grid-3' },
      panel('What it does', null, h('p', {}, 'Takes an anonymous inventory of a computer, checks every part of it against ', h('strong', {}, 'official vendor sources'), ', and grades it. Alongside that it collects patch, exploit and cloud health news in one place.')),
      panel('What you do not need', null, h('p', {}, 'No account to scan, and no agent to install. The scanner is one PowerShell script you can read line by line. You only sign in to see ', h('strong', {}, 'everyone’s'), ' results.')),
      panel('What it will not do', null, h('p', {}, 'It never fixes anything, never collects computer names, user names, addresses, serial numbers or files, and never posts anywhere.'))),
    panel('How a scan moves through HeatMap 360', 'Each step name opens the page where it happens',
      h('ol', { class: 'overview-flow' }, OVERVIEW_FLOW.map(([name, text, href], i) => h('li', { class: 'overview-step' },
        h('span', { class: 'overview-num' }, String(i + 1)), h('a', { class: 'overview-name', href }, name), h('span', { class: 'overview-text' }, text))))),
    panel('What each area does', 'The sections of the left pane, top to bottom',
      OVERVIEW_AREAS.map(([section, who, items]) => [h('h3', {}, section, ' ', h('span', { class: 'muted small' }, who)),
        h('dl', { class: 'kv' }, items.map(([name, text, href]) => [h('dt', {}, h('a', { href }, name)), h('dd', {}, text)]))])),
    h('div', { class: 'grid-2' },
      panel('Your first week', null, h('ol', { class: 'steps-list' }, OVERVIEW_FIRST_STEPS.map(([title, text]) => h('li', {}, h('strong', {}, title), h('p', { class: 'muted small' }, rich(text)))))),
      panel('Words you will hear', null, h('dl', { class: 'kv' }, OVERVIEW_TERMS.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])))),
    panel('Not built yet', 'So nobody goes looking for them', h('ul', {}, OVERVIEW_NOT_BUILT.map(t => h('li', {}, t)))),
    h('div', { class: 'row' }, h('a', { class: 'btn primary', href: '#guide' }, 'Next: the How To Guide'), h('a', { class: 'btn', href: '#scanner' }, 'Get the scanner')),
  ];
}

// ---------- How To Guide (public) ----------
// A user guide to one scan, end to end: what to do at each step and what HeatMap 360 does behind it.
const GUIDE_AI_NOTE = 'AI will be used to scan for known issues with each component.';
function viewGuide() {
  const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File .\\Invoke-HeatMapScan.ps1';
  const step = (title, todo, behind) => h('li', {}, h('strong', {}, title),
    todo ? h('div', { class: 'stack tight' }, todo) : null,
    h('div', { class: 'callout' }, h('strong', {}, 'What happens: '), behind));
  const lookups = [
    ['Windows', 'Microsoft release health: is this build still supported, is it the latest for its version, and which known issues Microsoft reports for it.'],
    ['Installed updates', 'Microsoft release health: known problems Microsoft has published for the updates on the computer.'],
    ['Apps', 'The winget catalog for the newest version, and the publisher’s release notes it links for known problems.'],
    ['BIOS and firmware', 'The HP and Lenovo catalogs for the newest BIOS for that model. Other makers show “Not checked” for now.'],
    ['Exploited vulnerabilities', 'The CISA Known Exploited Vulnerabilities list, matched to the installed versions using the official CVE records.'],
    ['Drivers, disks, network and security', 'Checked against healthy values: network driver age, disk wear and errors, adapter speed and settings, Defender, BitLocker, Secure Boot, TPM and firewall.'],
  ];
  const words = [
    [chip('ok', 'Good'), 'Up to date and no known problems found.'],
    [chip('warn', 'Needs attention'), 'Outdated, or a known problem the vendor has reported. Plan to update.'],
    [chip('bad', 'Action needed'), 'Unsupported, or a vulnerability that is being exploited in the wild. Update first.'],
    [chip('unknown', 'Not checked'), 'The scanner could not read it, or the lookup failed or does not cover it yet. Nothing is assumed.'],
  ];
  const trouble = [
    ['PowerShell says scripts are disabled', 'Use the command as shown: -ExecutionPolicy Bypass applies to this one run only and changes no setting.'],
    ['BitLocker or Secure Boot reads “Not checked”', 'Run PowerShell as administrator and scan again.'],
    ['The upload was rejected', 'Only an unchanged inventory-<time>.json file the scanner saved is accepted, up to 1 MB. Scan again and upload the new file.'],
    ['Too many uploads', 'Uploads are rate limited. Wait the number of minutes shown, then try again.'],
    ['Results are taking long', 'Save the ticket (or keep the scan ID), close the page and come back later, or run the scanner with -Resume <scan ID>.'],
  ];
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'How To Guide: scan a computer'),
      h('p', {}, 'Everything from downloading the scanner to reading your results, and what HeatMap 360 is doing at each step. HeatMap 360 only reports what it finds; it never installs, updates or changes anything on a computer.'))),
    panel('Before you start', null, h('ul', {},
      h('li', {}, 'A Windows 10 or Windows 11 computer with Windows PowerShell 5.1 (built in) or PowerShell 7.'),
      h('li', {}, 'Administrator rights are recommended so BitLocker and Secure Boot can be read. The scan still works without them.'),
      h('li', {}, 'An internet connection. The speed test sends and receives about 35 MB; you can turn it off.'),
      h('li', {}, 'No account and no password. Anyone who can reach this site can scan and upload.'))),
    panel('Step by step', null, h('ol', { class: 'steps-list' },
      step('Download the scanner',
        h('p', {}, 'Open ', h('a', { href: '#scanner' }, 'Get the scanner'), ' and download Invoke-HeatMapScan.ps1.'),
        'HeatMap 360 writes its own web address into the script as you download it, so the upload in step 4 comes back to this site. The script is plain text: you can open it in Notepad and read every line before you run it.'),
      step('Run the scan',
        [h('p', {}, 'Open PowerShell as administrator in the folder where you saved the script, then run:'), h('pre', { class: 'code' }, cmd)],
        'The scanner reads this computer only. It collects the Windows version, build and installed updates; installed apps and their versions; make, model, BIOS, motherboard, processor, memory, disks and drivers; Defender, BitLocker, Secure Boot, TPM and firewall status; how many errors Windows logged in the last 7 days (counts only); network adapter settings and Wi-Fi signal; disk and battery health; and network speed. It then removes everything that identifies you: the computer name, user names, domain, IP and MAC addresses, Wi-Fi network names and serial numbers are never collected. The computer is known only by a one-way code made from Windows’ own ID, so two scans of the same computer can be compared without revealing which computer it is. Anything it cannot read is noted and the scan carries on.'),
      step('Check the file (optional)',
        h('p', {}, 'Open Documents\\HeatMap360\\inventory-<time>.json in Notepad.'),
        'Nothing has been sent yet. This file is exactly what would be uploaded, so you can confirm there is nothing personal in it.'),
      step('Upload the file',
        [h('p', {}, 'On ', h('a', { href: '#scanner' }, 'Get the scanner'), ', choose the file with “Choose a scan file and upload”. Or upload from PowerShell, which also waits for the PDF:'), h('pre', { class: 'code' }, `${cmd} -Upload`)],
        'Only that one file is sent, over HTTPS. HeatMap 360 checks that it is a genuine HeatMap 360 scan and turns anything else away, then gives it a scan ID and a private ticket. The ticket stays in your browser (or with the script) and is the only way to fetch this scan’s results. The upload goes into HeatMap 360’s private data store, which starts the processing.'),
      step('Wait while each component is looked up', null,
        [h('span', {}, 'A processing bot checks the upload again, then looks up each component the scan found, one at a time, to find out whether it is current and whether there are known issues with it. ', GUIDE_AI_NOTE, ' Each lookup stands alone: if one source is down, only that part shows “Not checked” and the rest of the results still arrive. This usually takes a few minutes; the page checks for you every 20 seconds.')]),
      step('Get your results',
        h('p', {}, 'When the upload shows “Results ready”, select Download PDF. If you close the page, save the ticket first, or run the scanner with -Resume <scan ID> later.'),
        'HeatMap 360 builds the PDF from the bot’s results: an overall grade, then each area with what was found, what the latest version is, and any known issues or exploited vulnerabilities, with a link to the source where there is one.'),
      step('Keep watching (automatic)', null,
        'Every item from the scan is also saved in a central findings list, one row per item per computer. A background job looks each item up again about once a day, so a newly reported problem or a newly exploited vulnerability is flagged without you having to scan again. Scan again after you install updates to refresh the list.'))),
    h('div', { class: 'grid-2' },
      panel('What each component is looked up against', 'Official sources today', h('dl', { class: 'kv' }, lookups.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
        h('p', { class: 'callout' }, h('strong', {}, 'Coming next: '), GUIDE_AI_NOTE, ' It will read vendor pages, advisories and security news for problems with the exact versions found, on top of the official lookups above, and flag what it finds for review.')),
      panel('Reading the results', null, h('dl', { class: 'kv' }, words.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
        h('p', { class: 'muted small' }, 'HeatMap admins can also open every scan in full on the Scans page. That needs a sign-in with a work account and an active HeatMap Admins membership, activated in Privileged Identity Management (it lasts 8 hours).'))),
    panel('If something goes wrong', null, h('dl', { class: 'kv' }, trouble.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]))),
    h('div', { class: 'row' }, h('a', { class: 'btn primary', href: '#scanner' }, 'Start: get the scanner')),
  ];
}

// ---------- Settings (Settings Admins only) ----------
async function viewSettings() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Settings'), h('p', {}, 'Where HeatMap 360 keeps its findings table. Only Settings Admins can see or change this.')));
  if (!me.signedIn) return [head, gate()];
  if (!me.projectAdmin) return [head, h('div', { class: 'empty' },
    h('h2', {}, 'Elevate to Settings Admin'),
    h('p', { class: 'muted' }, 'Settings need an active Settings Admin membership. Activate it in Privileged Identity Management, then check again.'),
    h('div', { class: 'row' },
      pimLink(),
      h('button', { class: 'btn', busy: 'Checking with Microsoft…', fail: 'Not active yet', onclick: async () => {
        const r = await api('/api/me/recheck', { method: 'POST' });
        if (!r.projectAdmin) throw new Error('Activation can take a minute. Check again shortly.');
        toast('Settings Admin is active.'); await boot();
      } }, 'I activated it, check again')))];
  const s = await api('/api/admin/settings');
  const account = h('input', { type: 'text', value: s.findings.account || '', placeholder: 'storage account name', maxLength: 24, pattern: '[a-z0-9]{3,24}', required: true, autocomplete: 'off', spellcheck: false });
  const tableName = h('input', { type: 'text', value: s.findings.table || 'findings', maxLength: 63, pattern: '[A-Za-z][A-Za-z0-9]{2,62}', required: true, autocomplete: 'off', spellcheck: false });
  const saved = h('p', { class: 'muted small' }, s.updatedAt ? `Last changed ${when(s.updatedAt)}${s.updatedBy ? ` by ${s.updatedBy}` : ''}.` : 'Not set here yet: the findings job uses the account it was started with.');
  const form = h('form', { class: 'settings-form', busy: 'Saving…', done: 'Saved', fail: 'Not saved', onsubmit: async () => {
    const r = await api('/api/admin/settings/findings', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ account: account.value.trim(), table: tableName.value.trim() }) });
    saved.textContent = `Saved ${when(r.updatedAt)}. The findings job uses it from its next run.`;
  } },
    h('label', { class: 'field' }, h('span', {}, 'Azure storage account'), account),
    h('label', { class: 'field' }, h('span', {}, 'Table'), tableName),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save')));
  return [head, panel('Findings storage', 'Azure Table Storage, signed in with Entra (no keys are stored)', form, saved,
    h('p', { class: 'muted small' }, 'To move it: create the new storage account in Azure, give the account the findings job runs as the role Storage Table Data Contributor on it, then save the new name here. On its next run the job creates the table if needed and rebuilds it from the scan results it reads. The old table is left as it is.'))];
}

// ---------- router ----------
// Page loads give the same feedback as buttons: a spinner on the link that was pressed and on the page's rail entry,
// and "Loading <page>…" in the status bar until the page is on screen (or the reason it could not load).
const PAGE_NAMES = { scans: 'Scans', scan: 'the scan', pentests: 'Pen tests', vulnscans: 'Vulnerability scans', attention: 'High impact', cloud: 'Internet - Cloud Services', exploits: 'Internet - Exploits', cves: 'Cloudflare Radar CVEs', patches: 'Internet - Patches',
  x: 'x.com', bluesky: 'Bluesky', services: 'Service health', options: 'Options', actions: 'Options', settings: 'Settings', overview: 'Overview', guide: 'the How To Guide', scanner: 'Get the scanner' };
let pressedLink = null, routeSeq = 0;
async function route() {
  const hash = location.hash.slice(1) || (me?.elevated ? 'scans' : 'overview');
  const [name, arg] = hash.split('/');
  const current = name === 'scan' ? 'scans' : name === 'actions' ? 'options' : name;
  document.querySelectorAll('.nav-item').forEach(a => a.setAttribute('aria-current', a.dataset.route === current ? 'page' : 'false'));
  const view = $('#view');
  stopPolling();
  const seq = ++routeSeq;
  const spinning = [document.querySelector(`.nav-item[data-route="${current}"]`), pressedLink].filter(Boolean);
  pressedLink = null;
  document.querySelectorAll('.is-loading').forEach(el => el.classList.remove('is-loading'));
  spinning.forEach(el => el.classList.add('is-loading'));
  const page = PAGE_NAMES[name] || 'Scans';
  const act = activity.start(`Loading ${page}…`);
  let failed = null;
  try {
    const content = name === 'scan' ? await viewScan(arg) : name === 'options' || name === 'actions' ? viewOptions() : name === 'services' ? await viewServices() : name === 'attention' ? await viewAttention()
      : Object.hasOwn(NEWS_TITLES, name) ? await viewNews(name) : name === 'cves' ? await viewCves() : name === 'x' ? viewX() : name === 'pentests' ? viewPenTests() : name === 'vulnscans' ? viewVulnScans() : name === 'bluesky' ? await viewBluesky() : name === 'settings' ? await viewSettings() : name === 'scanner' ? viewScanner() : name === 'guide' ? viewGuide() : name === 'overview' ? viewOverview() : await viewScans();
    if (seq !== routeSeq) { act.done(); return; } // a newer page was asked for while this one loaded
    view.classList.toggle('wide', ['services', 'cloud', 'exploits', 'cves', 'patches', 'bluesky', 'attention'].includes(name));
    view.replaceChildren(...[content].flat().filter(Boolean));
  } catch (e) {
    if (seq !== routeSeq) { act.done(); return; }
    if (e.status === 401 || e.status === 403) { spinning.forEach(el => el.classList.remove('is-loading')); act.done(); await boot(false); return; }
    failed = e;
    view.replaceChildren(h('p', { class: 'callout bad' }, `Could not load this page: ${e.message}`));
  }
  spinning.forEach(el => el.classList.remove('is-loading'));
  if (failed) act.fail(`Could not load ${page}: ${failed.message}`); else act.done();
  window.scrollTo(0, 0);
}

// Controls that are not built with h(): the rail and menu buttons in index.html and the shared shell, and links.
// Capture phase, so the wording is read before the control changes.
document.addEventListener('click', e => {
  const el = e.target.closest?.('#theme-toggle, .nav-label, #nav-toggle, .app-switcher-toggle, a.app-switch-item[href], a[href^="#"]:not([data-jump])');
  if (!el || e.defaultPrevented || e.button > 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
  if (el.id === 'theme-toggle') activity.flash(document.documentElement.dataset.theme === 'dark' ? 'Switching to light mode…' : 'Switching to dark mode…');
  else if (el.classList.contains('nav-label')) activity.flash(`${el.getAttribute('aria-expanded') === 'false' ? 'Opening' : 'Closing'} ${el.textContent.trim()}…`);
  else if (el.id === 'nav-toggle') activity.flash(document.body.classList.contains('nav-open') ? 'Closing the menu…' : 'Opening the menu…');
  else if (el.classList.contains('app-switcher-toggle')) activity.flash(el.parentElement.open ? 'Closing the 360 apps list…' : 'Opening the 360 apps list…');
  else if (el.classList.contains('app-switch-item')) busy(el, `Opening ${el.querySelector('strong')?.textContent || 'the app'}…`, () => new Promise(() => {}));
  else if (location.hash && el.getAttribute('href') === location.hash) { e.preventDefault(); pressedLink = el; route(); } // same page: load it again
  else if (el.getAttribute('href').length > 1) pressedLink = el;
}, true);
// Coming back with the browser's Back button can restore a page still showing "Opening sign-in…": start fresh.
window.addEventListener('pageshow', e => { if (e.persisted) boot(); });

async function boot(doRoute = true) {
  me = await api('/api/me').catch(() => ({ signedIn: false, authConfigured: false, scannerUrl: '/client/Invoke-HeatMapScan.ps1' }));
  renderAccount();
  if (doRoute) await route(); else { $('#view').replaceChildren(gate()); }
}
window.addEventListener('hashchange', route);
boot();
