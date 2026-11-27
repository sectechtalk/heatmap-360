// HeatMap 360 UI. Plain DOM (CSP: script-src 'self'), hash routes: #scans, #scan/<id>, #pentests, #vulnscans, #adposture, #attackpaths, #entraposture, #cloudposture, #chaosmonkey, #setup, #attention, #affected, #catalog, #cases, #case/<id>, #cloud, #exploits, #cves, #patches, #x, #bluesky, #services, #options, #settings, #overview, #guide, #scanner, #compare.
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
// ---------- collapsible sections: every headed section on every page folds, and starts folded (asked 2026-11-27) ----------
// fold() is the one way to build a section with a heading; panel() is fold() with an h2 heading and a grey subtitle.
// The heading row stays visible and opens or closes the section. What you open stays open while you stay on the page
// (a filter, timeframe or domain change re-draws it) and everything is folded again when you open a page. route() adds
// Expand all / Collapse all to every page with more than one section. tests/collapsible.test.mjs keeps new pages to this.
const foldOpen = new Set();
function fold({ class: cls = '', key, id } = {}, summary, ...body) {
  const sum = h('summary', {}, summary);
  const k = key || sum.textContent.trim();
  const d = h('details', { class: `fold ${cls}`.trim(), id, open: foldOpen.has(k) }, sum, body);
  d.addEventListener('toggle', () => { if (d.open) foldOpen.add(k); else foldOpen.delete(k); });
  return d;
}
const panel = (title, sub, ...body) => fold({ class: 'panel' }, h('span', { class: 'panel-head' }, h('h2', {}, title), sub ? h('span', { class: 'sub' }, sub) : null), body);
// The words a section is known by: its heading, else its whole heading row.
const foldLabel = d => (d?.querySelector(':scope > summary :is(h2, h3, strong)') || d?.querySelector(':scope > summary'))?.textContent.trim() || 'the section';
// In-page "Details" links: open the section (and any section around it), then scroll to it.
function jumpTo(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const d = el.matches('details') ? el : el.querySelector('details');
  for (let x = d; x; x = x.parentElement?.closest('details')) x.open = true;
  activity.flash(`Opening ${foldLabel(d)}…`);
  el.scrollIntoView({ behavior: 'smooth' });
}
const setFolds = open => document.querySelectorAll('#view details').forEach(d => { d.open = open; });
const foldBar = () => h('div', { class: 'row fold-bar' },
  h('button', { class: 'btn sm', busy: 'Expanding…', onclick: () => setFolds(true) }, 'Expand all'),
  h('button', { class: 'btn sm', busy: 'Collapsing…', onclick: () => setFolds(false) }, 'Collapse all'));
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
// Download through fetch so the button can say "Building the file…" until the file has arrived, and show a failure.
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
  const area = (grade, title, detail, target) => h('div', { class: 'area' }, h('span', { class: `bar ${grade}` }), h('div', {}, h('strong', {}, title), h('div', { class: 'muted small' }, detail)), target ? h('a', { href: `#scan/${id}`, 'data-jump': '', onclick: e => { e.preventDefault(); jumpTo(target); } }, 'Details') : null);
  const issues = (ki.issues || []).filter(i => i.applies !== 'not-affected');
  return [
    h('div', { class: 'page-head' },
      h('div', {}, h('a', { href: '#scans', class: 'small' }, '← All scans'), h('h1', {}, [sys.manufacturer, sys.model].filter(Boolean).join(' ') || 'Scanned computer'),
        h('p', {}, `Anonymous ID ${inv.machineId} · scanned ${when(inv.collectedAt)} · checked ${when(r.processedAt)}`)),
      h('button', { class: 'btn', busy: 'Building results file…', done: 'Downloaded', fail: 'Download failed', title: 'One .mhtml file: opens in Edge or Chrome, works offline.', onclick: () => download(`/api/admin/scans/${encodeURIComponent(id)}/report.mhtml`, `HeatMap360-${id}.mhtml`) }, 'Download results (.mhtml)')),
    fold({ class: 'panel', key: 'verdict' },
      h('span', { class: 'verdict' }, h('span', { class: `dot ${s.overall}` }), h('span', {}, h('h2', {}, WORD[s.overall]), h('span', { class: 'muted' }, 'Each area below is checked against the vendor’s official source. Anything that could not be checked says so.'))),
      h('div', { class: 'areas' },
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
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Service health'), h('p', {}, 'Online services, from each provider’s own public status feed. Refreshed every 5 minutes. Tick a service on the left to show it; select a service to open or close it. Every service starts closed; its status shows on its heading.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/services');
  const hidden = new Set(prefs.get('services.hidden', []));
  const cardsEl = new Map();
  const card = p => fold({ class: 'panel svc', key: `svc:${p.id}` },
    [h('span', { class: 'svc-title' }, h('strong', {}, p.name), chip(p.grade === 'info' ? 'info' : p.grade, p.grade === 'unknown' ? p.summary : IMPACT[p.grade])),
      h('span', { class: 'muted small' }, p.error || p.note || p.summary)],
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
  render();
  return [head,
    h('div', { class: 'with-pane' },
      pickPane('Services', d.providers.map(p => ({ id: p.id, name: p.name, dot: COLUMN(p.grade) === 'incidents' ? (p.grade === 'info' ? 'info' : p.grade) : p.grade })), hidden, render),
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
      content = [foldBar(), h('div', { class: 'grid-2' }, shown.map(s => {
        const items = s.items.filter(inWindow);
        return fold({ class: 'panel svc', key: `news:${s.id}` },
          [h('span', { class: 'svc-title' }, h('strong', {}, s.name), s.status === 'checked' ? chip('info', `${items.length} post${items.length === 1 ? '' : 's'}`) : chip('unknown', 'Not checked')),
            h('span', { class: 'muted small' }, s.about)],
          h('div', { class: 'stack svc-body' },
            s.error ? h('p', { class: 'muted small' }, s.error)
              : items.length ? h('ul', { class: 'headlines' }, items.map(it => headline(it))) : h('p', { class: 'muted small' }, 'Nothing in this time window.'),
            h('p', { class: 'small' }, link(s.page, `Open ${s.name}`))));
      }))];
    }
    body.replaceChildren(controls, ...[content].flat());
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
  const item = it => fold({ class: `panel attn ${it.level}`, key: `attn:${it.kind}:${it.title}` },
    h('span', { class: 'attn-head' }, chip(...LEVEL_CHIP[it.level]), chip('info', it.kind === 'disruption' ? 'Disruption' : 'Exploit'),
      h('strong', { class: 'attn-title' }, it.title)),
    h('ul', { class: 'attn-why' }, it.why.map(w => h('li', {}, w))),
    it.detail ? h('p', { class: 'small' }, it.detail) : null,
    h('div', { class: 'muted small' }, [it.kind === 'disruption' ? (it.started ? `Started ${when(it.started)}` : 'Start time not given') : it.started ? `First reported ${new Date(it.started).toLocaleDateString()}` : null,
      it.seen && it.seen !== it.started ? `last update ${when(it.seen)}` : null, it.products?.length ? it.products.join(', ') : null, it.dueDate ? `CISA fix-by date for US agencies: ${it.dueDate}` : null].filter(Boolean).join(' · ')),
    h('div', { class: 'row attn-links' }, it.sources.map(s => link(s.link, s.name)), openCaseButton(it.id)));
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
    h('p', { class: 'muted small' }, `Checked ${when(d.checkedAt)}. This page tracks what is happening in the wild. Whether your scanned computers are affected is on `, h('a', { href: '#affected' }, 'Are we affected?'), '. HeatMap 360 only reports; it never changes anything.')];
}

// ---------- Are we affected? (High impact exploits matched against scanned computers) ----------
// Built by server/exposure.mjs: each exploit on the High impact list against the newest scan of every computer, with
// the bot's own verdict when it has one and the same KEV + CVE version check otherwise. Report only.
const CALL_CHIP = { 'act-now': ['bad', 'Act now'], affected: ['bad', 'Affected'], verify: ['warn', 'Check by hand'], 'cannot-check': ['unknown', 'Cannot check'], clear: ['ok', 'Not affected'], 'no-scans': ['unknown', 'No scans yet'] };
const VERDICT_CHIP = { affected: ['bad', 'Vulnerable version'], verify: ['warn', 'Check by hand'], patched: ['ok', 'Patched'], clear: ['ok', 'Not installed'], unknown: ['unknown', 'Not checked'] };
async function viewAffected() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Are we affected?'),
    h('p', {}, 'Every exploit on the High impact list, checked against the newest scan of each scanned computer: which computers have a vulnerable version, which need a check by hand, and which are fine. HeatMap 360 only reports; fixing belongs to Remediation 360.')));
  if (!me.elevated) return [head, gate()];
  let d = await api('/api/admin/exposure');
  const state = { show: prefs.get('affected.show', 'hits') };
  const body = h('div', { class: 'stack wide-gap' });
  const seg = options => h('div', { class: 'seg', role: 'group' }, options.map(([v, label]) => h('button', { class: `btn sm${state.show === v ? ' on' : ''}`, 'aria-pressed': String(state.show === v), busy: segBusy('show', label), onclick: () => { state.show = v; prefs.set('affected.show', v); render(); } }, label)));
  const machineRows = it => it.machines.filter(m => m.verdict !== 'clear').map(m => h('tr', {},
    h('td', {}, h('a', { href: `#scan/${m.scanId}` }, m.computer), h('div', { class: 'muted small' }, [m.windows, `machine ${m.machineId.slice(0, 8)}…`].filter(Boolean).join(' · '))),
    h('td', {}, chip(...VERDICT_CHIP[m.verdict])),
    h('td', { class: 'small' }, m.matches.map(x => h('div', {}, `${x.product}${x.fixedIn ? ` (fixed in ${x.fixedIn})` : ''}`, x.why ? h('div', { class: 'muted' }, x.why) : null))),
    h('td', { class: 'small' }, when(m.scannedAt), m.stale ? h('div', {}, chip('warn', 'Old scan')) : null,
      h('div', { class: 'muted' }, m.matches.some(x => x.source === 'scan') ? 'Judged by the bot' : 'Matched now'))));
  const item = it => {
    const rows = machineRows(it);
    const c = it.counts;
    // Collapsed by default (every section on every page, owner's rule 2026-11-26): the summary line carries the verdict.
    return fold({ class: `panel attn ${it.level}`, key: `affected:${it.title}` },
      [h('span', { class: 'attn-head' }, chip(...CALL_CHIP[it.call]), chip(...LEVEL_CHIP[it.level]), h('strong', { class: 'attn-title' }, it.title)),
        h('span', { class: 'muted small' }, [it.cves.length ? it.cves.join(', ') : 'No CVE named',
          ...(it.machines.length ? [`${c.affected} vulnerable`, `${c.verify} to check`, `${c.patched} patched`, `${c.clear} without the product`] : [])].join(' · '))],
      h('p', { class: 'small' }, d.calls[it.call]),
      it.note ? h('p', { class: 'muted small' }, it.note) : null,
      rows.length ? table(['Computer', 'Verdict', 'What matched', 'Scan'], rows) : null,
      h('div', { class: 'row attn-links' }, (it.sources || []).map(s => link(s.link, s.name)), openCaseButton(it.id)));
  };
  const render = () => {
    const hits = d.items.filter(i => ['act-now', 'affected', 'verify'].includes(i.call));
    const list = state.show === 'hits' ? hits : d.items;
    const n = call => d.items.filter(i => i.call === call).length;
    body.replaceChildren(
      h('div', { class: 'statline' },
        h('div', {}, h('span', { class: 'n' }, n('act-now')), h('span', { class: 'l' }, 'Act now')),
        h('div', {}, h('span', { class: 'n' }, n('affected')), h('span', { class: 'l' }, 'Affected')),
        h('div', {}, h('span', { class: 'n' }, n('verify')), h('span', { class: 'l' }, 'Check by hand')),
        h('div', {}, h('span', { class: 'n' }, n('clear')), h('span', { class: 'l' }, 'Not affected')),
        h('div', {}, h('span', { class: 'n' }, d.machines.length), h('span', { class: 'l' }, 'Computers checked'))),
      h('div', { class: 'row spread' }, seg([['hits', 'Only what affects us'], ['all', 'Every exploit']]),
        h('button', { class: 'btn sm', busy: 'Checking scanned computers…', done: 'Checked', onclick: async () => { d = await api('/api/admin/exposure?fresh=1'); render(); } }, 'Check again')),
      !d.machines.length ? h('p', { class: 'callout' }, 'No scans yet. Upload a scan on Get the scanner, then come back.')
        : list.length ? h('div', { class: 'stack' }, list.map(item))
          : h('p', { class: 'callout' }, `No scanned computer is affected by anything on the High impact list (${plural(d.items.length, 'exploit')} checked). That is the normal state.`));
  };
  render();
  return [head, body,
    fold({ class: 'panel', key: 'How the check works' }, [h('strong', {}, 'How the check works'), h('span', { class: 'muted small' }, 'Same official sources the bot uses')],
      h('ul', { class: 'stack tight' }, d.rules.map(r => h('li', { class: 'small' }, r)))),
    h('p', { class: 'muted small' }, `Checked ${when(d.checkedAt)} against High impact from ${when(d.highImpactCheckedAt)}; kept for 15 minutes. ${d.disruptionsSkipped ? `${plural(d.disruptionsSkipped, 'disruption')} on High impact ${d.disruptionsSkipped === 1 ? 'is a cloud outage' : 'are cloud outages'}, not software, so not matched. ` : ''}Computers are named by make and model only; HeatMap 360 never collects computer or user names.`)];
}

// ---------- Incident cases (server/cases.mjs) ----------
// One case per incident, run through the NIST SP 800-61 lifecycle: triage, a playbook checklist per type, an
// append-only timeline and evidence with SHA-256 hashes. HeatMap 360 never acts on a computer: containment links out
// to Remediation 360, Entity 360 and Federation 360. Every section starts collapsed.
const SEV_CHIP = { critical: ['bad', 'Critical'], high: ['bad', 'High'], medium: ['warn', 'Medium'], low: ['ok', 'Low'], unrated: ['unknown', 'Not rated'] };
const phaseName = (ref, id) => ref.phases.find(p => p.id === id)?.name || id;
// Open a case from a High impact item (High impact and Are we affected? pages), then go to it.
const openCaseButton = itemId => h('button', { class: 'btn sm', busy: 'Opening a case…', done: 'Case opened', onclick: async () => {
  const c = await api('/api/admin/cases', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fromItem: itemId }) });
  location.hash = `#case/${c.id}`;
} }, 'Open a case');
const field = (label, control) => h('label', { class: 'field' }, h('span', {}, label), control);
const select = (options, value) => h('select', {}, options.map(([v, l]) => h('option', { value: v, selected: v === value }, l)));

async function viewCases() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Incident cases'),
    h('p', {}, 'One record per security incident, from first report to the post-incident review: how bad it is, what has been done, who did it and when, and the evidence. HeatMap 360 only records and reports; containment and fixes happen in Remediation 360, Entity 360 and Federation 360.')));
  if (!me.elevated) return [head, gate()];
  const d = await api('/api/admin/cases');
  const ref = d.reference;
  const title = h('input', { type: 'text', maxLength: 200, required: true, placeholder: 'For example: Phishing wave on 26 November' });
  const type = select(ref.types.map(t => [t.id, t.name]), 'exploited-vuln');
  const form = h('form', { class: 'settings-form', busy: 'Opening a case…', done: 'Case opened', fail: 'Not opened', onsubmit: async () => {
    const c = await api('/api/admin/cases', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ title: title.value.trim(), type: type.value }) });
    location.hash = `#case/${c.id}`;
  } }, field('Title', title), field('Type', type), h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Open the case')));
  const open = d.cases.filter(c => c.status === 'open');
  const row = c => h('tr', {},
    h('td', {}, h('a', { href: `#case/${c.id}` }, c.title), h('div', { class: 'muted small' }, c.typeName)),
    h('td', {}, chip(...SEV_CHIP[c.severity])),
    h('td', {}, c.status === 'closed' ? chip('ok', 'Closed') : phaseName(ref, c.phase)),
    h('td', { class: 'num' }, `${c.steps.done} of ${c.steps.total}`),
    h('td', { class: 'num' }, c.evidence),
    h('td', { class: 'small' }, when(c.updatedAt)));
  return [head,
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, open.length), h('span', { class: 'l' }, 'Open')),
      h('div', {}, h('span', { class: 'n' }, open.filter(c => c.severity === 'critical' || c.severity === 'high').length), h('span', { class: 'l' }, 'Open, high or critical')),
      h('div', {}, h('span', { class: 'n' }, d.cases.length - open.length), h('span', { class: 'l' }, 'Closed'))),
    fold({ class: 'panel', key: 'Open a new case' }, [h('strong', {}, 'Open a new case'), h('span', { class: 'muted small' }, 'Or press Open a case on any item on High impact or Are we affected?, which attaches it as evidence')], form),
    fold({ class: 'panel', key: 'Cases' }, [h('strong', {}, `Cases (${d.cases.length})`), h('span', { class: 'muted small' }, 'Open cases first, then the most recently changed')],
      table(['Case', 'Severity', 'Phase', 'Playbook steps', 'Evidence', 'Last change'], d.cases.map(row), 'No cases yet.')),
    fold({ class: 'panel', key: 'How cases work' }, [h('strong', {}, 'How cases work'), h('span', { class: 'muted small' }, 'NIST SP 800-61 incident response lifecycle')],
      h('ul', { class: 'stack tight' }, ref.phases.map(p => h('li', { class: 'small' }, h('strong', {}, p.name), `: ${p.about}`)),
        h('li', { class: 'small' }, 'Severity comes from the three NIST impact categories (functional, information, recoverability). High or critical means escalate to security leadership.'),
        h('li', { class: 'small' }, 'Evidence is a snapshot with a SHA-256 hash. The page checks every hash again each time it opens, so a changed copy shows at once.'),
        h('li', { class: 'small' }, 'Closing a case needs the post-incident review and locks it. The review downloads as a PDF.')))];
}

async function viewCase(id) {
  if (!me.elevated) return [h('div', { class: 'page-head' }, h('h1', {}, 'Incident case')), gate()];
  let c = await api(`/api/admin/cases/${encodeURIComponent(id)}`);
  const ref = c.reference;
  const wrap = h('div', { class: 'stack wide-gap' });
  const send = async (path, body) => { const r = await api(`/api/admin/cases/${c.id}/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ version: c.version, ...body }) }); c = { ...r, reference: ref }; render(); };
  const act = body => send('actions', body);
  const render = () => {
    const locked = c.status === 'closed';
    const pb = c.playbook;
    const phaseIdx = ref.phases.findIndex(p => p.id === c.phase);
    const next = ref.phases[phaseIdx + 1];
    // Triage
    const sel = Object.fromEntries(Object.entries(ref.impact).map(([k, d]) => [k, select([['', 'Not rated'], ...d.options], c.triage[k] || '')]));
    const triage = h('form', { class: 'settings-form', busy: 'Saving the triage…', done: 'Saved', fail: 'Not saved', onsubmit: () => act({ action: 'triage', ...Object.fromEntries(Object.entries(sel).map(([k, el]) => [k, el.value || null])) }) },
      Object.entries(ref.impact).map(([k, d]) => field(d.label, sel[k])), locked ? null : h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save triage')));
    // Playbook checklist, by phase
    const stepRow = st => {
      const done = c.checklist[st.id];
      return h('li', { class: 'case-step' }, done ? chip('ok', 'Done') : chip('unknown', 'To do'), h('span', { class: 'small' }, st.text, done ? h('span', { class: 'muted' }, ` (${when(done.at)}, ${done.by})`) : null),
        locked ? null : h('button', { class: 'btn sm', busy: done ? 'Marking not done…' : 'Marking done…', onclick: () => act({ action: 'check', step: st.id, done: !done }) }, done ? 'Undo' : 'Mark done'));
    };
    const playbook = h('div', { class: 'stack' },
      pb.attack.length ? h('p', { class: 'small' }, h('strong', {}, 'MITRE ATT&CK: '), pb.attack.join(' · ')) : null,
      ref.phases.map(p => { const steps = pb.steps.filter(st => st.phase === p.id); return steps.length ? h('div', {}, h('h3', {}, p.name, p.id === c.phase && !locked ? ' (current)' : ''), h('ul', { class: 'stack tight case-steps' }, steps.map(stepRow))) : null; }));
    // Hand-off
    const handoff = h('ul', { class: 'stack tight' }, pb.handoff.map(x => h('li', { class: 'small' }, x.link.startsWith('#') ? h('a', { href: x.link }, x.name) : link(x.link, x.name), `: ${x.what}`)),
      h('li', { class: 'muted small' }, 'These open the other apps; each runs its own sign-in and approvals. HeatMap 360 changes nothing.'));
    // Timeline + note
    const note = h('textarea', { rows: 3, maxLength: 4000, required: true, placeholder: 'What was found or done, by whom' });
    const timeline = h('div', { class: 'stack' },
      locked ? null : h('form', { class: 'settings-form wide', busy: 'Adding the note…', done: 'Added', fail: 'Not added', onsubmit: async () => { await act({ action: 'note', text: note.value }); } },
        field('Add to the timeline', note), h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Add note'))),
      h('ol', { class: 'stack tight case-timeline' }, [...c.timeline].reverse().map(t => h('li', { class: 'small' }, h('span', { class: 'muted' }, `${when(t.at)} · ${t.by} · `), t.text))));
    // Evidence
    const evText = h('textarea', { rows: 3, maxLength: 8000, required: true, placeholder: 'Paste headers, an alert, a hash, a log line…' });
    const evLabel = h('input', { type: 'text', maxLength: 200, required: true, placeholder: 'Label, for example: Message headers' });
    const scanId = h('input', { type: 'text', maxLength: 23, pattern: '[0-9]{14}-[0-9a-f]{8}', required: true, placeholder: 'Scan ID, for example 20261125100000-aaaaaaaa' });
    const evidence = h('div', { class: 'stack' },
      table(['Evidence', 'Hash (SHA-256)', 'Added'], c.evidence.map(e => h('tr', {},
        h('td', {}, h('strong', {}, `${e.id} `), e.label, h('details', {}, h('summary', {}, 'Show the snapshot'), h('pre', { class: 'small case-json' }, JSON.stringify(e.data, null, 2)))),
        h('td', { class: 'small' }, h('code', {}, e.sha256.slice(0, 16), '…'), h('div', {}, e.intact ? chip('ok', 'Unchanged') : chip('bad', 'Changed after it was added'))),
        h('td', { class: 'small' }, when(e.at), h('div', { class: 'muted' }, e.by)))), 'No evidence yet.'),
      locked ? null : h('div', { class: 'grid-2' },
        h('form', { class: 'settings-form', busy: 'Saving the evidence…', done: 'Saved', fail: 'Not saved', onsubmit: () => send('evidence', { kind: 'note', label: evLabel.value, text: evText.value }) },
          field('Label', evLabel), field('Written evidence', evText), h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Add evidence'))),
        h('form', { class: 'settings-form', busy: 'Taking a snapshot of the scan…', done: 'Snapshot added', fail: 'Not added', onsubmit: () => send('evidence', { kind: 'scan', scanId: scanId.value.trim() }) },
          field('Snapshot of a scan', scanId), h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Add scan snapshot')))));
    // Close with the post-incident review
    const rv = { summary: h('textarea', { rows: 3, maxLength: 4000, required: true }), cause: h('textarea', { rows: 2, maxLength: 2000, required: true }), lessons: h('textarea', { rows: 3, maxLength: 4000, required: true }) };
    const review = locked
      ? h('div', { class: 'stack tight small' }, h('p', {}, h('strong', {}, 'What happened: '), c.review.summary), h('p', {}, h('strong', {}, 'Root cause: '), c.review.cause), h('p', {}, h('strong', {}, 'Lessons and improvements: '), c.review.lessons), h('p', { class: 'muted' }, `Closed ${when(c.closedAt)} by ${c.closedBy}.`))
      : h('form', { class: 'settings-form wide', busy: 'Closing the case…', done: 'Closed', fail: 'Not closed', onsubmit: () => act({ action: 'close', summary: rv.summary.value, cause: rv.cause.value, lessons: rv.lessons.value }) },
        field('What happened', rv.summary), field('Root cause', rv.cause), field('Lessons and improvements', rv.lessons),
        h('p', { class: 'muted small' }, 'Closing locks the case: no more notes, evidence or changes.'), h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Close the case')));
    const sev = c.severity;
    wrap.replaceChildren(
      h('div', { class: 'page-head' }, h('div', {}, h('p', { class: 'small' }, h('a', { href: '#cases' }, 'Incident cases')), h('h1', {}, c.title),
        h('div', { class: 'row' }, chip(...SEV_CHIP[sev.level]), chip('info', pb.name), locked ? chip('ok', 'Closed') : chip('warn', phaseName(ref, c.phase)), sev.escalate ? chip('bad', 'Escalate to security leadership') : null),
        h('p', { class: 'muted small' }, `Opened ${when(c.createdAt)} by ${c.createdBy} · last change ${when(c.updatedAt)} by ${c.updatedBy}`))),
      h('div', { class: 'row' },
        h('button', { class: 'btn', busy: 'Building PDF…', done: 'Downloaded', onclick: () => download(`/api/admin/cases/${c.id}/report.pdf`, `HeatMap360-case-${c.id}.pdf`) }, locked ? 'Download the review (PDF)' : 'Download the case (PDF)'),
        !locked && next ? h('button', { class: 'btn primary', busy: `Moving to ${next.name.toLowerCase()}…`, done: 'Moved', onclick: () => act({ action: 'phase', phase: next.id }) }, `Move to ${next.name}`) : null),
      h('ol', { class: 'case-phases' }, ref.phases.map((p, i) => h('li', { class: i < phaseIdx || locked ? 'done' : i === phaseIdx ? 'now' : '' }, h('strong', {}, p.name), h('span', { class: 'muted small' }, p.about)))),
      fold({ class: 'panel', key: 'Triage' }, [h('strong', {}, 'Triage'), h('span', { class: 'muted small' }, `Severity ${SEV_CHIP[sev.level][1].toLowerCase()}: ${sev.why}`)], triage),
      fold({ class: 'panel', key: 'Playbook' }, [h('strong', {}, `Playbook: ${pb.name}`), h('span', { class: 'muted small' }, `${pb.steps.filter(st => c.checklist[st.id]).length} of ${pb.steps.length} steps done`)], playbook),
      fold({ class: 'panel', key: 'Where to act' }, [h('strong', {}, 'Where to act'), h('span', { class: 'muted small' }, 'Containment and fixes happen in the other 360 apps')], handoff),
      fold({ class: 'panel', key: 'Timeline' }, [h('strong', {}, 'Timeline'), h('span', { class: 'muted small' }, `${c.timeline.length} entries, newest first, never edited`)], timeline),
      fold({ class: 'panel', key: 'Evidence' }, [h('strong', {}, 'Evidence'), h('span', { class: 'muted small' }, `${c.evidence.length} item${c.evidence.length === 1 ? '' : 's'}${c.evidence.some(e => !e.intact) ? ', one or more CHANGED' : ', hashes checked'}`)], evidence),
      fold({ class: 'panel', key: 'Post-incident review' }, [h('strong', {}, 'Post-incident review'), h('span', { class: 'muted small' }, locked ? 'Written; the case is closed' : 'Write it to close the case')], review));
  };
  render();
  return wrap;
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
      content = [foldBar(), h('div', { class: 'grid-2' }, shown.map(a => {
        const items = a.items.filter(inWindow);
        return fold({ class: 'panel svc', key: `bsky:${a.id}` },
          [h('span', { class: 'svc-title' }, h('strong', {}, a.rank ? `${a.rank}. ${a.name}` : a.name), a.status === 'checked' ? chip('info', plural(items.length, 'post')) : chip('unknown', 'Not checked')),
            h('span', { class: 'muted small' }, `${a.company} · @${a.handle}${a.rank ? '' : ' · official, has not posted yet'}`)],
          h('div', { class: 'stack svc-body' },
            a.error ? h('p', { class: 'muted small' }, a.error)
              : items.length ? h('ul', { class: 'headlines' }, items.map(it => post(it))) : h('p', { class: 'muted small' }, 'Nothing in this time window.'),
            h('p', { class: 'small' }, link(a.page, `Open @${a.handle}`))));
      }))];
    }
    body.replaceChildren(controls, ...[content].flat());
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
    ...PEN_TESTS.map(p => panel(p.title, `${p.source} · ${p.author} · ${p.date} · ${p.target}`,
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

// ---------- AD posture (PingCastle) ----------
// PingCastle health checks of Active Directory, run weekly by a scheduled task on the computer that hosts HeatMap 360
// (tools/adposture/Invoke-PingCastleScan.ps1). The reports stay in a local folder; this page only reads them.
const AD_AREAS = [['staleObjects', 'StaleObjects', 'Stale objects'], ['privilegedAccounts', 'PrivilegedAccounts', 'Privileged accounts'], ['trusts', 'Trusts', 'Trusts'], ['anomalies', 'Anomalies', 'Anomalies']];
const AD_AREA_NAME = Object.fromEntries(AD_AREAS.map(([, cat, name]) => [cat, name]));
const svg = (tag, attrs, ...kids) => {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k instanceof Node ? k : String(k));
  return e;
};
const day = iso => new Date(iso).toLocaleDateString();
// Change since the previous scan, in words. PingCastle scores: lower is better.
const adChange = d => (d == null ? 'First scan' : d === 0 ? 'No change' : d < 0 ? `${-d} better` : `${d} worse`);
// One line, the overall score over time: 0 to 100 on one axis, a dot per scan with its date and score on hover.
function adTrend(list) {
  const W = 640, H = 220, L = 34, R = 12, T = 12, B = 28;
  const t0 = Date.parse(list[0].generatedAt), t1 = Date.parse(list.at(-1).generatedAt);
  const x = s => (list.length === 1 || t1 === t0 ? L + (W - L - R) / 2 : L + ((Date.parse(s.generatedAt) - t0) / (t1 - t0)) * (W - L - R));
  const y = v => T + (1 - v / 100) * (H - T - B);
  const grid = [0, 25, 50, 75, 100].map(v => [svg('line', { class: 'trend-grid', x1: L, x2: W - R, y1: y(v), y2: y(v) }), svg('text', { class: 'trend-tick', x: L - 6, y: y(v) + 4, 'text-anchor': 'end' }, v)]);
  const ends = [list[0], list.at(-1)].filter((s, i, a) => i === 0 || s !== a[0]).map((s, i) => svg('text', { class: 'trend-tick', x: x(s), y: H - 8, 'text-anchor': list.length === 1 ? 'middle' : i ? 'end' : 'start' }, day(s.generatedAt)));
  const line = list.length > 1 ? svg('polyline', { class: 'trend-line', points: list.map(s => `${x(s)},${y(s.scores.global)}`).join(' ') }) : null;
  const dots = list.map(s => svg('g', { class: 'trend-point' },
    svg('circle', { class: 'trend-hit', cx: x(s), cy: y(s.scores.global), r: 12 }),
    svg('circle', { class: 'trend-dot', cx: x(s), cy: y(s.scores.global), r: 5 }),
    svg('title', {}, `${when(s.generatedAt)}: score ${s.scores.global}`)));
  return h('div', { class: 'trend' }, svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Overall PingCastle score over time, from ${list[0].scores.global} to ${list.at(-1).scores.global}. Lower is better.` }, grid, ends, line, dots));
}
const adReportButton = s => (s.hasReport
  ? h('button', { class: 'btn sm', busy: 'Downloading report…', done: 'Downloaded', fail: 'Download failed', onclick: () => download(`/api/admin/adposture/${s.id}/report.html`, `PingCastle-${s.domain}-${s.id}.html`) }, 'Report')
  : h('button', { class: 'btn sm', disabled: true, title: 'PingCastle saved no HTML report for this scan' }, 'No report'));
function adDomainView(list) {
  const latest = list.at(-1), prev = list.length > 1 ? list.at(-2) : null;
  const delta = k => (prev ? latest.scores[k] - prev.scores[k] : null);
  const before = new Set((prev?.rules || []).map(r => r.id)), now = new Set(latest.rules.map(r => r.id));
  const fixed = prev?.rules ? prev.rules.filter(r => !now.has(r.id)) : [];
  const fresh = prev?.rules ? latest.rules.filter(r => !before.has(r.id)) : [];
  return [
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, latest.scores.global), h('span', { class: 'l' }, 'Score out of 100, lower is better')),
      h('div', {}, h('span', { class: 'n' }, adChange(delta('global'))), h('span', { class: 'l' }, prev ? `Since ${day(prev.generatedAt)}` : 'Change since the last scan')),
      h('div', {}, h('span', { class: 'n' }, latest.rules.length), h('span', { class: 'l' }, `Rules triggered${prev?.rules ? `, ${fresh.length} new, ${fixed.length} fixed` : ''}`)),
      h('div', {}, h('span', { class: 'n' }, latest.maturityLevel ? `${latest.maturityLevel} of 5` : '–'), h('span', { class: 'l' }, 'Maturity level, higher is better'))),
    h('div', { class: 'grid-2' },
      panel('Overall score over time', `${list.length} scan${list.length > 1 ? 's' : ''}, hover a dot for its score`, adTrend(list)),
      panel('Score by area', `Scanned ${when(latest.generatedAt)}${latest.engineVersion ? ` · PingCastle ${latest.engineVersion}` : ''}`,
        h('dl', { class: 'kv' }, AD_AREAS.map(([k, , name]) => [h('dt', {}, name), h('dd', {}, h('strong', {}, latest.scores[k]), h('span', { class: 'muted small' }, ` · ${adChange(delta(k))}`))])),
        h('p', { class: 'muted small' }, 'PingCastle scores each area from 0 to 100 by adding up the points of the rules it triggers. The overall score is the worst area.'))),
    panel('What PingCastle found', 'Newest scan, most points first. PingCastle’s report explains each rule and how to fix it.',
      table(['Points', 'Area', 'Rule', 'Why'], latest.rules.map(r => h('tr', {},
        h('td', { class: 'nowrap' }, h('strong', {}, r.points)),
        h('td', { class: 'nowrap' }, AD_AREA_NAME[r.category] || r.category),
        h('td', {}, h('code', {}, r.id), fresh.includes(r) ? [' ', chip('warn', 'New')] : null),
        h('td', {}, r.rationale))), 'PingCastle triggered no rules. Nothing to show.'),
      fixed.length ? h('div', { class: 'stack tight' }, h('h3', {}, `Fixed since ${day(prev.generatedAt)}`), h('ul', {}, fixed.map(r => h('li', {}, h('code', {}, r.id), ` (${AD_AREA_NAME[r.category] || r.category}): ${r.rationale}`)))) : null),
    panel('Every scan', 'Newest first',
      table(['Scanned', 'Score', ...AD_AREAS.map(([, , name]) => name), 'Rules', 'PingCastle report'], [...list].reverse().map(s => h('tr', {},
        h('td', { class: 'nowrap' }, when(s.generatedAt)), h('td', {}, h('strong', {}, s.scores.global)),
        AD_AREAS.map(([k]) => h('td', {}, s.scores[k])), h('td', {}, s.ruleCount), h('td', {}, adReportButton(s)))))),
  ];
}
async function viewAdPosture() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'AD posture'),
    h('p', {}, 'Active Directory risk from PingCastle health checks, run every week by a scheduled task on the computer that hosts HeatMap 360. Scores run from 0 to 100; lower is better.')));
  if (!me.elevated) return [head, gate()];
  const data = await api('/api/admin/adposture');
  const setupLink = h('a', { class: 'btn primary', href: '#setup' }, 'Set up PingCastle scans');
  if (!data.configured) return [head, h('div', { class: 'empty' }, h('h2', {}, 'Not available on this copy'),
    h('p', { class: 'muted' }, 'AD posture reports name real accounts and servers, so they stay on the computer that runs the scans. This page works on the local copy of HeatMap 360 on that computer.'), setupLink)];
  if (!data.scans.length) return [head, h('div', { class: 'empty' }, h('h2', {}, 'No PingCastle scans yet'),
    h('p', { class: 'muted' }, data.folderFound ? 'The AD posture folder is there but holds no PingCastle reports yet. The first one appears after the scheduled task has run.' : 'The AD posture folder has not been created yet. It appears with the first PingCastle scan.'),
    data.skipped ? h('p', { class: 'callout warn' }, `${data.skipped} file${data.skipped > 1 ? 's' : ''} in the folder could not be read as a PingCastle summary and ${data.skipped > 1 ? 'were' : 'was'} skipped.`) : null, setupLink)];
  const domains = [...new Set(data.scans.map(s => s.domain))].sort();
  let domain = data.scans.at(-1).domain;
  const body = h('div', { class: 'stack' });
  const render = () => body.replaceChildren(...adDomainView(data.scans.filter(s => s.domain === domain)).filter(Boolean));
  render();
  const picker = domains.length > 1 ? h('label', { class: 'field inline' }, h('span', {}, 'Domain '),
    h('select', { onchange: e => { domain = e.target.value; activity.flash(`Showing ${domain}…`); render(); } }, domains.map(d => h('option', { value: d, selected: d === domain }, d)))) : null;
  return [head,
    data.skipped ? h('p', { class: 'callout warn' }, `${data.skipped} file${data.skipped > 1 ? 's' : ''} in the AD posture folder could not be read as a PingCastle summary and ${data.skipped > 1 ? 'were' : 'was'} skipped.`) : null,
    picker, body,
    h('p', { class: 'muted small' }, 'HeatMap 360 only reports. Fix what PingCastle finds with your normal tools. These reports name real accounts and servers: they stay on this computer and are never uploaded or published.')];
}

// ---------- Attack paths (BloodHound CE) ----------
// A weekly BloodHound collection of Active Directory (tools/bloodhound/Invoke-BloodHoundScan.ps1) and a fixed set of
// questions asked of the local BloodHound CE. The summaries stay in a local folder; this page only reads them.
const BH_URL = 'http://localhost:3461';
const AP_FINDINGS = [
  ['pathToDomainAdmins', 'Path to Domain Admins', 'Enabled users who are not Domain Admins but can become one through group membership, permissions or sessions. Each one is an attack path. Open BloodHound to see it.', 'bad'],
  ['dcsync', 'Can DCSync', 'Accounts that can copy every password hash from the domain, apart from domain controllers and the built-in admin groups. Some sync tools need this; anything else should not have it.', 'bad'],
  ['kerberoastable', 'Kerberoastable users', 'Enabled user accounts with a service principal name. Any domain user can request a ticket for them and guess the password offline, so these need long random passwords or a gMSA.', 'warn'],
  ['asrepRoastable', 'AS-REP roastable users', 'Enabled users that do not require Kerberos pre-authentication. Anyone can request data for them and guess the password offline.', 'warn'],
  ['unconstrainedDelegation', 'Unconstrained delegation', 'Computers other than domain controllers that keep the Kerberos tickets of everyone who signs in to them.', 'warn'],
  ['domainAdminMembers', 'Domain Admins members', 'Users in Domain Admins, directly or through nested groups. Keep this list short.', 'info'],
  ['passwordNeverExpires', 'Password never expires', 'Enabled users whose password never expires. Fine for long random service passwords, risky for people.', 'info'],
];
function apDomainView(list) {
  const latest = list.at(-1), prev = list.length > 1 ? list.at(-2) : null;
  const find = (s, id) => s?.findings.find(f => f.id === id);
  const urgent = AP_FINDINGS.filter(([, , , tone]) => tone === 'bad').reduce((n, [id]) => n + (find(latest, id)?.count || 0), 0);
  return [
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, find(latest, 'pathToDomainAdmins')?.count ?? '–'), h('span', { class: 'l' }, 'Users with a path to Domain Admins')),
      h('div', {}, h('span', { class: 'n' }, urgent), h('span', { class: 'l' }, 'Accounts in the two most serious findings')),
      h('div', {}, h('span', { class: 'n' }, latest.counts.users), h('span', { class: 'l' }, `Users, ${latest.counts.groups} groups, ${latest.counts.computers} computers`)),
      h('div', {}, h('span', { class: 'n' }, day(latest.generatedAt)), h('span', { class: 'l' }, `Last collected${latest.collection ? ` (${latest.collection})` : ''}`))),
    panel('What BloodHound found', `Newest collection, ${when(latest.generatedAt)}${prev ? `, compared with ${day(prev.generatedAt)}` : ''}`,
      table(['Finding', 'Count', 'Change', 'Accounts and computers'], AP_FINDINGS.map(([id, title, why, tone]) => {
        const f = find(latest, id) || { count: 0, items: [] };
        const before = new Set(find(prev, id)?.items || []);
        const d = prev && find(prev, id) ? f.count - find(prev, id).count : null;
        return h('tr', {},
          h('td', {}, h('strong', {}, title), h('div', { class: 'muted small' }, why)),
          h('td', { class: 'nowrap' }, f.count ? chip(tone, String(f.count)) : h('span', { class: 'muted' }, '0')),
          h('td', { class: 'nowrap' }, d == null ? h('span', { class: 'muted' }, prev ? '–' : 'First scan') : d === 0 ? 'No change' : d > 0 ? `${d} more` : `${-d} fewer`),
          h('td', {}, f.items.length ? h('ul', { class: 'plain' }, f.items.map(i => h('li', {}, h('code', {}, i), prev?.findings && find(prev, id) && !before.has(i) ? [' ', chip('warn', 'New')] : null)))
            : h('span', { class: 'muted' }, 'None'),
          f.count > f.items.length ? h('p', { class: 'muted small' }, `First ${f.items.length} of ${f.count} shown.`) : null));
      }))),
    panel('Every collection', 'Newest first',
      table(['Collected', 'Path to Domain Admins', 'Can DCSync', 'Kerberoastable', 'AS-REP roastable', 'Users'], [...list].reverse().map(s => h('tr', {},
        h('td', { class: 'nowrap' }, when(s.generatedAt)),
        ['pathToDomainAdmins', 'dcsync', 'kerberoastable', 'asrepRoastable'].map(id => h('td', {}, find(s, id)?.count ?? '–')),
        h('td', {}, s.counts.users))))),
  ];
}
// AD Miner turns the same BloodHound data into a scored risk report (tools/bloodhound/Invoke-ADMinerReport.ps1). The
// report is a folder of HTML pages with their own scripts, so it is a zip to download, never shown inside this page.
const fileSize = bytes => (bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`);
const amDownload = (r, label, cls = 'btn sm') => (r.bytes
  ? h('button', { class: cls, busy: 'Downloading report…', done: 'Downloaded', fail: 'Download failed', onclick: () => download(`/api/admin/attackpaths/adminer/${r.id}/report.zip`, `ADMiner-${r.domains[0]}-${r.id}.zip`) }, label)
  : h('button', { class: cls, disabled: true, title: 'The zip for this report is missing from the folder' }, 'No report file'));
// AD Miner's own words for its five colours, worst first, and the names of its areas.
const AM_RATINGS = [['red', 'Immediate risk', 'bad'], ['orange', 'Potential risk', 'warn'], ['yellow', 'Minor risk', 'info'], ['green', 'Handled', 'ok'], ['grey', 'Not evaluated', 'unknown']];
const AM_AREAS = { passwords: 'Passwords', kerberos: 'Kerberos', permissions: 'Permissions', misc: 'Other', az_permissions: 'Entra permissions', az_passwords: 'Entra passwords', az_misc: 'Entra, other', ms_graph: 'Microsoft Graph' };
function amPanel(data) {
  const reports = data.reports || [], latest = reports[0];
  const skipped = data.skippedReports ? h('p', { class: 'callout warn' }, `${data.skippedReports} file${data.skippedReports > 1 ? 's' : ''} in the AD Miner folder could not be read as report details and ${data.skippedReports > 1 ? 'were' : 'was'} skipped.`) : null;
  const intro = h('p', {}, 'AD Miner reads the graph BloodHound holds and rates what it finds: paths to Domain Admins, risky permissions, Kerberos and password weaknesses, old accounts and computers. It works on a copy and never contacts Active Directory. Each report is a zip of HTML pages: unzip it and open ', h('code', {}, 'index.html'), '.');
  if (!latest) return panel('AD Miner report', 'A scored risk report built from the same BloodHound data', intro, skipped,
    h('p', { class: 'muted' }, 'No AD Miner report yet. The ', h('a', { href: '#setup' }, 'How to set up'), ' page shows the one command that builds it.'));
  const nameOf = id => latest.controls?.find(c => c.id === id)?.name || id;
  return panel('AD Miner report', 'A scored risk report built from the same BloodHound data', intro, skipped,
    h('div', { class: 'statline' }, AM_RATINGS.map(([rating, label]) => h('div', {}, h('span', { class: 'n' }, latest.ratings[rating]), h('span', { class: 'l' }, label)))),
    h('p', { class: 'muted small' }, `Newest report, built ${when(latest.generatedAt)}${latest.dataDate ? ` from data AD Miner dates ${latest.dataDate}` : ''}${latest.objects ? `, ${latest.objects} objects` : ''}. The numbers count AD Miner’s checks, not accounts.`),
    latest.failedRequests.length ? h('p', { class: 'callout warn' }, `${latest.failedRequests.length} of AD Miner’s database questions failed while this report was built, so parts of it may be missing. Build it again; if it happens again, run the script with -Verbose to see why.`) : null,
    latest.failedControls.length ? h('p', { class: 'callout' }, `AD Miner’s log reports ${latest.failedControls.length === 1 ? 'one check' : `${latest.failedControls.length} checks`} failing on this data: ${latest.failedControls.map(nameOf).join(', ')}. The report shows a failed check as not evaluated.`) : null,
    table(['Rating', 'Area', 'What AD Miner checked'], (latest.controls || []).map(c => {
      const [, label, tone] = AM_RATINGS.find(([rating]) => rating === c.rating);
      return h('tr', {}, h('td', { class: 'nowrap' }, chip(tone, label)), h('td', { class: 'nowrap' }, AM_AREAS[c.area] || c.area || '–'), h('td', {}, c.name));
    }), 'AD Miner rated every check as handled.'),
    h('p', { class: 'muted small' }, 'Handled means AD Miner found nothing in the data it was given. Checks that need data the collector did not gather show as handled too, so read the report for what each check looked at.'),
    h('h3', {}, 'Every report'),
    table(['Built', 'Domains', 'AD Miner', 'Immediate', 'Potential', 'Minor', 'Files', 'Size', 'Report'], reports.map(r => h('tr', {},
      h('td', { class: 'nowrap' }, when(r.generatedAt)), h('td', {}, r.domains.join(', ')), h('td', { class: 'nowrap' }, r.version),
      ['red', 'orange', 'yellow'].map(rating => h('td', {}, r.ratings[rating])),
      h('td', {}, r.files), h('td', { class: 'nowrap' }, r.bytes ? fileSize(r.bytes) : '–'), h('td', {}, amDownload(r, 'Download'))))),
    h('p', { class: 'muted small' }, 'A report shows the data as BloodHound held it when the report was built. It names real accounts and computers: keep the zip on this computer.'));
}
async function viewAttackPaths() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Attack paths'),
    h('p', {}, 'Who can take over Active Directory, from a weekly BloodHound collection on the computer that hosts HeatMap 360. BloodHound itself shows each path as a graph.')));
  if (!me.elevated) return [head, gate()];
  const data = await api('/api/admin/attackpaths');
  const setupLink = h('a', { class: 'btn primary', href: '#setup' }, 'Set up BloodHound');
  const bhLink = h('a', { class: 'btn', href: BH_URL, target: '_blank', rel: 'noopener noreferrer', busy: 'Opening BloodHound…', done: 'Opened in a new tab' }, 'Open BloodHound');
  if (!data.configured) return [head, h('div', { class: 'empty' }, h('h2', {}, 'Not available on this copy'),
    h('p', { class: 'muted' }, 'Attack path summaries name real accounts and computers, so they stay on the computer that runs BloodHound. This page works on the local copy of HeatMap 360 on that computer.'), setupLink)];
  const newest = (data.reports || []).find(r => r.bytes);
  if (!data.scans.length) return [head, h('div', { class: 'empty' }, h('h2', {}, 'No BloodHound collections yet'),
    h('p', { class: 'muted' }, data.folderFound ? 'The attack paths folder is there but holds no summaries yet. The first one appears after the scheduled task has run.' : 'The attack paths folder has not been created yet. It appears with the first collection.'),
    data.skipped ? h('p', { class: 'callout warn' }, `${data.skipped} file${data.skipped > 1 ? 's' : ''} in the folder could not be read as a BloodHound summary and ${data.skipped > 1 ? 'were' : 'was'} skipped.`) : null,
    h('div', { class: 'row' }, setupLink, bhLink)),
    data.reports?.length || data.skippedReports ? amPanel(data) : null];
  const domains = [...new Set(data.scans.map(s => s.domain))].sort();
  let domain = data.scans.at(-1).domain;
  const body = h('div', { class: 'stack' });
  const render = () => body.replaceChildren(...apDomainView(data.scans.filter(s => s.domain === domain)).filter(Boolean));
  render();
  const picker = domains.length > 1 ? h('label', { class: 'field inline' }, h('span', {}, 'Domain '),
    h('select', { onchange: e => { domain = e.target.value; activity.flash(`Showing ${domain}…`); render(); } }, domains.map(d => h('option', { value: d, selected: d === domain }, d)))) : null;
  return [head,
    data.skipped ? h('p', { class: 'callout warn' }, `${data.skipped} file${data.skipped > 1 ? 's' : ''} in the attack paths folder could not be read as a BloodHound summary and ${data.skipped > 1 ? 'were' : 'was'} skipped.`) : null,
    h('div', { class: 'row' }, picker, bhLink, newest ? amDownload(newest, 'Download AD Miner report', 'btn') : null), body, amPanel(data),
    h('p', { class: 'muted small' }, 'HeatMap 360 only reports. Fix what BloodHound and AD Miner find with your normal tools. These summaries and reports name real accounts and computers: they stay on this computer and are never uploaded or published.')];
}

// ---------- Entra posture (Maester) ----------
// Maester's Entra ID and Microsoft 365 checks, run weekly in a container by a scheduled task on the computer that hosts
// HeatMap 360 (tools/entraposture/Invoke-MaesterScan.ps1). The results stay in a local folder; this page only reads them.
const EP_SEVERITY = ['Critical', 'High', 'Medium', 'Low', 'Info', ''];
const EP_TONE = { Critical: 'bad', High: 'bad', Medium: 'warn', Low: 'info', Info: 'unknown', '': 'unknown' };
const EP_RESULT = { Failed: ['bad', 'Failed'], Error: ['warn', 'Error'], Investigate: ['info', 'Investigate'] };
const EP_OPEN = new Set(Object.keys(EP_RESULT));
// Change in pass rate since the previous run, in words. Higher is better.
const epChange = d => (d == null ? 'First run' : d === 0 ? 'No change' : d > 0 ? `${d} points better` : `${-d} points worse`);
// One line, the pass rate over time: 0 to 100% on one axis, a dot per run with its date and rate on hover.
function epTrend(list, what = 'Maester checks') {
  const W = 640, H = 220, L = 40, R = 12, T = 12, B = 28;
  const pts = list.filter(s => s.passRate != null);
  if (!pts.length) return h('p', { class: 'muted' }, 'No checks have run yet, so there is no pass rate to chart.');
  const t0 = Date.parse(pts[0].generatedAt), t1 = Date.parse(pts.at(-1).generatedAt);
  const x = s => (pts.length === 1 || t1 === t0 ? L + (W - L - R) / 2 : L + ((Date.parse(s.generatedAt) - t0) / (t1 - t0)) * (W - L - R));
  const y = v => T + (1 - v / 100) * (H - T - B);
  const grid = [0, 25, 50, 75, 100].map(v => [svg('line', { class: 'trend-grid', x1: L, x2: W - R, y1: y(v), y2: y(v) }), svg('text', { class: 'trend-tick', x: L - 6, y: y(v) + 4, 'text-anchor': 'end' }, `${v}%`)]);
  const ends = [pts[0], pts.at(-1)].filter((s, i, a) => i === 0 || s !== a[0]).map((s, i) => svg('text', { class: 'trend-tick', x: x(s), y: H - 8, 'text-anchor': pts.length === 1 ? 'middle' : i ? 'end' : 'start' }, day(s.generatedAt)));
  const line = pts.length > 1 ? svg('polyline', { class: 'trend-line', points: pts.map(s => `${x(s)},${y(s.passRate)}`).join(' ') }) : null;
  const dots = pts.map(s => svg('g', { class: 'trend-point' },
    svg('circle', { class: 'trend-hit', cx: x(s), cy: y(s.passRate), r: 12 }),
    svg('circle', { class: 'trend-dot', cx: x(s), cy: y(s.passRate), r: 5 }),
    svg('title', {}, `${when(s.generatedAt)}: ${s.passRate}% passed (${s.counts.passed} of ${s.counts.passed + s.counts.failed})`)));
  return h('div', { class: 'trend' }, svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Share of ${what} passed over time, from ${pts[0].passRate}% to ${pts.at(-1).passRate}%. Higher is better.` }, grid, ends, line, dots));
}
const epReportButton = s => (s.hasReport
  ? h('button', { class: 'btn sm', busy: 'Downloading report…', done: 'Downloaded', fail: 'Download failed', onclick: () => download(`/api/admin/entraposture/${s.id}/report.html`, `Maester-${s.id}.html`) }, 'Report')
  : h('button', { class: 'btn sm', disabled: true, title: 'Maester saved no HTML report for this run' }, 'No report'));
const epBySeverity = (a, b) => EP_SEVERITY.indexOf(a.severity) - EP_SEVERITY.indexOf(b.severity) || a.id.localeCompare(b.id, undefined, { numeric: true });
function epTenantView(list) {
  const latest = list.at(-1), prev = list.length > 1 ? list.at(-2) : null;
  const open = latest.tests.filter(t => EP_OPEN.has(t.result)).sort(epBySeverity);
  const before = new Set((prev?.tests || []).filter(t => EP_OPEN.has(t.result)).map(t => t.id));
  const now = new Set(open.map(t => t.id));
  const fresh = prev?.tests ? open.filter(t => !before.has(t.id)) : [];
  const fixed = prev?.tests ? prev.tests.filter(t => EP_OPEN.has(t.result) && !now.has(t.id) && latest.tests.some(n => n.id === t.id && n.result === 'Passed')).sort(epBySeverity) : [];
  const delta = prev && prev.passRate != null && latest.passRate != null ? latest.passRate - prev.passRate : null;
  const failedBy = sev => latest.tests.filter(t => t.result === 'Failed' && t.severity === sev).length;
  const c = latest.counts;
  return [
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, latest.passRate == null ? '–' : `${latest.passRate}%`), h('span', { class: 'l' }, 'Of the checks that ran, passed')),
      h('div', {}, h('span', { class: 'n' }, epChange(delta)), h('span', { class: 'l' }, prev ? `Since ${day(prev.generatedAt)}` : 'Change since the last run')),
      h('div', {}, h('span', { class: 'n' }, c.failed), h('span', { class: 'l' }, `Failed${prev?.tests ? `, ${fresh.length} new, ${fixed.length} fixed` : ''}`)),
      h('div', {}, h('span', { class: 'n' }, failedBy('Critical') + failedBy('High')), h('span', { class: 'l' }, 'Failed with critical or high severity'))),
    h('div', { class: 'grid-2' },
      panel('Pass rate over time', `${list.length} run${list.length > 1 ? 's' : ''}, hover a dot for its rate`, epTrend(list)),
      panel('Newest run', `${when(latest.generatedAt)}${latest.engineVersion ? ` · Maester ${latest.engineVersion}` : ''}`,
        h('dl', { class: 'kv' },
          h('dt', {}, 'Checks'), h('dd', {}, h('strong', {}, c.total), h('span', { class: 'muted small' }, ` · ${c.passed} passed, ${c.failed} failed, ${c.skipped + c.notRun} skipped`)),
          c.error || c.investigate ? [h('dt', {}, 'Need a look'), h('dd', {}, `${c.error} could not be checked, ${c.investigate} to investigate`)] : null,
          h('dt', {}, 'Failed by severity'), h('dd', {}, ['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => [chip(EP_TONE[s], `${s} ${failedBy(s)}`), ' ']))),
        h('p', { class: 'muted small' }, 'Skipped checks need a license, a service or a permission this run did not have, such as Exchange Online or Teams. The pass rate counts only checks that passed or failed.'))),
    panel('What needs attention', 'Newest run, most severe first. Maester’s report shows the details and how to fix each one.',
      table(['Severity', 'Check', 'Area', 'Result'], open.map(t => h('tr', {},
        h('td', { class: 'nowrap' }, t.severity ? chip(EP_TONE[t.severity], t.severity) : h('span', { class: 'muted' }, '–')),
        h('td', {}, h('code', {}, t.id), ' ', t.helpUrl ? link(t.helpUrl, t.title) : t.title, fresh.includes(t) ? [' ', chip('warn', 'New')] : null),
        h('td', {}, t.block),
        h('td', { class: 'nowrap' }, chip(...EP_RESULT[t.result])))), 'Every check that ran passed. Nothing to show.'),
      fixed.length ? h('div', { class: 'stack tight' }, h('h3', {}, `Fixed since ${day(prev.generatedAt)}`), h('ul', {}, fixed.map(t => h('li', {}, h('code', {}, t.id), ` ${t.title}`)))) : null),
    panel('Every run', 'Newest first',
      table(['Run', 'Pass rate', 'Passed', 'Failed', 'Skipped', 'Maester report'], [...list].reverse().map(s => h('tr', {},
        h('td', { class: 'nowrap' }, when(s.generatedAt)), h('td', {}, h('strong', {}, s.passRate == null ? '–' : `${s.passRate}%`)),
        h('td', {}, s.counts.passed), h('td', {}, s.counts.failed), h('td', {}, s.counts.skipped + s.counts.notRun), h('td', {}, epReportButton(s)))))),
  ];
}
async function viewEntraPosture() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Entra posture'),
    h('p', {}, 'Entra ID and Microsoft 365 security checks from Maester, run every week in a container on the computer that hosts HeatMap 360. Read-only: Maester signs in with an app that can only read.')));
  if (!me.elevated) return [head, gate()];
  const data = await api('/api/admin/entraposture');
  const setupLink = h('a', { class: 'btn primary', href: '#setup' }, 'Set up Maester checks');
  if (!data.configured) return [head, h('div', { class: 'empty' }, h('h2', {}, 'Not available on this copy'),
    h('p', { class: 'muted' }, 'Maester reports name real users, groups and policies, so they stay on the computer that runs the checks. This page works on the local copy of HeatMap 360 on that computer.'), setupLink)];
  const skippedNote = data.skipped ? h('p', { class: 'callout warn' }, `${data.skipped} file${data.skipped > 1 ? 's' : ''} in the Entra posture folder could not be read as a Maester summary and ${data.skipped > 1 ? 'were' : 'was'} skipped.`) : null;
  if (!data.scans.length) return [head, h('div', { class: 'empty' }, h('h2', {}, 'No Maester runs yet'),
    h('p', { class: 'muted' }, data.folderFound ? 'The Entra posture folder is there but holds no Maester results yet. The first one appears after the scheduled task has run.' : 'The Entra posture folder has not been created yet. It appears with the first Maester run.'),
    skippedNote, setupLink)];
  const tenants = [...new Map(data.scans.map(s => [s.tenant, s.tenantName])).entries()];
  let tenant = data.scans.at(-1).tenant;
  const body = h('div', { class: 'stack' });
  const render = () => body.replaceChildren(...epTenantView(data.scans.filter(s => s.tenant === tenant)).filter(Boolean));
  render();
  const picker = tenants.length > 1 ? h('label', { class: 'field inline' }, h('span', {}, 'Tenant '),
    h('select', { onchange: e => { tenant = e.target.value; activity.flash(`Showing ${e.target.selectedOptions[0].text}…`); render(); } }, tenants.map(([id, name]) => h('option', { value: id, selected: id === tenant }, name)))) : null;
  return [head, skippedNote, picker, body,
    h('p', { class: 'muted small' }, 'HeatMap 360 only reports. Fix what Maester finds in the Entra and Microsoft 365 admin centers. These reports name real users, groups and policies: they stay on this computer and are never uploaded or published.')];
}

// ---------- M365 & Azure posture (Monkey365) ----------
// Monkey365's CIS benchmark checks of Exchange Online, Teams, Purview and Azure, run weekly in a container by a scheduled
// task on the computer that hosts HeatMap 360 (tools/m365posture/Invoke-Monkey365Scan.ps1). Entra ID stays on the Entra
// posture page (Maester), so the two pages never show the same check. The results stay in a local folder.
const MP_STATUS = { Failed: ['bad', 'Failed'], Manual: ['info', 'Check by hand'] };
const MP_OPEN = new Set(Object.keys(MP_STATUS));
const MP_AREA = { ExchangeOnline: 'Exchange Online', MicrosoftTeams: 'Teams', Purview: 'Purview', Microsoft365: 'Microsoft 365', Azure: 'Azure', SharePointOnline: 'SharePoint Online' };
const mpArea = a => MP_AREA[a] || a;
const MP_REPORT = { microsoft365: 'Microsoft 365 report', azure: 'Azure report' };
const mpReportButtons = s => (s.reports.length
  ? s.reports.map(a => [h('button', { class: 'btn sm', busy: 'Downloading report…', done: 'Downloaded', fail: 'Download failed', onclick: () => download(`/api/admin/m365posture/${s.id}/${a}.html`, `Monkey365-${s.id}-${a}.html`) }, MP_REPORT[a]), ' '])
  : h('button', { class: 'btn sm', disabled: true, title: 'Monkey365 saved no HTML report for this run' }, 'No report'));
const mpBySeverity = (a, b) => EP_SEVERITY.indexOf(a.severity) - EP_SEVERITY.indexOf(b.severity) || (a.status === b.status ? 0 : a.status === 'Failed' ? -1 : 1) || a.id.localeCompare(b.id, undefined, { numeric: true });
function mpTenantView(list, state, rerender) {
  const latest = list.at(-1), prev = list.length > 1 ? list.at(-2) : null;
  const key = r => `${r.instance}:${r.id}`;
  const areas = [...new Set(latest.rules.map(r => r.area))].sort((a, b) => mpArea(a).localeCompare(mpArea(b)));
  const all = latest.rules.filter(r => MP_OPEN.has(r.status)).sort(mpBySeverity);
  const open = state.area ? all.filter(r => r.area === state.area) : all;
  const before = new Set((prev?.rules || []).filter(r => r.status === 'Failed').map(key));
  const now = new Set(latest.rules.filter(r => r.status === 'Failed').map(key));
  const fresh = prev?.rules ? latest.rules.filter(r => r.status === 'Failed' && !before.has(key(r))) : [];
  const fixed = prev?.rules ? prev.rules.filter(r => r.status === 'Failed' && !now.has(key(r)) && latest.rules.some(n => key(n) === key(r) && n.status === 'Passed')).sort(mpBySeverity) : [];
  const delta = prev && prev.passRate != null && latest.passRate != null ? latest.passRate - prev.passRate : null;
  const failedBy = sev => latest.rules.filter(r => r.status === 'Failed' && r.severity === sev).length;
  const c = latest.counts;
  const byArea = areas.map(a => {
    const rs = latest.rules.filter(r => r.area === a);
    const n = st => rs.filter(r => r.status === st).length;
    return h('tr', {}, h('td', {}, mpArea(a)), h('td', {}, h('strong', {}, (n('Passed') + n('Failed')) ? `${Math.round(n('Passed') / (n('Passed') + n('Failed')) * 100)}%` : '–')),
      h('td', {}, n('Passed')), h('td', {}, n('Failed')), h('td', {}, n('Manual')));
  });
  const areaPicker = areas.length > 1 ? h('label', { class: 'field inline' }, h('span', {}, 'Area '),
    h('select', { onchange: e => { state.area = e.target.value; activity.flash(`Showing ${e.target.selectedOptions[0].text}…`); rerender(); } },
      h('option', { value: '', selected: !state.area }, 'Every area'), areas.map(a => h('option', { value: a, selected: a === state.area }, mpArea(a))))) : null;
  return [
    h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, latest.passRate == null ? '–' : `${latest.passRate}%`), h('span', { class: 'l' }, 'Of the rules decided, passed')),
      h('div', {}, h('span', { class: 'n' }, epChange(delta)), h('span', { class: 'l' }, prev ? `Since ${day(prev.generatedAt)}` : 'Change since the last run')),
      h('div', {}, h('span', { class: 'n' }, c.failed), h('span', { class: 'l' }, `Failed${prev?.rules ? `, ${fresh.length} new, ${fixed.length} fixed` : ''}`)),
      h('div', {}, h('span', { class: 'n' }, failedBy('Critical') + failedBy('High')), h('span', { class: 'l' }, 'Failed with critical or high severity'))),
    latest.runs.filter(r => !r.ran).map(r => h('p', { class: 'callout warn' }, `The ${mpArea(r.area)} part of this run did not finish${r.error ? `: ${r.error}` : '.'} Its rules are missing from the counts.`)),
    h('div', { class: 'grid-2' },
      panel('Pass rate over time', `${list.length} run${list.length > 1 ? 's' : ''}, hover a dot for its rate`, epTrend(list, 'Monkey365 rules')),
      panel('Newest run', `${when(latest.generatedAt)}${latest.engineVersion ? ` · Monkey365 ${latest.engineVersion}` : ''}`,
        h('dl', { class: 'kv' },
          h('dt', {}, 'Rules'), h('dd', {}, h('strong', {}, c.total), h('span', { class: 'muted small' }, ` · ${c.passed} passed, ${c.failed} failed, ${c.manual} to check by hand`)),
          h('dt', {}, 'Areas'), h('dd', {}, latest.runs.map(r => [chip(r.ran ? 'ok' : 'bad', `${mpArea(r.area)} ${r.ran ? 'ran' : 'did not finish'}`), ' '])),
          h('dt', {}, 'Failed by severity'), h('dd', {}, ['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => [chip(EP_TONE[s], `${s} ${failedBy(s)}`), ' ']))),
        h('p', { class: 'muted small' }, 'Rules come from the CIS Microsoft 365 Foundations and CIS Microsoft Azure Foundations benchmarks. "Check by hand" means Monkey365 cannot decide the rule from settings alone. The pass rate counts only rules that passed or failed.'))),
    panel('By area', 'Newest run', table(['Area', 'Pass rate', 'Passed', 'Failed', 'Check by hand'], byArea)),
    panel('What needs attention', 'Newest run, most severe first. Monkey365’s report names the mailboxes, teams or resources and how to fix each one.',
      areaPicker,
      table(['Severity', 'Rule', 'Area', 'Result'], open.map(r => h('tr', {},
        h('td', { class: 'nowrap' }, r.severity ? chip(EP_TONE[r.severity], r.severity) : h('span', { class: 'muted' }, '–')),
        h('td', {}, h('code', {}, r.id), ' ', r.helpUrl ? link(r.helpUrl, r.title) : r.title, r.failed > 1 ? h('span', { class: 'muted small' }, ` · ${r.failed} resources`) : null, fresh.includes(r) ? [' ', chip('warn', 'New')] : null),
        h('td', {}, mpArea(r.area)),
        h('td', { class: 'nowrap' }, chip(...MP_STATUS[r.status])))), 'Every rule that ran passed. Nothing to show.'),
      fixed.length ? h('div', { class: 'stack tight' }, h('h3', {}, `Fixed since ${day(prev.generatedAt)}`), h('ul', {}, fixed.map(r => h('li', {}, h('code', {}, r.id), ` ${r.title}`)))) : null),
    panel('Every run', 'Newest first',
      table(['Run', 'Pass rate', 'Passed', 'Failed', 'Check by hand', 'Monkey365 reports'], [...list].reverse().map(s => h('tr', {},
        h('td', { class: 'nowrap' }, when(s.generatedAt)), h('td', {}, h('strong', {}, s.passRate == null ? '–' : `${s.passRate}%`)),
        h('td', {}, s.counts.passed), h('td', {}, s.counts.failed), h('td', {}, s.counts.manual), h('td', {}, mpReportButtons(s)))))),
  ];
}
async function viewM365Posture() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'M365 & Azure posture'),
    h('p', {}, 'CIS benchmark checks of Exchange Online, Teams, Purview and Azure from Monkey365, run every week in a container on the computer that hosts HeatMap 360. Read-only: Monkey365 signs in with an app that can only read. Entra ID is on the ', h('a', { href: '#entraposture' }, 'Entra posture'), ' page.')));
  if (!me.elevated) return [head, gate()];
  const data = await api('/api/admin/m365posture');
  const setupLink = h('a', { class: 'btn primary', href: '#setup' }, 'Set up Monkey365 checks');
  if (!data.configured) return [head, h('div', { class: 'empty' }, h('h2', {}, 'Not available on this copy'),
    h('p', { class: 'muted' }, 'Monkey365 reports name real mailboxes, users and resources, so they stay on the computer that runs the checks. This page works on the local copy of HeatMap 360 on that computer.'), setupLink)];
  const skippedNote = data.skipped ? h('p', { class: 'callout warn' }, `${data.skipped} file${data.skipped > 1 ? 's' : ''} in the M365 posture folder could not be read as a Monkey365 summary and ${data.skipped > 1 ? 'were' : 'was'} skipped.`) : null;
  if (!data.scans.length) return [head, h('div', { class: 'empty' }, h('h2', {}, 'No Monkey365 runs yet'),
    h('p', { class: 'muted' }, data.folderFound ? 'The M365 posture folder is there but holds no Monkey365 results yet. The first one appears after the scheduled task has run.' : 'The M365 posture folder has not been created yet. It appears with the first Monkey365 run.'),
    skippedNote, setupLink)];
  const tenants = [...new Map(data.scans.map(s => [s.tenant, s.tenantName])).entries()];
  let tenant = data.scans.at(-1).tenant;
  const state = { area: '' };
  const body = h('div', { class: 'stack' });
  const render = () => body.replaceChildren(...mpTenantView(data.scans.filter(s => s.tenant === tenant), state, render).flat().filter(Boolean));
  render();
  const picker = tenants.length > 1 ? h('label', { class: 'field inline' }, h('span', {}, 'Tenant '),
    h('select', { onchange: e => { tenant = e.target.value; state.area = ''; activity.flash(`Showing ${e.target.selectedOptions[0].text}…`); render(); } }, tenants.map(([id, name]) => h('option', { value: id, selected: id === tenant }, name)))) : null;
  return [head, skippedNote, picker, body,
    h('p', { class: 'muted small' }, 'HeatMap 360 only reports. Fix what Monkey365 finds in the Exchange, Teams, Purview and Azure admin centers. These reports name real mailboxes, users and resources: they stay on this computer and are never uploaded or published.')];
}

// ---------- Chaos Monkey (2026-11-25) ----------
// One button per hardening test. Each button makes one r360 remediation that Intune runs on the machines picked in
// r360; the test scripts live in r360 (chaos/tests). Tier 1 attempts the weak connection from the machine against a DC,
// CA or printer; tiers 2 and 3 are configuration checks and stay under their own headings so they never mix with the
// probes.
const CM_TIERS = [
  ['probe', 'Active probes', 'The machine running the test attempts the weak connection against a domain controller, certificate authority or printer and records whether it was accepted or refused. Nothing runs on the target.'],
  ['local', 'Configuration check: this machine', 'Reads the settings and logs of the machine the test runs on, so it cannot be used as a stepping stone. No other machine is involved.'],
  ['ad', 'Configuration check: AD objects', 'Reads accounts, certificate templates and CA settings over LDAP that an attacker could abuse. It does not attempt the abuse.'],
];
// [tier, group, id, name, what it proves, how it tests]
const CHAOS_TESTS = [
  ['probe', 'NTLM', 'N3', 'DCs refuse NTLMv1', 'Every domain controller rejects an NTLMv1 login.', 'Attempts an NTLMv1 login against each DC; passes when every DC refuses it. Needs its own login client: until it is built, reports Could not test.'],
  ['probe', 'NTLM', 'N6', 'DCs refuse NTLM', 'NTLM is blocked at the domain controllers (last reduction stage).', 'Opens \\\\<DC IP>\\NETLOGON by IP address, which forces NTLM; passes when every DC refuses it.'],
  ['probe', 'SMB', 'S2', 'DCs require SMB signing', 'No one can relay to a domain controller over SMB.', 'SMB2 negotiate on port 445, no login; reads the signing-required flag.'],
  ['probe', 'SMB', 'S3', 'CAs require SMB signing', 'No one can relay to a certificate authority over SMB.', 'The same SMB2 negotiate against each CA found in AD.'],
  ['probe', 'LDAP and coercion', 'L1', 'DCs require LDAP signing', 'A domain controller refuses unsigned LDAP.', 'Attempts an unsigned bind on port 389; passes when refused (strongerAuthRequired).'],
  ['probe', 'LDAP and coercion', 'L2', 'DCs enforce LDAP channel binding', 'A domain controller refuses LDAPS logins without channel binding.', 'Attempts an LDAPS login without channel binding against each DC; passes when refused. Needs its own login client: until it is built, reports Could not test.'],
  ['probe', 'LDAP and coercion', 'C1', 'Print Spooler off on DCs', 'The spooler coercion path to domain controllers is closed.', 'Looks for the spoolss pipe on each DC; passes when it is absent.'],
  ['probe', 'Name resolution', 'R4', 'WPAD cannot be hijacked', 'Nobody can pose as the proxy configuration server.', 'The name "wpad" does not resolve, and WinHTTP proxy auto-detect is off.'],
  ['probe', 'AD CS enrollment (KB5005413)', 'E1', 'No web enrollment over HTTP (ESC8)', 'No one can relay NTLM to the CA web pages.', 'Requests http://<CA>/certsrv/ and the CES addresses; passes when absent or no NTLM/Negotiate login is offered.'],
  ['probe', 'AD CS enrollment (KB5005413)', 'E2', 'HTTPS-only enrollment works', 'Enrollment still works, over HTTPS only.', 'The same addresses over https answer with a certificate this machine trusts.'],
  ['probe', 'AD CS enrollment (KB5005413)', 'E3', 'CA refuses NTLM', 'NTLM is restricted on the CA, as KB5005413 asks.', 'Opens \\\\<CA IP>\\IPC$ by IP address, which forces NTLM; passes when refused.'],
  ['probe', 'AD CS enrollment (KB5005413)', 'E4', 'Extended Protection on certsrv and CES', 'The CA HTTPS pages refuse logins without channel binding.', 'Attempts an HTTPS login without Extended Protection; passes when refused. Needs its own login client: until it is built, reports Could not test.'],
  ['probe', 'Printers', 'D2', 'Printers refuse SNMP "public"', 'The printers this machine uses do not answer the default community.', 'One SNMP read of the device description with community "public"; passes when no printer answers.'],
  ['probe', 'Printers', 'D3', 'Printers offer no cleartext protocols', 'Printer admin and file transfer are encrypted.', 'FTP (21), Telnet (23) and TFTP (69) are closed, and the web admin page redirects to HTTPS.'],
  ['probe', 'Windows LAPS', 'W1', 'Can\'t read other machines\' LAPS passwords', 'This machine cannot read the local admin password of any other machine.', 'Running as SYSTEM (the computer account), asks a DC for the LAPS password attributes of 20 other computers; passes when every value comes back empty.'],
  ['probe', 'Entra sync', 'H6', 'Sync server refuses NTLM', 'No one can relay or replay NTLM to the Entra sync server.', 'Finds the sync server from AD (MSOL_ account description or Cloud Sync gMSA hosts), opens \\\\<server IP>\\IPC$, which forces NTLM; passes when refused.'],
  ['probe', 'Entra sync', 'H7', 'Sync server requires SMB signing', 'No one can relay to the Entra sync server over SMB.', 'SMB2 negotiate on port 445 against the sync server, no login; reads the signing-required flag.'],
  ['probe', 'AD hygiene and Server 2025', 'G1', 'DCs refuse anonymous LDAP', 'Nobody can read the directory without signing in.', 'Binds anonymously to each DC and searches the domain; passes when the search is refused (reading rootDSE is allowed).'],
  ['probe', 'Enforcement changes', 'V3', 'DCs refuse RC4 service tickets', 'Since the July 2026 RC4 enforcement, no DC hands out an RC4 service ticket.', 'Asks each DC for a service ticket offering only RC4; passes on KDC_ERR_ETYPE_NOSUPP. Needs its own login client: until it is built, it asks each DC for a normal ticket, fails if any ticket this machine holds is RC4, and otherwise reports Could not test.'],
  ['local', 'NTLM', 'N1', 'NTLMv1 disabled on this machine', 'This machine can neither send nor accept NTLMv1.', 'Windows 11 24H2 or later, or LmCompatibilityLevel = 5 and NtlmMinClientSec / NtlmMinServerSec = 0x20080000.'],
  ['local', 'NTLM', 'N2', 'No NTLMv1 logons', 'Nothing used NTLMv1 here in the last 7 days.', 'Security event 4624 with package "NTLM V1" = 0.'],
  ['local', 'NTLM', 'N4', 'NTLM auditing on', 'Reduction stage 1: NTLM use is logged.', 'AuditReceivingNTLMTraffic = 2 and RestrictSendingNTLMTraffic = 1 or more; DC policy AuditNTLMInDomain set.'],
  ['local', 'NTLM', 'N5', 'No NTLM leaves this machine', 'Reduction stage 2: this machine uses Kerberos only.', 'NTLM event 8001 = 0 in 7 days; a fail names the servers it used NTLM with.'],
  ['local', 'SMB', 'S1', 'SMB signing required here', 'This machine signs every SMB connection, in and out.', 'RequireSecuritySignature = 1 for LanmanWorkstation and LanmanServer.'],
  ['local', 'SMB', 'S4', 'SMBv1 off', 'The legacy protocol with no protection is gone.', 'EnableSMB1Protocol = false and the SMB1 feature is not installed.'],
  ['local', 'LDAP and coercion', 'L3', 'This machine signs LDAP', 'This machine never sends unsigned LDAP.', 'LDAPClientIntegrity = 1 or more.'],
  ['local', 'LDAP and coercion', 'C2', 'WebClient off', 'This machine cannot be coerced into NTLM over HTTP (WebDAV).', 'The WebClient service is absent or disabled.'],
  ['local', 'Name resolution', 'R1', 'LLMNR off', 'This machine never asks the local network for names over LLMNR.', 'EnableMulticast = 0 under the DNSClient policy key.'],
  ['local', 'Name resolution', 'R2', 'NBT-NS off', 'NetBIOS name lookups are off on every network adapter.', 'NetbiosOptions = 2 on every adapter under NetBT\\Parameters\\Interfaces.'],
  ['local', 'Name resolution', 'R3', 'mDNS off', 'This machine never asks or answers names over mDNS.', 'EnableMDNS = 0 under Dnscache\\Parameters.'],
  ['local', 'Pass-the-hash', 'P1', 'LAPS manages the local admin password', 'Every machine has a unique, rotating local admin password.', 'Windows LAPS policy set, backs up to AD or Entra, last rotation under 30 days.'],
  ['local', 'Pass-the-hash', 'P2', 'Credential Guard running', 'Login secrets are isolated from Windows itself.', 'Win32_DeviceGuard reports Credential Guard running.'],
  ['local', 'Pass-the-hash', 'P3', 'LSA protection on', 'Tools cannot read the memory of the login process.', 'RunAsPPL = 1 under Control\\Lsa.'],
  ['local', 'Pass-the-hash', 'P4', 'WDigest off', 'No cleartext passwords are kept in memory.', 'UseLogonCredential is absent or 0.'],
  ['local', 'Pass-the-hash', 'P5', 'Local admins cannot log in over the network', 'A local admin hash cannot be reused against other machines.', 'LocalAccountTokenFilterPolicy is absent or 0 (remote UAC on).'],
  ['local', 'Printers and devices', 'D1', 'No SNMP service on this machine', 'This machine offers no SNMP v1/v2c.', 'The Windows SNMP service is not installed.'],
  ['local', 'Printers and devices', 'D4', 'No TFTP or Telnet client', 'This machine cannot move files or manage devices in cleartext.', 'The TFTP and Telnet client features are not installed.'],
  ['local', 'Windows LAPS', 'W2', 'LAPS passwords encrypted in AD', 'The local admin password is never stored in AD as clear text.', 'BackupDirectory = 2 with ADPasswordEncryptionEnabled = 1, or BackupDirectory = 1 (Entra); clear-text AD backup fails. Needs domain level 2016 (G6).'],
  ['local', 'Windows LAPS', 'W3', 'Legacy LAPS client removed', 'The deprecated legacy LAPS client is gone, so Windows LAPS is in charge.', 'Fails when the legacy client-side extension (AdmPwd.dll, GPExtensions {D76B9641-3288-4f75-942D-087DE603E3EA}) is registered.'],
  ['local', 'Windows LAPS', 'W4', 'Used LAPS password is reset', 'A LAPS password someone used stops working within a day.', 'PostAuthenticationResetDelay 1 to 24 hours and PostAuthenticationActions resets the password and signs out or restarts (3, 5 or 11); a delay of 0 fails.'],
  ['local', 'Windows LAPS', 'W5', 'LAPS password is long and complex', 'The local admin password cannot be guessed.', 'PasswordLength 14 or more with PasswordComplexity 4 or more, or a passphrase of 6 or more words.'],
  ['local', 'Enforcement changes', 'V2', 'SMB client blocks NTLM', 'This machine never falls back to NTLM for file shares (the step after N5).', 'SMB client BlockNTLM = 1 (Windows 11 24H2 and later); any exception list is shown.'],
  ['ad', 'Kerberos', 'K1', 'No Kerberoastable accounts', 'No user account with a service name has a weak, crackable setup.', 'A user account with a servicePrincipalName that allows RC4 (or sets no encryption types, so the domain default applies) or has a password older than 365 days fails.'],
  ['ad', 'Kerberos', 'K2', 'AES only for Kerberos', 'RC4 tickets are not issued.', 'DC policy and this machine allow AES only, and every service account has AES in msDS-SupportedEncryptionTypes.'],
  ['ad', 'Kerberos', 'K3', 'No AS-REP roastable accounts', 'Every account needs Kerberos pre-authentication.', 'Any enabled account with "Do not require Kerberos preauthentication" fails.'],
  ['ad', 'Kerberos', 'K4', 'No unconstrained delegation', 'Only domain controllers can hold other people\'s tickets.', 'Any non-DC computer or user trusted for unconstrained delegation fails.'],
  ['ad', 'Kerberos', 'K5', 'Admins are protected', 'Admin credentials cannot be delegated or cached weakly.', 'Every Domain, Enterprise and built-in Admin is in Protected Users or marked sensitive and cannot be delegated.'],
  ['ad', 'Kerberos', 'K6', 'No accounts explicitly allow RC4', 'No account opts back in to RC4.', 'Searches AD for accounts whose msDS-SupportedEncryptionTypes has the RC4 bit (0x4) set (LDAP filter msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4); any match fails and is named.'],
  ['ad', 'Kerberos', 'K7', 'No domain-wide RC4 override', 'No domain-wide RC4 override is left behind from the April 2026 change.', 'Looks for DefaultDomainSupportedEncTypes with RC4 in the KDC settings pushed to DCs by Group Policy (read from SYSVOL); a value set by hand on a DC can only be seen on the DC itself, so that case reports Could not test.'],
  ['ad', 'AD CS templates', 'T1', 'No ESC1 templates', 'No one can enroll as someone else.', 'Client login usage + requester-supplied subject + low-privilege enroll + no approval or signatures fails.'],
  ['ad', 'AD CS templates', 'T2', 'No ESC2 templates', 'No any-purpose certificate is open to everyone.', 'Any Purpose or no usage with low-privilege enroll fails.'],
  ['ad', 'AD CS templates', 'T3', 'No ESC3 templates', 'No one can enroll on behalf of others.', 'Certificate Request Agent usage with low-privilege enroll fails.'],
  ['ad', 'AD CS templates', 'T4', 'No ESC4 templates', 'No one can rewrite a template into ESC1.', 'Low-privilege GenericAll, WriteDacl, WriteOwner or WriteProperty on a template fails.'],
  ['ad', 'AD CS templates', 'T5', 'No ESC9 templates', 'Every certificate carries the strong mapping extension.', 'A template with CT_FLAG_NO_SECURITY_EXTENSION fails.'],
  ['ad', 'AD CS templates', 'T6', 'No ESC15 templates', 'Old version 1 templates cannot be abused.', 'Schema version 1 + requester-supplied subject + low-privilege enroll fails.'],
  ['ad', 'AD CS templates', 'T7', 'Enrollment and issuance controls', 'Only intended groups can enroll on login-capable templates, with approval where needed.', 'Low-privilege enroll on a login-capable template without manager approval fails; lists who can enroll on each.'],
  ['ad', 'Certificate authorities', 'A1', 'No ESC6 on CAs', 'A requester cannot add any name they like to a certificate.', 'EditFlags with EDITF_ATTRIBUTESUBJECTALTNAME2 fails (read with certutil).'],
  ['ad', 'Certificate authorities', 'A2', 'No ESC7 on CAs', 'Only admins can manage the CA or approve requests.', 'Low-privilege Manage CA or Manage Certificates rights fail.'],
  ['ad', 'Certificate authorities', 'A3', 'No ESC11 on CAs', 'Enrollment over RPC cannot be relayed.', 'InterfaceFlags without IF_ENFORCEENCRYPTICERTREQUEST fail.'],
  ['ad', 'Certificate authorities', 'A4', 'No ESC5 on PKI objects', 'PKI containers, the NTAuth store and CA computer objects are locked down.', 'Low-privilege write rights on any of them fail.'],
  ['ad', 'Windows LAPS', 'W6', 'No clear-text legacy LAPS left', 'No machine still writes its admin password to AD as clear text.', 'Counts computers whose legacy ms-Mcs-AdmPwdExpirationTime is still set; reads only the expiration time, never a password.'],
  ['ad', 'Windows LAPS', 'W7', 'Only a named group reads LAPS passwords', 'Only the intended group can read or decrypt local admin passwords.', 'Lists who holds All extended rights or read on the LAPS password attributes on each OU with computers; Domain Users, Authenticated Users or any group not on the allow list fails. Put the allowed reader groups in $AllowedReaders at the top of the script before you create the change.'],
  ['ad', 'Windows LAPS', 'W8', 'DCs back up their DSRM password', 'Every domain controller restore-mode password is managed and rotating.', 'msLAPS-PasswordExpirationTime is set on each DC computer object. Read rights for a computer account still need checking in the lab.'],
  ['ad', 'Entra sync', 'H1', 'Only expected accounts can DCSync', 'Only DCs, admins and the one sync account can pull password hashes.', 'Reads the domain root permissions; Replicating Directory Changes All for anyone other than DCs, Domain/Enterprise Admins, Administrators and the known sync account fails.'],
  ['ad', 'Entra sync', 'H2', 'Sync account is locked down', 'Nobody can take over the Entra sync account in AD.', 'On the MSOL_ or custom connector account: inheritance off, and only SYSTEM, Enterprise Admins, Domain Admins and Administrators can write it (as Set-ADSyncRestrictedPermissions sets).'],
  ['ad', 'Entra sync', 'H3', 'Sync rights stay off admin accounts', 'Admin accounts cannot be reset or changed through the sync account.', 'AdminSDHolder carries no permission for the sync account.'],
  ['ad', 'Entra sync', 'H4', 'Cloud Sync gMSA limited to agent servers', 'Only the provisioning agent servers can use the Cloud Sync account.', 'msDS-GroupMSAMembership on provAgentgMSA lists only the agent servers; not applicable when Cloud Sync is not used.'],
  ['ad', 'Entra sync', 'H5', 'Seamless SSO account is safe', 'Nobody can forge Entra sign-ins with the Seamless SSO key.', 'AZUREADSSOACC: password changed in the last 30 days, AES only (0x18), no delegation, no non-admin write; passes when the account is absent.'],
  ['ad', 'AD hygiene and Server 2025', 'G2', 'Users cannot add computers', 'Ordinary users cannot create computer accounts for relay or delegation attacks.', 'ms-DS-MachineAccountQuota = 0 (the default is 10).'],
  ['ad', 'AD hygiene and Server 2025', 'G3', 'krbtgt password changed recently', 'Old stolen krbtgt keys (golden tickets) stop working.', 'krbtgt pwdLastSet within 180 days (our own threshold; Microsoft gives no number).'],
  ['ad', 'AD hygiene and Server 2025', 'G4', 'Pre-Windows 2000 group holds no broad groups', 'Anyone signed in cannot read what that legacy group opens up.', 'Fails when Authenticated Users, Everyone or Anonymous Logon is a member of Pre-Windows 2000 Compatible Access.'],
  ['ad', 'AD hygiene and Server 2025', 'G5', 'No pre-Windows 2000 computer accounts', 'No computer account still has its name as its password.', 'Fails on computer accounts flagged password-not-required (userAccountControl 4128) that never signed in.'],
  ['ad', 'AD hygiene and Server 2025', 'G6', 'Domain at 2016 level or later', 'The domain supports LAPS encryption and DSRM backup.', 'msDS-Behavior-Version 7 or higher.'],
  ['ad', 'AD hygiene and Server 2025', 'G7', 'Only admins can create service accounts (BadSuccessor)', 'Nobody can use a new dMSA to take over another account.', 'Fails when a non-admin can create child objects (all types or msDS-DelegatedManagedServiceAccount) in any OU, or write an existing dMSA. Matters when a DC runs Server 2025.'],
  ['ad', 'AD hygiene and Server 2025', 'G8', 'AD Recycle Bin on', 'Deleted objects can be restored with their links intact.', 'The Recycle Bin optional feature is enabled in the forest.'],
  ['ad', 'AD hygiene and Server 2025', 'G9', 'DC policy refuses default machine passwords', 'DCs refuse to set a computer password to its default value.', 'Reads the GPOs linked to the Domain Controllers OU from SYSVOL for "Refuse setting default machine account password"; shows the policy as written, not what a DC applied.'],
  ['ad', 'Enforcement changes', 'V1', 'No weak certificate mappings', 'No account relies on a certificate mapping that full enforcement (2025) made unsafe.', 'altSecurityIdentities values of the weak types (Issuer and Subject, Subject only, RFC822) fail; Issuer and Serial, SKI and SHA1 public key pass.'],
];
const RUNS_ON = { probe: 'Probe', local: 'This machine', ad: 'AD read' };
// r360 runs on the same computer (localhost only). The button opens r360 in a new tab, which creates the change at once
// from the matching template (r360 public/chaos.js) with your own r360 write session, so HeatMap stays read-only and
// holds no r360 credential. r360 creates without a second press only when the link carries HeatMap's origin as its
// referrer (referrerpolicy="origin" on this link; the rest of HeatMap sends none).
const R360_URL = 'http://localhost:3660';
const r360Link = id => `${R360_URL}/#new/chaos-${encodeURIComponent(id)}?from=heatmap-360`;
function chaosCard([tier, , id, name, proves, how]) {
  return h('article', { class: 'cm-card' },
    h('div', { class: 'cm-top' }, h('span', { class: 'cm-id' }, id), h('strong', {}, name), chip(tier === 'probe' ? 'info' : 'unknown', RUNS_ON[tier])),
    h('p', { class: 'small' }, proves),
    h('p', { class: 'muted small' }, how),
    h('div', { class: 'row cm-foot' }, h('a', { class: 'btn sm', href: r360Link(id), target: '_blank', rel: 'noopener', referrerPolicy: 'origin', busy: 'Creating r360 change…', done: 'Created in the r360 tab',
      title: `Creates the r360 change "STT - Chaos - ${id} ${name}" in a new r360 tab, which shows the pull request it made (sign in and Elevate to write there first if asked)` }, 'Create r360 change')));
}
// Every tier and every category folds and starts folded, like every section on every page (fold()).
const cmFold = (key, cls, summary, ...body) => fold({ class: `cm-fold ${cls}`, key: `chaos:${key}` }, summary, ...body);
function viewChaosMonkey() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Chaos Monkey'),
    h('p', {}, 'One button per hardening test. Each button creates that test as a new r360 remediation (a pull request on the remediations repo), which Intune runs on the machines you pick in r360, to prove a piece of the topology is hardened. Tests only read or attempt a login that is meant to fail; nothing is changed and no certificate is requested.')));
  if (!me.elevated) return [head, gate()];
  const tiers = CM_TIERS.map(([tier, title, sub], i) => {
    const tests = CHAOS_TESTS.filter(t => t[0] === tier);
    const groups = [...new Set(tests.map(t => t[1]))];
    return cmFold(tier, `panel cm-tier cm-${tier}`, h('span', { class: 'cm-sum' }, h('h2', {}, `${i + 1}. ${title}`), h('span', { class: 'sub' }, `${tests.length} tests`)),
      h('p', { class: 'muted' }, sub),
      groups.map(g => { const list = tests.filter(t => t[1] === g); return cmFold(`${tier}:${g}`, 'cm-group', h('span', { class: 'cm-sum' }, h('h3', {}, g), h('span', { class: 'sub' }, `${list.length}`)), h('div', { class: 'cm-grid' }, list.map(chaosCard))); }));
  });
  return [head,
    h('p', { class: 'callout' }, 'Each test only reads and asks: it never changes the machine it runs on or any other. Intune shows its result as the first line of output: PASS, FAIL or COULD NOT TEST. Only PASS counts as hardened. Four probes (N3, L2, E4, V3) need their own login client, which is not built yet, so they report COULD NOT TEST. The change is created in a new r360 tab, which must be running on this computer (localhost:3660); sign in and Elevate to write there if it asks, and it carries on.'),
    h('div', { class: 'stack' }, tiers),
    h('p', { class: 'muted small' }, 'Not covered by any button: switches, routers and firewalls, and SNMPv3 setup on the printer itself. A script on an Intune machine cannot see those settings.')];
}

// ---------- x.com (not populated yet) ----------
function viewX() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'x.com'), h('p', {}, 'Latest news from x.com for five timeframes.')));
  if (!me.elevated) return [head, gate()];
  return [head,
    h('p', { class: 'callout' }, 'Not populated yet. How this page gets its posts is still being decided.'),
    h('div', { class: 'grid-2' }, TIMEFRAMES.map(([, t]) =>
      panel(t, null, h('p', { class: 'muted' }, 'No posts yet.'))))];
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
          h('label', { class: 'option' }, h('span', {}, h('strong', {}, 'Wait for results (minutes)'), h('span', { class: 'muted small' }, 'When uploading from the scanner: how long it waits for the results file before telling you how to fetch it later.')),
            h('input', { type: 'number', min: 1, max: 120, value: opts.wait, class: 'num-input', oninput: e => { opts.wait = Math.min(120, Math.max(1, Number(e.target.value) || 15)); render(); }, onchange: () => activity.flash('Updating the command…') }))),
        h('h3', {}, 'Command'), out,
        h('div', { class: 'row' }, copyButton(() => out.textContent), scannerButton('btn sm primary', 'Download the scanner'))),
      panel('What a scan checks', null, h('dl', { class: 'kv' }, what.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])))),
    panel('On-demand vulnerability check', chip('info', 'Planned'),
      h('p', { class: 'muted' }, 'Check a scanned computer’s installed versions against published vulnerabilities on request. Report only.'), h('button', { class: 'btn', disabled: true, title: 'Planned. This button does nothing until the check is built.' }, 'Not available yet')),
  ];
}

// ---------- Scanner (public) ----------
// Step 2 in the browser: send a file the scanner saved. The server returns a scan ID and a token; the token is the
// only way to fetch that scan's results file (.mhtml), so it stays in this browser (and in a ticket file the user can save).
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
        t.state === 'done' ? h('button', { class: 'btn sm primary', busy: 'Building results file…', done: 'Downloaded', fail: 'Download failed', title: 'One .mhtml file: opens in Edge or Chrome, works offline.', onclick: async () => {
          saveFile(`HeatMap360-${t.id}.mhtml`, await (await uploaderFetch(t, 'report.mhtml')).blob());
        } }, 'Download results (.mhtml)') : null,
        h('button', { class: 'btn sm', busy: 'Saving ticket…', done: 'Ticket saved', title: 'Save scan-<id>.json in Documents\\HeatMap360, then run the scanner with -Resume <id> to fetch the results file later.', onclick: () =>
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
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scan a Windows computer'), h('p', {}, 'The scanner lists what is installed and saves it without anything that identifies you or the computer. Nothing is sent until you upload the file. Your results come back as one .mhtml file that opens in Edge or Chrome.'),
      h('p', { class: 'small' }, 'First time? ', h('a', { href: '#guide' }, 'Read the How To Guide'), ' for every step and what happens behind it.'))),
    h('div', { class: 'grid-2' },
      panel('Four steps', null, h('ol', { class: 'steps-list' },
        h('li', {}, h('strong', {}, 'Download the scanner'), h('div', {}, scannerButton('btn', 'Download Invoke-HeatMapScan.ps1'))),
        h('li', {}, h('strong', {}, 'Scan: run it in PowerShell'), h('p', { class: 'muted small' }, 'Open PowerShell as administrator (so BitLocker and Secure Boot can be read) in the folder where you saved it. It saves the anonymized scan as Documents\\HeatMap360\\inventory-<time>.json and sends nothing. Open the file to read exactly what would be sent.'),
          h('pre', { class: 'code' }, cmd), copy(cmd)),
        h('li', {}, h('strong', {}, 'Upload the saved file'), h('p', { class: 'muted small' }, 'Choose the inventory file. Only that file is sent.'), up.button,
          h('p', { class: 'muted small' }, 'Or upload from PowerShell, which also waits for the results and saves the .mhtml file next to the scan:'), h('pre', { class: 'code' }, `${cmd} -Upload`), copy(`${cmd} -Upload`)),
        h('li', {}, h('strong', {}, 'Get your results'), h('p', { class: 'muted small' }, 'Your uploads appear below. When the results are ready, download the .mhtml file and open it in Edge or Chrome. If you close this page, save the ticket first; run the scanner with -Resume <scan ID> to fetch the file later.')))),
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
  ['Report', 'The uploader gets one .mhtml file (a web page that opens offline in Edge or Chrome). Admins see every scan, with its grade and every finding, on the Scans page.', '#scans'],
  ['Keep watching', 'Every item goes into one findings table. A background job looks each item up again about once a day, so a new problem shows up without a new scan.', '#scans'],
];
const OVERVIEW_AREAS = [
  ['New hire', 'Open to everyone, no sign-in.', [
    ['Overview', 'This page.', '#overview'],
    ['How To Guide', 'One scan end to end: each step, what happens behind it, what the result words mean, and troubleshooting.', '#guide'],
    ['Get the scanner', 'Download the scanner, upload a scan file and fetch your results (.mhtml).', '#scanner'],
    ['Scanner vs Intune & Defender', 'What the scanner collects compared with Microsoft Intune and Microsoft Defender, what each costs, and why HeatMap 360 does its own lookups.', '#compare'],
  ]],
  ['Results', 'Admins with an active PIM elevation.', [
    ['Scans', 'Every scan, newest first. Each one opens to its grade, every finding and a downloadable .mhtml file.', '#scans'],
    ['Inventory catalog', 'Every software, driver and firmware version seen on any scanned computer, stored once: which computers run it, whether an update exists, known problems, exploited vulnerabilities, and its history.', '#catalog'],
    ['Pen tests', 'Penetration testing write-ups, each with a short synopsis and a link to the original. For reading only.', '#pentests'],
    ['Vulnerability scans', 'Placeholder for vulnerability scan results, not built yet.', '#vulnscans'],
    ['AD posture', 'Active Directory risk scores from a weekly PingCastle health check, over time: what was found, what is new and what was fixed. Local copy only.', '#adposture'],
    ['Attack paths', 'Who can reach Domain Admins and other risky Active Directory settings, from a weekly BloodHound collection. Local copy only.', '#attackpaths'],
    ['Entra posture', 'Entra ID and Microsoft 365 security checks from a weekly Maester run in a container: the pass rate over time, what failed, what is new and what was fixed. Local copy only.', '#entraposture'],
    ['M365 & Azure posture', 'CIS benchmark checks of Exchange Online, Teams, Purview and Azure from a weekly Monkey365 run in a container, beside Maester’s Entra ID checks: the pass rate over time, what failed, what is new and what was fixed. Local copy only.', '#cloudposture'],
    ['Chaos Monkey', 'One button per hardening test (NTLM, SMB, LDAP, name resolution, Kerberos, pass-the-hash, AD CS, printers, Windows LAPS, Entra sync, AD hygiene, enforcement changes). Each button creates the test as an r360 remediation that Intune runs. Each test reports PASS, FAIL or COULD NOT TEST.', '#chaosmonkey'],
    ['High impact', 'One short list of what deserves attention now: vulnerabilities CISA just confirmed are exploited, zero-day headlines, and long or severe cloud outages. Each item says why it made the cut.', '#attention'],
    ['Incident cases', 'One record per security incident through the NIST lifecycle: triage and severity, a playbook checklist, a timeline, hashed evidence and a post-incident review PDF. Containment links out to Remediation 360, Entity 360 and Federation 360.', '#cases'],
    ['Are we affected?', 'Every exploit on High impact checked against the newest scan of each computer: which have a vulnerable version, which need a check by hand, and which are fine.', '#affected'],
    ['Internet - Cloud Services', 'Headlines from the big cloud providers’ own blogs and update pages.', '#cloud'],
    ['Internet - Exploits', 'Security advisories and news: CISA, the Microsoft Security Update Guide, SANS and others.', '#exploits'],
    ['Cloudflare Radar CVEs', 'Newly published CVEs from Cloudflare Radar, filtered by severity, timeframe, known exploited and search.', '#cves'],
    ['Internet - Patches', 'Patch news feeds, so you hear about a bad update before it reaches your computers.', '#patches'],
    ['x.com', 'Five timeframes, not populated yet.', '#x'],
    ['Bluesky', 'Latest posts from official vendor accounts about patches, security and service health, with replies on demand.', '#bluesky'],
    ['Service health', 'Microsoft 365 health for your tenant, plus Azure, AWS, Google Cloud, Google Workspace, GitHub and Cloudflare.', '#services'],
  ]],
  ['Tools', 'How to set up and Options are open to everyone; Settings needs Settings Admin.', [
    ['How to set up', 'How to set up every part of HeatMap 360: the local and hosted copies, the bot, and the AD posture scans.', '#setup'],
    ['Options', 'Builds the scanner command: speed test on or off, save only or scan and upload, wait time.', '#options'],
    ['Settings', 'Settings Admins only: which storage account and table hold the findings table.', '#settings'],
  ]],
];
const OVERVIEW_FIRST_STEPS = [
  ['Scan a computer yourself', 'Follow the [How To Guide] once from start to finish on your own computer. It takes about five minutes and shows you exactly what users see.'],
  ['Read your results', 'Open the .mhtml file in Edge or Chrome. Note which items are Good, Needs attention, Action needed and Not checked, and why. Not checked means the lookup could not tell; nothing is assumed.'],
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
  'Matching scans against the news and social feeds, with a verdict per product (the exploits on High impact are already matched on Are we affected?).',
  'AI-assisted lookups of known issues for each component.',
  'Posts on the x.com page.',
  'Vulnerability scan results.',
  'SharePoint Online and OneDrive checks on the M365 & Azure posture page (Monkey365 needs a permission that can change sites for them, so they are left out).',
  'BIOS lookups for makers other than HP, Lenovo and Dell, and drivers newer than what Windows Update offers (needs reading vendor web pages).',
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

// ---------- Scanner vs Intune & Defender (public) ----------
// Static comparison for new owners: what the scanner gathers next to Microsoft Intune and Microsoft Defender.
// Checked against Microsoft Learn on 2026-11-17. Prices are approximate list prices; Microsoft's pages have current ones.
const COMPARE_ROWS = [
  ['Installed programs', 'Name, version and publisher from all three Add/Remove Programs locations', 'The same, plus Store apps, install path and size', 'Software inventory matched to product IDs (CPE)'],
  ['Newest version of each app', 'Yes, from the winget catalog', 'No (only with the paid Intune Suite app catalog)', 'Vulnerable and fixed versions, for products with a CPE only'],
  ['Known issues in an app update', 'Yes, from the publisher’s release notes', 'No', 'No'],
  ['Exploited vulnerabilities (CVE, CISA KEV)', 'Yes, CISA KEV matched with official CVE records', 'No', 'Yes, automatic, with exploit and threat tags'],
  ['Windows build and installed updates', 'Yes, plus Microsoft release health known issues', 'Version and installed updates, update reports', 'Missing security updates as recommendations'],
  ['BIOS', 'Version and date, newest BIOS from the HP and Lenovo catalogs', 'Version, date and serial number', 'BIOS vulnerabilities and maker advisories, paid add-on only'],
  ['Disks', 'Model, firmware, health, wear, temperature, uncorrected errors', 'Model and size, no health', 'No'],
  ['Battery', 'Design and full capacity, charge cycles', 'The same; the health report is a paid add-on', 'No'],
  ['Drivers', 'Version and date for 11 device classes', 'One computer at a time, paid add-on only', 'No'],
  ['Security status', 'Defender, BitLocker, Secure Boot, TPM, firewall', 'BitLocker and TPM; compliance policies cover more', 'Configuration assessment and Secure Score, deeper than the scanner'],
  ['Event log errors', 'Counts per Windows component for 7 days', 'One computer at a time, paid add-on only', 'No'],
  ['Network adapters and Wi-Fi', 'Speed, duplex, driver, power and offload settings, signal and band', 'Maker and type only', 'No'],
  ['Network health', 'Gateway ping, loss, jitter, DNS time, download and upload speed', 'No', 'No'],
  ['Privacy', 'No computer names, user names, addresses or serial numbers', 'Serial numbers, computer and user names', 'Full device identity'],
];
const COMPARE_COST = [
  ['HeatMap 360 scanner', 'None', '$0', 'Any Windows computer, no account, nothing installed'],
  ['Intune inventory', 'Intune Plan 1 (in Microsoft 365 Business Premium, E3, E5)', 'about $8 on its own', 'Enrolled in Intune, company-owned, Entra joined'],
  ['Intune drivers, event log, battery report', 'Intune Plan 2 or Intune Suite, on top of Plan 1', 'several dollars more', 'The same, plus endpoint analytics'],
  ['Defender vulnerability management', 'Defender for Business (in Business Premium) or Defender for Endpoint Plan 2 (in E5)', 'about $3 or $5', 'Onboarded to Defender'],
  ['Defender hardware and firmware checks', 'Defender Vulnerability Management add-on or standalone; not sold with Defender for Business', 'about $2 to $3 more', 'Onboarded to Defender'],
];
function viewCompare() {
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Scanner vs Intune & Defender'),
      h('p', { class: 'overview-lead' }, 'Neither Microsoft Intune nor Microsoft Defender gathers everything the HeatMap 360 scanner gathers, and both work only on computers enrolled in your Microsoft tenant. HeatMap 360 keeps its own scanner and does its own lookups, at no cost.'))),
    h('div', { class: 'grid-3' },
      panel('Intune', null, h('p', {}, 'Lists about the same hardware and programs, but ', h('strong', {}, 'looks nothing up'), ': no newest versions, no vulnerabilities, no known issues.')),
      panel('Defender', null, h('p', {}, 'Better than the scanner at one thing: ', h('strong', {}, 'matching software to exploited vulnerabilities'), '. Needs a paid licence; firmware checks need a further add-on.')),
      panel('Only the scanner', null, h('p', {}, 'Network speed, adapter settings, Wi-Fi signal, disk wear, event log errors, and known issues in Windows and app updates.'))),
    panel('Area by area', 'What each one collects or checks',
      table(['Area', 'HeatMap 360 scanner', 'Microsoft Intune', 'Microsoft Defender'], COMPARE_ROWS.map(r => h('tr', {}, r.map((c, i) => (i ? h('td', {}, c) : h('th', { scope: 'row' }, c))))))),
    panel('Licences and cost', 'Approximate list price per user per month; Microsoft’s pages have current prices',
      table(['Option', 'Licence', 'Cost', 'Computers it works on'], COMPARE_COST.map(r => h('tr', {}, r.map((c, i) => (i ? h('td', {}, c) : h('th', { scope: 'row' }, c))))))),
    panel('What this means for HeatMap 360', null, h('ul', {},
      h('li', {}, 'The scanner stays the inventory for all software and all hardware.'),
      h('li', {}, 'Lookups come from official free sources: Microsoft release health, the winget catalog, publisher release notes, CISA KEV, CVE records and the HP and Lenovo catalogs.'),
      h('li', {}, 'If a tenant already pays for Defender, its vulnerability list could later be read as a second opinion for enrolled computers. That is not built.'))),
    panel('Sources', 'Microsoft Learn, checked 2026-11-17', h('ul', {},
      h('li', {}, link('https://learn.microsoft.com/intune/device-configuration/collect-device-properties', 'Intune properties catalog')),
      h('li', {}, link('https://learn.microsoft.com/intune/advanced-analytics/ref-data-platform-schema', 'Intune data platform schema')),
      h('li', {}, link('https://learn.microsoft.com/intune/app-management/deployment/enhanced-app-inventory', 'Intune app inventory')),
      h('li', {}, link('https://learn.microsoft.com/intune/fundamentals/licensing', 'Intune licensing')),
      h('li', {}, link('https://learn.microsoft.com/defender-vulnerability-management/defender-vulnerability-management-capabilities', 'Defender Vulnerability Management plans compared')),
      h('li', {}, link('https://learn.microsoft.com/defender-business/mdb-overview', 'Defender for Business compared with Defender for Endpoint')))),
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
        [h('p', {}, 'On ', h('a', { href: '#scanner' }, 'Get the scanner'), ', choose the file with “Choose a scan file and upload”. Or upload from PowerShell, which also waits for the results file:'), h('pre', { class: 'code' }, `${cmd} -Upload`)],
        'Only that one file is sent, over HTTPS. HeatMap 360 checks that it is a genuine HeatMap 360 scan and turns anything else away, then gives it a scan ID and a private ticket. The ticket stays in your browser (or with the script) and is the only way to fetch this scan’s results. The upload goes into HeatMap 360’s private data store, which starts the processing.'),
      step('Wait while each component is looked up', null,
        [h('span', {}, 'A processing bot checks the upload again, then looks up each component the scan found, one at a time, to find out whether it is current and whether there are known issues with it. ', GUIDE_AI_NOTE, ' Each lookup stands alone: if one source is down, only that part shows “Not checked” and the rest of the results still arrive. This usually takes a few minutes; the page checks for you every 20 seconds.')]),
      step('Get your results',
        h('p', {}, 'When the upload shows “Results ready”, select Download results (.mhtml) and open the file in Edge or Chrome. If you close the page, save the ticket first, or run the scanner with -Resume <scan ID> later.'),
        'HeatMap 360 builds the .mhtml file from the bot’s results: an overall grade, then each area with what was found, what the latest version is, and any known issues or exploited vulnerabilities, with a link to the source where there is one.'),
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

// ---------- How to set up HeatMap 360 (public) ----------
// One page for setting up every part of HeatMap 360, one section per component. Add a section when a component is
// added. No secrets, real computer names or domains here (contoso.example only): this page is public.
const SETUP_PARTS = [
  ['Web app (local copy)', 'A Docker container on the computer that hosts HeatMap 360, built from this repository. Reachable from that computer only.', 'setup-local'],
  ['Web app (hosted copy)', 'Azure Container Apps, scaled to zero when idle. Uploads and results live in a private GitHub repository.', 'setup-hosted'],
  ['Scan processing bot and findings job', 'Node scripts from this repository on the admin desktop: a GitHub self-hosted runner and an hourly Task Scheduler task.', 'setup-hosted'],
  ['AD posture (PingCastle)', 'A weekly Task Scheduler task on the computer that hosts the local copy. Reports stay in a local folder the web app reads.', 'setup-adposture'],
  ['Attack paths (BloodHound CE)', 'Three BloodHound containers beside the local copy, a collector container and a weekly Task Scheduler task. Summaries stay in a local folder the web app reads.', 'setup-attackpaths'],
  ['Attack path report (AD Miner)', 'A container that turns a copy of BloodHound’s data into a rated HTML report, run by hand when a report is wanted. It has no network and never contacts Active Directory. Reports stay in a local folder the web app reads.', 'setup-adminer'],
  ['Entra posture (Maester)', 'A read-only Entra app with a certificate, a Maester container and a weekly Task Scheduler task. Results stay in a local folder the web app reads.', 'setup-entraposture'],
  ['M365 & Azure posture (Monkey365)', 'A read-only Entra app with a certificate, Global Reader and Azure Reader, a Monkey365 container and a weekly Task Scheduler task. Results stay in a local folder the web app reads.', 'setup-cloudposture'],
];
const SETUP_RULES = [
  'Nothing is installed on a computer before it has been discussed and agreed. Prefer containers; anything that must be installed on a machine goes on the lab server, not the computer that hosts HeatMap 360.',
  'Storage is agreed before anything is deployed.',
  'Hosting stays at no cost: free tiers only.',
  'HeatMap 360 only reads and reports. It never fixes, installs or changes anything on the computers and domains it looks at.',
];
function viewSetup() {
  const repo = 'C:\\src\\heatmap-360';
  const code = text => [h('pre', { class: 'code' }, text), h('div', { class: 'row' }, copyButton(() => text))];
  const step = (title, ...body) => h('li', {}, h('strong', {}, title), h('div', { class: 'stack tight' }, body));
  const section = (id, title, sub, ...body) => Object.assign(panel(title, sub, ...body), { id });
  const pcFolder = 'C:\\src\\PingCastle';
  const script = `${repo}\\tools\\adposture\\Invoke-PingCastleScan.ps1`;
  const saveCred = `powershell -NoProfile -ExecutionPolicy Bypass -File "${script}" -SaveCredential`;
  const runOnce = `powershell -NoProfile -ExecutionPolicy Bypass -File "${script}" -Domain contoso.example`;
  const task = [
    `$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "${script}" -Domain contoso.example'`,
    "$trigger  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)",
    "Register-ScheduledTask -TaskName 'HeatMap 360 PingCastle' -Action $action -Trigger $trigger -Settings $settings -Description 'Weekly read-only PingCastle health check for the HeatMap 360 AD posture page'",
  ].join('\n');
  const rebuild = `cd ${repo}\ngit pull\ndocker compose up -d --build`;
  const bhDir = `${repo}\\tools\\bloodhound`;
  const bhScript = `${bhDir}\\Invoke-BloodHoundScan.ps1`;
  const bhEnv = [
    "function New-Secret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }",
    `$envFile = '${bhDir}\\.env'`,
    "\"POSTGRES_PASSWORD=$(New-Secret)`nNEO4J_SECRET=$(New-Secret)`nBH_ADMIN_PASSWORD=$(New-Secret)Aa1!\" | Set-Content $envFile -Encoding ascii",
    'icacls $envFile /inheritance:r /grant:r "${env:USERNAME}:F" "SYSTEM:F"',
  ].join('\n');
  const bhStart = `cd ${bhDir}\ndocker compose up -d`;
  const bhBuild = `docker build -t hm360-bhcollector:1.9.1 ${bhDir}\\collector`;
  const bhRunOnce = `powershell -NoProfile -ExecutionPolicy Bypass -File "${bhScript}" -Domain contoso.example -Server dc01.contoso.example`;
  const bhTask = [
    `$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "${bhScript}" -Domain contoso.example -Server dc01.contoso.example'`,
    "$trigger  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 4am",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)",
    "Register-ScheduledTask -TaskName 'HeatMap 360 BloodHound' -Action $action -Trigger $trigger -Settings $settings -Description 'Weekly read-only BloodHound collection for the HeatMap 360 Attack paths page'",
  ].join('\n');
  const bhRemove = [
    "Unregister-ScheduledTask -TaskName 'HeatMap 360 BloodHound' -Confirm:$false",
    `cd ${bhDir}`,
    'docker compose down -v',
    'docker image rm hm360-bhcollector:1.9.1 specterops/bloodhound:9.9.2 neo4j:4.4.42 postgres:18',
  ].join('\n');
  const amScript = `${bhDir}\\Invoke-ADMinerReport.ps1`;
  const amBuild = `docker build -t hm360-adminer:1.9.0 ${bhDir}\\adminer`;
  const amRun = `powershell -NoProfile -ExecutionPolicy Bypass -File "${amScript}"`;
  const amRemove = [
    'docker ps -aq --filter label=hm360.adminer | ForEach-Object { docker rm -f -v $_ }',
    'docker volume ls -q --filter label=hm360.adminer | ForEach-Object { docker volume rm $_ }',
    'docker image rm hm360-adminer:1.9.0',
  ].join('\n');
  const mtDir = `${repo}\\tools\\entraposture`;
  const mtBuild = `docker build -t hm360-maester:2.3.0 ${mtDir}\\runner`;
  const mtApp = `pwsh -NoProfile -File "${mtDir}\\New-MaesterApp.ps1" -TenantId contoso.example`;
  const mtRunOnce = `powershell -NoProfile -ExecutionPolicy Bypass -File "${mtDir}\\Invoke-MaesterScan.ps1"`;
  const mtTask = [
    `$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "${mtDir}\\Invoke-MaesterScan.ps1"'`,
    "$trigger  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 5am",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)",
    "Register-ScheduledTask -TaskName 'HeatMap 360 Maester' -Action $action -Trigger $trigger -Settings $settings -Description 'Weekly read-only Maester checks of Entra ID and Microsoft 365 for the HeatMap 360 Entra posture page'",
  ].join('\n');
  const mtRemove = [
    "Unregister-ScheduledTask -TaskName 'HeatMap 360 Maester' -Confirm:$false",
    "$cfg = Get-Content -Raw \"$env:LOCALAPPDATA\\HeatMap360\\maester.json\" | ConvertFrom-Json",
    "Connect-MgGraph -TenantId $cfg.tenantId -Scopes Application.ReadWrite.All -NoWelcome",
    "Invoke-MgGraphRequest DELETE \"/v1.0/applications(appId='$($cfg.clientId)')\"",
    'Disconnect-MgGraph | Out-Null',
    'Remove-Item "Cert:\\CurrentUser\\My\\$($cfg.thumbprint)"',
    'Remove-Item "$env:LOCALAPPDATA\\HeatMap360\\maester.json"',
    'docker image rm hm360-maester:2.3.0',
  ].join('\n');
  const mkDir = `${repo}\\tools\\m365posture`;
  const mkBuild = `docker build -t hm360-monkey365:1.0.5 ${mkDir}\\runner`;
  const mkApp = `az login\npwsh -NoProfile -File "${mkDir}\\New-Monkey365App.ps1" -TenantId contoso.example -SubscriptionId 00000000-0000-0000-0000-000000000000`;
  const mkRunOnce = `powershell -NoProfile -ExecutionPolicy Bypass -File "${mkDir}\\Invoke-Monkey365Scan.ps1" -Verbose`;
  const mkTask = [
    `$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "${mkDir}\\Invoke-Monkey365Scan.ps1"'`,
    "$trigger  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 6am",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)",
    "Register-ScheduledTask -TaskName 'HeatMap 360 Monkey365' -Action $action -Trigger $trigger -Settings $settings -Description 'Weekly read-only Monkey365 CIS checks of Exchange Online, Teams, Purview and Azure for the HeatMap 360 M365 & Azure posture page'",
  ].join('\n');
  const mkRemove = [
    "Unregister-ScheduledTask -TaskName 'HeatMap 360 Monkey365' -Confirm:$false",
    "$cfg = Get-Content -Raw \"$env:LOCALAPPDATA\\HeatMap360\\monkey365.json\" | ConvertFrom-Json",
    "foreach ($s in $cfg.subscriptions) { az role assignment delete --assignee $cfg.clientId --role Reader --scope \"/subscriptions/$s\" }",
    "Connect-MgGraph -TenantId $cfg.tenantId -Scopes Application.ReadWrite.All -NoWelcome",
    "Invoke-MgGraphRequest DELETE \"/v1.0/applications(appId='$($cfg.clientId)')\"",
    'Disconnect-MgGraph | Out-Null',
    'Remove-Item "Cert:\\CurrentUser\\My\\$($cfg.thumbprint)"',
    'Remove-Item "$env:LOCALAPPDATA\\HeatMap360\\monkey365.json"',
    'docker image rm hm360-monkey365:1.0.5',
  ].join('\n');
  const mkPermissions = ['AccessReview.Read.All', 'Application.Read.All', 'AuditLog.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'Directory.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'IdentityRiskEvent.Read.All', 'Organization.Read.All', 'OrgSettings-AppsAndServices.Read.All', 'OrgSettings-Forms.Read.All', 'Policy.Read.All', 'Policy.Read.AuthenticationMethod', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAccess.Read.AzureADGroup', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.AzureADGroup', 'SecurityEvents.Read.All', 'User.Read.All', 'UserAuthenticationMethod.Read.All', 'AppCatalog.Read.All', 'Channel.ReadBasic.All', 'ChannelMember.Read.All', 'ChannelSettings.Read.All', 'TeamSettings.Read.All'];
  const mtPermissions = ['AccessReview', 'AuditLog', 'DeviceManagementApps', 'DeviceManagementConfiguration', 'DeviceManagementManagedDevices', 'DeviceManagementRBAC', 'DeviceManagementServiceConfig', 'Directory', 'DirectoryRecommendations', 'EntitlementManagement', 'IdentityRiskEvent', 'NetworkAccess', 'OnPremDirectorySynchronization', 'OrgSettings-AppsAndServices', 'OrgSettings-Forms', 'Policy', 'Reports', 'ReportSettings', 'RoleManagement', 'SecurityIdentitiesSensors', 'SecurityIdentitiesHealth', 'SharePointTenantSettings', 'ThreatHunting', 'UserAuthenticationMethod'].map(p => `${p}.Read.All`)
    .concat(['Policy.Read.ConditionalAccess', 'RoleEligibilitySchedule.Read.Directory', 'RoleManagementAlert.Read.Directory']);
  return [
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'How to set up HeatMap 360'),
      h('p', {}, 'Every part of HeatMap 360, where it runs and how to set it up, in one place. Each section lists what it needs, the steps, where its data is kept and how to remove it.'))),
    h('div', { class: 'grid-2' },
      panel('What runs where', null, h('dl', { class: 'kv' }, SETUP_PARTS.map(([name, text, target]) => [h('dt', {}, h('a', { href: '#setup', 'data-jump': '', onclick: e => { e.preventDefault(); jumpTo(target); } }, name)), h('dd', {}, text)]))),
      panel('House rules', null, h('ul', {}, SETUP_RULES.map(t => h('li', {}, t))))),
    section('setup-local', 'Web app: local copy', 'Docker on the computer that hosts HeatMap 360',
      h('ol', { class: 'steps-list' },
        step('Needs', h('p', {}, 'Docker Desktop (Linux containers), Git, and a copy of this repository in ', h('code', {}, repo), '.')),
        step('Start it', ...code(`cd ${repo}\ndocker compose up -d --build`), h('p', { class: 'muted small' }, 'Then open http://localhost:3460. The local copy needs no sign-in and treats you as an elevated admin, which is only safe because it listens on this computer alone (127.0.0.1). Never publish its port to the network.')),
        step('Update it', ...code(rebuild)),
        step('Data', h('p', {}, h('code', {}, `${repo}\\data\\exchange`), ' holds local uploads and results, ', h('code', {}, `${repo}\\data\\adposture`), ' holds AD posture reports, ', h('code', {}, `${repo}\\data\\attackpaths`), ' holds BloodHound summaries and AD Miner reports, ', h('code', {}, `${repo}\\data\\entraposture`), ' holds Maester results and ', h('code', {}, `${repo}\\data\\m365posture`), ' holds Monkey365 results (all read only inside the container). All are left out of git.')))),
    section('setup-hosted', 'Web app (hosted), bot and findings job', 'Azure Container Apps, GitHub and the admin desktop',
      h('p', {}, 'The hosted copy, the scan processing bot, the findings table and Microsoft 365 service health are set up as described in ', h('code', {}, 'docs/SETUP.md'), ' in this repository: the GitHub repositories and the bot’s data token, the self-hosted runner, the findings job, Entra sign-in with PIM, and the Container Apps settings.'),
      h('p', { class: 'muted small' }, 'The hosted copy has no AD posture page data: AD posture reports never leave the computer that runs the scans.')),
    section('setup-adposture', 'AD posture with PingCastle', 'Weekly, read-only, on the computer that hosts HeatMap 360',
      h('p', {}, 'PingCastle reads Active Directory and scores its risk from 0 to 100 (lower is better) in four areas: stale objects, privileged accounts, trusts and anomalies. A scheduled task runs it once a week and the ', h('a', { href: '#adposture' }, 'AD posture'), ' page shows the scores over time, what was found, what is new and what was fixed.'),
      h('p', { class: 'callout' }, h('strong', {}, 'Why it runs outside the container: '), 'PingCastle is a Windows-only program (.NET Framework). The HeatMap 360 container runs Linux, and switching Docker to Windows containers would stop it. PingCastle needs no installer: it is one unzipped folder (the 4.x download is about 125 MB), removed by deleting the folder.'),
      h('h3', {}, 'What it needs'),
      h('ul', {},
        h('li', {}, 'The computer that hosts HeatMap 360 can reach a domain controller on TCP 389 (LDAP) and 9389 (AD Web Services). It does not need to be joined to the domain.'),
        h('li', {}, 'A plain domain user for PingCastle to sign in with, for example CONTOSO\\svc-hm360-scan. No admin rights: a normal user can read what PingCastle checks. Never use a Domain Admin account for a scheduled scan.'),
        h('li', {}, 'PingCastle (free Basic edition, for auditing your own domain) from pingcastle.com.')),
      h('h3', {}, 'Steps'),
      h('ol', { class: 'steps-list' },
        step('Create the domain account', h('p', {}, 'A domain admin creates a plain user (for example svc-hm360-scan) with a long random password, in no admin groups. Turn off "User must change password at next logon".')),
        step('Download PingCastle', h('p', {}, 'Download the zip from ', link('https://www.pingcastle.com/download/', 'pingcastle.com/download'), ', check it came from there, and unzip it to ', h('code', {}, pcFolder), ' so that ', h('code', {}, `${pcFolder}\\PingCastle.exe`), ' exists.')),
        step('Save the account for the scheduled task', h('p', {}, 'Run this once, as the Windows user the task will run as, and enter DOMAIN\\user and the password. It is saved in a file only that Windows user on that computer can decrypt.'), ...code(saveCred)),
        step('Run one scan by hand', h('p', {}, 'Use your domain name. Add ', h('code', {}, '-Server dc01.contoso.example'), ' to pick a domain controller. A scan takes a few minutes and prints the score when it is done.'), ...code(runOnce),
          h('p', { class: 'muted small' }, 'Then open the AD posture page: the first scan is there.')),
        step('Schedule it weekly', h('p', {}, 'In PowerShell on the same computer, as the same Windows user. It runs every Sunday at 3 AM, or as soon as the computer is on if it was off then. As set up here it runs while that user is signed in.'), ...code(task))),
      h('h3', {}, 'Where the data is kept'),
      h('p', {}, 'Each scan saves three files in ', h('code', {}, `${repo}\\data\\adposture`), ': a summary the page reads (.json), PingCastle’s full report (.html, downloadable from the page) and its raw data (.xml). About 1 to 5 MB per scan, so a year of weekly scans stays well under 1 GB. Nothing goes to the cloud. Delete old files by hand if you want to; the trend shows whatever is left.'),
      h('p', { class: 'callout warn' }, 'These reports name real accounts, groups and servers. Keep the folder on a local disk: not a synced drive, not git, never the public repository.'),
      h('h3', {}, 'Good to know'),
      h('ul', {},
        h('li', {}, 'Read-only: PingCastle’s health check only reads the directory. It changes nothing in the domain.'),
        h('li', {}, 'PingCastle takes the password on its command line, so local administrators of that computer could see it while a scan runs. That is one more reason to use a plain account with no rights.'),
        h('li', {}, 'Antivirus may flag security tools. PingCastle is widely used and normally not flagged; if it is, check the file came from pingcastle.com before allowing it.')),
      h('h3', {}, 'Remove it'),
      ...code("Unregister-ScheduledTask -TaskName 'HeatMap 360 PingCastle' -Confirm:$false"),
      h('p', { class: 'muted small' }, `Then delete ${pcFolder}, the saved account file in %LOCALAPPDATA%\\HeatMap360, and the reports in ${repo}\\data\\adposture, and disable the domain account.`)),
    section('setup-attackpaths', 'Attack paths with BloodHound CE', 'Containers beside HeatMap 360, collected weekly, read-only',
      h('p', {}, 'BloodHound Community Edition maps who can take over Active Directory: chains of group memberships, permissions and sessions that lead to Domain Admins. A weekly task collects the domain, loads it into BloodHound and saves a short summary that the ', h('a', { href: '#attackpaths' }, 'Attack paths'), ' page shows. BloodHound itself, at http://localhost:3461, draws each path as a graph.'),
      h('p', { class: 'callout' }, h('strong', {}, 'Why nothing is installed on a domain computer: '), 'BloodHound runs as three Linux containers next to HeatMap 360 (the BloodHound app, Neo4j and Postgres, about 1.5 GB of images and 2 to 3 GB of memory). The collector is bloodhound-ce-python in a throwaway Linux container instead of SharpHound, so there is no collector program on any Windows computer for antivirus to flag. The trade-off: it does not collect certificate services (AD CS) paths, which only SharpHound does.'),
      h('h3', {}, 'What it needs'),
      h('ul', {},
        h('li', {}, 'The computer that hosts HeatMap 360 can reach a domain controller on TCP 53 (DNS), 88 (Kerberos), 389 (LDAP) and 445 (SMB, for sessions and local groups). It does not need to be joined to the domain.'),
        h('li', {}, 'The same plain domain user as the AD posture scan, for example CONTOSO\\svc-hm360-scan. No admin rights. By default the script reuses the account the AD posture scan saved.'),
        h('li', {}, 'About 2 GB of disk inside Docker for the images and the databases. A small domain’s data is a few MB.')),
      h('h3', {}, 'Steps'),
      h('ol', { class: 'steps-list' },
        step('Make the passwords file', h('p', {}, 'Creates ', h('code', {}, bhDir + '\\.env'), ' with three random passwords: the two databases and BloodHound’s admin account. It is left out of git. Only you can read it.'), ...code(bhEnv)),
        step('Start BloodHound', ...code(bhStart), h('p', { class: 'muted small' }, 'Then open http://localhost:3461 and sign in as admin with BH_ADMIN_PASSWORD from the .env file. It listens on this computer only (127.0.0.1).')),
        step('Build the collector', ...code(bhBuild), h('p', { class: 'muted small' }, 'The image installs bloodhound-ce-python 1.9.1. Domains that require LDAP signing (the Windows Server 2025 default) refuse its plain sign-in, so the image also swaps in ldap3-bleeding-edge, the ldap3 fork bloodhound-ce-python itself points to, and turns on NTLM sealing.')),
        step('Run one collection by hand', h('p', {}, 'Use your domain name and a domain controller. It takes a minute or two for a small domain and prints the counts when it is done. Add ', h('code', {}, '-SaveCredential'), ' (on its own) first if you want a separate account from the AD posture scan.'), ...code(bhRunOnce),
          h('p', { class: 'muted small' }, 'Then open the Attack paths page: the first collection is there.')),
        step('Schedule it weekly', h('p', {}, 'Same computer, same Windows user, Sundays at 4 AM (an hour after PingCastle).'), ...code(bhTask))),
      h('h3', {}, 'Where the data is kept'),
      h('p', {}, 'Each collection saves two files in ', h('code', {}, `${repo}\\data\\attackpaths`), ': the summary the page reads (.json) and the collector’s raw data (.zip, which can be uploaded into BloodHound again). A few hundred KB per collection for a small domain. BloodHound’s own databases live in two Docker volumes (hm360-bloodhound_neo4j-data and hm360-bloodhound_postgres-data). Each run clears BloodHound’s graph and loads the new collection, so it always shows the domain as it is now. Nothing goes to the cloud.'),
      h('p', { class: 'callout warn' }, 'The summaries and zips name real accounts, groups and computers. Keep them on a local disk: not a synced drive, not git, never the public repository.'),
      h('h3', {}, 'Good to know'),
      h('ul', {},
        h('li', {}, 'Read-only: the collector only reads the directory and asks computers the questions any domain user may ask. HeatMap 360 and BloodHound change nothing in the domain.'),
        h('li', {}, 'The password reaches the collector container as an environment variable, never on a command line, and the container is removed after each run.'),
        h('li', {}, 'The collector signs in with NTLM, sealed. Kerberos sign-in to LDAP fails when signing is required, and LDAPS needs a certificate on the domain controller.')),
      h('h3', {}, 'Remove it'),
      ...code(bhRemove),
      h('p', { class: 'muted small' }, `Then delete ${repo}\\data\\attackpaths and ${bhDir}\\.env.`)),
    section('setup-adminer', 'Attack path report with AD Miner', 'A container beside BloodHound, run by hand, on a copy of BloodHound’s data',
      h('p', {}, link('https://github.com/AD-Security/AD_Miner', 'AD Miner'), ' turns the graph BloodHound holds into a report a person can read from top to bottom: about 60 checks, each rated immediate risk, potential risk, minor risk or handled, with the accounts and paths behind every one. The ', h('a', { href: '#attackpaths' }, 'Attack paths'), ' page shows the ratings of the newest report and offers every report as a download.'),
      h('p', { class: 'callout' }, h('strong', {}, 'Why it works on a copy with no network: '), 'AD Miner changes the database it analyses. It adds its own properties and relationships and deletes objects it cannot place, BloodHound’s own bookkeeping record among them. So the script never lets it near BloodHound’s database: it stops BloodHound for about half a minute, copies the Neo4j data volume, starts BloodHound again and runs AD Miner against a throwaway Neo4j on the copy. That pair of containers has no network at all: no internet, no local network, not even this computer. Nothing contacts Active Directory.'),
      h('h3', {}, 'What it needs'),
      h('ul', {},
        h('li', {}, 'BloodHound set up as above, holding at least one collection.'),
        h('li', {}, 'About 310 MB of disk inside Docker for the AD Miner image. During a run, room for a copy of BloodHound’s Neo4j data (about 0.5 GB for a small domain) and memory for a second Neo4j (up to 3 GB) and AD Miner (limit 8 GB).')),
      h('h3', {}, 'Steps'),
      h('ol', { class: 'steps-list' },
        step('Build the AD Miner image', ...code(amBuild), h('p', { class: 'muted small' }, 'The image installs AD Miner 1.9.0 from its release commit on GitHub, with every dependency pinned. AD Miner is licensed GPL-3.0. It runs as its own program in its own container: none of its code is part of HeatMap 360, and the image is built on this computer and not published.')),
        step('Build a report', h('p', {}, 'Run it whenever you want a fresh report, for example after a collection. It takes about a minute for a small domain and prints how AD Miner rated its checks. BloodHound is unavailable for about half a minute while its database is copied; if BloodHound is stopped, the script starts it first.'), ...code(amRun)),
        step('Read it', h('p', {}, 'On the Attack paths page press ', h('strong', {}, 'Download AD Miner report'), ', unzip the file and open ', h('code', {}, 'index.html'), '. The report works without a web server and loads nothing from the internet.'))),
      h('h3', {}, 'Where the data is kept'),
      h('p', {}, 'Each report saves two files in ', h('code', {}, `${repo}\\data\\attackpaths\\adminer`), ': the report (.zip, a few MB for a small domain, larger with the domain) and what the page lists (.json: the rating of each check, no account names). The copy of BloodHound’s database and AD Miner’s working files live in Docker volumes that the script deletes when it finishes, also when it fails. Nothing goes to the cloud. Delete old reports by hand when you no longer need them.'),
      h('p', { class: 'callout warn' }, 'A report is a full map of the domain and its attack paths, with real names. Keep it on a local disk: not a synced drive, not git, never the public repository.'),
      h('h3', {}, 'Good to know'),
      h('ul', {},
        h('li', {}, 'Read-only toward the domain and toward BloodHound: AD Miner only ever sees a copy that is deleted afterwards. The copy is taken while BloodHound is idle and stopped, so do not start a collection while a report is being built.'),
        h('li', {}, 'Repeatable: AD Miner files an object that BloodHound lists under two kinds (a group managed service account is both a user and a computer) under whichever kind comes first, and that order used to change from run to run, moving findings between checks. The script fixes the order (PYTHONHASHSEED=0), so the same data gives the same report. Which kind it picks is still arbitrary: look such accounts up in BloodHound itself.'),
        h('li', {}, 'Handled is not the same as checked: AD Miner rates a check as handled when it finds nothing in the data it was given, also when the collector never gathered that kind of data (for example sessions, local administrators or SMB signing).'),
        h('li', {}, 'A check AD Miner cannot run shows as not evaluated, and the script names it. AD Miner 1.9.0 fails its “Functional level of the domain” check when it cannot rate the level it finds; its scale ends at the level Windows Server 2016, 2019 and 2022 share.'),
        h('li', {}, 'AD Miner puts names and descriptions from the directory into its pages as they are. That is why HeatMap 360 only offers the report as a download and never shows it inside its own pages.'),
        h('li', {}, 'Limits: AD Miner has no time limits of its own, so the script stops it after two hours (', h('code', {}, '-TimeLimitMinutes'), ') and caps its memory at 8 GB (', h('code', {}, '-MemoryGB'), '). Raise both for a large domain. AD Miner 1.9.0 only works with Neo4j 4.4, the version BloodHound’s compose file pins.'),
        h('li', {}, 'If a run is cut short (window closed, computer restarted), the next run removes what it left behind and starts BloodHound again.')),
      h('h3', {}, 'Remove it'),
      ...code(amRemove),
      h('p', { class: 'muted small' }, `Then delete ${repo}\\data\\attackpaths\\adminer.`)),
    section('setup-entraposture', 'Entra posture with Maester', 'Weekly, read-only, in a container on the computer that hosts HeatMap 360',
      h('p', {}, link('https://maester.dev', 'Maester'), ' is a free, open source set of several hundred security checks for Entra ID and Microsoft 365: Conditional Access, authentication methods, privileged roles, app consent, guest access, Intune and more, including the CISA, CIS and EIDSCA baselines. A scheduled task runs it once a week and the ', h('a', { href: '#entraposture' }, 'Entra posture'), ' page shows the pass rate over time, what failed, what is new and what was fixed.'),
      h('p', { class: 'callout' }, h('strong', {}, 'Why a container and a certificate: '), 'Maester is a PowerShell 7 module. It runs in a Linux container (about 530 MB) with Maester 2.3.0, Pester and the Microsoft Graph module inside, so nothing is installed on the computer. It signs in as its own Entra app with a certificate whose private key is kept in your Windows certificate store and cannot be exported. Each week the scan script uses that certificate to get a Graph access token that expires within about an hour, and hands it to the container. There is no client secret anywhere.'),
      h('h3', {}, 'What it needs'),
      h('ul', {},
        h('li', {}, 'A Global Administrator (or Privileged Role Administrator), once, to create the app and grant admin consent. The weekly runs need no admin.'),
        h('li', {}, 'PowerShell 7 with the Microsoft.Graph.Authentication module, for the one-time app setup only. The weekly scan runs in Windows PowerShell and needs no module.'),
        h('li', {}, 'Docker Desktop (Linux containers), the same as the local copy.')),
      h('details', {}, h('summary', {}, `The ${mtPermissions.length} Microsoft Graph permissions the app gets (all read-only)`),
        h('p', { class: 'muted small' }, 'Application permissions, as listed in Maester’s documentation. The setup script refuses any permission that is not a Read permission. It does not grant Maester’s optional ReportSettings.ReadWrite.All, any Exchange, Teams or Azure role, or any Entra directory role.'),
        h('ul', { class: 'cols' }, mtPermissions.map(p => h('li', {}, h('code', {}, p))))),
      h('h3', {}, 'Steps'),
      h('ol', { class: 'steps-list' },
        step('Build the Maester container', ...code(mtBuild), h('p', { class: 'muted small' }, 'Downloads PowerShell 7.4 and the pinned modules from the PowerShell Gallery. A few minutes the first time.')),
        step('Create the read-only app', h('p', {}, 'In PowerShell 7, as the Windows user the weekly task will run as. Use your tenant ID or one of its domain names. A browser window asks you to sign in as a Global Administrator; the sign-in lasts only while the script runs. It makes the certificate, creates the app “HeatMap 360 Maester (read-only)”, grants admin consent and saves the tenant ID, client ID and certificate thumbprint (none secret) to %LOCALAPPDATA%\\HeatMap360\\maester.json.'), ...code(mtApp)),
        step('Run the checks once by hand', h('p', {}, 'Takes 5 to 15 minutes and prints the pass and fail counts when it is done.'), ...code(mtRunOnce),
          h('p', { class: 'muted small' }, 'Then open the Entra posture page: the first run is there.')),
        step('Schedule it weekly', h('p', {}, 'Same computer, same Windows user, Sundays at 5 AM (after PingCastle and BloodHound).'), ...code(mtTask))),
      h('h3', {}, 'Where the data is kept'),
      h('p', {}, 'Each run saves two files in ', h('code', {}, `${repo}\\data\\entraposture`), ': the summary the page reads (.json, the result of each check without its details) and Maester’s full report (.html, downloadable from the page). A few MB per run, so a year of weekly runs stays well under 1 GB. Nothing goes to the cloud.'),
      h('p', { class: 'callout warn' }, 'Maester’s report names real users, groups and policies. Keep the folder on a local disk: not a synced drive, not git, never the public repository.'),
      h('h3', {}, 'Good to know'),
      h('ul', {},
        h('li', {}, 'Read-only: the app can read Entra ID and Microsoft 365 settings and nothing else. HeatMap 360 and Maester change nothing in the tenant. Maester’s telemetry and version check are turned off.'),
        h('li', {}, 'Checks that need a license or a service the tenant does not have, or Exchange Online and Teams (which need extra read-only roles this setup does not grant), show as skipped. The pass rate counts only checks that passed or failed.'),
        h('li', {}, 'The certificate lasts two years. The scan warns 30 days before it expires. To renew, remove the app as below and run step 2 again.'),
        h('li', {}, 'To update Maester, change the version in tools\\entraposture\\runner\\Dockerfile and the scan script, then build again.')),
      h('h3', {}, 'Remove it'),
      h('p', {}, 'In PowerShell 7, signed in as a Global Administrator for the app deletion:'),
      ...code(mtRemove),
      h('p', { class: 'muted small' }, `Then delete ${repo}\\data\\entraposture.`)),
    section('setup-cloudposture', 'M365 & Azure posture with Monkey365', 'Weekly, read-only, in a container on the computer that hosts HeatMap 360',
      h('p', {}, link('https://github.com/silverhack/monkey365', 'Monkey365'), ' is a free, open source (Apache 2.0) PowerShell tool that checks Microsoft 365 and Azure against the CIS Microsoft 365 Foundations (v7) and CIS Microsoft Azure Foundations (v6) benchmarks. A scheduled task runs it once a week and the ', h('a', { href: '#cloudposture' }, 'M365 & Azure posture'), ' page shows the pass rate over time, what failed, what is new and what was fixed.'),
      h('p', { class: 'callout' }, h('strong', {}, 'What it adds to Maester: '), 'Maester covers Entra ID and skips Exchange Online, Teams and Azure because its app has no roles there. Monkey365 covers exactly those: Exchange Online (mail flow, forwarding, auditing, anti-spam and anti-phishing), Teams (external and guest access, meetings, apps), Purview (audit log, retention, data loss prevention) and Azure subscriptions (storage, networking, Key Vault, logging, Defender for Cloud settings). Its Entra ID checks are left off, so the two pages never show the same check.'),
      h('p', { class: 'callout' }, h('strong', {}, 'Why a container and a certificate: '), 'Monkey365 is a PowerShell module. It runs in a Linux container with PowerShell 7.4 and Monkey365 1.0.5 inside, so nothing is installed on the computer. It signs in as its own Entra app with a certificate kept in your Windows certificate store. Because Monkey365 signs in to Exchange, Teams and Azure itself, it needs the certificate, not a token: each week the scan script copies it into the container’s memory, locked with a one-time password, over stdin. It is never written to disk outside the certificate store. There is no client secret anywhere.'),
      h('h3', {}, 'What it needs'),
      h('ul', {},
        h('li', {}, 'A Global Administrator, once, to create the app, grant admin consent and give it Global Reader. An Owner of each Azure subscription, once, to give it Reader (the script does this with the Azure CLI). The weekly runs need no admin.'),
        h('li', {}, 'PowerShell 7 with the Microsoft.Graph.Authentication module and the Azure CLI, for the one-time app setup only. The weekly scan runs in Windows PowerShell and needs no module.'),
        h('li', {}, 'Docker Desktop (Linux containers), the same as the local copy.')),
      h('details', {}, h('summary', {}, `What the app is given (all read-only): ${mkPermissions.length} Microsoft Graph permissions, Exchange.ManageAsApp, Global Reader and Azure Reader`),
        h('ul', {},
          h('li', {}, h('strong', {}, 'Microsoft Graph application permissions: '), 'the ones Monkey365 documents for app-only sign-in, plus its Teams ones. The setup script refuses any Graph permission that is not a Read permission.'),
          h('li', {}, h('strong', {}, 'Office 365 Exchange Online, Exchange.ManageAsApp: '), 'lets the app open Exchange Online and Security & Compliance PowerShell. What it may do there is set by its Entra role, which is Global Reader.'),
          h('li', {}, h('strong', {}, 'Entra role Global Reader: '), 'can see everything a Global Administrator can see and change nothing.'),
          h('li', {}, h('strong', {}, 'Azure role Reader on each subscription you name: '), 'can see resources and settings and change nothing.'),
          h('li', {}, h('strong', {}, 'Not given, on purpose: '), 'SharePoint Online and OneDrive (Monkey365 needs Sites.FullControl.All and SharePoint Administrator for them, which can change sites), Microsoft Fabric, and any write permission.')),
        h('ul', { class: 'cols' }, mkPermissions.map(p => h('li', {}, h('code', {}, p))))),
      h('h3', {}, 'Steps'),
      h('ol', { class: 'steps-list' },
        step('Build the Monkey365 container', ...code(mkBuild), h('p', { class: 'muted small' }, 'Downloads PowerShell 7.4 and Monkey365 1.0.5 from the PowerShell Gallery. A few minutes the first time.')),
        step('Create the read-only app', h('p', {}, 'In PowerShell 7, as the Windows user the weekly task will run as. Use your tenant ID or one of its domain names and the ID of each Azure subscription to check (leave out -SubscriptionId to skip Azure). A browser window asks you to sign in as a Global Administrator; the sign-in lasts only while the script runs. It makes the certificate, creates the app “HeatMap 360 Monkey365 (read-only)”, grants admin consent, gives it Global Reader and Azure Reader, and saves the tenant ID, client ID, certificate thumbprint and subscriptions (none secret) to %LOCALAPPDATA%\\HeatMap360\\monkey365.json.'), ...code(mkApp)),
        step('Run the checks once by hand', h('p', {}, 'Allow 15 to 60 minutes; it prints the pass and fail counts when it is done. Watch Microsoft Defender during this first run.'), ...code(mkRunOnce),
          h('p', { class: 'muted small' }, 'Then open the M365 & Azure posture page: the first run is there.')),
        step('Schedule it weekly', h('p', {}, 'Same computer, same Windows user, Sundays at 6 AM (after PingCastle, BloodHound and Maester).'), ...code(mkTask))),
      h('h3', {}, 'Where the data is kept'),
      h('p', {}, 'Each run saves up to three files in ', h('code', {}, `${repo}\\data\\m365posture`), ': the summary the page reads (.json, one line per rule with how many resources failed it, no resource names) and Monkey365’s full reports for Microsoft 365 and Azure (.html, downloadable from the page). A few MB per run, so a year of weekly runs stays well under 1 GB. Nothing goes to the cloud.'),
      h('p', { class: 'callout warn' }, 'Monkey365’s reports name real mailboxes, users and resources. Keep the folder on a local disk: not a synced drive, not git, never the public repository.'),
      h('h3', {}, 'Good to know'),
      h('ul', {},
        h('li', {}, 'Read-only: Monkey365 states it only reads, and the app can only read. HeatMap 360 and Monkey365 change nothing in the tenant or the subscriptions.'),
        h('li', {}, 'Monkey365’s HTML report loads its styles and scripts from a public CDN when you open it. The page only offers it as a download.'),
        h('li', {}, 'The certificate lasts two years. The scan warns 30 days before it expires. To renew, remove the app as below and run step 2 again.'),
        h('li', {}, 'To update Monkey365, change the version in tools\\m365posture\\runner\\Dockerfile and the scan script, then build again.')),
      h('h3', {}, 'Remove it'),
      h('p', {}, 'In PowerShell 7, signed in with az login and as a Global Administrator for the app deletion:'),
      ...code(mkRemove),
      h('p', { class: 'muted small' }, `Then delete ${repo}\\data\\m365posture.`)),
    h('div', { class: 'row' }, h('a', { class: 'btn primary', href: '#adposture' }, 'Open AD posture'), h('a', { class: 'btn', href: '#attackpaths' }, 'Open Attack paths'), h('a', { class: 'btn', href: '#entraposture' }, 'Open Entra posture'), h('a', { class: 'btn', href: '#cloudposture' }, 'Open M365 & Azure posture'), h('a', { class: 'btn', href: '#overview' }, 'Overview')),
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

// ---------- Inventory catalog: every software, driver and firmware version once, with lookups and history ----------
const CATALOG_CHIP = { Exploited: 'bad', Unsupported: 'bad', Vulnerable: 'bad', 'Known problems': 'warn', Outdated: 'warn', 'Lookup failed': 'warn', Current: 'ok' };
const CATALOG_PROBLEM = new Set(['Exploited', 'Unsupported', 'Vulnerable', 'Known problems', 'Outdated']);
const MATCH_WORD = { strong: 'matched automatically', confirmed: 'confirmed by an admin', proposed: 'proposed, needs your confirmation', rejected: 'rejected: no NVD CVEs are checked', none: 'no NVD product found' };
const CATALOG_ORDER = ['Application', 'Driver', 'Firmware', 'Windows', 'Hardware', 'Disk', 'Network', 'Security'];
const CATALOG_CHANGE = { installed: 'Installed', changed: 'Version changed', removed: 'Removed' };
async function viewCatalog() {
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Inventory catalog'),
    h('p', {}, 'Every software, driver and firmware version seen on a scanned computer, stored once however many computers run it. Each version is checked for updates, known problems and actively exploited vulnerabilities, and keeps its history. HeatMap 360 only reports; fixing belongs to Remediation 360.')));
  if (!me.elevated) return [head, gate()];
  let d = await api('/api/admin/catalog');
  const state = { show: prefs.get('catalog.show', 'problems'), q: '' };
  const body = h('div', { class: 'stack wide-gap' });
  const statusChip = st => chip(CATALOG_CHIP[st] || 'unknown', st || 'Pending');
  const short = m => `${m.slice(0, 8)}…`;
  const seg = options => h('div', { class: 'seg', role: 'group' }, options.map(([v, label]) => h('button', { class: `btn sm${state.show === v ? ' on' : ''}`, 'aria-pressed': String(state.show === v), busy: segBusy('show', label), onclick: () => { state.show = v; prefs.set('catalog.show', v); render(); } }, label)));
  const findings = v => [
    ...v.exploited.map(c => h('div', {}, chip('bad', 'Exploited'), ' ', c.record ? link(c.record, c.cve) : c.cve, c.name ? ` ${c.name}` : '', c.ransomware ? h('span', { class: 'muted' }, ' · ransomware') : null)),
    ...v.issues.map(i => h('div', {}, chip('warn', 'Known problem'), ' ', i.source ? link(i.source, i.title) : i.title)),
    ...(v.cveCount ? [h('div', {}, chip('bad', `${v.cveCount} CVE${v.cveCount === 1 ? '' : 's'}`), ' ', h('span', { class: 'muted' }, `from ${v.cveSource}${v.cveMax ? `, highest CVSS ${v.cveMax}` : ''}`)),
      ...v.cves.slice(0, 8).map(c => h('div', {}, c.record ? link(c.record, c.cve) : c.cve, c.score != null ? ` CVSS ${c.score}` : '', c.kev ? h('span', {}, ' ', chip('bad', 'Exploited')) : null,
        c.fixedIn ? h('span', { class: 'muted' }, ` · fixed in ${c.fixedIn}${c.kb ? ` (${c.kb})` : ''}`) : null)),
      v.cveCount > 8 ? h('div', { class: 'muted' }, `and ${v.cveCount - 8} more`) : null] : []),
  ];
  // Which NVD product the item's CVEs come from. A proposed match is only used once an admin confirms it.
  const productLine = it => {
    const p = it.product;
    if (!p) return null;
    const choice = Object.hasOwn(p, 'choice') ? p.choice : undefined;
    const save = cpe => async () => {
      await api('/api/admin/catalog/products', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: p.key, cpe }) });
      p.choice = cpe; render();
    };
    const status = choice === null ? 'You said this is not the product; no NVD CVEs are checked for it.' : typeof choice === 'string' ? `You confirmed ${choice.replace(/^[aoh]:/, '').replace(':', ' ')}. CVEs follow at the next hourly run.` : `${p.cpe ? p.cpe.replace(/^[aoh]:/, '').replace(':', ' ') : 'No product'}: ${MATCH_WORD[p.status] || p.status}.`;
    const options = choice === undefined && p.status === 'proposed' ? (p.candidates.length ? p.candidates : [{ cpe: p.cpe }]).slice(0, 3) : [];
    return h('div', { class: 'small' }, h('strong', {}, 'NVD product: '), status,
      options.length ? h('div', { class: 'row' }, options.map(c => h('button', { class: 'btn sm', busy: 'Saving…', done: 'Confirmed', onclick: save(c.cpe) }, `Confirm ${String(c.cpe).replace(/^[aoh]:/, '').replace(':', ' ')}`)),
        h('button', { class: 'btn sm', busy: 'Saving…', done: 'Saved', onclick: save(null) }, 'Not this product')) : null,
      choice !== undefined ? h('button', { class: 'btn sm', busy: 'Saving…', done: 'Saved', onclick: save(p.cpe && choice === null ? p.cpe : null) }, choice === null ? 'Use the proposed product again' : 'Not this product') : null);
  };
  const versionRows = it => it.versions.map(v => h('tr', {},
    h('td', {}, h('strong', {}, v.version || 'Unknown'), v.itemDate ? h('div', { class: 'muted small' }, v.itemDate) : null),
    h('td', {}, statusChip(v.status)),
    h('td', { class: 'small' }, v.latest || '', v.latestDate ? h('div', { class: 'muted' }, String(v.latestDate).slice(0, 10)) : null),
    h('td', { class: 'small' }, v.machines.length ? `${v.machines.length} now` : 'None now', h('div', { class: 'muted' }, v.machines.slice(0, 5).map(short).join(', '))),
    h('td', { class: 'small' }, findings(v), v.note ? h('div', { class: 'muted' }, v.note) : null, v.source ? h('div', {}, link(v.source, 'Source')) : null),
    h('td', { class: 'small' }, v.lastChecked ? when(v.lastChecked) : 'Not yet', h('div', { class: 'muted' }, `Seen ${when(v.firstSeen)} to ${when(v.lastSeen)}`))));
  const item = it => fold({ class: 'panel', key: `catalog:${it.kind}:${it.itemKey}` },
    [h('span', { class: 'attn-head' }, statusChip(it.status), h('strong', { class: 'attn-title' }, it.name || it.itemKey)),
      h('span', { class: 'muted small' }, [it.vendor, `${it.versions.length} version${it.versions.length === 1 ? '' : 's'}`, `${new Set(it.versions.flatMap(v => v.machines)).size} computer(s)`].filter(Boolean).join(' · '))],
    productLine(it),
    table(['Version', 'Status', 'Newest', 'Computers', 'Vulnerabilities and known problems', 'Checked'], versionRows(it)),
    h('h3', {}, 'Check history'),
    table(['When', 'Version', 'What changed'], it.history.map(e => h('tr', {}, h('td', { class: 'small' }, when(e.at)), h('td', {}, e.version || ''), h('td', { class: 'small' }, e.source ? link(e.source, e.text) : e.text))), 'No checks recorded yet.'),
    h('h3', {}, 'Install history'),
    table(['When', 'Computer', 'Change'], it.installs.map(e => h('tr', {}, h('td', { class: 'small' }, when(e.at)), h('td', { class: 'small' }, short(e.machine)),
      h('td', { class: 'small' }, CATALOG_CHANGE[e.change] || e.change, ' ', [e.from, e.to].filter(Boolean).join(' → ')))), 'No installs, version changes or removals since the first scan of each computer.'));
  // The search box and buttons are built once, so typing never loses the cursor; render() redraws the rest.
  const segBox = h('span', {});
  const search = h('input', { type: 'search', placeholder: 'Find a name, vendor or version', 'aria-label': 'Find in the catalog', oninput: e => { state.q = e.target.value; render(); } });
  const controls = h('div', { class: 'row spread' }, segBox, search,
    h('button', { class: 'btn sm', busy: 'Loading the catalog…', done: 'Up to date', onclick: async () => { d = await api('/api/admin/catalog'); render(); } }, 'Reload'));
  const stats = h('div', {}), list = h('div', { class: 'stack wide-gap' });
  body.append(stats, controls, list);
  const render = () => {
    const q = state.q.trim().toLowerCase();
    const shown = d.items.filter(it => (state.show === 'all' || CATALOG_PROBLEM.has(it.status)) && (!q || `${it.name} ${it.vendor} ${it.versions.map(v => v.version).join(' ')}`.toLowerCase().includes(q)));
    const n = st => d.items.filter(it => it.status === st).length;
    const cats = [...new Set([...CATALOG_ORDER, ...shown.map(it => it.category || 'Other')])].filter(c => shown.some(it => (it.category || 'Other') === c));
    segBox.replaceChildren(seg([['problems', 'Only problems'], ['all', 'Everything']]));
    stats.replaceChildren(h('div', { class: 'statline' },
      h('div', {}, h('span', { class: 'n' }, d.items.length), h('span', { class: 'l' }, 'Items')),
      h('div', {}, h('span', { class: 'n' }, d.versions), h('span', { class: 'l' }, 'Versions, each stored once')),
      h('div', {}, h('span', { class: 'n' }, n('Exploited')), h('span', { class: 'l' }, 'Exploited')),
      h('div', {}, h('span', { class: 'n' }, n('Vulnerable')), h('span', { class: 'l' }, 'With CVEs')),
      h('div', {}, h('span', { class: 'n' }, n('Outdated') + n('Known problems') + n('Unsupported')), h('span', { class: 'l' }, 'Outdated or known problems')),
      h('div', {}, h('span', { class: 'n' }, d.items.filter(it => it.product?.status === 'proposed' && !Object.hasOwn(it.product, 'choice')).length), h('span', { class: 'l' }, 'Product matches to confirm'))));
    list.replaceChildren(...[
      h('p', { class: 'muted small' }, d.generatedAt ? `${d.machines} computer${d.machines === 1 ? '' : 's'}. Catalog written by the findings job ${when(d.generatedAt)}. It runs every hour and rechecks each version about once a day.` : ''),
      !d.generatedAt ? h('p', { class: 'callout' }, 'No catalog yet. The hourly findings job writes it after its next run; scans uploaded before then are included.')
        : !shown.length ? h('p', { class: 'callout' }, state.show === 'problems' && !q ? 'No item has a known problem. Choose Everything to see the whole catalog.' : 'Nothing matches.')
        : cats.map(c => { const items = shown.filter(it => (it.category || 'Other') === c); return panel(c, `${items.length} item${items.length === 1 ? '' : 's'}`, items.map(item)); })].flat());
  };
  render();
  return [head, body];
}

// ---------- router ----------
// Page loads give the same feedback as buttons: a spinner on the link that was pressed and on the page's rail entry,
// and "Loading <page>…" in the status bar until the page is on screen (or the reason it could not load).
const PAGE_NAMES = { scans: 'Scans', scan: 'the scan', pentests: 'Pen tests', vulnscans: 'Vulnerability scans', adposture: 'AD posture', attackpaths: 'Attack paths', entraposture: 'Entra posture', cloudposture: 'M365 & Azure posture', chaosmonkey: 'Chaos Monkey', setup: 'How to set up', attention: 'High impact', affected: 'Are we affected?', catalog: 'Inventory catalog', cases: 'Incident cases', case: 'the case', cloud: 'Internet - Cloud Services', exploits: 'Internet - Exploits', cves: 'Cloudflare Radar CVEs', patches: 'Internet - Patches',
  x: 'x.com', bluesky: 'Bluesky', services: 'Service health', options: 'Options', actions: 'Options', settings: 'Settings', overview: 'Overview', guide: 'the How To Guide', scanner: 'Get the scanner' };
let pressedLink = null, routeSeq = 0, foldPage = null;
async function route() {
  const hash = location.hash.slice(1) || (me?.elevated ? 'scans' : 'overview');
  const [name, arg] = hash.split('/');
  if (hash !== foldPage) { foldOpen.clear(); foldPage = hash; } // a page opens with every section folded
  const current = name === 'scan' ? 'scans' : name === 'case' ? 'cases' : name === 'actions' ? 'options' : name;
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
    const content = name === 'scan' ? await viewScan(arg) : name === 'options' || name === 'actions' ? viewOptions() : name === 'services' ? await viewServices() : name === 'attention' ? await viewAttention() : name === 'affected' ? await viewAffected() : name === 'catalog' ? await viewCatalog() : name === 'cases' ? await viewCases() : name === 'case' ? await viewCase(arg)
      : Object.hasOwn(NEWS_TITLES, name) ? await viewNews(name) : name === 'cves' ? await viewCves() : name === 'x' ? viewX() : name === 'pentests' ? viewPenTests() : name === 'vulnscans' ? viewVulnScans() : name === 'adposture' ? await viewAdPosture() : name === 'attackpaths' ? await viewAttackPaths() : name === 'entraposture' ? await viewEntraPosture() : name === 'cloudposture' ? await viewM365Posture() : name === 'chaosmonkey' ? viewChaosMonkey() : name === 'setup' ? viewSetup() : name === 'bluesky' ? await viewBluesky() : name === 'settings' ? await viewSettings() : name === 'scanner' ? viewScanner() : name === 'guide' ? viewGuide() : name === 'compare' ? viewCompare() : name === 'overview' ? viewOverview() : await viewScans();
    if (seq !== routeSeq) { act.done(); return; } // a newer page was asked for while this one loaded
    view.classList.toggle('wide', ['services', 'cloud', 'exploits', 'cves', 'patches', 'bluesky', 'attention', 'affected', 'catalog', 'cases', 'case', 'adposture', 'attackpaths', 'entraposture', 'cloudposture', 'chaosmonkey'].includes(name));
    view.replaceChildren(...[content].flat().filter(Boolean));
    // Expand all / Collapse all on every page with more than one section, under the page heading.
    if (view.querySelectorAll('details.fold').length > 1 && !view.querySelector('.fold-bar')) { const top = view.querySelector(':scope > .page-head'); if (top) top.after(foldBar()); else view.prepend(foldBar()); }
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
  const el = e.target.closest?.('#theme-toggle, .nav-label, #nav-toggle, .app-switcher-toggle, a.app-switch-item[href], a[href^="#"]:not([data-jump]), #view summary');
  if (!el || e.defaultPrevented || e.button > 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
  if (el.id === 'theme-toggle') activity.flash(document.documentElement.dataset.theme === 'dark' ? 'Switching to light mode…' : 'Switching to dark mode…');
  else if (el.classList.contains('nav-label')) activity.flash(`${el.getAttribute('aria-expanded') === 'false' ? 'Opening' : 'Closing'} ${el.textContent.trim()}…`);
  else if (el.id === 'nav-toggle') activity.flash(document.body.classList.contains('nav-open') ? 'Closing the menu…' : 'Opening the menu…');
  else if (el.classList.contains('app-switcher-toggle')) activity.flash(el.parentElement.open ? 'Closing the 360 apps list…' : 'Opening the 360 apps list…');
  else if (el.tagName === 'SUMMARY') activity.flash(`${el.parentElement.open ? 'Closing' : 'Opening'} ${foldLabel(el.parentElement)}…`);
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
