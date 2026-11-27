// HeatMap 360 server.
//   Public:   the scanner download, POST /api/scans (anonymous upload), and each uploader's own status + .mhtml results (by token).
//   Admins:   results pages, only for people signed in with Entra who are ACTIVE members of the HeatMap PIM group.
import express from 'express';
import path from 'node:path';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { pipeline } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.mjs';
import { checkInventory } from './schema.mjs';
import { createLimiter } from './ratelimit.mjs';
import { createLocalStore, createGitHubStore } from './datastore.mjs';
import { renderReport } from './report.mjs';
import { createServiceHealth } from './services.mjs';
import { createNews } from './news.mjs';
import { createBluesky } from './bluesky.mjs';
import { createAttention } from './attention.mjs';
import { createExposure } from './exposure.mjs';
import * as cases from './cases.mjs';
import { createCves } from './cves.mjs';
import { createAdPosture } from './adposture.mjs';
import { createAttackPaths } from './attackpaths.mjs';
import { createEntraPosture } from './entraposture.mjs';
import { createM365Posture } from './m365posture.mjs';
import { SessionStore, parseCookies, cookieHeader, SESSION_COOKIE, SESSION_TTL, PIM_GROUPS_URL, createAuth } from './auth.mjs';
import { createManagedIdentity } from './identity.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ID = /^[0-9]{14}-[0-9a-f]{8}$/;
const sha256 = s => createHash('sha256').update(s).digest('hex');
const eqHex = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const err = (status, message) => Object.assign(new Error(message), { status });

export function newScanId(now = new Date()) {
  return `${now.toISOString().replace(/\D/g, '').slice(0, 14)}-${randomBytes(4).toString('hex')}`;
}

// Summary row for the results list (no inventory detail, no token hash).
export function summarize(r) {
  if (r.rejected) return { id: r.id, receivedAt: r.receivedAt, processedAt: r.processedAt, state: 'rejected', reason: r.rejected };
  const inv = r.inventory || {};
  const sys = inv.hardware?.system || {};
  return { id: r.id, state: 'done', receivedAt: r.receivedAt, processedAt: r.processedAt, collectedAt: inv.collectedAt, machineId: inv.machineId,
    computer: [sys.manufacturer, sys.model].filter(Boolean).join(' ') || null,
    windows: inv.os ? `${inv.os.name || 'Windows'} ${inv.os.displayVersion || ''}`.trim() : null,
    build: inv.os ? `${inv.os.build}.${inv.os.ubr ?? 0}` : null, summary: r.summary };
}

export function createApp({ config = loadConfig(process.env, root), store, auth, sessions = new SessionStore(), now = () => Date.now(), clientScript, serviceHealth, news, bluesky, attention, exposure, cves, adposture, attackpaths, entraposture, m365posture } = {}) {
  store ??= config.data.kind === 'github' ? createGitHubStore(config.data) : createLocalStore(config.data.dir);
  // One managed identity (id-heatmap360) for sign-in and for Microsoft 365 service health. Only present when hosted.
  const miToken = config.entra && process.env.IDENTITY_ENDPOINT ? createManagedIdentity({ clientId: config.entra.miClientId }) : null;
  if (auth === undefined && config.entra) auth = createAuth({ config: config.entra, miToken: miToken || createManagedIdentity({ clientId: config.entra.miClientId }) });
  serviceHealth ??= createServiceHealth({ graphToken: miToken });
  news ??= createNews();
  bluesky ??= createBluesky();
  cves ??= createCves();
  attention ??= createAttention({ news, serviceHealth });
  adposture ??= createAdPosture({ dir: config.adposture?.dir });
  attackpaths ??= createAttackPaths({ dir: config.attackpaths?.dir });
  entraposture ??= createEntraPosture({ dir: config.entraposture?.dir });
  m365posture ??= createM365Posture({ dir: config.m365posture?.dir });
  clientScript ??= readFileSync(path.join(root, 'client', 'Invoke-HeatMapScan.ps1'), 'utf8');
  const limiter = createLimiter({ now, rules: [{ windowMs: 600_000, limit: config.limits.perIp10Min }, { windowMs: 86_400_000, limit: config.limits.perIpDay }] });
  const globalLimiter = createLimiter({ now, rules: [{ windowMs: 86_400_000, limit: config.limits.globalDay }] });
  const results = new Map(); // results are immutable once written
  async function result(id) {
    if (results.has(id)) return results.get(id);
    const r = await store.get(`results/${id}.json`);
    if (r) { if (results.size > 2000) results.clear(); results.set(id, r); }
    return r;
  }

  // The newest 200 processed scans (the same window as the Scans page), for "Are we affected?".
  async function recentResults() {
    const done = await store.list('results');
    return (await Promise.all(done.slice(-200).map(n => result(n.slice(0, -5)).catch(() => null)))).filter(Boolean);
  }
  exposure ??= createExposure({ attention, loadScans: recentResults, now });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // Container Apps ingress
  app.use((req, res, next) => {
    res.set({ 'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://login.microsoftonline.com",
      'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' });
    next();
  });

  // ---------- sessions ----------
  app.use((req, res, next) => {
    req.session = sessions.get(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
    next();
  });
  const ensureSession = (req, res) => {
    if (!req.session) { req.session = sessions.create(); res.append('Set-Cookie', cookieHeader(req.session.id, SESSION_TTL / 1000)); }
    return req.session;
  };
  const csrf = (req, res, next) => (req.session && eqHex(req.get('x-csrf') || '', req.session.csrf) ? next() : next(err(403, 'Missing or wrong CSRF token. Reload the page.')));
  const csrfIfSession = (req, res, next) => (req.session || !config.devAdmin ? csrf(req, res, next) : next());
  async function isAdmin(req, force = false) {
    if (config.devAdmin) return true;
    if (!auth || !req.session?.user) return false;
    return auth.elevated(req.session, { force });
  }
  async function isProjectAdmin(req, force = false) {
    if (config.devAdmin) return true;
    if (!auth?.projectAdmin || !req.session?.user) return false;
    return auth.projectAdmin(req.session, { force });
  }
  const requireProjectAdmin = async (req, res, next) => {
    try {
      if (!req.session?.user && !config.devAdmin) throw err(401, 'Sign in first.');
      if (!(await isProjectAdmin(req))) throw err(403, 'Activate your Settings Admin PIM group membership, then check again.');
      next();
    } catch (e) { next(e); }
  };
  const requireAdmin = async (req, res, next) => {
    try {
      if (!req.session?.user && !config.devAdmin) throw err(401, 'Sign in first.');
      if (!(await isAdmin(req))) throw err(403, 'Activate your HeatMap 360 PIM group membership, then check again.');
      next();
    } catch (e) { next(e); }
  };

  app.get('/api/health', (req, res) => res.json({ ok: true }));

  // ---------- public: scanner + upload ----------
  app.get('/client/Invoke-HeatMapScan.ps1', (req, res) => {
    res.type('text/plain').attachment('Invoke-HeatMapScan.ps1').send(clientScript.replace("'__HEATMAP_URL__'", `'${config.publicUrl.replace(/'/g, '')}'`));
  });

  app.post('/api/scans', express.json({ limit: '1mb', type: ['application/json'] }), async (req, res, next) => {
    try {
      const wait = limiter.take(req.ip || 'unknown') ?? globalLimiter.take('all');
      if (wait) { res.set('Retry-After', String(wait)); throw err(429, `Too many uploads. Try again in ${Math.ceil(wait / 60)} minutes.`); }
      const checked = checkInventory(req.body);
      if (!checked.ok) throw err(422, `The upload is not a valid HeatMap 360 inventory: ${checked.error}`);
      const id = newScanId(new Date(now()));
      const token = randomBytes(32).toString('base64url');
      await store.put(`inbox/${id}.json`, { schema: 'hm360.upload/1', id, receivedAt: new Date(now()).toISOString(), tokenHash: sha256(token), inventory: checked.inventory }, `Upload ${id}`);
      res.status(202).json({ id, token, status: `${config.publicUrl}/api/scans/${id}/status` });
    } catch (e) { next(e); }
  });

  // The uploader's token unlocks only that scan's status and .mhtml results.
  async function uploaderRecord(req) {
    const id = req.params.id;
    if (!ID.test(id)) throw err(404, 'Scan not found.');
    const m = String(req.get('authorization') || '').match(/^Bearer ([A-Za-z0-9_-]{43})$/);
    const r = await result(id);
    const record = r || await store.get(`inbox/${id}.json`);
    if (!record || !m || !eqHex(sha256(m[1]), record.tokenHash || '')) throw err(404, 'Scan not found.');
    return { id, result: r };
  }
  app.get('/api/scans/:id/status', async (req, res, next) => {
    try { const { result: r } = await uploaderRecord(req); res.json({ state: r ? (r.rejected ? 'rejected' : 'done') : 'queued', ...(r?.rejected ? { reason: r.rejected } : {}) }); } catch (e) { next(e); }
  });
  app.get('/api/scans/:id/report.mhtml', async (req, res, next) => {
    try {
      const { id, result: r } = await uploaderRecord(req);
      if (!r) throw err(409, 'Results are not ready yet.');
      res.attachment(`HeatMap360-${id}.mhtml`).send(renderReport(r));
    } catch (e) { next(e); }
  });

  // ---------- sign-in ----------
  app.get('/api/me', async (req, res, next) => {
    try {
      const s = req.session;
      // A failed check is not the same as "not a member": say why, so the page can ask for a fresh sign-in.
      let elevationError = null;
      const elevated = await isAdmin(req).catch(e => { elevationError = e.status === 401 ? 'signin' : 'check'; return false; });
      if (elevationError === 'signin' && s) s.user = null;
      const projectAdmin = elevationError ? false : await isProjectAdmin(req).catch(() => false);
      res.json({ authConfigured: Boolean(auth) || config.devAdmin, dev: config.devAdmin, signedIn: Boolean(s?.user) || config.devAdmin, elevationError,
        user: s?.user ? { name: s.user.name, upn: s.user.upn } : config.devAdmin ? { name: 'Local developer', upn: '' } : null,
        elevated, projectAdmin, activateUrl: PIM_GROUPS_URL, csrf: s?.csrf ?? null, scannerUrl: '/client/Invoke-HeatMapScan.ps1', publicUrl: config.publicUrl });
    } catch (e) { next(e); }
  });
  app.post('/api/me/recheck', csrf, async (req, res, next) => {
    try { res.json({ elevated: await isAdmin(req, true), projectAdmin: await isProjectAdmin(req, true).catch(() => false) }); } catch (e) { next(e); }
  });
  app.get('/auth/signin', async (req, res, next) => {
    try { if (!auth) throw err(503, 'Sign-in is not configured (HM360_TENANT_ID, HM360_CLIENT_ID).'); res.redirect(await auth.beginSignIn(ensureSession(req, res))); } catch (e) { next(e); }
  });
  app.get('/auth/callback', async (req, res, next) => {
    try {
      if (!auth || !req.session) throw err(400, 'No sign-in is in progress. Start again.');
      await auth.completeSignIn(req.session, req.query);
      res.redirect('/#scans');
    } catch (e) { next(e); }
  });
  // With no live session (expired, or the app restarted after scaling to zero) there is nothing to protect with CSRF:
  // just clear the cookie so the browser is signed out either way.
  app.post('/auth/signout', (req, res, next) => (req.session ? csrf(req, res, next) : next()), async (req, res, next) => {
    try {
      if (req.session) { await auth?.signOut(req.session); sessions.destroy(req.session.id); }
      res.append('Set-Cookie', cookieHeader('', 0)); res.json({ ok: true });
    } catch (e) { next(e); }
  });

  // ---------- Settings Admins: settings ----------
  // Where the findings table lives (Azure Table Storage account + table). Saved in the data store; the findings job
  // reads it on its next run, so the storage can be moved without a code change. Only names are stored, never keys.
  const SETTINGS = 'settings/findings.json';
  const ACCOUNT = /^[a-z0-9]{3,24}$/, TABLE = /^[A-Za-z][A-Za-z0-9]{2,62}$/;
  app.get('/api/admin/settings', requireProjectAdmin, async (req, res, next) => {
    try {
      const s = await store.get(SETTINGS);
      res.json({ findings: { account: s?.findings?.account ?? null, table: s?.findings?.table ?? 'findings' }, updatedAt: s?.updatedAt ?? null, updatedBy: s?.updatedBy ?? null });
    } catch (e) { next(e); }
  });
  app.put('/api/admin/settings/findings', requireProjectAdmin, csrfIfSession, express.json({ limit: '2kb', type: ['application/json'] }), async (req, res, next) => {
    try {
      const { account, table = 'findings', ...rest } = req.body || {};
      if (Object.keys(rest).length) throw err(400, 'Only account and table can be set.');
      if (typeof account !== 'string' || !ACCOUNT.test(account)) throw err(400, 'Storage account name: 3 to 24 lowercase letters and digits.');
      if (typeof table !== 'string' || !TABLE.test(table)) throw err(400, 'Table name: 3 to 63 letters and digits, starting with a letter.');
      const value = { schema: 'hm360.settings/1', findings: { account, table }, updatedAt: new Date(now()).toISOString(), updatedBy: req.session?.user?.upn || (config.devAdmin ? 'local developer' : null) };
      await store.put(SETTINGS, value, 'Findings storage location');
      res.json({ findings: value.findings, updatedAt: value.updatedAt, updatedBy: value.updatedBy });
    } catch (e) { next(e); }
  });

  // ---------- admins ----------
  app.get('/api/admin/scans', requireAdmin, async (req, res, next) => {
    try {
      const [done, queued] = await Promise.all([store.list('results'), store.list('inbox')]);
      const rows = (await Promise.all(done.slice(-200).reverse().map(n => result(n.slice(0, -5)).then(r => (r ? summarize(r) : null)).catch(() => null)))).filter(Boolean);
      res.json({ scans: rows, queued: queued.map(n => n.slice(0, -5)).reverse() });
    } catch (e) { next(e); }
  });
  app.get('/api/admin/scans/:id', requireAdmin, async (req, res, next) => {
    try {
      if (!ID.test(req.params.id)) throw err(404, 'Scan not found.');
      const r = await result(req.params.id);
      if (!r) throw err(404, 'Scan not found or not processed yet.');
      const { tokenHash, ...safe } = r;
      res.json(safe);
    } catch (e) { next(e); }
  });
  // Public status feeds of online services (Azure, AWS, Google, GitHub, Cloudflare), cached for 5 minutes.
  app.get('/api/admin/services', requireAdmin, async (req, res, next) => {
    try { res.json(await serviceHealth()); } catch (e) { next(e); }
  });
  // Internet pages: latest headlines from each listed source's public RSS/Atom feed, cached for 30 minutes.
  app.get('/api/admin/news/:kind', requireAdmin, async (req, res, next) => {
    try {
      const out = ['cloud', 'exploits', 'patches'].includes(req.params.kind) ? await news(req.params.kind) : null;
      if (!out) throw err(404, 'Unknown page.');
      res.json(out);
    } catch (e) { next(e); }
  });
  // Cloudflare Radar CVEs page: newly published CVEs from Cloudflare Radar's free public JSON feeds, cached 30 minutes.
  app.get('/api/admin/cves', requireAdmin, async (req, res, next) => {
    try { res.json(await cves()); } catch (e) { next(e); }
  });
  // High impact page: new CISA KEV entries, zero-day headlines and long or severe outages, in one short list.
  app.get('/api/admin/attention', requireAdmin, async (req, res, next) => {
    try { res.json(await attention()); } catch (e) { next(e); }
  });
  // "Are we affected?": each High impact exploit matched against the newest scan of every scanned computer.
  app.get('/api/admin/exposure', requireAdmin, async (req, res, next) => {
    try { res.json(await exposure({ fresh: req.query.fresh === '1' })); } catch (e) { next(e); }
  });
  // Inventory catalog: every item version once, with lookups and history (bot/catalog.mjs). The findings job writes the
  // snapshot after each run; until then the page says so.
  const PRODUCTS = 'settings/products.json';
  const productChoices = async () => { const p = await store.get(PRODUCTS); return p?.schema === 'hm360.products/1' && p.choices && typeof p.choices === 'object' ? p : { choices: {} }; };
  app.get('/api/admin/catalog', requireAdmin, async (req, res, next) => {
    try {
      const [snap, p] = await Promise.all([store.get('catalog/catalog.json'), productChoices()]);
      const out = snap?.schema === 'hm360.catalog/1' && Array.isArray(snap.items) ? snap : { schema: 'hm360.catalog/1', generatedAt: null, machines: 0, versions: 0, items: [] };
      // The newest choices, even before the findings job has run again.
      for (const it of out.items) if (it.product?.key && Object.hasOwn(p.choices, it.product.key)) it.product.choice = p.choices[it.product.key];
      res.json(out);
    } catch (e) { next(e); }
  });
  // Confirm a proposed NVD product for an item (cpe "a:vendor:product") or say it is not this product (cpe null). The
  // findings job uses the choice on its next run. Elevated admins only, with the CSRF token.
  const PRODUCT_KEY = /^(app|bios|driver|network-adapter)\|[a-z0-9+#\- ]{0,160}\|[a-z0-9+#\-]{0,40}$/;
  const CPE = /^[aoh]:[a-z0-9][a-z0-9._\-~%!+\\/]{0,99}:[a-z0-9][a-z0-9._\-~%!+\\/]{0,99}$/i;
  app.put('/api/admin/catalog/products', requireAdmin, csrfIfSession, express.json({ limit: '2kb', type: ['application/json'] }), async (req, res, next) => {
    try {
      const { key, cpe, ...rest } = req.body || {};
      if (Object.keys(rest).length || typeof key !== 'string' || !PRODUCT_KEY.test(key) || !(cpe === null || (typeof cpe === 'string' && CPE.test(cpe)))) return res.status(400).json({ error: 'Send a product key and a product name such as a:vendor:product, or null.' });
      const p = await productChoices();
      const choices = { ...p.choices, [key]: cpe };
      if (Object.keys(choices).length > 5000) return res.status(400).json({ error: 'Too many product choices.' });
      const value = { schema: 'hm360.products/1', choices, updatedAt: new Date(now()).toISOString(), updatedBy: req.session?.user?.upn || (config.devAdmin ? 'local developer' : null) };
      await store.put(PRODUCTS, value, 'hm360: product choice');
      res.json({ key, cpe, updatedAt: value.updatedAt });
    } catch (e) { next(e); }
  });
  // ---------- incident cases (server/cases.mjs) ----------
  // Elevated admins open and run cases; every change is on the case's timeline and needs the case's current version,
  // so two people cannot overwrite each other. Closed cases are locked.
  const who = req => req.session?.user?.upn || req.session?.user?.name || (config.devAdmin ? 'local developer' : 'unknown');
  const caseJson = express.json({ limit: '32kb', type: ['application/json'] });
  async function loadCase(id) {
    if (!cases.CASE_ID.test(id)) throw err(404, 'Case not found.');
    const c = await store.get(`cases/${id}.json`);
    if (!c) throw err(404, 'Case not found.');
    return c;
  }
  const checkVersion = (c, body) => { if (body?.version !== c.version) throw err(409, 'Someone changed this case since you opened it. Reload the page and try again.'); };
  // Evidence snapshot: the item as HeatMap 360 sees it right now, so it can be shown unchanged later.
  async function evidenceFrom(body) {
    if (body?.kind === 'high-impact') {
      const [att, exp] = await Promise.all([attention(), exposure().catch(() => null)]);
      const item = att.items.find(i => i.id === body.itemId);
      if (!item) throw err(404, 'That item is no longer on the High impact list.');
      const m = exp?.items.find(i => i.id === item.id);
      const { kev, ...shown } = item;
      return { kind: 'high-impact', label: `High impact: ${item.title}`.slice(0, 200), item,
        data: { capturedAt: new Date(now()).toISOString(), highImpact: shown, affected: m ? { call: m.call, counts: m.counts, machines: m.machines.filter(x => x.verdict !== 'clear') } : null } };
    }
    if (body?.kind === 'scan') {
      if (!ID.test(body.scanId || '')) throw err(404, 'Scan not found.');
      const r = await result(body.scanId);
      if (!r) throw err(404, 'Scan not found.');
      const pick = l => (l || []).map(c => ({ cveID: c.cveID, product: c.app || c.product, version: c.version ?? null, verdict: c.verdict ?? null }));
      return { kind: 'scan', label: `Scan ${r.id}${summarize(r).computer ? ` (${summarize(r).computer})` : ''}`,
        data: { capturedAt: new Date(now()).toISOString(), scan: summarize(r), exploited: { affected: pick(r.exploited?.affected), unverified: pick(r.exploited?.unverified) } } };
    }
    if (body?.kind === 'note') {
      const t = typeof body.text === 'string' ? body.text.trim() : '';
      if (!t || t.length > 8000) throw err(400, 'Evidence text: 1 to 8000 characters.');
      return { kind: 'note', label: typeof body.label === 'string' && body.label.trim() ? body.label : 'Written evidence', data: { capturedAt: new Date(now()).toISOString(), text: t } };
    }
    throw err(400, 'Evidence kind must be high-impact, scan or note.');
  }
  app.get('/api/admin/cases', requireAdmin, async (req, res, next) => {
    try {
      const names = (await store.list('cases')).slice(-300).reverse();
      const rows = (await Promise.all(names.map(n => store.get(`cases/${n}`).then(c => (c ? cases.summary(c) : null)).catch(() => null)))).filter(Boolean);
      rows.sort((a, b) => (a.status === b.status ? 0 : a.status === 'open' ? -1 : 1) || b.updatedAt.localeCompare(a.updatedAt));
      res.json({ cases: rows, reference: cases.reference() });
    } catch (e) { next(e); }
  });
  app.post('/api/admin/cases', requireAdmin, csrfIfSession, caseJson, async (req, res, next) => {
    try {
      const b = req.body || {};
      const ev = b.fromItem ? await evidenceFrom({ kind: 'high-impact', itemId: b.fromItem }) : null;
      const type = b.type || (ev ? (ev.item.kind === 'disruption' ? 'disruption' : 'exploited-vuln') : null);
      const c = cases.newCase({ title: b.title || ev?.item.title, type, by: who(req), now: now(), source: ev ? { kind: 'high-impact', ref: ev.item.id } : null });
      if (ev) cases.addEvidence(c, { label: ev.label, kind: ev.kind, data: ev.data, by: who(req), now: now() });
      await store.put(`cases/${c.id}.json`, c, `Case ${c.id} opened`);
      res.status(201).json(cases.view(c));
    } catch (e) { next(e); }
  });
  app.get('/api/admin/cases/:id', requireAdmin, async (req, res, next) => {
    try { res.json({ ...cases.view(await loadCase(req.params.id)), reference: cases.reference() }); } catch (e) { next(e); }
  });
  app.post('/api/admin/cases/:id/actions', requireAdmin, csrfIfSession, caseJson, async (req, res, next) => {
    try {
      const c = await loadCase(req.params.id);
      checkVersion(c, req.body);
      cases.applyAction(c, req.body, { by: who(req), now: now() });
      await store.put(`cases/${c.id}.json`, c, `Case ${c.id}: ${req.body.action}`);
      res.json(cases.view(c));
    } catch (e) { next(e); }
  });
  app.post('/api/admin/cases/:id/evidence', requireAdmin, csrfIfSession, caseJson, async (req, res, next) => {
    try {
      const c = await loadCase(req.params.id);
      checkVersion(c, req.body);
      if (c.status === 'closed') throw err(409, 'This case is closed and locked.');
      const ev = await evidenceFrom(req.body);
      cases.addEvidence(c, { label: ev.label, kind: ev.kind, data: ev.data, by: who(req), now: now() });
      c.updatedAt = new Date(now()).toISOString(); c.updatedBy = who(req); c.version += 1;
      await store.put(`cases/${c.id}.json`, c, `Case ${c.id}: evidence`);
      res.json(cases.view(c));
    } catch (e) { next(e); }
  });
  app.get('/api/admin/cases/:id/report.pdf', requireAdmin, async (req, res, next) => {
    try {
      const c = await loadCase(req.params.id);
      res.type('application/pdf').attachment(`HeatMap360-case-${c.id}.pdf`).send(await cases.renderCaseReport(c));
    } catch (e) { next(e); }
  });
  // Bluesky page: latest posts from the listed official vendor accounts (free public API, read only), cached 15 minutes.
  app.get('/api/admin/bluesky', requireAdmin, async (req, res, next) => {
    try { res.json(await bluesky.feed()); } catch (e) { next(e); }
  });
  // Replies to one post by a listed account, read on demand. Anything else is 404.
  app.get('/api/admin/bluesky/thread', requireAdmin, async (req, res, next) => {
    try {
      const out = typeof req.query.uri === 'string' && req.query.uri.length <= 200 ? await bluesky.thread(req.query.uri) : null;
      if (!out) throw err(404, 'Unknown post.');
      res.json(out);
    } catch (e) { next(e.status ? e : err(502, 'Could not read the replies from Bluesky.')); }
  });
  // AD posture page: PingCastle scores over time, read from the local AD posture folder (never from the data repo).
  app.get('/api/admin/adposture', requireAdmin, async (req, res, next) => {
    try { res.json(await adposture.list()); } catch (e) { next(e); }
  });
  // PingCastle's own HTML report, only as a download (it carries its own scripts, which this site's CSP would block).
  app.get('/api/admin/adposture/:id/report.html', requireAdmin, async (req, res, next) => {
    try {
      const html = await adposture.report(req.params.id);
      if (!html) throw err(404, 'Report not found.');
      res.type('text/html').attachment(`PingCastle-${req.params.id}.html`).send(html);
    } catch (e) { next(e); }
  });
  // Attack paths page: BloodHound CE summaries, read from the local attack paths folder (never from the data repo).
  app.get('/api/admin/attackpaths', requireAdmin, async (req, res, next) => {
    try { res.json(await attackpaths.list()); } catch (e) { next(e); }
  });
  // AD Miner's report of the same data: a zip of HTML pages with their own scripts, so it is only offered as a download.
  app.get('/api/admin/attackpaths/adminer/:id/report.zip', requireAdmin, async (req, res, next) => {
    try {
      const zip = await attackpaths.reportZip(req.params.id);
      if (!zip) throw err(404, 'Report not found.');
      const file = await open(zip.file, 'r'); // fails here, before any header is set, when the file cannot be read
      res.type('application/zip').attachment(`ADMiner-${req.params.id}.zip`).set('Content-Length', String(zip.size));
      // Streamed, not read into memory: a big domain's report can be hundreds of MB. pipeline() also closes the file when
      // the browser stops early; a failure part-way through cuts the connection, which the page reports as a failed download.
      pipeline(file.createReadStream(), res, () => {});
    } catch (e) { next(e); }
  });
  // Entra posture page: Maester results over time, read from the local Entra posture folder (never from the data repo).
  app.get('/api/admin/entraposture', requireAdmin, async (req, res, next) => {
    try { res.json(await entraposture.list()); } catch (e) { next(e); }
  });
  // Maester's own HTML report, only as a download (it carries its own scripts, which this site's CSP would block).
  app.get('/api/admin/entraposture/:id/report.html', requireAdmin, async (req, res, next) => {
    try {
      const html = await entraposture.report(req.params.id);
      if (!html) throw err(404, 'Report not found.');
      res.type('text/html').attachment(`Maester-${req.params.id}.html`).send(html);
    } catch (e) { next(e); }
  });
  // M365 & Azure posture page: Monkey365 results over time, read from the local M365 posture folder (never the data repo).
  app.get('/api/admin/m365posture', requireAdmin, async (req, res, next) => {
    try { res.json(await m365posture.list()); } catch (e) { next(e); }
  });
  // Monkey365's own HTML report for one area, only as a download (it loads its own scripts, which this site's CSP blocks).
  app.get('/api/admin/m365posture/:id/:area.html', requireAdmin, async (req, res, next) => {
    try {
      const html = await m365posture.report(req.params.id, req.params.area);
      if (!html) throw err(404, 'Report not found.');
      res.type('text/html').attachment(`Monkey365-${req.params.id}-${req.params.area}.html`).send(html);
    } catch (e) { next(e); }
  });
  app.get('/api/admin/scans/:id/report.mhtml', requireAdmin, async (req, res, next) => {
    try {
      if (!ID.test(req.params.id)) throw err(404, 'Scan not found.');
      const r = await result(req.params.id);
      if (!r) throw err(404, 'Scan not found or not processed yet.');
      res.attachment(`HeatMap360-${r.id}.mhtml`).send(renderReport(r));
    } catch (e) { next(e); }
  });

  app.use(express.static(path.join(root, 'public')));
  // eslint-disable-next-line no-unused-vars
  app.use((e, req, res, next) => {
    const status = e.status || e.statusCode || 500;
    if (!e.status && !e.statusCode) console.error(e);
    res.status(status).json({ error: status === 500 ? 'Something went wrong on the server.' : e.type === 'entity.too.large' ? 'The upload is too large (1 MB limit).' : e.message });
  });
  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = loadConfig(process.env, root);
  createApp({ config }).listen(config.port, config.bind, () => console.log(`HeatMap 360 on http://${config.bind === '0.0.0.0' ? 'localhost' : config.bind}:${config.port} (data: ${config.data.kind}${config.devAdmin ? ', DEV ADMIN' : ''})`));
}
