// HeatMap 360 server.
//   Public:   the scanner download, POST /api/scans (anonymous upload), and each uploader's own status + PDF (by token).
//   Admins:   results pages, only for people signed in with Entra who are ACTIVE members of the HeatMap PIM group.
import express from 'express';
import path from 'node:path';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.mjs';
import { checkInventory } from './schema.mjs';
import { createLimiter } from './ratelimit.mjs';
import { createLocalStore, createGitHubStore } from './datastore.mjs';
import { renderReport } from './report.mjs';
import { createServiceHealth } from './services.mjs';
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

export function createApp({ config = loadConfig(process.env, root), store, auth, sessions = new SessionStore(), now = () => Date.now(), clientScript, serviceHealth } = {}) {
  store ??= config.data.kind === 'github' ? createGitHubStore(config.data) : createLocalStore(config.data.dir);
  // One managed identity (id-heatmap360) for sign-in and for Microsoft 365 service health. Only present when hosted.
  const miToken = config.entra && process.env.IDENTITY_ENDPOINT ? createManagedIdentity({ clientId: config.entra.miClientId }) : null;
  if (auth === undefined && config.entra) auth = createAuth({ config: config.entra, miToken: miToken || createManagedIdentity({ clientId: config.entra.miClientId }) });
  serviceHealth ??= createServiceHealth({ graphToken: miToken });
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
  async function isAdmin(req, force = false) {
    if (config.devAdmin) return true;
    if (!auth || !req.session?.user) return false;
    return auth.elevated(req.session, { force });
  }
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

  // The uploader's token unlocks only that scan's status and PDF.
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
  app.get('/api/scans/:id/report.pdf', async (req, res, next) => {
    try {
      const { id, result: r } = await uploaderRecord(req);
      if (!r) throw err(409, 'Results are not ready yet.');
      res.type('application/pdf').attachment(`HeatMap360-${id}.pdf`).send(await renderReport(r));
    } catch (e) { next(e); }
  });

  // ---------- sign-in ----------
  app.get('/api/me', async (req, res, next) => {
    try {
      const s = req.session;
      const elevated = await isAdmin(req).catch(() => false);
      res.json({ authConfigured: Boolean(auth) || config.devAdmin, dev: config.devAdmin, signedIn: Boolean(s?.user) || config.devAdmin,
        user: s?.user ? { name: s.user.name, upn: s.user.upn } : config.devAdmin ? { name: 'Local developer', upn: '' } : null,
        elevated, activateUrl: PIM_GROUPS_URL, csrf: s?.csrf ?? null, scannerUrl: '/client/Invoke-HeatMapScan.ps1', publicUrl: config.publicUrl });
    } catch (e) { next(e); }
  });
  app.post('/api/me/recheck', csrf, async (req, res, next) => {
    try { res.json({ elevated: await isAdmin(req, true) }); } catch (e) { next(e); }
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
  app.post('/auth/signout', csrf, async (req, res, next) => {
    try { await auth?.signOut(req.session); sessions.destroy(req.session.id); res.append('Set-Cookie', cookieHeader('', 0)); res.json({ ok: true }); } catch (e) { next(e); }
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
  app.get('/api/admin/scans/:id/report.pdf', requireAdmin, async (req, res, next) => {
    try {
      if (!ID.test(req.params.id)) throw err(404, 'Scan not found.');
      const r = await result(req.params.id);
      if (!r) throw err(404, 'Scan not found or not processed yet.');
      res.type('application/pdf').attachment(`HeatMap360-${r.id}.pdf`).send(await renderReport(r));
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
