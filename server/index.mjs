// hm360 server: serves the HeatMap dashboard built from the collector inbox and the free vulnerability feeds.
// Binds to 127.0.0.1 only. Sign-in (Entra, like e360) comes before it is ever exposed beyond this PC.
import express from 'express';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadInbox, inboxSignature } from './store.mjs';
import { buildMachines } from './model.mjs';
import { createFeeds } from './feeds.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = path.resolve(process.env.HM360_DATA || path.join(root, 'data'));

function config() {
  const file = process.env.HM360_CONFIG || path.join(root, 'collectors', 'hm360.config.json');
  try { return JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, '')); } catch { return {}; }
}

export function createApp({ inboxDir = path.join(dataDir, 'inbox'), feeds = createFeeds({ dir: path.join(dataDir, 'feeds') }),
  now = () => Date.now(), cfg = config() } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set({ 'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' });
    next();
  });

  let cache = { key: null, value: null };
  async function machines() {
    const f = await feeds.refresh();
    const key = `${await inboxSignature(inboxDir)}#${f.fetchedAt}`;
    if (cache.key === key) return cache.value;
    const { envelopes, rejected } = await loadInbox(inboxDir);
    cache = { key, value: { ...buildMachines(envelopes, f, now(), cfg), rejected } };
    return cache.value;
  }

  app.get('/api/health', (req, res) => res.json({ ok: true }));
  app.get('/api/machines', async (req, res, next) => { try { res.json(await machines()); } catch (err) { next(err); } });
  app.get('/api/machines/:host', async (req, res, next) => {
    try {
      const m = (await machines()).machines.find(x => x.host.toUpperCase() === req.params.host.toUpperCase());
      m ? res.json(m) : res.status(404).json({ error: 'machine not found' });
    } catch (err) { next(err); }
  });
  app.post('/api/feeds/refresh', async (req, res, next) => {
    try { const f = await feeds.refresh({ force: true }); res.json({ fetchedAt: f.fetchedAt, lastError: f.lastError }); } catch (err) { next(err); }
  });
  app.use(express.static(path.join(root, 'public')));
  app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'internal error' }); });
  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3460), host = process.env.HM360_BIND || '127.0.0.1';
  createApp().listen(port, host, () => console.log(`hm360 on http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`));
}
