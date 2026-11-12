// Reads collector envelopes (schema hm360.envelope/1) from the inbox folder. Newest envelope per host wins.
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

export const SCHEMA = 'hm360.envelope/1';

export async function inboxSignature(dir) {
  try {
    const names = (await readdir(dir)).filter(n => n.endsWith('.json')).sort();
    const parts = await Promise.all(names.map(async n => { const s = await stat(path.join(dir, n)); return `${n}:${s.size}:${s.mtimeMs}`; }));
    return parts.join('|');
  } catch { return 'missing'; }
}

export async function loadInbox(dir) {
  const envelopes = new Map();
  const rejected = [];
  let names = [];
  try { names = (await readdir(dir)).filter(n => n.endsWith('.json')); } catch { return { envelopes: [], rejected }; }
  for (const file of names) {
    try {
      // Windows PowerShell 5.1 writes UTF-8 with a BOM.
      const env = JSON.parse((await readFile(path.join(dir, file), 'utf8')).replace(/^﻿/, ''));
      if (env.schema !== SCHEMA) throw new Error(`schema is not ${SCHEMA}`);
      if (!env.host || !env.collectedAt) throw new Error('host and collectedAt are required');
      const key = String(env.host).toUpperCase();
      const prev = envelopes.get(key);
      if (!prev || Date.parse(env.collectedAt) > Date.parse(prev.collectedAt)) envelopes.set(key, env);
    } catch (err) { rejected.push({ file, error: err.message }); }
  }
  return { envelopes: [...envelopes.values()], rejected };
}
