// App update status from the winget catalog (Microsoft's winget-pkgs repository on GitHub, where publishers submit
// their releases). The scanner sends each winget package ID with the installed version; the newest version is the
// highest version folder under manifests/<letter>/<Publisher>/<Name>/.
export const WINGET_REPO = 'https://github.com/microsoft/winget-pkgs';

const parts = v => String(v).trim().replace(/^v/i, '').split(/[.\-+_ ]/).filter(Boolean);
export function compareVersions(a, b) {
  const x = parts(a), y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i] ?? '0', q = y[i] ?? '0';
    const np = /^\d+$/.test(p), nq = /^\d+$/.test(q);
    if (np && nq) { const d = BigInt(p) - BigInt(q); if (d) return d > 0n ? 1 : -1; continue; }
    if (np !== nq) return np ? 1 : -1; // 1.0 > 1.0-beta
    const c = p.localeCompare(q, 'en', { sensitivity: 'base' });
    if (c) return c;
  }
  return 0;
}

const isVersionDir = name => /^v?\d/i.test(name);
export const manifestPath = id => `manifests/${id[0].toLowerCase()}/${id.split('.').map(encodeURIComponent).join('/')}`;

export function createWingetLookup({ fetchImpl = (...a) => fetch(...a), token = null } = {}) {
  const cache = new Map();
  return async function latest(id) {
    if (cache.has(id)) return cache.get(id);
    const p = (async () => {
      const r = await fetchImpl(`https://api.github.com/repos/microsoft/winget-pkgs/contents/${manifestPath(id)}`, {
        headers: { accept: 'application/vnd.github+json', 'user-agent': 'hm360-bot', 'x-github-api-version': '2022-11-28', ...(token ? { authorization: `Bearer ${token}` } : {}) },
        signal: AbortSignal.timeout(15_000) });
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`winget catalog lookup failed: HTTP ${r.status}`);
      const dirs = (await r.json()).filter(e => e.type === 'dir' && isVersionDir(e.name)).map(e => e.name);
      return dirs.length ? dirs.sort(compareVersions).at(-1) : null;
    })();
    cache.set(id, p);
    p.catch(() => cache.delete(id));
    return p;
  };
}

// Looks up at most `limit` packages, `concurrency` at a time. Each failure is recorded and the rest continue.
export async function appStatus(winget = [], latest, { limit = 400, concurrency = 6 } = {}) {
  const updates = [], current = [], unchecked = [];
  const queue = winget.slice(0, limit);
  for (const p of winget.slice(limit)) unchecked.push({ id: p.id, installed: p.version, reason: 'Over the per-scan lookup limit' });
  async function one(p) {
    if (p.source && !/^winget$/i.test(p.source)) return unchecked.push({ id: p.id, installed: p.version, reason: `${p.source} apps update through their own store` });
    if (!p.version || /unknown/i.test(p.version) || /^[<>]/.test(p.version)) return unchecked.push({ id: p.id, installed: p.version ?? null, reason: 'Installed version is unknown' });
    try {
      const v = await latest(p.id);
      if (!v) return unchecked.push({ id: p.id, installed: p.version, reason: 'Not found in the winget catalog' });
      (compareVersions(v, p.version) > 0 ? updates : current).push({ id: p.id, installed: p.version, latest: v, link: `${WINGET_REPO}/tree/master/${manifestPath(p.id)}/${encodeURIComponent(v)}` });
    } catch (e) { unchecked.push({ id: p.id, installed: p.version, reason: e.message }); }
  }
  for (let i = 0; i < queue.length; i += concurrency) await Promise.all(queue.slice(i, i + concurrency).map(one));
  const byId = (a, b) => a.id.localeCompare(b.id);
  return { source: WINGET_REPO, checked: updates.length + current.length, updates: updates.sort(byId), current: current.sort(byId), unchecked: unchecked.sort(byId) };
}
