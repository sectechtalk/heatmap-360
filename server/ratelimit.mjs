// Fixed-window limits kept in memory (one replica). Keys are client IPs as seen by the ingress.
export function createLimiter({ rules, now = () => Date.now(), max = 50_000 }) {
  const hits = new Map(); // key -> [{ start, count }] per rule
  return {
    // Returns null when allowed, or seconds to wait.
    take(key) {
      const t = now();
      if (hits.size > max) hits.clear();
      const list = hits.get(key) || rules.map(() => ({ start: t, count: 0 }));
      let wait = null;
      rules.forEach((r, i) => {
        if (t - list[i].start >= r.windowMs) list[i] = { start: t, count: 0 };
        if (list[i].count >= r.limit) wait = Math.max(wait ?? 0, Math.ceil((list[i].start + r.windowMs - t) / 1000));
      });
      if (wait === null) list.forEach(w => w.count++);
      hits.set(key, list);
      return wait;
    },
  };
}
