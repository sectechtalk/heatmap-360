// Network health measured by the scanner: ping to the gateway, connection time and speed to Cloudflare's public
// speed test, DNS lookup time. Pure functions, no I/O. Thresholds are for an office or home connection.
const RANK = { ok: 0, info: 0, unknown: 1, warn: 2, bad: 3 };
const worst = list => list.reduce((w, s) => (RANK[s] > RANK[w] ? s : w), 'ok');
const check = (id, label, status, detail) => ({ id, label, status, detail });
const ms = v => `${v} ms`;

export function networkHealthChecks(inv) {
  const nh = inv.networkHealth;
  if (!nh) return { status: 'unknown', reason: 'The scan did not include network health (older scanner, or it could not be measured).', checks: [] };
  const out = [];
  const g = nh.gateway, viaWifi = nh.via === 'wifi';
  if (!g) out.push(check('gateway', 'Computer to router (gateway)', 'unknown', 'No default gateway was found.'));
  else if (!g.received) out.push(check('gateway', 'Computer to router (gateway)', 'unknown', 'The router does not answer ping; many block it, so this is not a fault by itself.'));
  else {
    const lossBad = g.lossPercent >= 10, lossWarn = g.lossPercent > 0;
    const slow = g.avgMs > 100 ? 'bad' : g.avgMs > (viaWifi ? 30 : 10) ? 'warn' : 'ok';
    const jitter = g.jitterMs > 30 ? 'warn' : 'ok';
    const status = worst([lossBad ? 'bad' : lossWarn ? 'warn' : 'ok', slow, jitter]);
    const where = viaWifi ? 'over Wi-Fi' : nh.via === 'wired' ? 'over a cable' : '';
    const advice = status === 'ok' ? '' : viaWifi ? ' Delays or loss this close to home point to weak Wi-Fi or interference: move closer, use 5 GHz, or use a cable.' : ' On a cable this points to a faulty cable, switch port or an overloaded router.';
    out.push(check('gateway', 'Computer to router (gateway)', status, `${ms(g.avgMs)} average, ${ms(g.jitterMs ?? 0)} jitter, ${g.lossPercent}% lost of ${g.sent} pings ${where}.${advice}`.replace(' .', '.')));
  }
  const i = nh.internet;
  if (i?.received) {
    const status = worst([i.lossPercent >= 30 ? 'bad' : i.lossPercent > 0 ? 'warn' : 'ok', i.avgMs > 250 ? 'bad' : i.avgMs > 100 ? 'warn' : 'ok']);
    out.push(check('internet', 'Connection time to the internet', status, `${ms(i.avgMs)} average to speed.cloudflare.com, ${i.received} of ${i.sent} connections made.`));
  } else if (i) out.push(check('internet', 'Connection time to the internet', 'bad', 'Could not connect to speed.cloudflare.com (no internet, or a firewall blocks it).'));
  if (nh.dns) out.push(check('dns', 'DNS lookup', !nh.dns.ok ? 'bad' : nh.dns.ms > 1000 ? 'bad' : nh.dns.ms > 200 ? 'warn' : 'ok',
    nh.dns.ok ? `${ms(nh.dns.ms)} to look up www.microsoft.com.${nh.dns.ms > 200 ? ' Slow lookups make every website feel slow; check the DNS server the router hands out.' : ''}` : 'The lookup failed: DNS is not working on this computer or network.'));
  const s = nh.speed;
  if (s) {
    out.push(check('download', 'Download speed', s.downloadMbps < 3 ? 'bad' : s.downloadMbps < 10 ? 'warn' : 'ok', `${s.downloadMbps} Mbps${s.downloadMbps < 100 ? ' (below the FCC broadband benchmark of 100 Mbps)' : ''}`));
    out.push(check('upload', 'Upload speed', s.uploadMbps < 1 ? 'bad' : s.uploadMbps < 3 ? 'warn' : 'ok', `${s.uploadMbps} Mbps${s.uploadMbps < 20 ? ' (below the FCC broadband benchmark of 20 Mbps)' : ''}`));
  } else out.push(check('speed', 'Download and upload speed', 'unknown', nh.speedSkipped ? 'Skipped (-SkipSpeedTest).' : 'Could not be measured.'));
  const known = out.filter(c => c.status !== 'unknown');
  const problems = out.filter(c => c.status === 'warn' || c.status === 'bad');
  const reason = problems.length ? `${problems.map(c => c.label).join('; ')} ${problems.length === 1 ? 'needs' : 'need'} attention.`
    : s ? `${s.downloadMbps} Mbps down, ${s.uploadMbps} Mbps up; no network problems found.` : 'No network problems found.';
  return { status: 'checked', grade: known.length ? worst(known.map(c => c.status)) : 'unknown', reason, via: nh.via ?? null, server: s?.server ?? null, checks: out };
}
