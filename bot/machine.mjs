// Machine checks that need no outside source: event log errors and network adapter settings. Pure functions, no I/O.
// The scanner sends event counts per provider and event ID (never message text) and adapter settings from an
// allowlist (never names, addresses or network names).
const DAY = 86_400_000;
const RANK = { ok: 0, info: 0, unknown: 1, warn: 2, bad: 3 };
const worst = list => list.reduce((w, s) => (RANK[s] > RANK[w] ? s : w), 'ok');
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// ---------------------------------------------------------------- event log
// Each rule groups events that mean the same thing to an admin. `grade(count, entries)` decides the status.
const EVENT_RULES = [
  { id: 'bugcheck', label: 'Blue screen crashes', match: e => e.eventId === 1001 && /WER-SystemErrorReporting|BugCheck/i.test(e.provider),
    grade: () => 'bad', advice: 'Windows stopped with a blue screen. Check the drivers and firmware listed below for updates; repeated crashes can mean failing memory or disk.' },
  { id: 'whea', label: 'Hardware errors reported by the processor or chipset', match: e => /WHEA-Logger/i.test(e.provider),
    grade: (n, list) => (list.some(e => e.level !== 'warning') ? 'bad' : n >= 10 ? 'warn' : 'info'),
    advice: 'The hardware reported errors (WHEA). Corrected errors are warnings; uncorrected ones point to a failing component, overheating or unstable overclocking. Check for a BIOS update.' },
  { id: 'storage', label: 'Disk and file system errors', match: e => (/^disk$/i.test(e.provider) && [7, 11, 51, 153].includes(e.eventId)) || (/Ntfs$/i.test(e.provider) && [55, 98, 130, 137].includes(e.eventId)) || (/^(stornvme|storahci|iaStorA?V?)$/i.test(e.provider) && [11, 129].includes(e.eventId)),
    grade: () => 'bad', advice: 'The disk or file system reported errors. Back up the data, check the disk health and firmware, and run chkdsk.' },
  { id: 'unexpected', label: 'Unexpected restarts or power loss', match: e => (/Kernel-Power$/i.test(e.provider) && e.eventId === 41) || (/^EventLog$/i.test(e.provider) && e.eventId === 6008),
    grade: n => (n >= 3 ? 'bad' : 'warn'), advice: 'Windows restarted without shutting down cleanly: a crash, a hang, holding the power button, or lost power.' },
  { id: 'display', label: 'Display driver stopped responding', match: e => /^(Display|nvlddmkm|amdkmdag|igfx)$/i.test(e.provider),
    grade: n => (n >= 3 ? 'warn' : 'info'), advice: 'The graphics driver stopped responding and recovered. Check for a newer display driver.' },
  { id: 'updatefail', label: 'Windows Update installs that failed', match: e => /WindowsUpdateClient$/i.test(e.provider) && e.eventId === 20,
    grade: () => 'warn', advice: 'An update failed to install. Windows usually retries; if it keeps failing, run the Windows Update troubleshooter.' },
  { id: 'services', label: 'Services that failed or stopped unexpectedly', match: e => /^Service Control Manager$/i.test(e.provider) && [7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034].includes(e.eventId),
    grade: n => (n >= 10 ? 'warn' : 'info'), advice: 'Windows services failed to start or stopped unexpectedly. A few after updates are normal; many point to a broken program or driver.' },
  { id: 'appcrash', label: 'Program crashes and hangs', match: e => /^Application (Error|Hang)$/i.test(e.provider) && [1000, 1002].includes(e.eventId),
    grade: n => (n >= 10 ? 'warn' : 'info'), advice: 'Programs crashed or stopped responding. Check the app updates section for newer versions.' },
];
// Known noise: errors Windows logs on healthy computers. They are counted but never graded.
const NOISE = [e => /DistributedCOM$/i.test(e.provider) && [10010, 10016].includes(e.eventId)];

export function eventLogChecks(inv) {
  const log = inv.eventLog;
  if (!log || !Array.isArray(log.entries)) return { status: 'unknown', reason: 'The scan did not include the event log (older scanner, or the log could not be read).', findings: [], other: [] };
  const days = log.days || 7;
  const findings = [];
  const used = new Set();
  for (const rule of EVENT_RULES) {
    const list = log.entries.filter(e => !used.has(e) && rule.match(e));
    if (!list.length) continue;
    list.forEach(e => used.add(e));
    const count = list.reduce((n, e) => n + (e.count || 0), 0);
    const lastSeen = list.map(e => e.lastSeen).filter(Boolean).sort().at(-1) ?? null;
    findings.push({ id: rule.id, label: rule.label, status: rule.grade(count, list), count, lastSeen, advice: rule.advice,
      events: list.map(e => `${e.provider} ${e.eventId}`) });
  }
  const noise = log.entries.filter(e => !used.has(e) && NOISE.some(n => n(e)));
  const other = log.entries.filter(e => !used.has(e) && !noise.includes(e)).sort((a, b) => b.count - a.count);
  findings.sort((a, b) => RANK[b.status] - RANK[a.status] || b.count - a.count);
  const total = log.entries.reduce((n, e) => n + (e.count || 0), 0);
  const graded = findings.filter(f => f.status === 'warn' || f.status === 'bad');
  const reason = !log.entries.length ? `No critical or error events in the last ${days} days.`
    : graded.length ? `${graded.map(f => `${f.label} (${f.count})`).join('; ')} in the last ${days} days.`
      : `${plural(total, 'error event')} in the last ${days} days; none point to a hardware or stability problem.`;
  return { status: 'checked', grade: worst(findings.map(f => f.status)), days, reason, findings, other, noiseCount: noise.reduce((n, e) => n + (e.count || 0), 0) };
}

// ---------------------------------------------------------------- network adapters
const GIGABIT = /gigabit|\bgbe\b|2\.5g|\b5g\b|\b10g|i21[0-9]|i219|i22[56]|rtl8125|rtl8168|rtl8111|aqc1|killer e/i;
const OLD_WIFI = /802\.11\s?(a|b|g|n)\b/i;
const setting = (a, kw) => (a.settings || []).find(s => s.keyword === kw)?.value ?? null;
const isOn = v => v != null && /^(on|enabled?|yes|1)$/i.test(String(v).trim());
const finding = (status, label, detail) => ({ status, label, detail });

function adapterFindings(a, now) {
  const out = [];
  const wired = a.mediaType === '802.3';
  if (wired && a.fullDuplex === false) out.push(finding('bad', 'Half duplex', 'The link is half duplex, which causes collisions and slow transfers. Check the cable, the switch port and the Speed & Duplex setting (should be Auto Negotiation).'));
  if (wired && typeof a.linkSpeedMbps === 'number' && a.linkSpeedMbps > 0) {
    if (a.linkSpeedMbps <= 10) out.push(finding('bad', `Link speed ${a.linkSpeedMbps} Mbps`, 'The adapter connected at 10 Mbps. The cable or switch port is faulty, or speed is forced in the settings.'));
    else if (a.linkSpeedMbps < 1000 && GIGABIT.test(a.description || '')) out.push(finding('warn', `Link speed ${a.linkSpeedMbps} Mbps`, 'This is a gigabit adapter connected at 100 Mbps. Check for a damaged or Cat5 cable (use Cat5e or better), the switch port, and that Speed & Duplex is Auto Negotiation.'));
  }
  const sd = setting(a, '*SpeedDuplex');
  if (sd && !/auto/i.test(sd)) out.push(finding('info', 'Speed forced', `Speed & Duplex is set to "${sd}" instead of Auto Negotiation.`));
  const eee = setting(a, '*EEE') ?? setting(a, 'AdvancedEEE') ?? setting(a, 'EEELinkAdvertisement');
  if (isOn(eee)) out.push(finding('info', 'Energy Efficient Ethernet on', 'If this computer has dropouts or slow wake-ups on the wired network, try turning Energy Efficient Ethernet off.'));
  if (wired && a.powerSaving === 'Enabled') out.push(finding('info', 'Windows may turn this adapter off to save power', 'Fine for laptops. On a desktop with dropouts, clear "Allow the computer to turn off this device" in Device Manager > Power Management.'));
  const date = Date.parse(a.driverDate);
  if (Number.isFinite(date)) {
    const years = (now - date) / (365.25 * DAY);
    if (years > 3) out.push(finding('warn', 'Old driver', `The driver is from ${a.driverDate} (${years.toFixed(1)} years old). Check ${a.driverProvider || 'the adapter vendor'} or the computer maker for a newer one.`));
  }
  return out;
}

export function networkChecks(inv, now = Date.now()) {
  const net = inv.network;
  if (!net || !Array.isArray(net.adapters)) return { status: 'unknown', reason: 'The scan did not include network adapters (older scanner, or they could not be read).', adapters: [], wifi: null };
  const adapters = net.adapters.map(a => {
    const connected = /^up$/i.test(a.status || '');
    const findings = connected ? adapterFindings(a, now) : [];
    return { ...a, connected, findings, grade: connected ? worst(findings.map(f => f.status)) : 'unknown' };
  });
  let wifi = null;
  if (net.wifi) {
    const w = net.wifi, findings = [];
    if (typeof w.signalPercent === 'number') findings.push(w.signalPercent < 40 ? finding('bad', `Weak Wi-Fi signal (${w.signalPercent}%)`, 'Expect slow speeds and dropouts. Move closer to the access point, or add an access point or a wired connection.')
      : w.signalPercent < 60 ? finding('warn', `Fair Wi-Fi signal (${w.signalPercent}%)`, 'Speeds may drop. Moving closer to the access point or using 5 GHz or 6 GHz helps.')
        : finding('ok', `Good Wi-Fi signal (${w.signalPercent}%)`, ''));
    if (w.radioType && OLD_WIFI.test(w.radioType)) findings.push(finding('warn', `Older Wi-Fi standard (${w.radioType})`, 'The connection uses an older Wi-Fi standard. The access point or the adapter may be limiting speed.'));
    if (w.band && /2\.4/.test(w.band)) findings.push(finding('info', 'Connected on 2.4 GHz', '2.4 GHz reaches further but is slower and more crowded than 5 GHz or 6 GHz.'));
    wifi = { ...w, findings, grade: worst(findings.map(f => f.status)) };
  }
  const up = adapters.filter(a => a.connected);
  const grade = worst([...up.map(a => a.grade), wifi?.grade].filter(Boolean));
  const problems = [...up.flatMap(a => a.findings), ...(wifi?.findings || [])].filter(f => f.status === 'warn' || f.status === 'bad');
  const reason = !adapters.length ? 'No physical network adapter was reported.'
    : !up.length ? 'No physical adapter was connected during the scan.'
      : problems.length ? problems.map(f => f.label).join('; ') : `${plural(up.length, 'connected adapter')}, no problems found.`;
  return { status: 'checked', grade: up.length ? grade : 'unknown', reason, adapters, wifi };
}
