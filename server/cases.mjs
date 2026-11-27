// Incident cases: one record per security incident, run through the NIST SP 800-61 incident response lifecycle
// (Detection and Analysis, Containment, Eradication and Recovery, Post-incident activity). A case holds the triage
// (NIST impact categories give the severity and whether to escalate), a playbook checklist per incident type, an
// append-only timeline, and evidence snapshots with a SHA-256 hash so later readers can prove nothing was changed.
//
// HeatMap 360 still never changes a computer: containment and fixes are done in Remediation 360 (Emergency, Changes),
// Entity 360 and Federation 360. The playbooks only link there. Cases live in the data store (cases/<id>.json): the
// local data folder in development, hm-360-data when hosted. Nothing is posted anywhere else.
import { createHash, randomBytes } from 'node:crypto';
import PDFDocument from 'pdfkit';

export const CASE_ID = /^[0-9]{14}-[0-9a-f]{8}$/;
export const newCaseId = (now = new Date()) => `${now.toISOString().replace(/\D/g, '').slice(0, 14)}-${randomBytes(4).toString('hex')}`;

export const PHASES = [
  { id: 'detection', name: 'Detection and analysis', about: 'Confirm it is real, decide how bad it is, and find out what it touches.' },
  { id: 'containment', name: 'Containment', about: 'Stop it spreading: isolate computers, revoke sign-ins, block what it uses.' },
  { id: 'recovery', name: 'Eradication and recovery', about: 'Remove what the attacker left, fix the cause, and bring systems back safely.' },
  { id: 'post', name: 'Post-incident activity', about: 'Write down what happened, why, and what changes so it does not happen again.' },
];
const PHASE_IDS = PHASES.map(p => p.id);

// NIST SP 800-61 Rev. 2, tables 3-2 to 3-4. Severity is the worst category, Critical when two or more are at the top.
export const IMPACT = {
  functional: { label: 'Functional impact', options: [['none', 'None: no effect on services', 0], ['low', 'Low: minimal effect, all critical services still work', 1], ['medium', 'Medium: a critical service is lost for a subset of users', 2], ['high', 'High: a critical service is lost for all users', 3]] },
  information: { label: 'Information impact', options: [['none', 'None: no information taken or changed', 0], ['proprietary', 'Proprietary breach: internal information taken', 2], ['privacy', 'Privacy breach: personal information taken', 3], ['integrity', 'Integrity loss: important information changed or deleted', 3]] },
  recoverability: { label: 'Recoverability', options: [['regular', 'Regular: recovery is predictable with current resources', 0], ['supplemented', 'Supplemented: predictable with more people or tools', 1], ['extended', 'Extended: unpredictable, outside help needed', 2], ['notrecoverable', 'Not recoverable: cannot be recovered (for example data published)', 3]] },
};
export function severity(t) {
  const scores = Object.entries(IMPACT).map(([k, d]) => d.options.find(o => o[0] === t?.[k])?.[2]).filter(n => n != null);
  if (!scores.length) return { level: 'unrated', escalate: false, why: 'Not rated yet.' };
  const max = Math.max(...scores), tops = scores.filter(n => n === 3).length;
  const level = tops >= 2 ? 'critical' : max === 3 ? 'high' : max === 2 ? 'medium' : 'low';
  return { level, escalate: level === 'critical' || level === 'high',
    why: level === 'critical' ? 'Two or more impact categories are at their worst.' : level === 'high' ? 'One impact category is at its worst.' : level === 'medium' ? 'Moderate impact.' : 'Little or no impact.' };
}

// Where to act. HeatMap 360 only links; the other apps run their own approvals.
export const HANDOFF = {
  emergency: { name: 'Remediation 360: Emergency', link: 'http://localhost:3660/#emergency', what: 'Isolate a computer, run an antivirus scan, quarantine a file or collect an investigation package (Defender, second person approves).' },
  change: { name: 'Remediation 360: Changes', link: 'http://localhost:3660/#changes', what: 'Ship a reviewed fix or update to many computers through Intune.' },
  identity: { name: 'Entity 360: Investigate', link: 'http://localhost:3600/#signins', what: 'Sign-ins, risk, sessions, roles and devices for the affected person or app.' },
  federation: { name: 'Federation 360: Playbooks', link: 'http://localhost:5173/#playbooks', what: 'Responding to MFA fatigue, account takeover, stolen tokens and risky app consent.' },
  affected: { name: 'HeatMap 360: Are we affected?', link: '#affected', what: 'Which scanned computers have the vulnerable version.' },
  services: { name: 'HeatMap 360: Service health', link: '#services', what: 'The provider’s own status and updates.' },
};

// Playbook per incident type: steps per phase (each a checklist item) and the apps to hand off to.
const S = (id, phase, text) => ({ id, phase, text });
export const PLAYBOOKS = {
  'exploited-vuln': { name: 'Exploited vulnerability', attack: ['T1190 Exploit Public-Facing Application', 'T1203 Exploitation for Client Execution'], handoff: ['affected', 'change', 'emergency'], steps: [
    S('scope', 'detection', 'List the affected computers and versions on Are we affected?; attach that as evidence.'),
    S('exposed', 'detection', 'Decide which of them are reachable from the internet or hold sensitive data; they come first.'),
    S('signs', 'detection', 'Look for signs it was already used: Defender alerts, unexpected processes or accounts on those computers.'),
    S('mitigate', 'containment', 'Apply the vendor’s workaround or isolate exposed computers until patched (Remediation 360).'),
    S('patch', 'recovery', 'Ship the fixed version (Remediation 360 Changes) and confirm with a new scan that each computer is patched.'),
    S('verify', 'recovery', 'Check Are we affected? again: every computer Patched or Not installed.'),
    S('review', 'post', 'Record how long from CISA listing to every computer patched, and what would make it faster.')] },
  ransomware: { name: 'Ransomware', attack: ['T1486 Data Encrypted for Impact', 'T1490 Inhibit System Recovery', 'T1021 Remote Services'], handoff: ['emergency', 'identity', 'change'], steps: [
    S('confirm', 'detection', 'Confirm encryption or a ransom note; note the first computer and time seen.'),
    S('escalate', 'detection', 'Escalate to security leadership now; ransomware is always high severity.'),
    S('isolate', 'containment', 'Isolate every affected computer (Remediation 360 Emergency); do not power them off, memory is evidence.'),
    S('accounts', 'containment', 'Disable or reset the accounts used and revoke their sessions (Entity 360 shows them).'),
    S('backups', 'containment', 'Protect backups: take them offline or confirm they are immutable.'),
    S('package', 'containment', 'Collect an investigation package from one affected computer before cleaning it.'),
    S('rebuild', 'recovery', 'Rebuild or restore from a known-good backup; patch the way in before reconnecting.'),
    S('review', 'post', 'Record the way in, the dwell time and which control would have stopped it.')] },
  phishing: { name: 'Phishing', attack: ['T1566 Phishing', 'T1204 User Execution'], handoff: ['identity', 'federation', 'emergency'], steps: [
    S('collect', 'detection', 'Get the reported message with full headers; note sender, links and attachments (defanged).'),
    S('who', 'detection', 'Find everyone who received it and who clicked or replied.'),
    S('signins', 'detection', 'Check sign-ins of anyone who clicked for new locations, devices or MFA prompts (Entity 360).'),
    S('purge', 'containment', 'Remove the message from all mailboxes and block the sender, domain and links.'),
    S('reset', 'containment', 'For anyone who entered a password: reset it and revoke sessions; review new MFA methods and inbox rules.'),
    S('scan', 'recovery', 'Scan computers where an attachment was opened (Remediation 360 Emergency).'),
    S('review', 'post', 'Record why filtering missed it and send a short heads-up to staff if it was widespread.')] },
  credential: { name: 'Credential compromise', attack: ['T1078 Valid Accounts', 'T1110 Brute Force', 'T1621 MFA Request Generation', 'T1539 Steal Web Session Cookie'], handoff: ['identity', 'federation', 'emergency'], steps: [
    S('confirm', 'detection', 'Confirm the suspicious sign-ins: location, device, app and MFA result (Entity 360).'),
    S('scope', 'detection', 'List what the account can reach: roles, PIM eligibility, app permissions and mailboxes.'),
    S('revoke', 'containment', 'Reset the password, revoke sessions and refresh tokens, and remove MFA methods the user did not add.'),
    S('persistence', 'containment', 'Look for persistence: inbox rules, app consents, new credentials on apps, new devices.'),
    S('device', 'recovery', 'Scan or reimage the user’s computer if it may hold a token stealer (Remediation 360 Emergency).'),
    S('harden', 'recovery', 'Move the account to phishing-resistant MFA and check Conditional Access covers it.'),
    S('review', 'post', 'Record how the credential was taken and which detection fired first.')] },
  malware: { name: 'Malware on a computer', attack: ['T1204 User Execution', 'T1547 Boot or Logon Autostart Execution', 'T1059 Command and Scripting Interpreter'], handoff: ['emergency', 'identity', 'change'], steps: [
    S('alert', 'detection', 'Read the Defender alert: file, path, hash, how it started and whether it was stopped.'),
    S('spread', 'detection', 'Search for the same hash or behaviour on other computers.'),
    S('isolate', 'containment', 'Isolate the computer and quarantine the file (Remediation 360 Emergency).'),
    S('user', 'containment', 'Reset the user’s password if the malware could read credentials.'),
    S('clean', 'recovery', 'Clean or reimage; scan again; reconnect only when clean.'),
    S('review', 'post', 'Record how it arrived and what would have blocked it.')] },
  disruption: { name: 'Cloud service disruption', attack: [], handoff: ['services'], steps: [
    S('impact', 'detection', 'Confirm which of our users and services are affected, and since when.'),
    S('notify', 'detection', 'Tell affected teams what is down, the workaround and when the next update comes.'),
    S('workaround', 'containment', 'Use the provider’s workaround or fail over where possible.'),
    S('restore', 'recovery', 'Confirm service is back for our users; watch for a recurrence.'),
    S('review', 'post', 'Keep the provider’s post-incident report and note what we would do differently.')] },
};
export const TYPES = Object.keys(PLAYBOOKS);

export const sha256 = data => createHash('sha256').update(canonical(data)).digest('hex');
// Stable JSON (sorted keys) so the same evidence always hashes the same.
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v ?? null);
}

const err = (status, message) => Object.assign(new Error(message), { status });
const text = (v, max, name, required = true) => {
  if (v == null || v === '') { if (required) throw err(400, `${name} is required.`); return ''; }
  if (typeof v !== 'string') throw err(400, `${name} must be text.`);
  const t = v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim();
  if (required && !t) throw err(400, `${name} is required.`);
  if (t.length > max) throw err(400, `${name}: at most ${max} characters.`);
  return t;
};

export function newCase({ title, type, by, now, source = null }) {
  const at = new Date(now).toISOString();
  if (!TYPES.includes(type)) throw err(400, `Type must be one of: ${TYPES.join(', ')}.`);
  return { schema: 'hm360.case/1', id: newCaseId(new Date(now)), title: text(title, 200, 'Title'), type, status: 'open', phase: 'detection',
    createdAt: at, createdBy: by, updatedAt: at, updatedBy: by, version: 1, source,
    triage: { functional: null, information: null, recoverability: null }, checklist: {}, evidence: [], review: null,
    timeline: [{ at, by, kind: 'opened', text: `Case opened as ${PLAYBOOKS[type].name}.` }] };
}

export function addEvidence(c, { label, kind, data, by, now }) {
  const at = new Date(now).toISOString();
  const n = c.evidence.length + 1;
  const e = { id: `E${n}`, at, by, kind, label: text(label, 200, 'Evidence label'), sha256: sha256(data), data };
  c.evidence.push(e);
  c.timeline.push({ at, by, kind: 'evidence', text: `Evidence ${e.id} added: ${e.label} (SHA-256 ${e.sha256.slice(0, 12)}…).` });
  return e;
}

// One change to a case. Closed cases are locked. Every change is recorded on the timeline.
export function applyAction(c, body, { by, now }) {
  if (c.status === 'closed') throw err(409, 'This case is closed and locked. Open a new case if needed.');
  const at = new Date(now).toISOString();
  const log = (kind, t) => c.timeline.push({ at, by, kind, text: t });
  switch (body?.action) {
    case 'note': log('note', text(body.text, 4000, 'Note')); break;
    case 'phase': {
      if (!PHASE_IDS.includes(body.phase)) throw err(400, 'Unknown phase.');
      if (body.phase === c.phase) throw err(400, 'The case is already in that phase.');
      const from = PHASES.find(p => p.id === c.phase).name, to = PHASES.find(p => p.id === body.phase).name;
      c.phase = body.phase;
      log('phase', `Moved from ${from} to ${to}.${body.text ? ` ${text(body.text, 1000, 'Reason', false)}` : ''}`);
      break;
    }
    case 'triage': {
      const t = {};
      for (const k of Object.keys(IMPACT)) {
        const v = body[k];
        if (v != null && !IMPACT[k].options.some(o => o[0] === v)) throw err(400, `${IMPACT[k].label}: unknown value.`);
        t[k] = v ?? null;
      }
      const before = severity(c.triage).level;
      c.triage = t;
      const s = severity(t);
      log('triage', `Triage set: ${Object.keys(IMPACT).map(k => `${IMPACT[k].label.toLowerCase()} ${t[k] ?? 'not rated'}`).join(', ')}. Severity ${s.level}${s.level !== before ? ` (was ${before})` : ''}.${s.escalate ? ' Escalate to security leadership.' : ''}`);
      break;
    }
    case 'check': {
      const step = PLAYBOOKS[c.type].steps.find(s => s.id === body.step);
      if (!step) throw err(400, 'Unknown playbook step.');
      const done = body.done !== false;
      if (done) c.checklist[step.id] = { at, by }; else delete c.checklist[step.id];
      log('checklist', `${done ? 'Done' : 'Not done after all'}: ${step.text}`);
      break;
    }
    case 'close': {
      const review = { summary: text(body.summary, 4000, 'What happened'), cause: text(body.cause, 2000, 'Root cause'), lessons: text(body.lessons, 4000, 'Lessons and improvements') };
      c.review = review; c.status = 'closed'; c.phase = 'post'; c.closedAt = at; c.closedBy = by;
      log('closed', 'Case closed with a post-incident review. The case is now locked.');
      break;
    }
    default: throw err(400, 'Unknown action.');
  }
  c.updatedAt = at; c.updatedBy = by; c.version += 1;
  return c;
}

export function summary(c) {
  const steps = PLAYBOOKS[c.type].steps;
  return { id: c.id, title: c.title, type: c.type, typeName: PLAYBOOKS[c.type].name, status: c.status, phase: c.phase,
    severity: severity(c.triage).level, createdAt: c.createdAt, updatedAt: c.updatedAt, evidence: c.evidence.length,
    steps: { done: steps.filter(s => c.checklist[s.id]).length, total: steps.length } };
}

// Full case for the page, with the playbook and computed severity, and each evidence hash checked again.
export function view(c) {
  return { ...c, severity: severity(c.triage), playbook: { ...PLAYBOOKS[c.type], handoff: PLAYBOOKS[c.type].handoff.map(k => HANDOFF[k]) },
    evidence: c.evidence.map(e => ({ ...e, intact: sha256(e.data) === e.sha256 })) };
}

export const reference = () => ({ phases: PHASES, impact: Object.fromEntries(Object.entries(IMPACT).map(([k, d]) => [k, { label: d.label, options: d.options.map(([v, l]) => [v, l]) }])),
  types: TYPES.map(t => ({ id: t, name: PLAYBOOKS[t].name })) });

// Post-incident review as a PDF (built-in fonts, no external resources).
export function renderCaseReport(c, { now = new Date() } = {}) {
  const C = { ink: '#142026', muted: '#56666e', line: '#d9e0e3', accent: '#0b6e69', bad: '#b3261e' };
  const doc = new PDFDocument({ size: 'LETTER', margin: 48, info: { Title: `HeatMap 360 case ${c.id}`, Author: 'HeatMap 360' } });
  const chunks = [];
  doc.on('data', b => chunks.push(b));
  const done = new Promise(res => doc.on('end', () => res(Buffer.concat(chunks))));
  const W = doc.page.width - 96;
  const h2 = t => { if (doc.y > doc.page.height - 140) doc.addPage(); doc.moveDown(0.8).font('Helvetica-Bold').fontSize(13).fillColor(C.accent).text(t).moveDown(0.3); };
  const p = (t, color = C.ink, size = 10) => doc.font('Helvetica').fontSize(size).fillColor(color).text(String(t ?? ''), { width: W });
  const kv = (k, v) => doc.font('Helvetica-Bold').fontSize(10).fillColor(C.muted).text(`${k}: `, { continued: true }).font('Helvetica').fillColor(C.ink).text(String(v ?? ''));
  const s = severity(c.triage), pb = PLAYBOOKS[c.type];
  doc.font('Helvetica-Bold').fontSize(20).fillColor(C.ink).text(c.status === 'closed' ? 'Post-incident review' : 'Incident case (open)');
  p(`${c.title}`, C.ink, 13);
  p(`Case ${c.id}  ·  PDF made ${now.toISOString()}`, C.muted, 9);
  doc.moveDown(0.5);
  kv('Type', pb.name);
  kv('Severity', `${s.level}${s.escalate ? ' (escalated to security leadership)' : ''}`);
  kv('Phase', PHASES.find(x => x.id === c.phase).name);
  kv('Opened', `${c.createdAt} by ${c.createdBy}`);
  if (c.closedAt) kv('Closed', `${c.closedAt} by ${c.closedBy}`);
  if (pb.attack.length) kv('MITRE ATT&CK', pb.attack.join('; '));
  if (c.review) {
    h2('What happened'); p(c.review.summary);
    h2('Root cause'); p(c.review.cause);
    h2('Lessons and improvements'); p(c.review.lessons);
  }
  h2('Triage (NIST SP 800-61 impact categories)');
  for (const [k, d] of Object.entries(IMPACT)) kv(d.label, d.options.find(o => o[0] === c.triage[k])?.[1] || 'Not rated');
  h2('Playbook');
  for (const ph of PHASES) {
    const steps = pb.steps.filter(x => x.phase === ph.id);
    if (!steps.length) continue;
    doc.font('Helvetica-Bold').fontSize(10).fillColor(C.ink).text(ph.name);
    for (const st of steps) p(`${c.checklist[st.id] ? '[x]' : '[ ]'} ${st.text}${c.checklist[st.id] ? `  (${c.checklist[st.id].at}, ${c.checklist[st.id].by})` : ''}`, C.ink, 9);
    doc.moveDown(0.3);
  }
  h2('Timeline');
  for (const t of c.timeline) p(`${t.at}  ${t.by}: ${t.text}`, C.ink, 9);
  h2('Evidence');
  if (!c.evidence.length) p('No evidence attached.', C.muted);
  for (const e of c.evidence) {
    const ok = sha256(e.data) === e.sha256;
    p(`${e.id}  ${e.label}`, C.ink, 10);
    p(`Added ${e.at} by ${e.by}. SHA-256 ${e.sha256}${ok ? ' (checked: unchanged)' : ' (DOES NOT MATCH: changed after it was added)'}`, ok ? C.muted : C.bad, 8);
  }
  doc.end();
  return done;
}
