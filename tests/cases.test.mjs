import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { severity, newCase, applyAction, addEvidence, sha256, canonical, view, summary, PLAYBOOKS, HANDOFF, PHASES, renderCaseReport } from '../server/cases.mjs';
import { createApp } from '../server/index.mjs';
import { loadConfig } from '../server/config.mjs';
import { createLocalStore } from '../server/datastore.mjs';

const NOW = Date.parse('2026-11-26T20:00:00Z');
const opts = { by: 'admin@contoso.example', now: NOW };

test('severity follows the NIST impact categories; high and critical escalate', () => {
  assert.equal(severity({}).level, 'unrated');
  assert.deepEqual(severity({ functional: 'low', information: 'none', recoverability: 'regular' }), { level: 'low', escalate: false, why: 'Little or no impact.' });
  assert.equal(severity({ functional: 'medium' }).level, 'medium');
  assert.equal(severity({ functional: 'high', information: 'none' }).escalate, true);
  assert.equal(severity({ functional: 'high', information: 'privacy' }).level, 'critical');
});

test('every playbook has steps in known phases and hands off only to other apps or HeatMap pages', () => {
  const phases = PHASES.map(p => p.id);
  for (const [id, pb] of Object.entries(PLAYBOOKS)) {
    assert.ok(pb.steps.length >= 4, id);
    for (const s of pb.steps) assert.ok(phases.includes(s.phase), `${id}/${s.id}`);
    assert.equal(new Set(pb.steps.map(s => s.id)).size, pb.steps.length, `${id}: unique step ids`);
    assert.ok(pb.steps.some(s => s.phase === 'post'), `${id}: has a post-incident step`);
    for (const k of pb.handoff) assert.ok(HANDOFF[k], `${id}: ${k}`);
  }
  for (const h of Object.values(HANDOFF)) assert.match(h.link, /^(#|http:\/\/localhost:\d+\/#)/);
});

test('a case runs through the lifecycle, every change is on the timeline, and closing locks it', () => {
  const c = newCase({ title: 'Fabrikam Viewer exploited', type: 'exploited-vuln', ...opts });
  assert.equal(c.phase, 'detection'); assert.equal(c.version, 1);
  applyAction(c, { action: 'triage', functional: 'high', information: 'none', recoverability: 'regular' }, opts);
  assert.match(c.timeline.at(-1).text, /Severity high .*Escalate/);
  applyAction(c, { action: 'check', step: 'scope' }, opts);
  assert.ok(c.checklist.scope);
  applyAction(c, { action: 'phase', phase: 'containment' }, opts);
  applyAction(c, { action: 'note', text: 'Two desktops isolated in Remediation 360.' }, opts);
  assert.throws(() => applyAction(c, { action: 'phase', phase: 'nowhere' }, opts), /Unknown phase/);
  assert.throws(() => applyAction(c, { action: 'check', step: 'nope' }, opts), /Unknown playbook step/);
  assert.throws(() => applyAction(c, { action: 'close', summary: 'x' }, opts), /Root cause is required/);
  applyAction(c, { action: 'close', summary: 'Patched in 2 days.', cause: 'Unpatched viewer.', lessons: 'Auto-update the viewer.' }, opts);
  assert.equal(c.status, 'closed'); assert.equal(c.phase, 'post');
  assert.throws(() => applyAction(c, { action: 'note', text: 'late' }, opts), /closed and locked/);
  assert.deepEqual(c.timeline.map(t => t.kind), ['opened', 'triage', 'checklist', 'phase', 'note', 'closed']);
  assert.equal(summary(c).steps.done, 1);
});

test('evidence is hashed over stable JSON, and a changed copy is caught', () => {
  assert.equal(canonical({ b: 1, a: [2, { d: 1, c: 0 }] }), '{"a":[2,{"c":0,"d":1}],"b":1}');
  const c = newCase({ title: 't', type: 'phishing', ...opts });
  const e = addEvidence(c, { label: 'Headers', kind: 'note', data: { text: 'Received: from mail.contoso.example' }, ...opts });
  assert.equal(e.sha256, sha256({ text: 'Received: from mail.contoso.example' }));
  assert.equal(view(c).evidence[0].intact, true);
  c.evidence[0].data.text = 'tampered';
  assert.equal(view(c).evidence[0].intact, false);
});

test('the post-incident review renders as a PDF', async () => {
  const c = newCase({ title: 'Phish', type: 'phishing', ...opts });
  applyAction(c, { action: 'close', summary: 'One click, no sign-in.', cause: 'Look-alike domain.', lessons: 'Block look-alikes.' }, opts);
  const pdf = await renderCaseReport(c);
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
});

test('API: open from a High impact item with evidence, act with versions, PDF, admins only', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'hm360-cases-'));
  const item = { id: 'kev:CVE-2026-2222', kind: 'exploit', level: 'critical', title: 'Fabrikam Viewer: RCE', cves: ['CVE-2026-2222'], why: [], sources: [], kev: [] };
  const attention = async () => ({ checkedAt: 'x', items: [item], sources: {} });
  const exposure = async () => ({ items: [{ id: item.id, call: 'act-now', counts: { affected: 1 }, machines: [{ machineId: 'aaaaaaaaaaaaaaaa', verdict: 'affected' }, { verdict: 'clear' }] }] });
  const app = createApp({ config: loadConfig({ HM360_DATA_DIR: dir, HM360_DEV_ADMIN: '1' }, dir), store: createLocalStore(dir), clientScript: '', attention, exposure });
  const srv = app.listen(0);
  const url = p => `http://127.0.0.1:${srv.address().port}${p}`;
  const post = (p, body) => fetch(url(p), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    let r = await post('/api/admin/cases', { fromItem: item.id });
    assert.equal(r.status, 201);
    let c = await r.json();
    assert.equal(c.type, 'exploited-vuln'); assert.equal(c.title, item.title);
    assert.equal(c.evidence.length, 1); assert.equal(c.evidence[0].intact, true);
    assert.equal(c.evidence[0].data.affected.machines.length, 1, 'only computers that matched are kept');
    r = await post(`/api/admin/cases/${c.id}/actions`, { version: c.version, action: 'note', text: 'Looking.' });
    assert.equal(r.status, 200); c = await r.json();
    r = await post(`/api/admin/cases/${c.id}/actions`, { version: 1, action: 'note', text: 'Stale.' });
    assert.equal(r.status, 409, 'an old version is refused');
    r = await post(`/api/admin/cases/${c.id}/evidence`, { version: c.version, kind: 'note', label: 'Analyst note', text: 'Defender shows no alert.' });
    assert.equal((await r.json()).evidence.length, 2);
    const list = await (await fetch(url('/api/admin/cases'))).json();
    assert.equal(list.cases.length, 1); assert.equal(list.cases[0].typeName, 'Exploited vulnerability');
    const pdf = await fetch(url(`/api/admin/cases/${c.id}/report.pdf`));
    assert.equal(pdf.headers.get('content-type'), 'application/pdf');
    assert.equal((await fetch(url('/api/admin/cases/../../etc'))).status, 404);
    assert.equal((await post('/api/admin/cases', { title: 'x', type: 'unknown' })).status, 400);
  } finally { srv.close(); }
  const closed = createApp({ config: loadConfig({ HM360_DATA_DIR: dir }, dir), store: createLocalStore(dir), clientScript: '', attention });
  const srv2 = closed.listen(0);
  try { assert.notEqual((await fetch(`http://127.0.0.1:${srv2.address().port}/api/admin/cases`)).status, 200); } finally { srv2.close(); }
});
