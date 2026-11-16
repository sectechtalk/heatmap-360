import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isActiveMember, checkCallback, userFromClaims, parseCookies } from '../server/auth.mjs';

const G = '11111111-2222-3333-4444-555555555555';

test('elevation = active membership of the HeatMap group, via /me/transitiveMemberOf', async () => {
  let seen;
  const yes = async (url, init) => { seen = { url, init }; return Response.json({ value: [{ id: G }] }); };
  assert.equal(await isActiveMember('tok', G, yes), true);
  assert.match(seen.url, /\/me\/transitiveMemberOf\/microsoft\.graph\.group\?.*\$filter=id eq '11111111/);
  assert.equal(seen.init.headers.consistencylevel, 'eventual');
  assert.equal(await isActiveMember('tok', G, async () => Response.json({ value: [] })), false);
  await assert.rejects(isActiveMember('tok', G, async () => new Response('x', { status: 403 })), /403/);
  await assert.rejects(isActiveMember('tok', "x' or 1 eq 1", async () => Response.json({ value: [] })), /not a group object id/);
});

test('sign-in callback and claims checks', () => {
  const pending = { state: 's', created: Date.now() };
  assert.equal(checkCallback(pending, { state: 's', code: 'c'.repeat(20) }), null);
  assert.match(checkCallback(pending, { state: 'other', code: 'c'.repeat(20) }), /did not match/);
  assert.match(checkCallback({ ...pending, created: 0 }, { state: 's', code: 'c'.repeat(20) }), /expired/);
  assert.throws(() => userFromClaims({ tid: 'b', oid: G }, { tenantId: 'a', clientId: 'c' }), /tenant/);
  assert.equal(userFromClaims({ tid: 'a', aud: 'c', oid: G, name: 'N' }, { tenantId: 'a', clientId: 'c' }).name, 'N');
  assert.deepEqual(parseCookies('a=1; b=%E0%A4%A'), { a: '1' });
});

test('Project 360 Admin check reports its own setting name', async () => {
  await assert.rejects(isActiveMember('tok', 'nope', async () => Response.json({ value: [] }), 'HM360_PROJECT_ADMIN_GROUP_ID'), /HM360_PROJECT_ADMIN_GROUP_ID/);
});
