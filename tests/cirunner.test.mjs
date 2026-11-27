import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

test('the security workflow runs every job on the expected runner and pins gitleaks by hash', () => {
  const wf = read('.github/workflows/security.yml');
  const runsOn = wf.match(/runs-on: .*/g);
  assert.equal(runsOn.length, 3);
  for (const r of runsOn) assert.equal(r, 'runs-on: ubuntu-latest');
  assert.match(wf, /sha256sum -c/);
});


