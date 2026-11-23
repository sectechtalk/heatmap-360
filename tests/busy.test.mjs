// Every button, link-button and form gives feedback while it works (asked 2026-11-21): one shared mechanism, busy()
// in public/app.js, wired through h(). These checks keep new controls from slipping past it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../public/style.css', import.meta.url), 'utf8');
// The props object of each h('<tag>', { ... }) call, up to its first handler (busy wording is listed before onclick).
const propsOf = tag => [...app.matchAll(new RegExp(`h\\('${tag}', \\{([^]*?)(?:onclick|onsubmit|\\}\\))`, 'g'))].map(m => m[1]);

test('every button built by the app says what it is doing (busy wording), unless it is disabled or a form submit', () => {
  const buttons = propsOf('button');
  assert.ok(buttons.length >= 15, `found ${buttons.length} buttons`);
  for (const p of buttons) assert.match(p, /busy: |disabled: true|type: 'submit'/, `button without busy wording: ${p.trim()}`);
});

test('every form with a submit handler has busy wording for its submit button', () => {
  for (const m of app.matchAll(/h\('form', \{([^]*?)onsubmit/g)) assert.match(m[1], /busy: '/);
});

test('link-buttons either load an in-app page (route feedback) or have busy wording; downloads go through fetch', () => {
  for (const m of app.matchAll(/h\('a', \{ class: '[^']*\bbtn\b[^}]*\}/g)) assert.match(m[0], /href: '#|busy: /, m[0]);
  // saveFile() builds its own invisible download link after the fetch; no visible link-button may be a plain download.
  assert.doesNotMatch(app, /h\('a', \{ class: [^}]*download:/, 'a download link cannot report when it finishes or fails');
});

test('h() routes clicks and submits through busy(), with a default wording for buttons that have none', () => {
  assert.match(app, /withBusy\(e, tag, k, v, props\)/);
  assert.match(app, /props\.busy \|\| 'Working…'/);
  assert.match(app, /act\.fail\(`\$\{word\}: \$\{error\.message\}`\)/, 'a failure is shown with its reason');
});

test('rail and shell controls outside h() and page loads give feedback too', () => {
  for (const sel of ['#theme-toggle', '.nav-label', '#nav-toggle', '.app-switcher-toggle', 'a.app-switch-item[href]']) assert.ok(app.includes(sel), sel);
  assert.match(app, /activity\.start\(`Loading \$\{page\}…`\)/);
});

test('busy styles: spinner, done and failed looks, status bar, reduced motion', () => {
  for (const sel of ['.spinner', '.btn.is-busy', '.btn.is-done', '.btn.is-failed', '.activity.fail .activity-text', 'prefers-reduced-motion']) assert.ok(css.includes(sel), sel);
});
