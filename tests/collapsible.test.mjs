// Every headed section on every page is collapsible and starts collapsed (asked 2026-11-27, a standing rule for new
// pages too). One shared mechanism, fold() in public/app.js; panel() is built on it. These checks keep new pages to it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('../public/style.css', import.meta.url), 'utf8');
const foldDef = app.slice(app.indexOf('function fold('), app.indexOf('const panel = '));

test('fold() builds a <details> that starts closed unless it was opened on this page, and remembers what is opened', () => {
  assert.match(foldDef, /h\('details', \{ class: `fold \$\{cls\}`\.trim\(\), id, open: foldOpen\.has\(k\) \}/);
  assert.match(foldDef, /addEventListener\('toggle'/);
  assert.match(app, /const panel = \(title, sub, \.\.\.body\) => fold\(\{ class: 'panel' \}, h\('span', \{ class: 'panel-head' \}, h\('h2', \{\}, title\)/);
});

test('opening a page folds every section again; staying on it (filters, timeframes) keeps what is open', () => {
  assert.match(app, /if \(hash !== foldPage\) \{ foldOpen\.clear\(\); foldPage = hash; \}/);
  assert.ok(app.indexOf('foldOpen.clear()') < app.indexOf("const content = name === 'scan'"), 'cleared before the page is built');
});

test('no section with a heading is built outside fold(): no hand-made panel heads, no headed <section class="panel">', () => {
  const heads = [...app.matchAll(/class: 'panel-head'/g)].length;
  assert.equal(heads, 1, 'only panel() builds a panel heading row');
  for (const m of app.matchAll(/h\('section', \{ class: `?panel[^]*?(?=\n {0,6}\S|$)/g)) assert.doesNotMatch(m[0], /h\('h[1-3]'/, `headed section outside fold(): ${m[0].slice(0, 120)}`);
  assert.doesNotMatch(app, /h\('section', \{ class: '[^']*panel[^']*'[^)]*\}, h\('div', \{ class: '(?:panel-head|row)' \}, h\('h2'/);
});

test('every <details> starts closed: only fold() sets open, and nothing opens a section by default', () => {
  const lines = [...app.matchAll(/h\('details', \{(.*)$/gm)].map(m => m[1]);
  assert.ok(lines.length >= 1);
  for (const l of lines) assert.match(l, /^\s*\}|open: foldOpen\.has\(k\) \}/, `details with its own open state: ${l.slice(0, 120)}`);
  assert.doesNotMatch(app, /open: true/);
});

test('cards that fold (services, news sources, Bluesky accounts, High impact, Chaos Monkey) go through fold()', () => {
  for (const key of ['`svc:${p.id}`', '`news:${s.id}`', '`bsky:${a.id}`', '`attn:${it.kind}:${it.title}`', '`chaos:${key}`']) assert.ok(app.includes(`key: ${key}`), key);
  assert.doesNotMatch(app, /chaos\.open/, 'Chaos Monkey follows the shared rule (starts folded each visit)');
});

test('Expand all / Collapse all: added by route() to every page with more than one section, with busy wording', () => {
  assert.match(app, /view\.querySelectorAll\('details\.fold'\)\.length > 1 && !view\.querySelector\('\.fold-bar'\)/);
  assert.match(app, /busy: 'Expanding…', onclick: \(\) => setFolds\(true\)/);
  assert.match(app, /busy: 'Collapsing…', onclick: \(\) => setFolds\(false\)/);
});

test('opening or closing a section says so, and in-page links open the section they point at', () => {
  assert.match(app, /#view summary'\);/);
  assert.match(app, /activity\.flash\(`\$\{el\.parentElement\.open \? 'Closing' : 'Opening'\} \$\{foldLabel\(el\.parentElement\)\}…`\)/);
  assert.doesNotMatch(app, /getElementById\(target\)\?\.scrollIntoView/, 'jump links go through jumpTo(), which opens the section first');
  assert.match(app, /function jumpTo\(id\)/);
});

test('fold styles: hidden browser marker, a chevron that turns, keyboard focus ring, reduced motion', () => {
  for (const sel of ['details.fold:not(.svc) > summary::-webkit-details-marker', 'details.fold:not(.svc)[open] > summary::before', 'details.fold:not(.svc) > summary:focus-visible', 'details.fold > summary::before { transition: none; }']) assert.ok(css.includes(sel), sel);
});
