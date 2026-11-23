// 360 look-and-feel standard (2026-11-15): Inter, the shared type scale and colours, the teal HeatMap accent,
// the 360 app switcher under the brand, a theme toggle that follows the OS, and a menu drawer at phone width.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';
import { switcherHtml } from '../public/shell.js';
import { APPS_360 } from '../public/360-apps.js';

const url = f => new URL(`../public/${f}`, import.meta.url);
const read = f => readFileSync(url(f), 'utf8');
const base = read('360-base.css'), css = read('style.css'), html = read('index.html');

test('360-base.css: seven-step type scale with a 12px floor, self-hosted Inter, shared colour tokens', () => {
  const steps = { xs: '.75rem', sm: '.8125rem', base: '.875rem', md: '1rem', lg: '1.25rem', xl: '1.5rem', '2xl': '1.875rem' };
  for (const [name, size] of Object.entries(steps)) assert.match(base, new RegExp(`--text-${name}:${size.replace('.', '\\.')};`));
  assert.match(base, /@font-face\{font-family:Inter;/);
  assert.ok(existsSync(url('fonts/InterVariable.woff2')), 'font file is self-hosted');
  for (const t of ['--bg', '--surface', '--surface-2', '--line', '--fg', '--muted', '--ok', '--warn', '--crit']) assert.match(base, new RegExp(`${t}:#`), t);
});

test('style.css has balanced braces (a stray } makes the browser drop the next rule)', () => {
  let depth = 0;
  for (const ch of css.replace(/\/\*[\s\S]*?\*\//g, '')) { if (ch === '{') depth++; if (ch === '}') depth--; assert.ok(depth >= 0, 'closing brace with nothing open'); }
  assert.equal(depth, 0);
});

test('style.css uses only the type tokens, Inter and weights 400/500/600, and sets the teal accent', () => {
  assert.deepEqual(css.match(/font(?:-size)?:[^;}]*\d(?:px|pt|rem)\b/g) || [], [], 'font sizes outside the scale');
  assert.doesNotMatch(css, /IBM Plex|Sora|Segoe UI|fonts\.googleapis/, 'only Inter');
  assert.deepEqual((css.match(/font-weight:\s*(\d+)/g) || []).filter(w => !/(400|500|600)$/.test(w)), [], 'weights 400/500/600 only');
  assert.match(css, /--accent: #0b6e69;/);
  assert.match(css, /\.btn\.primary \{ background: var\(--accent-strong\)/);
});

test('index.html loads the shared base before style.css, the theme script in head, and no inline styles (CSP)', () => {
  assert.ok(html.indexOf('href="360-base.css"') > 0 && html.indexOf('href="360-base.css"') < html.indexOf('href="style.css"'));
  assert.match(html, /<script src="theme\.js"><\/script>/);
  assert.match(html, /<script type="module" src="shell\.js"><\/script>/);
  assert.doesNotMatch(html, /style="|<style|fonts\.googleapis/);
  assert.doesNotMatch(read('app.js'), /font-size:\s*\d/);
});

test('rail: app switcher under the brand, theme toggle, and a menu button that controls the rail', () => {
  const rail = html.slice(html.indexOf('<nav class="rail"'), html.indexOf('</nav>'));
  assert.match(rail, /id="rail" data-rail/);
  assert.ok(rail.indexOf('id="app-switcher"') > rail.indexOf('brand-name'), 'switcher sits under the brand');
  assert.match(rail, /<div id="app-switcher" class="app-switcher" data-app="hm-360"><\/div>/);
  assert.match(rail, /<button id="theme-toggle" class="btn" type="button"/);
  for (const m of rail.matchAll(/<a class="nav-item[^"]*" href="#([a-z0-9-]+)" data-route="([a-z0-9-]+)"/g)) assert.equal(m[1], m[2]);
  assert.match(html, /<button id="nav-toggle" class="btn nav-toggle" type="button" aria-controls="rail" aria-expanded="false">/);
});

test('app switcher lists every 360 app, marks HeatMap 360 as here, and never links an app with no URL', () => {
  const out = switcherHtml('hm-360');
  for (const a of APPS_360) assert.ok(out.includes(a.name), a.name);
  assert.match(out, /<span class="app-switch-item" aria-current="page"><strong>HeatMap 360<\/strong>/);
  assert.doesNotMatch(out, /href=""/);
});

test('theme: a stored choice wins, otherwise the OS setting; toggling stores the choice under hm360-theme', () => {
  // theme.js is a classic browser script; run it with a CommonJS-style module object to get its API.
  const mod = { exports: {} }; vm.runInNewContext(read('theme.js'), { module: mod, window: undefined }); const t = mod.exports;
  const store = m => ({ getItem: k => m[k] ?? null, setItem: (k, v) => { m[k] = v; } });
  const os = dark => ({ matchMedia: () => ({ matches: dark }) });
  assert.equal(t.KEY, 'hm360-theme');
  assert.equal(t.initialTheme(store({}), os(true)), 'dark');
  assert.equal(t.initialTheme(store({ 'hm360-theme': 'light' }), os(true)), 'light');
  const m = {}, doc = { documentElement: { dataset: { theme: 'light' } }, getElementById: () => null };
  assert.equal(t.toggleTheme(doc, store(m)), 'dark');
  assert.equal(m['hm360-theme'], 'dark');
});

test('rail: collapsible section headers and a unique shared icon for every page (360 rail standard)', async () => {
  const { ICONS_360 } = await import('../public/360-icons.js');
  const rail = html.slice(html.indexOf('<nav class="rail"'), html.indexOf('</nav>'));
  const pages = [...rail.matchAll(/data-route="([a-z]+)"><span data-nav-icon="([a-z0-9-]+)"><\/span>/g)];
  assert.equal(pages.length, [...rail.matchAll(/class="nav-item/g)].length, 'every page link has an icon');
  const icons = pages.map(m => m[2]);
  assert.deepEqual(icons.filter((n, i) => icons.indexOf(n) !== i), []);
  for (const n of icons) assert.ok(ICONS_360[n], n);
  assert.equal([...rail.matchAll(/<button type="button" class="nav-label" aria-expanded="true" data-section="[a-z-]+"><span>[^<]+<\/span><span class="nav-chevron" aria-hidden="true"><\/span><\/button>/g)].length, 3);
  assert.doesNotMatch(css, /\.nav-(label|item) \{[^}]*font-size/, 'header and link sizes come from 360-base.css');
});

test('New hire is the first rail section, above Results, with Overview, How To Guide and Get the scanner (as in r360)', () => {
  const rail = html.slice(html.indexOf('<nav class="rail"'), html.indexOf('</nav>'));
  const sections = [...rail.matchAll(/data-section="([a-z-]+)"><span>([^<]+)<\/span>/g)].map(m => [m[1], m[2]]);
  assert.deepEqual(sections, [['new-hire', 'New hire'], ['results', 'Results'], ['tools', 'Tools']]);
  assert.doesNotMatch(html, /Get started/);
  const hire = rail.slice(rail.indexOf('data-section="new-hire"'), rail.indexOf('data-section="results"'));
  assert.deepEqual([...hire.matchAll(/data-route="([a-z]+)"/g)].map(m => m[1]), ['overview', 'guide', 'scanner']);
});

test('Overview: routed, the landing page before elevation, explains every area and lists what is not built yet', () => {
  const app = read('app.js');
  assert.match(app, /name === 'overview' \? viewOverview\(\)/);
  assert.match(app, /me\?\.elevated \? 'scans' : 'overview'/);
  assert.match(app, /h\('h1', \{\}, 'Welcome to HeatMap 360'\)/);
  const block = app.slice(app.indexOf('const OVERVIEW_AREAS'), app.indexOf('const OVERVIEW_FIRST_STEPS'));
  for (const route of [...html.matchAll(/data-route="([a-z]+)"/g)].map(m => m[1])) assert.match(block, new RegExp(`'#${route}'`), `Overview describes #${route}`);
  for (const planned of ['Matching scans against the news', 'AI-assisted lookups', 'Posts on the x.com page']) assert.match(app.slice(app.indexOf('const OVERVIEW_NOT_BUILT')), new RegExp(planned));
});

test('How To Guide: routed, linked from the scanner page, and it says lookups find known issues and AI will be used', () => {
  const app = read('app.js');
  const hire = html.slice(html.indexOf('data-section="new-hire"'), html.indexOf('data-section="results"'));
  assert.match(hire, /<a class="nav-item" href="#guide" data-route="guide"><span data-nav-icon="book-open"><\/span>How To Guide<\/a>/);
  assert.match(app, /name === 'guide' \? viewGuide\(\)/);
  assert.match(app, /h\('a', \{ href: '#guide' \}, 'Read the How To Guide'\)/);
  assert.match(app, /const GUIDE_AI_NOTE = 'AI will be used to scan for known issues with each component\.'/);
  assert.match(app, /whether there are known issues with it/);
});
