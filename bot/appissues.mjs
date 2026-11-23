// Known issues for app updates, from the publisher's own release notes:
//   1. the winget catalog's locale manifest for that exact version (ReleaseNotes is the publisher's text, with the
//      publisher's ReleaseNotesUrl), read from raw.githubusercontent.com (no API rate limit);
//   2. when the notes point to a GitHub release of the app's own repository, that release's notes on GitHub.
// Only a section the publisher titles "Known issues" (or "Unresolved", "Known problems", "Known limitations") counts.
// Checked for the installed version and for the update winget would install. Pure functions except the lookups.
import { manifestPath } from './apps.mjs';

export const WINGET_RAW = 'https://raw.githubusercontent.com/microsoft/winget-pkgs/master';

// Minimal reader for the flat YAML winget manifests use: a top-level key with a plain, quoted or block (| >) value.
export function yamlValue(text, key) {
  const lines = String(text).split(/\r?\n/);
  const i = lines.findIndex(l => l.startsWith(`${key}:`));
  if (i < 0) return null;
  const rest = lines[i].slice(key.length + 1).trim();
  const body = [];
  for (let j = i + 1; j < lines.length && (lines[j] === '' || /^\s/.test(lines[j])); j++) body.push(lines[j]);
  while (body.length && !body.at(-1).trim()) body.pop();
  if (/^[|>][-+]?$/.test(rest)) {
    const indent = Math.min(...body.filter(l => l.trim()).map(l => l.match(/^ */)[0].length));
    return body.map(l => l.slice(Number.isFinite(indent) ? indent : 0)).join('\n');
  }
  if (rest.startsWith('"')) {
    const raw = [rest, ...body.map(l => l.trim())].join(' ').replace(/"\s*$/, '').slice(1);
    return raw.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  if (rest.startsWith("'")) return [rest, ...body.map(l => l.trim())].join(' ').replace(/'\s*$/, '').slice(1).replace(/''/g, "'");
  if (rest.startsWith('#')) return null;
  return [rest, ...body.map(l => l.trim())].join(' ').replace(/\s+#.*$/, '').trim() || null;
}

const HEADING = /^(?:#{1,6}\s*)?(?:\*\*|__)?\s*(known issues?|known problems?|known bugs?|known limitations?|unresolved(?: issues)?)\s*:?\s*(?:\*\*|__)?\s*:?\s*$/i;
const INLINE = /^(?:\*\*|__)?known issues?(?:\*\*|__)?\s*:\s*(?:\*\*|__)?\s*(.{3,})$/i;
const BULLET = /^\s*(?:[-*•+]|\d{1,2}[.)])\s+/;
const NONE = /^(none|n\/?a|no known issues?|none known|nothing)\.?$/i;
const clean = s => s.replace(BULLET, '').replace(/!\[[^\]]*\]\([^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/<[^>]+>/g, '')
  .replace(/(\*\*|__|`)/g, '').replace(/\s+/g, ' ').trim();
const isHeadingLine = (raw, baseIndent) => {
  const t = raw.trim();
  if (/^#{1,6}\s/.test(t) || /^(\*\*|__)[^*_]{1,80}(\*\*|__):?$/.test(t)) return true;
  // Plain-text section titles ("Fixed", "Changed", "Developer") as in Firefox's notes.
  return raw.match(/^ */)[0].length <= baseIndent && !BULLET.test(raw) && t.length <= 40 && !/[.,;!?]$/.test(t) && /^[A-Z]/.test(t);
};

// The publisher's known-issue items in a release-notes text, at most `max`.
export function knownIssuesSection(text, { max = 10 } = {}) {
  const lines = String(text ?? '').split(/\r?\n/);
  const items = [];
  for (let i = 0; i < lines.length && items.length < max; i++) {
    const t = lines[i].trim();
    const inline = INLINE.exec(clean(t) === t ? t : t.replace(BULLET, ''));
    if (inline && !HEADING.test(t)) { const s = clean(inline[1]); if (!NONE.test(s)) items.push(s); continue; }
    if (!HEADING.test(t.replace(BULLET, ''))) continue;
    const base = lines[i].match(/^ */)[0].length;
    for (i++; i < lines.length; i++) {
      const raw = lines[i];
      if (!raw.trim()) continue;
      if (isHeadingLine(raw, base)) { i--; break; }
      const s = clean(raw);
      if (!s) continue;
      if (BULLET.test(raw) || !items.length) items.push(s);
      else items[items.length - 1] = `${items.at(-1)} ${s}`;
    }
  }
  return items.filter(s => !NONE.test(s)).slice(0, max).map(s => (s.length > 400 ? `${s.slice(0, 397)}...` : s));
}

const GH_RELEASE = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})\/releases\/tag\/([^/?#\s]{1,120})$/;
export function githubRelease(url) {
  const m = GH_RELEASE.exec(String(url ?? '').trim());
  return m ? { owner: m[1], repo: m[2], tag: decodeURIComponent(m[3]) } : null;
}

// Release notes of one winget package version: { notes, url } or null when the catalog has no such version.
export function createReleaseNotesLookup({ fetchImpl = (...a) => fetch(...a) } = {}) {
  const get = async url => {
    const r = await fetchImpl(url, { headers: { 'user-agent': 'hm360-bot' }, signal: AbortSignal.timeout(15_000) });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`winget catalog returned HTTP ${r.status}`);
    return r.text();
  };
  const memo = new Map();
  return (id, version) => {
    const key = `${id}@${version}`;
    if (!memo.has(key)) {
      const dir = `${WINGET_RAW}/${manifestPath(id)}/${encodeURIComponent(version)}`;
      const file = encodeURIComponent(id);
      const p = (async () => {
        let text = await get(`${dir}/${file}.locale.en-US.yaml`);
        if (text == null) {
          const head = await get(`${dir}/${file}.yaml`);
          const locale = head && yamlValue(head, 'DefaultLocale');
          if (!locale || !/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(locale)) return null;
          text = await get(`${dir}/${file}.locale.${locale}.yaml`);
          if (text == null) return null;
        }
        return { notes: yamlValue(text, 'ReleaseNotes'), url: yamlValue(text, 'ReleaseNotesUrl') };
      })();
      memo.set(key, p);
      p.catch(() => memo.delete(key));
    }
    return memo.get(key);
  };
}

// Body of a GitHub release, or null if it does not exist.
export function createGithubReleaseLookup({ fetchImpl = (...a) => fetch(...a), token = null } = {}) {
  return async ({ owner, repo, tag }) => {
    const r = await fetchImpl(`https://api.github.com/repos/${owner}/${repo}/releases/tags/${encodeURIComponent(tag)}`, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'hm360-bot', 'x-github-api-version': '2022-11-28', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      signal: AbortSignal.timeout(15_000) });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub releases returned HTTP ${r.status}`);
    return String((await r.json()).body ?? '');
  };
}

// apps: the result of appStatus(). Each package version is looked up once; every failure is recorded and the rest
// continue. Returns the issues found per app and version, newest problems first.
export async function appKnownIssues(apps, { releaseNotes, githubReleaseNotes = null }, { concurrency = 6, limit = 400, githubLimit = 40 } = {}) {
  const jobs = [];
  for (const u of apps?.updates || []) { jobs.push({ id: u.id, version: u.installed, which: 'installed' }, { id: u.id, version: u.latest, which: 'update' }); }
  for (const u of apps?.current || []) jobs.push({ id: u.id, version: u.installed, which: 'installed' });
  const issues = [], failed = [];
  let checked = 0, missing = 0, githubCalls = 0;
  async function one(j) {
    try {
      const rn = await releaseNotes(j.id, j.version);
      if (!rn) { missing++; return; }
      checked++;
      let items = knownIssuesSection(rn.notes);
      let source = rn.url || `https://github.com/microsoft/winget-pkgs/tree/master/${manifestPath(j.id)}/${encodeURIComponent(j.version)}`;
      const gh = githubRelease(rn.url);
      if (!items.length && gh && githubReleaseNotes && githubCalls < githubLimit) {
        githubCalls++;
        const body = await githubReleaseNotes(gh).catch(() => null);
        if (body) items = knownIssuesSection(body);
      }
      if (items.length) issues.push({ id: j.id, version: j.version, which: j.which, items, source });
    } catch (e) { failed.push({ id: j.id, version: j.version, reason: String(e.message || e).slice(0, 160) }); }
  }
  const queue = jobs.slice(0, limit);
  for (let i = 0; i < queue.length; i += concurrency) await Promise.all(queue.slice(i, i + concurrency).map(one));
  issues.sort((a, b) => a.id.localeCompare(b.id) || (a.which === 'installed' ? -1 : 1));
  const onInstalled = issues.filter(i => i.which === 'installed').length, onUpdate = issues.filter(i => i.which === 'update').length;
  return {
    status: 'checked', checked, notInCatalog: missing, skipped: Math.max(0, jobs.length - limit), failed, issues, onInstalled, onUpdate,
    grade: onInstalled ? 'warn' : 'ok',
    reason: issues.length
      ? [onInstalled && `${onInstalled} installed app version${onInstalled > 1 ? 's have' : ' has'} known issues from the publisher`, onUpdate && `${onUpdate} available update${onUpdate > 1 ? 's list' : ' lists'} known issues: read before updating`].filter(Boolean).join('; ') + '.'
      : checked ? `No publisher lists a known issue for the ${checked} app version${checked > 1 ? 's' : ''} checked.` : 'No release notes were found in the winget catalog for these apps.',
  };
}
