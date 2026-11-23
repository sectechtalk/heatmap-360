// Bluesky page: the latest posts from official vendor accounts on Bluesky, read from Bluesky's free public API
// (public.api.bsky.app, no account, no key, no cost). The owner chose Bluesky over x.com on 2026-11-15 because x.com
// charges per post read. HeatMap 360 only reads: it never signs in, posts, likes or follows.
//
// The accounts are the top 50 official business accounts ranked on 2026-11-15 (every one checked as official: its
// handle is the vendor's own domain, or Bluesky verified it, or its bio says it is the official account), plus the
// official Microsoft accounts that exist but have not posted yet, so their first posts show up here.
// Accounts are pinned by DID (Bluesky's permanent account id), so a handle change cannot swap in someone else.
//
// Replies are read on demand for one post at a time (button on the page), only for posts by the listed accounts.
// Replies are written by anyone, so they are shown as plain text and never followed or acted on.

const API = 'https://public.api.bsky.app/xrpc/';
const PER_ACCOUNT = 25;
const MAX_REPLIES = 30;
const CONCURRENCY = 6;
const DID = /^did:plc:[a-z2-7]{24}$/;
const RKEY = /^[a-z2-7]{13}$/;
const POST_URI = /^at:\/\/(did:plc:[a-z2-7]{24})\/app\.bsky\.feed\.post\/([a-z2-7]{13})$/;

// [rank, handle, did, display name, company, group]. Group "microsoft" = Microsoft and its companies (GitHub, npm).
// Rank null = official account that has not posted yet (watched, not ranked).
const ROWS = [
  [1, 'firefox.com', 'did:plc:m424cqoxwhxgjutbta7jmrur', 'Firefox', 'Mozilla', 'vendor'],
  [2, 'signal.org', 'did:plc:tovhrfml47r6u4idaitaxefk', 'Signal', 'Signal', 'vendor'],
  [3, 'status.bsky.app', 'did:plc:4dtbz2ivhp5app3sbntcccxc', 'Bluesky Status', 'Bluesky', 'vendor'],
  [4, 'proton.me', 'did:plc:siul2ctdwvvrzfnfhyunmgvh', 'Proton', 'Proton', 'vendor'],
  [5, 'tuta.com', 'did:plc:hrl5pa232nb72z4f2dyyhasr', 'Tuta', 'Tuta', 'vendor'],
  [6, 'vivaldi.com', 'did:plc:5cnt2eyggmpbhdvogarubrcs', 'Vivaldi Browser', 'Vivaldi', 'vendor'],
  [7, 'keepassxc.org', 'did:plc:bqa2yiz7yiecee4djvygthjh', 'KeePassXC', 'KeePassXC', 'vendor'],
  [8, 'threatintel.microsoft.com', 'did:plc:ezrjx3qddwj4azn373c2ipdg', 'Microsoft Threat Intelligence', 'Microsoft', 'microsoft'],
  [9, 'typescriptlang.org', 'did:plc:svcebrizuuy6vy6tsqmc3icz', 'TypeScript', 'Microsoft', 'microsoft'],
  [10, 'frame.work', 'did:plc:qt6u5dgu2o6l2v4zdx6eqh22', 'Framework', 'Framework', 'vendor'],
  [11, 'malwarebytes.com', 'did:plc:xpqns3kptvh2uylrla7nuukk', 'Malwarebytes', 'Malwarebytes', 'vendor'],
  [12, 'obsidian.md', 'did:plc:u5cgub464m4dfjyjgx5f24y3', 'Obsidian', 'Obsidian', 'vendor'],
  [13, 'rust-lang.org', 'did:plc:wicua5idywllkobpfm64byvm', 'Rust', 'Rust Foundation', 'vendor'],
  [14, 'cloudflare.social', 'did:plc:urfmcbraacw7f6ywqhtjz5ku', 'Cloudflare', 'Cloudflare', 'vendor'],
  [15, 'duckduckgo.com', 'did:plc:v2yugzf5jep7pky7pni5dohx', 'DuckDuckGo', 'DuckDuckGo', 'vendor'],
  [16, 'nodejs.org', 'did:plc:abbt45q3u3bttqfs7nepehhu', 'Node.js', 'OpenJS Foundation', 'vendor'],
  [17, 'esetresearch.bsky.social', 'did:plc:u4jt77a2vcxw74anqy3jipb4', 'ESET Research', 'ESET', 'vendor'],
  [18, 'nextcloud.bsky.social', 'did:plc:wzhjna25kl74w3rywz6fn4ln', 'Nextcloud', 'Nextcloud', 'vendor'],
  [19, 'socket.dev', 'did:plc:n6f3j47vjucu5ijwdmow7n2w', 'Socket', 'Socket', 'vendor'],
  [20, 'npmjs.com', 'did:plc:t7gza4k773m6qvit4qlwi7ok', 'npm', 'Microsoft (GitHub)', 'microsoft'],
  [21, 'vscode.dev', 'did:plc:2xibtqlq4oplg5hkbqw56xgu', 'Visual Studio Code', 'Microsoft', 'microsoft'],
  [22, 'haveibeenpwned.com', 'did:plc:ao3wtyjoxf5akyqjbf5yhsvo', 'Have I Been Pwned', 'Have I Been Pwned', 'vendor'],
  [23, 'github.com', 'did:plc:sydgpvanh46u766n536r33oa', 'GitHub', 'Microsoft (GitHub)', 'microsoft'],
  [24, 'volexity.com', 'did:plc:z6yenb4npk2aibtsqkerghbo', 'Volexity', 'Volexity', 'vendor'],
  [25, 'home-assistant.io', 'did:plc:q4jmx4y3kob3eeub2clnjrva', 'Home Assistant', 'Open Home Foundation', 'vendor'],
  [26, 'censys.bsky.social', 'did:plc:rufpffyvogi3xxmj52zjliso', 'Censys', 'Censys', 'vendor'],
  [27, 'developer.chrome.com', 'did:plc:36mrcrcpvfmweffmmhvmnnoi', 'Chrome for Developers', 'Google', 'vendor'],
  [28, 'opensource.google', 'did:plc:x6bnzgic7duwjxogg7zb3qas', 'Google Open Source', 'Google', 'vendor'],
  [29, 'opnsense.org', 'did:plc:vpna73dxrqinj6ttwh3wryxv', 'OPNsense', 'Deciso', 'vendor'],
  [30, 'sentinelone.com', 'did:plc:5fpvkgmdixnrfl5filc7wvqq', 'SentinelOne', 'SentinelOne', 'vendor'],
  [31, 'thunderbird.net', 'did:plc:w4onptv4mpxf3rxigch6lc7j', 'Thunderbird', 'Mozilla', 'vendor'],
  [32, 'talosintelligence.com', 'did:plc:2klbilq5kbutfx2fkyijd5u6', 'Cisco Talos', 'Cisco', 'vendor'],
  [33, 'mozilla.org', 'did:plc:jxrrsbtaptoynkhm2tdvxohg', 'Mozilla', 'Mozilla', 'vendor'],
  [34, 'postgresql.org', 'did:plc:vfooenmoyp2alvc6asoxjezu', 'PostgreSQL', 'PostgreSQL', 'vendor'],
  [35, 'apache.org', 'did:plc:h3d3fy7e2rvkphyk2zioxpy3', 'Apache Software Foundation', 'Apache Software Foundation', 'vendor'],
  [36, 'msrc.microsoft.com', 'did:plc:qczyxpnnqjuyzzttzqcakkq2', 'Microsoft Security Response Center', 'Microsoft', 'microsoft'],
  [37, 'greynoise.io', 'did:plc:3y5lhkm7gbrixowhpoum2zaq', 'GreyNoise', 'GreyNoise', 'vendor'],
  [38, 'python.org', 'did:plc:sfrl4dmvaxeq4lqgaucotygo', 'Python', 'Python Software Foundation', 'vendor'],
  [39, 'gitea.com', 'did:plc:mbglmw23w7ifpzlwu5w5lbt5', 'Gitea', 'Gitea', 'vendor'],
  [40, 'torproject.org', 'did:plc:tnyyuxpjrcuf2sispj2m7bdc', 'Tor Project', 'Tor Project', 'vendor'],
  [41, 'msftexchange.bsky.social', 'did:plc:w2l4auh6itwvexla4jq6gpoe', 'Microsoft Exchange', 'Microsoft', 'microsoft'],
  [42, 'bitwarden.bsky.social', 'did:plc:5fxm64r2pm2pioahs53euhxh', 'Bitwarden', 'Bitwarden', 'vendor'],
  [43, 'tailscale.com', 'did:plc:tkc3xiya4k7uyx3jsei3bp65', 'Tailscale', 'Tailscale', 'vendor'],
  [44, 'wordpress.org', 'did:plc:r2no5dzwjjkp4cysp43tqzxa', 'WordPress', 'WordPress', 'vendor'],
  [45, 'dot.net', 'did:plc:bg2pdi4jqji45avhq6kqvjka', '.NET', 'Microsoft', 'microsoft'],
  [46, 'visualstudio.com', 'did:plc:i2xikuylmym5lagwxbmcp77n', 'Visual Studio', 'Microsoft', 'microsoft'],
  [47, 'msftmechanics.bsky.social', 'did:plc:nhagu5jrl7todm2yqui2sfx3', 'Microsoft Mechanics', 'Microsoft', 'microsoft'],
  [48, 'developer.microsoft.com', 'did:plc:jdrbb3mypdgze3kwvnxqz7rs', 'Microsoft Developer', 'Microsoft', 'microsoft'],
  [49, 'msft365insider.bsky.social', 'did:plc:x7zlj342x35dwb3uwompx5xt', 'Microsoft 365 Insider', 'Microsoft', 'microsoft'],
  [50, 'msftresearch.bsky.social', 'did:plc:rvofkpg4qgalioqtvphgclbh', 'Microsoft Research', 'Microsoft', 'microsoft'],
  [null, 'microsoft.com', 'did:plc:fivojrvylkim4nuo3pfqcf3k', 'Microsoft', 'Microsoft', 'microsoft'],
  [null, 'azure.microsoft.com', 'did:plc:eihqamfc7cvzzkdpbrpcza2z', 'Microsoft Azure', 'Microsoft', 'microsoft'],
  [null, 'microsoft365.microsoft.com', 'did:plc:mer6nng3nxrr4rgvweamuf6y', 'Microsoft 365', 'Microsoft', 'microsoft'],
  [null, 'teams.microsoft.com', 'did:plc:tznk6g3zwo7h3yqbwmtzs36l', 'Microsoft Teams', 'Microsoft', 'microsoft'],
  [null, 'security.microsoft.com', 'did:plc:bcwoycqatrgiqhphqlix3lkj', 'Microsoft Security', 'Microsoft', 'microsoft'],
  [null, 'powerplatform.microsoft.com', 'did:plc:gcdeiyennurydbhvkfdbpxgd', 'Microsoft Power Platform', 'Microsoft', 'microsoft'],
  [null, 'mssharepoint.bsky.social', 'did:plc:piwjdxqlez3zz6yxd7x5bnez', 'Microsoft SharePoint', 'Microsoft', 'microsoft'],
];
export const ACCOUNTS = ROWS.map(([rank, handle, did, name, company, group]) => ({ id: handle, rank, handle, did, name, company, group }));

const clip = (s, n) => { const t = String(s ?? '').replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
const num = v => (Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
const isoOrNull = v => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const rkeyOf = uri => String(uri ?? '').split('/').pop();
// Links are built from the pinned DID and a checked record key, never copied from the API response.
export const postLink = (did, rkey) => (DID.test(did) && RKEY.test(rkey) ? `https://bsky.app/profile/${did}/post/${rkey}` : null);

// Keeps the account's own top-level posts (no reposts of others, no replies), newest first.
export function parseAuthorFeed(json, did) {
  const feed = Array.isArray(json?.feed) ? json.feed : [];
  return feed
    .filter(x => !x?.reason && x?.post?.author?.did === did && !x.post.record?.reply)
    .map(({ post }) => {
      const m = POST_URI.exec(String(post.uri ?? ''));
      if (!m || m[1] !== did) return null;
      return {
        uri: post.uri,
        link: postLink(did, m[2]),
        text: clip(post.record?.text, 1000) || '(no text: picture or link only)',
        date: isoOrNull(post.record?.createdAt) ?? isoOrNull(post.indexedAt),
        replies: num(post.replyCount), reposts: num(post.repostCount), likes: num(post.likeCount),
      };
    })
    .filter(Boolean)
    .sort((a, b) => (b.date || '').localeCompare(a.date || ''));
}

// Direct replies to one post, most-liked first. Reply text is untrusted: plain text, clipped.
export function parseThread(json) {
  const replies = Array.isArray(json?.thread?.replies) ? json.thread.replies : [];
  return replies
    .filter(r => r?.post?.record && typeof r.post.author?.did === 'string')
    .map(({ post }) => ({
      author: clip(post.author.displayName || post.author.handle, 80),
      handle: clip(post.author.handle, 100),
      text: clip(post.record.text, 600) || '(no text: picture or link only)',
      date: isoOrNull(post.record.createdAt),
      likes: num(post.likeCount),
      link: DID.test(post.author.did) ? postLink(post.author.did, rkeyOf(post.uri)) : null,
    }))
    .sort((a, b) => b.likes - a.likes || (b.date || '').localeCompare(a.date || ''))
    .slice(0, MAX_REPLIES);
}

async function pool(items, size, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i]); }
  }));
  return out;
}

export function createBluesky({ fetchImpl = (...a) => fetch(...a), now = () => Date.now(), ttlMs = 900_000, accounts = ACCOUNTS } = {}) {
  const dids = new Set(accounts.map(a => a.did));
  const get = async path => {
    const r = await fetchImpl(API + path, { headers: { 'user-agent': 'HeatMap360/1.0', accept: 'application/json' }, signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };
  let cache = null;
  const threads = new Map();

  async function one(a) {
    const base = { id: a.id, rank: a.rank, handle: a.handle, name: a.name, company: a.company, group: a.group, page: `https://bsky.app/profile/${a.did}` };
    try {
      const json = await get(`app.bsky.feed.getAuthorFeed?actor=${encodeURIComponent(a.did)}&filter=posts_no_replies&limit=${PER_ACCOUNT}`);
      return { ...base, status: 'checked', items: parseAuthorFeed(json, a.did) };
    } catch (e) {
      return { ...base, status: 'unknown', error: `Could not read ${a.name} on Bluesky: ${String(e.message || e).slice(0, 200)}`, items: [] };
    }
  }

  function feed() {
    if (cache && now() - cache.at < ttlMs) return cache.value;
    const at = now();
    const value = pool(accounts, CONCURRENCY, one).then(list => ({ title: 'Bluesky', checkedAt: new Date(at).toISOString(), accounts: list }));
    cache = { at, value };
    return value;
  }

  // Replies to one post by a listed account. Returns null for anything else (the route answers 404).
  async function thread(uri) {
    const m = POST_URI.exec(String(uri ?? ''));
    if (!m || !dids.has(m[1])) return null;
    const hit = threads.get(uri);
    if (hit && now() - hit.at < ttlMs) return hit.value;
    const value = get(`app.bsky.feed.getPostThread?uri=${encodeURIComponent(uri)}&depth=1&parentHeight=0`)
      .then(json => ({ uri, checkedAt: new Date(now()).toISOString(), replies: parseThread(json) }));
    value.catch(() => threads.delete(uri));
    if (threads.size >= 300) threads.delete(threads.keys().next().value);
    threads.set(uri, { at: now(), value });
    return value;
  }

  return { feed, thread };
}
