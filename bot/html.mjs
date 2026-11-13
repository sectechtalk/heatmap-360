// Tiny, dependency-free readers for the official Microsoft pages the bot uses. They read table rows and headings only;
// if Microsoft changes the page layout the readers return nothing and the bot reports "could not check", never guesses.
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" };
export const decode = s => s.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e) => {
  if (e[0] === '#') { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1)); return Number.isFinite(n) ? String.fromCodePoint(n) : m; }
  return ENTITIES[e.toLowerCase()] ?? m;
});
export const text = html => decode(String(html).replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]*>/g, ' ')).replace(/[\s​]+/g, ' ').trim();

// Every <tr> as cells: { text, strong (first <strong>/<b> text), links (hrefs) }.
export function tableRows(html) {
  const rows = [];
  for (const tr of String(html).matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...tr[1].matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi)].map(c => ({
      text: text(c[1]),
      strong: (c[1].match(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1>/i) || [])[2] ? text(c[1].match(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1>/i)[2]) : null,
      links: [...c[1].matchAll(/href="([^"]+)"/gi)].map(m => decode(m[1])),
    }));
    if (cells.length) rows.push(cells);
  }
  return rows;
}

// Every <table> as { header: [text], rows: [[cell]] }.
export function tables(html) {
  return [...String(html).matchAll(/<table\b[^>]*>([\s\S]*?)<\/table>/gi)].map(t => {
    const rows = tableRows(t[1]);
    return { header: (rows[0] || []).map(c => c.text), rows: rows.slice(1) };
  });
}

export const kbOf = cell => (cell.text.match(/\bKB(\d{6,8})\b/) || cell.links.map(l => l.match(/support\.microsoft\.com\/(?:[a-z-]+\/)?help\/(\d{6,8})/i)).find(Boolean) || [])[1] || null;
