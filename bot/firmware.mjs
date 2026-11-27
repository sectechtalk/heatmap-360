// BIOS/UEFI firmware status. HP and Lenovo publish machine-readable catalogs that their own update tools read
// (HP Image Assistant reference files, Lenovo System Update catalogs, Dell Command Update catalogs); the bot reads the
// newest BIOS from those.
// Other makers get the BIOS age and a link to their official support site. A lookup that fails says so.
//
// URLs: only the model code from the upload goes into a catalog URL, and only after it matches a strict pattern
// (4 hex digits for HP, 4 letters/digits for Lenovo). The host and the rest of the path are fixed here.
import { compareVersions } from './apps.mjs';
import { text } from './html.mjs';

const DAY = 86_400_000;
const DATE_MARGIN_DAYS = 45; // vendors publish a BIOS some weeks after the date stamped in it

export const VENDORS = [
  { key: 'hp', test: /^(hp|hewlett)/i, name: 'HP', support: 'https://support.hp.com/drivers' },
  { key: 'lenovo', test: /lenovo/i, name: 'Lenovo', support: 'https://pcsupport.lenovo.com/' },
  { key: 'dell', test: /^dell/i, name: 'Dell', support: 'https://www.dell.com/support/home' },
  { key: 'microsoft', test: /^microsoft/i, name: 'Microsoft Surface', support: 'https://support.microsoft.com/surface' },
  { key: 'asus', test: /asus/i, name: 'ASUS', support: 'https://www.asus.com/support/download-center/' },
  { key: 'msi', test: /micro-star|^msi\b/i, name: 'MSI', support: 'https://www.msi.com/support/download' },
  { key: 'gigabyte', test: /gigabyte/i, name: 'GIGABYTE', support: 'https://www.gigabyte.com/Support' },
  { key: 'asrock', test: /asrock/i, name: 'ASRock', support: 'https://www.asrock.com/support/index.asp' },
  { key: 'acer', test: /^acer/i, name: 'Acer', support: 'https://www.acer.com/support' },
];
const VIRTUAL = /virtual machine|vmware|virtualbox|kvm|qemu|hvm domu|parallels/i;
export const findVendor = name => (name ? VENDORS.find(v => v.test.test(String(name).trim())) ?? null : null);

// ---------------------------------------------------------------- small XML readers (vendor catalogs)
const cdata = s => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
export const xmlBlocks = (xml, tag) => [...String(xml).matchAll(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'gi'))].map(m => m[1]);
export const xmlText = (xml, tag) => { const m = String(xml).match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'i')); return m ? text(cdata(m[1])) || null : null; };
const xmlAttr = (xml, tag, name) => { const m = String(xml).match(new RegExp(`<${tag}\\b[^>]*\\b${name}="([^"]*)"`, 'i')); return m ? text(m[1]) : null; };
const isoDay = s => { const t = Date.parse(s); return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : null; };
const dotted = s => (String(s ?? '').match(/\d+(?:\.\d+)+/g) || []).at(-1) ?? null;
const winVersion = os => {
  const dv = String(os?.displayVersion || '').toLowerCase();
  if (!/^\d{2}h\d$/.test(dv) || !os?.build) return null;
  return { gen: os.build >= 22000 ? 11 : 10, dv };
};

// ---------------------------------------------------------------- HP (HP Image Assistant reference file)
export const HP_REF = 'https://hpia.hpcloud.hp.com/ref';
// HP Image Assistant's catalog lists business models only. Consumer lines get a clearer "not covered" reason.
const HP_CONSUMER = /\b(ENVY|Pavilion|OMEN|Spectre|Victus|Chromebook|Stream)\b/i;
export function parseHpReference(xml) {
  return xmlBlocks(xml, 'UpdateInfo')
    .map(u => ({ category: xmlText(u, 'Category'), name: xmlText(u, 'Name'), version: xmlText(u, 'Version'), date: isoDay(xmlText(u, 'ReleaseDate')),
      url: xmlText(u, 'Url'), notes: xmlText(u, 'ReleaseNotesUrl') }))
    .filter(u => /^bios/i.test(u.category || '') && u.version);
}
const hpLink = u => (u && /^(https?:\/\/)?(ftp\.hp\.com|ftp\.ext\.hp\.com|downloads\.hpe?\.com)\//i.test(u) ? (u.startsWith('http') ? u.replace(/^http:/, 'https:') : `https://${u}`) : null);

async function hpLatest(inv, get) {
  const platform = String(inv.hardware?.baseboard?.product || '').trim();
  if (!/^[0-9A-F]{4}$/i.test(platform)) return { error: 'The motherboard ID is not an HP platform ID, so HP\'s catalog could not be read.' };
  const w = winVersion(inv.os);
  if (!w) return { error: 'Needs the Windows version to pick HP\'s catalog.' };
  const id = platform.toUpperCase();
  const url = `${HP_REF}/${id}/${id}_64_${w.gen}.0.${w.dv}.xml`;
  const xml = await get(url);
  if (xml == null) {
    const consumer = HP_CONSUMER.test(`${inv.hardware?.system?.model || ''} ${inv.hardware?.system?.family || ''}`);
    return { error: consumer
      ? "HP's update catalog covers HP business models only; consumer models (ENVY, Pavilion, OMEN, Spectre, Victus) are not in it, so check HP's support site."
      : `HP's update catalog has no entry for platform ${id} on Windows ${w.gen} ${w.dv.toUpperCase()}; check HP's support site.`, source: url };
  }
  const bios = parseHpReference(xml).sort((a, b) => compareVersions(dotted(a.version) ?? a.version, dotted(b.version) ?? b.version));
  if (!bios.length) return { error: 'HP\'s catalog for this model lists no BIOS.', source: url };
  const b = bios.at(-1);
  return { latest: { version: b.version, date: b.date, name: b.name, link: hpLink(b.notes) || hpLink(b.url) }, source: url };
}

// ---------------------------------------------------------------- Lenovo (System Update catalog)
export const LENOVO_CATALOG = 'https://download.lenovo.com/catalog';
export function parseLenovoCatalog(xml) {
  return xmlBlocks(xml, 'package').map(p => ({ location: xmlText(p, 'location'), category: xmlText(p, 'category') }))
    .filter(p => /bios/i.test(p.category || '') && /^https:\/\/download\.lenovo\.com\/[\w./-]+\.xml$/i.test(p.location || ''));
}
export function parseLenovoPackage(xml) {
  return { version: xmlAttr(xml, 'Package', 'version'), name: xmlText(xml, 'Title') || xmlAttr(xml, 'Package', 'name'), date: isoDay(xmlText(xml, 'ReleaseDate')) };
}

async function lenovoLatest(inv, get) {
  const m = String(inv.hardware?.system?.model || '').trim().toUpperCase().match(/^([0-9A-Z]{4})[0-9A-Z]{0,6}$/);
  if (!m) return { error: 'The model is not a Lenovo machine type, so Lenovo\'s catalog could not be read.' };
  const w = winVersion(inv.os);
  const gens = w?.gen === 10 ? [10] : [11, 10];
  let url = null, xml = null;
  for (const g of gens) { url = `${LENOVO_CATALOG}/${m[1]}_Win${g}.xml`; xml = await get(url); if (xml != null) break; }
  if (xml == null) return { error: `Lenovo publishes no update catalog for machine type ${m[1]}.`, source: url };
  const pkgs = parseLenovoCatalog(xml).slice(0, 4);
  if (!pkgs.length) return { error: 'Lenovo\'s catalog for this model lists no BIOS.', source: url };
  const found = [];
  for (const p of pkgs) { const x = await get(p.location); if (x != null) found.push(parseLenovoPackage(x)); }
  const best = found.filter(f => f.version || f.date).sort((a, b) => String(a.date).localeCompare(String(b.date))).at(-1);
  if (!best) return { error: 'Could not read the BIOS package in Lenovo\'s catalog.', source: url };
  return { latest: { ...best, link: `https://pcsupport.lenovo.com/products/${m[1].toLowerCase()}/downloads` }, source: url };
}

// ---------------------------------------------------------------- Dell (Dell Command Update catalogs)
// CatalogIndexPC.cab lists one catalog per model, keyed by the 4-hex system ID that Windows reports as the system SKU
// (scanner 1.4.0). sources.vendorFile() unpacks the .cab and returns the XML text.
export const DELL_INDEX = 'https://downloads.dell.com/catalog/CatalogIndexPC.cab';
const DELL_PATH = /^FOLDER\d+M\/\d+\/[A-Za-z0-9._-]+\.cab$/;
const tagged = (xml, tag) => [...String(xml).matchAll(new RegExp(`<${tag}\\b([^>]*)>([\\s\\S]*?)</${tag}>`, 'g'))].map(m => ({ attrs: m[1], body: m[2] }));
const attr = (attrs, name) => { const m = String(attrs).match(new RegExp(`\\b${name}="([^"]*)"`)); return m ? text(m[1]) : null; };
export function dellModelPath(indexXml, sku) {
  for (const g of tagged(indexXml, 'GroupManifest')) {
    if (!new RegExp(`<Model\\b[^>]*systemID="${sku}"`, 'i').test(g.body)) continue;
    const info = tagged(g.body, 'ManifestInformation')[0] || { attrs: (g.body.match(/<ManifestInformation\b([^>]*)/) || [])[1] || '' };
    const p = attr(info.attrs, 'path');
    if (p && DELL_PATH.test(p)) return p;
  }
  return null;
}
export function parseDellBios(modelXml, sku) {
  return tagged(modelXml, 'SoftwareComponent')
    .filter(c => /<ComponentType\b[^>]*value="BIOS"/i.test(c.body) && new RegExp(`<Model\\b[^>]*systemID="${sku}"`, 'i').test(c.body))
    .map(c => ({ version: attr(c.attrs, 'vendorVersion'), date: isoDay(attr(c.attrs, 'releaseDate')) || isoDay(attr(c.attrs, 'dateTime')),
      name: ((c.body.match(/<Name>\s*<Display[^>]*>(?:<!\[CDATA\[)?([^\]<]*)/) || [])[1] || '').trim() || null,
      releaseID: attr(c.attrs, 'releaseID') }))
    .filter(b => b.version);
}
async function dellLatest(inv, get) {
  const sku = String(inv.hardware?.system?.sku || '').trim().toUpperCase();
  if (!/^[0-9A-F]{4}$/.test(sku)) return { error: 'The scan did not report a Dell system ID (scanner 1.4.0 or later sends it), so Dell\'s catalog could not be read.' };
  const index = await get(DELL_INDEX);
  if (index == null) return { error: 'Dell\'s catalog index could not be found.', source: DELL_INDEX };
  const p = dellModelPath(index, sku);
  if (!p) return { error: `Dell's catalog has no entry for system ID ${sku}; check Dell's support site.`, source: DELL_INDEX };
  const url = `https://downloads.dell.com/${p}`;
  const xml = await get(url);
  if (xml == null) return { error: 'Dell\'s catalog for this model could not be found.', source: url };
  const bios = parseDellBios(xml, sku).sort((a, b) => compareVersions(dotted(a.version) ?? a.version, dotted(b.version) ?? b.version));
  if (!bios.length) return { error: 'Dell\'s catalog for this model lists no BIOS.', source: url };
  const b = bios.at(-1);
  return { latest: { version: b.version, date: b.date, name: b.name, link: b.releaseID && /^[A-Z0-9]{5}$/.test(b.releaseID) ? `https://www.dell.com/support/home/drivers/driversdetails?driverid=${b.releaseID.toLowerCase()}` : 'https://www.dell.com/support/home' }, source: url };
}

const LOOKUPS = { hp: hpLatest, lenovo: lenovoLatest, dell: dellLatest };

// Installed version in the vendor's own numbering: Lenovo "N32ET86W (1.62 )" -> 1.62, HP "T70 Ver. 01.15.00" -> 01.15.00.
export function installedBiosVersion(vendorKey, version) {
  const v = String(version ?? '');
  if (vendorKey === 'lenovo') return (v.match(/\((\d+\.\d+)/) || [])[1] ?? null;
  return dotted(v);
}

function compare(vendorKey, installed, latest) {
  const a = installedBiosVersion(vendorKey, installed.version), b = dotted(latest.version);
  if (a && b && a.split('.').length === b.split('.').length) return { newer: compareVersions(b, a) > 0, by: 'version' };
  const ti = Date.parse(installed.date), tl = Date.parse(latest.date);
  if (Number.isFinite(ti) && Number.isFinite(tl)) return { newer: tl - ti > DATE_MARGIN_DAYS * DAY, by: 'date' };
  return null;
}

// get(url) -> text, or null when the vendor has no such file (HTTP 404); throws on other failures.
export async function firmwareStatus(inv, get, now = Date.now()) {
  const hw = inv.hardware || {}, bios = hw.bios || {}, sys = hw.system || {}, board = hw.baseboard || {};
  if (!bios.version && !bios.releaseDate) return { status: 'unknown', grade: 'unknown', reason: 'The scan did not report the BIOS.' };
  if (VIRTUAL.test(`${sys.model || ''} ${sys.manufacturer || ''}`)) return { status: 'virtual', grade: 'unknown', reason: 'This is a virtual machine; its firmware comes from the host.' };
  const vendor = findVendor(sys.manufacturer) || findVendor(board.manufacturer) || findVendor(bios.vendor);
  const t = Date.parse(bios.releaseDate);
  const ageYears = Number.isFinite(t) ? Math.round(((now - t) / (365.25 * DAY)) * 10) / 10 : null;
  const installed = { version: bios.version ?? null, date: bios.releaseDate ?? null, ageYears };
  const base = { installed, vendor: vendor?.name ?? null, support: vendor?.support ?? null };
  const age = ageYears == null ? '' : ` It is ${ageYears} years old.`;

  const lookup = vendor && LOOKUPS[vendor.key];
  let r = null;
  if (lookup) { try { r = await lookup(inv, get); } catch (e) { r = { error: `${vendor.name} catalog: ${String(e.message || e).slice(0, 200)}` }; } }
  if (r?.latest) {
    const c = compare(vendor.key, installed, r.latest);
    if (c) {
      const latestLabel = `${r.latest.version || 'newest'}${r.latest.date ? ` (${r.latest.date})` : ''}`;
      return c.newer
        ? { ...base, status: 'update', grade: 'warn', latest: r.latest, comparedBy: c.by, source: r.source,
          reason: `${vendor.name} has a newer BIOS: ${latestLabel}. Installed: ${installed.version || 'unknown'}${installed.date ? ` (${installed.date})` : ''}.` }
        : { ...base, status: 'current', grade: 'ok', latest: r.latest, comparedBy: c.by, source: r.source, reason: `The BIOS is the newest ${vendor.name} lists (${latestLabel}).` };
    }
    r = { error: 'The installed and newest BIOS versions could not be compared.', source: r.source };
  }
  const why = r?.error || (vendor ? `HeatMap 360 can look up BIOS updates automatically for HP, Lenovo and Dell; check ${vendor.name}'s support site for this model.`
    : 'The computer maker was not recognised; check the maker\'s support site for this model.');
  const old = ageYears != null && ageYears > 3;
  return { ...base, status: 'not-checked', grade: old ? 'warn' : 'unknown', source: r?.source ?? null,
    reason: `${why}${age}${old ? ' A BIOS this old often has a newer version with security and stability fixes.' : ''}` };
}
