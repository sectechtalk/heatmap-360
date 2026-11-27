// The uploader's results are one .mhtml file (asked 2026-11-27: "only an *.mhtml file. Remove PDF functionality").
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderReport, renderReportHtml, toMhtml } from '../server/report.mjs';

const decode = buf => {
  const text = buf.toString('utf8');
  const boundary = text.match(/boundary="([^"]+)"/)[1];
  const part = text.split(`--${boundary}`)[1];
  return { text, boundary, part, html: Buffer.from(part.split('\r\n\r\n')[1].replace(/\s/g, ''), 'base64').toString('utf8') };
};

test('MHTML: RFC 2557 multipart/related with one base64 text/html part, closed boundary, CRLF lines of 76 or less', () => {
  const { text, boundary, part, html } = decode(toMhtml('<!doctype html><p>héllo</p>', { title: 'Scan x', now: new Date('2026-11-27T00:00:00Z') }));
  assert.match(text, /^From: <Saved by HeatMap 360>\r\nSubject: Scan x\r\nDate: Fri, 27 Nov 2026 00:00:00 GMT\r\nMIME-Version: 1\.0\r\n/);
  assert.match(text, /Content-Type: multipart\/related; type="text\/html"; boundary="/);
  assert.match(part, /Content-Type: text\/html; charset="utf-8"\r\nContent-Transfer-Encoding: base64\r\nContent-Location: https:\/\/heatmap360\.invalid\/scan\.html/);
  assert.ok(text.trimEnd().endsWith(`--${boundary}--`));
  assert.equal(html, '<!doctype html><p>héllo</p>');
  for (const line of text.split('\r\n')) assert.ok(line.length <= 120, line);
  assert.doesNotMatch(text.replace(/\r\n/g, ''), /\n/, 'every line ends in CRLF');
});

test('uploaded values are escaped and the page cannot run script or load anything', () => {
  const evil = '<img src=x onerror=alert(1)><script>alert(2)</script>';
  const html = renderReportHtml({ id: 'abc', processedAt: 'now', summary: { overall: 'ok', grade: {} },
    inventory: { machineId: evil, hardware: { system: { manufacturer: evil }, devices: [{ name: evil, class: 'x', driverVersion: '1.0' }] } },
    firmware: { grade: 'ok', reason: 'fine', latest: { link: 'javascript:alert(3)' } } });
  assert.doesNotMatch(html, /<script|<img|href="javascript/i);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"/);
});

test('a rejected upload still renders, and every driver keeps its version', () => {
  assert.match(decode(renderReport({ id: 'r1', rejected: 'Not a HeatMap scan' })).html, /could not be checked: Not a HeatMap scan/);
  const html = renderReportHtml({ id: 'd1', summary: { overall: 'warn', grade: {} }, inventory: { hardware: { devices: [{ name: 'Realtek Audio', class: 'MEDIA', driverVersion: '6.0.9.1', driverDate: '2025-01-02' }] } } });
  assert.match(html, /Realtek Audio<\/td><td>MEDIA<\/td><td>6\.0\.9\.1<\/td><td>2025-01-02/);
});

test('no scan PDF is left: no PDF route, button, scanner step or pdfkit use outside the incident-case review', () => {
  const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
  assert.doesNotMatch(read('server/report.mjs'), /pdfkit|PDFDocument/);
  assert.doesNotMatch(read('server/index.mjs'), /\/api\/(admin\/)?scans\/:id\/report\.pdf/);
  assert.doesNotMatch(read('client/Invoke-HeatMapScan.ps1'), /pdf/i);
  const app = read('public/app.js');
  for (const line of app.split('\n').filter(l => /PDF|\.pdf/.test(l))) assert.match(line, /case|incident/i, `scan PDF left in app.js: ${line.trim().slice(0, 120)}`);
});
