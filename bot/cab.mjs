// Reads the first file out of a Microsoft cabinet (.cab) compressed with MSZIP, the format Dell publishes its update
// catalogs in. Pure Node (zlib), no external tool is run. Only uncompressed and MSZIP folders are supported; anything
// else is refused. Sizes are bounded so a bad file cannot use unbounded memory.
import { inflateRawSync } from 'node:zlib';

const MAX_OUT = 200 * 1024 * 1024;

export function cabFirstFile(buf) {
  const b = Buffer.from(buf);
  if (b.length < 36 || b.toString('latin1', 0, 4) !== 'MSCF') throw new Error('not a cabinet file');
  const coffFiles = b.readUInt32LE(16), cFolders = b.readUInt16LE(26), cFiles = b.readUInt16LE(28), flags = b.readUInt16LE(30);
  if (!cFolders || !cFiles) throw new Error('empty cabinet');
  let off = 36, cbCFFolder = 0, cbCFData = 0;
  if (flags & 4) { const cbCFHeader = b.readUInt16LE(36); cbCFFolder = b[38]; cbCFData = b[39]; off = 40 + cbCFHeader; }
  if (flags & 3) throw new Error('multi-part cabinets are not supported');
  // First file entry.
  const cbFile = b.readUInt32LE(coffFiles), uoffFolderStart = b.readUInt32LE(coffFiles + 4), iFolder = b.readUInt16LE(coffFiles + 8);
  if (iFolder >= cFolders) throw new Error('bad folder index');
  const folder = off + iFolder * (8 + cbCFFolder);
  const coffCabStart = b.readUInt32LE(folder), cCFData = b.readUInt16LE(folder + 4), typeCompress = b.readUInt16LE(folder + 6) & 0x0f;
  if (typeCompress !== 0 && typeCompress !== 1) throw new Error(`cabinet compression type ${typeCompress} is not supported`);
  const out = [];
  let total = 0, history = Buffer.alloc(0), p = coffCabStart;
  for (let i = 0; i < cCFData && total < uoffFolderStart + cbFile; i++) {
    const cbData = b.readUInt16LE(p + 4), cbUncomp = b.readUInt16LE(p + 6);
    const data = b.subarray(p + 8 + cbCFData, p + 8 + cbCFData + cbData);
    p += 8 + cbCFData + cbData;
    let chunk;
    if (typeCompress === 0) chunk = data;
    else {
      if (data[0] !== 0x43 || data[1] !== 0x4b) throw new Error('bad MSZIP block');
      // Each MSZIP block is a raw deflate stream that may refer back to the previous 32 KB of output.
      chunk = inflateRawSync(data.subarray(2), history.length ? { dictionary: history } : {});
    }
    if (chunk.length !== cbUncomp) throw new Error('cabinet block has the wrong size');
    out.push(chunk); total += chunk.length;
    if (total > MAX_OUT) throw new Error('cabinet is too large');
    history = Buffer.concat([history, chunk]).subarray(-32768);
  }
  const all = Buffer.concat(out);
  if (all.length < uoffFolderStart + cbFile) throw new Error('cabinet is truncated');
  return all.subarray(uoffFolderStart, uoffFolderStart + cbFile);
}

// Dell's catalogs are UTF-16 XML with a byte order mark.
export function decodeXml(bytes) {
  const b = Buffer.from(bytes);
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b.subarray(2));
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b.subarray(2));
  return b.toString('utf8').replace(/^﻿/, '');
}
