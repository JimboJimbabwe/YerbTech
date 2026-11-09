'use strict';
/**
 * Reads Burp "Save items" / Proxy-history XML for the request viewer.
 *
 * The file is streamed through a SAX parser (never loaded whole), and only the request side of
 * each item is kept. Responses are parsed past and dropped, so a multi-hundred-MB export costs
 * memory for its requests only. Indexes are cached per file (keyed on size + mtime) and the
 * cache is bounded, so re-uploading a file or editing it by hand is picked up automatically.
 */
const fs = require('fs');
const fsp = require('fs/promises');
const sax = require('sax');
const { HttpError } = require('./errors');

const MAX_REQ_CHARS = 1_000_000; // per request; longer ones are cut and flagged
const CACHE_MAX_FILES = 4;
const CACHE_MAX_CHARS = 300_000_000;

const FIELDS = {
  time: 'time', url: 'url', host: 'host', port: 'port', protocol: 'protocol', method: 'method',
  path: 'path', status: 'status', mimetype: 'mime', responselength: 'length', request: 'req',
};

const cache = new Map(); // abs path -> { mtimeMs, size, chars, promise }

function parseFile(abs) {
  return new Promise((resolve, reject) => {
    const items = [];
    let errors = 0;
    let chars = 0;
    let cur = null;
    let field = null;
    let buf = '';

    const parser = sax.parser(false, { lowercase: true, trim: false });
    // Burp output has an internal DOCTYPE, CDATA and the odd stray byte. Count errors, keep going.
    parser.onerror = () => { errors++; parser.error = null; parser.resume(); };

    parser.onopentag = (node) => {
      if (node.name === 'item') {
        cur = { time: '', url: '', host: '', port: '', protocol: '', method: '', path: '', status: '', mime: '', length: '', req: '', b64: false, trunc: false };
        field = null;
      } else if (cur && FIELDS[node.name]) {
        field = node.name;
        buf = '';
        if (field === 'request') cur.b64 = String(node.attributes?.base64 ?? node.attributes?.BASE64 ?? '').toLowerCase() === 'true';
      }
    };

    const addText = (t) => {
      if (!field) return;
      if (field === 'request') {
        const room = MAX_REQ_CHARS - buf.length;
        if (t.length > room) { buf += t.slice(0, Math.max(room, 0)); cur.trunc = true; } else buf += t;
      } else if (buf.length < 4096) {
        buf += t;
      }
    };
    parser.ontext = addText;
    parser.oncdata = addText;

    parser.onclosetag = (name) => {
      if (cur && field && name === field) {
        cur[FIELDS[field]] = field === 'request' ? buf : buf.trim();
        if (field === 'request') chars += buf.length;
        field = null;
        buf = '';
      } else if (name === 'item' && cur) {
        items.push(cur);
        cur = null;
        field = null;
      }
    };

    const stream = fs.createReadStream(abs, { encoding: 'utf8', highWaterMark: 256 * 1024 });
    stream.on('data', (chunk) => {
      try { parser.write(chunk); } catch (e) { stream.destroy(e); }
    });
    stream.on('end', () => {
      try { parser.close(); } catch { /* trailing junk is not fatal */ }
      resolve({ items, errors, chars });
    });
    stream.on('error', reject);
  });
}

function evict() {
  let total = 0;
  for (const e of cache.values()) total += e.chars;
  for (const key of cache.keys()) {
    if (cache.size <= CACHE_MAX_FILES && total <= CACHE_MAX_CHARS) break;
    if (cache.size === 1) break; // always keep the file in use
    total -= cache.get(key).chars;
    cache.delete(key);
  }
}

async function load(abs) {
  let st;
  try {
    st = await fsp.stat(abs);
  } catch (e) {
    if (e.code === 'ENOENT') throw new HttpError(404, 'That XML file is no longer on disk.');
    throw e;
  }
  const hit = cache.get(abs);
  if (hit && hit.mtimeMs === st.mtimeMs && hit.size === st.size) {
    cache.delete(abs); // refresh LRU position
    cache.set(abs, hit);
    return hit.promise;
  }
  const entry = { mtimeMs: st.mtimeMs, size: st.size, chars: 0, promise: null };
  entry.promise = parseFile(abs).then(
    (r) => { entry.chars = r.chars; evict(); return r; },
    (e) => { cache.delete(abs); throw e; },
  );
  cache.set(abs, entry);
  return entry.promise;
}

const summary = (m, index) => ({
  index,
  method: m.method,
  url: m.url || `${m.protocol ? `${m.protocol}://` : ''}${m.host}${m.path}`,
  status: m.status,
  mime: m.mime,
  length: m.length,
  time: m.time,
});

/** One page of the request list, optionally filtered by a substring of method, URL or status. */
async function list(abs, { offset = 0, limit = 200, q = '' } = {}) {
  const idx = await load(abs);
  const total = idx.items.length;
  const needle = String(q).trim().toLowerCase().slice(0, 200);
  const out = [];
  let matched = 0;
  for (let i = 0; i < total; i++) {
    const m = idx.items[i];
    if (needle && !`${m.method} ${m.url} ${m.status}`.toLowerCase().includes(needle)) continue;
    if (matched >= offset && out.length < limit) out.push(summary(m, i));
    matched++;
  }
  return { total, matched, offset, limit, items: out, parseErrors: idx.errors };
}

/** Decoded text of one request. Always plain text; the client renders it with textContent. */
async function getRequest(abs, index) {
  const idx = await load(abs);
  const m = idx.items[index];
  if (!m) throw new HttpError(404, 'No such request in this file.');
  const buf = m.b64 ? Buffer.from(m.req, 'base64') : Buffer.from(m.req, 'utf8');
  const text = buf.toString('utf8').replace(/\0/g, '\\0');
  return { ...summary(m, index), host: m.host, port: m.port, protocol: m.protocol, bytes: buf.length, truncated: m.trunc, text };
}

/**
 * The exact bytes of one request, undecorated - no `\0` substitution, no display truncation
 * beyond the same MAX_REQ_CHARS cap already baked into parsing. For handing a request to
 * something that will replay it (Intruder), not for showing it on screen.
 */
async function getRawRequest(abs, index) {
  const idx = await load(abs);
  const m = idx.items[index];
  if (!m) throw new HttpError(404, 'No such request in this file.');
  const bytes = m.b64 ? Buffer.from(m.req, 'base64') : Buffer.from(m.req, 'utf8');

  // <host>/<port>/<protocol> are what real Burp "Save items" XML carries, but they're not
  // guaranteed on every export this file format gets fed (a hand-built or trimmed-down one
  // might only have <url>) - fall back to parsing the URL rather than silently sending Intruder
  // an empty host or the wrong scheme.
  let host = m.host || '';
  let protocol = String(m.protocol || '').toLowerCase();
  let port = Number(m.port) || 0;
  if (!host || !protocol || !port) {
    try {
      const u = new URL(m.url);
      host = host || u.hostname;
      protocol = protocol || u.protocol.replace(':', '');
      port = port || (u.port ? Number(u.port) : (protocol === 'https' ? 443 : 80));
    } catch { /* m.url wasn't parseable either - whatever we already have is all there is */ }
  }
  if (!port) port = protocol === 'https' ? 443 : 80;
  return { host, port, https: protocol === 'https', bytes, truncated: m.trunc };
}

module.exports = { list, getRequest, getRawRequest, _cache: cache };
