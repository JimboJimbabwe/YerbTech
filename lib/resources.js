'use strict';
const fs = require('fs/promises');
const path = require('path');
const cfg = require('./config');
const { HttpError } = require('./errors');
const { listDir, findChild, resolveSub, exists } = require('./fsx');

/* ------------------------------------------------------------------ */
/* ROUTING TABLE: where each kind of file is expected inside a         */
/* WSTG-XXXX-NN folder. Change a path here and the whole app follows.  */
/* A segment may be a list of accepted spellings.                      */
/* ------------------------------------------------------------------ */
const INPUTS = 'Inputs';
const WORDLIST_DIR = [INPUTS, ['Wordlists', 'Wordlist']];

const GROUPS = [
  { key: 'scripts', label: 'Scripts', fallback: [['Utilities', 'python'], ['Utilities', 'JS'], ['Utilities', 'GO'], ['Utilities', 'Kali_Tools']] },
  { key: 'json', label: 'JSON', inKey: 'json_in', outKey: 'json_out', dir: [INPUTS, 'JSON'] },
  { key: 'xml', label: 'XML', inKey: 'xml_in', outKey: 'xml_out', dir: [INPUTS, 'XML'] },
  { key: 'wordlists', label: 'Wordlists', inKey: 'wordlist_in', outKey: 'wordlist_out', dir: WORDLIST_DIR },
];

// Where a script is expected, by extension (first entry is the primary location).
const SCRIPT_DIRS = {
  py: [['Utilities', 'python']],
  js: [['Utilities', 'JS']],
  go: [['Utilities', 'GO']],
  sh: [['Utilities', 'Kali_Tools'], ['Utilities', 'python']],
};
const SCRIPT_DEFAULT = [['Utilities', 'python']];

// Reports and sitreps are filed under Inputs/Data per the project convention.
const REPORT_DIR = [INPUTS, 'Data'];

// Used to spot a file that exists but was filed in the wrong sub-folder.
const FILE_FALLBACKS = [[INPUTS, 'Data'], [INPUTS, 'JSON'], [INPUTS, 'XML'], WORDLIST_DIR, ['Outputs', 'test_outputs']];

/* ------------------------------------------------------------------ */

const TEST_DIR_RE = /^(WSTG-[A-Z]{4}-\d{2})(?:_.*)?$/i;

async function repoRoot(projectDir) {
  const real = await findChild(projectDir, [cfg.REPO_DIRNAME]);
  return real ? path.join(projectDir, real) : projectDir;
}

/**
 * Map every WSTG test ID to its folder by scanning for folders named WSTG-XXXX-NN
 * (optionally followed by _description). Works for "01_Information_Gathering/WSTG-INFO-01"
 * as well as the longer "Information_Gathering/WSTG-INFO-01_Conduct_Search..." naming.
 */
async function indexTestDirs(root) {
  const map = new Map();
  let level = [root];
  for (let depth = 0; depth < 4 && level.length; depth++) {
    const next = [];
    for (const dir of level) {
      for (const d of (await listDir(dir)) || []) {
        if (!d.isDirectory()) continue;
        const full = path.join(dir, d.name);
        const m = TEST_DIR_RE.exec(d.name);
        if (m) {
          const id = m[1].toUpperCase();
          if (!map.has(id)) map.set(id, full);
        } else if (!d.name.startsWith('.') && d.name !== 'node_modules') {
          next.push(full);
        }
      }
    }
    level = next;
  }
  return map;
}

async function locateTest(project, id) {
  const root = await repoRoot(project.dir);
  const index = await indexTestDirs(root);
  return { testDir: index.get(id) || null, found: index.size };
}

/* ---------------------------- item handling ------------------------ */

function classify(title) {
  const t = String(title ?? '').trim();
  if (!t || /^none$/i.test(t)) return 'none';
  if (/[<>]/.test(t) || t.includes('...')) return 'dynamic'; // name is built at run time
  if (/^item-specific artifact$/i.test(t) || /^\(generic\)/i.test(t)) return 'user'; // operator names it
  if (/[\\/]/.test(t) || t === '.' || t === '..') return 'invalid';
  return 'named';
}

function normalizeItems(list) {
  const merged = new Map();
  for (const raw of Array.isArray(list) ? list : []) {
    const title = String(raw?.title ?? '').trim();
    const kind = classify(title);
    if (kind === 'none') continue;
    const key = `${kind}:${title.toLowerCase()}`;
    const detail = String(raw?.detail ?? '').trim();
    const type = typeof raw?.type === 'string' && raw.type ? raw.type : null;
    if (merged.has(key)) {
      const m = merged.get(key);
      if (detail && !m.detail.includes(detail)) m.detail = m.detail ? `${m.detail} | ${detail}` : detail;
      if (!m.type && type) m.type = type;
    } else {
      merged.set(key, { title, kind, detail, type });
    }
  }
  return [...merged.values()];
}

/** "info10_collect.py (Script 1 of 2)" -> { title: "info10_collect.py", detail: <original text> } */
function parseScript(text) {
  const s = String(text ?? '').trim();
  const m = /^([A-Za-z0-9_][A-Za-z0-9_.-]*\.[A-Za-z0-9]{1,6})(?=\s|$)/.exec(s);
  return m ? { title: m[1], detail: s } : { title: s, detail: s, forceKind: 'dynamic' };
}

function extOf(name) {
  const m = /\.([A-Za-z0-9]+)$/.exec(name);
  return m ? m[1].toLowerCase() : '';
}

const label = (segs) => segs.map((s) => (Array.isArray(s) ? s[0] : s)).join('/');

/** Cached directory listings for one evaluation run: relative segments -> { abs, names:Map(lower -> real) } */
function makeDirCache(testDir) {
  const cache = new Map();
  return async function get(segs) {
    const key = label(segs);
    if (!cache.has(key)) {
      const abs = testDir ? await resolveSub(testDir, segs) : null;
      const entries = abs ? (await listDir(abs)) || [] : [];
      const names = new Map(entries.map((d) => [d.name.toLowerCase(), d.name]));
      cache.set(key, { abs, names, label: key });
    }
    return cache.get(key);
  };
}

/** Look for a file name in the expected folder(s), then in the fallback folders. */
async function locate(title, primarySegs, fallbackSegs, getDir) {
  for (const segs of primarySegs) {
    const d = await getDir(segs);
    const real = d.names.get(title.toLowerCase());
    if (real && (await exists(path.join(d.abs, real)))) return { status: 'present', real, dir: d };
  }
  for (const segs of fallbackSegs) {
    if (primarySegs.some((p) => label(p) === label(segs))) continue;
    const d = await getDir(segs);
    const real = d.names.get(title.toLowerCase());
    if (real && (await exists(path.join(d.abs, real)))) return { status: 'misplaced', real, dir: d };
  }
  return { status: 'missing' };
}

async function evaluateGroup(g, entry, getDir) {
  const isScripts = g.key === 'scripts';
  const ins = isScripts ? normalizeScripts(entry?.scripts) : normalizeItems(entry?.io?.[g.inKey]);
  const outs = isScripts ? [] : normalizeItems(entry?.io?.[g.outKey]);
  const primaryFor = (item) => (isScripts ? SCRIPT_DIRS[extOf(item.title)] || SCRIPT_DEFAULT : [g.dir]);
  const fallbacks = isScripts ? g.fallback : FILE_FALLBACKS;
  const claimed = new Set();

  const resolveNamed = async (item) => {
    const primary = primaryFor(item);
    const expected = `${label(primary[0])}/${item.title}`;
    let r = await locate(item.title, primary, fallbacks, getDir);
    if (g.key === 'xml' && r.status !== 'present') {
      // An XML title fed by several datasets is stored as stem__dataset.xml (see lib/xml.js).
      const ext = path.extname(item.title);
      const stem = (ext ? item.title.slice(0, -ext.length) : item.title).toLowerCase();
      const d = await getDir(g.dir);
      const hits = [...d.names.entries()].filter(([low]) => low.startsWith(`${stem}__`) && low.endsWith(ext.toLowerCase()) && low.length > stem.length + 2 + ext.length);
      if (hits.length) {
        for (const [, real] of hits) claimed.add(real.toLowerCase());
        const sets = hits.map(([low]) => low.slice(stem.length + 2, low.length - ext.length));
        return { title: item.title, status: 'present', note: `datasets: ${sets.join(', ')}`, detail: item.detail, expected: `${label(primary[0])}/${item.title}` };
      }
    }
    if (r.status === 'present') {
      claimed.add(r.real.toLowerCase());
      return { title: item.title, status: 'present', detail: item.detail, expected };
    }
    if (r.status === 'misplaced') {
      return { title: item.title, status: 'misplaced', note: `found in ${r.dir.label}`, detail: item.detail, expected };
    }
    return { title: item.title, status: 'missing', note: `expected in ${label(primary[0])}`, detail: item.detail, expected };
  };

  const items = [];
  const userItems = [];
  for (const item of ins) {
    if (item.kind === 'named') items.push(await resolveNamed(item));
    else if (item.kind === 'user') userItems.push(item);
    else items.push({ title: item.title, status: 'dynamic', note: 'name is set when the script runs', detail: item.detail });
  }

  const produces = [];
  for (const item of outs) {
    if (item.kind === 'named') {
      const r = await resolveNamed(item);
      produces.push({ ...r, status: r.status === 'missing' ? 'pending' : r.status === 'misplaced' ? 'present' : 'present' });
    } else if (item.kind === 'user') {
      produces.push({ title: item.title, status: 'dynamic', note: 'named by the operator', detail: item.detail });
    } else {
      produces.push({ title: item.title, status: 'dynamic', note: 'name is set when the script runs', detail: item.detail });
    }
  }

  // Operator-supplied inputs have no fixed name. They count as present when the folder holds
  // at least one file that no named expectation already accounts for.
  if (userItems.length) {
    const d = await getDir(g.dir);
    const unclaimed = [...d.names.values()].filter((n) => !n.startsWith('.') && !claimed.has(n.toLowerCase()));
    for (const item of userItems) {
      items.push(
        unclaimed.length
          ? { title: 'Operator-supplied file', status: 'present', note: `${unclaimed.length} unmatched file${unclaimed.length === 1 ? '' : 's'} in ${d.label}`, detail: item.detail }
          : { title: 'Operator-supplied file', status: 'missing', note: `drop it in ${label(g.dir)}`, detail: item.detail },
      );
    }
  }

  const required = items.filter((i) => i.status === 'present' || i.status === 'missing' || i.status === 'misplaced');
  let light = 'grey';
  if (required.length) {
    light = required.some((i) => i.status === 'missing') ? 'red' : required.some((i) => i.status === 'misplaced') ? 'amber' : 'green';
  }
  return { label: g.label, light, items, produces };
}

function normalizeScripts(list) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const p = parseScript(raw);
    if (seen.has(p.title.toLowerCase())) continue;
    seen.add(p.title.toLowerCase());
    out.push({ title: p.title, kind: p.forceKind || classify(p.title), detail: p.detail });
  }
  return out;
}

/** Best-effort: pull file names out of the free-text sitrep_or_output_files strings. */
async function evaluateReports(entry, getDir) {
  const names = new Map();
  for (const s of Array.isArray(entry?.sitrep_or_output_files) ? entry.sitrep_or_output_files : []) {
    for (const m of String(s).matchAll(/[A-Za-z0-9_<>.-]+\.(?:md|txt|json|html|svg|xml|csv)\b/gi)) {
      if (!names.has(m[0].toLowerCase())) names.set(m[0].toLowerCase(), { title: m[0], detail: String(s) });
    }
  }
  const out = [];
  for (const { title, detail } of names.values()) {
    const kind = classify(title);
    if (kind === 'dynamic') {
      out.push({ title, status: 'dynamic', note: 'name includes a run-time value', detail });
    } else if (kind === 'named') {
      const r = await locate(title, [REPORT_DIR], FILE_FALLBACKS, getDir);
      out.push({ title, status: r.status === 'missing' ? 'pending' : 'present', note: r.status === 'misplaced' ? `found in ${r.dir.label}` : undefined, detail });
    }
  }
  return out;
}

/**
 * Everything the checklist box needs for one assessment: for each of Scripts, JSON, XML and
 * Wordlists, an overall light plus a per-file status.
 *   green  all required inputs present
 *   amber  present, but filed in a different sub-folder than expected
 *   red    at least one required input missing
 *   grey   nothing required (or no config entry for this test)
 */
async function checkTest(project, id, io) {
  const { testDir } = await locateTest(project, id);
  const entry = io.byId.get(id);
  const getDir = makeDirCache(testDir);
  const groups = {};
  for (const g of GROUPS) groups[g.key] = await evaluateGroup(g, entry, getDir);
  return {
    id,
    configured: Boolean(entry),
    testDirFound: Boolean(testDir),
    testDir: testDir ? path.relative(project.dir, testDir).split(path.sep).join('/') : null,
    groups,
    reports: await evaluateReports(entry, getDir),
  };
}

/* ------------------------------ wordlists -------------------------- */

async function wordlistDir(testDir) {
  return testDir ? resolveSub(testDir, WORDLIST_DIR) : null;
}

async function listWordlists(project, id, io) {
  const { testDir } = await locateTest(project, id);
  const dir = await wordlistDir(testDir);
  if (!dir) return { dirFound: false, files: [] };

  const declared = new Map();
  const entry = io.byId.get(id);
  for (const [key, tag] of [['wordlist_in', 'in'], ['wordlist_out', 'out']]) {
    for (const it of normalizeItems(entry?.io?.[key])) {
      if (it.kind === 'named' && !declared.has(it.title.toLowerCase())) declared.set(it.title.toLowerCase(), tag);
    }
  }

  const files = [];
  for (const d of (await listDir(dir)) || []) {
    if (d.name.startsWith('.')) continue;
    const st = await fs.stat(path.join(dir, d.name)).catch(() => null); // follows symlinks
    if (!st || !st.isFile()) continue;
    files.push({ name: d.name, size: st.size, declared: declared.get(d.name.toLowerCase()) || null });
  }
  files.sort((a, b) => Number(Boolean(b.declared)) - Number(Boolean(a.declared)) || a.name.localeCompare(b.name));
  return { dirFound: true, files };
}

async function readWordlist(project, id, file) {
  if (typeof file !== 'string' || !file || file !== path.basename(file) || file.startsWith('.') || /[\\/\0]/.test(file)) {
    throw new HttpError(400, 'Invalid file name.');
  }
  const { testDir } = await locateTest(project, id);
  const dir = await wordlistDir(testDir);
  const hit = dir && ((await listDir(dir)) || []).find((d) => d.name === file);
  if (!hit) throw new HttpError(404, 'Wordlist not found.');

  const full = path.join(dir, hit.name);
  const st = await fs.stat(full).catch(() => null);
  if (!st || !st.isFile()) throw new HttpError(404, 'Wordlist not found.');
  if (st.size > cfg.MAX_COPY_BYTES) {
    const mb = (st.size / 1048576).toFixed(1);
    throw new HttpError(413, `${file} is ${mb} MB, over the ${(cfg.MAX_COPY_BYTES / 1048576).toFixed(0)} MB copy limit. Use the file directly.`);
  }
  const buf = await fs.readFile(full);
  if (buf.subarray(0, 8192).includes(0)) throw new HttpError(415, `${file} looks binary, so it can't be copied as text.`);
  return buf.toString('utf8').replace(/^﻿/, '');
}

module.exports = { indexTestDirs, locateTest, checkTest, listWordlists, readWordlist, repoRoot, normalizeItems, classify };
