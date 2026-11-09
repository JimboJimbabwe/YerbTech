'use strict';
/**
 * Turns wstg_tools_procedures.json into a "command model" for one assessment: which scripts run in
 * which order, and for each one the flags, the files it should be given and where they live.
 *
 * Nothing here runs anything. The model is data; public/js/cmdline.mjs turns it into a command
 * string for the shell the operator picks.
 *
 * Where files are expected (the part that matters most):
 *   <project>/WSTG_Repository/<category>/<ID>/Inputs/XML        XML_INPUT
 *   <project>/WSTG_Repository/<category>/<ID>/Inputs/JSON       JSON_INPUT
 *   <project>/WSTG_Repository/<category>/<ID>/Inputs/Wordlists  WORDLIST_INPUT
 * File NAMES come from wstg_io.json (the same source the file checks use). The path strings inside
 * the procedures file are only used as hints, because they are written in several different styles.
 */
const fs = require('fs/promises');
const path = require('path');
const cfg = require('./config');
const { DataError } = require('./errors');
const { readJson, derive, ID_RE } = require('./data');
const { listDir, findChild } = require('./fsx');
const { repoRoot, indexTestDirs, normalizeItems } = require('./resources');

/* ------------------------------ tag tables ------------------------------ */

const FILE_TAGS = { XML_INPUT: 'xml', JSON_INPUT: 'json', WORDLIST_INPUT: 'wordlist', MD_INPUT: 'md', TXT_INPUT: 'txt' };
const VALUE_TAGS = new Set(['URL_INPUT', 'DOMAIN_INPUT', 'IP_INPUT', 'KEYWORD_INPUT', 'TEXT_INPUT', 'FILETYPE_INPUT']);

// Folder (inside the assessment) where each kind of input file is expected; first entry is the primary one.
const TAG_DIRS = {
  xml: [['Inputs', 'XML']],
  json: [['Inputs', 'JSON'], ['Inputs', 'Data']],
  wordlist: [['Inputs', ['Wordlists', 'Wordlist']]],
  md: [['Outputs', 'test_outputs'], ['Inputs', 'Data']],
  txt: [['Inputs', 'Data'], ['Outputs', 'test_outputs']],
};
// wstg_io.json list that names the files for each tag.
const IO_KEYS = { xml: 'xml_in', json: 'json_in', wordlist: 'wordlist_in' };

const CANON = { inputs: 'Inputs', outputs: 'Outputs', utilities: 'Utilities', methodology: 'Methodology', json: 'JSON', xml: 'XML', data: 'Data', wordlist: 'Wordlists', wordlists: 'Wordlists', test_outputs: 'test_outputs' };
const KNOWN_ROOTS = new Set(['inputs', 'outputs', 'utilities', 'methodology']);

const SCRIPT_DIRS = {
  py: [['Utilities', 'python']], js: [['Utilities', 'JS']], go: [['Utilities', 'GO']],
  sh: [['Utilities', 'Kali_Tools'], ['Utilities', 'python']],
};
const ALL_SCRIPT_DIRS = [['Utilities', 'python'], ['Utilities', 'JS'], ['Utilities', 'GO'], ['Utilities', 'Kali_Tools']];
const INTERPRETERS = { py: 'python', js: 'node', sh: 'bash', go: 'go run' };

/* ------------------------- flag / template inference -------------------- */

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** "-x / --xml" or "-o, --output" -> ["-x", "--xml"] */
function splitFlags(flag) {
  if (typeof flag !== 'string') return [];
  return flag.split(/\s*(?:\/|,|\bor\b)\s*/).map((f) => f.trim()).filter((f) => /^-{1,2}[A-Za-z0-9][\w-]*$/.test(f));
}

/** Square-bracket depth at each character of a command template. */
function depthAt(cmd, index) {
  let d = 0;
  for (let i = 0; i < index; i++) { if (cmd[i] === '[') d++; else if (cmd[i] === ']') d = Math.max(0, d - 1); }
  return d;
}

/** Locate a flag in a command template. Returns { index, next } or null. */
function findFlag(cmd, flags) {
  if (!cmd) return null;
  for (const f of flags) {
    const m = new RegExp(`(?:^|[\\s\\[|])(${esc(f)})(?:=|(?=[\\s\\]|]|$))\\s*(\\S*)`).exec(cmd);
    if (m) return { index: m.index + m[0].indexOf(m[1]), next: m[2] || '' };
  }
  return null;
}

/**
 * Does this flag take a value? true / false / null (can't tell).
 * An explicit takes_value in the JSON always wins (tools/annotate_procedures.js writes it).
 */
function inferTakesValue(input, command) {
  if (typeof input.takes_value === 'boolean') return input.takes_value;
  if (FILE_TAGS[input.tag] || VALUE_TAGS.has(input.tag)) return true;
  if (typeof input.default === 'number' || typeof input.default === 'string') return true;
  const flags = splitFlags(input.flag);
  const hit = findFlag(command, flags);
  if (!hit) return flags.some((f) => /^--(no|skip)-|-only$|^--(reset|init|all|verbose|quiet|force|dry-run)$/.test(f)) ? false : null;
  const t = hit.next;
  if (!t || /^[\]|]/.test(t) || /^\[?-/.test(t) || /^\[/.test(t)) return false;
  return true;
}

/** Is an output flag required? Optional when it sits inside [ ] in the template, or the template is unknown. */
function outputFlagRequired(output, command) {
  if (typeof output.flag_required === 'boolean') return output.flag_required;
  const hit = findFlag(command, splitFlags(output.flag));
  return Boolean(hit) && depthAt(command, hit.index) === 0;
}

/** Split a template on top-level " | " into alternative full commands. */
function splitAlternatives(cmd) {
  if (!cmd) return [];
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < cmd.length; i++) {
    if (cmd[i] === '[') depth++;
    else if (cmd[i] === ']') depth = Math.max(0, depth - 1);
    else if (cmd[i] === '|' && depth === 0 && /\s/.test(cmd[i - 1] || '') && /\s/.test(cmd[i + 1] || '')) { out.push(cmd.slice(start, i).trim()); start = i + 1; }
  }
  out.push(cmd.slice(start).trim());
  return out.length > 1 ? out : [];
}

function tokenize(s) {
  return (String(s).match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) => t.replace(/^(["'])(.*)\1$/, '$2'));
}

/** "--xml ... --username jsmith" -> { '--xml': true, '--username': 'jsmith' } (placeholders become true). */
function flagsInExample(example) {
  const toks = tokenize(example);
  const out = {};
  for (let i = 0; i < toks.length; i++) {
    if (!/^-{1,2}[A-Za-z0-9][\w-]*$/.test(toks[i])) continue;
    const nxt = toks[i + 1];
    const real = nxt !== undefined && !/^-/.test(nxt) && !/\.\.\.|^<|^\[|\/path\/to|^\]/.test(nxt);
    out[toks[i]] = real ? nxt : true;
  }
  return out;
}

/* ------------------------------ loading --------------------------------- */

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 9999);

function normalize(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new DataError(`${cfg.PROCEDURES_FILE} must be a JSON object.`);
  const byId = new Map();
  const problems = [];
  for (const [catKey, ids] of Object.entries(raw)) {
    if (catKey === '_meta' || catKey === 'category_run_order') continue;
    if (!ids || typeof ids !== 'object' || Array.isArray(ids)) { problems.push(`${catKey}: not an object`); continue; }
    for (const [id, groups] of Object.entries(ids)) {
      if (!ID_RE.test(id)) { problems.push(`${catKey}/${id}: not an assessment ID`); continue; }
      const scripts = [];
      for (const group of Object.values(groups && typeof groups === 'object' ? groups : {})) {
        if (!group || typeof group !== 'object') continue;
        for (const [key, s] of Object.entries(group)) {
          if (!s || typeof s.name !== 'string' || !s.name || s.name !== path.basename(s.name) || /[\\/]/.test(s.name)) {
            problems.push(`${id}/${key}: script name missing or not a plain file name`);
            continue;
          }
          scripts.push({ key, ...s });
        }
      }
      scripts.sort((a, b) => num(a.run_order) - num(b.run_order));
      byId.set(id, { category: catKey, scripts });
    }
  }
  const order = new Map();
  const list = Array.isArray(raw.category_run_order) ? raw.category_run_order : [];
  for (const e of list) if (e && ID_RE.test(String(e.id))) order.set(e.id, { order: num(e.order), reason: typeof e.reason === 'string' ? e.reason : '' });
  return { byId, order, total: list.length || byId.size, problems };
}

async function getProcedures() {
  const file = path.join(cfg.DATA_DIR, cfg.PROCEDURES_FILE);
  await readJson(file, cfg.PROCEDURES_FILE);
  return derive(file, normalize);
}

/* ---------------------------- path resolution --------------------------- */

const STOP = new Set(['from', 'the', 'file', 'list', 'script', 'input', 'output', 'json', 'txt', 'xml', 'wordlist', 'md', 'out', 'and', 'for', 'path']);
/** Rough word set for matching an input to the earlier output that feeds it: "--url-list" ~ "curl_urls.txt". */
function words(s) {
  return new Set(String(s).toLowerCase().split(/[^a-z0-9]+/).map((w) => w.replace(/s$/, '')).filter((w) => w.length > 2 && !STOP.has(w)));
}
const OUT_TO_IN = { XML_OUTPUT: 'xml', JSON_OUTPUT: 'json', WORDLIST_OUTPUT: 'wordlist', MD_OUTPUT: 'md', TXT_OUTPUT: 'txt' };

const isPlaceholder = (p) => /[<>*]|\.\.\./.test(String(p));
const isFile = async (p) => (await fs.stat(p).catch(() => null))?.isFile() === true;

/** Walk segments under base. Existing parts use the real (case-insensitive) name, missing parts the canonical one. */
async function walk(base, segs) {
  let cur = base;
  for (const raw of segs) {
    const canon = CANON[raw.toLowerCase()] || raw;
    const aliases = /^wordlists?$/i.test(raw) ? ['Wordlists', 'Wordlist'] : [canon, raw];
    const real = await findChild(cur, aliases);
    cur = path.join(cur, real || canon);
  }
  return cur;
}

/** "WSTG_Repository/02_X/WSTG-CONF-02/inputs/json/a.json" -> { owner, segs: ['inputs','json','a.json'] } */
function parseHint(hint, ownId) {
  const segs = String(hint).replace(/\\/g, '/').trim().replace(/^\/+/, '').split('/').filter(Boolean);
  if (/^WSTG_Repository$/i.test(segs[0] || '')) segs.shift();
  if (/^\d{2}_/.test(segs[0] || '')) segs.shift();
  let owner = ownId;
  if (/^WSTG-[A-Z]{4}-\d{2}$/i.test(segs[0] || '')) owner = segs.shift().toUpperCase();
  return { owner, segs };
}

/* ------------------------------- model ---------------------------------- */

async function buildModel(project, id, io) {
  const proc = await getProcedures();
  const entry = proc.byId.get(id);
  const pos = proc.order.get(id);
  const position = pos ? { order: pos.order, total: proc.total, reason: pos.reason } : null;
  if (!entry) return { id, available: false, position, scripts: [] };

  const root = await repoRoot(project.dir);
  const index = await indexTestDirs(root);
  const dirOf = (tid) => index.get(tid) || path.join(root, proc.byId.get(tid)?.category || entry.category, tid);
  const testDir = dirOf(id);

  const dirCache = new Map();
  const fileNames = async (dir) => {
    if (!dirCache.has(dir)) dirCache.set(dir, ((await listDir(dir)) || []).filter((d) => !d.name.startsWith('.')).map((d) => d.name));
    return dirCache.get(dir);
  };

  const tagDir = async (tag, ownerDir = testDir, which = 0) => walk(ownerDir, TAG_DIRS[tag][which].flat());

  /** Candidate files for a file input, most likely first. */
  async function candidatesFor(input, tag, upstream = [], claimed = new Set()) {
    const seen = new Set();
    const out = [];
    const add = async (abs, label, rank, score = 0) => {
      const key = abs.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ path: abs, exists: await isFile(abs), label, rank, score, order: out.length });
    };

    if (input.path && !isPlaceholder(input.path)) {
      const { owner, segs } = parseHint(input.path, id);
      const ownerDir = dirOf(owner);
      if (segs.length && KNOWN_ROOTS.has(segs[0].toLowerCase())) {
        await add(await walk(ownerDir, segs), 'named in the procedures file', 0);
      } else if (segs.length) {
        // A bare file name such as how_to_steps_bridge.json: look in the usual folders for this kind.
        const name = segs[segs.length - 1];
        for (let w = 0; w < TAG_DIRS[tag].length; w++) {
          const dir = await tagDir(tag, ownerDir, w);
          if ((await fileNames(dir)).some((n) => n.toLowerCase() === name.toLowerCase())) { await add(path.join(dir, (await fileNames(dir)).find((n) => n.toLowerCase() === name.toLowerCase())), 'found in the project', 0); break; }
        }
        if (!out.length) await add(path.join(await tagDir(tag, ownerDir), name), 'expected here', 0);
      }
    }

    const dir = await tagDir(tag);
    const names = IO_KEYS[tag] ? normalizeItems(io.byId.get(id)?.io?.[IO_KEYS[tag]]).filter((i) => i.kind === 'named') : [];
    const present = await fileNames(dir);
    for (const n of names) {
      const real = present.find((p) => p.toLowerCase() === n.title.toLowerCase());
      await add(path.join(dir, real || n.title), 'named in wstg_io.json', 1);
      const stem = path.basename(n.title, path.extname(n.title)).toLowerCase();
      for (const p of present) {
        if (p.toLowerCase().startsWith(`${stem}__`) && p.toLowerCase().endsWith(path.extname(n.title).toLowerCase())) {
          await add(path.join(dir, p), `dataset: ${p.slice(stem.length + 2, p.length - path.extname(p).length)}`, 1);
        }
      }
    }
    // Outputs of earlier scripts in the same assessment (their flag and file names say which input they feed).
    const want = words(`${input.flag || ''} ${input.description || ''}`);
    for (const u of upstream) {
      if (u.tag !== tag) continue;
      const score = [...words(`${u.flag || ''} ${path.basename(u.path)}`)].filter((w) => want.has(w)).length;
      await add(u.path, `output of ${u.script}`, claimed.has(u.path.toLowerCase()) ? 3 : 2, score);
    }
    for (const p of present.slice(0, 15)) await add(path.join(dir, p), 'in this folder', 3);
    out.sort((a, b) => a.rank - b.rank || Number(b.exists) - Number(a.exists) || b.score - a.score || a.order - b.order);
    return { candidates: out.map(({ path: p, exists, label }) => ({ path: p, exists, label })), dir };
  }

  async function outputValue(o) {
    if (!o.path || isPlaceholder(o.path)) return null;
    const { owner, segs } = parseHint(o.path, id);
    if (!segs.length) return null;
    const base = dirOf(owner);
    const rooted = KNOWN_ROOTS.has(segs[0].toLowerCase()) ? segs : ['Outputs', 'test_outputs', ...segs];
    return walk(base, rooted);
  }

  async function locateScript(name) {
    const ext = (/\.([A-Za-z0-9]+)$/.exec(name) || [])[1]?.toLowerCase() || '';
    const dirs = [...(SCRIPT_DIRS[ext] || []), ...ALL_SCRIPT_DIRS];
    for (const segs of dirs) {
      const dir = await walk(testDir, segs.flat());
      const hit = (await fileNames(dir)).find((n) => n.toLowerCase() === name.toLowerCase());
      if (hit) return { abs: path.join(dir, hit), exists: true, ext };
    }
    return { abs: path.join(await walk(testDir, (SCRIPT_DIRS[ext] || [['Utilities', 'python']])[0].flat()), name), exists: false, ext };
  }

  const scripts = [];
  const upstream = []; // outputs of the scripts already processed, in run order
  for (const [n, s] of entry.scripts.entries()) {
    const command = typeof s.command === 'string' && s.command.trim() ? s.command.trim() : null;
    const where = await locateScript(s.name);
    const items = [];
    const writes = [];
    const interactive = [];
    const notes = [];
    const claimed = new Set();

    for (const [k, i] of (Array.isArray(s.inputs) ? s.inputs : []).entries()) {
      const flags = splitFlags(i.flag);
      const base = { id: `in${k}`, tag: String(i.tag || ''), flags, flag: flags[0] || null, description: i.description || '', required: i.required === true, default: i.default ?? null };

      if (i.tag === 'INTERACTIVE_INPUT') { interactive.push({ description: base.description }); continue; }
      if (i.tag === 'UNKNOWN_INPUT') { notes.push(`Undocumented input: ${base.description}`); continue; }

      const ftag = FILE_TAGS[i.tag];
      if (ftag) {
        if (!flags.length && i.path && command) { // a state file the script reads on its own, nothing to type
          const c = await candidatesFor(i, ftag, upstream, claimed);
          interactive.push({ description: `${base.description || 'Reads a file by itself'}`, implicit: c.candidates[0] || null });
          continue;
        }
        const c = await candidatesFor(i, ftag, upstream, claimed);
        if (c.candidates[0]?.label.startsWith('output of')) claimed.add(c.candidates[0].path.toLowerCase());
        const optionalByDefault = !base.required;
        items.push({
          ...base, kind: 'file', takesValue: true, include: !optionalByDefault,
          candidates: c.candidates, value: c.candidates[0]?.path || null, expectedDir: c.dir,
          missing: !c.candidates[0]?.exists, positional: !flags.length, flagUnknown: !flags.length && !command,
        });
        continue;
      }
      if (VALUE_TAGS.has(i.tag)) {
        items.push({ ...base, kind: 'value', takesValue: true, include: base.required, value: base.default !== null && typeof base.default !== 'boolean' ? String(base.default) : '', positional: !flags.length });
        continue;
      }
      if (i.tag === 'OPTION_INPUT' || flags.length) {
        const tv = inferTakesValue(i, command);
        if (!flags.length) continue;
        items.push({
          ...base, kind: tv === false ? 'switch' : 'value', takesValue: tv !== false, flagUnsure: tv === null,
          include: base.required, value: base.default !== null && typeof base.default !== 'boolean' ? String(base.default) : '',
        });
      }
    }

    // svc_dsr-style "modes": one flag chosen per run, some with a list of allowed values.
    for (const [k, m] of (Array.isArray(s.modes) ? s.modes : []).entries()) {
      const flags = splitFlags(m.flag);
      if (!flags.length || items.some((x) => x.flags.includes(flags[0]))) continue;
      const choices = Array.isArray(m.values) ? m.values.map(String) : null;
      items.push({ id: `mode${k}`, tag: 'MODE', flags, flag: flags[0], description: m.description || '', required: false, default: null, kind: choices ? 'value' : 'switch', takesValue: Boolean(choices), include: false, value: choices ? choices[0] : '', choices, group: 'Mode (pick one)' });
    }

    for (const o of Array.isArray(s.outputs) ? s.outputs : []) {
      const flags = splitFlags(o.flag);
      const value = await outputValue(o);
      if (flags.length) {
        const req = outputFlagRequired(o, command);
        items.push({ id: `out${items.length}`, tag: String(o.tag || ''), flags, flag: flags[0], description: o.description || '', required: req, default: null, kind: 'output', takesValue: true, include: req, value: value || '', placeholder: o.path || '' });
      } else {
        writes.push({ tag: String(o.tag || ''), path: o.path ? (isPlaceholder(o.path) ? o.path : (await outputValue(o)) || o.path) : null, condition: o.condition || '', description: o.description || '' });
      }
    }

    // Presets: alternative invocations written in the docs. Each one just switches fields on or off.
    const presets = [];
    const flagKey = (f) => items.find((x) => x.flags.includes(f))?.flag;
    const presetFrom = (label, example) => {
      const used = flagsInExample(example);
      const active = {};
      for (const [f, v] of Object.entries(used)) { const key = flagKey(f); if (key) active[key] = v; }
      if (Object.keys(active).length) presets.push({ label, active });
    };
    for (const v of Array.isArray(s.run_variants) ? s.run_variants : []) if (v && v.example) presetFrom(v.description || v.example, v.example);
    splitAlternatives(command).forEach((alt, k) => presetFrom(`Alternative ${k + 1}: ${alt.replace(/^\S+\s+\S+\s*/, '').slice(0, 70)}`, alt.replace(/\[|\]/g, ' ')));

    for (const o of Array.isArray(s.outputs) ? s.outputs : []) {
      const tag = OUT_TO_IN[o.tag];
      const abs = tag ? await outputValue(o) : null;
      if (abs) upstream.push({ tag, path: abs, script: s.name, flag: splitFlags(o.flag)[0] || '' });
    }

    // Inputs that an earlier script in this assessment will create are not "missing", just not there yet.
    const missingInputs = items.filter((x) => x.kind === 'file' && x.required && x.missing && !x.candidates[0]?.label.startsWith('output of')).length;
    scripts.push({
      key: s.key, name: s.name, position: n + 1, total: entry.scripts.length, runOrder: num(s.run_order),
      description: s.description || s.step_label || '',
      after: (Array.isArray(s.depends_on) ? s.depends_on : []).map(String),
      notes: [s.order_note, s.note, s.status_note, ...notes].filter((x) => typeof x === 'string' && x),
      inferred: s.inferred === true, commandKnown: command !== null, template: command,
      script: { path: where.abs, exists: where.exists, interpreter: INTERPRETERS[where.ext] || null },
      workdir: testDir,
      items, writes, interactive, presets,
      status: { scriptFound: where.exists, missingInputs },
    });
  }
  return { id, available: true, category: entry.category, position, platform: process.platform, scripts };
}

module.exports = { getProcedures, buildModel, normalize, splitFlags, inferTakesValue, outputFlagRequired, splitAlternatives, flagsInExample, findFlag, FILE_TAGS, VALUE_TAGS };
