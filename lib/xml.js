'use strict';
/**
 * XML intake and distribution.
 *
 *   <project>/project_utilities/files/XML/<kind folder>/<category>/<category file>   (the one stored copy)
 *   <project>/project_utilities/archive/XML/<kind folder>/<category>/<stamp>_<file>   (replaced uploads)
 *   <project>/project_utilities/manifest.json                                         (what was copied where)
 *
 * A stored file is copied into <assessment>/Inputs/XML/ under the name wstg_io.json expects
 * (raw.xml -> fingerprint_targets.xml). Which assessments get which category comes from
 * data/json/xml_routing.json. Everything that touches a project's files runs under a
 * per-project lock, so two uploads can't interleave.
 */
const fs = require('fs/promises');
const fss = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Transform } = require('stream');
const { pipeline } = require('stream/promises');
const cfg = require('./config');
const { HttpError } = require('./errors');
const { getRouting, getIo } = require('./data');
const { listDir, findChild, resolveSub } = require('./fsx');
const { repoRoot, indexTestDirs, locateTest, normalizeItems } = require('./resources');

const HEAD_BYTES = 16 * 1024;
const VIEWABLE = new Set(['burp_proxy_xml']); // kinds the request viewer can open

const utilDir = (p) => path.join(p.dir, cfg.UTIL_DIRNAME);
const intakeDir = (p, k, c) => path.join(utilDir(p), 'files', 'XML', k.folder, c.key);
const archiveDir = (p, k, c) => path.join(utilDir(p), 'archive', 'XML', k.folder, c.key);
const manifestFile = (p) => path.join(utilDir(p), 'manifest.json');
const rand = () => crypto.randomBytes(4).toString('hex');
const stamp = () => new Date().toISOString().replace(/[:.]/g, '-');

/* ------------------------------- lock -------------------------------- */

const locks = new Map();
function withLock(key, fn) {
  const prev = locks.get(key) || Promise.resolve();
  const run = prev.then(fn);
  const tail = run.catch(() => {});
  locks.set(key, tail);
  tail.then(() => { if (locks.get(key) === tail) locks.delete(key); });
  return run;
}

/* ----------------------------- manifest ------------------------------ */

async function readManifest(project) {
  try {
    const m = JSON.parse(await fs.readFile(manifestFile(project), 'utf8'));
    if (m && typeof m.sources === 'object' && m.sources !== null) return m;
  } catch { /* missing or damaged: rebuilt from what is on disk */ }
  return { version: 1, sources: {} };
}

async function writeManifest(project, m) {
  const file = manifestFile(project);
  const tmp = `${file}.${rand()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(m, null, 2));
  await fs.rename(tmp, file);
}

/* ------------------------------ folders ------------------------------ */

async function ensureUtilities(projectDir, routing) {
  const project = { dir: projectDir };
  const r = routing || (await getRouting());
  await fs.mkdir(path.join(utilDir(project), 'tmp'), { recursive: true });
  for (const kind of r.kinds) {
    if (!kind.enabled) continue;
    for (const cat of kind.categories) await fs.mkdir(intakeDir(project, kind, cat), { recursive: true });
  }
}

async function ensureSub(root, segs) {
  let cur = root;
  for (const s of segs) {
    const real = await findChild(cur, [s]);
    cur = path.join(cur, real || s);
    if (!real) await fs.mkdir(cur);
  }
  return cur;
}

/* ------------------------------ routing ------------------------------ */

function matches(cat, id) {
  if (cat.omit.includes(id)) return false;
  return cat.include.some((s) => id === s || id.startsWith(`${s}-`));
}

function variantName(title, catKey) {
  const ext = path.extname(title);
  const stem = ext ? title.slice(0, -ext.length) : title;
  return `${stem}__${catKey}${ext}`;
}

/**
 * For one assessment: which uploaded categories feed which xml_in titles, and which xml_in
 * entries could not be fed (and why). A title fed by more than one category gets a per-category
 * file name so the copies sit side by side instead of overwriting each other.
 */
function routesFor(routing, io, id) {
  const items = normalizeItems(io.byId.get(id)?.io?.xml_in);
  const ops = [];
  const skipped = [];
  for (const kind of routing.kinds) {
    if (!kind.enabled) continue;
    const feeds = new Map(); // title -> Set(category keys)
    const found = [];
    for (const cat of kind.categories) {
      if (!matches(cat, id)) continue;
      for (const item of items) {
        const fits = item.type ? kind.acceptsTypes.includes(item.type) : kind.includeUntyped;
        if (!fits) {
          if (!item.type) skipped.push({ kind, cat, title: item.title, reason: 'no "type" set for this xml_in entry in wstg_io.json' });
          continue;
        }
        if (item.kind !== 'named') {
          skipped.push({ kind, cat, title: item.title, reason: 'file name is not fixed' });
          continue;
        }
        const k = item.title.toLowerCase();
        if (!feeds.has(k)) feeds.set(k, new Set());
        feeds.get(k).add(cat.key);
        found.push({ kind, cat, title: item.title, k });
      }
    }
    for (const f of found) {
      const shared = feeds.get(f.k).size > 1;
      ops.push({ kind: f.kind, cat: f.cat, title: f.title, outName: shared ? variantName(f.title, f.cat.key) : f.title, shared });
    }
  }
  return { ops, skipped };
}

async function buildPlan(project, routing, io) {
  const index = await indexTestDirs(await repoRoot(project.dir));
  const ops = new Map();
  const skipped = new Map();
  const push = (m, key, v) => { if (!m.has(key)) m.set(key, []); m.get(key).push(v); };
  for (const id of io.byId.keys()) {
    const r = routesFor(routing, io, id);
    const testDir = index.get(id) || null;
    for (const o of r.ops) {
      const key = `${o.kind.key}/${o.cat.key}`;
      if (!testDir) push(skipped, key, { testId: id, title: o.outName, reason: 'assessment folder not found in this project' });
      else push(ops, key, { testId: id, testDir, title: o.title, outName: o.outName });
    }
    for (const s of r.skipped) push(skipped, `${s.kind.key}/${s.cat.key}`, { testId: id, title: s.title, reason: s.reason });
  }
  return { ops, skipped };
}

/** Copy one stored file into every assessment it feeds. Returns the manifest record. */
async function distribute(project, plan, kind, cat, src, st, archived) {
  const key = `${kind.key}/${cat.key}`;
  const distributed = [];
  const skipped = [...(plan.skipped.get(key) || [])];
  for (const op of plan.ops.get(key) || []) {
    let tmp = null;
    try {
      const dir = await ensureSub(op.testDir, ['Inputs', 'XML']);
      tmp = path.join(dir, `.${op.outName}.${rand()}.tmp`);
      await fs.copyFile(src, tmp);
      await fs.rename(tmp, path.join(dir, op.outName));
      distributed.push({ testId: op.testId, file: op.outName });
    } catch (e) {
      if (tmp) await fs.rm(tmp, { force: true }).catch(() => {});
      skipped.push({ testId: op.testId, title: op.outName, reason: `copy failed: ${e.code || e.message}` });
    }
  }
  return {
    name: cat.file,
    size: st.size,
    mtimeMs: st.mtimeMs,
    at: new Date().toISOString(),
    archived: archived || null,
    distributed,
    skipped,
  };
}

/**
 * Pick up files dropped straight into the intake folders (or changed by hand) since the last
 * look. Cheap: it stats at most one file per category and only copies when something changed.
 */
async function syncLocked(project, routing, io) {
  const manifest = await readManifest(project);
  let plan = null;
  let changed = false;
  for (const kind of routing.kinds) {
    if (!kind.enabled) continue;
    for (const cat of kind.categories) {
      const key = `${kind.key}/${cat.key}`;
      const src = path.join(intakeDir(project, kind, cat), cat.file);
      const st = await fs.lstat(src).catch(() => null);
      const rec = manifest.sources[key];
      if (!st || !st.isFile()) {
        if (rec) { delete manifest.sources[key]; changed = true; }
        continue;
      }
      if (rec && rec.size === st.size && rec.mtimeMs === st.mtimeMs) continue;
      plan = plan || (await buildPlan(project, routing, io));
      manifest.sources[key] = await distribute(project, plan, kind, cat, src, st, null);
      changed = true;
    }
  }
  if (changed) await writeManifest(project, manifest);
  return manifest;
}

/* ------------------------------- status ------------------------------ */

function compose(routing, manifest) {
  return {
    limits: { maxXmlBytes: cfg.MAX_XML_BYTES },
    kinds: routing.kinds.map((k) => ({
      key: k.key,
      title: k.title,
      enabled: k.enabled,
      categories: k.categories.map((c) => {
        const rec = k.enabled ? manifest.sources[`${k.key}/${c.key}`] : null;
        return {
          key: c.key,
          label: c.label,
          file: c.file,
          present: Boolean(rec),
          size: rec ? rec.size : null,
          uploadedAt: rec ? rec.at : null,
          replaced: Boolean(rec?.archived),
          copies: rec ? rec.distributed : [],
          skipped: rec ? rec.skipped : [],
        };
      }),
    })),
  };
}

async function prepared(project) {
  const routing = await getRouting();
  const io = await getIo();
  await ensureUtilities(project.dir, routing);
  const manifest = await syncLocked(project, routing, io);
  return { routing, io, manifest };
}

function getStatus(project) {
  return withLock(project.dir, async () => {
    const { routing, manifest } = await prepared(project);
    return compose(routing, manifest);
  });
}

/* ------------------------------- upload ------------------------------ */

function pick(routing, kindKey, catKey) {
  const kind = routing.kinds.find((k) => k.key === kindKey);
  if (!kind) throw new HttpError(404, 'Unknown XML type.');
  if (!kind.enabled) throw new HttpError(409, `${kind.title} is not enabled yet.`);
  const cat = kind.categories.find((c) => c.key === catKey);
  if (!cat) throw new HttpError(404, 'Unknown category.');
  return { kind, cat };
}

function sniff(head, kind) {
  const text = head.toString('utf8').replace(/^﻿/, '');
  if (!/^\s*<(\?xml|!DOCTYPE|[A-Za-z])/i.test(text)) return 'That does not look like an XML file.';
  if (kind.rootElement && !new RegExp(`<${kind.rootElement}[\\s>]`).test(text)) {
    return `That is XML, but not a ${kind.title} export (no <${kind.rootElement}> element near the top).`;
  }
  return null;
}

/** Stream the request body to disk (never into memory), check it, then install and distribute. */
async function saveUpload(project, kindKey, catKey, req) {
  const routing = await getRouting();
  const io = await getIo();
  const { kind, cat } = pick(routing, kindKey, catKey);

  const declared = Number(req.headers['content-length']);
  if (declared > cfg.MAX_XML_BYTES) throw new HttpError(413, `That file is over the ${Math.round(cfg.MAX_XML_BYTES / 1048576)} MB limit.`);
  await ensureUtilities(project.dir, routing);

  const tmp = path.join(utilDir(project), 'tmp', `${stamp()}-${rand()}.upload`);
  let bytes = 0;
  const head = [];
  let headLen = 0;
  const gate = new Transform({
    transform(chunk, enc, cb) {
      bytes += chunk.length;
      if (bytes > cfg.MAX_XML_BYTES) return cb(new HttpError(413, `That file is over the ${Math.round(cfg.MAX_XML_BYTES / 1048576)} MB limit.`));
      if (headLen < HEAD_BYTES) {
        const part = chunk.subarray(0, HEAD_BYTES - headLen);
        head.push(part);
        headLen += part.length;
      }
      cb(null, chunk);
    },
  });
  try {
    await pipeline(req, gate, fss.createWriteStream(tmp, { flags: 'wx' }));
    if (bytes === 0) throw new HttpError(400, 'The file is empty.');
    const problem = sniff(Buffer.concat(head), kind);
    if (problem) throw new HttpError(422, problem);
  } catch (e) {
    await fs.rm(tmp, { force: true }).catch(() => {});
    throw e instanceof HttpError ? e : new HttpError(400, 'The upload was interrupted.');
  }

  return withLock(project.dir, async () => {
    try {
      const manifest = await syncLocked(project, routing, io); // pick up hand-dropped files first, so nothing is skipped
      const dest = path.join(intakeDir(project, kind, cat), cat.file);
      await fs.mkdir(path.dirname(dest), { recursive: true });
      let archived = null;
      const prev = await fs.lstat(dest).catch(() => null);
      if (prev && prev.isFile()) {
        archived = `${stamp()}_${cat.file}`;
        const adir = archiveDir(project, kind, cat);
        await fs.mkdir(adir, { recursive: true });
        await fs.rename(dest, path.join(adir, archived));
      }
      await fs.rename(tmp, dest);

      const plan = await buildPlan(project, routing, io);
      manifest.sources[`${kind.key}/${cat.key}`] = await distribute(project, plan, kind, cat, dest, await fs.lstat(dest), archived);
      await writeManifest(project, manifest);
      return compose(routing, manifest);
    } finally {
      await fs.rm(tmp, { force: true }).catch(() => {});
    }
  });
}

/* ------------------------------ viewer ------------------------------- */

/**
 * What XML does this assessment take, and which of those files are on disk? `datasets` are the
 * ones the request viewer can open (an assessment fed by two categories has two to switch between).
 */
function datasetsFor(project, id, { withPaths = false } = {}) {
  return withLock(project.dir, async () => {
    const { routing, io, manifest } = await prepared(project);
    const { testDir } = await locateTest(project, id);
    const xmlDir = testDir ? await resolveSub(testDir, ['Inputs', 'XML']) : null;
    const present = new Map(((xmlDir && (await listDir(xmlDir))) || []).map((d) => [d.name.toLowerCase(), d.name]));

    const eligible = [];
    const datasets = [];
    for (const o of routesFor(routing, io, id).ops) {
      const real = present.get(o.outName.toLowerCase());
      const st = real ? await fs.stat(path.join(xmlDir, real)).catch(() => null) : null;
      const have = Boolean(st && st.isFile());
      const row = {
        kind: o.kind.key,
        kindTitle: o.kind.title,
        category: o.cat.key,
        label: o.cat.label,
        name: o.outName,
        present: have,
        uploaded: Boolean(manifest.sources[`${o.kind.key}/${o.cat.key}`]),
        size: have ? st.size : null,
      };
      eligible.push(row);
      if (have && VIEWABLE.has(o.kind.key)) {
        datasets.push({ id: real, kind: o.kind.key, category: o.cat.key, label: o.cat.label, size: st.size, ...(withPaths ? { abs: path.join(xmlDir, real) } : {}) });
      }
    }
    return { id, eligible, datasets };
  });
}

async function resolveDataset(project, id, datasetId) {
  const { datasets } = await datasetsFor(project, id, { withPaths: true });
  if (!datasets.length) throw new HttpError(404, 'No viewable XML for this assessment yet.');
  const hit = datasetId ? datasets.find((d) => d.id === datasetId) : datasets[0];
  if (!hit) throw new HttpError(404, 'That dataset is not available for this assessment.');
  return hit;
}

module.exports = { ensureUtilities, getStatus, saveUpload, datasetsFor, resolveDataset, routesFor, matches };
