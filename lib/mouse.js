'use strict';
/**
 * Mouse_Tool path lookup. Reads the project's static Settings/Configurations/Mouse_Tool/mouse_tool.json
 * (never written by this tool) and turns a WSTG ID into absolute input, output and XML folders inside
 * the project. Relative paths in the file are joined onto the project's WSTG_Repository folder.
 * Nothing is run and nothing is created here.
 */
const fs = require('fs/promises');
const path = require('path');
const cfg = require('./config');
const { HttpError, DataError } = require('./errors');
const { settingsRoot } = require('./settings');
const { listDir } = require('./fsx');

const FILE_REL = ['Configurations', 'Mouse_Tool', 'mouse_tool.json'];
const ID_RE = /^WSTG-[A-Z]{3,5}-\d{2}$/;
const KEYS = ['Input_Folder', 'Output_Folder', 'XML_Path', 'Master_Folder'];
const ACTIVE_REL = ['Configurations', 'Mouse_Tool', 'active_target.json'];

async function load(projectDir) {
  const file = path.join(settingsRoot(projectDir), ...FILE_REL);
  let text;
  try { text = await fs.readFile(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') throw new HttpError(404, 'mouse_tool.json is not in this project\'s Settings/Configurations/Mouse_Tool folder yet.');
    throw e;
  }
  let json;
  try { json = JSON.parse(text); } catch (e) { throw new DataError(`mouse_tool.json is not valid JSON: ${e.message}`); }
  if (!json || typeof json.Targets !== 'object' || json.Targets === null || Array.isArray(json.Targets)) {
    throw new DataError('mouse_tool.json needs a "Targets" object keyed by WSTG ID.');
  }
  return { file, targets: json.Targets };
}

/** Join a relative path from the file onto the repository, refusing anything that escapes it. */
function inside(repoDir, rel, label) {
  if (typeof rel !== 'string' || !rel.trim() || path.isAbsolute(rel) || /^[A-Za-z]:/.test(rel)) {
    throw new DataError(`${label} must be a relative path.`);
  }
  const abs = path.resolve(repoDir, ...rel.split(/[\\/]+/));
  const back = path.relative(repoDir, abs);
  if (!back || back.startsWith('..') || path.isAbsolute(back)) throw new DataError(`${label} points outside the project.`);
  return abs;
}

function resolveTarget(projectDir, id, t) {
  const repo = path.join(projectDir, cfg.REPO_DIRNAME);
  const out = { wstg_id: id, name: t.name || '', side: t.side || '', category_folder: t.Category_Folder || '' };
  for (const k of KEYS) out[k] = inside(repo, t[k], `${id}.${k}`);
  out.Master_File = path.join(out.Master_Folder, `${id}_association.json`);
  return out;
}

/** The one Burp XML in the item's XML folder. Zero or several is reported, never guessed. */
async function findXml(dir) {
  const names = ((await listDir(dir)) || []).filter((d) => !d.isDirectory() && /\.xml$/i.test(d.name)).map((d) => d.name).sort();
  if (names.length === 1) return { file: path.join(dir, names[0]), error: null };
  if (names.length === 0) return { file: null, error: 'No Burp XML found in the XML folder yet.' };
  return { file: null, error: `More than one XML in the XML folder (${names.join(', ')}). Leave exactly one.` };
}

async function listTargets(project) {
  const { targets } = await load(project.dir);
  return Object.entries(targets).map(([id, t]) => ({ wstg_id: id, name: t.name || '', side: t.side || '' }));
}

async function resolve(project, id) {
  if (!ID_RE.test(id)) throw new HttpError(400, 'Invalid WSTG ID.');
  const { targets } = await load(project.dir);
  if (!Object.prototype.hasOwnProperty.call(targets, id)) throw new HttpError(404, `${id} is not in mouse_tool.json.`);
  const r = resolveTarget(project.dir, id, targets[id] || {});
  r.Xml = await findXml(r.XML_Path);
  return r;
}

const activeFile = (dir) => path.join(settingsRoot(dir), ...ACTIVE_REL);

/** The item the Mouse_Tool is working on, or null if none was chosen yet. */
async function getActive(project) {
  let json;
  try { json = JSON.parse(await fs.readFile(activeFile(project.dir), 'utf8')); } catch { return { wstg_id: null }; }
  return { wstg_id: typeof json?.wstg_id === 'string' ? json.wstg_id : null };
}

/** Choose the item. The only file in Settings this tool writes: it is state, not config. Atomic. */
async function setActive(project, id) {
  if (typeof id !== 'string' || !ID_RE.test(id)) throw new HttpError(400, 'Invalid WSTG ID.');
  const { targets } = await load(project.dir);
  if (!Object.prototype.hasOwnProperty.call(targets, id)) throw new HttpError(404, `${id} is not in mouse_tool.json.`);
  const file = activeFile(project.dir);
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(tmp, JSON.stringify({ wstg_id: id }, null, 2) + '\n');
  await fs.rename(tmp, file);
  return { wstg_id: id };
}

module.exports = { listTargets, resolve, getActive, setActive };
