'use strict';
const fs = require('fs/promises');
const path = require('path');
const cfg = require('./config');
const { HttpError, DataError } = require('./errors');
const { isDir } = require('./fsx');

// Windows device names are illegal as folder names, with or without an extension.
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

async function ensureProjectsDir() {
  await fs.mkdir(cfg.PROJECTS_DIR, { recursive: true });
}

/**
 * Turn what the operator typed into a safe folder name, or explain why not.
 * This is path safety only (no traversal, no device names). It is NOT the
 * "anti project spoofing" check; see the TODO in listProjects().
 */
function validateProjectName(raw) {
  if (typeof raw !== 'string') return { error: 'Enter a project name.' }; // never coerce numbers or objects
  const name = raw.normalize('NFC').trim().replace(/\s+/g, '_');
  if (!name) return { error: 'Enter a project name.' };
  if (name.length > 64) return { error: 'Use 64 characters or fewer.' };
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) {
    return { error: 'Use letters, numbers, dots, dashes and underscores. Start with a letter or number.' };
  }
  if (name.endsWith('.')) return { error: 'The name cannot end with a dot.' };
  if (RESERVED.test(name)) return { error: `"${name}" is a reserved name on Windows. Pick another.` };
  return { name };
}

async function listProjects() {
  await ensureProjectsDir();

  // TODO(anti-project-spoofing): decide what makes a folder in /Projects a *valid* project
  // (for example: has the expected WSTG_Repository layout, matches a naming standard,
  // or carries a marker file) and drop or flag folders that fail. Deliberately NOT
  // implemented yet. Today every visible sub-folder counts as a project.
  const entries = await fs.readdir(cfg.PROJECTS_DIR, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    // Dirent.isDirectory() is false for symlinks, so links pointing elsewhere never show up.
    if (!e.isDirectory() || e.name.startsWith('.')) continue;
    const st = await fs.stat(path.join(cfg.PROJECTS_DIR, e.name));
    out.push({ name: e.name, createdAt: st.birthtime.toISOString(), modifiedAt: st.mtime.toISOString() });
  }
  out.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }));
  return out;
}

/**
 * Map a name from a URL onto an existing project folder.
 * The name must exactly match an entry from the directory listing, so nothing
 * the client sends is ever joined onto a path unchecked.
 */
async function resolveProject(name) {
  if (typeof name !== 'string' || !name || name.length > 255 || /[\\/\0]/.test(name) || name === '.' || name === '..') {
    throw new HttpError(400, 'Invalid project name.');
  }
  const hit = (await listProjects()).find((p) => p.name === name);
  if (!hit) throw new HttpError(404, 'Project not found.');
  return { name: hit.name, dir: path.join(cfg.PROJECTS_DIR, hit.name) };
}

async function createProject(rawName) {
  const v = validateProjectName(rawName);
  if (v.error) throw new HttpError(400, v.error);
  const name = v.name;

  // Only WSTG_Repository is copied. Anything else sitting in Base_Image is left alone.
  const source = path.join(cfg.BASE_IMAGE_DIR, cfg.REPO_DIRNAME);
  if (!(await isDir(source))) {
    throw new HttpError(500, `Base image not found. Expected a "${cfg.REPO_DIRNAME}" folder inside ${cfg.BASE_IMAGE_DIR}.`);
  }

  // Windows and macOS filesystems are case-insensitive, so "Acme" and "acme" would collide.
  const existing = await listProjects();
  if (existing.some((p) => p.name.toLowerCase() === name.toLowerCase())) {
    throw new HttpError(409, `A project named "${name}" already exists.`);
  }

  const dir = path.join(cfg.PROJECTS_DIR, name);
  const rel = path.relative(cfg.PROJECTS_DIR, dir);
  if (rel.startsWith('..') || path.isAbsolute(rel) || rel.includes(path.sep)) {
    throw new HttpError(400, 'Invalid project name.');
  }

  try {
    await fs.mkdir(dir); // non-recursive: fails if two requests race for the same name
  } catch (e) {
    if (e.code === 'EEXIST') throw new HttpError(409, `A project named "${name}" already exists.`);
    throw e;
  }

  try {
    await fs.cp(source, path.join(dir, cfg.REPO_DIRNAME), { recursive: true, errorOnExist: true, force: false });
    // Settings/Configurations (Mouse_Tool, Utilities, Wordlists). Files come from Base_Image/Settings if present.
    await require('./settings').ensureSettings(dir);
    // XML intake folders. If the routing file is missing or broken the project is still usable;
    // the folders are created the first time the sidebar is opened.
    try {
      await require('./xml').ensureUtilities(dir);
    } catch (e) {
      if (!(e instanceof DataError)) throw e;
    }
  } catch (e) {
    await fs.rm(dir, { recursive: true, force: true }); // only ever removes the folder created above
    throw new HttpError(500, `Could not copy the base image: ${e.message}`);
  }
  return { name };
}

module.exports = { validateProjectName, listProjects, resolveProject, createProject };
