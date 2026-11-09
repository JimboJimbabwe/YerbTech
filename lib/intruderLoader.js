'use strict';
/**
 * Intruder Loader panel support: two things that are deliberately separate.
 *
 *   1. Launching Burp itself (java -jar <path>). This app can start that process and track it
 *      the same way Callback Suite tracks server.py - but it CANNOT make Burp load the watcher
 *      extension on its own. Burp has no API for that; loading an extension happens once, by
 *      hand, in Burp's own Settings > Extensions UI (see the extension script's own docstring).
 *      "Automatically reload extensions on startup" is what makes every later launch - including
 *      one this panel starts - come up with the extension already running.
 *   2. Reporting on the shared queue folder (IntruderQueue/<project>/): how many pushed files are
 *      still waiting and how many the extension has already moved into processed/. This is a
 *      plain directory read - nothing here talks to Burp directly.
 */
const fs = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const cfg = require('./config');
const { HttpError } = require('./errors');
const { settingsRoot } = require('./settings');

// project.dir -> { proc, pid, startedAt, log: string[] }. In-memory only, same as Callback Suite
// and Mouse Tool: a server restart forgets a launch happened.
const procs = new Map();

function configFile(project) {
  return path.join(settingsRoot(project.dir), 'Configurations', 'Intruder_Loader', 'burp_launch.json');
}

const DEFAULT_CONFIG = { javaBin: 'java', burpJarPath: '', projectFile: '', extraArgs: [] };

async function readConfig(project) {
  try {
    const raw = await fs.readFile(configFile(project), 'utf8');
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_CONFIG, ...parsed };
  } catch (e) {
    if (e.code === 'ENOENT') return { ...DEFAULT_CONFIG };
    throw new HttpError(500, 'burp_launch.json exists but is not valid JSON.');
  }
}

async function saveConfig(project, patch) {
  const current = await readConfig(project);
  const next = {
    javaBin: typeof patch.javaBin === 'string' && patch.javaBin.trim() ? patch.javaBin.trim() : current.javaBin,
    burpJarPath: typeof patch.burpJarPath === 'string' ? patch.burpJarPath.trim() : current.burpJarPath,
    projectFile: typeof patch.projectFile === 'string' ? patch.projectFile.trim() : current.projectFile,
    extraArgs: Array.isArray(patch.extraArgs) ? patch.extraArgs.map(String) : current.extraArgs,
  };
  const file = configFile(project);
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(next, null, 2) + '\n');
  await fs.rename(tmp, file);
  return next;
}

function pushLog(rec, chunk) {
  rec.log.push(chunk.toString());
  if (rec.log.length > 300) rec.log.splice(0, rec.log.length - 300);
}

async function launch(project) {
  if (procs.has(project.dir)) throw new HttpError(409, 'Burp is already tracked as running for this project.');
  const conf = await readConfig(project);
  if (!conf.burpJarPath) throw new HttpError(400, 'Set the Burp jar path first (Save in the Intruder Loader panel).');

  const args = ['-jar', conf.burpJarPath, ...conf.extraArgs];
  if (conf.projectFile) args.push('--project-file', conf.projectFile);

  let proc;
  try {
    proc = spawn(conf.javaBin, args);
  } catch (e) {
    throw new HttpError(500, `Could not launch Burp: ${e.message}`);
  }
  const rec = { proc, pid: proc.pid, startedAt: new Date().toISOString(), log: [] };
  procs.set(project.dir, rec);
  proc.stdout?.on('data', (d) => pushLog(rec, d));
  proc.stderr?.on('data', (d) => pushLog(rec, d));
  proc.on('error', (e) => { pushLog(rec, `[spawn error] ${e.message}\n`); procs.delete(project.dir); });
  proc.on('exit', (code, signal) => { pushLog(rec, `[exited] code=${code} signal=${signal}\n`); procs.delete(project.dir); });
  return { running: true, pid: rec.pid, startedAt: rec.startedAt };
}

function stop(project) {
  const rec = procs.get(project.dir);
  if (!rec) throw new HttpError(409, 'Burp is not tracked as running for this project.');
  rec.proc.kill();
  procs.delete(project.dir);
  return { running: false };
}

/** *.json directly under the project's queue folder (not yet picked up) vs. its processed/
 * subfolder (the extension already sent these). Purely a directory read - no Burp involved. */
async function queueCounts(project) {
  const dir = path.join(cfg.INTRUDER_QUEUE_DIR, project.name);
  const count = async (d, suffix) => {
    try {
      const names = await fs.readdir(d);
      return names.filter((n) => n.endsWith(suffix)).length;
    } catch {
      return 0;
    }
  };
  const pending = await count(dir, '.json');
  const sent = await count(path.join(dir, 'processed'), '.json');
  return { pending, sent };
}

async function status(project) {
  const rec = procs.get(project.dir);
  const queue = await queueCounts(project);
  if (!rec) return { running: false, queue };
  return { running: true, pid: rec.pid, startedAt: rec.startedAt, log: rec.log.slice(-60).join(''), queue };
}

module.exports = { readConfig, saveConfig, launch, stop, status, queueCounts };
