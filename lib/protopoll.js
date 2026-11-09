'use strict';
/**
 * WSTG-INJT-22 (Prototype Pollution): protopoll_wordlists.py (run-to-completion, same shape as
 * lib/errh.js and lib/deser.js) and hash_fragment_opener.py (the "second script" - a long-lived,
 * cancelable process like the Reporting overlay, tracked here the same corrected way
 * reportingProc.js tracks its own - kept with an `exited` flag instead of deleted on exit, so a
 * crash reason (e.g. firefox missing) survives to the next status poll).
 *
 * Both scripts are project-local, like every other per-item WSTG script here (copied in from
 * Base_Image, not shipped centrally) - if one isn't in WSTG-INJT-22's Utilities/python yet, this
 * reports that clearly instead of trying to run something that isn't there.
 */
const fs = require('fs');
const path = require('path');
const { execFile, spawn } = require('child_process');
const resources = require('./resources');
const { HttpError } = require('./errors');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

const WSTG_ID = 'WSTG-INJT-22';
const WORDLISTS_SCRIPT = 'protopoll_wordlists.py';
const OPENER_SCRIPT = 'hash_fragment_opener.py';

async function scriptPath(project, name) {
  const { testDir } = await resources.locateTest(project, WSTG_ID);
  if (!testDir) throw new HttpError(404, `${WSTG_ID}'s folder was not found in this project.`);
  const script = path.join(testDir, 'Utilities', 'python', name);
  if (!fs.existsSync(script)) {
    throw new HttpError(404, `${name} is not in ${WSTG_ID}'s Utilities/python yet - see the README's "Prototype Pollution" section.`);
  }
  return script;
}

/* -------------------------- wordlists + urls.txt (run-to-completion) ------------------------- */

async function runWordlists(project, wstgId, body) {
  if (wstgId !== WSTG_ID) throw new HttpError(400, `Not the Prototype Pollution item: ${wstgId}`);
  const script = await scriptPath(project, WORDLISTS_SCRIPT);

  const args = [script, '--project-root', project.dir];
  const maxUrls = body?.maxUrls;
  if (maxUrls !== undefined && maxUrls !== null && maxUrls !== '') {
    const n = Number(maxUrls);
    if (!Number.isInteger(n) || n < 1 || n > 50) throw new HttpError(400, '"maxUrls" must be an integer between 1 and 50.');
    args.push('--max-urls', String(n));
  }

  return new Promise((resolve, reject) => {
    execFile(pythonBin(), args, { timeout: 5 * 60 * 1000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(new HttpError(504, `${WORDLISTS_SCRIPT} timed out.`));
      if (err && err.code === 'ENOENT') return reject(new HttpError(500, `Could not run Python ("${pythonBin()}" not found). Set PYTHON_BIN if it uses a different name.`));
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

/* -------------------------- hash fragment opener (spawn + track + stop) ---------------------- */

// project.dir -> { proc, pid, startedAt, log: string[], exited }. In-memory only - a server
// restart forgets it was running, same as every other local process tracked this way.
const openers = new Map();

function pushLog(rec, chunk) {
  rec.log.push(chunk.toString());
  if (rec.log.length > 300) rec.log.splice(0, rec.log.length - 300);
}

async function startOpener(project, opts = {}) {
  const existing = openers.get(project.dir);
  if (existing && !existing.exited) throw new HttpError(409, 'The hash fragment opener is already running for this project.');

  const script = await scriptPath(project, OPENER_SCRIPT);
  const args = [script, '--project-root', project.dir];

  if (opts.delay !== undefined && opts.delay !== null && opts.delay !== '') {
    const d = Number(opts.delay);
    if (!Number.isFinite(d) || d < 0 || d > 300) throw new HttpError(400, '"delay" must be a number of seconds between 0 and 300.');
    args.push('--delay', String(d));
  }
  if (opts.payloadsPerUrl !== undefined && opts.payloadsPerUrl !== null && opts.payloadsPerUrl !== '') {
    const p = Number(opts.payloadsPerUrl);
    if (!Number.isInteger(p) || p < 1 || p > 20) throw new HttpError(400, '"payloadsPerUrl" must be an integer between 1 and 20.');
    args.push('--payloads-per-url', String(p));
  }
  if (opts.newWindow) args.push('--new-window');

  let proc;
  try {
    proc = spawn(pythonBin(), args, { cwd: project.dir });
  } catch (e) {
    throw new HttpError(500, `Could not start the hash fragment opener: ${e.message}`);
  }
  const rec = { proc, pid: proc.pid, startedAt: new Date().toISOString(), log: [], exited: false };
  openers.set(project.dir, rec);
  proc.stdout?.on('data', (d) => pushLog(rec, d));
  proc.stderr?.on('data', (d) => pushLog(rec, d));
  proc.on('error', (e) => { rec.exited = true; pushLog(rec, `[spawn error] ${e.message}\n`); });
  proc.on('exit', (code, signal) => { rec.exited = true; pushLog(rec, `[exited] code=${code} signal=${signal}\n`); });
  return { running: true, pid: rec.pid, startedAt: rec.startedAt };
}

function stopOpener(project) {
  const rec = openers.get(project.dir);
  if (!rec || rec.exited) throw new HttpError(409, 'The hash fragment opener is not running for this project.');
  rec.proc.kill();
  return { running: false };
}

function openerStatus(project) {
  const rec = openers.get(project.dir);
  if (!rec) return { running: false };
  return { running: !rec.exited, pid: rec.pid, startedAt: rec.startedAt, log: rec.log.slice(-80).join('') };
}

module.exports = { WSTG_ID, runWordlists, startOpener, stopOpener, openerStatus };
