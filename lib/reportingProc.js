'use strict';
/**
 * Runs the Reporting tool's overlay listener (start/stop, a long-lived process), the same way
 * lib/mouseProc.js runs the Mouse_Tool listener. The overlay needs the operator's own desktop
 * (global hotkeys, the mouse, a display, a screenshot tool), so this only makes sense when the
 * server and the browser are on the same machine - same deployment model as Mouse_Tool.
 *
 * The overlay is handed --project-root (so it can find each WSTG item's own folder the same
 * scan-for-WSTG-ID way the rest of this project does) and --reporting-file (this server's own
 * data/json/wstg_reporting.json, the same file lib/data.js's getReporting() reads) - never a
 * hardcoded category list, so a project's checklist and the overlay's circles can never drift
 * apart.
 */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const cfg = require('./config');
const { HttpError } = require('./errors');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

// project.dir -> { proc, pid, startedAt, log: string[] }. In-memory only: a server restart
// forgets any listener it had running, same as any other local dev tool's process state.
const listeners = new Map();

function overlayScript() {
  return path.join(cfg.ROOT, 'tools', 'reporting', 'reporting_overlay.py');
}

function reportingFile() {
  return path.join(cfg.DATA_DIR, cfg.REPORTING_FILE);
}

function pushLog(rec, chunk) {
  rec.log.push(chunk.toString());
  if (rec.log.length > 300) rec.log.splice(0, rec.log.length - 300);
}

function startOverlay(project) {
  const existing = listeners.get(project.dir);
  if (existing && !existing.exited) throw new HttpError(409, 'The Reporting tool overlay is already running for this project.');
  const script = overlayScript();
  if (!fs.existsSync(script)) {
    throw new HttpError(404, 'tools/reporting/reporting_overlay.py is missing from this install.');
  }
  const repFile = reportingFile();
  if (!fs.existsSync(repFile)) {
    throw new HttpError(404, `Missing ${cfg.REPORTING_FILE}. Put your copy at ${repFile}`);
  }
  const args = [script, '--project-root', project.dir, '--reporting-file', repFile];

  let proc;
  try {
    proc = spawn(pythonBin(), args, { cwd: project.dir });
  } catch (e) {
    throw new HttpError(500, `Could not start the Reporting overlay: ${e.message}`);
  }
  // exited:false until proc.on('exit'/'error') fires. The record is kept (not deleted) after
  // that so the next status poll can still show *why* it died - crashes are the normal way an
  // operator finds out about a missing dependency (pynput, tkinter, scrot, no DISPLAY), and
  // deleting the record on exit, as this used to do, threw that reason away before anyone could
  // read it.
  const rec = { proc, pid: proc.pid, startedAt: new Date().toISOString(), log: [], exited: false };
  listeners.set(project.dir, rec);
  proc.stdout?.on('data', (d) => pushLog(rec, d));
  proc.stderr?.on('data', (d) => pushLog(rec, d));
  proc.on('error', (e) => { rec.exited = true; pushLog(rec, `[spawn error] ${e.message}\n`); });
  proc.on('exit', (code, signal) => { rec.exited = true; pushLog(rec, `[exited] code=${code} signal=${signal}\n`); });
  return { running: true, pid: rec.pid, startedAt: rec.startedAt };
}

function stopOverlay(project) {
  const rec = listeners.get(project.dir);
  if (!rec || rec.exited) throw new HttpError(409, 'The Reporting tool overlay is not running for this project.');
  rec.proc.kill();
  return { running: false };
}

function overlayStatus(project) {
  const rec = listeners.get(project.dir);
  if (!rec) return { running: false };
  return { running: !rec.exited, pid: rec.pid, startedAt: rec.startedAt, log: rec.log.slice(-60).join('') };
}

module.exports = { startOverlay, stopOverlay, overlayStatus };
