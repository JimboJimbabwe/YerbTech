'use strict';
/**
 * Runs the Mouse_Tool listener (start/stop, a long-lived process) and the test-data
 * orchestrator (run-to-completion) for a project. This is the first thing in the app that
 * launches a program: every call below is an explicit argument list handed straight to
 * child_process, never a shell string, so nothing here is vulnerable to shell quoting.
 *
 * The listener needs the operator's own desktop (global hotkeys, clipboard, a display), so
 * this only makes sense when the server and the browser are on the same machine - which is
 * this tool's whole deployment model (loopback-only, see server.js).
 */
const fs = require('fs');
const path = require('path');
const { spawn, execFile } = require('child_process');
const { HttpError } = require('./errors');
const { settingsRoot } = require('./settings');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

// project.dir -> { proc, pid, startedAt, log: string[] }. In-memory only: a server restart
// forgets any listener it had running, same as any other local dev tool's process state.
const listeners = new Map();

function scriptPaths(project) {
  const cfgDir = path.join(settingsRoot(project.dir), 'Configurations');
  return {
    interceptor: path.join(cfgDir, 'Mouse_Tool', 'python', 'clipboard_interceptor.py'),
    js: path.join(cfgDir, 'Mouse_Tool', 'javascript', 'listener.js'),
    mouseConfig: path.join(cfgDir, 'Mouse_Tool', 'mouse_tool.json'),
    orchestrator: path.join(cfgDir, 'Utilities', 'python', 'orchestrator.py'),
    serverSideOrchestrator: path.join(cfgDir, 'Utilities', 'python', 'server_side_orchestrator.py'),
  };
}

function pushLog(rec, chunk) {
  rec.log.push(chunk.toString());
  if (rec.log.length > 300) rec.log.splice(0, rec.log.length - 300);
}

function startListener(project) {
  if (listeners.has(project.dir)) throw new HttpError(409, 'The Mouse_Tool listener is already running for this project.');
  const { interceptor, js, mouseConfig } = scriptPaths(project);
  if (!fs.existsSync(interceptor)) {
    throw new HttpError(404, 'clipboard_interceptor.py is not in this project\'s Settings/Configurations/Mouse_Tool/python yet.');
  }
  if (!fs.existsSync(mouseConfig)) {
    throw new HttpError(404, 'mouse_tool.json is not in this project\'s Settings/Configurations/Mouse_Tool yet.');
  }
  const args = ['--config', mouseConfig, '--project-root', project.dir];
  if (fs.existsSync(js)) args.push('--js', js);

  let proc;
  try {
    proc = spawn(pythonBin(), [interceptor, ...args], { cwd: project.dir });
  } catch (e) {
    throw new HttpError(500, `Could not start the listener: ${e.message}`);
  }
  const rec = { proc, pid: proc.pid, startedAt: new Date().toISOString(), log: [] };
  listeners.set(project.dir, rec);
  proc.stdout?.on('data', (d) => pushLog(rec, d));
  proc.stderr?.on('data', (d) => pushLog(rec, d));
  proc.on('error', (e) => { pushLog(rec, `[spawn error] ${e.message}\n`); listeners.delete(project.dir); });
  proc.on('exit', (code, signal) => { pushLog(rec, `[exited] code=${code} signal=${signal}\n`); listeners.delete(project.dir); });
  return { running: true, pid: rec.pid, startedAt: rec.startedAt };
}

function stopListener(project) {
  const rec = listeners.get(project.dir);
  if (!rec) throw new HttpError(409, 'The Mouse_Tool listener is not running for this project.');
  rec.proc.kill();
  listeners.delete(project.dir);
  return { running: false };
}

function listenerStatus(project) {
  const rec = listeners.get(project.dir);
  if (!rec) return { running: false };
  return { running: true, pid: rec.pid, startedAt: rec.startedAt, log: rec.log.slice(-60).join('') };
}

function runOrchestrator(project, { split, capPercent, side } = {}) {
  return new Promise((resolve, reject) => {
    if (typeof split !== 'string' || !split.trim()) return reject(new HttpError(400, 'A split string is required.'));
    if (split.length > 500) return reject(new HttpError(400, 'The split string is too long.'));
    const cap = capPercent === undefined || capPercent === null || capPercent === '' ? 10 : Number(capPercent);
    if (!Number.isFinite(cap) || cap <= 0 || cap > 100) return reject(new HttpError(400, '"capPercent" must be a number between 0 and 100.'));
    const s = side === 'Server_Side' ? 'Server_Side' : 'Client_Side';
    const { orchestrator } = scriptPaths(project);
    if (!fs.existsSync(orchestrator)) {
      return reject(new HttpError(404, 'orchestrator.py is not in this project\'s Settings/Configurations/Utilities/python yet.'));
    }
    const args = [orchestrator, '--project-root', project.dir, '--split', split, '--cap-percent', String(cap), '--side', s];
    execFile(pythonBin(), args, { timeout: 10 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(new HttpError(504, 'The orchestrator run timed out.'));
      if (err && err.code === 'ENOENT') return reject(new HttpError(500, `Could not run Python ("${pythonBin()}" not found). Set PYTHON_BIN if it uses a different name.`));
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

function runServerSideOrchestrator(project) {
  return new Promise((resolve, reject) => {
    const { serverSideOrchestrator } = scriptPaths(project);
    if (!fs.existsSync(serverSideOrchestrator)) {
      return reject(new HttpError(404, 'server_side_orchestrator.py is not in this project\'s Settings/Configurations/Utilities/python yet.'));
    }
    const args = [serverSideOrchestrator, '--project-root', project.dir];
    execFile(pythonBin(), args, { timeout: 10 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(new HttpError(504, 'The server-side orchestrator run timed out.'));
      if (err && err.code === 'ENOENT') return reject(new HttpError(500, `Could not run Python ("${pythonBin()}" not found). Set PYTHON_BIN if it uses a different name.`));
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

module.exports = { scriptPaths, startListener, stopListener, listenerStatus, runOrchestrator, runServerSideOrchestrator };
