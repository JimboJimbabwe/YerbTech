'use strict';
/**
 * WSTG-CLNT Callback Suite: runs the operator's own server.py (a stdlib-only Python HTTP server
 * that hosts the client-side callback/payload pages and logs every hit) and, separately, exports
 * its log into the matching WSTG-CLNT-NN item's Outputs/test_outputs.
 *
 * Unlike the rest of this tool, this server is MEANT to be reachable from outside the operator's
 * own machine - it's the thing the target application calls back to during an engagement - so,
 * unlike the main app, it is not forced onto loopback. It defaults to whatever server.py itself
 * defaults to (0.0.0.0) unless a host is given.
 *
 * Export is a read of server.log, not of a live connection: it works whether the server is
 * running or stopped, and is only triggered when the operator asks for it (no file is written
 * to a WSTG item's folder on its own).
 */
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const { HttpError } = require('./errors');
const { settingsRoot } = require('./settings');
const resources = require('./resources');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
const DEFAULT_PORT = 8000;

// project.dir -> { proc, pid, startedAt, port, log: string[] }. In-memory only, same as the
// Mouse_Tool listener: a server restart forgets it was running.
const servers = new Map();

function scriptPaths(project) {
  const dir = path.join(settingsRoot(project.dir), 'Configurations', 'Callback_Suite');
  return { dir, server: path.join(dir, 'server.py'), index: path.join(dir, 'index.html'), log: path.join(dir, 'server.log') };
}

function pushLog(rec, chunk) {
  rec.log.push(chunk.toString());
  if (rec.log.length > 300) rec.log.splice(0, rec.log.length - 300);
}

function startServer(project, { port, host } = {}) {
  if (servers.has(project.dir)) throw new HttpError(409, 'The Callback Suite server is already running for this project.');
  const { dir, server } = scriptPaths(project);
  if (!fs.existsSync(server)) {
    throw new HttpError(404, 'server.py is not in this project\'s Settings/Configurations/Callback_Suite yet.');
  }
  const p = port === undefined || port === null || port === '' ? DEFAULT_PORT : Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new HttpError(400, '"port" must be an integer between 1 and 65535.');
  const args = [server, '--port', String(p)];
  if (host) args.push('--host', String(host));

  let proc;
  try {
    proc = spawn(pythonBin(), args, { cwd: dir });
  } catch (e) {
    throw new HttpError(500, `Could not start the Callback Suite server: ${e.message}`);
  }
  const rec = { proc, pid: proc.pid, startedAt: new Date().toISOString(), port: p, log: [] };
  servers.set(project.dir, rec);
  proc.stdout?.on('data', (d) => pushLog(rec, d));
  proc.stderr?.on('data', (d) => pushLog(rec, d));
  proc.on('error', (e) => { pushLog(rec, `[spawn error] ${e.message}\n`); servers.delete(project.dir); });
  proc.on('exit', (code, signal) => { pushLog(rec, `[exited] code=${code} signal=${signal}\n`); servers.delete(project.dir); });
  return { running: true, pid: rec.pid, startedAt: rec.startedAt, port: rec.port };
}

function stopServer(project) {
  const rec = servers.get(project.dir);
  if (!rec) throw new HttpError(409, 'The Callback Suite server is not running for this project.');
  rec.proc.kill();
  servers.delete(project.dir);
  return { running: false };
}

function serverStatus(project) {
  const rec = servers.get(project.dir);
  if (!rec) return { running: false };
  return { running: true, pid: rec.pid, startedAt: rec.startedAt, port: rec.port, log: rec.log.slice(-60).join('') };
}

/* --------------------------- log -> WSTG ID mapping ---------------------------
 * Mirrors the dashboard's own pathMap in index.html: the URL path already names the WSTG
 * item (clnt-04, clnt-06, clnt-07, clnt-09, clnt-13), so there is no need for a second,
 * separately-maintained table - this one just has to agree with that one.
 */
const PATH_MAP = [
  { prefix: '/payloads/clnt-04-url-redirect.html', wstg_id: 'WSTG-CLNT-04', exact: true },
  { prefix: '/payloads/clnt-06-resource-manip.html', wstg_id: 'WSTG-CLNT-06', exact: true },
  { prefix: '/payloads/clnt-07-cors.html', wstg_id: 'WSTG-CLNT-07', exact: true },
  { prefix: '/payloads/clnt-09-clickjacking/', wstg_id: 'WSTG-CLNT-09', exact: false }, // any PoC file under it too
  { prefix: '/payloads/clnt-13-cssi.html', wstg_id: 'WSTG-CLNT-13', exact: false }, // CLNT-13 itself, no sub-paths expected
];

function matchWstgId(reqPath) {
  for (const m of PATH_MAP) {
    if (m.exact ? reqPath === m.prefix : reqPath.startsWith(m.prefix)) return m.wstg_id;
  }
  return null;
}

const LOG_LINE_RE = /^\[(\d{2}:\d{2}:\d{2})\]\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)(?:\s+»\s+(.*))?$/;

/** Parse server.log into hits grouped by the WSTG ID their path matches. Lines that don't
 * match anything in PATH_MAP (the SSE stream, /api/* calls, the dashboard itself) are ignored -
 * those aren't "something contacted the operator's callback for item X" events. */
function parseLog(text) {
  const byId = new Map();
  let matched = 0;
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    total++;
    const m = LOG_LINE_RE.exec(line);
    if (!m) continue;
    const [, ts, ip, method, status, reqPath, note] = m;
    const wstgId = matchWstgId(reqPath);
    if (!wstgId) continue;
    matched++;
    if (!byId.has(wstgId)) byId.set(wstgId, []);
    byId.get(wstgId).push({ ts, ip, method, status, path: reqPath, note: note || '' });
  }
  return { byId, total, matched };
}

function renderMarkdown(wstgId, hits) {
  const lines = [];
  lines.push(`# ${wstgId} — Callback Suite hits`);
  lines.push(`Total hits: ${hits.length}`);
  lines.push(`Exported: ${new Date().toISOString()}`);
  lines.push('');
  for (const h of hits) {
    lines.push(`- \`[${h.ts}]\` **${h.ip}** ${h.method} ${h.status} \`${h.path}\`${h.note ? ` — ${h.note}` : ''}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Read server.log, group hits by the WSTG item their path names, and write a JSON + Markdown
 * snapshot into each matched item's Outputs/test_outputs. An item whose folder can't be found
 * in this project yet is reported as skipped, not silently dropped.
 */
async function exportHits(project) {
  const { log } = scriptPaths(project);
  let text;
  try {
    text = await fsp.readFile(log, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return { written: [], skipped: [], total_lines: 0, matched_lines: 0 };
    throw e;
  }
  const { byId, total, matched } = parseLog(text);

  const written = [];
  const skipped = [];
  for (const [wstgId, hits] of byId) {
    let testDir;
    try {
      ({ testDir } = await resources.locateTest(project, wstgId));
    } catch {
      testDir = null;
    }
    if (!testDir) {
      skipped.push({ wstg_id: wstgId, hits: hits.length, reason: `Could not find a ${wstgId} folder in this project's WSTG_Repository.` });
      continue;
    }
    const outDir = path.join(testDir, 'Outputs', 'test_outputs');
    await fsp.mkdir(outDir, { recursive: true });
    const exportedAt = new Date().toISOString();
    const jsonFile = path.join(outDir, 'callback_hits.json');
    const mdFile = path.join(outDir, 'callback_hits.md');
    const tmpJson = `${jsonFile}.${process.pid}.tmp`;
    const tmpMd = `${mdFile}.${process.pid}.tmp`;
    await fsp.writeFile(tmpJson, JSON.stringify({ wstg_id: wstgId, total_hits: hits.length, exported_at: exportedAt, hits }, null, 2) + '\n');
    await fsp.rename(tmpJson, jsonFile);
    await fsp.writeFile(tmpMd, renderMarkdown(wstgId, hits));
    await fsp.rename(tmpMd, mdFile);
    written.push({ wstg_id: wstgId, hits: hits.length, json: jsonFile, md: mdFile });
  }
  return { written, skipped, total_lines: total, matched_lines: matched };
}

module.exports = { scriptPaths, startServer, stopServer, serverStatus, exportHits, matchWstgId, parseLog };
