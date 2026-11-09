'use strict';
/**
 * Runs the WSTG-INJT-23 (Insecure Deserialization) wrapper script - tools/deser/deser_wordlist.py,
 * which shells out to ysoserial (Java) or phpggc (PHP) per the project's own README section.
 * Same run-to-completion shape as lib/errh.js - execFile and wait, nothing long-lived to track.
 *
 * Like every other per-item WSTG script here, deser_wordlist.py is project-local (copied in from
 * Base_Image, not shipped centrally) - if it isn't in WSTG-INJT-23's Utilities/python yet, this
 * reports that clearly instead of trying to run something that isn't there.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const resources = require('./resources');
const { HttpError } = require('./errors');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

const WSTG_ID = 'WSTG-INJT-23';
const SCRIPT_NAME = 'deser_wordlist.py';
const LANGUAGES = new Set(['php', 'java']);
const SYS_TYPES = new Set(['linux', 'windows']);

async function runDeserWordlist(project, wstgId, body) {
  if (wstgId !== WSTG_ID) throw new HttpError(400, `Not the Insecure Deserialization item: ${wstgId}`);

  const language = String(body?.language || '').toLowerCase();
  const sysType = String(body?.sysType || '').toLowerCase();
  if (!LANGUAGES.has(language)) throw new HttpError(400, "language must be 'php' or 'java'.");
  if (!SYS_TYPES.has(sysType)) throw new HttpError(400, "sysType must be 'linux' or 'windows'.");

  const command = typeof body?.command === 'string' ? body.command.trim() : '';
  const gadget = typeof body?.gadget === 'string' ? body.gadget.trim() : '';

  const { testDir } = await resources.locateTest(project, WSTG_ID);
  if (!testDir) throw new HttpError(404, `${WSTG_ID}'s folder was not found in this project.`);

  const script = path.join(testDir, 'Utilities', 'python', SCRIPT_NAME);
  if (!fs.existsSync(script)) {
    throw new HttpError(404, `${SCRIPT_NAME} is not in ${WSTG_ID}'s Utilities/python yet - see the README's "Insecure Deserialization tool" section.`);
  }

  const args = [script, '--project-root', project.dir, '--language', language, '--sys-type', sysType];
  if (command) args.push('--command', command);
  if (gadget) args.push('--gadget', gadget);

  return new Promise((resolve, reject) => {
    execFile(pythonBin(), args, { timeout: 5 * 60 * 1000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(new HttpError(504, `${SCRIPT_NAME} timed out.`));
      if (err && err.code === 'ENOENT') return reject(new HttpError(500, `Could not run Python ("${pythonBin()}" not found). Set PYTHON_BIN if it uses a different name.`));
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

module.exports = { runDeserWordlist, WSTG_ID };
