'use strict';
/**
 * Runs the WSTG-INJT-17 (Host Header Injection) wrapper script -
 * tools/hostheader/hostheader_wordlist.py, which builds a Host-header wordlist by reusing
 * whatever WSTG-INFO-04 (DNS / Port / VHost Enumeration) has already produced for this project
 * (subdomains, DNS results, nmap XML) rather than asking the operator to re-type any of it.
 * Same run-to-completion shape as lib/errh.js / lib/deser.js / protopoll.js's runWordlists -
 * execFile and wait, nothing long-lived to track.
 *
 * Like every other per-item WSTG script here, hostheader_wordlist.py is project-local (copied in
 * from Base_Image, not shipped centrally) - if it isn't in WSTG-INJT-17's Utilities/python yet,
 * this reports that clearly instead of trying to run something that isn't there.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const resources = require('./resources');
const { HttpError } = require('./errors');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

const WSTG_ID = 'WSTG-INJT-17';
const SCRIPT_NAME = 'hostheader_wordlist.py';

async function runHostHeaderWordlist(project, wstgId, body) {
  if (wstgId !== WSTG_ID) throw new HttpError(400, `Not the Host Header Injection item: ${wstgId}`);

  const targetUrl = typeof body?.targetUrl === 'string' ? body.targetUrl.trim() : '';
  if (!targetUrl) throw new HttpError(400, '"targetUrl" is required.');

  const { testDir } = await resources.locateTest(project, WSTG_ID);
  if (!testDir) throw new HttpError(404, `${WSTG_ID}'s folder was not found in this project.`);

  const script = path.join(testDir, 'Utilities', 'python', SCRIPT_NAME);
  if (!fs.existsSync(script)) {
    throw new HttpError(404, `${SCRIPT_NAME} is not in ${WSTG_ID}'s Utilities/python yet - see the README's "Host Header Injection" section.`);
  }

  const args = [script, '--project-root', project.dir, '--target-url', targetUrl];

  const cidr = body?.cidr;
  if (cidr !== undefined && cidr !== null && cidr !== '') {
    const n = Number(cidr);
    if (!Number.isInteger(n) || n < 0 || n > 32) throw new HttpError(400, '"cidr" must be an integer between 0 and 32.');
    args.push('--cidr', String(n));
  }
  if (body?.noResolve) args.push('--no-resolve');
  if (body?.noReuseRecon) args.push('--no-reuse-recon');
  if (body?.noCloud) args.push('--no-cloud');
  if (body?.noRegionGuess) args.push('--no-region-guess');
  if (body?.noEncode) args.push('--no-encode');

  const scopeFile = typeof body?.scopeFile === 'string' ? body.scopeFile.trim() : '';
  if (scopeFile) args.push('--scope-file', scopeFile);

  return new Promise((resolve, reject) => {
    execFile(pythonBin(), args, { timeout: 5 * 60 * 1000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(new HttpError(504, `${SCRIPT_NAME} timed out.`));
      if (err && err.code === 'ENOENT') return reject(new HttpError(500, `Could not run Python ("${pythonBin()}" not found). Set PYTHON_BIN if it uses a different name.`));
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

module.exports = { WSTG_ID, runHostHeaderWordlist };
