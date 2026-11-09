'use strict';
/**
 * Runs one of the WSTG-ERRH-01 / WSTG-ERRH-02 wordlist scripts (tools/errh/README mirrors this -
 * see the project README's "Error Handling wordlists" section) for a project. Unlike Mouse_Tool
 * or the Reporting overlay, these are run-to-completion scripts with no desktop/mouse involved,
 * so this is closer to mouseProc.js's runOrchestrator - execFile and wait, not spawn-and-track.
 *
 * The scripts themselves are project-local, like every other per-item WSTG script (ATHN_07.py,
 * conf_05_wordlist.py, ...) - they live in that item's own Utilities/python/, copied in from
 * Base_Image like the rest of the project tree, not shipped centrally with this app. If an
 * operator hasn't dropped errh01_wordlist.py / errh02_wordlist.py into their project yet (see the
 * README), this just reports that clearly instead of trying to run something that isn't there.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const resources = require('./resources');
const { HttpError } = require('./errors');

const pythonBin = () => process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');

const SCRIPTS = {
  'WSTG-ERRH-01': 'errh01_wordlist.py',
  'WSTG-ERRH-02': 'errh02_wordlist.py',
};

async function runErrhWordlist(project, wstgId) {
  const scriptName = SCRIPTS[wstgId];
  if (!scriptName) throw new HttpError(400, `Not an Error Handling wordlist item: ${wstgId}`);

  const { testDir } = await resources.locateTest(project, wstgId);
  if (!testDir) throw new HttpError(404, `${wstgId}'s folder was not found in this project.`);

  const script = path.join(testDir, 'Utilities', 'python', scriptName);
  if (!fs.existsSync(script)) {
    throw new HttpError(404, `${scriptName} is not in ${wstgId}'s Utilities/python yet - see the README's "Error Handling wordlists" section.`);
  }

  return new Promise((resolve, reject) => {
    const args = [script, '--project-root', project.dir];
    execFile(pythonBin(), args, { timeout: 5 * 60 * 1000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(new HttpError(504, `${scriptName} timed out.`));
      if (err && err.code === 'ENOENT') return reject(new HttpError(500, `Could not run Python ("${pythonBin()}" not found). Set PYTHON_BIN if it uses a different name.`));
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

module.exports = { runErrhWordlist };
