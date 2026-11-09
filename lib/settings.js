'use strict';
/**
 * Per-project Settings folder, created when a project is spawned:
 *
 *   <project>/Settings/Configurations/
 *       Mouse_Tool/{python, javascript}/   + mouse_tool.json
 *       Utilities/JSON/                    + injection_router.json, server_side_* JSON
 *       Utilities/python/                  + shuttle_gen/rebuild_tag/tag_combine/orchestrator.py
 *       Wordlists/                         (the wordlist JSONs)
 *       Questionnaires/                    + questionnaire_router.json, questionnaire_inventory.json
 *       Callback_Suite/                    + server.py, index.html, payloads/*.html
 *
 * The folders are always created from the list below. The FILES are never written by this tool:
 * they are copied from Base_Image/Settings if that folder exists (same idea as WSTG_Repository),
 * and only where the project doesn't already have them, so a project's own edits are never overwritten.
 * Today the folder lives in each project. It is resolved in one place (settingsRoot) so it can move
 * to a single global location later.
 */
const fs = require('fs/promises');
const path = require('path');
const cfg = require('./config');
const { listDir, isDir } = require('./fsx');

const SKELETON = [
  ['Configurations', 'Mouse_Tool', 'python'],
  ['Configurations', 'Mouse_Tool', 'javascript'],
  ['Configurations', 'Utilities', 'JSON'],
  ['Configurations', 'Utilities', 'python'],
  ['Configurations', 'Wordlists'],
  ['Configurations', 'Questionnaires'],
  ['Configurations', 'Callback_Suite', 'payloads', 'clnt-09-clickjacking'],
  ['Configurations', 'Intruder_Loader'],
];

// Files we know by name. Everything else in those folders is the operator's.
const EXPECTED_FILES = [
  { rel: ['Configurations', 'Mouse_Tool', 'mouse_tool.json'], label: 'mouse_tool.json' },
  { rel: ['Configurations', 'Mouse_Tool', 'python', 'clipboard_interceptor.py'], label: 'clipboard_interceptor.py' },
  { rel: ['Configurations', 'Mouse_Tool', 'javascript', 'listener.js'], label: 'listener.js' },
  { rel: ['Configurations', 'Utilities', 'JSON', 'injection_router.json'], label: 'injection_router.json' },
  { rel: ['Configurations', 'Utilities', 'python', 'shuttle_gen.py'], label: 'shuttle_gen.py' },
  { rel: ['Configurations', 'Utilities', 'python', 'rebuild_tag.py'], label: 'rebuild_tag.py' },
  { rel: ['Configurations', 'Utilities', 'python', 'tag_combine.py'], label: 'tag_combine.py' },
  { rel: ['Configurations', 'Utilities', 'python', 'orchestrator.py'], label: 'orchestrator.py' },
  { rel: ['Configurations', 'Utilities', 'JSON', 'server_side_inj.json'], label: 'server_side_inj.json' },
  { rel: ['Configurations', 'Utilities', 'JSON', 'waf_items.json'], label: 'waf_items.json' },
  { rel: ['Configurations', 'Utilities', 'JSON', 'server_side_waf_map.json'], label: 'server_side_waf_map.json' },
  { rel: ['Configurations', 'Utilities', 'python', 'server_side_orchestrator.py'], label: 'server_side_orchestrator.py' },
  { rel: ['Configurations', 'Questionnaires', 'questionnaire_router.json'], label: 'questionnaire_router.json' },
  { rel: ['Configurations', 'Questionnaires', 'questionnaire_inventory.json'], label: 'questionnaire_inventory.json' },
  { rel: ['Configurations', 'Callback_Suite', 'server.py'], label: 'Callback_Suite/server.py' },
  { rel: ['Configurations', 'Callback_Suite', 'index.html'], label: 'Callback_Suite/index.html' },
  { rel: ['Configurations', 'Callback_Suite', 'payloads', 'clnt-04-url-redirect.html'], label: 'clnt-04-url-redirect.html' },
  { rel: ['Configurations', 'Callback_Suite', 'payloads', 'clnt-06-resource-manip.html'], label: 'clnt-06-resource-manip.html' },
  { rel: ['Configurations', 'Callback_Suite', 'payloads', 'clnt-07-cors.html'], label: 'clnt-07-cors.html' },
  { rel: ['Configurations', 'Callback_Suite', 'payloads', 'clnt-13-cssi.html'], label: 'clnt-13-cssi.html' },
  { rel: ['Configurations', 'Callback_Suite', 'payloads', 'clnt-09-clickjacking', 'index.html'], label: 'clnt-09-clickjacking/index.html' },
  { rel: ['Configurations', 'Intruder_Loader', 'intruder_loader_extension.py'], label: 'intruder_loader_extension.py' },
  { rel: ['Configurations', 'Intruder_Loader', 'burp_launch.json'], label: 'burp_launch.json' },
];

const settingsRoot = (projectDir) => path.join(projectDir, cfg.SETTINGS_DIRNAME);
const templateDir = () => path.join(cfg.BASE_IMAGE_DIR, cfg.SETTINGS_DIRNAME);

/** Create the folder structure and copy any template files the project doesn't have yet. */
async function ensureSettings(projectDir) {
  const root = settingsRoot(projectDir);
  let templateFound = false;
  const tpl = templateDir();
  if (await isDir(tpl)) {
    templateFound = true;
    await fs.cp(tpl, root, { recursive: true, force: false, errorOnExist: false });
  }
  for (const segs of SKELETON) await fs.mkdir(path.join(root, ...segs), { recursive: true });
  return { root, templateFound };
}

async function countFiles(dir, re) {
  return ((await listDir(dir)) || []).filter((d) => !d.name.startsWith('.') && !d.isDirectory() && (!re || re.test(d.name))).length;
}

/** What is in the Settings folder, for the briefing page. */
async function settingsReport(projectDir) {
  const root = settingsRoot(projectDir);
  const missing = [];
  for (const f of EXPECTED_FILES) {
    const st = await fs.stat(path.join(root, ...f.rel)).catch(() => null);
    if (!st || !st.isFile()) missing.push(f);
  }
  const scripts = {
    python: await countFiles(path.join(root, 'Configurations', 'Mouse_Tool', 'python'), /\.py$/i),
    javascript: await countFiles(path.join(root, 'Configurations', 'Mouse_Tool', 'javascript'), /\.(c|m)?js$/i),
  };
  const wordlists = await countFiles(path.join(root, 'Configurations', 'Wordlists'), /\.json$/i);
  return { root, missing, scripts, wordlists };
}

module.exports = { SKELETON, EXPECTED_FILES, settingsRoot, ensureSettings, settingsReport };
