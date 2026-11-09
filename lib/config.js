'use strict';
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const env = process.env;

module.exports = {
  ROOT,
  // Bound to loopback on purpose: this tool reads and writes engagement data.
  HOST: env.HOST || '127.0.0.1',
  PORT: env.PORT !== undefined ? Number(env.PORT) : 3000,

  // Where projects live and what new projects are cloned from.
  PROJECTS_DIR: path.resolve(env.PROJECTS_DIR || path.join(ROOT, 'Projects')),
  BASE_IMAGE_DIR: path.resolve(env.BASE_IMAGE_DIR || path.join(ROOT, 'Base_Image')),

  // Folder inside Base_Image that gets copied into every new project.
  // Result on disk: Projects/<Project_Name>/WSTG_Repository/...
  REPO_DIRNAME: 'WSTG_Repository',

  // The two reference files that drive the checklist (this server's own data/, not a project's).
  DATA_DIR: path.resolve(env.DATA_DIR || path.join(ROOT, 'data', 'json')),
  IO_FILE: 'wstg_io.json',
  REPORTING_FILE: 'wstg_reporting.json',
  PROCEDURES_FILE: 'wstg_tools_procedures.json',

  // Per-project Settings folder, and the template of the same name in Base_Image that seeds it.
  SETTINGS_DIRNAME: 'Settings',

  // Largest wordlist the "copy to clipboard" feature will serve.
  MAX_COPY_BYTES: Number(env.MAX_COPY_BYTES) || 5 * 1024 * 1024,

  // XML intake: where the routing rules live, where intake folders go inside a project,
  // and the largest single upload accepted (Burp exports with responses get big).
  ROUTING_FILE: 'xml_routing.json',
  UTIL_DIRNAME: 'project_utilities',
  MAX_XML_BYTES: Number(env.MAX_XML_BYTES) || 1024 * 1024 * 1024,

  // Intruder queue: a sibling of Projects/, NOT inside any one project, because the Burp-side
  // extension watches one shared root across every project at once. Pushed files always live
  // under a subfolder named for the project they came from - <INTRUDER_QUEUE_DIR>/<project> -
  // so two projects' requests can never land in the same folder (see lib/threatModel.js).
  INTRUDER_QUEUE_DIR: path.resolve(env.INTRUDER_QUEUE_DIR || path.join(ROOT, 'IntruderQueue')),
};
