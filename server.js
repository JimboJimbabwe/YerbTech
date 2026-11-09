'use strict';
const path = require('path');
const express = require('express');
const cfg = require('./lib/config');
const { HttpError } = require('./lib/errors');
const projects = require('./lib/projects');
const data = require('./lib/data');
const resources = require('./lib/resources');
const xml = require('./lib/xml');
const burp = require('./lib/burp');
const procedures = require('./lib/procedures');
const settings = require('./lib/settings');
const mouse = require('./lib/mouse');
const mouseProc = require('./lib/mouseProc');
const reporting = require('./lib/reporting');
const reportingProc = require('./lib/reportingProc');
const errh = require('./lib/errh');
const deser = require('./lib/deser');
const protopoll = require('./lib/protopoll');
const hostheader = require('./lib/hostheader');
const questionnaire = require('./lib/questionnaire');
const callbackProc = require('./lib/callbackProc');
const threatModel = require('./lib/threatModel');
const intruderLoader = require('./lib/intruderLoader');
const findings = require('./lib/findings');

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const extraHosts = (process.env.ALLOWED_HOSTS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const hostAllowed = (h) => LOCAL_HOSTS.has(h) || extraHosts.includes(h);

function hostnameOf(hostHeader) {
  const m = /^(\[[^\]]+\]|[^:]+)(?::\d+)?$/.exec(String(hostHeader || ''));
  return m ? m[1].toLowerCase() : '';
}

// Query values can be arrays or objects (?a=1&a=2); only accept a single string.
const qs = (v) => (typeof v === 'string' ? v : undefined);
function intParam(v, dflt, min, max) {
  const n = typeof v === 'string' && /^\d{1,9}$/.test(v) ? Number(v) : dflt;
  return Math.min(Math.max(n, min), max);
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function testId(req) {
  const id = String(req.params.id || '').toUpperCase();
  if (!data.ID_RE.test(id)) throw new HttpError(400, 'Invalid test ID.');
  return id;
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');

  // This is a local tool that reads and writes engagement data. Refuse requests that could only
  // come from another website: DNS rebinding (wrong Host), cross-site POSTs (wrong Origin) and
  // form-style POSTs (not JSON, which also forces a CORS preflight that we never approve).
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    });
    if (!hostAllowed(hostnameOf(req.headers.host))) {
      return next(new HttpError(403, 'Host not allowed.'));
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const origin = req.headers.origin;
      if (origin) {
        let ok = false;
        try {
          ok = hostAllowed(new URL(origin).hostname.replace(/^([^[].*:.*)$/, '[$1]').toLowerCase());
        } catch {}
        if (!ok) return next(new HttpError(403, 'Origin not allowed.'));
      }
      // JSON everywhere, plus raw XML on the upload route only. Neither can be sent by a plain
      // HTML form, and both force a CORS preflight that this server never approves.
      const isUpload = req.method === 'PUT' && /^\/api\/projects\/[^/]+\/xml\/[^/]+\/[^/]+$/.test(req.path);
      if (!(req.is('application/json') || (isUpload && req.is(['application/xml', 'text/xml'])))) {
        return next(new HttpError(415, isUpload ? 'Send the file as application/xml.' : 'Send JSON.'));
      }
    }
    next();
  });
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  // 4kb covered every POST body until the questionnaire feature: a page of free-text answers
  // (notes, endpoint lists) can run well past that, so this is sized for that, not for XML/wordlist
  // bodies - those still go through their own byte caps (MAX_COPY_BYTES / MAX_XML_BYTES) below.
  app.use(express.json({ limit: '256kb' }));
  app.use(express.static(path.join(cfg.ROOT, 'public'), { index: false, extensions: ['html'] }));

  /* ------------------------------ pages ----------------------------- */
  const page = (file) => (req, res) => res.sendFile(path.join(cfg.ROOT, 'public', file));
  app.get('/', page('index.html'));
  app.get('/project/:name', page('project.html'));
  app.get('/project/:name/workspace', page('workspace.html'));
  app.get('/project/:name/questionnaires', page('questionnaires.html'));

  /* ---------------------------- projects API ------------------------ */
  app.get('/api/projects', wrap(async (req, res) => {
    const list = await projects.listProjects();
    res.json({ count: list.length, projects: list });
  }));

  app.post('/api/projects', wrap(async (req, res) => {
    const created = await projects.createProject(req.body?.name);
    res.status(201).json(created);
  }));

  app.get('/api/projects/:name/preflight', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await buildPreflight(project));
  }));

  /* ------------------------- WSTG reference API --------------------- */
  app.get('/api/wstg/checklist', wrap(async (req, res) => {
    const { categories } = await data.getReporting();
    res.json({ categories });
  }));

  // Feature 3: look the clicked ID up in wstg_reporting.json.
  app.get('/api/wstg/tests/:id', wrap(async (req, res) => {
    const id = testId(req);
    const { byId } = await data.getReporting();
    const hit = byId.get(id);
    if (!hit) throw new HttpError(404, `${id} is not in ${cfg.REPORTING_FILE}.`);
    const reporting = (Array.isArray(hit.test.reporting) ? hit.test.reporting : []).map((r) => ({
      what: String(r?.What ?? ''),
      why: String(r?.Why ?? ''),
    }));
    res.json({
      id,
      name: String(hit.test.name ?? id),
      category: hit.category,
      categoryId: hit.categoryId,
      reference: typeof hit.test.reference === 'string' ? hit.test.reference : null,
      reporting,
    });
  }));

  /* ---------------------- per-project test status ------------------- */
  // Feature 1: do the files this assessment needs exist in this project?
  app.get('/api/projects/:name/tests/:id/resources', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    const id = testId(req);
    res.json(await resources.checkTest(project, id, await data.getIo()));
  }));

  // Feature 4: wordlists for an assessment, and their contents for the clipboard.
  app.get('/api/projects/:name/tests/:id/wordlists', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    const id = testId(req);
    res.json(await resources.listWordlists(project, id, await data.getIo()));
  }));

  app.get('/api/projects/:name/tests/:id/wordlists/:file', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    const id = testId(req);
    const text = await resources.readWordlist(project, id, req.params.file);
    res.type('text/plain; charset=utf-8').send(text);
  }));

  /* --------------------------- XML intake / viewer ------------------- */
  app.get('/api/projects/:name/xml', wrap(async (req, res) => {
    res.json(await xml.getStatus(await projects.resolveProject(req.params.name)));
  }));

  // Body is the raw file (Content-Type: application/xml), streamed to disk.
  app.put('/api/projects/:name/xml/:kind/:category', wrap(async (req, res) => {
    if (!req.is(['application/xml', 'text/xml'])) throw new HttpError(415, 'Send the file as application/xml.'); // a parsed JSON body leaves nothing to stream
    const project = await projects.resolveProject(req.params.name);
    res.json(await xml.saveUpload(project, req.params.kind, req.params.category, req));
  }));

  // Which XML does this assessment take, and which datasets can the viewer open?
  app.get('/api/projects/:name/tests/:id/xml', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await xml.datasetsFor(project, testId(req)));
  }));

  app.get('/api/projects/:name/tests/:id/requests', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    const ds = await xml.resolveDataset(project, testId(req), qs(req.query.dataset));
    res.json({
      dataset: ds.id,
      ...(await burp.list(ds.abs, { offset: intParam(req.query.offset, 0, 0, 1e9), limit: intParam(req.query.limit, 200, 1, 500), q: qs(req.query.q) || '' })),
    });
  }));

  app.get('/api/projects/:name/tests/:id/requests/:index', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    const ds = await xml.resolveDataset(project, testId(req), qs(req.query.dataset));
    if (!/^\d{1,9}$/.test(req.params.index)) throw new HttpError(400, 'Invalid request index.');
    res.json(await burp.getRequest(ds.abs, Number(req.params.index)));
  }));

  // Threat-Model: a 5th "dataset" the viewer can switch to, fed by Threat_Model.json
  // (written outside this app by tools/param_mapper/threat_rank.py) instead of a raw
  // XML file under Inputs/XML. The item index is into Threat_Model.json's own list;
  // the server resolves which XML file + request index that means from the file it
  // just read, never from anything the client supplies.
  app.get('/api/projects/:name/tests/:id/threat-model', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await threatModel.listItems(project, testId(req)));
  }));

  app.get('/api/projects/:name/tests/:id/threat-model/:itemIndex/request', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    if (!/^\d{1,9}$/.test(req.params.itemIndex)) throw new HttpError(400, 'Invalid item index.');
    res.json(await threatModel.getItemRequest(project, testId(req), Number(req.params.itemIndex)));
  }));

  // "Push to Testing": selected Threat-Model rows -> one JSON file in the shared Intruder
  // queue (a sibling of Projects/, never inside it - see lib/threatModel.js / cfg.INTRUDER_QUEUE_DIR).
  app.post('/api/projects/:name/tests/:id/threat-model/push', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    const indexes = Array.isArray(req.body?.item_indexes) ? req.body.item_indexes : null;
    if (!indexes || !indexes.length || !indexes.every((n) => Number.isInteger(n) && n >= 0)) {
      throw new HttpError(400, '"item_indexes" must be a non-empty array of non-negative integers.');
    }
    res.json(await threatModel.pushToQueue(project, testId(req), indexes));
  }));

  // Error Handling wordlists: only meaningful for WSTG-ERRH-01 / WSTG-ERRH-02 (lib/errh.js
  // rejects any other id with a 400). Run-to-completion, like the server-side wordlist pipeline -
  // no process to track, just the result of one run.
  app.post('/api/projects/:name/tests/:id/errh-wordlist', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await errh.runErrhWordlist(project, testId(req)));
  }));

  // Insecure Deserialization (WSTG-INJT-23): wraps ysoserial/phpggc per lib/deser.js. Also
  // run-to-completion - language/sysType/command/gadget come from the request body.
  app.post('/api/projects/:name/tests/:id/deser-run', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await deser.runDeserWordlist(project, testId(req), req.body));
  }));

  // Prototype Pollution (WSTG-INJT-22): wordlists + urls.txt run to completion (lib/protopoll.js).
  app.post('/api/projects/:name/tests/:id/protopoll-wordlists', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await protopoll.runWordlists(project, testId(req), req.body));
  }));
  // The hash fragment opener is the "second script" - a longer, cancelable run, same start/stop/
  // status shape as the Reporting overlay and Mouse_Tool listener above.
  app.get('/api/projects/:name/protopoll/opener/status', wrap(async (req, res) => {
    res.json(protopoll.openerStatus(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/protopoll/opener/start', wrap(async (req, res) => {
    res.json(await protopoll.startOpener(await projects.resolveProject(req.params.name), req.body));
  }));
  app.post('/api/projects/:name/protopoll/opener/stop', wrap(async (req, res) => {
    res.json(protopoll.stopOpener(await projects.resolveProject(req.params.name)));
  }));

  // Host Header Injection (WSTG-INJT-17): builds a Host-header wordlist, reusing WSTG-INFO-04's
  // subdomains/DNS/nmap output when present (lib/hostheader.js). Run-to-completion, same shape
  // as the Deserialization and Prototype Pollution wordlist endpoints above.
  app.post('/api/projects/:name/tests/:id/hostheader-run', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await hostheader.runHostHeaderWordlist(project, testId(req), req.body));
  }));

  // Injection Distributor GUI panel removed 2026-11-08 (see README) - inj_distributor.py is
  // placeholder scaffolding now superseded by the real server-side/client-side orchestrators.
  // The script itself still works from the CLI if ever needed for a WSTG-INJT item that has
  // no dedicated tool yet.

  /* --------------------- run order and command building -------------- */
  // Everything needed to assemble the commands for one assessment: scripts in run order, their flags,
  // and the files they should be given (resolved from the project's folders). Read-only: nothing is run.
  app.get('/api/projects/:name/tests/:id/procedures', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await procedures.buildModel(project, testId(req), await data.getIo()));
  }));

  // Mouse_Tool: absolute input/output/XML folders for a WSTG ID, from the project's static mouse_tool.json. Read-only.
  app.get('/api/projects/:name/mouse', wrap(async (req, res) => {
    res.json({ targets: await mouse.listTargets(await projects.resolveProject(req.params.name)) });
  }));
  app.get('/api/projects/:name/mouse/active', wrap(async (req, res) => {
    res.json(await mouse.getActive(await projects.resolveProject(req.params.name)));
  }));
  app.put('/api/projects/:name/mouse/active', wrap(async (req, res) => {
    res.json(await mouse.setActive(await projects.resolveProject(req.params.name), req.body?.wstg_id));
  }));
  app.get('/api/projects/:name/mouse/:wstgId', wrap(async (req, res) => {
    res.json(await mouse.resolve(await projects.resolveProject(req.params.name), req.params.wstgId));
  }));

  // Mouse_Tool listener: start/stop the clipboard interceptor process (needs the operator's own
  // desktop - hotkeys, clipboard - so this only works when the server and browser share a machine).
  app.get('/api/projects/:name/mouse/listener/status', wrap(async (req, res) => {
    res.json(mouseProc.listenerStatus(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/mouse/listener/start', wrap(async (req, res) => {
    res.json(mouseProc.startListener(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/mouse/listener/stop', wrap(async (req, res) => {
    res.json(mouseProc.stopListener(await projects.resolveProject(req.params.name)));
  }));

  // Injection test-data pipeline: run shuttle_gen / rebuild_tag / tag_combine across one side's
  // WSTG items. Run-to-completion (not a background process), so this just waits for it.
  app.post('/api/projects/:name/mouse/orchestrator/run', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await mouseProc.runOrchestrator(project, req.body || {}));
  }));

  // Server-side wordlist pipeline: base commands x WAF-evasion strings, one file per WSTG item,
  // no mouse capture involved - a separate, smaller run-to-completion script.
  app.post('/api/projects/:name/mouse/server-side/run', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await mouseProc.runServerSideOrchestrator(project));
  }));

  // Reporting tool: a category/item-picking screenshot overlay (see tools/reporting/). Same
  // deployment model as Mouse_Tool - needs the operator's own desktop - so it's start/stop +
  // status the same way, plus a read-only summary of what's been captured so far.
  app.get('/api/projects/:name/reporting/summary', wrap(async (req, res) => {
    res.json(await reporting.getSummary(await projects.resolveProject(req.params.name)));
  }));
  app.get('/api/projects/:name/reporting/overlay/status', wrap(async (req, res) => {
    res.json(reportingProc.overlayStatus(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/reporting/overlay/start', wrap(async (req, res) => {
    res.json(reportingProc.startOverlay(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/reporting/overlay/stop', wrap(async (req, res) => {
    res.json(reportingProc.stopOverlay(await projects.resolveProject(req.params.name)));
  }));

  // Questionnaires: informational/checkbox pre-test items, answered on the web (no script run).
  // List is for the topbar's info card; item/save are for the full answering page.
  app.get('/api/projects/:name/questionnaires', wrap(async (req, res) => {
    res.json(await questionnaire.listItems(await projects.resolveProject(req.params.name)));
  }));
  app.get('/api/projects/:name/questionnaires/:key', wrap(async (req, res) => {
    res.json(await questionnaire.getItem(await projects.resolveProject(req.params.name), req.params.key));
  }));
  app.put('/api/projects/:name/questionnaires/:key/answers', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await questionnaire.saveAnswers(project, req.params.key, req.body?.answers));
  }));

  // Callback Suite: start/stop the operator's server.py (the client-side payload/callback
  // catcher), and export its log into the matching WSTG-CLNT-NN item's Outputs/test_outputs.
  // Unlike Mouse_Tool's listener, this server is meant to be reachable from outside this
  // machine - it's what the target application calls back to - so it isn't forced onto loopback.
  app.get('/api/projects/:name/callback/status', wrap(async (req, res) => {
    res.json(callbackProc.serverStatus(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/callback/start', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(callbackProc.startServer(project, req.body || {}));
  }));
  app.post('/api/projects/:name/callback/stop', wrap(async (req, res) => {
    res.json(callbackProc.stopServer(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/callback/export', wrap(async (req, res) => {
    res.json(await callbackProc.exportHits(await projects.resolveProject(req.params.name)));
  }));

  // Intruder Loader panel: launch/stop/track a local Burp process the same way Callback Suite
  // tracks server.py, plus read-only status on the shared queue folder. This app can start Burp;
  // it cannot make Burp load the watcher extension - that's a one-time, by-hand Burp setting
  // (see Base_Image/.../Intruder_Loader/intruder_loader_extension.py's own docstring).
  app.get('/api/projects/:name/intruder-loader/config', wrap(async (req, res) => {
    res.json(await intruderLoader.readConfig(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/intruder-loader/config', wrap(async (req, res) => {
    res.json(await intruderLoader.saveConfig(await projects.resolveProject(req.params.name), req.body || {}));
  }));
  app.get('/api/projects/:name/intruder-loader/status', wrap(async (req, res) => {
    res.json(await intruderLoader.status(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/intruder-loader/launch', wrap(async (req, res) => {
    res.json(await intruderLoader.launch(await projects.resolveProject(req.params.name)));
  }));
  app.post('/api/projects/:name/intruder-loader/stop', wrap(async (req, res) => {
    res.json(intruderLoader.stop(await projects.resolveProject(req.params.name)));
  }));

  // Findings Entry: one or more findings per WSTG item, entered by hand through the GUI's
  // left-pane form. See lib/findings.js for the file shape (findings.json + findings.md,
  // both in that item's own Outputs/test_outputs/).
  app.get('/api/projects/:name/tests/:id/findings', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await findings.readFindings(project, testId(req)));
  }));
  app.post('/api/projects/:name/tests/:id/findings', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.status(201).json(await findings.createFinding(project, testId(req), req.body));
  }));
  app.put('/api/projects/:name/tests/:id/findings/:findingId', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await findings.updateFinding(project, testId(req), req.params.findingId, req.body));
  }));
  app.delete('/api/projects/:name/tests/:id/findings/:findingId', wrap(async (req, res) => {
    const project = await projects.resolveProject(req.params.name);
    res.json(await findings.deleteFinding(project, testId(req), req.params.findingId));
  }));

  /* ------------------------------ errors ---------------------------- */
  app.use('/api',(req, res, next) => next(new HttpError(404, 'Unknown endpoint.')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status || (err.type === 'entity.parse.failed' ? 400 : 500);
    if (status >= 500 && !(err instanceof HttpError)) console.error(err);
    const message = status >= 500 && !(err instanceof HttpError) ? 'Something went wrong on the server.' : err.message;
    if (req.path.startsWith('/api/')) return res.status(status).json({ error: message });
    res.status(status).type('text/plain').send(message);
  });

  return app;
}

async function buildPreflight(project) {
  const checks = [];
  const add = (id, status, label, detail) => checks.push({ id, status, label, detail });

  add('folder', 'ok', 'Project folder found', project.dir);

  const root = await resources.repoRoot(project.dir);
  const hasRepo = root !== project.dir;
  add('repo', hasRepo ? 'ok' : 'warn', hasRepo ? 'WSTG repository found' : 'No WSTG_Repository folder',
    hasRepo ? path.relative(project.dir, root) : 'Searching the project folder directly for WSTG-XXXX-NN folders.');

  const stats = { expected: null, found: null };
  let reporting = null;
  try {
    reporting = await data.getReporting();
  } catch (e) {
    add('reporting', 'fail', `${cfg.REPORTING_FILE} not loaded`, e.message);
  }
  let io = null;
  try {
    io = await data.getIo();
  } catch (e) {
    add('io', 'fail', `${cfg.IO_FILE} not loaded`, e.message);
  }

  if (reporting) {
    add('reporting', 'ok', `${cfg.REPORTING_FILE} loaded`, `${reporting.byId.size} assessments in ${reporting.categories.length} categories`);
    const index = await resources.indexTestDirs(root);
    const missing = [...reporting.byId.keys()].filter((id) => !index.has(id));
    stats.expected = reporting.byId.size;
    stats.found = reporting.byId.size - missing.length;
    add('tests', missing.length ? 'warn' : 'ok',
      missing.length ? `${stats.found} of ${stats.expected} assessment folders present` : `All ${stats.expected} assessment folders present`,
      missing.length ? `Missing: ${missing.slice(0, 12).join(', ')}${missing.length > 12 ? ` and ${missing.length - 12} more` : ''}` : 'Every assessment in the checklist has a folder.');
  }
  if (io) {
    add('io', 'ok', `${cfg.IO_FILE} loaded`, `${io.byId.size} assessments have file requirements`);
    if (reporting) {
      const rep = await data.validationReport();
      const gaps = rep.testsWithoutIo.length;
      if (gaps) {
        add('io-gaps', 'warn', `${gaps} ${gaps === 1 ? 'assessment has' : 'assessments have'} no entry in ${cfg.IO_FILE}`, `${gaps === 1 ? 'Its lights stay' : 'Their lights stay'} grey: ${rep.testsWithoutIo.join(', ')}`);
      }
      const loose = rep.unattachedKeys.length;
      if (loose) {
        add('io-keys', 'warn', `${loose} ${loose === 1 ? 'entry' : 'entries'} in ${cfg.IO_FILE} ${loose === 1 ? 'is' : 'are'} not tied to one assessment`, `Not shown in the checklist: ${rep.unattachedKeys.join(', ')}`);
      }
    }
  }

  try {
    const routing = await data.getRouting();
    const on = routing.kinds.filter((k) => k.enabled);
    add('routing', 'ok', `${cfg.ROUTING_FILE} loaded`, `${on.map((k) => `${k.title} (${k.categories.length} categories)`).join(', ') || 'No XML types enabled'}`);
  } catch (e) {
    add('routing', 'warn', `${cfg.ROUTING_FILE} not loaded`, `${e.message} XML upload is unavailable until it is fixed.`);
  }

  try {
    // Older projects get the Settings folders on first look (folders only; nothing already there is touched).
    await settings.ensureSettings(project.dir);
    const rep = await settings.settingsReport(project.dir);
    const rel = path.relative(project.dir, rep.root);
    if (rep.missing.length) {
      add('settings', 'warn', 'Settings folder created, files still to add',
        `Put ${rep.missing.map((f) => f.label).join(' and ')} in ${rel}${path.sep}Configurations, or in Base_Image${path.sep}Settings so new projects get them.`);
    } else {
      add('settings', 'ok', 'Settings folder in place',
        `${rel}: Mouse_Tool (${rep.scripts.python} Python, ${rep.scripts.javascript} JavaScript), Utilities, Wordlists (${rep.wordlists} JSON)`);
    }
  } catch (e) {
    add('settings', 'warn', 'Settings folder could not be checked', e.message);
  }

  try {
    const proc = await procedures.getProcedures();
    const n = [...proc.byId.values()].reduce((a, e) => a + e.scripts.length, 0);
    add('procedures', proc.problems.length ? 'warn' : 'ok', `${cfg.PROCEDURES_FILE} loaded`,
      `${n} scripts across ${proc.byId.size} assessments${proc.problems.length ? `. Skipped: ${proc.problems.slice(0, 3).join('; ')}${proc.problems.length > 3 ? ` and ${proc.problems.length - 3} more` : ''}` : ''}`);
  } catch (e) {
    add('procedures', 'warn', `${cfg.PROCEDURES_FILE} not loaded`, `${e.message} Run order and commands are unavailable until it is fixed.`);
  }

  return { project: project.name, path: project.dir, stats, checks, ready: !checks.some((c) => c.status === 'fail') };
}

async function start() {
  const app = createApp();
  const server = app.listen(cfg.PORT, cfg.HOST, async () => {
    server.requestTimeout = 30 * 60 * 1000; // a 1 GB Burp export on a slow disk can take a while
    const { port } = server.address();
    console.log(`Red Team Audit Tool running at http://${cfg.HOST === '::1' ? '[::1]' : cfg.HOST}:${port}`);
    console.log(`  Projects:    ${cfg.PROJECTS_DIR}`);
    console.log(`  Base image:  ${path.join(cfg.BASE_IMAGE_DIR, cfg.REPO_DIRNAME)}`);
    console.log(`  Data files:  ${cfg.DATA_DIR}`);
    try {
      await require('fs/promises').mkdir(cfg.PROJECTS_DIR, { recursive: true });
      const rep = await data.validationReport();
      console.log(`  Loaded ${rep.reportingTests} assessments and ${rep.ioConfigs} file requirement entries.`);
      if (rep.testsWithoutIo.length) console.log(`  Note: no ${cfg.IO_FILE} entry for ${rep.testsWithoutIo.join(', ')} (lights will stay grey).`);
      if (rep.unattachedKeys.length) console.log(`  Note: ${cfg.IO_FILE} entries not tied to one assessment: ${rep.unattachedKeys.join('; ')}`);
    } catch (e) {
      console.warn(`  WARNING: ${e.message}`);
    }
    try {
      const routing = await data.getRouting();
      console.log(`  XML routing: ${routing.kinds.filter((k) => k.enabled).map((k) => k.title).join(', ') || 'none enabled'}`);
    } catch (e) {
      console.warn(`  WARNING: ${e.message}`);
    }
  });
  return server;
}

if (require.main === module) start();

module.exports = { createApp, start };
