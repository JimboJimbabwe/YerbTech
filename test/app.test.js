'use strict';
// Run with: npm test
// Spins up the real server against throwaway folders. Nothing in your real Projects/ is touched.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rtat-'));
const dirs = {
  projects: path.join(tmp, 'Projects'),
  base: path.join(tmp, 'Base_Image'),
  data: path.join(tmp, 'data'),
  intruderQueue: path.join(tmp, 'IntruderQueue'),
};
process.env.PROJECTS_DIR = dirs.projects;
process.env.BASE_IMAGE_DIR = dirs.base;
process.env.DATA_DIR = dirs.data;
process.env.INTRUDER_QUEUE_DIR = dirs.intruderQueue;
process.env.MAX_COPY_BYTES = '2048';
process.env.MAX_XML_BYTES = '100000';

const { createApp } = require('../server');

const CATEGORY_DIRS = {
  'WSTG-INFO': '01_Information_Gathering',
  'WSTG-CONF': '02_Configuration_and_Deployment_Management',
  'WSTG-BUSL': '10_Business_Logic',
  'WSTG-INJT': '07_Injection',
};
const SUBDIRS = ['Inputs/Data', 'Inputs/JSON', 'Inputs/Wordlists', 'Inputs/XML', 'Methodology', 'Outputs/test_outputs',
  'Utilities/GO', 'Utilities/JS', 'Utilities/Kali_Tools', 'Utilities/python'];
const IDS = ['WSTG-INFO-01', 'WSTG-INFO-02', 'WSTG-INFO-06', 'WSTG-CONF-02', 'WSTG-CONF-11', 'WSTG-CONF-12', 'WSTG-BUSL-08', 'WSTG-INJT-04', 'WSTG-CONF-06', 'WSTG-CONF-07'];

let server;
let base;

const mkfile = (...p) => { fs.mkdirSync(path.dirname(path.join(...p)), { recursive: true }); fs.writeFileSync(path.join(...p), 'x'); };
const testDir = (project, id) => path.join(dirs.projects, project, 'WSTG_Repository', CATEGORY_DIRS[id.slice(0, 9)], id);

function raw(method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const { port } = server.address();
    // Node's http client only auto-adds Content-Length for methods it assumes carry a body
    // (POST/PUT/PATCH); for others - DELETE included - a body passed via write()+end() goes out
    // on the wire with no Content-Length/Transfer-Encoding at all, which makes Express's
    // type-is-based req.is() treat the request as bodyless and never match the Content-Type
    // header, however correct that header is. Setting it explicitly here (whenever there's a
    // body) is what a real browser fetch()/XHR DELETE call does automatically, so this also
    // keeps the test honest about what the as-yet-unbuilt GUI's own DELETE calls will need.
    if (body && headers['Content-Length'] === undefined && headers['content-length'] === undefined) {
      headers = { ...headers, 'Content-Length': Buffer.byteLength(body) };
    }
    const req = http.request({ host: '127.0.0.1', port, path: urlPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: data, json: () => JSON.parse(data) }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
const get = (p, headers) => raw('GET', p, { headers });
const post = (p, obj) => raw('POST', p, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
const putJson = (p, obj) => raw('PUT', p, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
const del = (p) => raw('DELETE', p, { headers: { 'Content-Type': 'application/json' }, body: '{}' });

before(async () => {
  fs.mkdirSync(dirs.data, { recursive: true });
  fs.copyFileSync(path.join(__dirname, 'fixtures/wstg_io.sample.json'), path.join(dirs.data, 'wstg_io.json'));
  fs.copyFileSync(path.join(__dirname, 'fixtures/wstg_reporting.sample.json'), path.join(dirs.data, 'wstg_reporting.json'));
  fs.copyFileSync(path.join(__dirname, '../data/json/xml_routing.json'), path.join(dirs.data, 'xml_routing.json'));
  fs.copyFileSync(path.join(__dirname, 'fixtures/wstg_tools_procedures.sample.json'), path.join(dirs.data, 'wstg_tools_procedures.json'));
  for (const id of IDS) for (const s of SUBDIRS) {
    fs.mkdirSync(path.join(dirs.base, 'WSTG_Repository', CATEGORY_DIRS[id.slice(0, 9)], id, ...s.split('/')), { recursive: true });
  }
  fs.writeFileSync(path.join(dirs.base, 'unrelated.txt'), 'should not be copied');
  await new Promise((r) => { server = createApp().listen(0, '127.0.0.1', r); });
});

after(() => { server.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

/* ------------------------------ projects ------------------------------ */

test('empty project list', async () => {
  const r = await get('/api/projects');
  assert.equal(r.status, 200);
  assert.deepEqual(r.json(), { count: 0, projects: [] });
});

test('create copies WSTG_Repository only, and lists the project', async () => {
  const r = await post('/api/projects', { name: 'Acme Corp 2026' });
  assert.equal(r.status, 201);
  assert.equal(r.json().name, 'Acme_Corp_2026');
  assert.ok(fs.existsSync(path.join(dirs.projects, 'Acme_Corp_2026/WSTG_Repository/01_Information_Gathering/WSTG-INFO-01/Inputs/XML')));
  assert.ok(!fs.existsSync(path.join(dirs.projects, 'Acme_Corp_2026/unrelated.txt')));
  const list = (await get('/api/projects')).json();
  assert.equal(list.count, 1);
  assert.equal(list.projects[0].name, 'Acme_Corp_2026');
});

test('duplicate names are refused, case-insensitively', async () => {
  assert.equal((await post('/api/projects', { name: 'acme_corp_2026' })).status, 409);
});

test('unsafe or illegal names are refused', async () => {
  for (const name of ['../escape', 'a/b', 'a\\b', '..', '.hidden', '', '   ', 'CON', 'nul.txt', 'x'.repeat(65), 'bad|name', 'trailing.', null, 42, { a: 1 }]) {
    const r = await post('/api/projects', { name });
    assert.equal(r.status, 400, `expected 400 for ${JSON.stringify(name)}, got ${r.status}`);
  }
  assert.deepEqual(fs.readdirSync(dirs.projects), ['Acme_Corp_2026']);
});

test('creating a project with no base image fails cleanly and leaves nothing behind', async () => {
  fs.renameSync(path.join(dirs.base, 'WSTG_Repository'), path.join(dirs.base, 'moved'));
  const r = await post('/api/projects', { name: 'NoBase' });
  fs.renameSync(path.join(dirs.base, 'moved'), path.join(dirs.base, 'WSTG_Repository'));
  assert.equal(r.status, 500);
  assert.match(r.json().error, /Base image not found/);
  assert.ok(!fs.existsSync(path.join(dirs.projects, 'NoBase')));
});

test('project names from URLs are never trusted', async () => {
  for (const name of ['..', '%2e%2e', '..%2F..%2Fetc', 'Nope']) {
    const r = await get(`/api/projects/${name}/preflight`);
    assert.ok([400, 404].includes(r.status), `${name} -> ${r.status}`);
  }
});

/* ------------------------------ reference data ------------------------ */

test('checklist keeps file order', async () => {
  const { categories } = (await get('/api/wstg/checklist')).json();
  assert.deepEqual(categories.map((c) => c.id), ['WSTG-INFO', 'WSTG-CONF', 'WSTG-BUSL']);
  assert.deepEqual(categories[0].tests.map((t) => t.id), ['WSTG-INFO-01', 'WSTG-INFO-02', 'WSTG-INFO-06']);
});

test('what/why lookup by ID', async () => {
  const r = await get('/api/wstg/tests/wstg-busl-08'); // case-insensitive
  assert.equal(r.status, 200);
  const j = r.json();
  assert.equal(j.name, 'Upload of Unexpected File Types');
  assert.equal(j.category, 'Business Logic');
  assert.equal(j.reporting.length, 2);
  assert.equal(j.reporting[0].what, 'Tests rejected file types.');
  assert.equal((await get('/api/wstg/tests/WSTG-INFO-99')).status, 404);
  assert.equal((await get('/api/wstg/tests/not-an-id')).status, 400);
});

/* --------------------------- diagnostic lights ------------------------ */

const lights = async (id) => (await get(`/api/projects/Acme_Corp_2026/tests/${id}/resources`)).json();

test('lights: red before files exist, green after (named xml + script)', async () => {
  let r = await lights('WSTG-INFO-02');
  assert.equal(r.configured, true);
  assert.equal(r.groups.xml.light, 'red');
  assert.equal(r.groups.scripts.light, 'red');
  assert.equal(r.groups.json.light, 'grey'); // nothing required
  assert.equal(r.groups.wordlists.light, 'grey');
  assert.equal(r.testDir, 'WSTG_Repository/01_Information_Gathering/WSTG-INFO-02');

  const t = testDir('Acme_Corp_2026', 'WSTG-INFO-02');
  mkfile(t, 'Inputs', 'XML', 'Fingerprint_Targets.XML'); // different case on purpose
  mkfile(t, 'Utilities', 'python', 'info2_orchestrator.py');
  r = await lights('WSTG-INFO-02');
  assert.equal(r.groups.xml.light, 'green');
  assert.equal(r.groups.scripts.light, 'green');
  assert.equal(r.groups.xml.items[0].status, 'present');
});

test('lights: run-time names stay informational, never red', async () => {
  const r = await lights('WSTG-INFO-02');
  const produces = r.groups.json.produces[0];
  assert.equal(produces.status, 'dynamic');
  assert.ok(r.reports.some((x) => x.title === 'findings.md' && x.status === 'pending'));
  assert.ok(r.reports.some((x) => x.status === 'dynamic')); // curl_<ts>.md
});

test('lights: a file in the wrong sub-folder is amber, not red', async () => {
  const t = testDir('Acme_Corp_2026', 'WSTG-CONF-12');
  mkfile(t, 'Inputs', 'XML', 'csp_targets.xml');
  mkfile(t, 'Utilities', 'python', 'conf12_csp_scanner.py');
  mkfile(t, 'Inputs', 'Data', 'CSP_Strings.json'); // expected in Inputs/JSON
  const r = await lights('WSTG-CONF-12');
  assert.equal(r.groups.json.light, 'amber');
  assert.equal(r.groups.json.items[0].status, 'misplaced');
  assert.match(r.groups.json.items[0].note, /Inputs\/Data/);
  assert.equal(r.groups.xml.light, 'green');
});

test('lights: duplicate titles collapse; one missing makes the group red', async () => {
  const t = testDir('Acme_Corp_2026', 'WSTG-CONF-02');
  mkfile(t, 'Inputs', 'JSON', 'svc_repo.json');
  const r = await lights('WSTG-CONF-02');
  const names = r.groups.json.items.map((i) => i.title);
  assert.deepEqual(names, ['how_to_steps_bridge.json', 'svc_repo.json']);
  assert.equal(r.groups.json.light, 'red');
  assert.equal(r.groups.json.items[1].status, 'present');
  assert.match(r.groups.json.items[1].detail, /conf_02_wordlist\.py.*conf02_enum\.py/);
  assert.equal(r.groups.scripts.items.length, 4);
});

test('lights: operator-supplied inputs need an unmatched file in the folder', async () => {
  const t = testDir('Acme_Corp_2026', 'WSTG-INFO-01');
  let r = await lights('WSTG-INFO-01');
  assert.equal(r.groups.wordlists.light, 'red');
  mkfile(t, 'Inputs', 'Wordlists', 'my_terms.txt');
  r = await lights('WSTG-INFO-01');
  assert.equal(r.groups.wordlists.light, 'green');
});

test('lights: script annotations are stripped and the extension picks the folder', async () => {
  const t = testDir('Acme_Corp_2026', 'WSTG-BUSL-08');
  let r = await lights('WSTG-BUSL-08');
  assert.deepEqual(r.groups.scripts.items.map((i) => i.title), ['busl_08_questionnaire.py', 'conf10_run.sh', 'clnt_setup.py']);
  mkfile(t, 'Utilities', 'Kali_Tools', 'conf10_run.sh'); // .sh lives in Kali_Tools
  mkfile(t, 'Utilities', 'python', 'busl_08_questionnaire.py');
  r = await lights('WSTG-BUSL-08');
  assert.equal(r.groups.scripts.items[0].status, 'present');
  assert.equal(r.groups.scripts.items[1].status, 'present');
  assert.equal(r.groups.scripts.items[2].status, 'missing');
  assert.equal(r.groups.scripts.light, 'red');
});

test('lights: assessments without a config entry are grey and say so', async () => {
  const r = await lights('WSTG-INFO-06');
  assert.equal(r.configured, false);
  assert.equal(r.testDirFound, true);
  for (const g of Object.values(r.groups)) assert.equal(g.light, 'grey');
});

test('lights: a test folder missing from the project is reported', async () => {
  fs.rmSync(testDir('Acme_Corp_2026', 'WSTG-CONF-11'), { recursive: true });
  const r = await lights('WSTG-CONF-11');
  assert.equal(r.testDirFound, false);
  assert.equal(r.testDir, null);
  assert.equal(r.groups.json.light, 'red');
});

test('lights: the longer descriptive folder naming also resolves', async () => {
  const long = path.join(dirs.projects, 'Acme_Corp_2026', 'WSTG_Repository', 'Weird_Layout', 'WSTG-CONF-11_Cloud_Storage', 'Inputs', 'JSON');
  fs.mkdirSync(long, { recursive: true });
  fs.writeFileSync(path.join(long, 'cloud_strings.json'), '{}');
  const r = await lights('WSTG-CONF-11');
  assert.equal(r.testDirFound, true);
  assert.equal(r.groups.json.light, 'green');
});

test('resource endpoint rejects bad IDs', async () => {
  assert.equal((await get('/api/projects/Acme_Corp_2026/tests/..%2F..%2Fx/resources')).status, 400);
  assert.equal((await get('/api/projects/Acme_Corp_2026/tests/WSTG-INFO-1/resources')).status, 400);
});

/* ------------------------------ preflight ----------------------------- */

test('preflight counts folders and flags gaps in the two JSON files', async () => {
  const p = (await get('/api/projects/Acme_Corp_2026/preflight')).json();
  assert.equal(p.stats.expected, 7);
  assert.equal(p.ready, true);
  const byId = Object.fromEntries(p.checks.map((c) => [c.id, c]));
  assert.equal(byId.io.status, 'ok');
  assert.match(byId['io-gaps'].detail, /WSTG-INFO-06/);
  assert.match(byId['io-keys'].detail, /WSTG-INJT \(distributor\)/);
});

/* ------------------------------ wordlists ----------------------------- */

test('wordlists: listing tags declared files, hides dotfiles, and copy returns text', async () => {
  const t = testDir('Acme_Corp_2026', 'WSTG-CONF-02');
  const dir = path.join(t, 'Inputs', 'Wordlists');
  fs.writeFileSync(path.join(dir, 'raw.txt'), 'admin\r\nlogin\r\n');
  fs.writeFileSync(path.join(dir, 'zz_other.txt'), 'x');
  fs.writeFileSync(path.join(dir, '.gitkeep'), '');
  const l = (await get('/api/projects/Acme_Corp_2026/tests/WSTG-CONF-02/wordlists')).json();
  assert.equal(l.dirFound, true);
  assert.deepEqual(l.files.map((f) => [f.name, f.declared]), [['raw.txt', 'out'], ['zz_other.txt', null]]);
  const c = await get('/api/projects/Acme_Corp_2026/tests/WSTG-CONF-02/wordlists/raw.txt');
  assert.equal(c.status, 200);
  assert.match(c.headers['content-type'], /text\/plain/);
  assert.equal(c.text, 'admin\r\nlogin\r\n');
});

test('wordlists: traversal, hidden files, unknown names, big and binary files', async () => {
  const dir = path.join(testDir('Acme_Corp_2026', 'WSTG-CONF-02'), 'Inputs', 'Wordlists');
  fs.writeFileSync(path.join(dir, 'big.txt'), 'a'.repeat(3000));
  fs.writeFileSync(path.join(dir, 'blob.bin'), Buffer.from([1, 2, 0, 3]));
  fs.writeFileSync(path.join(dir, '..', '..', 'secret.txt'), 'secret');
  const u = (f) => `/api/projects/Acme_Corp_2026/tests/WSTG-CONF-02/wordlists/${f}`;
  assert.equal((await get(u('..%2Fsecret.txt'))).status, 400);
  assert.equal((await get(u('..%2F..%2Fsecret.txt'))).status, 400);
  assert.equal((await get(u('%2e%2e%5csecret.txt'))).status, 400);
  assert.equal((await get(u('.gitkeep'))).status, 400);
  assert.equal((await get(u('nope.txt'))).status, 404);
  assert.equal((await get(u('big.txt'))).status, 413);
  assert.equal((await get(u('blob.bin'))).status, 415);
  assert.ok(!(await get(u('secret.txt'))).text.includes('secret'));
});

/* ------------------------------ guards -------------------------------- */

test('requests with a foreign Host header are refused (DNS rebinding)', async () => {
  assert.equal((await get('/api/projects', { Host: 'evil.example' })).status, 403);
  assert.equal((await get('/api/projects', { Host: 'localhost:3000' })).status, 200);
  assert.equal((await get('/api/projects', { Host: '127.0.0.1:9' })).status, 200);
});

test('cross-site and form-style POSTs are refused', async () => {
  const json = { 'Content-Type': 'application/json' };
  assert.equal((await raw('POST', '/api/projects', { headers: { ...json, Origin: 'https://evil.example' }, body: '{"name":"Hax"}' })).status, 403);
  assert.equal((await raw('POST', '/api/projects', { headers: { 'Content-Type': 'text/plain' }, body: '{"name":"Hax"}' })).status, 415);
  assert.equal((await raw('POST', '/api/projects', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'name=Hax' })).status, 415);
  assert.equal((await raw('POST', '/api/projects', { headers: { ...json, Origin: 'http://localhost:3000' }, body: '{"name":"FromLocal"}' })).status, 201);
  assert.ok(!fs.existsSync(path.join(dirs.projects, 'Hax')));
});

test('malformed JSON is a 400, not a crash', async () => {
  const r = await raw('POST', '/api/projects', { headers: { 'Content-Type': 'application/json' }, body: '{nope' });
  assert.equal(r.status, 400);
});

test('pages are served and the CSP forbids inline script', async () => {
  for (const p of ['/', '/project/Acme_Corp_2026', '/project/Acme_Corp_2026/workspace', '/js/workspace.js', '/css/app.css']) {
    const r = await get(p);
    assert.equal(r.status, 200, p);
  }
  const csp = (await get('/')).headers['content-security-policy'];
  assert.match(csp, /default-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline/);
});

test('a missing data file gives a clear 503 and the rest still works', async () => {
  const f = path.join(dirs.data, 'wstg_reporting.json');
  const keep = fs.readFileSync(f);
  fs.unlinkSync(f);
  const r = await get('/api/wstg/checklist');
  fs.writeFileSync(f, keep);
  assert.equal(r.status, 503);
  assert.match(r.json().error, /Missing wstg_reporting\.json/);
  assert.equal((await get('/api/wstg/checklist')).status, 200);
});

test('editing a data file while running is picked up', async () => {
  const f = path.join(dirs.data, 'wstg_reporting.json');
  const keep = fs.readFileSync(f, 'utf8');
  fs.writeFileSync(f, keep.replace('Fingerprint Web Server', 'Fingerprint Web Server (edited)'));
  const j = (await get('/api/wstg/tests/WSTG-INFO-02')).json();
  fs.writeFileSync(f, keep);
  assert.equal(j.name, 'Fingerprint Web Server (edited)');
});

/* ------------------------------ Burp XML intake ----------------------- */

const P = 'Acme_Corp_2026';
const BURP = fs.readFileSync(path.join(__dirname, 'fixtures/burp_small.xml'));
const put = (cat, body, { type = 'application/xml', headers = {}, kind = 'burp_proxy_xml', project = P } = {}) =>
  raw('PUT', `/api/projects/${project}/xml/${kind}/${cat}`, { headers: { 'Content-Type': type, ...headers }, body });
const util = (...p) => path.join(dirs.projects, P, 'project_utilities', ...p);
const { indexTestDirs } = require('../lib/resources');
let dirIndex = null;
const refreshIndex = async () => { dirIndex = await indexTestDirs(path.join(dirs.projects, P, 'WSTG_Repository')); };
const inXml = (id, name) => path.join(dirIndex.get(id), 'Inputs', 'XML', name); // CONF-11 was moved by an earlier test
const status = async () => (await get(`/api/projects/${P}/xml`)).json();
const cat = (st, key) => st.kinds.find((k) => k.key === 'burp_proxy_xml').categories.find((c) => c.key === key);

test('xml: new projects get the four intake folders; Nmap and Intruder are listed but disabled', async () => {
  for (const c of ['raw', 'authorization', 'authentication', 'input_surface']) {
    assert.ok(fs.statSync(util('files', 'XML', 'burp_proxy', c)).isDirectory(), c);
  }
  const st = await status();
  assert.deepEqual(st.kinds.map((k) => [k.title, k.enabled]), [['Burp Proxy XML', true], ['Nmap Output XML', false], ['Intruder XML', false]]);
  assert.equal(st.limits.maxXmlBytes, 100000);
  assert.equal((await put('raw', BURP, { kind: 'nmap_scan_xml' })).status, 409);
});

test('xml: raw.xml is stored once and copied, renamed, into the right assessments only', async () => {
  const r = await put('raw', BURP);
  assert.equal(r.status, 200, r.text);
  await refreshIndex();
  assert.ok(fs.readFileSync(util('files', 'XML', 'burp_proxy', 'raw', 'raw.xml')).equals(BURP));
  for (const [id, name] of [['WSTG-INFO-02', 'fingerprint_targets.xml'], ['WSTG-CONF-02', 'config_probe.xml'], ['WSTG-CONF-11', 'cloud_recon.xml'], ['WSTG-CONF-12', 'csp_targets.xml']]) {
    assert.ok(fs.readFileSync(inXml(id, name)).equals(BURP), `${id} ${name}`);
  }
  assert.ok(!fs.existsSync(inXml('WSTG-BUSL-08', 'upload_probe.xml')), 'BUSL belongs to authorization, not raw');
  const raw_ = cat(r.json(), 'raw');
  assert.equal(raw_.present, true);
  assert.equal(raw_.copies.length, 4);
  assert.ok(!fs.readdirSync(util('tmp')).length, 'no temp files left behind');
  assert.equal((await lights('WSTG-INFO-02')).groups.xml.light, 'green');
});

test('xml: INJT is fed by two categories, so both copies are kept under separate names', async () => {
  assert.equal((await put('authorization', BURP)).status, 200);
  assert.ok(fs.existsSync(inXml('WSTG-BUSL-08', 'upload_probe.xml')));
  const a = Buffer.from(BURP.toString().replace('/api/profile', '/api/AUTHN'));
  const r = await put('authentication', a);
  assert.equal(r.status, 200);
  const dir = path.join(testDir(P, 'WSTG-INJT-04'), 'Inputs', 'XML');
  assert.deepEqual(fs.readdirSync(dir).filter((n) => !n.startsWith('.')).sort(), ['injection_points__authentication.xml', 'injection_points__authorization.xml']);
  assert.ok(fs.readFileSync(path.join(dir, 'injection_points__authentication.xml')).equals(a));
  assert.ok(fs.readFileSync(path.join(dir, 'injection_points__authorization.xml')).equals(BURP));
  const skipped = cat(r.json(), 'authentication').skipped;
  assert.ok(skipped.some((s) => s.testId === 'WSTG-INJT-04' && s.title === 'stray.xml' && /type/.test(s.reason)), JSON.stringify(skipped));
  const l = await lights('WSTG-INJT-04');
  const item = l.groups.xml.items.find((i) => i.title === 'injection_points.xml');
  assert.equal(item.status, 'present');
  assert.match(item.note, /datasets: authorization, authentication|datasets: authentication, authorization/);
});

test('xml: re-uploading replaces the file and archives the old one', async () => {
  const v2 = Buffer.from(BURP.toString().replace('/static/app.js', '/static/v2.js'));
  const r = await put('raw', v2);
  assert.equal(r.status, 200);
  assert.ok(fs.readFileSync(inXml('WSTG-INFO-02', 'fingerprint_targets.xml')).equals(v2));
  const archived = fs.readdirSync(util('archive', 'XML', 'burp_proxy', 'raw'));
  assert.equal(archived.length, 1);
  assert.match(archived[0], /^\d{4}-\d\d-\d\dT.*_raw\.xml$/);
  assert.ok(fs.readFileSync(util('archive', 'XML', 'burp_proxy', 'raw', archived[0])).equals(BURP));
  assert.equal(cat(r.json(), 'raw').replaced, true);
});

test('xml: bad uploads are refused and leave nothing behind', async () => {
  assert.equal((await put('input_surface', Buffer.from('just some text'))).status, 422);
  assert.equal((await put('input_surface', Buffer.from('<?xml version="1.0"?><nmaprun></nmaprun>'))).status, 422);
  assert.equal((await put('input_surface', Buffer.alloc(0))).status, 400);
  assert.equal((await put('input_surface', BURP, { type: 'text/plain' })).status, 415);
  assert.equal((await put('input_surface', Buffer.from('{}'), { type: 'application/json' })).status, 415); // JSON parser would have eaten the body
  assert.equal((await put('nonsense', BURP)).status, 404);
  assert.equal((await put('input_surface', BURP, { kind: 'nope' })).status, 404);
  assert.equal((await put('input_surface', BURP, { project: 'Nope' })).status, 404);
  assert.deepEqual(fs.readdirSync(util('files', 'XML', 'burp_proxy', 'input_surface')), []);
  assert.deepEqual(fs.readdirSync(util('tmp')), []);
});

test('xml: size cap applies whether or not the client declares the length', async () => {
  const big = Buffer.concat([BURP, Buffer.alloc(150000, 0x20)]);
  assert.equal((await put('input_surface', big)).status, 413); // chunked: caught while streaming
  const r = await put('input_surface', 'x', { headers: { 'Content-Length': '999999' } }).catch((e) => ({ status: e.code }));
  assert.ok([413, 'ECONNRESET'].includes(r.status), String(r.status)); // declared: refused up front
  assert.deepEqual(fs.readdirSync(util('tmp')), []);
  assert.deepEqual(fs.readdirSync(util('files', 'XML', 'burp_proxy', 'input_surface')), []);
});

test('xml: cross-site uploads are refused', async () => {
  const r = await put('input_surface', BURP, { headers: { Origin: 'https://evil.example' } }).catch((e) => ({ status: e.code }));
  assert.ok([403, 'ECONNRESET'].includes(r.status), String(r.status)); // refused before the body is read
  const r2 = await put('input_surface', BURP, { headers: { Host: 'evil.example' } }).catch((e) => ({ status: e.code }));
  assert.ok([403, 'ECONNRESET'].includes(r2.status), String(r2.status)); // refused before the body is read
  assert.deepEqual(fs.readdirSync(util('files', 'XML', 'burp_proxy', 'input_surface')), []);
});

test('xml: a file dropped straight into an intake folder is picked up', async () => {
  const v3 = Buffer.from(BURP.toString().replace('/api/orders/2', '/api/orders/3'));
  fs.writeFileSync(util('files', 'XML', 'burp_proxy', 'raw', 'raw.xml'), v3);
  const st = await status();
  assert.equal(cat(st, 'raw').size, v3.length);
  assert.ok(fs.readFileSync(inXml('WSTG-CONF-12', 'csp_targets.xml')).equals(v3));
  // and a file removed from the intake folder is no longer reported
  fs.rmSync(util('files', 'XML', 'burp_proxy', 'authorization', 'authorization.xml'));
  assert.equal(cat(await status(), 'authorization').present, false);
});

test('viewer: datasets per assessment', async () => {
  fs.copyFileSync(path.join(__dirname, 'fixtures/burp_small.xml'), util('files', 'XML', 'burp_proxy', 'authorization', 'authorization.xml'));
  const inj = (await get(`/api/projects/${P}/tests/WSTG-INJT-04/xml`)).json();
  assert.deepEqual(inj.datasets.map((d) => [d.category, d.id]).sort(), [
    ['authentication', 'injection_points__authentication.xml'],
    ['authorization', 'injection_points__authorization.xml'],
  ]);
  assert.equal(inj.eligible.length, 2);
  const info = (await get(`/api/projects/${P}/tests/WSTG-INFO-02/xml`)).json();
  assert.deepEqual(info.datasets.map((d) => d.id), ['fingerprint_targets.xml']);
  const none = (await get(`/api/projects/${P}/tests/WSTG-INFO-01/xml`)).json();
  assert.deepEqual([none.eligible, none.datasets], [[], []]);
  assert.equal(JSON.stringify(inj).includes(dirs.projects), false, 'no server paths leak');
});

test('viewer: request list, filter, paging and decoded request', async () => {
  const base_ = `/api/projects/${P}/tests/WSTG-INJT-04`;
  const ds = 'injection_points__authentication.xml';
  let r = (await get(`${base_}/requests?dataset=${ds}`)).json();
  assert.equal(r.total, 5);
  assert.equal(r.items.length, 5);
  assert.deepEqual([r.items[0].method, r.items[0].url, r.items[0].status], ['POST', 'https://app.example.com/api/users?id=1', '500']);

  r = (await get(`${base_}/requests?dataset=${ds}&q=500`)).json();
  assert.equal(r.matched, 3);
  r = (await get(`${base_}/requests?dataset=${ds}&limit=2&offset=3`)).json();
  assert.deepEqual(r.items.map((i) => i.index), [3, 4]);
  r = (await get(`${base_}/requests?dataset=${ds}&q=AUTHN`)).json(); // the edit made to the authentication copy only
  assert.equal(r.matched, 1);
  assert.equal((await get(`${base_}/requests?dataset=injection_points__authorization.xml&q=AUTHN`)).json().matched, 0);
  assert.equal((await get(`${base_}/requests?dataset=injection_points__authorization.xml&q=put`)).json().matched, 1);

  const one = (await get(`${base_}/requests/0?dataset=${ds}`)).json();
  assert.match(one.text, /^POST \/api\/users\?id=1 HTTP\/1\.1\r\nHost: app\.example\.com/);
  assert.equal(one.truncated, false);
  assert.ok(one.bytes > 40);
  assert.equal((await get(`${base_}/requests/99?dataset=${ds}`)).status, 404);
  assert.equal((await get(`${base_}/requests/abc?dataset=${ds}`)).status, 400);
  assert.equal((await get(`${base_}/requests/-1?dataset=${ds}`)).status, 400);
});

test('viewer: dataset names are looked up, never joined onto a path', async () => {
  const base_ = `/api/projects/${P}/tests/WSTG-INJT-04/requests`;
  for (const ds of ['../../../../../etc/passwd', '..%2F..%2Fx.xml', 'injection_points.xml', 'raw.xml']) {
    assert.equal((await get(`${base_}?dataset=${ds}`)).status, 404, ds);
  }
  assert.equal((await get(`${base_}?dataset[]=a&dataset[]=b`)).status, 200); // arrays are ignored -> default dataset
  assert.equal((await get(`/api/projects/${P}/tests/WSTG-INFO-01/requests`)).status, 404);
});

test('viewer: hostile request text is just data', async () => {
  const evil = BURP.toString().replace(/<request base64="true">.*?<\/request>/s, `<request base64="false"><![CDATA[GET /<img src=x onerror=alert(1)> HTTP/1.1\nHost: x\n\n]]></request>`);
  fs.writeFileSync(util('files', 'XML', 'burp_proxy', 'raw', 'raw.xml'), evil);
  const one = (await get(`/api/projects/${P}/tests/WSTG-INFO-02/requests/0`)).json();
  assert.match(one.text, /<img src=x onerror=alert\(1\)>/);
  const res = await get(`/api/projects/${P}/tests/WSTG-INFO-02/requests/0`);
  assert.match(res.headers['content-type'], /application\/json/);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
});

test('routing: a broken xml_routing.json is reported, not fatal to the rest of the app', async () => {
  const file = path.join(dirs.data, 'xml_routing.json');
  const good = fs.readFileSync(file, 'utf8');
  try {
    const bad = JSON.parse(good);
    bad.kinds.burp_proxy_xml.categories.raw.include = ['WSTG-INFO/../x'];
    fs.writeFileSync(file, JSON.stringify(bad));
    const r = await get(`/api/projects/${P}/xml`);
    assert.equal(r.status, 503);
    assert.match(r.json().error, /xml_routing\.json.*include/);
    const pf = (await get(`/api/projects/${P}/preflight`)).json();
    assert.equal(pf.checks.find((c) => c.id === 'routing').status, 'warn');
    assert.equal(pf.ready, true);
    assert.equal((await lights('WSTG-INFO-02')).groups.xml.light, 'green');
    fs.writeFileSync(file, '{ not json');
    assert.equal((await get(`/api/projects/${P}/xml`)).status, 503);
  } finally {
    fs.writeFileSync(file, good);
  }
  assert.equal((await get(`/api/projects/${P}/xml`)).status, 200);
});

test('routing: omit and prefix matching', () => {
  const { matches } = require('../lib/xml');
  const c = { include: ['WSTG-INFO', 'WSTG-CONF-02'], omit: ['WSTG-INFO-07'] };
  assert.equal(matches(c, 'WSTG-INFO-02'), true);
  assert.equal(matches(c, 'WSTG-INFO-07'), false);
  assert.equal(matches(c, 'WSTG-CONF-02'), true);
  assert.equal(matches(c, 'WSTG-CONF-03'), false);
  assert.equal(matches({ include: ['WSTG-INFO'], omit: [] }, 'WSTG-INFOX-01'), false);
});

/* ------------------------ run order and commands ---------------------- */

const proc = require('../lib/procedures');
const procs = async (id, project = P) => (await get(`/api/projects/${project}/tests/${id}/procedures`)).json();
const item = (s, flag) => s.items.find((i) => i.flag === flag);
const rel = (p) => p.split(/WSTG_Repository[\\/]/)[1].replace(/\\/g, '/');

test('procedures: flag and template inference', () => {
  assert.deepEqual(proc.splitFlags('-x / --xml'), ['-x', '--xml']);
  assert.deepEqual(proc.splitFlags('-o, --output'), ['-o', '--output']);
  assert.deepEqual(proc.splitFlags(null), []);
  const t = (flag, cmd, extra = {}) => proc.inferTakesValue({ tag: 'OPTION_INPUT', flag, ...extra }, cmd);
  assert.equal(t('--no-wait', 'x --file <a> [--no-wait]'), false);
  assert.equal(t('--timeout', 'x [--timeout <seconds>]'), true);
  assert.equal(t('--ua', 'x [--ua <0-11>] [--reset]'), true);
  assert.equal(t('--reset', 'x [--ua <0-11>] [--reset]'), false);
  assert.equal(t('--x', 'x --x --y 1'), false); // followed by another flag
  assert.equal(t('--depth', null, { default: 3 }), true);
  assert.equal(t('--no-encode', null), false); // name pattern
  assert.equal(t('--category', null), null); // can't tell
  assert.equal(t('--x', null, { takes_value: true }), true); // explicit field wins
  assert.equal(proc.inferTakesValue({ tag: 'XML_INPUT', flag: '--f' }, null), true);
  assert.equal(proc.outputFlagRequired({ flag: '-o' }, 'x --in a -o out.md'), true);
  assert.equal(proc.outputFlagRequired({ flag: '-o' }, 'x --in a [-o out.md]'), false);
  assert.equal(proc.outputFlagRequired({ flag: '-o' }, null), false);
  assert.deepEqual(proc.splitAlternatives('p a.py -d x [y ...] | p a.py -f z'), ['p a.py -d x [y ...]', 'p a.py -f z']);
  assert.deepEqual(proc.splitAlternatives('p a.py [-x | -y]'), []); // a | inside brackets is not an alternative
  assert.deepEqual(proc.flagsInExample('--xml ... --username jsmith --reset'), { '--xml': true, '--username': 'jsmith', '--reset': true });
});

test('procedures: bad entries are skipped and reported, not fatal', () => {
  const n = proc.normalize({ '01_X': { 'WSTG-INFO-01': { G: { a: { name: '../evil.py', run_order: 1 }, b: { name: 'ok.py', run_order: 2 } } }, 'not-an-id': {} }, category_run_order: [{ id: 'WSTG-INFO-01', order: 1 }] });
  assert.deepEqual(n.byId.get('WSTG-INFO-01').scripts.map((s) => s.name), ['ok.py']);
  assert.equal(n.problems.length, 2);
  assert.throws(() => proc.normalize([]), /JSON object/);
});

test('procedures: required XML resolves to Inputs/XML/<name from wstg_io.json>, run order is reported', async () => {
  const m = await procs('WSTG-INFO-02');
  assert.equal(m.available, true);
  assert.equal(m.position.order, 2);
  assert.ok(m.position.total >= 6);
  const s = m.scripts[0];
  assert.equal(s.name, 'info2_orchestrator.py');
  const f = item(s, '--file');
  assert.equal(f.kind, 'file');
  assert.equal(f.required, true);
  assert.equal(f.include, true);
  assert.equal(rel(f.value).toLowerCase(), '01_information_gathering/wstg-info-02/inputs/xml/fingerprint_targets.xml');
  assert.equal(f.candidates[0].exists, true); // the Burp upload put it there
  assert.ok(path.isAbsolute(f.value));
  assert.equal(item(s, '--no-wait').kind, 'switch');
  assert.equal(item(s, '--base').include, false); // optional stays off
  assert.equal(s.script.interpreter, 'python');
  assert.equal(rel(s.script.path), '01_Information_Gathering/WSTG-INFO-02/Utilities/python/info2_orchestrator.py');
  assert.equal(s.script.exists, true); // an earlier lights test put it there
  assert.equal(s.status.scriptFound, true);
  const missing = (await procs('WSTG-CONF-06')).scripts[0];
  assert.equal(missing.script.exists, false);
  mkfile(testDir(P, 'WSTG-CONF-06'), 'Utilities', 'python', 'methods_gen.py');
  assert.equal((await procs('WSTG-CONF-06')).scripts[0].script.exists, true);
});

test('procedures: chained scripts get the earlier script\'s outputs as their inputs', async () => {
  const m = await procs('WSTG-CONF-06');
  assert.deepEqual(m.scripts.map((s) => s.name), ['methods_gen.py', 'methods_test.py', 'methods_outcome.py']);
  assert.deepEqual(m.scripts.map((s) => s.position), [1, 2, 3]);
  const t = m.scripts[1];
  const urls = item(t, '--url-list');
  const methods = item(t, '--methods');
  assert.match(rel(urls.value), /Inputs\/Wordlists\/curl_urls\.txt$/);
  assert.match(rel(methods.value), /Inputs\/Wordlists\/methods\.txt$/);
  assert.match(urls.candidates[0].label, /output of methods_gen\.py/);
  assert.notEqual(urls.value, methods.value); // each output is used once
  assert.equal(t.status.missingInputs, 0); // not "missing": script 1 creates them
  assert.equal(m.scripts[0].status.missingInputs, 1); // the XML for methods_gen really is missing
  const o = item(t, '-o');
  assert.equal(o.kind, 'output');
  assert.equal(o.required, true);
  assert.equal(item(t, '--timeout').value, '10');
  assert.equal(item(t, '--timeout').include, false);
  assert.ok(t.after[0].includes('methods_gen.py'));
});

test('procedures: alternatives become presets', async () => {
  const s = (await procs('WSTG-CONF-07')).scripts[0];
  assert.equal(s.presets.length, 2);
  assert.ok('-d' in s.presets[0].active);
  assert.ok('--domains-file' in s.presets[1].active);
  const sess = (await procs('WSTG-SESS-01')).scripts.find((x) => x.name === 'sess01_m3_reverse_engineer.py');
  assert.ok(sess.presets.some((p) => p.active['--username'] === 'jsmith'));
});

test('procedures: undocumented scripts and mode flags are handled', async () => {
  const m = await procs('WSTG-CONF-02');
  const enumr = m.scripts.find((s) => s.name === 'conf02_enum.py');
  assert.equal(enumr.commandKnown, false);
  assert.ok(enumr.items.some((i) => i.flagUnknown && i.positional));
  const dsr = m.scripts.find((s) => s.name === 'svc_dsr.py');
  const type = item(dsr, '--type');
  assert.deepEqual(type.choices, ['env_vars', 'paths', 'headers', 'default_creds', 'commands']);
  assert.equal(item(dsr, '--init').kind, 'switch');
  assert.ok(dsr.presets.length >= 1);
});

test('procedures: INJT-style assessments offer each Burp dataset as a choice', async () => {
  const s = (await procs('WSTG-INJT-04')).scripts[0];
  const x = item(s, '--xml');
  const names = x.candidates.map((c) => path.basename(c.path));
  assert.ok(names.includes('injection_points__authentication.xml') && names.includes('injection_points__authorization.xml'), names.join());
  assert.ok(x.candidates.every((c) => c.exists || c.label.startsWith('named')));
  assert.ok(x.candidates.some((c) => /dataset: authentication/.test(c.label)));
  assert.equal(item(s, '--depth').value, '3');
});

test('procedures: assessments without data, bad IDs and unknown projects', async () => {
  const none = await procs('WSTG-INFO-06');
  assert.deepEqual([none.available, none.scripts], [false, []]);
  assert.equal((await get(`/api/projects/${P}/tests/nope/procedures`)).status, 400);
  assert.equal((await get('/api/projects/Nope/tests/WSTG-INFO-02/procedures')).status, 404);
  assert.equal(JSON.stringify(await procs('WSTG-INFO-02')).includes('<script'), false);
});

test('procedures: a broken procedures file is a clean 503 and a briefing warning', async () => {
  const file = path.join(dirs.data, 'wstg_tools_procedures.json');
  const good = fs.readFileSync(file, 'utf8');
  try {
    fs.writeFileSync(file, '{ nope');
    const r = await get(`/api/projects/${P}/tests/WSTG-INFO-02/procedures`);
    assert.equal(r.status, 503);
    assert.match(r.json().error, /wstg_tools_procedures\.json is not valid JSON/);
    const pf = (await get(`/api/projects/${P}/preflight`)).json();
    assert.equal(pf.checks.find((c) => c.id === 'procedures').status, 'warn');
    assert.equal(pf.ready, true);
    assert.equal((await lights('WSTG-INFO-02')).groups.xml.light, 'green'); // the file checks don't depend on it
  } finally {
    fs.writeFileSync(file, good);
  }
  assert.equal((await procs('WSTG-INFO-02')).available, true);
});

test('procedures: the real data file loads, and every script resolves without error', async () => {
  const real = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/json/wstg_tools_procedures.json'), 'utf8'));
  const n = proc.normalize(real);
  assert.equal(n.problems.length, 0);
  assert.equal(n.byId.size, 47);
  assert.equal([...n.byId.values()].reduce((a, e) => a + e.scripts.length, 0), 84);
  const unannotated = [];
  for (const e of n.byId.values()) for (const s of e.scripts) for (const i of s.inputs || []) if (proc.splitFlags(i.flag).length && !('takes_value' in i)) unannotated.push(s.name);
  assert.deepEqual(unannotated, [], 'run: node tools/annotate_procedures.js --write');
});

test('commands: quoting for PowerShell and bash', async () => {
  const { quote, buildCommand, buildSequence, applyPreset, initialFields } = await import('../public/js/cmdline.mjs');
  const cases = [
    ['plain.txt', 'plain.txt', 'plain.txt'],
    ['C:\\Users\\a b\\f.xml', "'C:\\Users\\a b\\f.xml'", "'C:\\Users\\a b\\f.xml'"],
    ["it's", "'it''s'", "'it'\\''s'"],
    ['a;b', "'a;b'", "'a;b'"],
    ['$(whoami)', "'$(whoami)'", "'$(whoami)'"],
    ['`id`', "'`id`'", "'`id`'"],
    ['a&b|c', "'a&b|c'", "'a&b|c'"],
    ['', "''", "''"],
    ['x\nrm -rf /', "'x rm -rf /'", "'x rm -rf /'"], // a line break would run a second command
    ['x\r\ny', "'x y'", "'x y'"],
    ['‘x’', "'‘‘x’’'", "'‘x’'"], // PowerShell treats curly quotes as quotes
  ];
  for (const [v, ps, bash] of cases) {
    assert.equal(quote('powershell', v), ps, `ps ${JSON.stringify(v)}`);
    assert.equal(quote('bash', v), bash, `bash ${JSON.stringify(v)}`);
  }
  assert.equal(quote('bash', 'C:\\a\\b'), "'C:\\a\\b'"); // backslash is special in bash
  assert.equal(quote('powershell', 'C:\\a\\b'), 'C:\\a\\b');

  const script = { script: { path: 'C:\\p q\\x.py', interpreter: 'python' }, workdir: 'C:\\p q', name: 'x.py', position: 1 };
  const fields = [
    { kind: 'file', tag: 'XML_INPUT', flag: '--file', required: true, include: true, value: 'C:\\a\\b.xml' },
    { kind: 'switch', flag: '--no-wait', include: true },
    { kind: 'value', flag: '--depth', include: false, value: '3' },
    { kind: 'file', tag: 'XML_INPUT', flag: '-x', required: true, include: true, value: null },
    { kind: 'value', flag: '--maybe', flagUnsure: true, include: true, value: '' },
    { kind: 'file', tag: 'WORDLIST_INPUT', flag: null, required: true, include: true, value: 'w.txt' },
  ];
  let r = buildCommand('powershell', script, fields);
  assert.equal(r.text, "python 'C:\\p q\\x.py' w.txt --file C:\\a\\b.xml --no-wait -x '<xml file>' --maybe");
  assert.equal(r.missing, 1);
  r = buildCommand('bash', script, fields, { cd: true });
  assert.equal(r.text, "cd 'C:\\p q' && python3 'C:\\p q\\x.py' w.txt --file 'C:\\a\\b.xml' --no-wait -x '<xml file>' --maybe");
  assert.equal(buildCommand('powershell', script, fields, { cd: true }).text.startsWith("Set-Location -LiteralPath 'C:\\p q'; python "), true);
  // a hostile typed value stays one inert argument
  fields[2].include = true;
  fields[2].value = '3; Remove-Item -Recurse C:\\';
  assert.match(buildCommand('powershell', script, fields).text, /--depth '3; Remove-Item -Recurse C:\\'/);
  // presets switch optional flags on and off
  const f2 = applyPreset(initialFields({ items: [{ flag: '-d', required: false, include: false, kind: 'value', value: '' }, { flag: '-f', required: false, include: true, kind: 'value', value: '' }] }), { active: { '-d': 'example.com' } });
  assert.deepEqual(f2.map((x) => [x.include, x.value]), [[true, 'example.com'], [false, '']]);
  const seq = buildSequence('bash', [{ ...script, position: 1, items: fields.slice(0, 2) }, { ...script, name: 'y.py', position: 2, items: [] }]);
  assert.match(seq, /^# 1\. x\.py\npython3 .*\n# 2\. y\.py\npython3 /);
});

/* ------------------------------ Settings folder ----------------------- */

const settingsDir = (project) => path.join(dirs.projects, project, 'Settings', 'Configurations');
const SETTINGS_DIRS = ['Mouse_Tool/python', 'Mouse_Tool/javascript', 'Utilities/JSON', 'Wordlists', 'Questionnaires', 'Callback_Suite/payloads/clnt-09-clickjacking'];

test('settings: every new project gets Settings/Configurations with the required subfolders', async () => {
  for (const d of SETTINGS_DIRS) assert.ok(fs.statSync(path.join(settingsDir(P), ...d.split('/'))).isDirectory(), d);
  // no template yet, so no files were invented
  assert.deepEqual(fs.readdirSync(path.join(settingsDir(P), 'Mouse_Tool')).sort(), ['javascript', 'python']);
  assert.deepEqual(fs.readdirSync(path.join(settingsDir(P), 'Utilities', 'JSON')), []);
  const pf = (await get(`/api/projects/${P}/preflight`)).json();
  const c = pf.checks.find((x) => x.id === 'settings');
  assert.equal(c.status, 'warn');
  assert.match(c.detail, /mouse_tool\.json and clipboard_interceptor\.py/);
  assert.equal(pf.ready, true);
});

test('settings: files come from Base_Image/Settings, are never written by the tool, and never overwritten', async () => {
  const tpl = path.join(dirs.base, 'Settings', 'Configurations');
  mkfile(tpl, 'Mouse_Tool', 'mouse_tool.json');
  mkfile(tpl, 'Mouse_Tool', 'python', 'clipboard_interceptor.py');
  mkfile(tpl, 'Mouse_Tool', 'javascript', 'listener.js');
  mkfile(tpl, 'Utilities', 'JSON', 'injection_router.json');
  for (const n of ['shuttle_gen', 'rebuild_tag', 'tag_combine', 'orchestrator', 'server_side_orchestrator']) mkfile(tpl, 'Utilities', 'python', `${n}.py`);
  for (const n of ['server_side_inj', 'waf_items', 'server_side_waf_map']) mkfile(tpl, 'Utilities', 'JSON', `${n}.json`);
  for (const n of ['a', 'b', 'c']) mkfile(tpl, 'Wordlists', `${n}.json`);
  mkfile(tpl, 'Questionnaires', 'questionnaire_router.json');
  mkfile(tpl, 'Questionnaires', 'questionnaire_inventory.json');
  mkfile(tpl, 'Callback_Suite', 'server.py');
  mkfile(tpl, 'Callback_Suite', 'index.html');
  for (const n of ['clnt-04-url-redirect', 'clnt-06-resource-manip', 'clnt-07-cors', 'clnt-13-cssi']) mkfile(tpl, 'Callback_Suite', 'payloads', `${n}.html`);
  mkfile(tpl, 'Callback_Suite', 'payloads', 'clnt-09-clickjacking', 'index.html');
  mkfile(tpl, 'Intruder_Loader', 'intruder_loader_extension.py');
  mkfile(tpl, 'Intruder_Loader', 'burp_launch.json');
  try {
    assert.equal((await post('/api/projects', { name: 'With Settings' })).status, 201);
    const s = settingsDir('With_Settings');
    for (const f of ['Mouse_Tool/mouse_tool.json', 'Mouse_Tool/python/clipboard_interceptor.py', 'Mouse_Tool/javascript/listener.js', 'Utilities/JSON/injection_router.json', 'Wordlists/c.json']) {
      assert.equal(fs.readFileSync(path.join(s, ...f.split('/')), 'utf8'), 'x', f);
    }
    const c = (await get('/api/projects/With_Settings/preflight')).json().checks.find((x) => x.id === 'settings');
    assert.equal(c.status, 'ok');
    assert.match(c.detail, /1 Python, 1 JavaScript.*3 JSON/);

    // the operator edits a copy; a later look must not overwrite it
    fs.writeFileSync(path.join(s, 'Mouse_Tool', 'mouse_tool.json'), '{"edited":true}');
    await get('/api/projects/With_Settings/preflight');
    assert.equal(fs.readFileSync(path.join(s, 'Mouse_Tool', 'mouse_tool.json'), 'utf8'), '{"edited":true}');

    // older project without Settings: folders and template files appear on first look
    assert.ok(!fs.existsSync(path.join(dirs.projects, P, 'Settings', 'Configurations', 'Mouse_Tool', 'mouse_tool.json')));
    fs.rmSync(path.join(dirs.projects, P, 'Settings'), { recursive: true });
    assert.equal((await get(`/api/projects/${P}/preflight`)).status, 200);
    assert.ok(fs.existsSync(path.join(settingsDir(P), 'Mouse_Tool', 'mouse_tool.json')));
    assert.ok(fs.statSync(path.join(settingsDir(P), 'Wordlists')).isDirectory());
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

/* ------------------------------ Mouse_Tool paths ---------------------- */

test('mouse: resolves a WSTG ID to absolute folders inside the project, from the static mouse_tool.json', async () => {
  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Mouse_Tool');
  fs.mkdirSync(tpl, { recursive: true });
  fs.copyFileSync(path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Mouse_Tool', 'mouse_tool.json'), path.join(tpl, 'mouse_tool.json'));
  try {
    assert.equal((await post('/api/projects', { name: 'Mouse One' })).status, 201);
    const list = (await get('/api/projects/Mouse_One/mouse')).json().targets;
    assert.deepEqual(list.map((t) => t.wstg_id), ['WSTG-CLNT-01', 'WSTG-CLNT-02', 'WSTG-CLNT-03', 'WSTG-INJT-01', 'WSTG-INJT-02', 'WSTG-INJT-08']);
    const r = (await get('/api/projects/Mouse_One/mouse/WSTG-INJT-08')).json();
    const repo = path.join(dirs.projects, 'Mouse_One', 'WSTG_Repository');
    assert.equal(r.Input_Folder, path.join(repo, '07_Injection', 'WSTG-INJT-08', 'Inputs', 'Data'));
    assert.equal(r.Output_Folder, r.Input_Folder);
    assert.equal(r.XML_Path, path.join(repo, '07_Injection', 'WSTG-INJT-08', 'Inputs', 'XML'));
    assert.equal((await get('/api/projects/Mouse_One/mouse/WSTG-INJT-05')).status, 404); // server side: not a mouse target
    assert.equal((await get('/api/projects/Mouse_One/mouse/..%2Fetc')).status, 400);

    // a path that tries to leave the project is refused, and nothing is created
    const f = path.join(dirs.projects, 'Mouse_One', 'Settings', 'Configurations', 'Mouse_Tool', 'mouse_tool.json');
    fs.writeFileSync(f, JSON.stringify({ Targets: { 'WSTG-INJT-08': { Input_Folder: '../../../evil', Output_Folder: 'a/b', XML_Path: 'a/c' }, 'WSTG-INJT-01': { Input_Folder: 'C:\\x', Output_Folder: 'a', XML_Path: 'b' } } }));
    assert.equal((await get('/api/projects/Mouse_One/mouse/WSTG-INJT-08')).status >= 400, true);
    assert.equal((await get('/api/projects/Mouse_One/mouse/WSTG-INJT-01')).status >= 400, true);
    fs.writeFileSync(f, '{ nope');
    assert.equal((await get('/api/projects/Mouse_One/mouse')).status >= 400, true);
    fs.rmSync(f);
    assert.equal((await get('/api/projects/Mouse_One/mouse')).status, 404);
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

test('mouse: master file path, the one-XML rule, and the active selection file', async () => {
  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Mouse_Tool');
  fs.mkdirSync(tpl, { recursive: true });
  fs.copyFileSync(path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Mouse_Tool', 'mouse_tool.json'), path.join(tpl, 'mouse_tool.json'));
  try {
    assert.equal((await post('/api/projects', { name: 'Mouse Two' })).status, 201);
    const base = '/api/projects/Mouse_Two/mouse';
    const r = (await get(`${base}/WSTG-CLNT-02`)).json();
    const repo = path.join(dirs.projects, 'Mouse_Two', 'WSTG_Repository');
    assert.equal(r.Master_Folder, path.join(repo, '11_Client-side', 'WSTG-CLNT-02', 'Outputs', 'test_outputs'));
    assert.equal(r.Master_File, path.join(r.Master_Folder, 'WSTG-CLNT-02_association.json'));

    // XML: none, one, several
    assert.match(r.Xml.error, /No Burp XML/);
    fs.mkdirSync(r.XML_Path, { recursive: true });
    fs.writeFileSync(path.join(r.XML_Path, 'walk.xml'), '<items/>');
    const one = (await get(`${base}/WSTG-CLNT-02`)).json().Xml;
    assert.equal(one.error, null);
    assert.equal(one.file, path.join(r.XML_Path, 'walk.xml'));
    fs.writeFileSync(path.join(r.XML_Path, 'second.XML'), '<items/>');
    const two = (await get(`${base}/WSTG-CLNT-02`)).json().Xml;
    assert.equal(two.file, null);
    assert.match(two.error, /More than one/);

    // active selection
    assert.equal((await get(`${base}/active`)).json().wstg_id, null);
    assert.equal((await raw('PUT', `${base}/active`, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ wstg_id: 'WSTG-INJT-02' }) })).status, 200);
    assert.equal((await get(`${base}/active`)).json().wstg_id, 'WSTG-INJT-02');
    const f = path.join(dirs.projects, 'Mouse_Two', 'Settings', 'Configurations', 'Mouse_Tool', 'active_target.json');
    assert.deepEqual(JSON.parse(fs.readFileSync(f, 'utf8')), { wstg_id: 'WSTG-INJT-02' });
    assert.equal(fs.readdirSync(path.dirname(f)).filter((n) => n.endsWith('.tmp')).length, 0);
    for (const bad of ['WSTG-INJT-05', '../x', 'WSTG-CLNT-99', 5, null]) {
      const res = await raw('PUT', `${base}/active`, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ wstg_id: bad }) });
      assert.ok(res.status === 400 || res.status === 404, String(bad));
    }
    assert.equal((await get(`${base}/active`)).json().wstg_id, 'WSTG-INJT-02'); // unchanged by the bad ones
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

/* ------------------------------ Orchestrator pipeline (script 1/2/3) ---- */

test('orchestrator: drives shuttle_gen, rebuild_tag and tag_combine across a WSTG item end to end', async (t) => {
  const { execFileSync } = require('node:child_process');
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'python');
  if (!fs.existsSync(path.join(scriptsSrc, 'orchestrator.py'))) { t.skip('orchestrator.py not present'); return; }

  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Mouse_Tool');
  fs.mkdirSync(tpl, { recursive: true });
  fs.copyFileSync(path.join(scriptsSrc, '..', '..', 'Mouse_Tool', 'mouse_tool.json'), path.join(tpl, 'mouse_tool.json'));
  try {
    assert.equal((await post('/api/projects', { name: 'Orch One' })).status, 201);
    const projectDir = path.join(dirs.projects, 'Orch_One');
    const repo = path.join(projectDir, 'WSTG_Repository');
    const inDir = path.join(repo, '07_Injection', 'WSTG-INJT-08', 'Inputs', 'Data');
    const outDir = path.join(repo, '07_Injection', 'WSTG-INJT-08', 'Outputs', 'test_outputs');
    fs.mkdirSync(inDir, { recursive: true });
    fs.mkdirSync(outDir, { recursive: true });

    const inputFile = path.join(inDir, 'input_Req_1.json');
    fs.writeFileSync(inputFile, JSON.stringify({
      element: 'div#srp-search-box > div > div > form > a#submitBtn',
      domAttributes: [
        { name: 'id', value: 'submitBtn' },
        { name: 'href', value: 'https://example.com/search?query=rested' },
      ],
    }));
    fs.writeFileSync(path.join(outDir, 'WSTG-INJT-08_association.json'), JSON.stringify({
      Associations: [{ Xml_index: 7, Input: { Input: 1, File: inputFile }, Output: null }],
    }));
    fs.mkdirSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON'), { recursive: true });
    fs.writeFileSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON', 'injection_router.json'), JSON.stringify({
      Client_Side: [{ category: '07_Injection', wstg_id: 'WSTG-INJT-08', name: 'SSI Injection' }],
    }));

    const out = execFileSync(process.env.PYTHON || 'python3', [
      path.join(scriptsSrc, 'orchestrator.py'),
      '--project-root', projectDir,
      '--scripts-dir', scriptsSrc,
      '--split', 'rested',
      '--cap-percent', '10',
    ], { encoding: 'utf8' });
    assert.match(out, /TOTAL: 1 job\(s\), 1 tagged file\(s\) written/);

    assert.ok(fs.statSync(path.join(outDir, '7_wordlist_SFCi1.txt')).size > 0);
    assert.ok(fs.statSync(path.join(outDir, '7_tagsplit_SFCi1.json')).size > 0);
    const tagged = fs.readFileSync(path.join(outDir, '7_tagged_SFCi1.txt'), 'utf8').trim().split('\n');
    assert.ok(tagged.length > 0);
    for (const line of tagged) assert.match(line, /^<a id="submitBtn" href="https:\/\/example\.com\/search\?query=.*rested"[^>]*><\/a>$/);
    const split = JSON.parse(fs.readFileSync(path.join(outDir, '7_tagsplit_SFCi1.json'), 'utf8'));
    assert.ok(split.tag_start.includes('id="submitBtn"'));
    // every tagged line is exactly tag_start + (a payload from the wordlist) + tag_end
    const wordlist = fs.readFileSync(path.join(outDir, '7_wordlist_SFCi1.txt'), 'utf8').trim().split('\n');
    assert.equal(tagged.length, wordlist.length);
    for (let i = 0; i < tagged.length; i++) assert.equal(tagged[i], split.tag_start + wordlist[i] + split.tag_end);
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

test('orchestrator: a missing association file is skipped, not a crash; no tagged file without one', async () => {
  const { execFileSync } = require('node:child_process');
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'python');
  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Mouse_Tool');
  fs.mkdirSync(tpl, { recursive: true });
  fs.copyFileSync(path.join(scriptsSrc, '..', '..', 'Mouse_Tool', 'mouse_tool.json'), path.join(tpl, 'mouse_tool.json'));
  try {
    assert.equal((await post('/api/projects', { name: 'Orch Two' })).status, 201);
    const projectDir = path.join(dirs.projects, 'Orch_Two');
    fs.mkdirSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON'), { recursive: true });
    fs.writeFileSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON', 'injection_router.json'), JSON.stringify({
      Client_Side: [{ category: '07_Injection', wstg_id: 'WSTG-INJT-08', name: 'SSI Injection' }],
    }));
    let threw = false;
    try {
      execFileSync(process.env.PYTHON || 'python3', [
        path.join(scriptsSrc, 'orchestrator.py'),
        '--project-root', projectDir,
        '--scripts-dir', scriptsSrc,
        '--split', 'anything',
      ], { encoding: 'utf8' });
    } catch (e) { threw = true; assert.match(e.stderr || e.stdout || '', /nothing to do/); }
    assert.equal(threw, true); // no association file anywhere yet -> clean non-zero exit, not a traceback
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

/* ------------------------------ Mouse_Tool listener process ------------ */

test('mouse listener: start/stop/status, and a clean 404/409 when it cannot run', async () => {
  // Fresh project, no Settings template -> clipboard_interceptor.py is not there yet.
  assert.equal((await post('/api/projects', { name: 'Proc One' })).status, 201);
  const base = '/api/projects/Proc_One/mouse/listener';
  assert.equal((await get(`${base}/status`)).json().running, false);
  const startRes = await raw('POST', `${base}/start`, { headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(startRes.status, 404);
  assert.match(startRes.json().error, /clipboard_interceptor\.py is not in this project/);
  assert.equal((await raw('POST', `${base}/stop`, { headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 409);

  // With the real template scripts in place, start actually spawns python; pynput is very
  // unlikely to be installed in a clean test environment, so the process is expected to exit
  // almost immediately with a message - the point here is the server's own bookkeeping.
  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Mouse_Tool');
  fs.mkdirSync(path.join(tpl, 'python'), { recursive: true });
  fs.mkdirSync(path.join(tpl, 'javascript'), { recursive: true });
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Mouse_Tool');
  fs.copyFileSync(path.join(scriptsSrc, 'mouse_tool.json'), path.join(tpl, 'mouse_tool.json'));
  fs.copyFileSync(path.join(scriptsSrc, 'python', 'clipboard_interceptor.py'), path.join(tpl, 'python', 'clipboard_interceptor.py'));
  fs.copyFileSync(path.join(scriptsSrc, 'javascript', 'listener.js'), path.join(tpl, 'javascript', 'listener.js'));
  try {
    assert.equal((await post('/api/projects', { name: 'Proc Two' })).status, 201);
    const base2 = '/api/projects/Proc_Two/mouse/listener';
    const start2 = await raw('POST', `${base2}/start`, { headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(start2.status, 200);
    assert.equal(typeof start2.json().pid, 'number');
    const dup = await raw('POST', `${base2}/start`, { headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(dup.status, 409); // already running (or just exited - either way, not a silent duplicate)
    await new Promise((r) => setTimeout(r, 400));
    const status = (await get(`${base2}/status`)).json();
    assert.equal(typeof status.running, 'boolean');
    // stop is harmless whether the process is still up or already exited on its own
    await raw('POST', `${base2}/stop`, { headers: { 'Content-Type': 'application/json' }, body: '{}' }).catch(() => {});
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

/* ------------------------------ Orchestrator run endpoint -------------- */

test('orchestrator run endpoint: validates input and reports a clean result over HTTP', async () => {
  const base = '/api/projects/Orch_One/mouse/orchestrator/run';
  // Orch_One was created by the earlier orchestrator test and has everything wired up.
  const bad1 = await raw('POST', base, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
  assert.equal(bad1.status, 400);
  assert.match(bad1.json().error, /split string is required/);

  const bad2 = await raw('POST', base, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ split: 'x', capPercent: 500 }) });
  assert.equal(bad2.status, 400);

  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Utilities', 'python');
  fs.mkdirSync(tpl, { recursive: true });
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'python');
  for (const n of ['shuttle_gen.py', 'rebuild_tag.py', 'tag_combine.py', 'orchestrator.py']) {
    fs.copyFileSync(path.join(scriptsSrc, n), path.join(tpl, n));
  }
  const mouseTpl = path.join(dirs.base, 'Settings', 'Configurations', 'Mouse_Tool');
  fs.mkdirSync(mouseTpl, { recursive: true });
  fs.copyFileSync(path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Mouse_Tool', 'mouse_tool.json'), path.join(mouseTpl, 'mouse_tool.json'));
  try {
    // the Node-level settings copy only backfills what's missing project-side; Orch_One already
    // has its own copies from the earlier test, so re-create a project to pick up the real scripts
    assert.equal((await post('/api/projects', { name: 'Orch Three' })).status, 201);
    const projectDir = path.join(dirs.projects, 'Orch_Three');
    const repo = path.join(projectDir, 'WSTG_Repository');
    const inDir = path.join(repo, '07_Injection', 'WSTG-INJT-08', 'Inputs', 'Data');
    const outDir = path.join(repo, '07_Injection', 'WSTG-INJT-08', 'Outputs', 'test_outputs');
    fs.mkdirSync(inDir, { recursive: true });
    fs.mkdirSync(outDir, { recursive: true });
    const inputFile = path.join(inDir, 'input_Req_1.json');
    fs.writeFileSync(inputFile, JSON.stringify({
      element: 'div > a#submitBtn',
      domAttributes: [{ name: 'id', value: 'submitBtn' }, { name: 'href', value: 'https://example.com/search?q=rested' }],
    }));
    fs.writeFileSync(path.join(outDir, 'WSTG-INJT-08_association.json'), JSON.stringify({
      Associations: [{ Xml_index: 1, Input: { Input: 1, File: inputFile }, Output: null }],
    }));
    fs.mkdirSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON'), { recursive: true });
    fs.writeFileSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON', 'injection_router.json'), JSON.stringify({
      Client_Side: [{ category: '07_Injection', wstg_id: 'WSTG-INJT-08', name: 'SSI Injection' }],
    }));

    const run = await raw('POST', '/api/projects/Orch_Three/mouse/orchestrator/run', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ split: 'rested', capPercent: 10 }),
    });
    assert.equal(run.status, 200);
    const body = run.json();
    assert.equal(body.ok, true);
    assert.match(body.stdout, /TOTAL: 1 job\(s\), 1 tagged file\(s\) written/);
    assert.ok(fs.existsSync(path.join(outDir, '1_tagged_SFCi1.txt')));
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

/* ------------------------------ Server-side wordlist pipeline ---------- */

test('server_side_orchestrator.py: joins router + waf map + server_side_inj by WSTG ID, skips an item with no folder on disk cleanly, writes one wordlist per matched item', async () => {
  const { execFileSync } = require('node:child_process');
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'python');
  const jsonSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'JSON');

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssorch-'));
  try {
    const settingsJson = path.join(root, 'Settings', 'Configurations', 'Utilities', 'JSON');
    fs.mkdirSync(settingsJson, { recursive: true });
    for (const n of ['server_side_inj.json', 'waf_items.json', 'server_side_waf_map.json']) {
      fs.copyFileSync(path.join(jsonSrc, n), path.join(settingsJson, n));
    }
    // Router has one ID with a folder on disk (WSTG-INJT-08) and one without (WSTG-INJT-19,
    // SSRF - in the router/waf-map/cfg now that the 2026-11-08 fix corrected its spelling, but
    // its project folder is deliberately not created below) - both are in the project's own
    // injection_router.json, which this tool never writes itself.
    fs.writeFileSync(path.join(settingsJson, 'injection_router.json'), JSON.stringify({
      Server_Side: [
        { category: '07_Injection', wstg_id: 'WSTG-INJT-08', name: 'SSI Injection' },
        { category: '07_Injection', wstg_id: 'WSTG-INJT-19', name: 'SSRF' },
      ],
    }));
    const outDir = path.join(root, 'WSTG_Repository', '07_Injection', 'WSTG-INJT-08', 'Outputs', 'test_outputs');
    fs.mkdirSync(outDir, { recursive: true });
    // WSTG-INJT-19's folder deliberately does not exist, to also exercise the preflight skip path.

    const out = execFileSync(process.env.PYTHON || 'python3', [
      path.join(scriptsSrc, 'server_side_orchestrator.py'),
      '--project-root', root,
    ], { encoding: 'utf8' });

    assert.match(out, /WSTG-INJT-19 .*folder missing/);
    assert.match(out, /Wrote 1 wordlist\(s\)\./);
    const wlFile = path.join(outDir, 'WSTG-INJT-08_WL.txt');
    assert.ok(fs.statSync(wlFile).size > 0);
    const lines = fs.readFileSync(wlFile, 'utf8').trim().split('\n');
    assert.ok(lines.length > 0);
    assert.ok(lines.includes('id')); // one of the plain base commands, unmodified
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('server_side_orchestrator.py: nothing in router/map/cfg at once -> clean non-zero exit, not a traceback', async () => {
  const { execFileSync } = require('node:child_process');
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'python');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssorch-empty-'));
  try {
    const settingsJson = path.join(root, 'Settings', 'Configurations', 'Utilities', 'JSON');
    fs.mkdirSync(settingsJson, { recursive: true });
    fs.writeFileSync(path.join(settingsJson, 'injection_router.json'), JSON.stringify({ Server_Side: [] }));
    fs.writeFileSync(path.join(settingsJson, 'server_side_inj.json'), JSON.stringify({}));
    fs.writeFileSync(path.join(settingsJson, 'waf_items.json'), JSON.stringify({}));
    fs.writeFileSync(path.join(settingsJson, 'server_side_waf_map.json'), JSON.stringify({}));
    let threw = false;
    try {
      execFileSync(process.env.PYTHON || 'python3', [
        path.join(scriptsSrc, 'server_side_orchestrator.py'),
        '--project-root', root,
      ], { encoding: 'utf8' });
    } catch (e) { threw = true; assert.match(e.stderr || e.stdout || '', /nothing to do/); }
    assert.equal(threw, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('server-side run endpoint: clean 404 when the script is not in the project yet, 200 with a real run once it is', async () => {
  assert.equal((await post('/api/projects', { name: 'SS One' })).status, 201);
  const missing = await raw('POST', '/api/projects/SS_One/mouse/server-side/run', { headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(missing.status, 404);
  assert.match(missing.json().error, /server_side_orchestrator\.py is not in this project/);

  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Utilities');
  fs.mkdirSync(path.join(tpl, 'python'), { recursive: true });
  fs.mkdirSync(path.join(tpl, 'JSON'), { recursive: true });
  const scriptsSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'python');
  const jsonSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Utilities', 'JSON');
  fs.copyFileSync(path.join(scriptsSrc, 'server_side_orchestrator.py'), path.join(tpl, 'python', 'server_side_orchestrator.py'));
  for (const n of ['server_side_inj.json', 'waf_items.json', 'server_side_waf_map.json']) {
    fs.copyFileSync(path.join(jsonSrc, n), path.join(tpl, 'JSON', n));
  }
  try {
    assert.equal((await post('/api/projects', { name: 'SS Two' })).status, 201);
    const projectDir = path.join(dirs.projects, 'SS_Two');
    fs.writeFileSync(path.join(projectDir, 'Settings', 'Configurations', 'Utilities', 'JSON', 'injection_router.json'), JSON.stringify({
      Server_Side: [{ category: '07_Injection', wstg_id: 'WSTG-INJT-08', name: 'SSI Injection' }],
    }));
    const outDir = path.join(projectDir, 'WSTG_Repository', '07_Injection', 'WSTG-INJT-08', 'Outputs', 'test_outputs');
    fs.mkdirSync(outDir, { recursive: true });

    const run = await raw('POST', '/api/projects/SS_Two/mouse/server-side/run', { headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(run.status, 200);
    const body = run.json();
    assert.equal(body.ok, true);
    assert.match(body.stdout, /Wrote 1 wordlist\(s\)\./);
    assert.ok(fs.statSync(path.join(outDir, 'WSTG-INJT-08_WL.txt')).size > 0);
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

/* ------------------------------ Questionnaires -------------------------- */

const qTpl = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Questionnaires');

function installQuestionnaireFiles(projectDir) {
  const dir = path.join(projectDir, 'Settings', 'Configurations', 'Questionnaires');
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(path.join(qTpl, 'questionnaire_router.json'), path.join(dir, 'questionnaire_router.json'));
  fs.copyFileSync(path.join(qTpl, 'questionnaire_inventory.json'), path.join(dir, 'questionnaire_inventory.json'));
}

test('questionnaires list: joins router + inventory (incl. the two WSTG-IDNT-02 entries), no warnings over the real data', async () => {
  assert.equal((await post('/api/projects', { name: 'Quest One' })).status, 201);
  installQuestionnaireFiles(path.join(dirs.projects, 'Quest_One'));

  const r = await get('/api/projects/Quest_One/questionnaires');
  assert.equal(r.status, 200);
  const body = r.json();
  assert.equal(body.warnings.length, 0);
  assert.equal(body.items.length, 12);
  const idnt = body.items.filter((it) => it.wstg_id === 'WSTG-IDNT-02');
  assert.equal(idnt.length, 2);
  assert.deepEqual(idnt.map((it) => it.key), ['idnt02_q1', 'idnt02_q2']);
  const busl08 = body.items.find((it) => it.key === 'busl_08_questionnaire');
  assert.equal(busl08.question_count, 11);
  assert.equal(busl08.answered, false);
});

test('questionnaires item: full question detail, 404 for an unknown key', async () => {
  const detail = await get('/api/projects/Quest_One/questionnaires/weak_lockout');
  assert.equal(detail.status, 200);
  const item = detail.json();
  assert.equal(item.wstg_id, 'WSTG-ATHN-03');
  assert.equal(item.questions.length, 3);
  assert.equal(item.answers, null);

  const missing = await get('/api/projects/Quest_One/questionnaires/not_a_real_key');
  assert.equal(missing.status, 404);
});

test('questionnaires save: writes JSON + Markdown under the real WSTG folder (found by scan, not a hardcoded map), round-trips on GET', async () => {
  // WSTG-BUSL-08 is in the shared Base_Image fixture, so every project already has that folder.
  const outDir = path.join(dirs.projects, 'Quest_One', 'WSTG_Repository', '10_Business_Logic', 'WSTG-BUSL-08', 'Outputs', 'test_outputs');
  const answers = {
    'BUSL08-01': { value: 'https://example.com' },
    'BUSL08-02': { value: 'A login portal' },
    'BUSL08-04': { value: 'Y' },
    'BUSL08-04__fu0': { value: 'admin' },
    'BUSL08-05': { value: 'N' },
  };
  const save = await raw('PUT', '/api/projects/Quest_One/questionnaires/busl_08_questionnaire/answers', {
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ answers }),
  });
  assert.equal(save.status, 200);
  const saved = save.json();
  assert.ok(fs.existsSync(saved.json));
  assert.ok(fs.existsSync(saved.md));

  const jsonBody = JSON.parse(fs.readFileSync(path.join(outDir, 'busl_08_questionnaire_answers.json'), 'utf8'));
  assert.equal(jsonBody.wstg_id, 'WSTG-BUSL-08');
  assert.deepEqual(jsonBody.answers['BUSL08-01'], { value: 'https://example.com' });

  const md = fs.readFileSync(path.join(outDir, 'busl_08_questionnaire_answers.md'), 'utf8');
  assert.match(md, /# WSTG-BUSL-08/);
  assert.match(md, /\*\*\[BUSL08-04\]\*\*[^\n]*\n→ \*\*Y\*\*\n {2}- \*What role \/ privilege level\?\* → admin/);
  assert.match(md, /\*\*\[BUSL08-03\]\*\*[^\n]*\n→ _\(no answer\)_/); // optional, never answered

  const again = (await get('/api/projects/Quest_One/questionnaires')).json();
  assert.equal(again.items.find((it) => it.key === 'busl_08_questionnaire').answered, true);
  const detail = (await get('/api/projects/Quest_One/questionnaires/busl_08_questionnaire')).json();
  assert.deepEqual(detail.answers['BUSL08-05'], { value: 'N' });
});

test('questionnaires save: a condition left unmet is recorded as skipped in the Markdown, not silently dropped', async () => {
  const repo = path.join(dirs.projects, 'Quest_One', 'WSTG_Repository');
  const outDir = path.join(repo, '04_Authentication', 'WSTG-ATHN-03', 'Outputs', 'test_outputs');
  fs.mkdirSync(outDir, { recursive: true });

  const save = await raw('PUT', '/api/projects/Quest_One/questionnaires/weak_lockout/answers', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ answers: { 'ATHN03-Item_1': { value: 'N' }, 'ATHN03-Item_2': { value: 'N' } } }),
  });
  assert.equal(save.status, 200);
  const md = fs.readFileSync(path.join(outDir, 'weak_lockout_answers.md'), 'utf8');
  assert.match(md, /\*\*\[ATHN03-Item_3\]\*\*[^\n]*\n→ _skipped \(condition "ATHN03-Item_1 == Y" not met\)_/);
});

test('questionnaires save: a clean 404 when the WSTG folder cannot be found in the project yet', async () => {
  // WSTG-ATHN-07 has no folder anywhere in Quest_One's WSTG_Repository.
  const save = await raw('PUT', '/api/projects/Quest_One/questionnaires/ATHN_07/answers', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ answers: { Q1_entropy: { value: 'Y' } } }),
  });
  assert.equal(save.status, 404);
  assert.match(save.json().error, /Could not find a WSTG-ATHN-07 folder/);
});

test('questionnaires save: rejects a non-object answers body', async () => {
  const save = await raw('PUT', '/api/projects/Quest_One/questionnaires/weak_lockout/answers', {
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ answers: ['not an object'] }),
  });
  assert.equal(save.status, 400);
});

/* ------------------------------ Callback Suite -------------------------- */

const { matchWstgId, parseLog } = require('../lib/callbackProc');

test('callbackProc.matchWstgId / parseLog: the path convention maps straight to a WSTG ID, unmatched traffic is ignored', () => {
  assert.equal(matchWstgId('/payloads/clnt-04-url-redirect.html'), 'WSTG-CLNT-04');
  assert.equal(matchWstgId('/payloads/clnt-09-clickjacking/cj_foo_123.html'), 'WSTG-CLNT-09');
  assert.equal(matchWstgId('/api/hits'), null);
  assert.equal(matchWstgId('/'), null);

  const log = [
    '[09:00:00]  127.0.0.1           GET      200  /',
    '[09:00:01]  10.1.1.5            GET      200  /payloads/clnt-13-cssi.html',
    '[09:00:02]  10.1.1.5            POST     200  /api/generate-cj  »  generated → cj_x_1.html',
    '[09:00:03]  10.1.1.6            GET      200  /payloads/clnt-09-clickjacking/cj_x_1.html',
  ].join('\n');
  const { byId, total, matched } = parseLog(log);
  assert.equal(total, 4);
  assert.equal(matched, 2);
  assert.deepEqual([...byId.keys()].sort(), ['WSTG-CLNT-09', 'WSTG-CLNT-13']);
});

test('callback server: clean 404 before the template exists, real start/stop bookkeeping once it does', async () => {
  assert.equal((await post('/api/projects', { name: 'CB One' })).status, 201);
  const base = '/api/projects/CB_One/callback';
  assert.equal((await get(`${base}/status`)).json().running, false);
  const startMissing = await raw('POST', `${base}/start`, { headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(startMissing.status, 404);
  assert.match(startMissing.json().error, /server\.py is not in this project/);

  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Callback_Suite');
  fs.mkdirSync(tpl, { recursive: true });
  const cbSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Callback_Suite');
  fs.cpSync(cbSrc, tpl, { recursive: true });
  try {
    assert.equal((await post('/api/projects', { name: 'CB Two' })).status, 201);
    const base2 = '/api/projects/CB_Two/callback';
    const freePort = await new Promise((resolve) => {
      const srv = require('node:net').createServer();
      srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
    });
    const start = await raw('POST', `${base2}/start`, { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: freePort, host: '127.0.0.1' }) });
    assert.equal(start.status, 200);
    assert.equal(typeof start.json().pid, 'number');
    assert.equal(start.json().port, freePort);

    const dup = await raw('POST', `${base2}/start`, { headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(dup.status, 409);

    // Give the real python process a moment to bind, then actually hit a payload URL on it.
    await new Promise((r) => setTimeout(r, 500));
    const hit = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: freePort, path: '/payloads/clnt-04-url-redirect.html?redirect=https://evil.example' }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }).on('error', reject);
    });
    assert.equal(hit, 200);
    // The directory-index fix: the CLNT-09 generator's folder itself must serve its index.html.
    const cjHit = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: freePort, path: '/payloads/clnt-09-clickjacking/' }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }).on('error', reject);
    });
    assert.equal(cjHit, 200);

    const status = (await get(`${base2}/status`)).json();
    assert.equal(status.running, true);
    assert.equal(status.port, freePort);

    assert.equal((await raw('POST', `${base2}/stop`, { headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 200);
    assert.equal((await get(`${base2}/status`)).json().running, false);
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

test('callback export: writes callback_hits.json + .md into the matching WSTG-CLNT folder, skips a hit with no folder yet', async () => {
  const tpl = path.join(dirs.base, 'Settings', 'Configurations', 'Callback_Suite');
  fs.mkdirSync(tpl, { recursive: true });
  const cbSrc = path.join(__dirname, '..', 'Base_Image', 'Settings', 'Configurations', 'Callback_Suite');
  fs.cpSync(cbSrc, tpl, { recursive: true });
  try {
    assert.equal((await post('/api/projects', { name: 'CB Three' })).status, 201);
    const projectDir = path.join(dirs.projects, 'CB_Three');
    const outDir = path.join(projectDir, 'WSTG_Repository', '09_Client_Side', 'WSTG-CLNT-04', 'Outputs', 'test_outputs');
    fs.mkdirSync(outDir, { recursive: true });

    const logFile = path.join(projectDir, 'Settings', 'Configurations', 'Callback_Suite', 'server.log');
    fs.writeFileSync(logFile, [
      '[10:00:00]  198.51.100.9        GET      200  /payloads/clnt-04-url-redirect.html',
      '[10:00:05]  198.51.100.9        GET      200  /payloads/clnt-06-resource-manip.html',
    ].join('\n') + '\n');

    const exp = await raw('POST', '/api/projects/CB_Three/callback/export', { headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(exp.status, 200);
    const body = exp.json();
    assert.equal(body.written.length, 1);
    assert.equal(body.written[0].wstg_id, 'WSTG-CLNT-04');
    assert.equal(body.skipped.length, 1);
    assert.equal(body.skipped[0].wstg_id, 'WSTG-CLNT-06');
    assert.match(body.skipped[0].reason, /Could not find a WSTG-CLNT-06 folder/);

    const jsonBody = JSON.parse(fs.readFileSync(path.join(outDir, 'callback_hits.json'), 'utf8'));
    assert.equal(jsonBody.total_hits, 1);
    assert.equal(jsonBody.hits[0].ip, '198.51.100.9');
    const md = fs.readFileSync(path.join(outDir, 'callback_hits.md'), 'utf8');
    assert.match(md, /# WSTG-CLNT-04 — Callback Suite hits/);
    assert.match(md, /198\.51\.100\.9/);
  } finally {
    fs.rmSync(path.join(dirs.base, 'Settings'), { recursive: true, force: true });
  }
});

test('callback export: no server.log yet is a clean empty result, not an error', async () => {
  assert.equal((await post('/api/projects', { name: 'CB Four' })).status, 201);
  const exp = await raw('POST', '/api/projects/CB_Four/callback/export', { headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(exp.status, 200);
  assert.deepEqual(exp.json(), { written: [], skipped: [], total_lines: 0, matched_lines: 0 });
});

test('threat-model: empty list before Threat_Model.json exists, real list + request after', async () => {
  assert.equal((await post('/api/projects', { name: 'TM One' })).status, 201);
  const dir = testDir('TM_One', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir, ...s.split('/')), { recursive: true });

  const before = await get('/api/projects/TM_One/tests/WSTG-INJT-04/threat-model');
  assert.equal(before.status, 200);
  assert.deepEqual(before.json(), { generated_at: null, model: null, items: [] });

  // A tiny real Burp XML with two plain-text (non-base64) requests, so getRequest has
  // something real to resolve by burp_index.
  const xmlFile = path.join(dir, 'Inputs/XML/sample.xml');
  fs.writeFileSync(xmlFile, `<?xml version="1.0"?><items>
    <item><url>https://example.com/a?x=1</url><request base64="false">GET /a?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n</request><status>200</status></item>
    <item><url>https://example.com/b?y=2</url><request base64="false">GET /b?y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n</request><status>200</status></item>
  </items>`);

  const outDir = path.join(dir, 'Outputs/test_outputs');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'Threat_Model.json'), JSON.stringify({
    wstg_id: 'WSTG-INJT-04', category: '07_Injection', generated_at: '2026-01-01T00:00:00Z', model: 'qwen2.5:7b-instruct',
    items: [
      { endpoint: { method: 'GET', path: 'https://example.com/a?x=1', xml_index: 1, burp_index: 0 }, xml_file: xmlFile,
        best_match: 'x', ranked_parameters: [{ parameter: 'x', rank: 1, confidence: 'high', reason: 'exact name match' }] },
      { endpoint: { method: 'GET', path: 'https://example.com/b?y=2', xml_index: 2, burp_index: 1 }, xml_file: xmlFile,
        best_match: null, ranked_parameters: [] },
    ],
  }));

  const list = await get('/api/projects/TM_One/tests/WSTG-INJT-04/threat-model');
  assert.equal(list.status, 200);
  const body = list.json();
  assert.equal(body.model, 'qwen2.5:7b-instruct');
  assert.equal(body.items.length, 2);
  assert.deepEqual(body.items[0], { item_index: 0, xml_index: 1, method: 'GET', path: 'https://example.com/a?x=1', best_match: 'x', top_confidence: 'high', ranked_count: 1 });
  assert.deepEqual(body.items[1], { item_index: 1, xml_index: 2, method: 'GET', path: 'https://example.com/b?y=2', best_match: null, top_confidence: null, ranked_count: 0 });

  const reqRes = await get('/api/projects/TM_One/tests/WSTG-INJT-04/threat-model/0/request');
  assert.equal(reqRes.status, 200);
  const req0 = reqRes.json();
  assert.equal(req0.index, 0);
  assert.match(req0.text, /GET \/a\?x=1 HTTP\/1\.1/);
  assert.deepEqual(req0.ranking, { best_match: 'x', ranked_parameters: [{ parameter: 'x', rank: 1, confidence: 'high', reason: 'exact name match' }] });

  const missing = await get('/api/projects/TM_One/tests/WSTG-INJT-04/threat-model/9/request');
  assert.equal(missing.status, 404);
});

test('threat-model: 404 for an unknown WSTG folder, not a crash', async () => {
  assert.equal((await post('/api/projects', { name: 'TM Two' })).status, 201);
  const res = await get('/api/projects/TM_Two/tests/WSTG-INJT-99/threat-model');
  assert.equal(res.status, 404);
});

test('threat-model push: writes a base64 queue file under <IntruderQueue>/<project>/, never mixes projects, skips a truncated/missing request', async () => {
  assert.equal((await post('/api/projects', { name: 'TM Push' })).status, 201);
  const dir = testDir('TM_Push', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir, ...s.split('/')), { recursive: true });

  const xmlFile = path.join(dir, 'Inputs/XML/sample.xml');
  fs.writeFileSync(xmlFile, `<?xml version="1.0"?><items>
    <item><url>https://example.com/a?x=1</url><host>example.com</host><port>443</port><protocol>https</protocol><request base64="false">GET /a?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n</request><status>200</status></item>
  </items>`);

  const outDir = path.join(dir, 'Outputs/test_outputs');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'Threat_Model.json'), JSON.stringify({
    wstg_id: 'WSTG-INJT-04', category: '07_Injection', generated_at: '2026-01-01T00:00:00Z', model: 'qwen2.5:7b-instruct',
    items: [
      { endpoint: { method: 'GET', path: 'https://example.com/a?x=1', xml_index: 1, burp_index: 0 }, xml_file: xmlFile,
        best_match: 'x', ranked_parameters: [{ parameter: 'x', rank: 1, confidence: 'high', reason: 'exact name match' }] },
    ],
  }));

  // index 0 is real and pushable; index 9 doesn't exist, so it's skipped, not fatal to the rest.
  const res = await post('/api/projects/TM_Push/tests/WSTG-INJT-04/threat-model/push', { item_indexes: [0, 9] });
  assert.equal(res.status, 200);
  const body = res.json();
  assert.equal(body.pushed.length, 1);
  assert.equal(body.pushed[0].host, 'example.com');
  assert.equal(body.skipped.length, 1);
  assert.equal(body.skipped[0].item_index, 9);
  assert.ok(body.file);

  // The file landed under IntruderQueue/TM_Push/, not IntruderQueue/ directly or any other project.
  assert.equal(path.dirname(body.file), path.join(dirs.intruderQueue, 'TM_Push'));
  const entries = JSON.parse(fs.readFileSync(body.file, 'utf8'));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].host, 'example.com');
  assert.equal(entries[0].port, 443);
  assert.equal(entries[0].https, true);
  assert.equal(entries[0].wstg_id, 'WSTG-INJT-04');
  assert.equal(entries[0].project, 'TM_Push');
  const decoded = Buffer.from(entries[0].raw_request_b64, 'base64').toString('utf8');
  assert.match(decoded, /GET \/a\?x=1 HTTP\/1\.1/);

  // A second, unrelated project pushing never lands in the same folder.
  assert.equal((await post('/api/projects', { name: 'TM Push Two' })).status, 201);
  const dir2 = testDir('TM_Push_Two', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir2, ...s.split('/')), { recursive: true });
  const xmlFile2 = path.join(dir2, 'Inputs/XML/sample.xml');
  fs.writeFileSync(xmlFile2, `<?xml version="1.0"?><items>
    <item><url>https://other.example/b?y=2</url><host>other.example</host><port>80</port><protocol>http</protocol><request base64="false">GET /b?y=2 HTTP/1.1\r\nHost: other.example\r\n\r\n</request><status>200</status></item>
  </items>`);
  const outDir2 = path.join(dir2, 'Outputs/test_outputs');
  fs.mkdirSync(outDir2, { recursive: true });
  fs.writeFileSync(path.join(outDir2, 'Threat_Model.json'), JSON.stringify({
    wstg_id: 'WSTG-INJT-04', category: '07_Injection', generated_at: '2026-01-01T00:00:00Z', model: 'qwen2.5:7b-instruct',
    items: [{ endpoint: { method: 'GET', path: 'https://other.example/b?y=2', xml_index: 1, burp_index: 0 }, xml_file: xmlFile2, best_match: null, ranked_parameters: [] }],
  }));
  const res2 = await post('/api/projects/TM_Push_Two/tests/WSTG-INJT-04/threat-model/push', { item_indexes: [0] });
  assert.equal(res2.status, 200);
  assert.equal(path.dirname(res2.json().file), path.join(dirs.intruderQueue, 'TM_Push_Two'));

  const tmPushFiles = fs.readdirSync(path.join(dirs.intruderQueue, 'TM_Push'));
  assert.equal(tmPushFiles.length, 1); // the other project's push never landed here
});

test('threat-model push: falls back to parsing the URL when the XML has no <host>/<port>/<protocol> tags', async () => {
  assert.equal((await post('/api/projects', { name: 'TM Push NoHost' })).status, 201);
  const dir = testDir('TM_Push_NoHost', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir, ...s.split('/')), { recursive: true });

  // No <host>/<port>/<protocol> fields at all - only <url> and <request>, like a hand-built or
  // trimmed export might look.
  const xmlFile = path.join(dir, 'Inputs/XML/sample.xml');
  fs.writeFileSync(xmlFile, `<?xml version="1.0"?><items>
    <item><url>https://example.com/a?x=1</url><request base64="false">GET /a?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n</request><status>200</status></item>
  </items>`);
  const outDir = path.join(dir, 'Outputs/test_outputs');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'Threat_Model.json'), JSON.stringify({
    wstg_id: 'WSTG-INJT-04', category: '07_Injection', generated_at: '2026-01-01T00:00:00Z', model: 'qwen2.5:7b-instruct',
    items: [{ endpoint: { method: 'GET', path: 'https://example.com/a?x=1', xml_index: 1, burp_index: 0 }, xml_file: xmlFile, best_match: 'x', ranked_parameters: [] }],
  }));

  const res = await post('/api/projects/TM_Push_NoHost/tests/WSTG-INJT-04/threat-model/push', { item_indexes: [0] });
  assert.equal(res.status, 200);
  const file = res.json().file;
  const [entry] = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(entry.host, 'example.com');
  assert.equal(entry.port, 443);
  assert.equal(entry.https, true);
});

test('threat-model push: rejects an empty or malformed item_indexes body', async () => {
  assert.equal((await post('/api/projects', { name: 'TM Push Bad' })).status, 201);
  const dir = testDir('TM_Push_Bad', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir, ...s.split('/')), { recursive: true });
  assert.equal((await post('/api/projects/TM_Push_Bad/tests/WSTG-INJT-04/threat-model/push', {})).status, 400);
  assert.equal((await post('/api/projects/TM_Push_Bad/tests/WSTG-INJT-04/threat-model/push', { item_indexes: [] })).status, 400);
  assert.equal((await post('/api/projects/TM_Push_Bad/tests/WSTG-INJT-04/threat-model/push', { item_indexes: [-1] })).status, 400);
});

test('intruder-loader: config save/read round-trips, status reports queue counts, launch needs a jar path first', async () => {
  assert.equal((await post('/api/projects', { name: 'IL One' })).status, 201);

  const before = await get('/api/projects/IL_One/intruder-loader/config');
  assert.equal(before.status, 200);
  assert.equal(before.json().burpJarPath, '');

  const saved = await post('/api/projects/IL_One/intruder-loader/config', { javaBin: 'java', burpJarPath: '/opt/burp/burpsuite.jar', projectFile: '', extraArgs: ['-Xmx4g'] });
  assert.equal(saved.status, 200);
  assert.deepEqual(saved.json(), { javaBin: 'java', burpJarPath: '/opt/burp/burpsuite.jar', projectFile: '', extraArgs: ['-Xmx4g'] });

  const reread = await get('/api/projects/IL_One/intruder-loader/config');
  assert.equal(reread.json().burpJarPath, '/opt/burp/burpsuite.jar');

  const status = await get('/api/projects/IL_One/intruder-loader/status');
  assert.equal(status.status, 200);
  assert.deepEqual(status.json(), { running: false, queue: { pending: 0, sent: 0 } });

  // A jar path that doesn't actually exist still lets the launch attempt happen (this app
  // doesn't validate the jar itself - java would report that) - only a MISSING path is rejected.
  await post('/api/projects/IL_One/intruder-loader/config', { burpJarPath: '' });
  const launchNoJar = await post('/api/projects/IL_One/intruder-loader/launch', {});
  assert.equal(launchNoJar.status, 400);

  const stopNotRunning = await post('/api/projects/IL_One/intruder-loader/stop', {});
  assert.equal(stopNotRunning.status, 409);
});

test('intruder-loader: queue counts reflect pending vs. processed files for that project only', async () => {
  assert.equal((await post('/api/projects', { name: 'IL Two' })).status, 201);
  const qdir = path.join(dirs.intruderQueue, 'IL_Two');
  fs.mkdirSync(path.join(qdir, 'processed'), { recursive: true });
  fs.writeFileSync(path.join(qdir, 'a.json'), '[]');
  fs.writeFileSync(path.join(qdir, 'b.json'), '[]');
  fs.writeFileSync(path.join(qdir, 'processed', 'c.json'), '[]');

  const status = await get('/api/projects/IL_Two/intruder-loader/status');
  assert.equal(status.status, 200);
  assert.deepEqual(status.json().queue, { pending: 2, sent: 1 });
});

test('findings: empty before anything is entered, create/update/delete round-trip, supports more than one per item', async () => {
  assert.equal((await post('/api/projects', { name: 'FND One' })).status, 201);
  const dir = testDir('FND_One', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir, ...s.split('/')), { recursive: true });

  const before = await get('/api/projects/FND_One/tests/WSTG-INJT-04/findings');
  assert.equal(before.status, 200);
  assert.deepEqual(before.json(), { wstg_id: 'WSTG-INJT-04', findings: [] });

  const payload1 = {
    Risk_Matrix: { CVSS_Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', CVSS_Score: 9.8, Risk_Level: 'Critical' },
    CWE_Information: { CWE_Number: 'CWE-89', CWE_Name: 'SQL Injection', CWE_Description: 'desc', CWE_Why: 'why', CWE_Impact: 'impact' },
    Remediation: { Remediation_Statement: 'stmt', Recommendation: 'rec', Additional_recommendations: ['one', '', '  two  '] },
    Affected_URLs: { URLs: ['https://example.com/a', '', '  https://example.com/b  '] },
  };
  const created = await post('/api/projects/FND_One/tests/WSTG-INJT-04/findings', payload1);
  assert.equal(created.status, 201);
  const f1 = created.json();
  assert.ok(f1.id);
  assert.equal(f1.Risk_Matrix.CVSS_Score, 9.8);
  assert.equal(f1.Risk_Matrix.Risk_Level, 'Critical');
  // blanks dropped, surrounding whitespace trimmed
  assert.deepEqual(f1.Remediation.Additional_recommendations, ['one', 'two']);
  assert.deepEqual(f1.Affected_URLs.URLs, ['https://example.com/a', 'https://example.com/b']);
  assert.equal(f1.created_at, f1.updated_at);

  // a second, distinct finding for the SAME item
  const created2 = await post('/api/projects/FND_One/tests/WSTG-INJT-04/findings', {
    Risk_Matrix: { CVSS_Score: 2.1, Risk_Level: 'Low' },
    CWE_Information: { CWE_Number: 'CWE-79', CWE_Name: 'XSS' },
    Remediation: {}, Affected_URLs: {},
  });
  assert.equal(created2.status, 201);
  const f2 = created2.json();
  assert.notEqual(f2.id, f1.id);

  const list = await get('/api/projects/FND_One/tests/WSTG-INJT-04/findings');
  assert.equal(list.json().findings.length, 2);

  // update the first finding
  const updated = await putJson(`/api/projects/FND_One/tests/WSTG-INJT-04/findings/${f1.id}`, {
    ...payload1,
    Risk_Matrix: { ...payload1.Risk_Matrix, CVSS_Score: 7.2, Risk_Level: 'High' },
  });
  assert.equal(updated.status, 200);
  const u1 = updated.json();
  assert.equal(u1.id, f1.id);
  assert.equal(u1.Risk_Matrix.Risk_Level, 'High');
  assert.equal(u1.created_at, f1.created_at); // created_at survives an edit
  assert.notEqual(u1.updated_at, f1.updated_at); // updated_at moves

  const updateMissing = await putJson('/api/projects/FND_One/tests/WSTG-INJT-04/findings/doesnotexist', payload1);
  assert.equal(updateMissing.status, 404);

  // the markdown twin exists and names both findings
  const md = fs.readFileSync(path.join(dir, 'Outputs/test_outputs/findings.md'), 'utf8');
  assert.match(md, /Finding 1/);
  assert.match(md, /Finding 2/);
  assert.match(md, /XSS/);

  // delete the second finding, confirm only one remains
  const deleted = await del(`/api/projects/FND_One/tests/WSTG-INJT-04/findings/${f2.id}`);
  assert.equal(deleted.status, 200);
  const afterDelete = await get('/api/projects/FND_One/tests/WSTG-INJT-04/findings');
  assert.equal(afterDelete.json().findings.length, 1);
  assert.equal(afterDelete.json().findings[0].id, f1.id);

  const deleteMissing = await del('/api/projects/FND_One/tests/WSTG-INJT-04/findings/doesnotexist');
  assert.equal(deleteMissing.status, 404);
});

test('findings: rejects a Risk_Level outside the five real bands, and clamps a nonsense CVSS score', async () => {
  assert.equal((await post('/api/projects', { name: 'FND Two' })).status, 201);
  const dir = testDir('FND_Two', 'WSTG-INJT-04');
  for (const s of SUBDIRS) fs.mkdirSync(path.join(dir, ...s.split('/')), { recursive: true });

  const created = await post('/api/projects/FND_Two/tests/WSTG-INJT-04/findings', {
    Risk_Matrix: { CVSS_Score: 99, Risk_Level: 'Super Critical' },
  });
  assert.equal(created.status, 201);
  const f = created.json();
  assert.equal(f.Risk_Matrix.CVSS_Score, 10); // clamped to the real 0-10 range
  assert.equal(f.Risk_Matrix.Risk_Level, null); // not one of the five real bands - dropped, not trusted
});

test('findings: 404 for an unknown WSTG folder, not a crash', async () => {
  assert.equal((await post('/api/projects', { name: 'FND Three' })).status, 201);
  const res = await get('/api/projects/FND_Three/tests/WSTG-INJT-99/findings');
  assert.equal(res.status, 404);
});
