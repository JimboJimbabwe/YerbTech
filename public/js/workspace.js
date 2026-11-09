import { el, api, startClock, projectFromPath, projectUrl, fmtBytes, copyText } from './common.js';
import { initXmlSide } from './xml-side.js';
import { initMouseSide } from './mouse-side.js';
import { initReportingSide } from './reporting-side.js';
import { initProtopollSide } from './protopoll-side.js';
import { initQuestionnaireInfo } from './questionnaire-info.js';
import { initCallbackSide } from './callback-side.js';
import { initIntruderSide } from './intruder-side.js';
import { initFindingsSide } from './findings-side.js';
import { initViewer } from './viewer.js';
import { mountProcedures } from './procs.js';

const project = projectFromPath();
const base = `/api/projects/${encodeURIComponent(project)}`;
const $ = (s) => document.querySelector(s);

startClock($('#clock'));
$('#crumb-project').textContent = project;
$('#crumb-project').href = projectUrl(project);
document.title = `${project} workspace | Red Team Audit Tool`;

const LIGHT_TEXT = { green: 'Ready', amber: 'Wrong folder', red: 'Missing', grey: 'Not required' };
const MARK = { present: '✓', missing: '✗', misplaced: '↪', dynamic: '~', pending: '·' };

let selectedId = null;
let detailToken = 0;

// wstg_id -> { busy, result: {ok,code,stdout,stderr}|null } - only ever populated for
// WSTG-ERRH-01/02, module-scoped so the result survives the box's own re-render (loadResources
// rebuilds the whole box from scratch after a run, same as every other action in this box).
const errhRuns = new Map();

// WSTG-INJT-23 (Insecure Deserialization), module-scoped for the same reason as errhRuns above -
// one project only ever has one of these, so a single state object is enough.
const deserState = { language: 'java', sysType: 'linux', command: '', gadget: '', busy: false, result: null };

// WSTG-INJT-17 (Host Header Injection), same single-state-object reasoning as deserState above.
const hostheaderState = {
  targetUrl: '', cidr: 24, scopeFile: '',
  noResolve: false, noReuseRecon: false, noCloud: false, noRegionGuess: false, noEncode: false,
  busy: false, result: null,
};

/* ---------------------------- checklist column --------------------------- */

async function buildChecklist() {
  const nav = $('#checklist');
  try {
    const { categories } = await api('/api/wstg/checklist');
    nav.replaceChildren(...categories.map(renderCategory));
  } catch (e) {
    nav.replaceChildren(el('p', { class: 'notice notice--error', text: e.message }));
  }
}

function renderCategory(cat) {
  const listId = `cat-${cat.id}`;
  const list = el('ul', { class: 'tests', id: listId, hidden: true }, cat.tests.map(renderTest));
  const head = el('button', { type: 'button', class: 'cat__head', 'aria-expanded': 'false', 'aria-controls': listId },
    el('span', { class: 'chev', 'aria-hidden': 'true' }),
    el('span', { text: cat.name }),
    el('span', { class: 'cat__count', text: String(cat.tests.length) }));
  head.addEventListener('click', () => {
    const open = head.getAttribute('aria-expanded') === 'true';
    head.setAttribute('aria-expanded', String(!open));
    list.hidden = open;
  });
  return el('section', { class: 'cat' }, head, list);
}

function renderTest(t) {
  const boxId = `box-${t.id}`;
  const box = el('div', { class: 'box', id: boxId, 'data-id': t.id, hidden: true });
  const head = el('button', { type: 'button', class: 'test__head', 'aria-expanded': 'false', 'aria-controls': boxId, 'data-id': t.id },
    el('span', { class: 'test__id', text: t.id.replace('WSTG-', '') }),
    el('span', { class: 'test__name', text: t.name }));

  head.addEventListener('click', () => {
    selectTest(t.id);
    const open = head.getAttribute('aria-expanded') === 'true';
    head.setAttribute('aria-expanded', String(!open));
    box.hidden = open;
    if (!open) loadResources(t.id, box);
  });
  return el('li', {}, head, box);
}

function markSelected(id) {
  selectedId = id;
  for (const b of document.querySelectorAll('.test__head')) {
    b.classList.toggle('is-selected', b.dataset.id === id);
  }
}

/* ------------------------- diagnostic lights (box) ----------------------- */

async function loadResources(id, box) {
  box.replaceChildren(el('p', { class: 'box__msg', text: 'Checking files...' }));
  try {
    const data = await api(`${base}/tests/${id}/resources`);
    if (box.hidden) return; // collapsed while the request was in flight
    renderBox(box, id, data);
  } catch (e) {
    box.replaceChildren(el('p', { class: 'box__msg', text: e.message }));
  }
}

function renderBox(box, id, data) {
  const parts = [];

  if (!data.configured) {
    parts.push(el('p', { class: 'box__msg', text: 'This assessment has no entry in wstg_io.json, so no files are checked.' }));
  }
  if (!data.testDirFound) {
    parts.push(el('p', { class: 'notice', text: 'This assessment’s folder is missing from the project. It may have been created from an older Base_Image.' }));
  }

  for (const key of ['scripts', 'json', 'xml', 'wordlists']) {
    const g = data.groups[key];
    const stateText = data.configured ? LIGHT_TEXT[g.light] : 'No config';
    parts.push(el('div', {},
      el('div', { class: 'diag__row' },
        el('span', { class: `light light--${g.light}`, role: 'img', 'aria-label': `${g.label}: ${stateText}` }),
        el('span', { class: 'diag__label', text: g.label }),
        el('span', { class: `diag__state diag__state--${g.light}`, text: stateText })),
      g.items.length ? el('ul', { class: 'files' }, g.items.map(fileRow)) : null));
  }

  // Run order and commands load separately so a slow lookup never holds up the lights.
  const procHost = el('div', { class: 'procs-host' });
  parts.push(procHost);
  mountProcedures(procHost, base, id);

  if (id === 'WSTG-INJT-23') parts.push(deserSection(id, box));
  if (id === 'WSTG-INJT-17') parts.push(hostheaderSection(id, box));

  const later = [
    ...Object.values(data.groups).flatMap((g) => g.produces.map((p) => ({ ...p, group: g.label }))),
    ...data.reports.map((r) => ({ ...r, group: 'Report' })),
  ];
  if (later.length) {
    parts.push(el('details', {},
      el('summary', { text: `Files this assessment produces (${later.length})` }),
      el('ul', { class: 'files' }, later.map(fileRow))));
  }

  if (id === 'WSTG-ERRH-01' || id === 'WSTG-ERRH-02') {
    parts.push(errhSection(id, box));
  }

  parts.push(el('div', { class: 'box__foot' },
    el('span', { class: 'box__path mono' }, data.testDir ? pathNode(data.testDir) : 'folder not found'),
    el('button', { type: 'button', class: 'linkbtn', text: 'Re-check', onclick: () => loadResources(id, box) })));

  box.replaceChildren(...parts);
}

/** WSTG-ERRH-01 / WSTG-ERRH-02 only: a "Generate wordlist" button that runs that item's own
 * errh0{1,2}_wordlist.py (see lib/errh.js / the README's "Error Handling wordlists" section).
 * Each item's box only ever shows its own button - ERRH-01's box never offers to run ERRH-02's
 * script or vice versa - the pairing/exclusion coordination happens inside the scripts, not here. */
function errhSection(id, box) {
  const st = errhRuns.get(id) || { busy: false, result: null };
  errhRuns.set(id, st);

  const btn = el('button', { type: 'button', class: 'linkbtn', disabled: st.busy || null, text: st.busy ? 'Running...' : 'Generate wordlist' });
  btn.addEventListener('click', async () => {
    st.busy = true;
    btn.disabled = true;
    btn.textContent = 'Running...';
    try {
      st.result = await api(`${base}/tests/${id}/errh-wordlist`, { method: 'POST', body: '{}' });
    } catch (e) {
      st.result = { ok: false, code: 1, stdout: '', stderr: e.message };
    } finally {
      st.busy = false;
      loadResources(id, box); // full refresh - picks up the new file in the wordlists light too
    }
  });

  const kids = [el('div', { class: 'mouse__row' }, btn)];
  if (st.result) {
    const logText = [st.result.stdout, st.result.stderr].filter(Boolean).join('\n');
    kids.push(el('p', {
      class: `mouse__status${st.result.ok ? ' is-ok' : ' is-error'}`, role: 'status',
      text: st.result.ok ? 'Wordlist generated.' : 'Finished with errors (see log below).',
    }));
    if (logText) kids.push(el('div', { class: 'mouse__log', text: logText }));
  }
  return el('section', { class: 'mouse__sec' }, el('div', { class: 'mouse__h', text: 'Error Handling wordlist' }), ...kids);
}

/** WSTG-INJT-23 only: the Insecure Deserialization tool (lib/deser.js / tools/deser/deser_wordlist.py -
 * see the README's "Insecure Deserialization tool" section). A PHP/JAVA toggle and a linux/windows
 * toggle sit next to the usual Copy/Build row above - the sys-type toggle is also what implies
 * linux.txt vs windows.txt for the script's command list, so there's no separate flag for that
 * in this panel; it's just whichever file the toggle points at. Command and Gadget override are
 * both optional free-text fields, same as the script's own --command/--gadget. */
function deserToggle(label, options, get, set, redraw) {
  const wrap = el('div', { class: 'seg', role: 'group', 'aria-label': label });
  for (const [key, text] of options) {
    const b = el('button', { type: 'button', class: 'seg__btn', 'aria-pressed': String(get() === key), text });
    b.addEventListener('click', () => { if (get() !== key) { set(key); redraw(); } });
    wrap.append(b);
  }
  return wrap;
}

function deserSection(id, box) {
  const st = deserState;
  const commandListFile = `${st.sysType}.txt`;

  const redraw = () => { box.querySelector('.deser-sec-anchor')?.replaceWith(deserSection(id, box)); };

  const langToggle = deserToggle('Language', [['java', 'JAVA'], ['php', 'PHP']], () => st.language, (v) => { st.language = v; }, redraw);
  const sysToggle = deserToggle('OS', [['linux', 'linux'], ['windows', 'windows']], () => st.sysType, (v) => { st.sysType = v; }, redraw);

  const commandInput = el('input', { type: 'text', class: 'fld__input mono', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Command to test', placeholder: 'command to test, e.g. id (optional)' });
  commandInput.value = st.command;
  commandInput.addEventListener('input', () => { st.command = commandInput.value; });

  const gadgetInput = el('input', { type: 'text', class: 'fld__input mono', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Gadget override', placeholder: 'gadget override, e.g. CommonsCollections6 (optional - default is every gadget)' });
  gadgetInput.value = st.gadget;
  gadgetInput.addEventListener('input', () => { st.gadget = gadgetInput.value; });

  const btn = el('button', { type: 'button', class: 'pill', disabled: st.busy || null, text: st.busy ? 'Running...' : 'Run' });
  btn.addEventListener('click', async () => {
    st.busy = true;
    st.result = null;
    redraw();
    try {
      st.result = await api(`${base}/tests/${id}/deser-run`, {
        method: 'POST',
        body: JSON.stringify({ language: st.language, sysType: st.sysType, command: st.command, gadget: st.gadget }),
      });
    } catch (e) {
      st.result = { ok: false, code: 1, stdout: '', stderr: e.message };
    } finally {
      st.busy = false;
      loadResources(id, box); // full refresh - picks up the new raw/encoded files in the wordlists light too
    }
  });

  const kids = [
    el('div', { class: 'mouse__row' }, langToggle, sysToggle),
    el('p', { class: 'fld__desc', text: `Command list: Inputs/Data/${commandListFile} (implied by the OS toggle above). Command and Gadget override below are both optional and additive to it.` }),
    el('div', { class: 'mouse__row' }, commandInput),
    el('div', { class: 'mouse__row' }, gadgetInput),
    el('div', { class: 'mouse__row' }, btn),
  ];
  if (st.result) {
    const logText = [st.result.stdout, st.result.stderr].filter(Boolean).join('\n');
    kids.push(el('p', {
      class: `mouse__status${st.result.ok ? ' is-ok' : ' is-error'}`, role: 'status',
      text: st.result.ok ? 'Run finished - raw payloads saved, wordlists rebuilt.' : 'Finished with errors (see log below).',
    }));
    if (logText) kids.push(el('div', { class: 'mouse__log', text: logText }));
  }
  return el('section', { class: 'mouse__sec deser-sec-anchor' }, el('div', { class: 'mouse__h', text: 'Insecure Deserialization (ysoserial / phpggc)' }), ...kids);
}

/** WSTG-INJT-17 only: the Host Header Injection wordlist tool (lib/hostheader.js /
 * tools/hostheader/hostheader_wordlist.py - see the README's "Host Header Injection" section).
 * One-shot run-to-completion action, same as the Deserialization card above - it reuses
 * WSTG-INFO-04's subdomains/DNS/nmap output automatically when present, so the only required
 * field is the target URL; the five checkboxes just turn off one category each (cloud metadata,
 * region/provider-token guesses, the WSTG-INFO-04 reuse step entirely, the live-DNS fallback, or
 * the encoded-variants file), all of which default ON. */
function hostheaderSection(id, box) {
  const st = hostheaderState;
  const redraw = () => { box.querySelector('.hostheader-sec-anchor')?.replaceWith(hostheaderSection(id, box)); };

  const urlInput = el('input', { type: 'text', class: 'fld__input mono', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Target URL', placeholder: 'target URL, e.g. https://example.com (required)' });
  urlInput.value = st.targetUrl;
  urlInput.addEventListener('input', () => { st.targetUrl = urlInput.value; });

  const cidrInput = el('input', { type: 'number', class: 'fld__input mono', style: 'width:5rem', min: '0', max: '32', step: '1', 'aria-label': 'Broadcast CIDR assumption' });
  cidrInput.value = String(st.cidr);
  cidrInput.addEventListener('input', () => { st.cidr = Number(cidrInput.value) || 24; });

  const scopeInput = el('input', { type: 'text', class: 'fld__input mono', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Scope file override', placeholder: 'extra scope file path (optional - defaults to WSTG-INFO-04’s domains.txt if present)' });
  scopeInput.value = st.scopeFile;
  scopeInput.addEventListener('input', () => { st.scopeFile = scopeInput.value; });

  const check = (label, get, set) => {
    const box_ = el('input', { type: 'checkbox' });
    box_.checked = get();
    box_.addEventListener('change', () => set(box_.checked));
    return el('label', { class: 'bld__check' }, box_, ' ', label);
  };

  const btn = el('button', { type: 'button', class: 'pill', disabled: st.busy || null, text: st.busy ? 'Running...' : 'Run' });
  btn.addEventListener('click', async () => {
    if (!st.targetUrl.trim()) {
      st.result = { ok: false, code: 1, stdout: '', stderr: 'Target URL is required.' };
      redraw();
      return;
    }
    st.busy = true;
    st.result = null;
    redraw();
    try {
      st.result = await api(`${base}/tests/${id}/hostheader-run`, {
        method: 'POST',
        body: JSON.stringify({
          targetUrl: st.targetUrl, cidr: st.cidr, scopeFile: st.scopeFile || undefined,
          noResolve: st.noResolve, noReuseRecon: st.noReuseRecon, noCloud: st.noCloud,
          noRegionGuess: st.noRegionGuess, noEncode: st.noEncode,
        }),
      });
    } catch (e) {
      st.result = { ok: false, code: 1, stdout: '', stderr: e.message };
    } finally {
      st.busy = false;
      loadResources(id, box); // full refresh - picks up Host_Values.txt / Host_Values_Encoded.txt in the Wordlists light
    }
  });

  const kids = [
    el('div', { class: 'mouse__row' }, urlInput),
    el('p', { class: 'fld__desc', text: 'Reuses WSTG-INFO-04’s subdomains, DNS results and nmap XML automatically when present - none of the fields below are required.' }),
    el('div', { class: 'mouse__row' }, scopeInput),
    el('div', { class: 'mouse__row' }, el('label', { class: 'bld__check' }, 'broadcast CIDR ', cidrInput)),
    el('div', { class: 'mouse__row' },
      check('skip WSTG-INFO-04 reuse', () => st.noReuseRecon, (v) => { st.noReuseRecon = v; }),
      check('skip live DNS fallback', () => st.noResolve, (v) => { st.noResolve = v; })),
    el('div', { class: 'mouse__row' },
      check('skip cloud metadata', () => st.noCloud, (v) => { st.noCloud = v; }),
      check('skip region/provider guesses', () => st.noRegionGuess, (v) => { st.noRegionGuess = v; })),
    el('div', { class: 'mouse__row' }, check('skip encoded-variants file', () => st.noEncode, (v) => { st.noEncode = v; })),
    el('div', { class: 'mouse__row' }, btn),
  ];
  if (st.result) {
    const logText = [st.result.stdout, st.result.stderr].filter(Boolean).join('\n');
    kids.push(el('p', {
      class: `mouse__status${st.result.ok ? ' is-ok' : ' is-error'}`, role: 'status',
      text: st.result.ok ? 'Wordlist(s) written - see the Wordlists panel for this item.' : 'Finished with errors (see log below).',
    }));
    if (logText) kids.push(el('div', { class: 'mouse__log', text: logText }));
  }
  return el('section', { class: 'mouse__sec hostheader-sec-anchor' }, el('div', { class: 'mouse__h', text: 'Host Header Injection wordlist' }), ...kids);
}

function fileRow(item) {
  const cls = item.status === 'pending' || item.status === 'dynamic' ? '' : ` file--${item.status}`;
  return el('li', { class: `file${cls}`, title: item.detail || null },
    el('span', { class: 'file__mark', 'aria-hidden': 'true', text: MARK[item.status] || '' }),
    el('span', { class: 'file__body' },
      el('span', { class: 'file__name mono', text: item.title }),
      item.note ? el('span', { class: 'file__note', text: item.note }) : null),
    el('span', { class: 'sr-only', text: item.status }));
}

/** Folder path that may wrap after a slash but never inside a name. */
function pathNode(p) {
  return p.split('/').flatMap((seg, i) => (i ? ['/', el('wbr'), seg] : [seg]));
}

/* ------------------------- detail column: what / why --------------------- */

async function selectTest(id) {
  if (id === selectedId) return;
  markSelected(id);
  viewer.setAssessment(id);
  feSide.setCurrent(id);
  const token = ++detailToken;
  const pane = $('#detail');
  pane.replaceChildren(el('div', { class: 'detail__empty', text: 'Loading...' }));
  try {
    const [info, wl] = await Promise.all([
      api(`/api/wstg/tests/${id}`),
      api(`${base}/tests/${id}/wordlists`).catch((e) => ({ error: e.message, files: [] })),
    ]);
    if (token !== detailToken) return; // a newer click won
    pane.replaceChildren(renderDetail(info), renderWordlists(id, wl));
  } catch (e) {
    if (token !== detailToken) return;
    pane.replaceChildren(el('div', { class: 'detail__empty' }, el('strong', { text: `Could not load ${id}` }), e.message));
  }
}

function renderDetail(info) {
  const ref = info.reference && /^https:\/\//i.test(info.reference)
    ? el('a', { class: 'detail__ref', href: info.reference, target: '_blank', rel: 'noopener noreferrer', text: 'OWASP reference' })
    : null;

  const entries = info.reporting.length ? info.reporting : [{ what: '', why: '' }];
  return el('div', { class: 'detail' },
    el('header', {},
      el('h2', { class: 'detail__title', text: info.category }),
      el('p', { class: 'detail__sub', text: info.id }),
      el('p', { class: 'detail__assess', text: info.name }),
      ref),
    entries.map((r) => el('div', { class: 'entry' },
      el('section', {},
        el('h3', { text: 'What are we testing for?' }),
        el('div', { class: 'textbox', text: r.what || 'No description in wstg_reporting.json.' })),
      el('section', {},
        el('h3', { text: 'Why do we test for this?' }),
        el('div', { class: 'textbox', text: r.why || 'No description in wstg_reporting.json.' })))));
}

/* ------------------------- wordlist copy (feature 4) --------------------- */

// Per-item, per-file notes shown next to a wordlist's Copy button (id + exact filename, so this
// never accidentally matches another item's same-named file). WSTG-INJT-22's three are generated
// by protopoll_wordlists.py; WSTG-INJT-17's two by hostheader_wordlist.py - see their panels
// above and the README.
const WORDLIST_NOTES = {
  'WSTG-INJT-22:URL_Seg.txt': 'Use this for testing requests in the URL.',
  'WSTG-INJT-22:Body_Data.txt': 'Use this for testing body data.',
  'WSTG-INJT-22:URL_Hash.txt': 'Used by the hash fragment opener (hash_fragment_opener.py), not meant to be pasted into Burp the same way as the other two.',
  'WSTG-INJT-17:Host_Values.txt': 'Raw candidate Host header values - paste straight into Burp Intruder.',
  'WSTG-INJT-17:Host_Values_Encoded.txt': 'URL-encoded / double-encoded / decimal / hex variants of the same values, for WAF or parser bypass testing.',
};

function renderWordlists(id, wl) {
  const status = el('p', { class: 'wl__status', role: 'status' });
  const say = (text, kind) => { status.textContent = text; status.className = `wl__status${kind ? ` is-${kind}` : ''}`; };

  let body;
  if (wl.error) body = el('p', { class: 'hint', text: wl.error });
  else if (!wl.dirFound) body = el('p', { class: 'hint', text: 'This assessment has no Wordlists folder in the project.' });
  else if (!wl.files.length) body = el('p', { class: 'hint', text: 'The Wordlists folder is empty.' });
  else {
    body = el('ul', { class: 'wl__list' }, wl.files.map((f) => {
      const tag = f.declared === 'in' ? 'input' : f.declared === 'out' ? 'generated' : null;
      const btn = el('button', { type: 'button', class: 'linkbtn', text: 'Copy' });
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        say(`Copying ${f.name}...`);
        try {
          const text = await api(`${base}/tests/${id}/wordlists/${encodeURIComponent(f.name)}`);
          await copyText(text);
          const lines = text === '' ? 0 : text.replace(/\r?\n$/, '').split(/\r?\n/).length;
          say(`Copied ${f.name}: ${lines.toLocaleString()} ${lines === 1 ? 'line' : 'lines'}.`, 'ok');
        } catch (e) {
          say(e.message, 'error');
        } finally {
          btn.disabled = false;
        }
      });
      const note = WORDLIST_NOTES[`${id}:${f.name}`];
      return el('li', { class: 'wl__item' },
        el('span', { class: 'wl__name' },
          el('span', { class: 'mono', text: f.name }),
          el('span', { class: 'wl__meta', text: [fmtBytes(f.size), tag].filter(Boolean).join(' · ') }),
          note ? el('span', { class: 'hint', text: note }) : null),
        btn);
    }));
  }
  return el('section', { class: 'detail wl' }, el('h3', { text: 'Wordlists' }), body, status);
}

/* ------------------------- XML sidebar and request viewer ---------------- */

const mouseSide = initMouseSide({ base });
const repSide = initReportingSide({ base });
const ppSide = initProtopollSide({ base });
const qstInfo = initQuestionnaireInfo({ base, project });
const cbSide = initCallbackSide({ base });
const ilSide = initIntruderSide({ base });
const feSide = initFindingsSide({ base });
const viewer = initViewer({ base, openSidebar: () => xmlSide.open() });
const xmlSide = initXmlSide({
  base,
  // New XML was copied into assessments: refresh the lights of any open box and the viewer.
  onChange: () => {
    for (const box of document.querySelectorAll('.box:not([hidden])')) loadResources(box.dataset.id, box);
    viewer.refresh();
  },
});

buildChecklist();
