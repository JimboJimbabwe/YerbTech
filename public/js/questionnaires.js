import { el, api, startClock, projectFromPath, projectUrl } from './common.js';

/**
 * Questionnaire answering page. Left: every questionnaire, grouped by category, with an
 * answered/unanswered marker. Right: the selected questionnaire's questions, rendered by
 * answer_type - radio buttons for yes/no-style questions, checkboxes for a checklist, a text box
 * for anything that needs typing. Save writes both the JSON and the Markdown on the server.
 */
const project = projectFromPath();
const base = `/api/projects/${encodeURIComponent(project)}`;
const $ = (s) => document.querySelector(s);

startClock($('#clock'));
$('#crumb-project').textContent = project;
$('#crumb-project').href = projectUrl(project);
$('#crumb-workspace').href = `${projectUrl(project)}/workspace`;
document.title = `${project} questionnaires | Red Team Audit Tool`;

const nav = $('#qnav');
const form = $('#qform');

let listState = null;   // { items, warnings } from GET /questionnaires
let activeKey = null;
let activeItem = null;  // full item from GET /questionnaires/:key (has .answers from disk)
let answers = {};        // in-memory working copy, { qid: { value } }
let busy = false;
let message = null;

const Y = 'Y', N = 'N';

/* --------------------------- condition helpers (mirrors lib/questionnaire.js) ------------- */

function conditionMet(cond) {
  if (!cond) return true;
  const m = /^\s*([^=\s][^=]*?)\s*==\s*(.+?)\s*$/.exec(cond);
  if (!m) return true;
  const [, qid, want] = m;
  const got = answers[qid];
  if (got == null) return false;
  return String(got.value) === want;
}

function followUpVisible(q) {
  const got = answers[q.id];
  return got && got.value === Y;
}

/* --------------------------------- left nav --------------------------------- */

async function loadList() {
  try {
    listState = await api(`${base}/questionnaires`);
    message = null;
  } catch (e) {
    listState = { items: [], warnings: [] };
    message = { text: e.message, kind: 'error' };
  }
  renderNav();
}

function renderNav() {
  const items = listState?.items || [];
  const byCat = new Map();
  for (const it of items) {
    if (!byCat.has(it.category)) byCat.set(it.category, []);
    byCat.get(it.category).push(it);
  }
  const sections = [...byCat.entries()].map(([cat, its]) => {
    const rows = its.map((it) => {
      const row = el('button', {
        type: 'button', class: `qnav__item${it.key === activeKey ? ' is-active' : ''}`,
      },
        el('span', { class: `qnav__dot${it.answered ? ' is-done' : ''}`, 'aria-hidden': 'true' }),
        el('span', { class: 'qnav__label' },
          el('span', { class: 'qnav__id', text: it.wstg_id.replace('WSTG-', '') }),
          el('span', { class: 'qnav__title', text: it.title || it.runner || it.key })),
        el('span', { class: 'qnav__count', text: String(it.question_count) }));
      row.addEventListener('click', () => selectItem(it.key));
      return row;
    });
    return el('section', { class: 'qnav__cat' }, el('h3', { class: 'qnav__h', text: cat }), rows);
  });
  const warn = listState?.warnings?.length
    ? el('p', { class: 'mouse__status is-error', role: 'status', text: `${listState.warnings.length} data warning(s): ${listState.warnings.join('; ')}` })
    : null;
  nav.replaceChildren(el('h2', { class: 'qnav__title-main', text: 'Questionnaires' }), warn, ...sections);
}

async function selectItem(key) {
  if (busy) return;
  activeKey = key;
  renderNav();
  form.replaceChildren(el('p', { class: 'mouse__status', text: 'Loading...' }));
  try {
    activeItem = await api(`${base}/questionnaires/${encodeURIComponent(key)}`);
    answers = {};
    for (const [qid, v] of Object.entries(activeItem.answers || {})) {
      answers[qid] = (v && typeof v === 'object' && 'value' in v) ? v : { value: v };
    }
    message = null;
  } catch (e) {
    activeItem = null;
    message = { text: e.message, kind: 'error' };
  }
  renderForm();
}

/* --------------------------------- right form --------------------------------- */

function setAnswer(qid, value, { rerender } = {}) {
  answers[qid] = { value };
  if (rerender) renderForm();
}

function radioGroup(q, options) {
  const wrap = el('div', { class: 'qf__options', role: 'radiogroup' });
  for (const opt of options) {
    const id = `${q.id}__${opt}`;
    const input = el('input', {
      type: 'radio', name: q.id, id, value: opt,
      checked: answers[q.id]?.value === opt || null,
    });
    input.addEventListener('change', () => setAnswer(q.id, opt, { rerender: true }));
    wrap.append(el('label', { class: 'qf__radio', for: id }, input, el('span', { text: opt })));
  }
  return wrap;
}

function checklistGroup(q) {
  const current = Array.isArray(answers[q.id]?.value) ? answers[q.id].value : [];
  const wrap = el('div', { class: 'qf__options' });
  for (const opt of q.options || []) {
    const id = `${q.id}__${opt}`;
    const input = el('input', { type: 'checkbox', id, value: opt, checked: current.includes(opt) || null });
    input.addEventListener('change', () => {
      const set = new Set(Array.isArray(answers[q.id]?.value) ? answers[q.id].value : []);
      if (input.checked) set.add(opt); else set.delete(opt);
      setAnswer(q.id, [...set]);
    });
    wrap.append(el('label', { class: 'qf__radio', for: id }, input, el('span', { text: opt })));
  }
  return wrap;
}

function textBox(qid, placeholder, { rows } = {}) {
  const value = answers[qid]?.value;
  const input = rows > 1
    ? el('textarea', { rows: String(rows), placeholder: placeholder || '' })
    : el('input', { type: 'text', placeholder: placeholder || '' });
  input.value = typeof value === 'string' ? value : '';
  input.addEventListener('input', () => setAnswer(qid, input.value));
  return input;
}

function fieldsBox(q) {
  const current = (answers[q.id]?.value && typeof answers[q.id].value === 'object') ? answers[q.id].value : {};
  const wrap = el('div', { class: 'qf__fields' });
  const obj = { ...current };
  for (const fname of q.fields) {
    const input = el('input', { type: 'text', placeholder: fname });
    input.value = typeof current[fname] === 'string' ? current[fname] : '';
    input.addEventListener('input', () => { obj[fname] = input.value; setAnswer(q.id, { ...obj }); });
    wrap.append(el('label', { class: 'qf__field' }, el('span', { text: fname }), input));
  }
  return wrap;
}

function renderControl(q) {
  switch (q.answer_type) {
    case 'yn': return radioGroup(q, [Y, N]);
    case 'yn_unknown': return radioGroup(q, [Y, N, 'Unknown']);
    case 'yn_skip': return radioGroup(q, [Y, N, 'Skip']);
    case 'flawed': return radioGroup(q, ['Flawed', 'Not Flawed']);
    case 'choice': return radioGroup(q, q.options || []);
    case 'checklist': return checklistGroup(q);
    case 'list': return textBox(q.id, 'comma-separated');
    case 'auto':
      return el('div', { class: 'qf__auto' },
        el('span', { class: 'mouse__status', text: 'Auto-scanned from the Burp XML; no answer needed here.' }),
        el('label', { class: 'qf__field' }, el('span', { text: 'manual override (optional)' }), textBox(q.id, 'leave blank to use the automatic scan')));
    case 'text':
    default:
      return q.fields ? fieldsBox(q) : textBox(q.id, undefined, { rows: 2 });
  }
}

function questionBlock(q) {
  const hiddenBy = q.parent_condition && !conditionMet(q.parent_condition) ? q.parent_condition
    : (q.condition && !conditionMet(q.condition) ? q.condition : null);

  const head = el('div', { class: 'qf__head' },
    el('span', { class: 'qf__id', text: q.id }),
    q.is_gate ? el('span', { class: 'qf__badge is-gate', text: 'GATE' }) : null,
    q.optional ? el('span', { class: 'qf__badge', text: 'optional' }) : null);

  if (hiddenBy) {
    return el('div', { class: 'qf__q is-hidden' }, head,
      el('p', { class: 'qf__text', text: q.question }),
      el('p', { class: 'mouse__status', text: `Hidden - condition "${hiddenBy}" not met.` }));
  }

  const kids = [head, el('p', { class: 'qf__text', text: q.question }), renderControl(q)];

  if (Array.isArray(q.follow_up) && q.follow_up.length) {
    if (followUpVisible(q)) {
      for (let i = 0; i < q.follow_up.length; i++) {
        const fuId = `${q.id}__fu${i}`;
        kids.push(el('label', { class: 'qf__field qf__followup' },
          el('span', { text: q.follow_up[i] }), textBox(fuId)));
      }
    } else {
      kids.push(el('p', { class: 'mouse__status', text: `${q.follow_up.length} follow-up question(s) appear once this is answered "${Y}".` }));
    }
  }

  if (q.note) kids.push(el('p', { class: 'qf__note', text: q.note }));
  if (q.reference) kids.push(el('p', { class: 'qf__note' }, 'Reference: ', el('a', { href: q.reference, target: '_blank', rel: 'noopener', text: q.reference })));

  return el('div', { class: 'qf__q' }, ...kids);
}

async function save() {
  if (!activeItem || busy) return;
  busy = true;
  message = { text: 'Saving...', kind: 'info' };
  renderForm();
  try {
    const res = await api(`${base}/questionnaires/${encodeURIComponent(activeKey)}/answers`, {
      method: 'PUT',
      body: JSON.stringify({ answers }),
    });
    message = { text: `Saved (${new Date(res.saved_at).toLocaleTimeString()}).`, kind: 'ok' };
    const it = listState?.items?.find((x) => x.key === activeKey);
    if (it) it.answered = true;
    renderNav();
  } catch (e) {
    message = { text: e.message, kind: 'error' };
  } finally {
    busy = false;
    renderForm();
  }
}

function renderForm() {
  if (!activeItem) {
    form.replaceChildren(message
      ? el('p', { class: 'mouse__status is-error', role: 'status', text: message.text })
      : el('div', { class: 'qempty' }, el('strong', { text: 'No questionnaire selected' }), 'Choose one from the list to answer it.'));
    return;
  }

  let lastGroup = null;
  const blocks = [];
  for (const q of activeItem.questions) {
    const group = q.category_name;
    if (group && group !== lastGroup) {
      blocks.push(el('h3', { class: 'qf__group', text: q.category ? `${q.category}. ${group}` : group }));
      lastGroup = group;
    }
    blocks.push(questionBlock(q));
  }

  const saveBtn = el('button', { type: 'button', class: 'linkbtn', disabled: busy || null, text: busy ? 'Saving...' : 'Save answers' });
  saveBtn.addEventListener('click', save);

  const head = el('header', { class: 'qf__pageHead' },
    el('h2', { text: `${activeItem.wstg_id} — ${activeItem.title || activeItem.key}` }),
    el('p', { class: 'mouse__status', text: `${activeItem.category} · ${activeItem.questions.length} question(s)${activeItem.polarity ? ` · polarity: ${activeItem.polarity}` : ''}` }),
    saveBtn,
    message ? el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }) : null);

  form.replaceChildren(head, ...blocks);
}

loadList();
