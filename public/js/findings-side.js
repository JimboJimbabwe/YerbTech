import { el, api } from './common.js';
import { METRICS, computeCvss31, parseCvss31Vector } from './cvss31.js';

/**
 * Findings Entry: the "+" popup asks, for whichever WSTG item is currently selected in the
 * checklist, whether the test turned anything up. "No" just closes it - nothing is written.
 * "Yes" opens the left-pane aside with a blank data-entry form (CVSS calculator first, then
 * CWE/Remediation/Affected-URLs) for a new finding.json entry under that item, snapshotting the
 * category/name/id at the moment of confirming so the form stays correctly labelled even if the
 * operator clicks around the checklist while it's open. The aside also lists - and lets you edit
 * or delete - every finding already recorded for whichever item it's currently showing.
 */
export function initFindingsSide({ base }) {
  const side = document.querySelector('#fe-side');
  const panel = document.querySelector('#fe-panel');
  const toggle = document.querySelector('#fe-toggle');
  const addBtn = document.querySelector('#fe-add');
  const popup = document.querySelector('#fe-popup');

  let currentId = null; // the checklist's current selection - kept live by setCurrent()
  const metaCache = new Map(); // wstg_id -> { category, name }

  let popupOpen = false;
  let popupMinimized = false;
  let popupChoice = 'no'; // 'yes' | 'no'
  let popupMeta = null; // { category, name } for currentId, once loaded
  let popupLoading = false;

  let targetId = null; // the item whose findings the aside is listing/editing
  let targetMeta = null;
  let mode = 'list'; // 'list' | 'form'
  let findingsList = [];
  let listBusy = false;
  let form = null; // see blankForm()
  let saveBusy = false;
  let deleteArmed = null; // id of the finding one click from being deleted
  let message = null; // { text, kind }

  /* --------------------------------- meta lookup -------------------------------- */

  async function ensureMeta(id) {
    if (metaCache.has(id)) return metaCache.get(id);
    const info = await api(`/api/wstg/tests/${id}`);
    const meta = { category: info.category, name: info.name };
    metaCache.set(id, meta);
    return meta;
  }

  /* ------------------------------------ popup ------------------------------------ */

  function setCurrent(id) {
    currentId = id;
    if (popupOpen) {
      popupMeta = null;
      loadPopupMeta();
    }
  }

  async function loadPopupMeta() {
    if (!currentId) { renderPopup(); return; }
    popupLoading = true;
    renderPopup();
    try {
      popupMeta = await ensureMeta(currentId);
    } catch (e) {
      popupMeta = { category: '—', name: `Could not load: ${e.message}` };
    } finally {
      popupLoading = false;
      renderPopup();
    }
  }

  function openPopup() {
    popupOpen = true;
    popupMinimized = false;
    popupChoice = 'no';
    popupMeta = null;
    addBtn.setAttribute('aria-expanded', 'true');
    loadPopupMeta();
  }

  function closePopup() {
    popupOpen = false;
    addBtn.setAttribute('aria-expanded', 'false');
    renderPopup();
  }

  function toggleMinimizePopup() {
    popupMinimized = !popupMinimized;
    renderPopup();
  }

  async function confirmPopup() {
    if (popupChoice === 'yes' && currentId) {
      const meta = popupMeta || (await ensureMeta(currentId).catch(() => ({ category: '', name: '' })));
      startNewFinding(currentId, meta);
      openAside(true);
    }
    closePopup();
  }

  addBtn.addEventListener('click', () => (popupOpen ? closePopup() : openPopup()));

  function renderPopup() {
    if (!popupOpen) { popup.hidden = true; popup.replaceChildren(); return; }
    popup.hidden = false;

    const head = el('div', { class: 'fe-pop__head' },
      el('span', { class: 'fe-pop__title', text: 'Findings Entry' }),
      el('button', {
        type: 'button', class: 'fe-pop__min', 'aria-label': popupMinimized ? 'Restore' : 'Minimize',
        text: popupMinimized ? '▢' : '_', onclick: toggleMinimizePopup,
      }));

    if (popupMinimized) {
      popup.replaceChildren(el('div', { class: 'fe-pop__body' }, head));
      return;
    }

    let body;
    if (!currentId) {
      body = el('p', { class: 'mouse__status', text: 'Select a WSTG item in the checklist first.' });
    } else if (popupLoading || !popupMeta) {
      body = el('p', { class: 'mouse__status', text: 'Loading...' });
    } else {
      const yn = (value, label) => {
        const input = el('input', { type: 'radio', name: 'fe-pop-yn', value, checked: popupChoice === value || null });
        input.addEventListener('change', () => { popupChoice = value; });
        return el('label', { class: 'fe-pop__yn' }, input, el('span', { text: label }));
      };
      body = el('div', { class: 'fe-pop__form' },
        el('div', { class: 'fe-pop__row' }, el('span', { class: 'fe-pop__k', text: 'CATEGORY' }), el('span', { class: 'fe-pop__v', text: popupMeta.category })),
        el('div', { class: 'fe-pop__row' }, el('span', { class: 'fe-pop__k', text: 'WSTG ITEM' }), el('span', { class: 'fe-pop__v', text: popupMeta.name })),
        el('div', { class: 'fe-pop__row' }, el('span', { class: 'fe-pop__k', text: 'WSTG-ID' }), el('span', { class: 'fe-pop__v mono', text: currentId })),
        el('div', { class: 'fe-pop__row' }, el('span', { class: 'fe-pop__k', text: 'Findings?' }), el('div', { class: 'fe-pop__ynrow' }, yn('yes', 'Yes'), yn('no', 'No'))),
        el('button', { type: 'button', class: 'linkbtn fe-pop__confirm', text: 'Confirm', onclick: confirmPopup }));
    }

    popup.replaceChildren(el('div', { class: 'fe-pop__body' }, head, body));
  }

  /* ------------------------------------ aside ------------------------------------ */

  function openAside(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Findings Entry panel' : 'Open the Findings Entry panel');
    if (open && !targetId && currentId) showList(currentId);
  }
  toggle.addEventListener('click', () => openAside(side.hidden));

  async function showList(id) {
    targetId = id;
    mode = 'list';
    form = null;
    message = null;
    deleteArmed = null;
    listBusy = true;
    render();
    try {
      targetMeta = await ensureMeta(id);
      const data = await api(`${base}/tests/${id}/findings`);
      findingsList = data.findings;
    } catch (e) {
      findingsList = [];
      message = { text: e.message, kind: 'error' };
    } finally {
      listBusy = false;
      render();
    }
  }

  function blankForm() {
    return {
      cvss: {},
      Risk_Matrix: { CVSS_Vector: '', CVSS_Score: null, Risk_Level: null },
      CWE_Information: { CWE_Number: '', CWE_Name: '', CWE_Description: '', CWE_Why: '', CWE_Impact: '' },
      Remediation: { Remediation_Statement: '', Recommendation: '', Additional_recommendations: [] },
      Affected_URLs: { URLs: [] },
    };
  }

  function formFromFinding(f) {
    const rm = f.Risk_Matrix || {};
    return {
      id: f.id,
      cvss: parseCvss31Vector(rm.CVSS_Vector),
      Risk_Matrix: { CVSS_Vector: rm.CVSS_Vector || '', CVSS_Score: rm.CVSS_Score ?? null, Risk_Level: rm.Risk_Level ?? null },
      CWE_Information: { ...blankForm().CWE_Information, ...(f.CWE_Information || {}) },
      Remediation: {
        Remediation_Statement: f.Remediation?.Remediation_Statement || '',
        Recommendation: f.Remediation?.Recommendation || '',
        Additional_recommendations: [...(f.Remediation?.Additional_recommendations || [])],
      },
      Affected_URLs: { URLs: [...(f.Affected_URLs?.URLs || [])] },
    };
  }

  function startNewFinding(id, meta) {
    targetId = id;
    targetMeta = meta;
    mode = 'form';
    form = blankForm();
    message = null;
    deleteArmed = null;
    render();
  }

  function startEditFinding(f) {
    mode = 'form';
    form = formFromFinding(f);
    message = null;
    deleteArmed = null;
    render();
  }

  function cancelForm() {
    mode = 'list';
    form = null;
    render();
  }

  async function saveForm() {
    if (saveBusy || !form) return;
    saveBusy = true;
    message = null;
    render();
    const payload = {
      Risk_Matrix: form.Risk_Matrix,
      CWE_Information: form.CWE_Information,
      Remediation: form.Remediation,
      Affected_URLs: form.Affected_URLs,
    };
    try {
      if (form.id) {
        await api(`${base}/tests/${targetId}/findings/${form.id}`, { method: 'PUT', body: JSON.stringify(payload) });
      } else {
        await api(`${base}/tests/${targetId}/findings`, { method: 'POST', body: JSON.stringify(payload) });
      }
      mode = 'list';
      form = null;
      const data = await api(`${base}/tests/${targetId}/findings`);
      findingsList = data.findings;
      message = { text: 'Saved.', kind: 'ok' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      saveBusy = false;
      render();
    }
  }

  async function deleteFinding(f) {
    if (deleteArmed !== f.id) {
      deleteArmed = f.id;
      render();
      return;
    }
    deleteArmed = null;
    try {
      await api(`${base}/tests/${targetId}/findings/${f.id}`, { method: 'DELETE', body: '{}' });
      findingsList = findingsList.filter((x) => x.id !== f.id);
      message = { text: 'Deleted.', kind: 'ok' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    }
    render();
  }

  /* --------------------------------- CVSS calculator -------------------------------- */

  function recomputeCvss() {
    const result = computeCvss31(form.cvss);
    if (result) {
      form.Risk_Matrix.CVSS_Vector = result.vector;
      form.Risk_Matrix.CVSS_Score = result.score;
      form.Risk_Matrix.Risk_Level = result.severity;
    }
    render();
  }

  function renderCvssSection() {
    const grid = el('div', { class: 'fe-cvss__grid' }, METRICS.map((m) => {
      const options = [el('option', { value: '', text: '—' }), ...m.options.map(([v, label]) => el('option', { value: v, selected: form.cvss[m.key] === v || null, text: `${v} – ${label}` }))];
      const select = el('select', { 'aria-label': m.label }, options);
      select.value = form.cvss[m.key] || '';
      select.addEventListener('change', () => { form.cvss[m.key] = select.value || undefined; recomputeCvss(); });
      return el('label', { class: 'fe-cvss__field' }, el('span', { text: m.label }), select);
    }));

    const rm = form.Risk_Matrix;
    const result = computeCvss31(form.cvss);
    const scoreLine = result
      ? `${result.score.toFixed(1)} — ${result.severity}`
      : (rm.CVSS_Score != null ? `${rm.CVSS_Score.toFixed(1)}${rm.Risk_Level ? ` — ${rm.Risk_Level}` : ''} (set from a saved vector; pick every metric above to recompute)` : 'Pick every metric to compute a score.');

    const levelSelect = el('select', { 'aria-label': 'Risk level' },
      el('option', { value: '', text: '(none)' }),
      ['None', 'Low', 'Medium', 'High', 'Critical'].map((lv) => el('option', { value: lv, selected: rm.Risk_Level === lv || null, text: lv })));
    levelSelect.value = rm.Risk_Level || '';
    levelSelect.addEventListener('change', () => { form.Risk_Matrix.Risk_Level = levelSelect.value || null; });

    return el('section', { class: 'mouse__sec fe-cvss' },
      el('div', { class: 'mouse__h', text: 'CVSS 3.1 matrix' }),
      grid,
      el('p', { class: 'fe-cvss__score' }, el('strong', { text: 'Base score: ' }), scoreLine),
      el('label', { class: 'fe-cvss__field' }, el('span', { text: 'Risk level (recalculated above; override here if needed)' }), levelSelect),
      rm.CVSS_Vector ? el('p', { class: 'mouse__status mono', text: rm.CVSS_Vector }) : null);
  }

  /* ----------------------------------- plain fields ---------------------------------- */

  function textField(label, obj, key, { area = false, placeholder } = {}) {
    const input = el(area ? 'textarea' : 'input', { placeholder: placeholder || '', ...(area ? { rows: '3' } : { type: 'text' }) });
    input.value = obj[key] || '';
    input.addEventListener('input', () => { obj[key] = input.value; });
    return el('label', { class: 'fe-field' }, el('span', { text: label }), input);
  }

  function listField(label, arr, placeholder) {
    const rows = arr.map((_, i) => {
      const input = el('input', { type: 'text', value: arr[i], placeholder });
      input.addEventListener('input', () => { arr[i] = input.value; });
      const removeBtn = el('button', { type: 'button', class: 'fe-list__rm', 'aria-label': `Remove item ${i + 1}`, text: '×' });
      removeBtn.addEventListener('click', () => { arr.splice(i, 1); renderForm(); });
      return el('div', { class: 'fe-list__row' }, input, removeBtn);
    });
    const addBtn = el('button', { type: 'button', class: 'linkbtn', text: '+ Add' });
    addBtn.addEventListener('click', () => { arr.push(''); renderForm(); });
    return el('div', { class: 'fe-field fe-list' }, el('span', { text: label }), rows, addBtn);
  }

  function renderForm() {
    const kids = [];
    kids.push(el('p', { class: 'mouse__status', text: `New finding for ${targetId} — ${targetMeta?.name || ''}` }));

    kids.push(renderCvssSection());

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'CWE information' }),
      textField('CWE number', form.CWE_Information, 'CWE_Number', { placeholder: 'CWE-79' }),
      textField('CWE name', form.CWE_Information, 'CWE_Name'),
      textField('Description', form.CWE_Information, 'CWE_Description', { area: true }),
      textField('Why this matters', form.CWE_Information, 'CWE_Why', { area: true }),
      textField('Impact', form.CWE_Information, 'CWE_Impact', { area: true })));

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Remediation' }),
      textField('Remediation statement', form.Remediation, 'Remediation_Statement', { area: true }),
      textField('Recommendation', form.Remediation, 'Recommendation', { area: true }),
      listField('Additional recommendations', form.Remediation.Additional_recommendations, 'Another recommendation')));

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Affected URLs' }),
      listField('URLs', form.Affected_URLs.URLs, 'https://...')));

    const saveBtn = el('button', { type: 'button', class: 'linkbtn', disabled: saveBusy || null, text: saveBusy ? 'Saving...' : 'Save finding' });
    saveBtn.addEventListener('click', saveForm);
    const cancelBtn = el('button', { type: 'button', class: 'linkbtn', disabled: saveBusy || null, text: 'Cancel' });
    cancelBtn.addEventListener('click', cancelForm);
    kids.push(el('div', { class: 'mouse__row' }, saveBtn, cancelBtn));

    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  function findingRow(f) {
    const rm = f.Risk_Matrix || {};
    const cwe = f.CWE_Information || {};
    const editBtn = el('button', { type: 'button', class: 'linkbtn', text: 'Edit' });
    editBtn.addEventListener('click', () => startEditFinding(f));
    const delBtn = el('button', {
      type: 'button', class: `linkbtn${deleteArmed === f.id ? ' is-error' : ''}`,
      text: deleteArmed === f.id ? 'Confirm delete?' : 'Delete',
    });
    delBtn.addEventListener('click', () => deleteFinding(f));
    return el('li', { class: 'fe-list__item' },
      el('div', { class: 'fe-list__item-head' },
        el('span', { class: `fe-chip fe-chip--${(rm.Risk_Level || 'none').toLowerCase()}`, text: rm.Risk_Level || 'No level' }),
        el('span', { text: cwe.CWE_Name || cwe.CWE_Number || '(untitled finding)' })),
      rm.CVSS_Score != null ? el('p', { class: 'mouse__status', text: `CVSS ${rm.CVSS_Score}${rm.CVSS_Vector ? ` — ${rm.CVSS_Vector}` : ''}` }) : null,
      el('div', { class: 'mouse__row' }, editBtn, delBtn));
  }

  function render() {
    if (mode === 'form' && form) { renderForm(); return; }

    const kids = [];
    if (!targetId) {
      kids.push(el('p', { class: 'mouse__status', text: 'Select a WSTG item in the checklist, then use the "+" button to add a finding.' }));
    } else {
      kids.push(el('p', { class: 'mouse__status', text: `${targetId} — ${targetMeta?.name || ''}` }));
      if (listBusy) {
        kids.push(el('p', { class: 'mouse__status', text: 'Loading...' }));
      } else {
        const addBtn2 = el('button', { type: 'button', class: 'linkbtn', text: '+ New finding' });
        addBtn2.addEventListener('click', () => startNewFinding(targetId, targetMeta));
        kids.push(el('div', { class: 'mouse__row' }, addBtn2));
        kids.push(findingsList.length
          ? el('ul', { class: 'fe-list' }, findingsList.map(findingRow))
          : el('p', { class: 'mouse__status', text: 'No findings recorded for this item yet.' }));
      }
    }
    if (message && mode === 'list') kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  render();
  renderPopup();

  return { setCurrent };
}
