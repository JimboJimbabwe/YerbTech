import { el, api, fmtBytes, copyText } from './common.js';

/**
 * Burp-style request viewer, upside down on purpose: the request sits in the large box on top and
 * the list of requests in the short box underneath. Request side only for now.
 * Everything is rendered with textContent, so hostile request data stays inert text.
 */
const PAGE = 200;

/** The list shows path and query only (the host is in the header strip); the full URL is the tooltip. */
function shortUrl(u) {
  try {
    const x = new URL(u);
    return `${x.pathname}${x.search}` || '/';
  } catch {
    return u;
  }
}

export function initViewer({ base, openSidebar }) {
  const root = document.querySelector('#viewer');

  let testId = null;
  let info = null; // { eligible, datasets }
  let mode = 'baseline'; // 'baseline' (raw XML datasets) | 'threat-model'
  let dataset = null; // dataset id (a file name in the assessment's Inputs/XML) - baseline mode only
  let query = '';
  let loaded = 0;
  let matched = 0;
  let total = 0;
  let selected = null;
  let current = null; // the request on show
  let token = 0;
  let loadingMore = false;
  let tmMeta = null; // { generated_at, model } from the last threat-model list fetch
  let tmItems = []; // the rows currently shown in threat-model mode (never paginated)
  let pushSelected = new Set(); // item_index values checked for "Push to Testing"
  let pushBusy = false;
  let pushMsg = null; // { text, kind } | null

  // Static frame, built once.
  const head = el('header', { class: 'vw__head' });
  const display = el('pre', { class: 'vw__req mono', tabindex: '0', 'aria-label': 'Request' });
  const meta = el('div', { class: 'vw__meta' });
  const rankRow = el('div', { class: 'vw__rank', hidden: true });
  const list = el('ul', { class: 'vw__list', role: 'listbox', 'aria-label': 'Requests' });
  // Shown only in Threat-Model mode, with at least one row: select rows below, then push them
  // into the shared Intruder queue (lib/threatModel.js's pushToQueue, via the Intruder Loader
  // extension running inside Burp - see that extension script's own docstring).
  const pushBar = el('div', { class: 'vw__pushbar', hidden: true });
  const listBox = el('div', { class: 'vw__listbox' }, pushBar, list);
  const empty = el('div', { class: 'vw__empty' });
  // The dataset rail: one button per applicable XML category (raw/authorization/authentication/
  // input surface - whichever this assessment is eligible for, from xml_routing.json), plus a
  // Threat-Model button. Thin strip under the request+list stage, same spot regardless of mode.
  const rail = el('div', { class: 'vw__rail', role: 'tablist', 'aria-label': 'Dataset', hidden: true });
  const stage = el('div', { class: 'vw__stage' },
    el('section', { class: 'vw__box vw__box--req', 'aria-label': 'Request' }, meta, rankRow, display),
    listBox);
  const response = el('section', { class: 'vw__box vw__box--resp', 'aria-label': 'Response (not built yet)' },
    el('p', { class: 'vw__soon', text: 'Response' }), el('p', { text: 'Not built yet. This box will show the response for the request on the left.' }));
  root.replaceChildren(head, empty, el('div', { class: 'vw__cols' }, stage, response), rail);
  const cols = root.querySelector('.vw__cols');

  listBox.addEventListener('scroll', () => {
    if (listBox.scrollTop + listBox.clientHeight >= listBox.scrollHeight - 80) loadMore();
  });
  list.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const rows = [...list.querySelectorAll('.vw__row')];
    const i = rows.indexOf(document.activeElement);
    const next = rows[i + (e.key === 'ArrowDown' ? 1 : -1)];
    if (next) { e.preventDefault(); next.focus(); next.click(); }
    if (e.key === 'ArrowDown' && !next) loadMore();
  });

  function showEmpty(title, text, action) {
    cols.hidden = true;
    empty.hidden = false;
    empty.replaceChildren(...[el('strong', { text: title }), text ? el('p', { text }) : null, action].filter(Boolean));
  }

  function showStage() {
    cols.hidden = false;
    empty.hidden = true;
  }

  function renderHead() {
    const parts = [el('h2', { class: 'vw__title', text: mode === 'threat-model' ? 'Threat Model' : 'Burp Proxy XML' }), el('span', { class: 'vw__id mono', text: testId })];
    if (mode === 'threat-model') {
      if (tmMeta && tmMeta.model) parts.push(el('span', { class: 'vw__chip', text: tmMeta.model, title: `Generated ${tmMeta.generated_at || ''}` }));
    } else if (info && info.datasets.length) {
      const f = el('input', { type: 'search', class: 'vw__filter', placeholder: 'Filter: method, URL, status', 'aria-label': 'Filter requests', value: query });
      let timer = null;
      f.addEventListener('input', () => {
        clearTimeout(timer);
        timer = setTimeout(() => { query = f.value.trim(); reload(); }, 200);
      });
      parts.push(f);
    }
    head.replaceChildren(...parts);
  }

  /** The thin button rail under the stage: one per XML category this assessment is
   * eligible for (whatever info.datasets currently holds), plus Threat-Model always
   * last - that one works independently of whether any raw XML has been uploaded,
   * since Threat_Model.json comes from a separate pipeline, not xml_routing uploads. */
  function renderRail() {
    const buttons = (info ? info.datasets : []).map((d) => {
      const b = el('button', { type: 'button', role: 'tab', class: 'vw__railbtn', 'aria-selected': String(mode === 'baseline' && d.id === dataset), title: d.id, text: d.label });
      b.addEventListener('click', () => {
        if (mode === 'baseline' && d.id === dataset) return;
        mode = 'baseline'; dataset = d.id; selected = null; current = null;
        renderHead(); renderRail(); renderPushBar(); reload();
      });
      return b;
    });
    const tm = el('button', { type: 'button', role: 'tab', class: 'vw__railbtn vw__railbtn--tm', 'aria-selected': String(mode === 'threat-model'), text: 'Threat-Model' });
    tm.addEventListener('click', () => {
      if (mode === 'threat-model') return;
      mode = 'threat-model'; selected = null; current = null;
      renderHead(); renderRail(); loadThreatModel();
    });
    buttons.push(tm);
    rail.replaceChildren(...buttons);
  }

  /** Called when the operator picks an assessment in the checklist (or after an upload). */
  async function setAssessment(id, { keep = false } = {}) {
    const mine = ++token;
    if (!keep) { testId = id; mode = 'baseline'; dataset = null; query = ''; selected = null; current = null; info = null; tmMeta = null; pushSelected = new Set(); pushMsg = null; tmItems = []; }
    head.replaceChildren();
    rail.hidden = !id;
    renderPushBar();
    if (!id) {
      showEmpty('No assessment selected', 'Pick an assessment in the checklist on the right to see its Burp requests.');
      return;
    }
    showEmpty('Loading…', '');
    try {
      const data = await api(`${base}/tests/${id}/xml`);
      if (mine !== token) return;
      info = data;
    } catch (e) {
      if (mine !== token) return;
      info = null;
      showEmpty('Could not load the XML for this assessment', e.message);
      renderRail();
      return;
    }
    if (mode === 'threat-model') { renderHead(); renderRail(); showStage(); loadThreatModel(); return; }
    if (!info.eligible.length) {
      renderHead();
      renderRail();
      showEmpty('No Burp XML applies to this assessment', `${testId} is not fed by any Burp Proxy XML category in xml_routing.json, or its entry in wstg_io.json has no Burp-typed XML input. (Threat-Model, below, works independently of this.)`);
      return;
    }
    if (!info.datasets.length) {
      renderHead();
      renderRail();
      const names = info.eligible.map((e) => e.label.toLowerCase()).join(' and ');
      const btn = el('button', { type: 'button', class: 'pill pill--quiet', text: 'Open the XML panel' });
      btn.addEventListener('click', openSidebar);
      const waiting = info.eligible.some((e) => e.uploaded && !e.present);
      showEmpty(`${testId} takes ${names} Burp XML`, waiting
        ? 'The file is uploaded but has not been copied into this assessment yet. Re-adding it will copy it.'
        : 'Nothing has been added for it yet. Add the file in the XML panel and it will appear here.', btn);
      return;
    }
    if (!dataset || !info.datasets.some((d) => d.id === dataset)) dataset = info.datasets[0].id;
    renderHead();
    renderRail();
    showStage();
    reload();
  }

  async function reload() {
    const mine = ++token;
    loaded = 0;
    list.replaceChildren(el('li', { class: 'vw__note', text: 'Reading the XML…' }));
    listBox.scrollTop = 0;
    if (!current) showRequest(null);
    try {
      const page = await fetchPage(0);
      if (mine !== token) return;
      total = page.total;
      matched = page.matched;
      list.replaceChildren();
      appendRows(page.items);
      if (!page.items.length) {
        list.append(el('li', { class: 'vw__note', text: total ? 'No requests match the filter.' : `No requests found in this file${page.parseErrors ? ' (it did not parse as Burp XML)' : ''}.` }));
      } else if (!current || !page.items.some((i) => i.index === selected)) {
        select(page.items[0].index);
      }
      updateCount();
    } catch (e) {
      if (mine !== token) return;
      list.replaceChildren(el('li', { class: 'vw__note is-error', text: e.message }));
    }
  }

  function fetchPage(offset) {
    const q = new URLSearchParams({ dataset, offset: String(offset), limit: String(PAGE) });
    if (query) q.set('q', query);
    return api(`${base}/tests/${testId}/requests?${q}`);
  }

  async function loadMore() {
    if (loadingMore || loaded >= matched) return;
    loadingMore = true;
    const mine = token;
    try {
      const page = await fetchPage(loaded);
      if (mine !== token) return;
      appendRows(page.items);
      updateCount();
    } catch { /* leave the list as is; scrolling again retries */ } finally {
      loadingMore = false;
    }
  }

  function appendRows(items) {
    loaded += items.length;
    list.append(...items.map((it) => {
      const row = el('button', { type: 'button', class: `vw__row${it.index === selected ? ' is-selected' : ''}`, role: 'option', 'aria-selected': String(it.index === selected), 'data-index': String(it.index) },
        el('span', { class: 'vw__n mono', text: String(it.index + 1) }),
        el('span', { class: `vw__m vw__m--${/^[A-Z]+$/.test(it.method) ? it.method.toLowerCase() : 'x'}`, text: it.method }),
        el('span', { class: 'vw__u mono', text: shortUrl(it.url), title: it.url }),
        el('span', { class: `vw__s vw__s--${String(it.status)[0] || 'x'}`, text: it.status }));
      row.addEventListener('click', () => select(it.index));
      return el('li', {}, row);
    }));
  }

  function updateCount() {
    const shown = query ? `${matched.toLocaleString()} of ${total.toLocaleString()}` : total.toLocaleString();
    const c = head.querySelector('.vw__count') || head.appendChild(el('span', { class: 'vw__count' }));
    c.textContent = `${shown} ${total === 1 ? 'request' : 'requests'}${loaded < matched ? ` · ${loaded.toLocaleString()} loaded` : ''}`;
  }

  async function select(index) {
    selected = index;
    for (const r of list.querySelectorAll('.vw__row')) {
      const on = r.dataset.index === String(index);
      r.classList.toggle('is-selected', on);
      r.setAttribute('aria-selected', String(on));
      if (on) r.scrollIntoView({ block: 'nearest' });
    }
    const mine = token;
    try {
      const r = await api(`${base}/tests/${testId}/requests/${index}?dataset=${encodeURIComponent(dataset)}`);
      if (mine !== token || selected !== index) return;
      showRequest(r);
    } catch (e) {
      if (mine !== token || selected !== index) return;
      showRequest(null, e.message);
    }
  }

  /* --------------------------- Threat-Model mode --------------------------- */

  async function loadThreatModel() {
    const mine = ++token;
    loaded = 0;
    pushSelected = new Set();
    pushMsg = null;
    tmItems = [];
    renderPushBar();
    list.replaceChildren(el('li', { class: 'vw__note', text: 'Loading the Threat Model…' }));
    listBox.scrollTop = 0;
    if (!current) showRequest(null);
    try {
      const data = await api(`${base}/tests/${testId}/threat-model`);
      if (mine !== token) return;
      tmMeta = { generated_at: data.generated_at, model: data.model };
      renderHead();
      if (!data.items.length) {
        list.replaceChildren(el('li', {
          class: 'vw__note',
          text: 'No Threat Model data for this assessment yet. Run the parameter mapper + ranking scripts (tools/param_mapper) to generate Threat_Model.json.',
        }));
        renderPushBar();
        return;
      }
      appendThreatModelRows(data.items);
      if (!current || !data.items.some((i) => i.item_index === selected)) selectThreatModelItem(data.items[0].item_index);
      total = matched = data.items.length;
      loaded = data.items.length;
    } catch (e) {
      if (mine !== token) return;
      list.replaceChildren(el('li', { class: 'vw__note is-error', text: e.message }));
      renderPushBar();
    }
  }

  function appendThreatModelRows(items) {
    tmItems = items;
    list.replaceChildren(...items.map((it) => {
      const badge = it.best_match ? `${it.best_match} · ${it.top_confidence}` : (it.ranked_count ? 'no match' : '—');
      const cb = el('input', {
        type: 'checkbox', class: 'vw__tmcb', 'aria-label': `Select ${it.method} ${shortUrl(it.path)} to push to testing`,
        checked: pushSelected.has(it.item_index) || null,
      });
      cb.addEventListener('change', () => {
        if (cb.checked) pushSelected.add(it.item_index); else pushSelected.delete(it.item_index);
        renderPushBar();
      });
      const row = el('button', {
        type: 'button', class: `vw__row vw__row--tm${it.item_index === selected ? ' is-selected' : ''}`, role: 'option',
        'aria-selected': String(it.item_index === selected), 'data-index': String(it.item_index),
      },
        el('span', { class: 'vw__n mono', text: String(it.xml_index) }),
        el('span', { class: `vw__m vw__m--${/^[A-Z]+$/.test(it.method) ? it.method.toLowerCase() : 'x'}`, text: it.method }),
        el('span', { class: 'vw__u mono', text: shortUrl(it.path), title: it.path }),
        el('span', { class: `vw__s${it.best_match ? ' vw__s--top' : ''}`, text: badge, title: badge }));
      row.addEventListener('click', () => selectThreatModelItem(it.item_index));
      return el('li', { class: 'vw__li--tm' }, cb, row);
    }));
    renderPushBar();
  }

  /** The select-all + "Push N to Testing" strip above the Threat-Model list. Hidden outside
   * threat-model mode or when there is nothing to push. */
  function renderPushBar() {
    if (mode !== 'threat-model' || !tmItems.length) {
      pushBar.hidden = true;
      pushBar.replaceChildren();
      return;
    }
    pushBar.hidden = false;
    const allOn = tmItems.every((it) => pushSelected.has(it.item_index));
    const selectAll = el('input', { type: 'checkbox', class: 'vw__tmcb', 'aria-label': 'Select all', checked: allOn || null });
    selectAll.addEventListener('change', () => {
      if (selectAll.checked) tmItems.forEach((it) => pushSelected.add(it.item_index));
      else pushSelected.clear();
      appendThreatModelRows(tmItems);
    });
    const btn = el('button', {
      type: 'button', class: 'linkbtn', disabled: (pushBusy || !pushSelected.size) || null,
      text: pushBusy ? 'Pushing…' : `Push ${pushSelected.size} to Testing`,
    });
    btn.addEventListener('click', pushSelectedToTesting);
    const kids = [selectAll, el('span', { class: 'vw__pushcount', text: `${pushSelected.size} selected` }), btn];
    if (pushMsg) kids.push(el('span', { class: `vw__pushmsg${pushMsg.kind === 'error' ? ' is-error' : ''}`, text: pushMsg.text }));
    pushBar.replaceChildren(...kids);
  }

  async function pushSelectedToTesting() {
    if (pushBusy || !pushSelected.size) return;
    pushBusy = true;
    pushMsg = null;
    renderPushBar();
    try {
      const body = JSON.stringify({ item_indexes: [...pushSelected] });
      const result = await api(`${base}/tests/${testId}/threat-model/push`, { method: 'POST', body });
      const n = result.pushed.length;
      const bits = [n ? `Pushed ${n} to the Intruder queue.` : 'Nothing could be pushed.'];
      if (result.skipped.length) bits.push(`${result.skipped.length} skipped (${result.skipped[0].reason}${result.skipped.length > 1 ? ', ...' : ''}).`);
      pushMsg = { text: bits.join(' '), kind: n ? 'ok' : 'error' };
      pushSelected.clear();
    } catch (e) {
      pushMsg = { text: e.message, kind: 'error' };
    } finally {
      pushBusy = false;
      renderPushBar();
    }
  }

  async function selectThreatModelItem(itemIndex) {
    selected = itemIndex;
    for (const r of list.querySelectorAll('.vw__row')) {
      const on = r.dataset.index === String(itemIndex);
      r.classList.toggle('is-selected', on);
      r.setAttribute('aria-selected', String(on));
      if (on) r.scrollIntoView({ block: 'nearest' });
    }
    const mine = token;
    try {
      const r = await api(`${base}/tests/${testId}/threat-model/${itemIndex}/request`);
      if (mine !== token || selected !== itemIndex) return;
      showRequest(r, null, r.ranking);
    } catch (e) {
      if (mine !== token || selected !== itemIndex) return;
      showRequest(null, e.message);
    }
  }

  function showRequest(r, error, ranking) {
    current = r;
    meta.replaceChildren();
    if (!ranking) {
      rankRow.hidden = true;
      rankRow.replaceChildren();
    } else {
      rankRow.hidden = false;
      const parts = ranking.ranked_parameters.length
        ? ranking.ranked_parameters.map((p, i) => el('span', { class: `vw__rankchip${i === 0 ? ' is-top' : ''}`, title: p.reason, text: `${p.parameter} · ${p.confidence}` }))
        : [el('span', { class: 'vw__rankchip', text: 'No candidate parameter ranked above none.' })];
      rankRow.replaceChildren(el('span', { class: 'vw__rankhead', text: 'Threat Model:' }), ...parts);
    }
    if (!r) {
      display.replaceChildren(document.createTextNode(error || 'Select a request from the list below.'));
      return;
    }
    const btn = el('button', { type: 'button', class: 'linkbtn', text: 'Copy request' });
    btn.addEventListener('click', async () => {
      try { await copyText(r.text); btn.textContent = 'Copied'; } catch { btn.textContent = 'Copy blocked'; }
      setTimeout(() => { btn.textContent = 'Copy request'; }, 1500);
    });
    meta.append(
      el('span', { class: `vw__m vw__m--${/^[A-Z]+$/.test(r.method) ? r.method.toLowerCase() : 'x'}`, text: r.method }),
      el('span', { class: 'vw__metaurl mono', text: r.url }),
      el('span', { class: 'vw__metasz', text: `#${r.index + 1} · ${fmtBytes(r.bytes)}${r.truncated ? ' · cut at 1 MB' : ''}` }),
      btn);

    // Request line and header names get colour; the body is left as one plain text node.
    const text = r.text.replace(/\r\n/g, '\n');
    const split = text.indexOf('\n\n');
    const headText = split === -1 ? text : text.slice(0, split);
    const body = split === -1 ? '' : text.slice(split);
    const lines = headText.split('\n');
    const frag = document.createDocumentFragment();
    lines.forEach((line, i) => {
      if (i === 0) {
        frag.append(el('span', { class: 'rq-line', text: line }));
      } else {
        const c = line.indexOf(':');
        if (c > 0) frag.append(el('span', { class: 'rq-name', text: line.slice(0, c) }), document.createTextNode(line.slice(c)));
        else frag.append(document.createTextNode(line));
      }
      if (i < lines.length - 1) frag.append(document.createTextNode('\n'));
    });
    if (body) frag.append(document.createTextNode(body));
    display.replaceChildren(frag);
    display.scrollTop = 0;
  }

  setAssessment(null);
  return {
    setAssessment: (id) => setAssessment(id),
    refresh: () => (testId ? setAssessment(testId, { keep: true }) : null),
  };
}
