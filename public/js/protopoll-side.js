import { el, api } from './common.js';

/**
 * Prototype Pollution panel (WSTG-INJT-22). Mirrors reporting-side.js: toggle button opens an
 * aside, state lives in this module, render() redraws from it.
 *
 * Two separate things live here:
 *   - "Generate wordlists" - protopoll_wordlists.py, run to completion. Writes Body_Data.txt /
 *     URL_Hash.txt / URL_Seg.txt to the item's Inputs/Wordlists/ (where they show up in the
 *     Wordlists panel in the detail column, with Copy buttons, same as any other wordlist) and
 *     urls.txt from the item's Burp Proxy XML, if any is on file yet.
 *   - "Hash fragment opener" - hash_fragment_opener.py, the "second script": start/stop/status,
 *     same shape as the Reporting overlay, since it's also a longer-running process the operator
 *     watches and may want to cancel partway through. Needs the operator's own desktop (it opens
 *     real Firefox windows) and urls.txt + URL_Hash.txt to already exist - run "Generate
 *     wordlists" first.
 */
export function initProtopollSide({ base }) {
  const side = document.querySelector('#pp-side');
  const panel = document.querySelector('#pp-panel');
  const toggle = document.querySelector('#pp-toggle');

  let wordlists = { busy: false, result: null };
  let opener = { running: false };
  let openerBusy = false;
  let openerOpts = { delay: 10, payloadsPerUrl: 3, newWindow: false };
  let message = null;
  let pollTimer = null;

  function setOpen(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Prototype Pollution panel' : 'Open the Prototype Pollution panel');
    if (open) {
      refreshStatus();
      if (!pollTimer) pollTimer = setInterval(refreshStatus, 4000);
    } else if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
  toggle.addEventListener('click', () => setOpen(side.hidden));

  async function refreshStatus() {
    try {
      opener = await api(`${base}/protopoll/opener/status`);
    } catch { /* a transient failure here just leaves the last known status showing */ }
    render();
  }

  async function runWordlists() {
    if (wordlists.busy) return;
    wordlists.busy = true;
    wordlists.result = null;
    render();
    try {
      wordlists.result = await api(`${base}/tests/WSTG-INJT-22/protopoll-wordlists`, { method: 'POST', body: '{}' });
    } catch (e) {
      wordlists.result = { ok: false, code: 1, stdout: '', stderr: e.message };
    } finally {
      wordlists.busy = false;
      render();
    }
  }

  async function toggleOpener() {
    if (openerBusy) return;
    openerBusy = true;
    render();
    try {
      if (opener.running) {
        opener = await api(`${base}/protopoll/opener/stop`, { method: 'POST', body: '{}' });
        message = { text: 'Hash fragment opener stopped.', kind: 'ok' };
      } else {
        const body = JSON.stringify({ delay: openerOpts.delay, payloadsPerUrl: openerOpts.payloadsPerUrl, newWindow: openerOpts.newWindow });
        opener = await api(`${base}/protopoll/opener/start`, { method: 'POST', body });
        message = { text: `Opener started (pid ${opener.pid}).`, kind: 'ok' };
      }
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      openerBusy = false;
      await refreshStatus();
    }
  }

  function render() {
    const kids = [];

    // --- wordlists + urls.txt ---
    const wlBtn = el('button', { type: 'button', class: 'linkbtn', disabled: wordlists.busy || null, text: wordlists.busy ? 'Running...' : 'Generate wordlists' });
    wlBtn.addEventListener('click', runWordlists);
    const wlKids = [el('div', { class: 'mouse__row' }, wlBtn)];
    if (wordlists.result) {
      const logText = [wordlists.result.stdout, wordlists.result.stderr].filter(Boolean).join('\n');
      wlKids.push(el('p', {
        class: `mouse__status${wordlists.result.ok ? ' is-ok' : ' is-error'}`, role: 'status',
        text: wordlists.result.ok ? 'Wordlists generated (see the Wordlists panel for this item).' : 'Finished with errors (see log below).',
      }));
      if (logText) wlKids.push(el('div', { class: 'mouse__log', text: logText }));
    }
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'WSTG-INJT-22 wordlists' }),
      el('p', { class: 'mouse__status', text: 'Writes Body_Data.txt / URL_Hash.txt / URL_Seg.txt from proto_pollution_probes.json, '
        + 'and urls.txt from this item’s Burp Proxy XML (if any is on file) for the opener below.' }),
      ...wlKids));

    // --- hash fragment opener ---
    const delayInput = el('input', { type: 'number', class: 'fld__input mono', min: '0', max: '300', step: '1', style: 'width:5rem', 'aria-label': 'Delay between opens, in seconds' });
    delayInput.value = String(openerOpts.delay);
    delayInput.addEventListener('input', () => { openerOpts.delay = Number(delayInput.value) || 0; });

    const perUrlInput = el('input', { type: 'number', class: 'fld__input mono', min: '1', max: '20', step: '1', style: 'width:4rem', 'aria-label': 'Max payloads per URL' });
    perUrlInput.value = String(openerOpts.payloadsPerUrl);
    perUrlInput.addEventListener('input', () => { openerOpts.payloadsPerUrl = Number(perUrlInput.value) || 1; });

    const newWinBox = el('input', { type: 'checkbox' });
    newWinBox.checked = openerOpts.newWindow;
    newWinBox.addEventListener('change', () => { openerOpts.newWindow = newWinBox.checked; });

    const openerBtn = el('button', {
      type: 'button', class: 'linkbtn', disabled: openerBusy || null,
      text: openerBusy ? 'Working...' : opener.running ? 'Stop opener' : 'Start opener',
    });
    openerBtn.addEventListener('click', toggleOpener);

    const optsRow = opener.running ? null : el('div', { class: 'mouse__row' },
      el('label', { class: 'bld__check' }, 'delay (s) ', delayInput),
      el('label', { class: 'bld__check' }, 'max payloads/URL ', perUrlInput),
      el('label', { class: 'bld__check' }, newWinBox, ' new window (instead of new tab)'));

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Hash fragment opener' }),
      el('div', { class: 'mouse__row' },
        el('span', { class: `mouse__dot${opener.running ? ' is-on' : ''}`, 'aria-hidden': 'true' }),
        el('span', { text: opener.running ? `Running (pid ${opener.pid})` : 'Stopped' }),
        openerBtn),
      optsRow,
      el('p', { class: 'mouse__status', text: 'Opens every URL in urls.txt in Firefox with a URL_Hash.txt payload appended as the #fragment, '
        + 'one at a time, waiting between opens - never more than a few payloads against any one URL in a run. Needs the operator’s own '
        + 'desktop and Firefox, and urls.txt + URL_Hash.txt already generated above. Entirely optional - the wordlists above are the main '
        + 'deliverable either way.' }),
      opener.log ? el('div', { class: 'mouse__log', text: opener.log }) : null));

    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  render();
  return { open: () => setOpen(true) };
}
