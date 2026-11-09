import { el, api } from './common.js';

/**
 * Reporting tool panel: start/stop the overlay (tools/reporting/reporting_overlay.py) and show
 * a read-only summary of what it has captured so far (Reporting/reporting_index.json). Mirrors
 * mouse-side.js: the toggle button opens an aside, state lives in this module, render() redraws
 * from it. The overlay itself is driven entirely from the operator's own desktop (middle-click
 * to pick a category/item, Space/Shift+scroll for the capture rectangle, F9 to capture) - this
 * panel only starts/stops the process and shows what landed.
 */
export function initReportingSide({ base }) {
  const side = document.querySelector('#rep-side');
  const panel = document.querySelector('#rep-panel');
  const toggle = document.querySelector('#rep-toggle');

  let overlay = { running: false };
  let summary = null;          // { exists, categories, items, steps } | null
  let busy = { overlay: false };
  let message = null;          // { text, kind }
  let pollTimer = null;

  function setOpen(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Reporting panel' : 'Open the Reporting panel');
    if (open) {
      refresh();
      if (!pollTimer) pollTimer = setInterval(refreshStatus, 4000);
    } else if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
  toggle.addEventListener('click', () => setOpen(side.hidden));

  async function refresh() {
    try {
      const [o, s] = await Promise.all([
        api(`${base}/reporting/overlay/status`),
        api(`${base}/reporting/summary`),
      ]);
      overlay = o;
      summary = s;
      message = null;
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    }
    render();
  }

  async function refreshStatus() {
    try {
      const [o, s] = await Promise.all([
        api(`${base}/reporting/overlay/status`),
        api(`${base}/reporting/summary`),
      ]);
      overlay = o;
      summary = s;
      render();
    } catch { /* a transient failure here just leaves the last known status showing */ }
  }

  async function toggleOverlay() {
    if (busy.overlay) return;
    busy.overlay = true;
    render();
    try {
      const path = overlay.running ? 'stop' : 'start';
      overlay = await api(`${base}/reporting/overlay/${path}`, { method: 'POST', body: '{}' });
      if (path === 'stop') overlay = { running: false };
      message = { text: overlay.running ? `Overlay started (pid ${overlay.pid}).` : 'Overlay stopped.', kind: 'ok' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.overlay = false;
      await refreshStatus();
      render();
    }
  }

  function render() {
    const kids = [];

    const btn = el('button', {
      type: 'button', class: 'linkbtn', disabled: busy.overlay || null,
      text: busy.overlay ? 'Working...' : overlay.running ? 'Stop overlay' : 'Start overlay',
    });
    btn.addEventListener('click', toggleOverlay);
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Reporting overlay' }),
      el('div', { class: 'mouse__row' },
        el('span', { class: `mouse__dot${overlay.running ? ' is-on' : ''}`, 'aria-hidden': 'true' }),
        el('span', { text: overlay.running ? `Running (pid ${overlay.pid})` : 'Stopped' }),
        btn),
      el('p', { class: 'mouse__status', text: 'Middle-click to pick a category, then an item. '
        + 'Space shows the capture rectangle, Shift (held) + scroll resizes it, F9 captures and '
        + 'asks for a description, Esc un-primes. Needs the operator’s own desktop and a mouse - '
        + 'start it here, then work on-screen.' }),
      overlay.log ? el('div', { class: 'mouse__log', text: overlay.log }) : null));

    const s = summary;
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Captured so far' }),
      s && s.exists
        ? el('div', { class: 'mouse__row' },
            el('span', { text: `${s.categories} categor${s.categories === 1 ? 'y' : 'ies'}, ${s.items} item${s.items === 1 ? '' : 's'}, ${s.steps} step${s.steps === 1 ? '' : 's'}` }))
        : el('p', { class: 'mouse__status', text: 'No Reporting/reporting_index.json yet - nothing captured for this project.' })));

    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  return { open: () => setOpen(true), refresh };
}
