import { el, api } from './common.js';

/**
 * Callback Suite panel: start/stop the operator's server.py (the client-side payload/callback
 * catcher), a link to open its dashboard in a new tab - it runs on its own port, a different
 * origin from this app, so it can't be embedded here - and a button to export its log into the
 * matching WSTG-CLNT-NN item's Outputs/test_outputs. Mirrors mouse-side.js.
 */
export function initCallbackSide({ base }) {
  const side = document.querySelector('#cb-side');
  const panel = document.querySelector('#cb-panel');
  const toggle = document.querySelector('#cb-toggle');

  let status = { running: false };
  let portInput = '8000';
  let exportResult = null; // { written, skipped, total_lines, matched_lines } | null
  let busy = { server: false, export: false };
  let message = null;
  let pollTimer = null;

  function setOpen(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Callback Suite panel' : 'Open the Callback Suite panel');
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
      status = await api(`${base}/callback/status`);
      render();
    } catch { /* a transient failure here just leaves the last known status showing */ }
  }

  async function toggleServer() {
    if (busy.server) return;
    busy.server = true;
    render();
    try {
      if (status.running) {
        await api(`${base}/callback/stop`, { method: 'POST', body: '{}' });
        status = { running: false };
        message = { text: 'Server stopped.', kind: 'ok' };
      } else {
        const port = Number(portInput) || 8000;
        status = await api(`${base}/callback/start`, { method: 'POST', body: JSON.stringify({ port }) });
        message = { text: `Server started on port ${status.port} (pid ${status.pid}).`, kind: 'ok' };
      }
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.server = false;
      await refreshStatus();
      render();
    }
  }

  async function exportHits() {
    if (busy.export) return;
    busy.export = true;
    exportResult = null;
    message = { text: 'Reading server.log and exporting...', kind: 'info' };
    render();
    try {
      exportResult = await api(`${base}/callback/export`, { method: 'POST', body: '{}' });
      const n = exportResult.written.length;
      message = { text: n ? `Exported hits for ${n} item(s).` : 'No matching hits in server.log yet.', kind: n ? 'ok' : 'info' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.export = false;
      render();
    }
  }

  function render() {
    const kids = [];

    const btn = el('button', {
      type: 'button', class: 'linkbtn', disabled: busy.server || null,
      text: busy.server ? 'Working...' : status.running ? 'Stop server' : 'Start server',
    });
    btn.addEventListener('click', toggleServer);
    const portField = el('input', { type: 'text', value: portInput, class: 'mouse__cap', disabled: status.running || null });
    portField.addEventListener('input', () => { portInput = portField.value; });

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Callback Suite server' }),
      el('div', { class: 'mouse__row' },
        el('span', { class: `mouse__dot${status.running ? ' is-on' : ''}`, 'aria-hidden': 'true' }),
        el('span', { text: status.running ? `Running on port ${status.port} (pid ${status.pid})` : 'Stopped' })),
      el('div', { class: 'mouse__row' },
        el('label', { class: 'mouse__field' }, el('span', { text: 'Port' }), portField),
        btn),
      status.running
        ? el('div', { class: 'mouse__row' }, el('a', { class: 'linkbtn qst__open', href: `http://127.0.0.1:${status.port}/`, target: '_blank', rel: 'noopener', text: 'Open dashboard ↗' }))
        : el('p', { class: 'mouse__status', text: 'Start the server to get a dashboard link. It binds the same way server.py always has (reachable from other machines) - that’s the point, it’s what the target calls back to.' }),
      status.log ? el('div', { class: 'mouse__log', text: status.log }) : null));

    const exportBtn = el('button', { type: 'button', class: 'linkbtn', disabled: busy.export || null, text: busy.export ? 'Exporting...' : 'Export hits to WSTG outputs' });
    exportBtn.addEventListener('click', exportHits);
    const exportKids = [el('div', { class: 'mouse__h', text: 'Hit export' }),
      el('p', { class: 'mouse__status', text: 'Reads server.log (works whether the server is running or stopped) and writes callback_hits.json + .md into each matching WSTG-CLNT item’s Outputs/test_outputs.' }),
      el('div', { class: 'mouse__row' }, exportBtn)];
    if (exportResult) {
      const lines = [];
      for (const w of exportResult.written) lines.push(`${w.wstg_id}: ${w.hits} hit(s) → ${w.json}`);
      for (const s of exportResult.skipped) lines.push(`${s.wstg_id}: skipped (${s.reason})`);
      if (!lines.length) lines.push(`No payload hits found in server.log (${exportResult.total_lines} line(s) read).`);
      exportKids.push(el('div', { class: 'mouse__log', text: lines.join('\n') }));
    }
    kids.push(el('section', { class: 'mouse__sec' }, ...exportKids));

    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  render();

  return { open: () => setOpen(true) };
}
