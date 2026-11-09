import { el, api } from './common.js';

/**
 * Mouse_Tool panel: pick the active WSTG item, start/stop the clipboard interceptor listener,
 * and run the injection test-data orchestrator (split string + cap percent). Mirrors xml-side.js:
 * the toggle button opens an aside, state lives in this module, render() redraws from it.
 */
export function initMouseSide({ base }) {
  const side = document.querySelector('#mouse-side');
  const panel = document.querySelector('#mouse-panel');
  const toggle = document.querySelector('#mouse-toggle');

  let targets = null;          // [{wstg_id, name, side}]
  let active = null;           // wstg_id or null
  let listener = { running: false };
  let orchForm = { split: '', capPercent: '10' };
  let orchResult = null;       // { ok, code, stdout, stderr } | null
  let serverSideResult = null; // { ok, code, stdout, stderr } | null
  let busy = { active: false, listener: false, orchestrator: false, serverSide: false };
  let message = null;          // { text, kind }
  let pollTimer = null;

  function setOpen(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Mouse Tool panel' : 'Open the Mouse Tool panel');
    if (open) {
      if (!targets) refresh();
      if (!pollTimer) pollTimer = setInterval(refreshListenerStatus, 4000);
    } else if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
  toggle.addEventListener('click', () => setOpen(side.hidden));

  async function refresh() {
    try {
      const [t, a, l] = await Promise.all([
        api(`${base}/mouse`),
        api(`${base}/mouse/active`),
        api(`${base}/mouse/listener/status`),
      ]);
      targets = t.targets;
      active = a.wstg_id;
      listener = l;
      message = null;
    } catch (e) {
      targets = [];
      message = { text: e.message, kind: 'error' };
    }
    render();
  }

  async function refreshListenerStatus() {
    try {
      listener = await api(`${base}/mouse/listener/status`);
      render();
    } catch { /* a transient failure here just leaves the last known status showing */ }
  }

  async function chooseActive(wstgId) {
    if (busy.active || wstgId === active) return;
    busy.active = true;
    render();
    try {
      await api(`${base}/mouse/active`, { method: 'PUT', body: JSON.stringify({ wstg_id: wstgId }) });
      active = wstgId;
      message = { text: `Active item: ${wstgId}`, kind: 'ok' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.active = false;
      render();
    }
  }

  async function toggleListener() {
    if (busy.listener) return;
    busy.listener = true;
    render();
    try {
      const path = listener.running ? 'stop' : 'start';
      listener = await api(`${base}/mouse/listener/${path}`, { method: 'POST', body: '{}' });
      if (path === 'stop') listener = { running: false };
      message = { text: listener.running ? `Listener started (pid ${listener.pid}).` : 'Listener stopped.', kind: 'ok' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.listener = false;
      await refreshListenerStatus();
      render();
    }
  }

  async function runOrchestrator() {
    if (busy.orchestrator) return;
    if (!orchForm.split.trim()) {
      message = { text: 'Enter the split string first.', kind: 'error' };
      render();
      return;
    }
    busy.orchestrator = true;
    orchResult = null;
    message = { text: 'Running shuttle_gen, rebuild_tag and tag_combine across every item...', kind: 'info' };
    render();
    try {
      orchResult = await api(`${base}/mouse/orchestrator/run`, {
        method: 'POST',
        body: JSON.stringify({ split: orchForm.split, capPercent: Number(orchForm.capPercent) || 10, side: 'Client_Side' }),
      });
      message = { text: orchResult.ok ? 'Generation finished.' : 'Generation finished with errors (see log below).', kind: orchResult.ok ? 'ok' : 'error' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.orchestrator = false;
      render();
    }
  }

  async function runServerSide() {
    if (busy.serverSide) return;
    busy.serverSide = true;
    serverSideResult = null;
    message = { text: 'Generating server-side wordlists...', kind: 'info' };
    render();
    try {
      serverSideResult = await api(`${base}/mouse/server-side/run`, { method: 'POST', body: '{}' });
      message = { text: serverSideResult.ok ? 'Wordlists written.' : 'Finished with errors (see log below).', kind: serverSideResult.ok ? 'ok' : 'error' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.serverSide = false;
      render();
    }
  }

  function render() {
    const kids = [];

    // ---- active item ----
    const options = (targets || []).map((t) => el('option', { value: t.wstg_id, selected: t.wstg_id === active || null }, `${t.wstg_id.replace('WSTG-', '')} — ${t.name}`));
    const select = el('select', { disabled: busy.active || !targets?.length || null }, options.length ? options : [el('option', { value: '', text: '(no items in mouse_tool.json)' })]);
    select.addEventListener('change', () => chooseActive(select.value));
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Active WSTG item' }),
      el('div', { class: 'mouse__row' }, select)));

    // ---- listener start/stop ----
    const btn = el('button', {
      type: 'button', class: 'linkbtn', disabled: busy.listener || null,
      text: busy.listener ? 'Working...' : listener.running ? 'Stop listener' : 'Start listener',
    });
    btn.addEventListener('click', toggleListener);
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Clipboard interceptor' }),
      el('div', { class: 'mouse__row' },
        el('span', { class: `mouse__dot${listener.running ? ' is-on' : ''}`, 'aria-hidden': 'true' }),
        el('span', { text: listener.running ? `Running (pid ${listener.pid})` : 'Stopped' }),
        btn),
      listener.log ? el('div', { class: 'mouse__log', text: listener.log }) : null));

    // ---- orchestrator run ----
    const splitInput = el('input', { type: 'text', value: orchForm.split, placeholder: 'string to split the tag on' });
    splitInput.addEventListener('input', () => { orchForm.split = splitInput.value; });
    const capInput = el('input', { type: 'number', min: '1', max: '100', value: orchForm.capPercent, class: 'mouse__cap' });
    capInput.addEventListener('input', () => { orchForm.capPercent = capInput.value; });
    const runBtn = el('button', { type: 'button', class: 'linkbtn', disabled: busy.orchestrator || null, text: busy.orchestrator ? 'Running...' : 'Generate test data' });
    runBtn.addEventListener('click', runOrchestrator);

    const logText = orchResult ? [orchResult.stdout, orchResult.stderr].filter(Boolean).join('\n') : '';
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Injection test-data pipeline (client-side)' }),
      el('div', { class: 'mouse__field' }, el('label', { text: 'Split string (reused for every item)' }), splitInput),
      el('div', { class: 'mouse__row' },
        el('div', { class: 'mouse__field' }, el('label', { text: 'Cap %' }), capInput),
        runBtn),
      logText ? el('div', { class: 'mouse__log', text: logText }) : null));

    // ---- server-side wordlist run ----
    const ssBtn = el('button', { type: 'button', class: 'linkbtn', disabled: busy.serverSide || null, text: busy.serverSide ? 'Running...' : 'Generate server-side wordlists' });
    ssBtn.addEventListener('click', runServerSide);
    const ssLogText = serverSideResult ? [serverSideResult.stdout, serverSideResult.stderr].filter(Boolean).join('\n') : '';
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Server-side wordlist pipeline' }),
      el('div', { class: 'mouse__row' }, ssBtn),
      ssLogText ? el('div', { class: 'mouse__log', text: ssLogText }) : null));

    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  return { open: () => setOpen(true), refresh };
}
