import { el, api } from './common.js';

/**
 * Intruder Loader panel: launch/stop a local Burp process (java -jar <path>) and show the
 * shared Intruder queue's pending/sent counts for this project. Mirrors callback-side.js.
 *
 * What this panel can't do: make Burp load the watcher extension. That's a one-time setting
 * inside Burp itself (Settings > Extensions > Add, then "Automatically reload extensions on
 * startup") - see Settings/Configurations/Intruder_Loader/intruder_loader_extension.py's own
 * docstring for the exact steps. Once that's set, every later Burp launch - including the one
 * this panel's Launch button starts - comes up with the extension already running.
 */
export function initIntruderSide({ base }) {
  const side = document.querySelector('#il-side');
  const panel = document.querySelector('#il-panel');
  const toggle = document.querySelector('#il-toggle');

  let status = { running: false, queue: { pending: 0, sent: 0 } };
  let config = { javaBin: 'java', burpJarPath: '', projectFile: '', extraArgs: [] };
  let configLoaded = false;
  let busy = { launch: false, save: false };
  let message = null;
  let pollTimer = null;

  function setOpen(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Intruder Loader panel' : 'Open the Intruder Loader panel');
    if (open) {
      if (!configLoaded) loadConfig();
      refreshStatus();
      if (!pollTimer) pollTimer = setInterval(refreshStatus, 4000);
    } else if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
  toggle.addEventListener('click', () => setOpen(side.hidden));

  async function loadConfig() {
    try {
      config = await api(`${base}/intruder-loader/config`);
      configLoaded = true;
      render();
    } catch { /* fields just stay at their defaults */ }
  }

  async function refreshStatus() {
    try {
      status = await api(`${base}/intruder-loader/status`);
      render();
    } catch { /* a transient failure here just leaves the last known status showing */ }
  }

  async function saveConfig() {
    if (busy.save) return;
    busy.save = true;
    render();
    try {
      config = await api(`${base}/intruder-loader/config`, { method: 'POST', body: JSON.stringify(config) });
      message = { text: 'Saved.', kind: 'ok' };
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.save = false;
      render();
    }
  }

  async function toggleLaunch() {
    if (busy.launch) return;
    busy.launch = true;
    render();
    try {
      if (status.running) {
        await api(`${base}/intruder-loader/stop`, { method: 'POST', body: '{}' });
        message = { text: 'Stopped.', kind: 'ok' };
      } else {
        const r = await api(`${base}/intruder-loader/launch`, { method: 'POST', body: '{}' });
        message = { text: `Burp launched (pid ${r.pid}). If "Automatically reload extensions on startup" is on, the watcher extension is already running inside it.`, kind: 'ok' };
      }
    } catch (e) {
      message = { text: e.message, kind: 'error' };
    } finally {
      busy.launch = false;
      await refreshStatus();
      render();
    }
  }

  function field(label, key, placeholder) {
    const input = el('input', { type: 'text', value: config[key] || '', placeholder: placeholder || '', class: 'mouse__cap' });
    input.addEventListener('input', () => { config[key] = input.value; });
    return el('label', { class: 'mouse__field' }, el('span', { text: label }), input);
  }

  function render() {
    const kids = [];

    const launchBtn = el('button', {
      type: 'button', class: 'linkbtn', disabled: busy.launch || null,
      text: busy.launch ? 'Working...' : status.running ? 'Stop Burp' : 'Launch Burp',
    });
    launchBtn.addEventListener('click', toggleLaunch);

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Burp process' }),
      el('div', { class: 'mouse__row' },
        el('span', { class: `mouse__dot${status.running ? ' is-on' : ''}`, 'aria-hidden': 'true' }),
        el('span', { text: status.running ? `Running (pid ${status.pid})` : 'Not running' })),
      field('Java binary', 'javaBin', 'java'),
      field('Burp jar path', 'burpJarPath', '/path/to/burpsuite_pro.jar'),
      field('Project file (optional)', 'projectFile', '/path/to/engagement.burp'),
      el('div', { class: 'mouse__row' },
        (() => {
          const saveBtn = el('button', { type: 'button', class: 'linkbtn', disabled: busy.save || null, text: busy.save ? 'Saving...' : 'Save' });
          saveBtn.addEventListener('click', saveConfig);
          return saveBtn;
        })(),
        launchBtn),
      el('p', { class: 'mouse__status', text: 'This only starts the java process - it cannot make Burp load the watcher extension itself. Load it once in Burp\'s own Settings → Extensions → Add, then turn on "Automatically reload extensions on startup"; every launch from here afterward comes up with it already running.' }),
      status.log ? el('div', { class: 'mouse__log', text: status.log }) : null));

    const q = status.queue || { pending: 0, sent: 0 };
    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Intruder queue' }),
      el('p', { class: 'mouse__status', text: `${q.pending} pending · ${q.sent} sent for this project. Pushed from the Threat-Model list in the request viewer ("Push to Testing").` })));

    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : message.kind === 'ok' ? ' is-ok' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  render();

  return { open: () => setOpen(true) };
}
