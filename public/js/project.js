import { el, api, projectFromPath } from './common.js';

const name = projectFromPath();
const $ = (s) => document.querySelector(s);

$('#project-name').textContent = name;
$('#crumb-name').textContent = name;
document.title = `${name} | Red Team Audit Tool`;
$('#enter').href = `/project/${encodeURIComponent(name)}/workspace`;

const STATE_TEXT = { ok: 'Ready', warn: 'Check', fail: 'Problem' };

try {
  const pre = await api(`/api/projects/${encodeURIComponent(name)}/preflight`);
  $('#project-path').textContent = pre.path;

  const status = $('#status');
  status.replaceChildren();

  if (pre.stats.expected) {
    const pct = Math.round((pre.stats.found / pre.stats.expected) * 100);
    const fill = el('div', { class: `meter__fill${pre.stats.found < pre.stats.expected ? ' is-partial' : ''}` });
    fill.style.width = `${pct}%`;
    status.append(el('section', { class: 'coverage' },
      el('div', { class: 'coverage__figure' },
        el('span', { class: 'coverage__num', text: `${pre.stats.found}/${pre.stats.expected}` }),
        el('span', { class: 'coverage__of', text: 'assessment folders in this project' })),
      el('div', { class: 'meter', role: 'img', 'aria-label': `${pct}% of assessment folders present` }, fill)));
  }

  status.append(el('ul', { class: 'checks' }, pre.checks.map((c) =>
    el('li', { class: `check check--${c.status}` },
      el('span', { class: 'check__state', text: STATE_TEXT[c.status] || c.status }),
      el('div', {},
        el('div', { class: 'check__label', text: c.label }),
        c.detail ? el('div', { class: 'check__detail', text: c.detail }) : null)))));
} catch (e) {
  $('#status').replaceChildren(el('p', { class: `notice notice--error`, text: e.status === 404 ? 'This project folder no longer exists. Go back to the project list.' : e.message }));
  if (e.status === 404) $('#enter').setAttribute('aria-disabled', 'true');
}
