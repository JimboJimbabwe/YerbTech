import { el, api, startClock, projectUrl, fmtDate } from './common.js';

const $ = (s) => document.querySelector(s);
const grid = $('#folders');
const countLabel = $('#project-count');
const dialog = $('#add-dialog');
const form = $('#add-form');
const input = $('#project-name');
const errorBox = $('#add-error');
const submit = $('#add-submit');

startClock($('#clock'));

async function loadProjects(highlight) {
  try {
    const { projects, count } = await api('/api/projects');
    countLabel.textContent = `${count} ${count === 1 ? 'project' : 'projects'}`;
    grid.replaceChildren();
    if (!count) {
      grid.append(el('div', { class: 'empty' },
        el('strong', { text: 'No projects yet' }),
        'Add a project to copy the WSTG template into your Projects folder.'));
      return;
    }
    // TODO(anti-project-spoofing): once the server decides which folders are valid projects,
    // show the ones that fail here (greyed out or flagged) instead of treating them as normal.
    for (const p of projects) {
      grid.append(el('a', { class: `folder${p.name === highlight ? ' is-new' : ''}`, href: projectUrl(p.name) },
        el('span', { class: 'folder__name', text: p.name }),
        el('span', { class: 'folder__meta', text: `Created ${fmtDate(p.createdAt)}` })));
    }
    if (highlight) grid.querySelector('.is-new')?.focus();
  } catch (e) {
    countLabel.textContent = '';
    grid.replaceChildren(el('div', { class: 'empty' },
      el('strong', { text: 'Could not load projects' }), e.message));
  }
}

function openDialog() {
  errorBox.textContent = '';
  input.value = '';
  dialog.showModal();
  input.focus();
}

$('#add-project').addEventListener('click', openDialog);
$('#add-cancel').addEventListener('click', () => dialog.close());

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  errorBox.textContent = '';
  submit.disabled = true;
  submit.textContent = 'Creating...';
  try {
    const { name } = await api('/api/projects', { method: 'POST', body: JSON.stringify({ name: input.value }) });
    dialog.close();
    await loadProjects(name);
  } catch (e) {
    errorBox.textContent = e.message;
    input.focus();
  } finally {
    submit.disabled = false;
    submit.textContent = 'Create project';
  }
});

loadProjects();
