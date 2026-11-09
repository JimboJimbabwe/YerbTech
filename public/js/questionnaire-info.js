import { el, api, projectUrl } from './common.js';

/**
 * Questionnaires info card: a topbar pill opens a small aside with a count/description and an
 * "Open questionnaires" button to the full answering page (questionnaires.html). No answering
 * happens here - checkboxes and text boxes need more room than this sidebar strip gives.
 */
export function initQuestionnaireInfo({ base, project }) {
  const side = document.querySelector('#qst-side');
  const panel = document.querySelector('#qst-panel');
  const toggle = document.querySelector('#qst-toggle');

  let state = null; // { items, warnings } | null
  let message = null;

  function setOpen(open) {
    side.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close the Questionnaires info card' : 'Open the Questionnaires info card');
    if (open && !state) refresh();
  }
  toggle.addEventListener('click', () => setOpen(side.hidden));

  async function refresh() {
    try {
      state = await api(`${base}/questionnaires`);
      message = null;
    } catch (e) {
      state = { items: [], warnings: [] };
      message = { text: e.message, kind: 'error' };
    }
    render();
  }

  function render() {
    const kids = [];
    const items = state?.items || [];
    const byCat = new Map();
    for (const it of items) {
      if (!byCat.has(it.category)) byCat.set(it.category, []);
      byCat.get(it.category).push(it);
    }
    const answered = items.filter((it) => it.answered).length;

    kids.push(el('section', { class: 'mouse__sec' },
      el('div', { class: 'mouse__h', text: 'Questionnaires' }),
      el('p', { class: 'qst__blurb', text: 'Pre-test checklists for items that are mostly questions, not a script run. Answer them on the full page - yes/no boxes where that fits, a text box where it doesn’t.' }),
      el('div', { class: 'mouse__row' },
        el('span', { text: `${items.length} questionnaire${items.length === 1 ? '' : 's'} across ${byCat.size} categor${byCat.size === 1 ? 'y' : 'ies'}` })),
      el('div', { class: 'mouse__row' },
        el('span', { text: `${answered} answered so far` }))));

    const openBtn = el('a', { class: 'linkbtn qst__open', href: `${projectUrl(project)}/questionnaires`, text: 'Open questionnaires' });
    kids.push(el('div', { class: 'mouse__row' }, openBtn));

    if (state?.warnings?.length) {
      kids.push(el('p', { class: 'mouse__status is-error', role: 'status', text: `${state.warnings.length} data warning(s): ${state.warnings.join('; ')}` }));
    }
    if (message) kids.push(el('p', { class: `mouse__status${message.kind === 'error' ? ' is-error' : ''}`, role: 'status', text: message.text }));

    panel.replaceChildren(...kids);
  }

  return { open: () => setOpen(true), refresh };
}
