import { el, api, copyText } from './common.js';
import { SHELLS, buildCommand, buildSequence, initialFields, applyPreset } from './cmdline.mjs';

/**
 * "Run order and commands" for one assessment: the scripts in order, a Copy button for each
 * command, and a Build dialog where optional flags can be filled in. Nothing here runs anything.
 * All text from the server is rendered with textContent.
 */

let shell = 'powershell';
let shellTouched = false;
try {
  const saved = localStorage.getItem('rtat.shell');
  if (saved in SHELLS) { shell = saved; shellTouched = true; }
} catch { /* storage unavailable: the default is fine */ }

let cdFirst = false;
const redraws = new Set();

function setShell(next) {
  shell = next;
  shellTouched = true;
  try { localStorage.setItem('rtat.shell', next); } catch { /* ignore */ }
  for (const fn of [...redraws]) fn();
}

function shellToggle() {
  const wrap = el('div', { class: 'seg', role: 'group', 'aria-label': 'Shell' });
  for (const [key, def] of Object.entries(SHELLS)) {
    const b = el('button', { type: 'button', class: 'seg__btn', 'aria-pressed': String(shell === key), text: def.label });
    b.addEventListener('click', () => { if (shell !== key) setShell(key); });
    wrap.append(b);
  }
  return wrap;
}

/* ------------------------------ list in the box --------------------------- */

export async function mountProcedures(host, base, id) {
  host.replaceChildren();
  let model;
  try {
    model = await api(`${base}/tests/${id}/procedures`);
  } catch (e) {
    host.replaceChildren(el('p', { class: 'box__msg', text: e.status === 503 ? 'Run order is unavailable: wstg_tools_procedures.json is not loaded.' : e.message }));
    return;
  }
  if (!shellTouched && model.platform && model.platform !== 'win32') shell = 'bash';

  if (!model.available) {
    host.replaceChildren(el('p', { class: 'box__msg', text: 'No procedure data for this assessment yet, so no commands can be built.' }));
    return;
  }

  const status = el('p', { class: 'procs__status', role: 'status' });
  const say = (text, kind) => { status.textContent = text; status.className = `procs__status${kind ? ` is-${kind}` : ''}`; };

  const body = el('div', { class: 'procs__body' });
  const details = el('details', { class: 'procs' }, el('summary', { text: `Run order and commands (${model.scripts.length} ${model.scripts.length === 1 ? 'script' : 'scripts'})` }), body);

  const draw = () => {
    if (!host.isConnected) { redraws.delete(draw); return; }
    const parts = [];
    const bar = el('div', { class: 'procs__bar' });
    if (model.position) {
      bar.append(el('span', { class: 'procs__pos', text: `Assessment ${model.position.order} of ${model.position.total} in the overall sequence`, title: model.position.reason || null }));
    }
    bar.append(shellToggle());
    parts.push(bar);
    if (model.position?.reason) parts.push(el('p', { class: 'procs__reason', text: model.position.reason }));

    const list = el('ol', { class: 'procs__list' });
    for (const s of model.scripts) list.append(row(s));
    parts.push(list);

    const all = el('button', { type: 'button', class: 'linkbtn', text: 'Copy all in order' });
    all.addEventListener('click', async () => {
      try {
        await copyText(buildSequence(shell, model.scripts, { cd: cdFirst }));
        say(`Copied ${model.scripts.length} commands in run order (${SHELLS[shell].label}).`, 'ok');
      } catch (e) { say(e.message, 'error'); }
    });
    parts.push(el('div', { class: 'procs__foot' }, all), status);
    body.replaceChildren(...parts);
  };

  function row(s) {
    const chips = [];
    if (!s.status.scriptFound) chips.push(el('span', { class: 'chip chip--warn', text: 'script not in project', title: s.script.path }));
    if (s.status.missingInputs) chips.push(el('span', { class: 'chip chip--bad', text: `${s.status.missingInputs} input${s.status.missingInputs === 1 ? '' : 's'} missing` }));
    if (!s.commandKnown) chips.push(el('span', { class: 'chip', text: 'flags not documented', title: 'The procedures file has no command line for this script, so only the documented inputs are listed.' }));
    if (s.inferred) chips.push(el('span', { class: 'chip', text: 'inferred', title: 'Inferred from the script docstring, not stated explicitly.' }));
    if (s.interactive.length) chips.push(el('span', { class: 'chip', text: 'interactive prompts', title: s.interactive.map((x) => x.description).filter(Boolean).join('\n') || null }));

    const copy = el('button', { type: 'button', class: 'linkbtn', text: 'Copy' });
    copy.addEventListener('click', async () => {
      const { text, missing } = buildCommand(shell, s, initialFields(s), { cd: cdFirst });
      try {
        await copyText(text);
        say(missing ? `Copied ${s.name}, but ${missing} required value${missing === 1 ? ' is' : 's are'} still a placeholder. Use Build to fill ${missing === 1 ? 'it' : 'them'}.` : `Copied ${s.name} (${SHELLS[shell].label}).`, missing ? 'warn' : 'ok');
      } catch (e) { say(e.message, 'error'); }
    });
    const build = el('button', { type: 'button', class: 'linkbtn', text: 'Build…' });
    build.addEventListener('click', () => openBuilder(s, model));

    return el('li', { class: 'proc' },
      el('span', { class: 'proc__n', 'aria-label': `Step ${s.position} of ${s.total}`, text: String(s.position) }),
      el('span', { class: 'proc__main' },
        el('span', { class: 'proc__name mono', text: s.name }),
        chips.length ? el('span', { class: 'proc__chips' }, chips) : null,
        s.after.length ? el('span', { class: 'proc__after', title: s.after.join('\n'), text: `after: ${s.after.join('; ')}` }) : null),
      el('span', { class: 'proc__btns' }, copy, build));
  }

  redraws.add(draw);
  draw();
  host.replaceChildren(details);
}

/* ------------------------------ build dialog ------------------------------ */

let dialog = null;

function openBuilder(script, model) {
  if (!dialog) {
    dialog = el('dialog', { class: 'bld', 'aria-label': 'Build command' });
    dialog.addEventListener('click', (e) => { if (e.target === dialog) dialog.close(); });
    document.body.append(dialog);
  }
  const fields = initialFields(script);
  const out = el('pre', { class: 'bld__out mono', tabindex: '0', 'aria-label': 'Command preview' });
  const warn = el('p', { class: 'bld__warn', role: 'status' });
  const flash = el('span', { class: 'bld__flash', role: 'status' });

  const update = () => {
    const { text, missing } = buildCommand(shell, script, fields, { cd: cdFirst });
    out.textContent = text;
    warn.textContent = missing ? `${missing} required value${missing === 1 ? ' is' : 's are'} empty and shown as a <placeholder>. Fill ${missing === 1 ? 'it' : 'them'} in before running.` : '';
  };
  redraws.add(function once() { if (!dialog.open) { redraws.delete(once); return; } rebuildControls(); update(); });

  const fieldHost = el('div', { class: 'bld__fields' });
  const controls = el('div', { class: 'bld__controls' });

  function rebuildControls() {
    const sh = shellToggle();
    const cd = el('label', { class: 'bld__check' });
    const cdBox = el('input', { type: 'checkbox' });
    cdBox.checked = cdFirst;
    cdBox.addEventListener('change', () => { cdFirst = cdBox.checked; update(); });
    cd.append(cdBox, ' start in the assessment folder first');
    controls.replaceChildren(sh, cd);
    if (script.presets.length) {
      const sel = el('select', { class: 'bld__select', 'aria-label': 'Preset' }, el('option', { value: '', text: 'Preset: default (required inputs only)' }),
        script.presets.map((p, i) => el('option', { value: String(i), text: p.label.length > 80 ? `${p.label.slice(0, 77)}…` : p.label })));
      sel.addEventListener('change', () => {
        const fresh = initialFields(script);
        fields.splice(0, fields.length, ...(sel.value === '' ? fresh : applyPreset(fresh, script.presets[Number(sel.value)])));
        drawFields();
        update();
      });
      controls.append(sel);
    }
  }

  function drawFields() {
    const groups = { required: [], optional: [] };
    const modes = [];
    for (const f of fields) (f.group ? modes : f.required ? groups.required : groups.optional).push(fieldRow(f));
    const parts = [];
    if (groups.required.length) parts.push(el('h3', { text: 'Required' }), ...groups.required);
    if (modes.length) parts.push(el('h3', { text: 'Mode (pick one)' }), ...modes);
    if (groups.optional.length) parts.push(el('h3', { text: 'Optional' }), ...groups.optional);
    if (!parts.length) parts.push(el('p', { class: 'hint', text: 'This script has no documented flags.' }));
    fieldHost.replaceChildren(...parts);
  }

  function fieldRow(f) {
    const inc = el('input', { type: 'checkbox', 'aria-label': `Include ${f.flag || f.tag}` });
    inc.checked = f.required || f.include;
    inc.disabled = f.required;
    inc.addEventListener('change', () => { f.include = inc.checked; update(); });

    const head = el('label', { class: 'fld__head' }, inc,
      el('code', { text: f.flag || '(positional)' }),
      f.flags.length > 1 ? el('span', { class: 'fld__alt', text: `also ${f.flags.slice(1).join(', ')}` }) : null,
      f.kind === 'output' ? el('span', { class: 'chip', text: 'output file' }) : null,
      f.flagUnsure ? el('span', { class: 'chip', text: 'switch or value?', title: 'The docs do not say whether this flag takes a value. Leave the box empty to pass just the flag.' }) : null);
    const kids = [head];
    if (f.description) kids.push(el('p', { class: 'fld__desc', text: f.description }));
    if (f.flagUnknown) kids.push(el('p', { class: 'fld__desc', text: 'The flag for this input is not documented, so it is placed after the script name without one.' }));

    if (f.kind !== 'switch') {
      const input = el('input', { type: 'text', class: 'fld__input mono', spellcheck: 'false', autocomplete: 'off', 'aria-label': `${f.flag || f.tag} value`, placeholder: f.kind === 'file' ? `${f.expectedDir || 'path to file'}` : (f.placeholder || 'value') });
      input.value = f.value ?? '';
      const badge = el('span', { class: 'fld__badge' });
      const paint = () => {
        if (f.kind !== 'file') { badge.textContent = ''; return; }
        const known = (f.candidates || []).find((c) => c.path === input.value);
        const later = known && !known.exists && known.label.startsWith('output of');
        badge.textContent = known ? (known.exists ? '✓ found' : later ? `… not there yet; ${known.label.replace('output of', 'created by')}` : '✗ not in the project yet') : (input.value ? 'custom path' : '✗ no file yet');
        badge.className = `fld__badge${known ? (known.exists ? ' is-ok' : later ? '' : ' is-bad') : ''}`;
      };
      let ctl = input;
      if (f.choices) {
        ctl = el('select', { class: 'bld__select', 'aria-label': `${f.flag} value` }, f.choices.map((c) => el('option', { value: c, text: c })));
        ctl.value = f.value || f.choices[0];
        ctl.addEventListener('change', () => { f.value = ctl.value; update(); });
        kids.push(ctl);
      } else {
        input.addEventListener('input', () => {
          f.value = input.value;
          if (f.kind === 'file' && input.value && !f.required) { f.include = true; inc.checked = true; }
          if (sel) sel.value = (f.candidates || []).some((c) => c.path === input.value) ? input.value : '';
          paint();
          update();
        });
        let sel = null;
        if (f.kind === 'file' && f.candidates?.length > 1) {
          sel = el('select', { class: 'bld__select', 'aria-label': `Choose a file for ${f.flag || 'this input'}` },
            f.candidates.map((c) => el('option', { value: c.path, text: `${c.exists ? '✓' : '✗'} ${c.path.split(/[\\/]/).pop()} (${c.label})` })));
          sel.value = f.value || '';
          sel.addEventListener('change', () => { input.value = sel.value; f.value = sel.value; paint(); update(); });
          kids.push(sel);
        }
        kids.push(input);
      }
      paint();
      kids.push(badge);
    }
    return el('div', { class: `fld${f.kind === 'output' ? ' fld--out' : ''}` }, kids);
  }

  const copy = el('button', { type: 'button', class: 'pill', text: 'Copy command' });
  copy.addEventListener('click', async () => {
    try {
      await copyText(out.textContent);
      flash.textContent = 'Copied.';
      flash.className = 'bld__flash is-ok';
    } catch (e) {
      flash.textContent = e.message;
      flash.className = 'bld__flash is-error';
    }
  });
  const close = el('button', { type: 'button', class: 'pill pill--quiet', text: 'Close' });
  close.addEventListener('click', () => dialog.close());

  const info = [];
  if (script.description) info.push(el('p', { class: 'bld__desc', text: script.description }));
  for (const a of script.after) info.push(el('p', { class: 'bld__note', text: `Runs after: ${a}` }));
  for (const n of script.notes) info.push(el('p', { class: 'bld__note', text: n }));
  if (!script.commandKnown) info.push(el('p', { class: 'bld__note', text: 'No command line is documented for this script. Only its documented inputs are shown, so check the flags against the script’s --help.' }));
  if (!script.status.scriptFound) info.push(el('p', { class: 'bld__note is-warn', text: 'This script is not in the project folder yet. The path below is where it is expected.' }));
  for (const x of script.interactive) info.push(el('p', { class: 'bld__note', text: `Prompted at run time: ${x.description || 'questionnaire answers'}` }));

  const writes = script.writes.length
    ? el('details', { class: 'bld__writes' }, el('summary', { text: `Files this script writes (${script.writes.length})` }),
      el('ul', {}, script.writes.map((w) => el('li', {}, el('code', { text: w.path || '(path not documented)' }), w.condition ? ` · ${w.condition}` : '', w.description ? ` · ${w.description}` : ''))))
    : null;

  const parts = [
    el('header', { class: 'bld__head' },
      el('div', {}, el('h2', { class: 'mono', text: script.name }), el('p', { class: 'bld__sub', text: `${model.id} · step ${script.position} of ${script.total}` })),
      close),
    ...info,
    controls,
    fieldHost,
    writes,
    el('div', { class: 'bld__preview' }, el('h3', { text: 'Command' }), out, warn, el('div', { class: 'bld__actions' }, copy, flash)),
  ];
  dialog.replaceChildren(...parts.filter(Boolean));
  rebuildControls();
  drawFields();
  update();
  dialog.showModal();
}
