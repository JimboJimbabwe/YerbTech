import { el, api, fmtBytes } from './common.js';

/**
 * Left sidebar. "Add XML files" expands into one titled block per XML type (Burp Proxy XML is live,
 * Nmap and Intruder are greyed copies), each with four click-to-add squares. Choosing or dropping
 * a file uploads it; the server stores it and copies it into the right assessments.
 */
export function initXmlSide({ base, onChange }) {
  const side = document.querySelector('#xml-side');
  const panel = document.querySelector('#xml-panel');
  const burger = document.querySelector('#burger');

  let status = null;
  let expanded = false;
  let busy = null; // "kind/category" while uploading
  let message = null; // { text, kind }

  function setOpen(open) {
    side.hidden = !open;
    burger.setAttribute('aria-expanded', String(open));
    burger.setAttribute('aria-label', open ? 'Close the XML panel' : 'Open the XML panel');
    if (open && !status) refresh();
  }
  burger.addEventListener('click', () => setOpen(side.hidden));

  async function refresh() {
    try {
      status = await api(`${base}/xml`);
      message = message && message.kind !== 'error-load' ? message : null;
    } catch (e) {
      status = null;
      message = { text: e.message, kind: 'error-load' };
    }
    render();
  }

  function render() {
    const kids = [];
    const toggle = el('button', { type: 'button', class: 'xml-add', 'aria-expanded': String(expanded), 'aria-controls': 'xml-groups' },
      el('span', { class: 'xml-add__plus', 'aria-hidden': 'true', text: '+' }),
      el('span', { text: 'Add XML files' }),
      el('span', { class: 'chev', 'aria-hidden': 'true' }));
    toggle.addEventListener('click', () => { expanded = !expanded; render(); });
    kids.push(toggle);

    const groups = el('div', { class: 'xml-groups', id: 'xml-groups', hidden: !expanded });
    if (status) groups.append(...status.kinds.map(renderKind));
    kids.push(groups);

    kids.push(el('p', {
      class: `xml-msg${message ? ` is-${message.kind.startsWith('error') ? 'error' : message.kind}` : ''}`,
      role: 'status',
      text: message ? message.text : (status && !expanded ? 'Open “Add XML files” to add Burp exports.' : ''),
    }));
    panel.replaceChildren(...kids);
  }

  function renderKind(kind) {
    const live = kind.enabled;
    const zones = kind.categories.map((c) => renderZone(kind, c));
    const sec = el('section', { class: `xml-kind${live ? '' : ' is-off'}`, 'aria-label': kind.title },
      el('h3', { class: 'xml-kind__title' },
        el('span', { text: kind.title }),
        live ? null : el('span', { class: 'xml-kind__soon', text: 'coming later' })),
      el('div', { class: 'xml-zones' }, zones));
    const copied = kind.categories.filter((c) => c.present);
    if (live && copied.length) sec.append(renderDetails(copied));
    return sec;
  }

  function renderZone(kind, c) {
    const live = kind.enabled;
    const key = `${kind.key}/${c.key}`;
    const input = el('input', { type: 'file', accept: '.xml,application/xml,text/xml', class: 'sr-only', tabindex: '-1', 'aria-hidden': 'true' });
    const isBusy = busy === key;
    const zone = el('button', {
      type: 'button',
      class: `zone${c.present ? ' is-filled' : ''}${isBusy ? ' is-busy' : ''}`,
      disabled: !live || (busy && !isBusy) ? true : null,
      'aria-label': `${kind.title}, ${c.label}: ${c.present ? `${c.file} added. Click to replace.` : 'click to add a file.'}`,
    },
      el('span', { class: 'zone__label', text: c.label }),
      c.present && live
        ? el('span', { class: 'zone__body' },
          el('span', { class: 'zone__file mono', text: c.file }),
          el('span', { class: 'zone__meta', text: `${fmtBytes(c.size)} · ${c.copies.length} ${c.copies.length === 1 ? 'copy' : 'copies'}` }),
          c.skipped.length ? el('span', { class: 'zone__warn', text: `${c.skipped.length} skipped` }) : null,
          c.replaced ? el('span', { class: 'zone__meta', text: 'replaced, old one archived' }) : null)
        : el('span', { class: 'zone__plus', 'aria-hidden': 'true', text: isBusy ? '…' : '+' }),
      isBusy ? el('span', { class: 'zone__bar' }, el('span', { class: 'zone__fill', id: 'zone-fill' })) : null);

    if (live) {
      zone.addEventListener('click', () => input.click());
      input.addEventListener('change', () => { if (input.files[0]) upload(kind, c, input.files[0]); });
      zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('is-over'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('is-over'));
      zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('is-over');
        const f = e.dataTransfer?.files?.[0];
        if (f) upload(kind, c, f);
      });
    }
    return el('div', { class: 'zone-wrap' }, zone, input);
  }

  function renderDetails(cats) {
    const rows = [];
    for (const c of cats) {
      rows.push(el('h4', { class: 'xml-det__h', text: `${c.label} → ${c.copies.length} ${c.copies.length === 1 ? 'assessment' : 'assessments'}` }));
      if (c.copies.length) {
        rows.push(el('ul', { class: 'xml-det__list' }, c.copies.map((x) => el('li', {},
          el('span', { class: 'mono', text: x.testId.replace('WSTG-', '') }), ' ', el('span', { class: 'xml-det__file mono', text: x.file })))));
      }
      if (c.skipped.length) {
        rows.push(el('ul', { class: 'xml-det__list is-skip' }, c.skipped.map((x) => el('li', {},
          el('span', { class: 'mono', text: x.testId.replace('WSTG-', '') }), ' ', el('span', { class: 'mono', text: x.title }),
          el('span', { class: 'xml-det__why', text: ` skipped: ${x.reason}` })))));
      }
    }
    return el('details', { class: 'xml-det' }, el('summary', { text: 'Where the files went' }), rows);
  }

  function upload(kind, c, file) {
    if (busy) return;
    const limit = status?.limits?.maxXmlBytes;
    if (limit && file.size > limit) {
      message = { text: `${file.name} is ${fmtBytes(file.size)}, over the ${fmtBytes(limit)} limit.`, kind: 'error' };
      render();
      return;
    }
    busy = `${kind.key}/${c.key}`;
    message = { text: `Uploading ${file.name} (${fmtBytes(file.size)})...`, kind: 'info' };
    render();

    // XMLHttpRequest rather than fetch: it reports upload progress, which matters for big exports.
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `${base}/xml/${encodeURIComponent(kind.key)}/${encodeURIComponent(c.key)}`);
    xhr.setRequestHeader('Content-Type', 'application/xml');
    xhr.upload.onprogress = (e) => {
      const bar = document.querySelector('#zone-fill');
      if (bar && e.lengthComputable) bar.style.width = `${Math.round((e.loaded / e.total) * 100)}%`;
    };
    const done = (ok, text) => {
      busy = null;
      if (ok) {
        const rec = status.kinds.find((k) => k.key === kind.key).categories.find((x) => x.key === c.key);
        message = { text, kind: 'ok' };
        onChange?.(rec);
      } else {
        message = { text, kind: 'error' };
      }
      render();
    };
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status === 200 && body?.kinds) {
        status = body;
        const rec = body.kinds.find((k) => k.key === kind.key).categories.find((x) => x.key === c.key);
        const n = rec.copies.length;
        const extra = rec.skipped.length ? ` ${rec.skipped.length} skipped (see details).` : '';
        const replaced = rec.replaced ? ' The previous file was archived.' : '';
        done(true, `${c.file} added: copied to ${n} ${n === 1 ? 'assessment' : 'assessments'}.${extra}${replaced}`);
      } else {
        done(false, (body && body.error) || `Upload failed (${xhr.status || 'no response'}).`);
      }
    };
    xhr.onerror = () => done(false, 'The upload was interrupted or refused before it finished.');
    xhr.send(file);
  }

  return { open: () => setOpen(true), refresh };
}
