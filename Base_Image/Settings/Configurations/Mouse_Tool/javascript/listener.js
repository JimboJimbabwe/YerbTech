// DATA PRESENTATION + TRANSFORM CHECK: Console. tabs: Overview / Origin / Code / Timeline / Raw (blueprint look).
// Adds: compares the raw source value with the text shown (case, encoding, wrapping, truncation, number format) and looks for pieces when no single field holds the text.
// Same hotkeys and detection as hover-trace-keys.js; this version lays the information out differently.
// Hover Trace: shows what rendered an element, what code inserted it, and where its data came from.
// Paste into the browser console BEFORE you trigger the thing you want to trace.
//   1. Paste this script.
//   2. Do your search (or whatever makes the item appear).
//   3. Hover the item, press Alt+Q.
// A small card follows the cursor with a summary (component / sink / source / candidate flow).
// Sinks are labelled (HTML parser = risky, plain text = safe). Sources include network responses,
// embedded page data, storage, URL (search/hash/path), cookies, window.name, referrer and postMessage.
// Not hooked: eval/new Function (replacing them can change how page code runs) and location assignments.
// NEW in this version: Alt+Q also pulls the relevant source code and shows it with the flow highlighted:
//   SOURCE READ (likely) -> REQUEST -> SINK -> CALLER, using the recorded call stacks. Script files are
//   re-fetched (same-origin, or cross-origin with CORS), and source maps are followed when present,
//   so minified bundles show the original code when the map embeds it.
// NEW in this version:
//   * Timeline: every recorded event (request, response, postMessage, localStorage/sessionStorage/cookie
//     writes and reads, DOM writes, attribute sets) merged into one list ordered by time, with gaps in ms.
//   * Direction: each place the value appears is tagged origin? / destination? / derived? / shipped with
//     page / unclear. On text inputs, matches in requests or storage are usually where the value WENT.
//   * Storage hooks: localStorage/sessionStorage get/set/remove/clear and document.cookie writes are
//     recorded with a timestamp and call stack.
//   * Password fields are never read into the panel, card, console or JSON.
// NEW in this version:
//   * Alt+M  DATA -> ELEMENT MAP. Finds the array (in a response, embedded data or ld+json) that holds the
//     hovered text, links every entry to the page element it produced (labelled [0], [1]... over the page),
//     says whether array order, page order and write order agree, and shows the code that wrote them
//     (call path, loop frames, the value that reached each write).
//   * Alt+W  WHO-WROTE-WHAT OVERLAY. Colors every visible text element by the code that wrote it.
//     Alt+Shift+W changes which stack frame the grouping uses (0 = writer, 1 = caller, ...).
//     Click a legend row to show just that group.
// NEW in this version (fixes for "the code shown is only generic helpers"):
//   * Deeper stacks: browsers keep only 10 call-stack frames by default, which cut off the app's own
//     component code. Capture now keeps ~45 frames, and the code view shows the nearest callers PLUS the
//     outermost captured ones (labelled), which are usually the app's real code.
//   * "Code that reads these fields": takes the field names from the data path (e.g. data.filterButtons[2]
//     .buttonLabel -> filterButtons, buttonLabel), text-searches every script on the page (same-origin or CORS,
//     plus inline scripts), and shows the lines that mention them, ranked by how many fields sit close
//     together. A hit is a strong lead, not proof. Works in both Alt+Q and Alt+M.
// MOUSE_TOOL: this script no longer holds any paths or a BASE_PATH to fill in. It only tags each
// exported JSON with the WSTG ID it was copied for (mouse_target.wstg_id); clipboard_interceptor.py
// resolves every actual folder from the project's mouse_tool.json and checks the tag against it.
// CONTEXT: right below it, OBJECT_CONTEXT can be set to 'input' or 'output'; it is written into every JSON as object_context.
// Hotkeys: Alt+Q full trace + timeline + code, Alt+M map, Alt+W overlay, Alt+J copy last trace as JSON,
//          Alt+H toggle hover card, Esc closes the panel and clears the map.
// Stop with: __traceCleanup()
(() => {
  if (window.__traceCleanup) window.__traceCleanup();

  // =====================================================================
  // Mouse_Tool: this script no longer carries any paths. The Python (clipboard_interceptor.py)
  // resolves every input/output/XML folder itself from the project's mouse_tool.json, keyed by
  // WSTG ID. All this script does is say WHICH WSTG ID it was copied for, as a backup check:
  // the Python compares this to the item it currently has active and rejects the clipboard JSON
  // (with an ALERT) if they don't match, so pasting a stale copy never saves under the wrong item.
  // __WSTG_ID__ is replaced by the Python at copy time (Left Shift) with whatever item is active;
  // left as-is (if you paste this manually instead of through the listener) it reads as "unset",
  // and the Python treats an "unset" tag as never matching, so an unset paste is also rejected.
  // =====================================================================
  const MOUSE_TARGET_WSTG_ID = '__WSTG_ID__';
  const mouseTarget = () => ({ wstg_id: MOUSE_TARGET_WSTG_ID });
  // =====================================================================
  // EDIT THIS (optional): is the thing you are tracing an INPUT or an OUTPUT?
  // Type  input  or  output  between the quotes (any capitals are fine). Leave '' for "not set".
  // It is written into every exported JSON as object_context. You can also change it at any time from
  // the console, without editing this file:   __setObjectContext('input')   or   __setObjectContext('output')
  // (it lasts until you re-paste the script; __setObjectContext('') clears it).
  // =====================================================================
  const OBJECT_CONTEXT = '';
  const ctxNorm = v => { const s = String(v == null ? '' : v).trim().toLowerCase(); return s === 'input' || s === 'output' ? s : ''; };
  let objectContext = ctxNorm(OBJECT_CONTEXT);
  if (String(OBJECT_CONTEXT).trim() && !objectContext) console.warn('[Hover Trace] OBJECT_CONTEXT must be "input" or "output"; it was ignored.');
  window.__setObjectContext = v => {
    const n = ctxNorm(v);
    if (String(v == null ? '' : v).trim() && !n) { console.warn('[Hover Trace] object_context must be "input" or "output" (or empty to clear). Left as ' + JSON.stringify(objectContext)); return objectContext; }
    objectContext = n;
    console.log('[Hover Trace] object_context = ' + JSON.stringify(n));
    return n;
  };
  // ===== THEME: the only part that differs between the design variants =====
  const THEME = ({
  name: 'Midnight Blueprint',
  palette: { bg: '#0b2b4d', bg2: '#071f3a', sel: '#164f86', text: '#e4f3ff', muted: '#82a9cc', red: '#ff7b7b', yellow: '#ffe66d', teal: '#55e6e0', blue: '#9bcbff', orange: '#ffb86b', purple: '#c9b0ff', green: '#9dffcb', pink: '#ffa8dc' },
  panel: "background-color:#0b2b4d;background-image:linear-gradient(rgba(155,203,255,.10) 1px,transparent 1px),linear-gradient(90deg,rgba(155,203,255,.10) 1px,transparent 1px),linear-gradient(rgba(155,203,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(155,203,255,.05) 1px,transparent 1px);background-size:96px 96px,96px 96px,16px 16px,16px 16px;background-attachment:local;color:#e4f3ff;font:12px/1.55 ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,monospace;padding:16px 18px;border:1.5px solid #9bcbff;border-radius:2px;box-shadow:0 0 0 5px #0b2b4d,0 0 0 6.5px rgba(155,203,255,.55),0 22px 44px rgba(0,10,30,.6);",
  card: "background-color:#0b2b4d;background-image:linear-gradient(rgba(155,203,255,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(155,203,255,.07) 1px,transparent 1px);background-size:16px 16px;color:#e4f3ff;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:8px 10px;border:1px solid #9bcbff;border-radius:1px;box-shadow:0 0 0 3px #0b2b4d,0 0 0 4px rgba(155,203,255,.5),0 10px 24px rgba(0,10,30,.5);",
  hover: "border:1.5px dashed #ffe66d;background:rgba(255,230,109,.08);outline:1px solid rgba(255,230,109,.4);outline-offset:3px;",
  head: t => `<div style="margin:16px 0 6px;color:#ffe66d;font-weight:bold;letter-spacing:.04em;display:flex;align-items:center;gap:8px;"><span style="flex:none;width:8px;height:8px;border:1.5px solid #ffe66d;transform:rotate(45deg);"></span><span style="min-width:0;word-break:break-word;">${t}</span><span style="flex:1;border-top:1px dashed rgba(155,203,255,.5);min-width:16px;"></span></div>`,
  title: (t, c) => `<span style="color:${c};font-weight:bold;letter-spacing:.18em;border-top:2px solid ${c};border-bottom:2px solid ${c};padding:2px 7px;">${t}</span>`,
  role: (t, c) => `<span style="color:${c};border:1px solid ${c};background:rgba(7,31,58,.65);padding:0 6px;font-weight:bold;letter-spacing:.08em;">${t}</span>`,
  tag: (t, c) => `<span style="color:${c};border:1px solid ${c};padding:0 5px;font-weight:bold;">${t}</span>`,
  val: s => `<span style="color:#9dffcb;">${s}</span>`,
  codeBox: "white-space:pre;overflow-x:auto;background:rgba(7,31,58,.90);border:1px solid rgba(155,203,255,.45);border-radius:1px;padding:6px 8px;margin:6px 0;tab-size:2;",
  hitRow: "background:rgba(255,123,123,.17);box-shadow:inset 2px 0 0 #ff7b7b;",
  mark: { col: 'background:#ffe66d;color:#071f3a;font-weight:bold', risky: 'color:#ff7b7b;font-weight:bold', safe: 'color:#9bcbff', src: 'color:#ffe66d;font-weight:bold' },
  box: (c, strong) => `border:${strong ? 2 : 1.5}px dashed ${c};background:${c}14;border-radius:0;outline:1px solid ${c}55;outline-offset:2px;`,
  label: c => `left:-1px;top:-15px;background:#071f3a;color:${c};border:1px solid ${c};font:bold 10px/12px ui-monospace,Menlo,Consolas,monospace;padding:0 5px;`,
  surface: "padding:8px 12px;border:1px dashed rgba(155,203,255,.55);background:rgba(7,31,58,.55);margin:8px 0;",
  chip: (t, c) => `<span style="display:inline-block;padding:0 6px;border:1px solid ${c};color:${c};background:rgba(7,31,58,.7);">${t}</span>`,
  css: `.ht-panel{scrollbar-width:thin;scrollbar-color:#9bcbff #0b2b4d}
.ht-panel::-webkit-scrollbar{width:9px}.ht-panel::-webkit-scrollbar-track{background:#071f3a}.ht-panel::-webkit-scrollbar-thumb{background:#4b7fb3}
.ht-panel [data-entry]:hover,.ht-panel [data-cand]:hover,.ht-panel [data-group]:hover{background:#164f86}
.ht-panel ::selection{background:#ffe66d;color:#071f3a}`
});
  const VIEW = ({
  name: 'Console',
  trace(M, S) {
    const t = M.t, p = M.primary, ib = M.ib, w = M.ladder[0];
    const TABS = [['overview', 'Overview'], ['origin', 'Origin'], ['code', 'Code'], ['time', 'Timeline'], ['raw', 'Raw']];
    const tab = TABS.some(x => x[0] === S.tab) ? S.tab : 'overview';
    let h = traceHeader(M, 'Esc closes · Alt+J copies JSON · switch tabs below');

    // tab bar
    h += `<div style="display:flex;gap:2px;margin:10px 0 0;border-bottom:1px solid #82a9cc;">`;
    TABS.forEach(([k, label]) => {
      const on = k === tab;
      const count = k === 'origin' ? ' ' + M.origins.length : k === 'code' ? ' ' + M.ladder.length : k === 'time' ? ' ' + M.events.length : '';
      h += act('tab', k, `${esc(label)}<span ${MUTED}>${count}</span>`, `padding:5px 12px;${on ? 'color:#ffe66d;border:1px solid #82a9cc;border-bottom:1px solid #0b2b4d;margin-bottom:-1px;background:#0b2b4d;font-weight:bold;' : 'color:#9bcbff;'}`);
    });
    h += `</div><div style="margin-top:10px;">`;

    if (tab === 'overview') {
      const sk = ib && ib.sink;
      const facts = [
        ['shows', t.textShown ? Qs(clip(t.textShown, 80)) : '<span ' + MUTED + '>(no own text)</span>'],
        ['context', t.object_context ? Bs(t.object_context) : '<span ' + MUTED + '>not set (see OBJECT_CONTEXT at the top of the script)</span>'],
        ['page', t.page_endpoint ? Cs(t.page_endpoint.path) : '—'],
        ['written by', w ? Cs(fnShown(w) + '()') + (w.file ? ' <span ' + MUTED + '>' + esc(w.file + ':' + w.line + ':' + w.col) + '</span>' : '') : '<span ' + MUTED + '>no write recorded</span>'],
        ['how', ib ? esc(ib.via) + ' ' + THEME.tag(esc(sk.label), sk.risky ? '#ff7b7b' : '#9dffcb') : '—'],
        ['when', M.writeMs != null ? esc(fmtT(M.writeMs)) + ' after page load' : '—'],
        ['came from', p ? Cs(originLine(p)) : '<span ' + MUTED + '>no match found</span>'],
        ['changed?', t.transform && t.transform.verdict !== 'unknown' ? (t.transform.verdict === 'unchanged' ? xfTag('identical') + ' <span ' + MUTED + '>exactly as in the source</span>' : t.transform.built ? xfTag('built') + ' <span ' + MUTED + '>built from pieces</span>' : xfTag(t.transform.direct[0] ? t.transform.direct[0].kind : 'wrapped') + ' <span ' + MUTED + '>see Origin tab</span>') : '<span ' + MUTED + '>nothing to compare</span>'],
        ['direction', p ? dirTag(p.d.direction) + ' <span ' + MUTED + '>' + esc(DIR_WORDS[p.d.direction] || '') + '</span>' : '—'],
        ['position', p && p.ctxs[0] && p.ctxs[0].arr ? 'entry ' + Bs(String(p.ctxs[0].arr.idx + 1)) + ' of ' + Bs(String(p.ctxs[0].arr.total)) + ' in ' + Cs(p.ctxs[0].arr.path) : '—'],
        ['call depth', M.ladder.length ? M.ladder.length + ' frames' + (M.loops ? ', ' + M.loops + ' array loop' + (M.loops === 1 ? '' : 's') : '') : '—'],
        ['mentioned in', M.fr && M.fr.items.length ? Cs(M.fr.items[0].name + ':' + M.fr.items[0].line + ':' + M.fr.items[0].col) + ' <span ' + MUTED + '>+' + (M.fr.items.length - 1) + ' more</span>' : '<span ' + MUTED + '>' + (M.fr ? 'no readable script mentions the field names' : 'searching…') + '</span>']
      ];
      h += `<div style="display:grid;grid-template-columns:104px minmax(0,1fr);gap:4px 12px;">` +
        facts.map(([k, v]) => `<span style="color:#9bcbff;">${esc(k)}</span><span style="min-width:0;overflow-wrap:anywhere;">${v}</span>`).join('') + `</div>`;
      h += `<div style="${THEME.surface}line-height:1.6;margin-top:12px;">${M.story.lead}</div>`;
      M.story.notes.forEach(n => { h += `<div style="margin:6px 0 0 4px;line-height:1.55;">• ${n}</div>`; });
      h += `<div ${MUTED} style="margin-top:12px;">Next: ${act('tab', 'origin', '<u>Origin</u>', 'color:#ffe66d;')} shows the data around the value · ${act('tab', 'code', '<u>Code</u>', 'color:#ffe66d;')} the functions, one click each · ${act('tab', 'time', '<u>Timeline</u>', 'color:#ffe66d;')} what happened in what order.</div>`;
    }

    if (tab === 'origin') {
      h += head('Did the page change it on the way?') + xfHtml(M);
      h += head('Where it was found');
      if (!M.origins.length) h += `<span ${MUTED}>No exact match in captured requests, embedded page data, storage, the URL, cookies, window.name, the referrer or postMessage.${xfNote(M)}</span>`;
      M.origins.forEach((o, i) => {
        const d = o.d;
        h += `<div style="${THEME.surface}">` +
          `<div>${THEME.role(String(i + 1), '#ffe66d')} <b>${esc(d.sourceKind)}</b> ${dirTag(d.direction)}</div>` +
          `<div style="margin:4px 0;overflow-wrap:anywhere;">${Cs(originLine(o))}</div>` +
          `<div ${MUTED}>${esc(DIR_WORDS[d.direction] || '')}${d.relation ? ' · ' + esc(d.relation) : ''}</div>` +
          o.ctxs.map((c, k) => (k ? `<div ${MUTED} style="margin-top:6px;">also at:</div>` : '') + ctxHtml(c, { noEntry: k > 0 })).join('') +
          (o.ladder.length ? `<div ${MUTED} style="margin-top:8px;">requested by</div><div style="line-height:1.9;">${chainHtml(o.ladder, 2, 3)}</div>` : '') +
          `</div>`;
      });
    }

    if (tab === 'code') {
      h += `<div>${act('allframes', String(M.ladder.length), `<span style="color:#ffe66d">${S.open.size >= M.ladder.length ? '▾ collapse all' : '▸ open every frame'}</span>`)} <span ${MUTED}>click any row to read it</span></div>`;
      h += head('Call path, write at the top');
      h += ladderHtml(M.ladder, S, '', { chip: (role, col) => THEME.tag(esc(role), col) });
      h += head('Code that mentions the data');
      h += fieldReadsHtml(M.fr, M.frState);
      if (M.sourceReads.length) {
        h += head('Likely reads of page-controlled sources (guessed by pattern)');
        M.sourceReads.forEach(it => { h += `\n${THEME.role('SOURCE READ', '#ffe66d')} ${esc(it.label)}\n` + resolvedCodeHtml({ doc: it.doc, line: it.line, col: it.col, name: it.name, hitLen: it.hitLen }); });
      }
    }

    if (tab === 'time') h += timelineHtml(M.events, true);

    if (tab === 'raw') {
      let raw;
      try { raw = JSON.stringify({ ...t, timeline: (t.timeline || []).map(e => ({ ...e, stack: undefined })) }, null, 2); } catch (e) { raw = String(e); }
      h += `<div ${MUTED}>The same object Alt+J copies (call stacks trimmed from the timeline here).</div><div style="${THEME.codeBox}">${esc(clip(raw, 9000))}</div>`;
      h += `<div style="margin-top:8px;">${moreHtml(t)}</div>`;
    }
    return h + `</div>`;
  }
});
  // ===== end THEME =====

  const installedAt = new Date().toISOString();
  const installT = performance.now();           // ms since page load when this script was pasted
  let seqCounter = 0;
  const stamp = () => ({ seq: ++seqCounter, t: performance.now(), time: new Date().toISOString() });
  const MAX_BODY = 2000000;
  const requests = [];
  const domLog = new WeakMap();
  const undo = [];
  let busy = false;
  let current = null;
  let lastTrace = null;

  const cssEsc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^\w-]/g, '\\$&');
  const norm = s => String(s).replace(/\s+/g, ' ').trim().toLowerCase();
  const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);

  // Call stack captured at the moment of a hooked call. n = frames between this helper and page code.
  // Browsers keep only 10 stack frames by default. Real apps are deeper than that, so raise the limit
  // just while we capture (and put it back), otherwise the outer component code is cut off.
  const STACK_CAPTURE = 60, STACK_KEEP = 45;
  const stack = n => {
    const old = Error.stackTraceLimit;
    let raw;
    try { Error.stackTraceLimit = STACK_CAPTURE; raw = new Error().stack || ''; }
    finally { if (typeof old === 'number') Error.stackTraceLimit = old; }
    let lines = raw.split('\n');
    if (/^Error/.test(lines[0])) lines = lines.slice(1);
    return lines.slice(1 + n).map(l => l.trim()).filter(Boolean).slice(0, STACK_KEEP);
  };

  function selectorPath(el) {
    const parts = [];
    while (el && el.nodeType === 1 && el !== document.documentElement) {
      let part = el.tagName.toLowerCase();
      if (el.id) { parts.unshift(`${part}#${cssEsc(el.id)}`); break; }
      const parent = el.parentNode;
      if (parent && parent.children) {
        const sibs = Array.from(parent.children).filter(c => c.tagName === el.tagName);
        if (sibs.length > 1) part += `:nth-of-type(${sibs.indexOf(el) + 1})`;
      }
      parts.unshift(part);
      el = parent;
    }
    return parts.join(' > ');
  }

  // ---------- Hook 1: who inserted this into the DOM ----------
  // Sink classification: what happens to a string written through this API?
  // risky = the browser parses it as HTML/JS/URL, so attacker-influenced text could become markup or code.
  function classify(via, node) {
    const v = String(via).replace(/ = …$/, '');
    const isScript = !!(node && node.tagName === 'SCRIPT');
    if (v === 'innerHTML' || v === 'outerHTML' || v === 'insertAdjacentHTML') return { label: 'HTML parser', risky: true };
    if (v === 'srcdoc') return { label: 'iframe HTML parser', risky: true };
    if (isScript && (v === 'text' || v === 'textContent' || v === 'innerText')) return { label: 'script code', risky: true };
    if (isScript && v === 'src') return { label: 'script URL', risky: true };
    if (isScript) return { label: 'inserts <script> element', risky: true };
    if (/\(string\)$/.test(v) || ['textContent', 'innerText', 'nodeValue', 'data', 'insertAdjacentText'].includes(v)) return { label: 'plain text', risky: false };
    return { label: 'DOM node insert', risky: false };
  }

  // Cheap preview of what a node holds (first text child only, so big subtrees cost nothing).
  const nodePreview = n => {
    try {
      if (n.nodeType === 3) return clip(n.nodeValue || '', 160);
      let c = n.firstChild;
      for (let i = 0; c && i < 8 && c.nodeType !== 3; i++) c = c.nextSibling;
      return c && c.nodeType === 3 ? clip(c.nodeValue || '', 160) : '';
    } catch (e) { return ''; }
  };

  // written = the string handed to the API, when there is one (innerHTML, textContent...).
  const mark = (node, via, written) => {
    if (!node || busy) return;
    try {
      const prev = domLog.get(node);
      domLog.set(node, {
        via, sink: classify(via, node), ...stamp(), stack: stack(2),
        preview: written !== undefined ? clip(String(written), 160) : nodePreview(node),
        history: prev ? [prev, ...(prev.history || [])].slice(0, 3) : []
      });
    } catch (e) {}
  };

  function patchMethod(proto, name) {
    const orig = proto[name];
    if (typeof orig !== 'function') return;
    proto[name] = function (...args) {
      for (const a of args) {
        if (a && a.nodeType === 11) { for (const c of Array.from(a.childNodes)) mark(c, name); }
        else if (a && a.nodeType) mark(a, name);
        else if (typeof a === 'string' && name !== 'insertAdjacentElement' && !(/^insertAdjacent/.test(name) && a === args[0])) {
          mark(this, /^insertAdjacent(HTML|Text)$/.test(name) ? name : name + '(string)', a);
        }
      }
      return orig.apply(this, args);
    };
    undo.push(() => { proto[name] = orig; });
  }

  function patchSetter(proto, prop, pick) {
    const d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      ...d,
      set(v) { mark(pick ? pick(this) : this, prop + ' = …', v); return d.set.call(this, v); }
    });
    undo.push(() => Object.defineProperty(proto, prop, d));
  }

  try {
    [[Node.prototype, ['appendChild', 'insertBefore', 'replaceChild']],
     [Element.prototype, ['append', 'prepend', 'before', 'after', 'replaceWith', 'replaceChildren',
                          'insertAdjacentHTML', 'insertAdjacentText', 'insertAdjacentElement']]
    ].forEach(([proto, names]) => names.forEach(n => { try { patchMethod(proto, n); } catch (e) {} }));

    [[Element.prototype, 'innerHTML'],
     [Element.prototype, 'outerHTML', n => n.parentNode],
     [Node.prototype, 'textContent'],
     [HTMLElement.prototype, 'innerText'],
     [Node.prototype, 'nodeValue'],
     [CharacterData.prototype, 'data'],
     [HTMLScriptElement.prototype, 'src'],
     [HTMLScriptElement.prototype, 'text'],
     [HTMLIFrameElement.prototype, 'srcdoc']
    ].forEach(([p, n, pick]) => { try { patchSetter(p, n, pick); } catch (e) {} });
  } catch (e) { console.warn('DOM hooks partially failed', e); }

  // ---------- Hook 1b: sinks that aren't plain DOM node writes ----------
  const attrLog = new WeakMap();   // element -> risky attributes set via setAttribute
  const codeSinks = [];            // document.write / string timers
  const messages = [];             // postMessage data seen (a source)

  const attrKind = (name, value) => {
    if (/^on/i.test(name)) return { kind: 'event-handler JS', risky: true };
    if (name.toLowerCase() === 'srcdoc') return { kind: 'iframe HTML parser', risky: true };
    if (/^(href|src|action|formaction|data|xlink:href)$/i.test(name)) {
      return { kind: 'URL', risky: /^\s*(javascript|data|vbscript):/i.test(String(value)) };
    }
    return null;
  };
  const logAttr = (el, name, value, k) => {
    try {
      const list = attrLog.get(el) || [];
      list.push({ name, value: clip(String(value), 200), kind: k.kind, risky: k.risky, ...stamp(), stack: stack(2) });
      attrLog.set(el, list);
    } catch (e) {}
  };
  const logCode = (sink, arg) => {
    try {
      codeSinks.push({ sink, arg: clip(String(arg), 2000), ...stamp(), stack: stack(2) });
      if (codeSinks.length > 300) codeSinks.shift();
    } catch (e) {}
  };

  try {
    const oSet = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      if (!busy) { const k = attrKind(String(name), value); if (k) logAttr(this, String(name), value, k); }
      return oSet.apply(this, arguments);
    };
    undo.push(() => { Element.prototype.setAttribute = oSet; });
  } catch (e) {}

  ['write', 'writeln'].forEach(name => {
    try {
      const o = Document.prototype[name];
      Document.prototype[name] = function (...args) {
        if (!busy) logCode('document.' + name + ' (HTML parser)', args.join(''));
        return o.apply(this, args);
      };
      undo.push(() => { Document.prototype[name] = o; });
    } catch (e) {}
  });

  ['setTimeout', 'setInterval'].forEach(name => {
    try {
      const o = window[name];
      window[name] = function (fn) {
        if (typeof fn === 'string' && !busy) logCode(name + '(string) (code)', fn);
        return o.apply(this, arguments);
      };
      undo.push(() => { window[name] = o; });
    } catch (e) {}
  });

  const onMessage = e => {
    try {
      const s = typeof e.data === 'string' ? e.data : JSON.stringify(e.data);
      if (s) { messages.push({ origin: e.origin, data: s.slice(0, 5000), ...stamp() }); if (messages.length > 200) messages.shift(); }
    } catch (err) {}
  };
  window.addEventListener('message', onMessage, true);
  undo.push(() => window.removeEventListener('message', onMessage, true));

  // ---------- Hook 1c: storage and cookie writes/reads (so we can order them against everything else) ----------
  const storageEvents = [];
  const logStorage = (area, op, key, value) => {
    if (busy) return;
    try {
      const v = value == null ? '' : String(value);
      storageEvents.push({ ...stamp(), area, op, key: String(key), value: clip(v, 500), vnorm: norm(v).slice(0, 500), stack: stack(2) });
      if (storageEvents.length > 500) storageEvents.shift();
    } catch (e) {}
  };
  const areaOf = o => {
    try { return o === window.localStorage ? 'localStorage' : o === window.sessionStorage ? 'sessionStorage' : 'storage'; }
    catch (e) { return 'storage'; }
  };
  try {
    const SP = Storage.prototype;
    const oSetItem = SP.setItem, oGetItem = SP.getItem, oRemoveItem = SP.removeItem, oClear = SP.clear;
    SP.setItem = function (k, v) { logStorage(areaOf(this), 'set', k, v); return oSetItem.apply(this, arguments); };
    SP.getItem = function (k) { const r = oGetItem.apply(this, arguments); logStorage(areaOf(this), 'get', k, r); return r; };
    SP.removeItem = function (k) { logStorage(areaOf(this), 'remove', k, ''); return oRemoveItem.apply(this, arguments); };
    SP.clear = function () { logStorage(areaOf(this), 'clear', '*', ''); return oClear.apply(this, arguments); };
    undo.push(() => { SP.setItem = oSetItem; SP.getItem = oGetItem; SP.removeItem = oRemoveItem; SP.clear = oClear; });
  } catch (e) {}
  try {
    const cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cd && cd.set) {
      Object.defineProperty(Document.prototype, 'cookie', {
        ...cd,
        set(v) {
          const s = String(v), i = s.indexOf('=');
          logStorage('cookie', 'set', i > 0 ? s.slice(0, i).trim() : s, i > 0 ? s.slice(i + 1).split(';')[0] : '');
          return cd.set.call(this, v);
        }
      });
      undo.push(() => Object.defineProperty(Document.prototype, 'cookie', cd));
    }
  } catch (e) {}

  // ---------- Hook 2: network responses (so we can match shown text to data) ----------
  const origFetch = window.fetch;
  if (typeof origFetch === 'function') {
    window.fetch = function (input, init) {
      const entry = {
        kind: 'fetch',
        url: String((input && input.url) || input),
        method: (init && init.method) || (input && input.method) || 'GET',
        ...stamp(), stack: stack(1), status: null, body: null,
        reqBody: init && typeof init.body === 'string' ? clip(init.body, 2000) : null
      };
      requests.push(entry);
      return origFetch.apply(this, arguments).then(res => {
        entry.status = res.status;
        entry.respT = performance.now();
        try { res.clone().text().then(t => { if (t.length <= MAX_BODY) entry.body = t; }).catch(() => {}); } catch (e) {}
        return res;
      });
    };
    undo.push(() => { window.fetch = origFetch; });
  }

  if (window.XMLHttpRequest) {
    const XP = XMLHttpRequest.prototype;
    const oOpen = XP.open, oSend = XP.send;
    XP.open = function (method, url) {
      this.__traceReq = { kind: 'xhr', method, url: String(url), status: null, body: null };
      return oOpen.apply(this, arguments);
    };
    XP.send = function (body) {
      const e = this.__traceReq;
      if (e) {
        Object.assign(e, stamp());
        e.stack = stack(1);
        e.reqBody = typeof body === 'string' ? clip(body, 2000) : null;
        requests.push(e);
        this.addEventListener('loadend', () => {
          e.status = this.status;
          e.respT = performance.now();
          try {
            let t = null;
            if (this.responseType === '' || this.responseType === 'text') t = this.responseText;
            else if (this.responseType === 'json') t = JSON.stringify(this.response);
            if (t && t.length <= MAX_BODY) e.body = t;
          } catch (err) {}
        });
      }
      return oSend.apply(this, arguments);
    };
    undo.push(() => { XP.open = oOpen; XP.send = oSend; });
  }

  // ---------- Safe serialization (no cycles, no fibers, bounded size) ----------
  const SKIP = new Set(['_owner', '_store', 'return', 'child', 'sibling', 'alternate', 'stateNode']);
  function safe(v, depth = 0, seen = new WeakSet()) {
    if (v == null || typeof v === 'number' || typeof v === 'boolean') return v;
    if (typeof v === 'string') return clip(v, 200);
    if (typeof v === 'function') return `ƒ ${v.name || 'anonymous'}()`;
    if (typeof v === 'symbol' || typeof v === 'bigint') return String(v);
    if (v instanceof Node) return `<${(v.nodeName || '').toLowerCase()}>`;
    if (v instanceof Date) { try { return v.toISOString(); } catch (e) { return 'Invalid Date'; } }
    if (v instanceof Map) return `Map(${v.size})`;
    if (v instanceof Set) return `Set(${v.size})`;
    if (typeof v === 'object') {
      if (seen.has(v)) return '[circular]';
      if (depth >= 3) return Array.isArray(v) ? `[Array(${v.length})]` : '{…}';
      seen.add(v);
      if (Array.isArray(v)) return v.slice(0, 30).map(x => safe(x, depth + 1, seen));
      const out = {};
      Object.keys(v).slice(0, 30).forEach(k => {
        if (SKIP.has(k)) return;
        try { out[k] = safe(v[k], depth + 1, seen); } catch (e) { out[k] = '[unreadable]'; }
      });
      return out;
    }
    return String(v);
  }

  // ---------- Framework detection ----------
  function compName(f) {
    const t = f.type;
    if (!t || typeof t === 'string') return null;
    if (typeof t === 'function') return t.displayName || t.name || 'Anonymous';
    return t.displayName || (t.render && (t.render.displayName || t.render.name)) ||
           (t.type && (t.type.displayName || t.type.name)) || null;
  }

  // Host props in the order they were written on the tag (JS keeps object keys in creation order, and this
  // copies them one by one without sorting). Function-valued props (onClick, onChange...) never appear as
  // page text, so they are moved out of hostProps into their own list. hostPropsOrder is the full list of
  // prop names in order, including the functions, so the order survives tools that re-sort object keys.
  function splitProps(p) {
    if (!p || typeof p !== 'object') return { values: safe(p), order: [], fns: [] };
    const values = {}, order = [], fns = [];
    Object.keys(p).slice(0, 60).forEach((k, i) => {
      order.push(k);
      let v;
      try { v = p[k]; } catch (e) { values[k] = '[unreadable]'; return; }
      if (typeof v === 'function') {
        let src = ''; try { src = clip(String(v).replace(/\s+/g, ' '), 160); } catch (e) {}
        fns.push({ prop: k, position: i, fn: v.name || 'anonymous', source: src });
        return;
      }
      if (SKIP.has(k)) return;
      try { values[k] = safe(v, 1, new WeakSet()); } catch (e) { values[k] = '[unreadable]'; }
    });
    return { values, order, fns };
  }

  // The address of the page you are on (full URL, and just the path).
  function pageEndpoint() {
    try { return { url: location.href, path: location.pathname }; } catch (e) { return null; }
  }

  // The tag as it is in the page: attribute names and values in the order the browser lists them (what you
  // see in the Elements panel). prop = the React prop that produced the attribute, when there is one.
  // Note the page order is not the React props order: React sets a field's value last, and an attribute
  // added by a later render is appended at the end.
  const PROP_ATTR = { className: 'class', htmlFor: 'for', httpEquiv: 'http-equiv', acceptCharset: 'accept-charset', defaultValue: 'value', defaultChecked: 'checked' };
  function domAttrList(el, propNames) {
    const lcToProp = new Map();
    (propNames || []).forEach(k => lcToProp.set((PROP_ATTR[k] || k).toLowerCase(), k));
    const pw = el.type === 'password';
    let names = []; try { names = el.getAttributeNames(); } catch (e) {}
    return names.map(n => {
      let v = ''; try { v = el.getAttribute(n); } catch (e) {}
      return { name: n, value: pw && n.toLowerCase() === 'value' ? '[hidden: password field]' : clip(String(v), 200), prop: lcToProp.get(n.toLowerCase()) || null };
    });
  }

  function reactInfo(el) {
    const key = Object.keys(el).find(k => k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$'));
    if (!key) return null;
    const fiber = el[key];
    const chain = [];
    let nearest = null, source = null;
    for (let f = fiber, i = 0; f && i < 80; f = f.return, i++) {
      if (!source && f._debugSource) source = f._debugSource;
      const name = compName(f);
      if (name) { if (!nearest) nearest = f; if (chain.length < 25) chain.push(name); }
    }
    const owners = [];
    for (let o = fiber._debugOwner, i = 0; o && i < 10; o = o._debugOwner, i++) {
      const nm = compName(o); if (nm) owners.push(nm);
    }
    let state;
    if (nearest) {
      const t = nearest.type;
      const isClass = typeof t === 'function' && t.prototype && t.prototype.isReactComponent;
      if (isClass) state = safe(nearest.memoizedState);
      else {
        const hooks = [];
        let h = nearest.memoizedState;
        while (h && typeof h === 'object' && 'next' in h && hooks.length < 20) { hooks.push(safe(h.memoizedState)); h = h.next; }
        state = hooks;
      }
    }
    const propsKey = Object.keys(el).find(k => k.startsWith('__reactProps$'));
    const hp = splitProps(propsKey && el[propsKey] && typeof el[propsKey] === 'object' ? el[propsKey] : fiber.memoizedProps);
    // hostProps in tag order: props that became attributes first, in the order they are on the tag, then the
    // rest (false/empty props that never reach the tag, children) in React's order.
    const tagOrdered = {}, seenP = new Set();
    domAttrList(el, hp.order).forEach(a => { if (a.prop && !seenP.has(a.prop) && Object.prototype.hasOwnProperty.call(hp.values, a.prop)) { seenP.add(a.prop); tagOrdered[a.prop] = hp.values[a.prop]; } });
    Object.keys(hp.values).forEach(k => { if (!seenP.has(k)) { seenP.add(k); tagOrdered[k] = hp.values[k]; } });
    hp.values = tagOrdered;
    return {
      framework: 'React', component: chain[0] || null, chain,
      owners: owners.length ? owners : undefined,
      source: source ? `${source.fileName}:${source.lineNumber}` : undefined,
      hostProps: hp.values,
      hostPropsOrder: hp.order,
      hostHandlers: hp.fns.length ? hp.fns : undefined,
      componentProps: nearest ? safe(nearest.memoizedProps) : undefined,
      state
    };
  }

  function vueInfo(el) {
    const inst = el.__vueParentComponent;
    if (inst) {
      const chain = [];
      for (let c = inst, i = 0; c && i < 25; c = c.parent, i++) {
        chain.push((c.type && (c.type.name || c.type.__name || String(c.type.__file || '').split('/').pop())) || 'Anonymous');
      }
      return { framework: 'Vue 3', component: chain[0], chain, file: inst.type && inst.type.__file, props: safe(inst.props), state: safe(inst.setupState) };
    }
    const v = el.__vue__;
    if (v) {
      const chain = [];
      for (let c = v, i = 0; c && i < 25; c = c.$parent, i++) chain.push(c.$options.name || c.$options._componentTag || 'Anonymous');
      return { framework: 'Vue 2', component: chain[0], chain, props: safe(v.$props), state: safe(v._data) };
    }
    return null;
  }

  function svelteInfo(el) {
    const loc = el.__svelte_meta && el.__svelte_meta.loc;
    return loc ? { framework: 'Svelte (dev mode)', source: `${loc.file}:${loc.line}:${loc.column}` } : null;
  }

  function angularInfo(el) {
    try {
      const ng = window.ng;
      if (!ng || !ng.getOwningComponent) return null;
      const c = ng.getOwningComponent(el) || (ng.getComponent && ng.getComponent(el));
      if (!c) return null;
      return { framework: 'Angular (dev mode)', component: c.constructor && c.constructor.name, state: safe(c) };
    } catch (e) { return null; }
  }

  function frameworkInfo(el) {
    for (let n = el, hops = 0; n && n.nodeType === 1 && hops < 8; n = n.parentElement, hops++) {
      let info = null;
      try { info = reactInfo(n) || vueInfo(n) || svelteInfo(n) || angularInfo(n); } catch (e) {}
      if (info) { if (n !== el) info.foundOn = selectorPath(n); return info; }
    }
    return null;
  }

  // ---------- Who inserted it ----------
  function domOrigin(el) {
    const order = Array.from(el.childNodes).filter(n => n.nodeType === 3).map(n => [n, 'text inside this element']);
    order.push([el, 'this element']);
    for (let p = el.parentNode; p && p.nodeType === 1; p = p.parentNode) order.push([p, () => 'ancestor ' + selectorPath(p)]);
    for (const [n, label] of order) {
      const rec = domLog.get(n);
      if (rec) {
        // Prefer the step that wrote the content (innerHTML, textContent...) over a later plain node move.
        const content = [rec, ...rec.history].find(x => x.sink.label !== 'DOM node insert') || rec;
        return {
          target: typeof label === 'function' ? label() : label,
          via: content.via, sink: content.sink, at: content.time, t: content.t, seq: content.seq, stack: content.stack,
          placedBy: content !== rec ? { via: rec.via, at: rec.time, caller: rec.stack[0] || null } : undefined
        };
      }
    }
    return null;
  }

  // ---------- Where the data came from ----------
  function findInJson(obj, needle, path, out, seen, depth) {
    if (out.length >= 5 || obj == null || depth > 14) return;
    const t = typeof obj;
    if (t === 'string' || t === 'number') { if (norm(obj).includes(needle)) out.push(path || '(root)'); return; }
    if (t !== 'object' || seen.has(obj)) return;
    seen.add(obj);
    for (const k of Object.keys(obj)) {
      if (out.length >= 5) return;
      let v; try { v = obj[k]; } catch (e) { continue; }
      findInJson(v, needle, Array.isArray(obj) ? `${path}[${k}]` : (path ? `${path}.${k}` : k), out, seen, depth + 1);
    }
  }
  const jsonHits = (obj, needle) => { const out = []; findInJson(obj, needle, '', out, new WeakSet(), 0); return out; };

  function searchSources(needle) {
    const hits = [];
    for (const r of requests) {
      if (!r.body || !r.body.toLowerCase().includes(needle)) continue;
      let paths = [];
      try { paths = jsonHits(JSON.parse(r.body), needle); } catch (e) {}
      hits.push({
        source: `${r.kind.toUpperCase()} ${r.method} ${r.url}`, status: r.status,
        where: paths.length ? paths : ['(in response text)'],
        reqSeq: r.seq,
        requestedBy: (r.stack || []).slice(0, 8)
      });
    }
    ['__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', '__APOLLO_STATE__', '__PRELOADED_STATE__', '__REDUX_STATE__', '__remixContext'].forEach(name => {
      try {
        if (window[name]) { const p = jsonHits(window[name], needle); if (p.length) hits.push({ source: 'window.' + name + ' (server-embedded data)', where: p }); }
      } catch (e) {}
    });
    try {
      document.querySelectorAll('script[type="application/json"], script[type="application/ld+json"]').forEach(s => {
        try { const p = jsonHits(JSON.parse(s.textContent), needle); if (p.length) hits.push({ source: 'inline <script type="' + s.type + '"' + (s.id ? ' id="' + s.id + '"' : '') + '>', where: p }); } catch (e) {}
      });
    } catch (e) {}
    try {
      [['localStorage', localStorage], ['sessionStorage', sessionStorage]].forEach(([nm, st]) => {
        for (let i = 0; i < st.length; i++) {
          const k = st.key(i);
          if (String(st.getItem(k)).toLowerCase().includes(needle)) hits.push({ source: nm, where: [k] });
        }
      });
    } catch (e) {}
    return hits;
  }

  const ownText = el => Array.from(el.childNodes).filter(n => n.nodeType === 3).map(n => n.nodeValue).join(' ').replace(/\s+/g, ' ').trim();

  function candidates(el) {
    const out = [];
    const t = ownText(el) || String(el.innerText || '').trim();
    if (t && t.length <= 300) out.push({ label: 'text', value: t });
    ['value', 'alt', 'title', 'placeholder'].forEach(p => {
      if (p === 'value' && el.type === 'password') return;   // never read password fields
      if (typeof el[p] === 'string' && el[p]) out.push({ label: p, value: el[p] });
    });
    ['href', 'src'].forEach(a => { const v = el.getAttribute && el.getAttribute(a); if (v) out.push({ label: a, value: v }); });
    return out.map(c => ({ label: c.label, value: norm(c.value).slice(0, 100) })).filter(c => c.value.length >= 3);
  }

  function listeners(el) {
    if (typeof getEventListeners !== 'function') return null; // console-only API
    try {
      return Object.entries(getEventListeners(el)).map(([type, arr]) => ({
        type,
        handlers: arr.map(l => ({ capture: l.useCapture, name: (l.listener && l.listener.name) || 'anonymous', src: clip(String(l.listener), 160) }))
      }));
    } catch (e) { return null; }
  }

  // URL / cookie / window.name / referrer / postMessage sources. These can match in both directions:
  // the shown text may contain the source value (reflection) or the source may contain the shown text.
  const safeDecode = s => { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); } };

  function relate(val, needle) {
    const v = norm(val);
    if (v.length < 3) return null;
    if (v.includes(needle)) return 'shown value appears inside the source';
    if (v.length <= 200 && needle.includes(v)) return 'source value appears inside the shown value';
    return null;
  }

  function liveSources(needle) {
    const hits = [];
    const add = (source, where, val, kind, ctrl) => {
      const relation = relate(val, needle);
      if (relation) hits.push({ source, where: [where], sourceKind: kind, controllable: ctrl, relation, value: clip(norm(val), 100) });
    };
    try {
      new URLSearchParams(location.search).forEach((v, k) => add('location.search', '?' + k, v, 'URL', true));
      const hash = location.hash.replace(/^#/, '');
      if (hash) {
        if (hash.includes('=')) new URLSearchParams(hash).forEach((v, k) => add('location.hash', '#' + k, v, 'URL', true));
        add('location.hash', '#…', safeDecode(hash), 'URL', true);
      }
      safeDecode(location.pathname).split('/').filter(Boolean).forEach((seg, i) => add('location.pathname', 'segment ' + i, seg, 'URL', true));
    } catch (e) {}
    try {
      document.cookie.split(';').forEach(c => {
        const i = c.indexOf('=');
        if (i > 0) add('document.cookie', c.slice(0, i).trim(), safeDecode(c.slice(i + 1)), 'cookie', false);
      });
    } catch (e) {}
    try { if (window.name) add('window.name', 'window.name', window.name, 'window.name', true); } catch (e) {}
    try { if (document.referrer) add('document.referrer', 'referrer', safeDecode(document.referrer), 'referrer', true); } catch (e) {}
    messages.forEach(m => add('postMessage from ' + m.origin, 'event.data', m.data, 'postMessage', true));
    return hits;
  }

  function kindOf(source) {
    if (/^(FETCH|XHR) /.test(source)) return 'network response';
    if (/^window\.|^inline <script/.test(source)) return 'embedded page data';
    if (/^(localStorage|sessionStorage)$/.test(source)) return 'storage';
    return 'other';
  }

  // ---------- Direction + timeline ----------
  const isEditable = el => !!(el.isContentEditable || el.tagName === 'TEXTAREA' ||
    (el.tagName === 'INPUT' && !/^(checkbox|radio|button|submit|reset|image|file|hidden|range|color)$/i.test(el.type || '')));

  // Which way does the value probably flow relative to the hovered element? Guessed from the kind of
  // source, whether a request carried the value out, and whether we saw a storage write or read.
  //   origin?       the element's value probably came from here
  //   destination?  the element's value probably went here
  //   derived?      this data was probably produced FROM the value (e.g. the response to a request carrying it)
  //   with page     shipped in the page HTML/data, a sibling of the value rather than its source
  function directionOf(d, editable, needleVals) {
    const has = s => !!s && needleVals.some(v => s.includes(v));
    if (d.sourceKind === 'embedded page data') return { direction: editable ? 'with page' : 'origin?' };
    if (d.sourceKind === 'network response') {
      const r = requests.find(x => x.seq === d.reqSeq);
      const sent = !!r && (has(norm(safeDecode(r.url))) || has(norm(r.reqBody || '')));
      if (!editable) return { direction: 'origin?', carriesValue: sent };
      return { direction: sent ? 'derived?' : 'unclear', carriesValue: sent };
    }
    if (d.sourceKind === 'storage' || d.sourceKind === 'cookie') {
      const area = d.sourceKind === 'cookie' ? 'cookie' : d.source;
      const key = d.where[0];
      const wrote = storageEvents.some(e => e.area === area && e.key === key && e.op === 'set' && has(e.vnorm));
      const read = storageEvents.some(e => e.area === area && e.key === key && e.op === 'get');
      if (editable) return { direction: wrote ? 'destination?' : 'unclear' };
      return { direction: read ? 'origin?' : 'unclear' };
    }
    return { direction: editable ? 'unclear' : 'origin?' };
  }

  function callerOf(stk) {
    const fr = parseFrame((stk || [])[0]);
    if (fr) return `${fr.url.split('/').pop().split('?')[0]}:${fr.line}:${fr.col}`;
    return stk && stk[0] ? clip(stk[0].replace(/^at /, ''), 90) : '';
  }

  function domRecords(el) {
    const order = Array.from(el.childNodes).filter(n => n.nodeType === 3).map(n => [n, 'text node']);
    order.push([el, 'this element']);
    for (let p = el.parentNode; p && p.nodeType === 1; p = p.parentNode) {
      order.push([p, 'ancestor <' + p.tagName.toLowerCase() + (p.id ? '#' + p.id : '') + '>']);
    }
    for (const [n, label] of order) {
      const rec = domLog.get(n);
      if (rec) return { label, recs: [rec, ...rec.history] };
    }
    return null;
  }

  // One list of everything we recorded that touches this value, oldest first.
  function timelineFor(el, dataSources, attrSinks, codeHits, needleVals) {
    const ev = [
      { seq: -2, t: 0, kind: 'page', text: 'page load: URL, server HTML and embedded page data exist from here' },
      { seq: -1, t: installT, kind: 'hooks', text: 'Hover Trace pasted. Anything before this point is invisible to it' }
    ];
    const seenReq = new Set();
    dataSources.filter(d => d.reqSeq != null).forEach(d => {
      if (seenReq.has(d.reqSeq)) return;
      seenReq.add(d.reqSeq);
      const r = requests.find(x => x.seq === d.reqSeq);
      if (!r) return;
      ev.push({ seq: r.seq, t: r.t, kind: 'request', caller: callerOf(r.stack), stack: r.stack,
        text: `${r.kind.toUpperCase()} ${r.method} ${clip(safeDecode(r.url), 100)}${d.carriesValue ? '   [URL/body carries the value]' : ''}` });
      if (r.respT) ev.push({ seq: r.seq + 0.5, t: r.respT, kind: 'response', text: `response ${r.status} after ${Math.round(r.respT - r.t)} ms; body contains the value` });
    });
    messages.filter(m => needleVals.some(v => relate(m.data, v))).slice(-5).forEach(m =>
      ev.push({ seq: m.seq, t: m.t, kind: 'message', text: `postMessage from ${m.origin}: ${clip(m.data, 80)}` }));

    const keys = new Set(dataSources.filter(d => d.sourceKind === 'storage' || d.sourceKind === 'cookie').map(d => d.where[0]));
    storageEvents.filter(e => keys.has(e.key) || (e.op === 'set' && needleVals.some(v => relate(e.value, v)))).slice(-8).forEach(e => {
      const what = e.area === 'cookie' ? `document.cookie = "${e.key}=${clip(e.value, 60)}"`
        : e.op === 'set' ? `${e.area}.setItem("${e.key}", "${clip(e.value, 60)}")`
        : e.op === 'get' ? `${e.area}.getItem("${e.key}") → ${e.value ? '"' + clip(e.value, 60) + '"' : 'null'}`
        : e.op === 'remove' ? `${e.area}.removeItem("${e.key}")` : `${e.area}.clear()`;
      ev.push({ seq: e.seq, t: e.t, kind: 'storage', text: what, caller: callerOf(e.stack), stack: e.stack });
    });

    const dr = domRecords(el);
    if (dr) dr.recs.forEach(rec => ev.push({ seq: rec.seq, t: rec.t, kind: 'dom', risky: rec.sink.risky, caller: callerOf(rec.stack), stack: rec.stack,
      text: `${rec.via} on ${dr.label} → ${rec.sink.label}` }));
    attrSinks.forEach(a => ev.push({ seq: a.seq, t: a.t, kind: 'attr', risky: a.risky, caller: callerOf(a.stack), stack: a.stack,
      text: `setAttribute(${a.name}) → ${a.kind}: ${clip(a.value, 60)}` }));
    codeHits.slice(-5).forEach(c => ev.push({ seq: c.seq, t: c.t, kind: 'code', risky: true, caller: callerOf(c.stack), stack: c.stack,
      text: `${c.sink}: ${clip(c.arg, 60)}` }));

    return ev.filter(e => typeof e.t === 'number').sort((a, b) => (a.t - b.t) || (a.seq - b.seq));
  }

  function trace(el) {
    const needles = candidates(el);
    const seen = new Set();
    const dataSources = [];
    const addSource = (n, m) => {
      const k = JSON.stringify([m.source, m.where]);
      if (seen.has(k)) return;
      seen.add(k);
      dataSources.push({ matched: `${n.label}: "${n.value}"`, sourceKind: kindOf(m.source), controllable: false, ...m });
    };
    needles.forEach(n => {
      searchSources(n.value).forEach(m => addSource(n, m));
      liveSources(n.value).forEach(m => addSource(n, m));
    });

    const needleVals = needles.map(n => n.value);
    const editable = isEditable(el);
    dataSources.forEach(d => Object.assign(d, directionOf(d, editable, needleVals)));

    const insertedBy = domOrigin(el);
    const attrSinks = (attrLog.get(el) || []).slice(-10);
    const codeHits = codeSinks.filter(c => needles.some(n => c.arg.toLowerCase().includes(n.value)));

    // Candidate flows: a URL/postMessage/etc. source whose value shows up at a sink.
    // Based on value matching, not real taint tracking, so treat it as a lead.
    const flows = [];
    dataSources.filter(d => d.controllable).forEach(d => {
      const src = `${d.source} (${d.where[0]})`;
      if (insertedBy) flows.push({ source: src, sink: `${insertedBy.sink.label} via ${insertedBy.via}`, risky: insertedBy.sink.risky, relation: d.relation });
      attrSinks.filter(a => d.value && a.value.toLowerCase().includes(d.value)).forEach(a =>
        flows.push({ source: src, sink: `setAttribute(${a.name}) → ${a.kind}`, risky: a.risky, relation: d.relation }));
      codeHits.filter(c => d.value && c.arg.toLowerCase().includes(d.value)).forEach(c =>
        flows.push({ source: src, sink: c.sink, risky: true, relation: d.relation }));
    });

    const framework = frameworkInfo(el);
    if (framework && el.type === 'password') {
      ['hostProps', 'componentProps', 'props', 'state'].forEach(k => { if (framework[k] !== undefined) framework[k] = '[hidden: password field]'; });
    }

    return {
      mouse_target: mouseTarget(),
      object_context: objectContext,
      page_endpoint: pageEndpoint(),
      element: selectorPath(el),
      domAttributes: domAttrList(el, framework && framework.hostPropsOrder),
      textShown: ownText(el) || null,
      editable,
      framework,
      insertedBy,
      dataSources,
      flows,
      attrSinks,
      codeSinks: codeHits.slice(-5),
      timeline: timelineFor(el, dataSources, attrSinks, codeHits, needleVals),
      listeners: listeners(el),
      hooksInstalledAt: installedAt,
      requestsLogged: requests.length
    };
  }

  // Run trace() without our own storage/DOM reads being logged by our own hooks.
  function traceQuiet(el) {
    const was = busy;
    busy = true;
    try { return trace(el); } finally { busy = was; }
  }

  // ---------- Source code view ----------
  const srcCache = new Map();   // script url -> Promise<{ doc, map, mapDocs } | null>
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const LIB = /node_modules|react-dom|react\.|vendor|jquery|lodash|polyfill|chunk-vendors|framework/i;
  // Use the ORIGINAL fetch so our own source downloads don't show up in the request log.
  const rawFetch = u => (origFetch || window.fetch).call(window, u, { credentials: 'same-origin' });

  function vlq(str) {
    const out = [];
    let shift = 0, val = 0;
    for (let i = 0; i < str.length; i++) {
      const d = B64.indexOf(str[i]);
      if (d < 0) return out;
      val += (d & 31) << shift;
      if (d & 32) shift += 5;
      else { const neg = val & 1; val >>= 1; out.push(neg ? -val : val); val = 0; shift = 0; }
    }
    return out;
  }

  // Generated (line, col), both 1-based, -> original source position via a standard v3 source map.
  function mapPos(map, line, col) {
    const lines = map.__lines || (map.__lines = map.mappings.split(';'));
    let src = 0, oLine = 0, oCol = 0;
    for (let l = 0; l < lines.length && l <= line - 1; l++) {
      let gCol = 0, best = null;
      if (lines[l]) {
        for (const seg of lines[l].split(',')) {
          const v = vlq(seg);
          if (!v.length) continue;
          gCol += v[0];
          if (v.length >= 4) {
            src += v[1]; oLine += v[2]; oCol += v[3];
            if (l === line - 1 && gCol <= col - 1) best = { src, oLine, oCol };
          }
        }
      }
      if (l === line - 1) {
        if (!best) return null;
        const root = map.sourceRoot ? String(map.sourceRoot).replace(/\/?$/, '/') : '';
        return {
          source: root + map.sources[best.src], line: best.oLine + 1, col: best.oCol + 1,
          content: map.sourcesContent && map.sourcesContent[best.src] != null ? map.sourcesContent[best.src] : null
        };
      }
    }
    return null;
  }

  async function loadMap(ref, base) {
    try {
      let json;
      if (/^data:/i.test(ref)) {
        const comma = ref.indexOf(',');
        const meta = ref.slice(0, comma), data = ref.slice(comma + 1);
        json = /;base64/i.test(meta)
          ? new TextDecoder().decode(Uint8Array.from(atob(data), c => c.charCodeAt(0)))
          : decodeURIComponent(data);
      } else {
        const res = await rawFetch(new URL(ref, base).href);
        if (!res.ok) return null;
        json = await res.text();
      }
      const map = JSON.parse(json.replace(/^\)\]\}'[^\n]*\n/, ''));
      if (!map || typeof map.mappings !== 'string' || !Array.isArray(map.sources) || map.sections) return null;
      return map;
    } catch (e) { return null; }
  }

  function makeDoc(name, text, url) {
    const starts = [0];
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
    return { name, text, starts, url };
  }
  const lineText = (doc, n) => {
    const s = doc.starts[n - 1];
    if (s === undefined) return null;
    const e = n < doc.starts.length ? doc.starts[n] - 1 : doc.text.length;
    return doc.text.slice(s, e).replace(/\r$/, '');
  };
  const idxOf = (doc, line, col) => (doc.starts[line - 1] || 0) + col - 1;
  const lineOfIdx = (doc, idx) => {
    let lo = 0, hi = doc.starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (doc.starts[mid] <= idx) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };

  function loadScript(url) {
    if (srcCache.has(url)) return srcCache.get(url);
    const p = (async () => {
      try {
        const res = await rawFetch(url);
        if (!res.ok) return null;
        const text = await res.text();
        if (text.length > 8e6) return null;
        const entry = { doc: makeDoc(url.split('/').pop().split('?')[0] || url, text, url), map: null, mapDocs: {} };
        let mm, last = null;
        const re = /[#@]\s*sourceMappingURL=([^\s'"*]+)/g;
        while ((mm = re.exec(text))) last = mm[1];
        if (last) entry.map = await loadMap(last, url);
        return entry;
      } catch (e) { return null; }
    })();
    srcCache.set(url, p);
    return p;
  }

  function parseFrame(line) {
    const m = /(https?:\/\/[^\s()]+|file:\/\/[^\s()]+):(\d+):(\d+)\)?\s*$/.exec(line || '');
    return m ? { url: m[1], line: +m[2], col: +m[3], raw: line } : null;
  }

  async function resolveFrame(fr) {
    const fname = fr.url.split('/').pop().split('?')[0] || fr.url;
    const entry = await loadScript(fr.url);
    if (!entry) return { frame: fr, unavailable: true, doc: null, line: fr.line, col: fr.col, name: fname };
    if (entry.map) {
      const pos = mapPos(entry.map, fr.line, fr.col);
      if (pos && pos.content != null) {
        const doc = entry.mapDocs[pos.source] || (entry.mapDocs[pos.source] = makeDoc(pos.source, pos.content, null));
        return { frame: fr, doc, line: pos.line, col: pos.col, original: true, bundle: `${entry.doc.name}:${fr.line}:${fr.col}`, name: pos.source };
      }
      if (pos) {
        return { frame: fr, doc: entry.doc, line: fr.line, col: fr.col, original: false, name: entry.doc.name,
                 originalLoc: `${pos.source}:${pos.line}:${pos.col} (not embedded in the map)` };
      }
    }
    return { frame: fr, doc: entry.doc, line: fr.line, col: fr.col, original: false, name: entry.doc.name };
  }

  // Heuristic: which code patterns read each kind of source?
  function sourceRegex(source) {
    if (/^location\.search/.test(source)) return /location\.search|URLSearchParams|location\.href|document\.URL/g;
    if (/^location\.hash/.test(source)) return /location\.hash|location\.href|document\.URL/g;
    if (/^location\.pathname/.test(source)) return /location\.pathname|location\.href|document\.URL/g;
    if (/^document\.cookie/.test(source)) return /document\.cookie/g;
    if (/^window\.name/.test(source)) return /window\.name/g;
    if (/^document\.referrer/.test(source)) return /document\.referrer/g;
    if (/^postMessage/.test(source)) return /addEventListener\(\s*['"]message['"]|\.onmessage\b/g;
    if (/^(localStorage|sessionStorage)$/.test(source)) return new RegExp(source, 'g');
    return null;
  }

  // First frame (the write itself), then `near` nearest callers and `far` outermost ones, skipping
  // frames that are plainly third-party library code when there are alternatives.
  function pickFrames(frames, near, far) {
    if (!frames.length) return [];
    const idxd = frames.map((fr, idx) => ({ fr, idx, lib: LIB.test(fr.url) }));
    const rest = idxd.slice(1);
    const own = rest.filter(x => !x.lib);
    const pool = own.length >= near + far ? own : rest;
    const nearPick = pool.slice(0, near);
    const farPick = pool.slice(nearPick.length).slice(-far).map(x => ({ ...x, outer: true }));
    return [{ ...idxd[0], outer: false }, ...nearPick.map(x => ({ ...x, outer: false })), ...farPick];
  }

  async function buildCodeView(t) {
    const items = [];
    const seen = new Set();
    const add = it => {
      const key = (it.doc ? it.doc.name : it.name) + ':' + it.line + ':' + it.col + ':' + it.role;
      if (seen.has(key)) return;
      seen.add(key);
      items.push(it);
    };
    const framesOf = (arr, max) => (arr || []).map(parseFrame).filter(Boolean).slice(0, max);

    // Sink side: where the value was written, plus who called that code
    const sinkSets = [];
    if (t.insertedBy) sinkSets.push({ frames: framesOf(t.insertedBy.stack, STACK_KEEP), label: `${t.insertedBy.via} · ${t.insertedBy.sink.label}`, risky: t.insertedBy.sink.risky });
    (t.attrSinks || []).filter(a => a.risky).slice(-1).forEach(a => sinkSets.push({ frames: framesOf(a.stack, STACK_KEEP), label: `setAttribute(${a.name}) · ${a.kind}`, risky: true }));
    (t.codeSinks || []).slice(-1).forEach(c => sinkSets.push({ frames: framesOf(c.stack, STACK_KEEP), label: c.sink, risky: true }));
    for (const s of sinkSets) {
      // Show the nearest callers and the OUTERMOST ones: the outer frames are usually the app's own
      // component code, while the nearest ones are generic helpers.
      const pick = pickFrames(s.frames, 3, 3);
      const res = await Promise.all(pick.map(f => resolveFrame(f.fr)));
      if (!res.length) continue;
      res.forEach((r, i) => { r.lib = LIB.test(r.frame.url + ' ' + r.name); r.outer = pick[i].outer; r.depth = pick[i].idx; });
      add({ ...res[0], role: 'SINK', label: s.label, risky: s.risky });
      res.slice(1).forEach(r => add({ ...r, role: 'CALLER', label: r.outer ? `outermost captured frame (#${r.depth + 1} of ${s.frames.length})` : 'called from', risky: false }));
    }

    // Source side (network): the code that made the request
    for (const d of t.dataSources.filter(d => d.sourceKind === 'network response').slice(0, 2)) {
      const res = await Promise.all(framesOf(d.requestedBy, 3).map(resolveFrame));
      if (res[0]) add({ ...res[0], role: 'REQUEST', label: d.source, risky: false });
    }

    // Source side (URL, cookie, postMessage, storage...): likely read sites near the sink code
    const anchors = items.filter(i => (i.role === 'SINK' || i.role === 'CALLER') && i.doc);
    for (const d of t.dataSources) {
      const re = sourceRegex(d.source);
      if (!re || !anchors.length) continue;
      const cands = [], seenIdx = new Set();
      for (const a of anchors) {
        const base = idxOf(a.doc, a.line, a.col);
        re.lastIndex = 0;
        let m, guard = 0;
        while ((m = re.exec(a.doc.text)) && guard++ < 2000) {
          if (m[0].length === 0) { re.lastIndex++; continue; }
          const k = a.doc.name + ':' + m.index;
          if (seenIdx.has(k)) continue;
          seenIdx.add(k);
          const dist = Math.abs(m.index - base);
          if (dist <= 6000) cands.push({ doc: a.doc, idx: m.index, len: m[0].length, dist });
        }
      }
      const seenLines = new Set();
      cands.sort((x, y) => x.dist - y.dist).filter(c => {
        const k = c.doc.name + ':' + lineOfIdx(c.doc, c.idx);
        if (seenLines.has(k)) return false;
        seenLines.add(k);
        return true;
      }).slice(0, 2).forEach(c => {
        const line = lineOfIdx(c.doc, c.idx);
        add({ doc: c.doc, line, col: c.idx - c.doc.starts[line - 1] + 1, hitLen: c.len, name: c.doc.name,
              role: 'SOURCE READ', label: `${d.source} (likely read, matched by pattern)`, risky: false, original: false });
      });
    }

    const order = { 'SOURCE READ': 0, REQUEST: 1, SINK: 2, CALLER: 3 };
    return items.sort((a, b) => order[a.role] - order[b.role]);
  }

  // =====================================================================
  // Field-name search: which code mentions the fields this value came from?
  // The call stack at the DOM write only shows generic helpers, and the response was read in a
  // different callback, so the stack cannot connect them. The data path can: if the value sits at
  // data.filterButtons[2].buttonLabel, the code that builds it must mention "filterButtons".
  // =====================================================================
  const GENERIC_KEYS = new Set(['data', 'value', 'values', 'name', 'text', 'title', 'label', 'items', 'item', 'type', 'key', 'keys',
    'result', 'results', 'response', 'body', 'content', 'url', 'href', 'list', 'params', 'query', 'html', 'props', 'state', 'node',
    'children', 'index', 'count', 'total', 'status', 'message', 'error', 'default', 'user', 'page', 'size', 'code', 'meta', 'info',
    'null', 'true', 'false', 'undefined', 'object', 'array', 'string', 'number', 'this', 'with', 'page', 'from', 'text']);

  function keysFromPaths(paths, loose) {
    const seen = new Set();
    (paths || []).forEach(p => {
      p = String(p);
      if (p.charAt(0) === '(') return;                       // e.g. "(in response text)"
      p.replace(/\[\d+\]/g, '').replace(/^\?/, '').split(/[^\w$]+/).forEach(k => {
        if (!k || k.length < 4 || /^\d+$/.test(k)) return;
        if (!loose && GENERIC_KEYS.has(k.toLowerCase())) return;
        seen.add(k);
      });
    });
    const score = k => k.length + (/_|[a-z][A-Z]/.test(k) ? 8 : 0);
    return Array.from(seen).sort((a, b) => score(b) - score(a)).slice(0, 4);
  }
  function pickKeys(paths) {
    const strict = keysFromPaths(paths, false);
    return strict.length ? strict : keysFromPaths(paths, true);
  }

  function pageScriptUrls() {
    const urls = new Set();
    document.querySelectorAll('script[src]').forEach(s => { try { urls.add(new URL(s.src, location.href).href); } catch (e) {} });
    try {
      performance.getEntriesByType('resource').forEach(r => {
        if (r.initiatorType === 'script' || /\.m?js(\?|#|$)/i.test(r.name)) urls.add(r.name);
      });
    } catch (e) {}
    // scripts we already downloaded for the call stack first, then the rest
    return Array.from(urls).sort((a, b) => (srcCache.has(b) ? 1 : 0) - (srcCache.has(a) ? 1 : 0)).slice(0, 40);
  }

  async function findFieldReads(keys) {
    const out = { keys, stats: {}, items: [], scripts: 0, unavailable: 0 };
    if (!keys.length) return out;
    const urls = pageScriptUrls();
    const loaded = await Promise.all(urls.map(u => loadScript(u)));
    const docs = [];
    loaded.forEach((en, i) => { if (en) docs.push({ doc: en.doc, url: urls[i] }); else out.unavailable++; });
    let n = 0;
    document.querySelectorAll('script:not([src])').forEach(s => {
      const type = (s.type || '').toLowerCase();
      if (type && !/javascript|module/.test(type)) return;
      const txt = s.textContent || '';
      if (txt.length < 40 || txt.length > 3e6 || n >= 15) return;
      n++;
      docs.push({ doc: makeDoc('inline <script> #' + n, txt, null), url: null });
    });
    out.scripts = docs.length;

    const CAP = 300, NEAR = 2500;
    const found = [];                                         // { d, key, pos: [idx...] }
    keys.forEach(k => { out.stats[k] = { hits: 0, scripts: 0, common: false }; });
    for (const d of docs) {
      for (const k of keys) {
        const re = new RegExp('(?<![\\w$])' + k.replace(/\$/g, '\\$') + '(?![\\w$])', 'g');
        const pos = [];
        let m;
        while ((m = re.exec(d.doc.text)) && pos.length < CAP) pos.push(m.index);
        if (pos.length) {
          out.stats[k].hits += pos.length;
          out.stats[k].scripts++;
          found.push({ d, key: k, pos });
        }
      }
    }
    keys.forEach(k => { if (out.stats[k].hits > 60) out.stats[k].common = true; });

    // Score each hit by how many OTHER searched fields appear close by in the same script.
    const specificity = k => k.length + (/_|[a-z][A-Z]/.test(k) ? 8 : 0);
    const cands = [];
    found.filter(f => !out.stats[f.key].common).forEach(f => {
      f.pos.forEach(idx => {
        const near = [];
        found.forEach(g => {
          if (g.d !== f.d || g.key === f.key) return;
          if (g.pos.some(p => Math.abs(p - idx) <= NEAR)) near.push(g.key);
        });
        cands.push({ d: f.d, key: f.key, idx, near, score: near.length * 100 + specificity(f.key) });
      });
    });
    cands.sort((a, b) => b.score - a.score || a.idx - b.idx);
    const chosen = [];
    for (const c of cands) {
      if (chosen.length >= 5) break;
      if (chosen.some(x => x.d === c.d && Math.abs(x.idx - c.idx) < 400)) continue;
      chosen.push(c);
    }
    for (const c of chosen) {
      const line = lineOfIdx(c.d.doc, c.idx);
      const col = c.idx - c.d.doc.starts[line - 1] + 1;
      const label = `reads ${c.key}` + (c.near.length ? ` (${c.near.join(', ')} nearby)` : '');
      let r = null;
      if (c.d.url) { try { r = await resolveFrame({ url: c.d.url, line, col, raw: '' }); } catch (e) { r = null; } }
      if (r && r.doc) out.items.push({ ...r, role: 'FIELD READ', label, risky: false, hitLen: r.original ? 0 : c.key.length });
      else out.items.push({ doc: c.d.doc, line, col, hitLen: c.key.length, name: c.d.doc.name, role: 'FIELD READ', label, risky: false, original: false });
    }
    return out;
  }

  // ----- snippet + highlighting -----
  const PATS = [
    [/\b(innerHTML|outerHTML|insertAdjacentHTML|document\.writeln?|srcdoc|eval|new Function)\b/g, 'risky'],
    [/\b(textContent|innerText|nodeValue|appendChild|insertAdjacentText|setAttribute|createTextNode)\b/g, 'safe'],
    [/(location\.(?:search|hash|href|pathname)|URLSearchParams|document\.(?:cookie|referrer|URL)|window\.name|localStorage|sessionStorage|\bfetch\s*\(|XMLHttpRequest|addEventListener\(\s*['"]message['"]|\.onmessage\b)/g, 'src']
  ];
  const MARK_STYLE = THEME.mark;

  function tokenAt(text, c0) {
    let s = Math.max(0, Math.min(c0, text.length - 1));
    const w = /[\w$]/;
    if (w.test(text[s] || '')) {
      while (s > 0 && w.test(text[s - 1])) s--;
      let e = s;
      while (e < text.length && w.test(text[e])) e++;
      return { s, e };
    }
    const m = /[\w$]+/.exec(text.slice(s, s + 12));
    return m ? { s: s + m.index, e: s + m.index + m[0].length } : { s, e: Math.min(text.length, s + 1) };
  }

  function paintLine(text, colMark) {
    let marks = [];
    PATS.forEach(([re, cls]) => {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        marks.push({ s: m.index, e: m.index + m[0].length, cls });
      }
    });
    if (colMark) {
      marks = marks.filter(p => !(p.e > colMark.s && p.s < colMark.e));
      marks.push({ s: colMark.s, e: colMark.e, cls: 'col' });
    }
    marks.sort((a, b) => a.s - b.s);
    let out = '', cur = 0;
    marks.forEach(mk => {
      if (mk.s < cur) return;
      out += esc(text.slice(cur, mk.s)) + `<span style="${MARK_STYLE[mk.cls]}">${esc(text.slice(mk.s, mk.e))}</span>`;
      cur = mk.e;
    });
    return out + esc(text.slice(cur));
  }

  function snippet(doc, line, col, ctx = 3) {
    const L = lineText(doc, line);
    if (L == null) return null;
    const rows = [];
    if (L.length > 400) {                       // minified: show a character window around the column
      const c0 = col - 1;
      const s = Math.max(0, c0 - 200), e = Math.min(L.length, c0 + 300);
      rows.push({ n: line, text: (s > 0 ? '…' : '') + L.slice(s, e) + (e < L.length ? '…' : ''), hit: true, colAt: c0 - s + (s > 0 ? 1 : 0) });
    } else {
      for (let n = Math.max(1, line - ctx); n <= Math.min(doc.starts.length, line + ctx); n++) {
        rows.push({ n, text: lineText(doc, n), hit: n === line, colAt: n === line ? col - 1 : -1 });
      }
    }
    return { rows };
  }

  const ROLE_COLOR = { 'SOURCE READ': '#ffe66d', REQUEST: '#ffe66d', 'FIELD READ': '#55e6e0', SINK: '#ff7b7b', CALLER: '#82a9cc' };

  function plainItem(it) {
    const sn = it.doc ? snippet(it.doc, it.line, it.col) : null;
    return {
      role: it.role, label: it.label,
      location: it.unavailable ? `${it.frame.url}:${it.frame.line}:${it.frame.col}` : `${it.name}:${it.line}:${it.col}`,
      viaSourceMap: it.original ? it.bundle : undefined,
      unavailable: it.unavailable || undefined,
      lines: sn ? sn.rows.map(r => ({ n: r.n, hit: r.hit, text: r.text })) : undefined
    };
  }

  // =====================================================================
  // PRESENTATION DATA LAYER (shared by every design). It turns the raw trace into things a view can
  // lay out: a call ladder with function names, re-flowed code, the data around a matched field,
  // and a plain-English account. The views below only decide how to arrange them.
  // =====================================================================
  const shortFile = u => String(u || '').split('/').pop().split('?')[0] || String(u || '');
  const LOOP_FN = /\b(?:Array|Map|Set|NodeList|Object)\.(?:forEach|map|reduce|filter|flatMap|some|every|find|from|entries)\b/;
  const fmtLoc = f => (f.url ? shortFile(f.url) + ':' + f.line + ':' + f.col : f.raw.replace(/^at\s+/, ''));
  const keyOf = fr => fr.url + ':' + fr.line + ':' + fr.col;

  // "at fn (url:l:c)" lines -> [{ i, fn, native, loop, lib, url, line, col, file }]
  function ladderOf(stack) {
    return (stack || []).map((raw, i) => {
      const fr = parseFrame(raw);
      const m = /^at\s+(?:async\s+)?(?:(.+?)\s+\()?([^()]*?)\)?$/.exec(String(raw).trim());
      return {
        i, raw, fr, fn: m && m[1] ? m[1] : '', native: !fr, loop: LOOP_FN.test(raw),
        url: fr ? fr.url : null, line: fr ? fr.line : 0, col: fr ? fr.col : 0,
        file: fr ? shortFile(fr.url) : '', lib: !!fr && LIB.test(fr.url)
      };
    });
  }
  const fnShown = f => f.fn || (f.native ? '(native)' : 'anonymous');
  function frameRole(f, last) {
    if (f.i === 0) return 'WRITE';
    if (f.loop) return 'LOOP';
    if (f.native) return 'NATIVE';
    if (f.lib) return 'LIB';
    return last ? 'ENTRY' : 'CALL';
  }
  // The call path as plain data for the JSON export: one entry per frame, innermost first.
  // role uses the same rules as the panel (WRITE / LOOP / NATIVE / LIB / CALL / ENTRY).
  function callPathOf(stack, res, firstRole) {
    const lad = ladderOf(stack);
    const lastApp = lad.filter(f => !f.native).slice(-1)[0];
    return lad.map(f => {
      const o = { step: f.i, role: f.i === 0 && firstRole ? firstRole : frameRole(f, lastApp && f.i === lastApp.i), fn: f.fn || (f.native ? '(native)' : '(anonymous)') };
      if (f.fr) { o.file = f.file; o.line = f.line; o.col = f.col; o.url = f.url; } else o.builtIn = true;
      const r = res && f.fr ? res.get(keyOf(f.fr)) : null;
      if (r && r.original) o.originalSource = r.name + ':' + r.line + ':' + r.col;
      else if (r && r.originalLoc) o.originalSource = r.originalLoc;
      return o;
    });
  }
  function attachCallPaths(t, res) {
    t.callPathOrder = 'innermost first: step 0 is the write itself, the last step is the outermost caller';
    t.callPath = callPathOf(t.insertedBy && t.insertedBy.stack, res);
    (t.dataSources || []).forEach(d => { if (d.requestedBy && d.requestedBy.length) d.requestedByPath = callPathOf(d.requestedBy, res, 'REQUEST'); });
  }
  // outermost -> write, as short display names, long runs collapsed in the middle
  function pathNames(ladder, headN, tailN) {
    const names = ladder.slice().reverse().filter(f => !f.native || f.loop).map(f => (f.loop ? '⟳ ' + f.fn.replace(/^.*\./, '') : fnShown(f)));
    if (names.length <= headN + tailN + 1) return names;
    return names.slice(0, headN).concat(['… ' + (names.length - headN - tailN) + ' more …'], names.slice(-tailN));
  }

  // Nearest function declaration before a position (a hint for "which function is this inside?")
  function enclosingFn(doc, idx) {
    const s = doc.text.slice(Math.max(0, idx - 2500), idx);
    const re = /function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?function\b|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>/g;
    let best = null, m;
    while ((m = re.exec(s))) best = m[1] || m[2] || m[3];
    return best;
  }

  // ----- re-flow minified code around a position so it can be read -----
  function beautify(src, hS, hE) {
    const lines = [];
    let cur = '', indent = 0, paren = 0, hs = -1, he = -1, hitLine = -1;
    const ps = [];
    const pad = () => '  '.repeat(Math.min(indent, 12));
    const note = (str, at) => {
      if (hs === -1 && hS >= at && hS < at + str.length) hs = cur.length + (hS - at);
      if (hs >= 0 && he === -1 && hE > at && hE <= at + str.length) he = cur.length + (hE - at);
    };
    const flush = () => {
      const txt = cur.replace(/\s+$/, '');
      if (txt.trim()) {
        const ln = { text: txt, hs: -1, he: -1 };
        if (hs >= 0 && hitLine < 0) { hitLine = lines.length; ln.hs = hs; ln.he = he >= 0 ? Math.min(he, txt.length) : txt.length; hs = -2; he = -2; }
        lines.push(ln);
      }
      cur = '';
    };
    const newline = () => { flush(); cur = pad(); };
    for (let i = 0; i < src.length;) {
      const c = src[i];
      if (c === '"' || c === "'" || c === '`') {
        let j = i + 1;
        while (j < src.length && src[j] !== c) { if (src[j] === '\\') j++; j++; }
        j = Math.min(src.length, j + 1);
        const tok = src.slice(i, j); note(tok, i); cur += tok; i = j; continue;
      }
      if (c === '/' && src[i + 1] === '*') {
        const j = src.indexOf('*/', i + 2), e = j < 0 ? src.length : j + 2;
        const tok = src.slice(i, e); note(tok, i); cur += tok; i = e; continue;
      }
      if (c === '\n' || c === '\r') { if (cur.trim()) newline(); i++; continue; }
      if (c === '{') {
        if (/^\s*\}/.test(src.slice(i + 1, i + 4))) { const j = src.indexOf('}', i + 1); const tok = src.slice(i, j + 1); note(tok, i); cur += tok; i = j + 1; continue; }
        note('{', i); cur += '{'; ps.push(paren); paren = 0; indent++; newline(); i++; continue;
      }
      if (c === '}') {
        paren = ps.length ? ps.pop() : 0; indent = Math.max(0, indent - 1);
        flush(); cur = pad(); note('}', i); cur += '}'; i++;
        if (src[i] && !/[,;)\].]/.test(src[i])) newline();
        continue;
      }
      if (c === ';') { note(';', i); cur += ';'; i++; if (paren <= 0) newline(); else cur += ' '; continue; }
      if (c === '(' || c === '[') paren++;
      else if (c === ')' || c === ']') paren = Math.max(0, paren - 1);
      note(c, i); cur += c; i++;
    }
    flush();
    return { lines, hitLine };
  }

  // Rows of readable code around a position. Normal source keeps its real line numbers; a minified
  // line is re-flowed (line numbers shown as ·) so it reads like code instead of one long line.
  function prettyAt(doc, line, col, hitLen) {
    const L = lineText(doc, line);
    if (L == null) return null;
    if (L.length <= 400) {
      const sn = snippet(doc, line, col, 4);
      if (!sn) return null;
      return { minified: false, rows: sn.rows.map(r => {
        const mk = r.hit ? (hitLen ? { s: r.colAt, e: r.colAt + hitLen } : tokenAt(r.text, r.colAt)) : null;
        return { n: r.n, text: r.text, hit: r.hit, hs: mk ? mk.s : -1, he: mk ? mk.e : -1 };
      }) };
    }
    const base = doc.starts[line - 1] || 0;
    const idx = base + col - 1;
    let tok;
    if (hitLen) tok = { s: idx, e: idx + hitLen };
    else { const lc = tokenAt(L, col - 1); tok = { s: base + lc.s, e: base + lc.e }; }
    let a = Math.max(0, idx - 700), b = Math.min(doc.text.length, idx + 900);
    if (a > 0) { const k = doc.text.slice(a, idx).search(/[;}{]/); if (k >= 0) a += k + 1; }
    if (b < doc.text.length) { const fw = doc.text.slice(idx, b); const lb = Math.max(fw.lastIndexOf(';'), fw.lastIndexOf('}')); if (lb > 200) b = idx + lb + 1; }
    const bt = beautify(doc.text.slice(a, b), tok.s - a, tok.e - a);
    const hi = Math.max(0, bt.hitLine);
    const from = Math.max(0, hi - 8), to = Math.min(bt.lines.length, hi + 9);
    return { minified: true, clipTop: from > 0, clipBottom: to < bt.lines.length,
      rows: bt.lines.slice(from, to).map((l, k) => ({ n: null, text: l.text, hit: from + k === hi, hs: l.hs, he: l.he })) };
  }

  function codeBlockHtml(pr, note) {
    if (!pr) return `<span ${MUTED}>no source available for this position</span>\n`;
    let h = `<div style="${THEME.codeBox}">`;
    if (pr.clipTop) h += `<div ${MUTED}>      …</div>`;
    pr.rows.forEach(r => {
      const mk = r.hs >= 0 ? { s: r.hs, e: r.he } : null;
      const gut = r.n != null ? String(r.n).padStart(5) + '  ' : '    ·  ';
      h += `<div style="${r.hit ? THEME.hitRow : ''}"><span style="color:#82a9cc;user-select:none">${esc(gut)}</span>${paintLine(r.text, mk)}</div>`;
    });
    if (pr.clipBottom) h += `<div ${MUTED}>      …</div>`;
    h += `</div>`;
    if (pr.minified) h += `<div ${MUTED}>minified code, re-flowed here so it can be read${note ? ' · ' + note : ''}</div>`;
    else if (note) h += `<div ${MUTED}>${note}</div>`;
    return h;
  }

  // Readable code for a resolved frame/field read (result of resolveFrame, or a field-read item).
  function resolvedCodeHtml(res) {
    if (!res) return `<span ${MUTED}>source not loaded yet</span>\n`;
    if (res.unavailable) return `<span ${MUTED}>source unavailable (cross-origin without CORS, blocked by CSP, or not downloadable)</span>\n`;
    const where = (res.original ? res.name + ':' + res.line + ':' + res.col + ' (source map; bundle ' + res.bundle + ')' : res.name + ':' + res.line + ':' + res.col);
    return `<div ${MUTED}>${esc(where)}</div>` + codeBlockHtml(prettyAt(res.doc, res.line, res.col, res.hitLen || 0));
  }

  // ----- the data around a matched field: "what is data.items and why is it there" -----
  const clipV = (v, n) => {
    if (v == null) return String(v);
    if (typeof v === 'string') return '"' + clip(v, n) + '"';
    if (typeof v !== 'object') return String(v);
    try { return clip(JSON.stringify(v), n); } catch (e) { return '{…}'; }
  };

  function rootFor(d) {
    try {
      if (d.reqSeq != null) { const r = requests.find(x => x.seq === d.reqSeq); return r ? tryJson(r) : null; }
      const m = /^window\.([\w$]+)/.exec(d.source);
      if (m) return window[m[1]];
      const id = /id="([^"]+)"/.exec(d.source);
      const sel = id ? 'script#' + cssEsc(id[1]) : null;
      const els = sel ? document.querySelectorAll(sel) : document.querySelectorAll('script[type="application/json"], script[type="application/ld+json"]');
      for (const s of els) { try { return JSON.parse(s.textContent); } catch (e) {} }
    } catch (e) {}
    return null;
  }

  function dataContext(root, path) {
    if (!root || !path || path.charAt(0) === '(') return null;
    const toks = pathTokens(path);
    const leaf = getTok(root, toks);
    const ctx = { path, toks, leaf: clipV(leaf, 80), crumbs: toks.map(t => (typeof t === 'number' ? '[' + t + ']' : String(t))) };
    let pos = -1;
    for (let p = toks.length - 1; p >= 0; p--) if (typeof toks[p] === 'number') { pos = p; break; }
    if (pos >= 0) {
      const arrToks = toks.slice(0, pos), arr = getTok(root, arrToks);
      if (Array.isArray(arr)) {
        const idx = toks[pos], field = toks.slice(pos + 1);
        const lo = Math.max(0, idx - 2), hi = Math.min(arr.length, idx + 3);
        ctx.arr = { path: arrToks.join('.') || '(root)', total: arr.length, idx, field: field.join('.'),
          before: lo, after: arr.length - hi,
          items: arr.slice(lo, hi).map((e, k) => ({ i: lo + k, text: clipV(field.length ? getTok(e, field) : e, 60), hit: lo + k === idx })) };
        const entry = arr[idx];
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
          ctx.entry = Object.keys(entry).slice(0, 8).map(k => ({ k, v: clipV(entry[k], 50), hit: field.length && k === field[0] }));
        }
        return ctx;
      }
    }
    const parent = toks.length > 1 ? getTok(root, toks.slice(0, -1)) : root;
    if (parent && typeof parent === 'object' && !Array.isArray(parent)) {
      ctx.obj = { path: toks.slice(0, -1).join('.') || '(root)', total: Object.keys(parent).length,
        keys: Object.keys(parent).slice(0, 8).map(k => ({ k, v: clipV(parent[k], 50), hit: k === toks[toks.length - 1] })) };
    }
    return ctx;
  }
  const dataContexts = d => {
    const root = rootFor(d);
    if (!root) return [];
    return (d.where || []).slice(0, 3).map(p => dataContext(root, p)).filter(Boolean);
  };

  function ctxHtml(ctx, opts) {
    opts = opts || {};
    let h = '';
    const crumbs = ctx.crumbs.map((c, i) => (i === ctx.crumbs.length - 1 ? THEME.tag(esc(c), '#ffb86b') : `<span style="color:#e4f3ff">${esc(c)}</span>`)).join(`<span ${MUTED}> › </span>`);
    h += `<div style="margin:3px 0 5px;">${crumbs}</div>`;
    if (ctx.arr) {
      const a = ctx.arr;
      h += `<div ${MUTED}>${esc(a.path)} is a list of ${a.total} entries${a.field ? '; showing field ' + esc(a.field) + ' of each' : ''}</div>`;
      h += `<div style="${THEME.codeBox}">`;
      if (a.before) h += `<div ${MUTED}>   … ${a.before} before</div>`;
      a.items.forEach(it => {
        h += `<div style="${it.hit ? THEME.hitRow : ''}"><span ${MUTED}>${esc(('[' + it.i + ']').padEnd(6))}</span>${it.hit ? '<span style="color:#ffb86b">' + esc(it.text) + '</span>  <span style="color:#ffb86b">◀ the value you hovered</span>' : esc(it.text)}</div>`;
      });
      if (a.after) h += `<div ${MUTED}>   … ${a.after} after</div>`;
      h += `</div>`;
      if (ctx.entry && !opts.noEntry) {
        h += `<div ${MUTED}>that entry as a whole:</div><div style="${THEME.codeBox}">`;
        ctx.entry.forEach(f => { h += `<div style="${f.hit ? THEME.hitRow : ''}"><span style="color:#55e6e0">${esc(f.k)}</span><span ${MUTED}>: </span>${esc(f.v)}</div>`; });
        h += `</div>`;
      }
    } else if (ctx.obj) {
      h += `<div ${MUTED}>${esc(ctx.obj.path)} is an object with ${ctx.obj.total} fields</div><div style="${THEME.codeBox}">`;
      ctx.obj.keys.forEach(f => { h += `<div style="${f.hit ? THEME.hitRow : ''}"><span style="color:#55e6e0">${esc(f.k)}</span><span ${MUTED}>: </span>${f.hit ? '<span style="color:#ffb86b">' + esc(f.v) + '</span>' : esc(f.v)}</div>`; });
      if (ctx.obj.total > ctx.obj.keys.length) h += `<div ${MUTED}>… ${ctx.obj.total - ctx.obj.keys.length} more fields</div>`;
      h += `</div>`;
    }
    return h;
  }

  // ----- sources, in a useful order, with plain-English direction -----
  const DIR_WORDS = {
    'origin?': 'probably where the page got the value',
    'destination?': 'probably where the value was sent',
    'derived?': 'probably a response to a request that carried the value',
    'with page': 'shipped with the page (a neighbour of the value, not necessarily its source)',
    'unclear': 'direction unclear'
  };
  function parseSource(s) {
    const m = /^(FETCH|XHR)\s+(\w+)\s+(.*)$/.exec(s);
    if (!m) return null;
    let short = m[3];
    try { const u = new URL(m[3], location.href); short = u.pathname + u.search; } catch (e) {}
    return { kind: m[1], method: m[2], url: m[3], short: clip(safeDecode(short), 90) };
  }
  const originRank = d => (d.sourceKind === 'network response' ? 0 : d.sourceKind === 'embedded page data' ? 1 : d.sourceKind === 'storage' ? 2 : d.sourceKind === 'cookie' ? 3 : 4) + (d.direction === 'origin?' ? 0 : 10);

  // ----- the model every view renders -----
  function buildModel(ts) {
    const t = ts.t, ib = t.insertedBy;
    const ladder = ladderOf(ib && ib.stack);
    ladder.forEach(f => { if (f.fr && ts.res) f.res = ts.res.get(keyOf(f.fr)); });
    const origins = t.dataSources.map((d, k) => {
      const src = parseSource(d.source);
      const lad = ladderOf(d.requestedBy || []);
      lad.forEach(f => { if (f.fr && ts.res) f.res = ts.res.get(keyOf(f.fr)); });
      return { d, k, src, ctxs: (d.sourceKind === 'network response' || d.sourceKind === 'embedded page data') ? dataContexts(d) : [], ladder: lad };
    }).sort((a, b) => originRank(a.d) - originRank(b.d));
    const events = (t.timeline || []).map((e, i, arr) => ({ ...e, dt: i ? Math.max(0, e.t - arr[i - 1].t) : 0, ladder: e.stack ? ladderOf(e.stack) : null }));
    events.forEach(e => (e.ladder || []).forEach(f => { if (f.fr && ts.res) f.res = ts.res.get(keyOf(f.fr)); }));
    const code = Array.isArray(ts.code) ? ts.code : [];
    const M = {
      t, ts, ib, ladder, origins, events,
      loops: ladder.filter(f => f.loop).length,
      codeState: ts.code === 'loading' ? 'loading' : ts.code === 'error' ? 'error' : 'ready',
      fr: ts.fr,                                    // field-read result, null while searching
      frState: ts.fr ? 'ready' : (ts.code === 'loading' ? 'waiting' : 'loading'),
      sourceReads: code.filter(i => i.role === 'SOURCE READ'),
      primary: origins[0] || null,
      writeMs: ib && ib.t != null ? ib.t : null
    };
    M.story = storyOf(M);
    return M;
  }

  // ----- plain-English account -----
  const Qs = s => '“' + esc(s) + '”';
  const Cs = s => THEME.val(esc(s));
  const Bs = s => '<b>' + esc(s) + '</b>';
  function storyOf(M) {
    const t = M.t, ib = M.ib, steps = [], notes = [];
    const val = t.textShown ? Qs(clip(t.textShown, 60)) : 'this element';
    const w = M.ladder[0];
    const writer = w ? Cs(fnShown(w) + '()') + (w.file ? ' <span ' + MUTED + '>(' + esc(w.file + ':' + w.line + ':' + w.col) + ')</span>' : '') : null;
    const when = M.writeMs != null ? ' at ' + Bs(fmtT(M.writeMs)) + ' after page load' : '';
    const o = M.primary;
    const originPhrase = o => {
      const d = o.d;
      if (o.src) return 'the response of ' + Cs(o.src.method + ' ' + o.src.short) + (d.status ? ' (status ' + d.status + ')' : '') + (d.where[0] && d.where[0].charAt(0) !== '(' ? ', at ' + Cs(d.where[0]) : '');
      if (d.sourceKind === 'embedded page data') return Cs(d.source) + (d.where[0] ? ', at ' + Cs(d.where[0]) : '');
      if (d.sourceKind === 'storage') return Cs(d.source) + ' under the key ' + Cs(d.where[0]);
      if (d.sourceKind === 'cookie') return 'the cookie ' + Cs(d.where[0]);
      if (d.sourceKind === 'URL') return 'the page URL (' + Cs(d.where[0]) + ')';
      return Cs(d.source);
    };

    // lead (worded by direction: an input's text is often where the value WENT, not where it came from)
    const link = o => {
      const dir = o.d.direction;
      const k = o.d.change && o.d.change.kind;
      const same = !k || k === 'identical' ? 'the same text' : 'a version of the same text';
      if (dir === 'origin?') return `${same} is in ${originPhrase(o)}`;
      if (dir === 'derived?') return `${same} also appears in ${originPhrase(o)}, which looks like a response to a request that carried it`;
      if (dir === 'destination?') return `${same} also appears in ${originPhrase(o)}, probably because it was saved there`;
      return `${same} also appears in ${originPhrase(o)}`;
    };
    const tr = t.transform;
    let lead;
    if (ib) lead = `${val} was put on the page by ${writer} using ${Cs(ib.via)}${when}` + (o ? `, and ${link(o)}.` : '.');
    else if (t.editable) lead = `${val} is in an editable field. No script wrote it after you pasted this (it may have been typed, or set earlier).` + (o ? ` Also, ${link(o)}.` : '');
    else lead = `${val} was not written by any script that ran after you pasted this, so it was probably in the server's HTML or rendered earlier.` + (o ? ` Also, ${link(o)}.` : '');
    // 1. where it came from
    if (o) {
      let s = `<b>Where the text came from.</b> It matches ${originPhrase(o)}. That is ${esc(DIR_WORDS[o.d.direction] || 'a match')}.`;
      const c = o.ctxs[0];
      if (c && c.arr) s += ` In that data it is entry ${Bs(String(c.arr.idx + 1))} of ${Bs(String(c.arr.total))} in ${Cs(c.arr.path)}${c.arr.field ? ', in the field ' + Cs(c.arr.field) : ''}, so the server sent a list and the page turned each entry into one element.`;
      else if (c && c.obj) s += ` In that data it sits in the object ${Cs(c.obj.path)}, next to ${esc(c.obj.keys.filter(k => !k.hit).slice(0, 3).map(k => k.k).join(', '))}.`;
      steps.push(s);
      M.origins.filter(x => x !== o).slice(0, 3).forEach(x => {
        if (x.d.sourceKind === 'URL') notes.push(`The text also appears in the page URL (${Cs(x.d.where[0])}). That is a match of values only; it does not show the URL was written into the page. Check this if it matters for safety.`);
        else notes.push(`It also matches ${originPhrase(x)} (${esc(DIR_WORDS[x.d.direction] || 'direction unclear')}).`);
      });
    } else if (tr && tr.direct.length) {
      steps.push(`<b>Where the text came from.</b> No source holds exactly this text, but ${esc(tr.summary)}`);
      lead += ` No source holds exactly this text, but ${esc(tr.summary)}`;
    } else if (tr && tr.built) {
      steps.push(`<b>Where the text came from.</b> No single source holds this text, but it ${esc(tr.built.summary)}. That is a match on text only.`);
      lead += ` No single source holds this text, but it ${esc(tr.built.summary)}.`;
    } else steps.push(`<b>Where the text came from.</b> No match was found in captured requests, embedded page data, storage, the URL, cookies, window.name, the referrer or postMessage, so it may be computed in the page or came from something this tool cannot see.`);
    // 1b. did the page change it on the way
    if (tr && tr.verdict === 'unchanged') steps.push(`<b>Changed on the way?</b> No. ${esc(tr.summary)}`);
    else if (o && tr && (tr.verdict === 'changed' || tr.verdict === 'reformatted')) steps.push(`<b>Changed on the way?</b> Yes. ${esc(tr.summary)} This compares values only, so it shows that a change happened but not which line of code did it.`);
    // 2. how it got there
    if (M.ladder.length) {
      const names = pathNames(M.ladder, 3, 4).map(n => (n.charAt(0) === '…' ? `<span ${MUTED}>${esc(n)}</span>` : Cs(n))).join(' <span ' + MUTED + '>→</span> ');
      const outer = M.ladder.filter(f => !f.native).slice(-1)[0];
      let s = `<b>How it got there.</b> The write happened ${M.ladder.length} calls deep: ${names}.`;
      if (M.loops) s += ` The path goes through ${Bs(String(M.loops))} array loop${M.loops === 1 ? '' : 's'}, so this code runs once for each item in a list.`;
      if (outer) s += ` The outermost call recorded is ${Cs(fnShown(outer))} <span ${MUTED}>(${esc(outer.file + ':' + outer.line + ':' + outer.col)})</span>.`;
      steps.push(s);
    }
    // 3. the code that knows the field names
    if (M.fr && M.fr.items && M.fr.items.length) {
      const it = M.fr.items[0];
      const fnm = it.doc ? enclosingFn(it.doc, idxOf(it.doc, it.line, it.col)) : null;
      steps.push(`<b>Code that mentions the data.</b> ${Bs(String(M.fr.items.length))} place${M.fr.items.length === 1 ? '' : 's'} in the page's scripts mention ${esc(M.fr.keys.join(', '))}. The best match is ${Cs(it.name + ':' + it.line + ':' + it.col)}${fnm ? ' <span ' + MUTED + '>(near the function ' + esc(fnm) + ')</span>' : ''}. This is a text search, so it is a strong lead rather than proof.`);
    } else if (M.frState === 'loading' || M.frState === 'waiting') steps.push(`<b>Code that mentions the data.</b> <span ${MUTED}>Searching the page's scripts…</span>`);
    else if (M.fr && M.fr.keys.length) steps.push(`<b>Code that mentions the data.</b> No readable script mentions ${esc(M.fr.keys.join(', '))}. The names may be built at run time or live in a script that could not be downloaded.`);
    // 4. timing
    const req = M.events.find(e => e.kind === 'request'), res = M.events.find(e => e.kind === 'response'), dom = M.events.find(e => e.kind === 'dom');
    if (req && dom) steps.push(`<b>When.</b> The request left at ${Bs(fmtT(req.t))}${res ? ', the response arrived at ' + Bs(fmtT(res.t)) : ''}, and the element was written at ${Bs(fmtT(dom.t))} (${esc(fmtT(Math.max(0, dom.t - req.t)))} after the request).`);
    // notes
    const risky = (t.flows || []).find(f => f.risky);
    if (risky) notes.unshift(`${Bs('Heads-up:')} the page-controllable value ${Cs(risky.source)} also appears in this element, and the write used an HTML-parsing sink (${esc(risky.sink)}). Matching values do not prove the URL value was written there. To check, put ${Cs('<b>x</b>')} in that parameter and see whether it renders bold.`);
    if (!ib && !o && !t.editable) notes.push(`To check whether the server wrote it: open the page source (Ctrl/Cmd+U) and search for the text. If it is there, it arrived in the HTML.`);
    if (t.editable) notes.push(`This is an editable field, so matches in requests, storage and the URL are often where the value <b>went</b>, not where it came from.`);
    return { lead, steps, notes };
  }

  // ----- secondary blocks, shared by all views -----
  function extrasHtml(r) {
    const out = { framework: '', listeners: '', attr: '', sinks: '' };
    const f = r.framework;
    if (f) {
      let h = `${esc(f.framework)}${f.foundOn ? ' (found on ' + esc(f.foundOn) + ')' : ''}\n`;
      if (f.chain) h += `chain: ${green(f.chain.join(' ‹ '))}\n`;
      else if (f.component) h += `component: ${green(f.component)}\n`;
      if (f.owners) h += `rendered by (dev): ${green(f.owners.join(' ‹ '))}\n`;
      if (f.source || f.file) h += `source: ${green(f.source || f.file)}\n`;
      if (f.componentProps) h += `props:\n${green(json(f.componentProps))}\n`;
      if (f.props) h += `props:\n${green(json(f.props))}\n`;
      if (f.hostProps) h += `element props (in tag order):\n${green(json(f.hostProps))}\n`;
      if (f.hostHandlers && f.hostHandlers.length) h += `element handlers (functions, not shown on the page):\n` + f.hostHandlers.map(x => `  #${x.position + 1} ${green(x.prop)}: ${esc(x.fn)}${x.fn === 'anonymous' ? ' <span ' + MUTED + '>' + esc(clip(x.source, 80)) + '</span>' : ''}\n`).join('');
      if (f.state !== undefined) h += `state:\n${green(json(f.state))}\n`;
      out.framework = h;
    } else out.framework = `<span ${MUTED}>No React, Vue, Angular or Svelte data on this element or its parents.</span>\n`;
    if (r.listeners && r.listeners.length) out.listeners = r.listeners.map(l => `${esc(l.type)}: ${green(l.handlers.map(x => x.name).join(', '))}\n`).join('');
    if (r.attrSinks && r.attrSinks.length) out.attr = r.attrSinks.map(a => `${a.risky ? '<span style="color:#ff7b7b">⚠</span> ' : ''}setAttribute(${esc(a.name)}) → ${green(a.kind)}: ${green(clip(a.value, 80))}  <span ${MUTED}>${esc((a.stack[0] || '').replace(/^at /, ''))}</span>\n`).join('');
    if (r.codeSinks && r.codeSinks.length) out.sinks = r.codeSinks.map(c => `<span style="color:#ff7b7b">⚠</span> ${green(c.sink)}: ${green(clip(c.arg, 80))}  <span ${MUTED}>${esc((c.stack[0] || '').replace(/^at /, ''))}</span>\n`).join('');
    return out;
  }

  const attrQ = s => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  // a clickable thing inside the panel (handled by onPanelClick)
  const act = (kind, key, inner, css) => `<span data-act="${kind}" data-k="${attrQ(key)}" style="cursor:pointer;${css || ''}">${inner}</span>`;
  const pre = s => `<div style="white-space:pre-wrap;">${s}</div>`;

  function fieldReadsHtml(fr, state) {
    if (!fr) return `<span ${MUTED}>${state === 'loading' || state === 'waiting' ? 'Searching the page\'s scripts…' : 'not searched'}</span>\n`;
    if (!fr.keys.length) return `<span ${MUTED}>The field names in the data path are too generic to search for (data, value, name…), or there was no data path.</span>\n`;
    let h = `<span ${MUTED}>Text search of ${fr.scripts} script${fr.scripts === 1 ? '' : 's'} for the field names this value sits under. A hit means the code mentions the field: a strong lead, not proof. Hits where several fields sit close together come first.</span>\n`;
    fr.keys.forEach(k => {
      const s = fr.stats[k];
      h += `  ${green(k)}  <span ${MUTED}>${s.common ? s.hits + '+ hits, too common to be useful, skipped' : s.hits + ' hit' + (s.hits === 1 ? '' : 's') + ' in ' + s.scripts + ' script' + (s.scripts === 1 ? '' : 's')}</span>\n`;
    });
    if (fr.unavailable) h += `<span ${MUTED}>${fr.unavailable} script${fr.unavailable === 1 ? '' : 's'} could not be downloaded (cross-origin without CORS or blocked), so they were not searched.</span>\n`;
    if (!fr.items.length) return h + `<span ${MUTED}>No readable script mentions these fields${fr.keys.some(k => fr.stats[k].common) ? ' beyond the too-common ones' : ''}. The names may be built at run time, or the code may be in a script that could not be downloaded.</span>\n`;
    return h + fieldItemsHtml(fr.items);
  }
  function fieldItemsHtml(items) {
    let h = '';
    items.forEach(it => {
      const fnm = it.doc ? enclosingFn(it.doc, idxOf(it.doc, it.line, it.col)) : null;
      h += `\n${THEME.role('FIELD READ', '#55e6e0')} ${esc(it.label)}${fnm ? ' <span ' + MUTED + '>· near function ' + esc(fnm) + '</span>' : ''}\n`;
      h += resolvedCodeHtml({ doc: it.doc, line: it.line, col: it.col, name: it.name, original: it.original, bundle: it.bundle, hitLen: it.hitLen });
    });
    return h;
  }

  // ----- trace panel state and painting -----
  let ts = null;
  function paintTrace(reset) {
    if (!ts) return;
    const M = buildModel(ts);
    const top = reset ? 0 : panel.scrollTop;
    quiet(() => { panel.innerHTML = VIEW.trace(M, ts.ui); });
    panel.style.display = 'block';
    panel.scrollTop = top;
    return M;
  }
  function handleAct(kind, key) {
    if (!ts) return;
    const ui = ts.ui;
    const flip = (set, k) => { if (set.has(k)) set.delete(k); else set.add(k); };
    if (kind === 'tab') ui.tab = key;
    else if (kind === 'frame') flip(ui.open, key);
    else if (kind === 'sec') flip(ui.sec, key);
    else if (kind === 'ev') ui.ev = +key;
    else if (kind === 'allframes') { const n = +key; if (ui.open.size >= n) ui.open.clear(); else for (let i = 0; i < n; i++) ui.open.add(String(i)); }
    paintTrace(false);
  }

  // =====================================================================
  // DID THE PAGE CHANGE THE VALUE?  (1) compare the raw source value with what is shown, and
  // (2) when no single source holds the text, look for pieces of it (the page may have built it).
  // Value comparison only: it can show that a change happened and what kind, not which line did it.
  // =====================================================================
  const Qt = s => '“' + clip(String(s), 70) + '”';
  const unHtml = s => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e.charAt(0) === '#') { const n = /^#x/i.test(e) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(n); } catch (x) { return m; } }
    const k = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[e.toLowerCase()];
    return k === undefined ? m : k;
  });
  const unB64 = s => {
    s = s.trim();
    if (s.length < 8 || s.length % 4 === 1 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
    try {
      const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
      try { return decodeURIComponent(escape(bin)); } catch (e) { return /^[\x20-\x7e]*$/.test(bin) ? bin : null; }
    } catch (e) { return null; }
  };
  const numOf = s => { const m = String(s).replace(/[,\s$€£¥%]/g, ''); return /^-?\d+(\.\d+)?$/.test(m) ? parseFloat(m) : null; };
  const collapse = s => String(s).replace(/\s+/g, ' ').trim();

  // the shown text contains the source text with something added around it
  function wrapOf(rc, s) {
    if (rc.length < 3) return null;
    const i = s.toLowerCase().indexOf(rc.toLowerCase());
    if (i < 0) return null;
    return { before: s.slice(0, i), after: s.slice(i + rc.length), caseChanged: s.substr(i, rc.length) !== rc };
  }
  const wrapDetail = (w, how) => {
    const parts = [];
    if (w.before.trim()) parts.push(Qt(w.before) + ' before it');
    if (w.after.trim()) parts.push(Qt(w.after) + ' after it');
    const extra = [how, w.caseChanged ? 'capitalisation also differs' : ''].filter(Boolean).join('; ');
    return 'the page added ' + (parts.join(' and ') || 'extra spacing or punctuation') + (extra ? ' (' + extra + ')' : '');
  };

  // S = what the page shows, R = the raw value found in the source. null when they are unrelated.
  function classifyChange(S, R) {
    const s = collapse(S), r = String(R), rc = collapse(r);
    const out = (kind, detail, extra) => Object.assign({ kind, detail }, extra || {});
    if (r === s) return out('identical', 'the source holds exactly the text the page shows');
    if (rc === s) return out('whitespace', 'same text; extra spaces or line breaks were tidied');
    if (rc.toLowerCase() === s.toLowerCase()) return out('case', 'same letters, different capitalisation');
    // the source holds an encoded form
    const decoders = [['URL-encoded', () => decodeURIComponent(r.replace(/\+/g, ' '))], ['HTML-escaped', () => unHtml(r)], ['base64', () => unB64(r)]];
    for (const [label, fn] of decoders) {
      let v = null; try { v = fn(); } catch (e) { v = null; }
      if (v == null || v === r) continue;
      const vc = collapse(v);
      if (vc.toLowerCase() === s.toLowerCase()) return out('encoded', 'the source holds it ' + label + '; the page shows the decoded text', { encoding: label });
      const w = wrapOf(vc, s);
      if (w) return out('wrapped', 'the source holds it ' + label + '; ' + wrapDetail(w), { encoding: label, before: w.before, after: w.after });
    }
    // the page shows an encoded form of the source
    try {
      if (encodeURIComponent(rc) === s || encodeURI(rc) === s) return out('encoded', 'the page shows the source text URL-encoded', { encoding: 'URL-encoded' });
      const esc2 = rc.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      if (esc2 !== rc && esc2 === s) return out('encoded', 'the page shows the source text HTML-escaped', { encoding: 'HTML-escaped' });
    } catch (e) {}
    const na = numOf(rc), nb = numOf(s);
    if (na !== null && nb !== null && na === nb) return out('reformatted', 'same number, formatted differently');
    const w = wrapOf(rc, s);
    if (w) return out('wrapped', wrapDetail(w), { before: w.before, after: w.after });
    if (rc.length > s.length) {
      const stripped = s.replace(/\s*(…|\.\.\.)$/, '');
      const truncated = stripped !== s;
      if (stripped.length >= 3) {
        const i = rc.toLowerCase().indexOf(stripped.toLowerCase());
        if (i === 0 && truncated) return out('truncated', 'the page shows only the first ' + stripped.length + ' characters of a longer source value (' + rc.length + ' characters)');
        if (i >= 0) return out('partial', 'the page shows a piece of a longer source value (' + rc.length + ' characters)');
      }
    }
    return null;
  }

  // The raw string behind a data source entry, or null when it cannot be read back.
  function rawValueFor(d) {
    try {
      if (d.reqSeq != null || /^window\./.test(d.source) || /^inline <script/.test(d.source)) {
        const w0 = d.where && d.where[0];
        if (!w0 || w0.charAt(0) === '(') return null;
        const v = getTok(rootFor(d), pathTokens(w0));
        return typeof v === 'string' || typeof v === 'number' ? String(v) : null;
      }
      const w0 = (d.where && d.where[0]) || '';
      if (d.source === 'location.search') return new URLSearchParams(location.search).get(w0.replace(/^\?/, ''));
      if (d.source === 'location.hash') { const h = location.hash.replace(/^#/, ''); return w0 === '#…' ? safeDecode(h) : new URLSearchParams(h).get(w0.replace(/^#/, '')); }
      if (d.source === 'location.pathname') return safeDecode(location.pathname).split('/').filter(Boolean)[+String(w0).replace(/\D/g, '')] || null;
      if (d.source === 'window.name') return window.name || null;
      if (d.source === 'document.referrer') return safeDecode(document.referrer) || null;
      if (d.source === 'document.cookie') {
        for (const c of document.cookie.split(';')) { const i = c.indexOf('='); if (i > 0 && c.slice(0, i).trim() === w0) return safeDecode(c.slice(i + 1)); }
        return null;
      }
      if (d.source === 'localStorage' || d.source === 'sessionStorage') {
        const v = window[d.source].getItem(w0);
        return v != null && v.length <= 2000 ? v : null;
      }
    } catch (e) {}
    return null;
  }

  // ----- (2) pieces: which fields could the shown text be made of? -----
  const LEAF_CAP = 30000;
  function leafWalk(obj, path, src, out, depth, seen) {
    if (out.length >= LEAF_CAP || depth > 12 || obj == null) return;
    const ty = typeof obj;
    if (ty === 'string' || ty === 'number') { const v = String(obj); if (v.length >= 3 && v.length <= 300) out.push({ src, path: path || '(root)', value: v }); return; }
    if (ty !== 'object' || seen.has(obj)) return;
    seen.add(obj);
    const arr = Array.isArray(obj);
    const keys = arr ? obj.slice(0, 500).map((_, i) => i) : Object.keys(obj).slice(0, 500);
    for (const k of keys) {
      let v; try { v = obj[k]; } catch (e) { continue; }
      leafWalk(v, arr ? path + '[' + k + ']' : (path ? path + '.' + k : String(k)), src, out, depth + 1, seen);
    }
  }
  function gatherLeaves() {
    const out = [], seen = new WeakSet();
    for (const r of requests) {
      const j = tryJson(r);
      if (j) leafWalk(j, '', r.kind.toUpperCase() + ' ' + r.method + ' ' + r.url, out, 0, seen);
    }
    EMBED_GLOBALS.forEach(name => { try { if (window[name]) leafWalk(window[name], '', 'window.' + name + ' (server-embedded data)', out, 0, seen); } catch (e) {} });
    try {
      document.querySelectorAll('script[type="application/json"], script[type="application/ld+json"]').forEach(s => {
        try { leafWalk(JSON.parse(s.textContent), '', 'inline <script type="' + s.type + '"' + (s.id ? ' id="' + s.id + '"' : '') + '>', out, 0, seen); } catch (e) {}
      });
    } catch (e) {}
    try {
      [['localStorage', localStorage], ['sessionStorage', sessionStorage]].forEach(([nm, st]) => {
        for (let i = 0; i < st.length && out.length < LEAF_CAP; i++) {
          const k = st.key(i); const v = st.getItem(k);
          if (v == null || v.length > 20000) continue;
          let j = null; try { j = JSON.parse(v); } catch (e) {}
          if (j && typeof j === 'object') leafWalk(j, k, nm, out, 0, seen);
          else if (v.length >= 3 && v.length <= 300) out.push({ src: nm, path: k, value: v });
        }
      });
    } catch (e) {}
    try { new URLSearchParams(location.search).forEach((v, k) => { if (v.length >= 3) out.push({ src: 'location.search', path: '?' + k, value: v }); }); } catch (e) {}
    try { if (window.name && window.name.length >= 3) out.push({ src: 'window.name', path: 'window.name', value: window.name }); } catch (e) {}
    return out;
  }

  function builtFrom(shown) {
    const S = collapse(shown), L = S.toLowerCase();
    if (S.length < 5) return null;
    const word = c => !!c && /[a-z0-9]/.test(c);
    const cands = new Map();                                        // lowercase value -> candidate
    for (const lf of gatherLeaves()) {
      const v = collapse(lf.value);
      if (!/[a-z0-9]/i.test(v)) continue;
      const lv = v.toLowerCase();
      if (lv === L) return null;                                    // one field holds all of it: the direct comparison covers that
      if (lv.length >= L.length) continue;
      if (lv.length < 4 && !/^\d{3}$/.test(lv)) continue;
      let c = cands.get(lv);
      if (!c) {
        let from = 0, idx = -1;
        while ((from = L.indexOf(lv, from)) >= 0) {
          if ((!word(L[from - 1]) || !word(lv[0])) && (!word(L[from + lv.length]) || !word(lv[lv.length - 1]))) { idx = from; break; }
          from++;
        }
        if (idx < 0) { cands.set(lv, false); continue; }
        c = { value: v, idx, len: lv.length, srcs: [] };
        cands.set(lv, c);
      }
      if (c && c.srcs.length < 3) c.srcs.push({ source: lf.src, where: lf.path });
    }
    const list = Array.from(cands.values()).filter(Boolean).sort((a, b) => b.len - a.len);
    const chosen = [];
    for (const c of list) if (!chosen.some(x => c.idx < x.idx + x.len && x.idx < c.idx + c.len)) chosen.push(c);
    if (!chosen.length) return null;
    chosen.sort((a, b) => a.idx - b.idx);
    const nonSp = x => x.replace(/\s/g, '').length;
    const covered = chosen.reduce((n, c) => n + nonSp(S.substr(c.idx, c.len)), 0);
    const coverage = covered / Math.max(1, nonSp(S));
    if (!(coverage >= 0.5 || (chosen.length === 1 && chosen[0].len >= 8 && coverage >= 0.35))) return null;
    if (chosen.length === 1 && coverage >= 0.999) return null;
    const added = [];
    let pos = 0;
    chosen.forEach((c, i) => {
      const gap = S.slice(pos, c.idx);
      if (gap.trim()) added.push({ text: gap, position: i === 0 ? 'before' : 'between' });
      pos = c.idx + c.len;
    });
    const tail = S.slice(pos);
    if (tail.trim()) added.push({ text: tail, position: 'after' });
    const pieces = chosen.map(c => ({ value: c.value, source: c.srcs[0].source, where: c.srcs[0].where, offset: c.idx,
      alsoIn: c.srcs.slice(1) }));
    const shortSrc = s => { const p = parseSource(s); return p ? p.method + ' ' + p.short : s; };
    const summary = 'looks built from ' + pieces.map(p => Qt(p.value) + ' (' + shortSrc(p.source) + ', at ' + p.where + ')').join(' + ') +
      (added.length ? ', with ' + added.map(a => Qt(a.text.trim()) + ' (' + a.position + ')').join(' and ') + ' added by the page' : '');
    return { coverage: Math.round(coverage * 100) / 100, pieces, added, summary };
  }

  const srcKindOf = src => /^(FETCH|XHR) /.test(src) ? 'network response' : /^window\.|^inline <script/.test(src) ? 'embedded page data' : /^(localStorage|sessionStorage)$/.test(src) ? 'storage' : /^location\./.test(src) || /^document\.referrer/.test(src) ? 'URL' : src === 'document.cookie' ? 'cookie' : 'other';
  const kindRank = k => ({ 'network response': 0, 'embedded page data': 1, storage: 2, cookie: 3 }[k] === undefined ? 4 : { 'network response': 0, 'embedded page data': 1, storage: 2, cookie: 3 }[k]);
  // A field whose whole value is the shown text after a change (found even when the shown text is not a substring of it)
  const LEAF_KINDS = ['whitespace', 'case', 'encoded', 'reformatted', 'truncated'];
  function leafChanges(shown, have) {
    const out = [];
    for (const lf of gatherLeaves()) {
      const key = lf.src + '|' + lf.path;
      if (have.has(key)) continue;
      const c = classifyChange(shown, lf.value);
      if (!c) continue;
      if (!(LEAF_KINDS.includes(c.kind) || (c.kind === 'wrapped' && c.encoding))) continue;
      have.add(key);
      out.push({ source: lf.src, sourceKind: srcKindOf(lf.src), where: lf.path, sourceValue: clip(lf.value, 200), kind: c.kind, detail: c.detail });
      if (out.length >= 8) break;
    }
    return out;
  }

  // Compare every data source with the shown text, then look further (whole-field comparison, then pieces).
  function attachTransform(t, el) {
    const shown = t.textShown || (el && typeof el.value === 'string' && el.type !== 'password' && el.value ? el.value : null);
    const tr = { shown: shown || null, verdict: 'unknown', direct: [], built: null, summary: 'No source value to compare.' };
    t.transform = tr;
    if (!shown) return;
    const have = new Set();
    (t.dataSources || []).forEach(d => {
      const raw = rawValueFor(d);
      if (raw == null) return;
      d.sourceValue = clip(String(raw), 200);
      const c = classifyChange(shown, raw);
      if (c) { d.change = c; have.add(d.source + '|' + d.where[0]); tr.direct.push({ source: d.source, sourceKind: d.sourceKind, where: d.where[0], sourceValue: d.sourceValue, kind: c.kind, detail: c.detail }); }
    });
    if (!tr.direct.some(x => x.kind === 'identical')) tr.direct.push(...leafChanges(shown, have));
    tr.direct.sort((a, b) => (kindRank(a.sourceKind) + (a.kind === 'partial' ? 10 : 0)) - (kindRank(b.sourceKind) + (b.kind === 'partial' ? 10 : 0)));
    const same = tr.direct.find(x => x.kind === 'identical');
    if (same) { tr.verdict = 'unchanged'; tr.summary = 'The text on screen is exactly what the source holds (' + Qt(same.sourceValue) + ').'; return; }
    if (tr.direct.length) {
      const x = tr.direct[0];
      if (x.kind === 'partial') {
        tr.verdict = 'contained';
        tr.summary = 'The shown text is part of a longer source value (' + srcShort(x.source) + ', at ' + x.where + '). That is a match, not necessarily a change made by the page.';
        return;
      }
      tr.verdict = x.kind === 'case' || x.kind === 'whitespace' ? 'reformatted' : 'changed';
      tr.summary = 'The source (' + srcShort(x.source) + ', at ' + x.where + ') holds ' + Qt(x.sourceValue) + ' and the page shows ' + Qt(shown) + ': ' + x.detail + '.';
      return;
    }
    const b = builtFrom(shown);
    if (b) { tr.built = b; tr.verdict = 'built'; tr.summary = Qt(shown) + ' ' + b.summary + '.'; }
  }
  const srcShort = s => { const p = parseSource(s); return p ? p.method + ' ' + p.short : s; };
  const xfNote = M => (M.t.transform && (M.t.transform.direct.length || M.t.transform.built)) ? ' A changed or assembled form of the text was found; see the section on changes.' : '';

  // ----- display -----
  const XF_TAG = { identical: ['UNCHANGED', '#9dffcb'], whitespace: ['TIDIED', '#ffe66d'], case: ['CASE CHANGED', '#ffe66d'], encoded: ['ENCODING', '#ffb86b'], wrapped: ['WRAPPED', '#ffb86b'], truncated: ['SHORTENED', '#ffb86b'], partial: ['PIECE OF', '#ffb86b'], reformatted: ['REFORMATTED', '#ffe66d'], built: ['ASSEMBLED', '#c9b0ff'] };
  const xfTag = k => { const x = XF_TAG[k] || [k.toUpperCase(), '#e4f3ff']; return THEME.tag(esc(x[0]), x[1]); };
  function xfHtml(M) {
    const tr = M.t.transform;
    if (!tr || !tr.shown) return `<span ${MUTED}>Nothing to compare: this element has no text of its own.</span>`;
    let h = '';
    tr.direct.slice(0, 4).forEach(d => {
      h += `<div style="margin:5px 0;">${xfTag(d.kind)} <span ${MUTED}>${esc(d.sourceKind)}${d.where ? ' · ' + esc(clip(d.where, 50)) : ''}</span>` +
        `<div style="line-height:1.55;">${esc(d.detail)}</div>` +
        (d.kind === 'identical' ? '' : `<div ${MUTED}>source ${Qs(clip(d.sourceValue, 80))} → page ${Qs(clip(tr.shown, 80))}</div>`) + `</div>`;
    });
    if (tr.built) {
      h += `<div style="margin:5px 0;">${xfTag('built')} <span ${MUTED}>no single field holds this text; ${Math.round(tr.built.coverage * 100)}% of it matches field values</span>`;
      tr.built.pieces.forEach(p => { h += `<div style="margin:2px 0 2px 8px;">${Qs(p.value)} <span ${MUTED}>from</span> ${Cs(clip(p.source.replace(/^(FETCH|XHR) /, ''), 60))} <span ${MUTED}>at</span> ${Cs(p.where)}</div>`; });
      tr.built.added.forEach(a => { h += `<div style="margin:2px 0 2px 8px;"><span ${MUTED}>page adds ${esc(a.position)}:</span> ${Qs(a.text.trim())}</div>`; });
      h += `<div ${MUTED}>Based on matching text only; a field with the same words elsewhere could be the real source.</div></div>`;
    }
    if (!tr.direct.length && !tr.built) h += `<span ${MUTED}>No source value to compare. The text may be computed in the page from something this tool cannot see, or built from pieces too short to match safely.</span>`;
    return h;
  }

  // ----- the call stack as an expandable ladder (used inside several views) -----
  const ROLE_COL = { WRITE: '#ff7b7b', LOOP: '#c9b0ff', ENTRY: '#ffe66d', CALL: '#e4f3ff', LIB: '#82a9cc', NATIVE: '#82a9cc' };
  function ladderHtml(ladder, S, pfx, opts) {
    opts = opts || {};
    if (!ladder.length) return `<span ${MUTED}>no call stack was recorded</span>\n`;
    const lastApp = ladder.filter(f => !f.native).slice(-1)[0];
    let h = '';
    ladder.forEach(f => {
      const role = frameRole(f, lastApp && f.i === lastApp.i);
      const key = pfx + f.i;
      const open = !!f.fr && S.open.has(key);
      const col = ROLE_COL[role] || '#e4f3ff';
      const row = `<span ${MUTED}>${esc(String(f.i).padStart(2))}</span> ${opts.chip ? opts.chip(role, col) : `<span style="color:${col};font-weight:bold;">${esc(role.padEnd(6))}</span>`} ` +
        `<span style="color:${f.native || f.lib ? '#82a9cc' : '#e4f3ff'};font-weight:${role === 'WRITE' || role === 'ENTRY' ? 'bold' : 'normal'};">${esc(fnShown(f))}</span> ` +
        (f.fr ? `<span ${MUTED}>${esc(f.file + ':' + f.line + ':' + f.col)}</span> <span style="color:#55e6e0">${open ? '▾' : '▸ code'}</span>` : `<span ${MUTED}>built-in</span>`);
      h += f.fr ? `<div>${act('frame', key, row)}</div>` : `<div>${row}</div>`;
      if (open) h += `<div style="margin:2px 0 6px 22px;">${resolvedCodeHtml(f.res)}</div>`;
    });
    return h;
  }
  // one line of function pills, outermost on the left
  function chainHtml(ladder, headN, tailN) {
    return pathNames(ladder, headN == null ? 3 : headN, tailN == null ? 4 : tailN).map(n =>
      n.charAt(0) === '…' ? `<span ${MUTED}>${esc(n)}</span>` : THEME.chip(esc(n), n.charAt(0) === '⟳' ? '#c9b0ff' : '#9bcbff')
    ).join(`<span ${MUTED}> → </span>`);
  }

  function traceHeader(M, hint) {
    const t = M.t;
    let h = `${THEME.title('TRACE', '#ff7b7b')} <span ${MUTED}>${hint || 'Esc closes · Alt+J copies JSON · full objects logged to console'}</span>\n`;
    h += `<span style="color:#9bcbff">${esc(t.element)}</span>\n`;
    if (t.textShown) h += `shows: <span style="color:#ffb86b">"${esc(clip(t.textShown, 120))}"</span>\n`;
    if (M.codeState === 'loading') h += `<span ${MUTED}>Loading source code…</span>\n`;
    if (M.codeState === 'error') h += `<span style="color:#ff7b7b">Source view failed: ${esc(M.ts.err || '')}</span>\n`;
    return h;
  }
  const moreHtml = r => {
    const x = extrasHtml(r);
    let h = `<b>Component (what rendered it)</b>\n${x.framework}`;
    if (x.listeners) h += `\n<b>Event listeners on this element</b>\n${x.listeners}`;
    if (x.attr) h += `\n<b>Attribute sinks set on this element</b>\n${x.attr}`;
    if (x.sinks) h += `\n<b>Other sinks that received this text</b>\n${x.sinks}`;
    h += `\n<span ${MUTED}>${r.requestsLogged} requests logged since ${esc(r.hooksInstalledAt)}. Only events after you pasted the script are recorded. Not hooked: storage written as a property (localStorage.x = …), cookie reads, eval.</span>`;
    return h;
  };
  const originLine = o => {
    if (!o) return 'unknown';
    const d = o.d;
    if (o.src) return o.src.method + ' ' + o.src.short + (d.status ? ' [' + d.status + ']' : '');
    return d.source + (d.where[0] ? ' · ' + d.where[0] : '');
  };

  // ---------- UI ----------
  const ui = document.createElement('div');
  ui.style.cssText = 'position:fixed;z-index:2147483646;pointer-events:none;display:none;' + THEME.hover;
  const panel = document.createElement('div');
  panel.style.cssText = 'position:fixed;z-index:2147483647;top:12px;right:12px;width:min(720px,96vw);max-height:84vh;overflow:auto;' +
    'display:none;white-space:pre-wrap;word-break:break-word;' + THEME.panel;
  panel.className = 'ht-panel';
  const card = document.createElement('div');
  card.style.cssText = 'position:fixed;z-index:2147483647;pointer-events:none;max-width:380px;' +
    'display:none;white-space:pre-wrap;word-break:break-word;' + THEME.card;
  card.className = 'ht-card';
  // Optional polish (scrollbars, hover states, animation). The look works without it, so a page
  // whose security policy blocks <style> elements only loses these extras.
  const themeStyle = document.createElement('style');
  quiet(() => { themeStyle.textContent = THEME.css || ''; });
  quiet(() => document.documentElement.appendChild(themeStyle));   // our own element: keep it out of the page-write log
  document.documentElement.appendChild(ui);
  document.documentElement.appendChild(panel);
  document.documentElement.appendChild(card);
  let cardOn = true;
  let cardTimer = null;

  const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  // Stack lines with long script URLs shortened to the file name (full URLs are still in the JSON/console).
  const stackText = (lines, max = 30) => {
    const out = (lines || []).slice(0, max).map(l => l.replace(/https?:\/\/[^\s()]*\/([^\s()\/?]*)(\?[^\s():]*)?(?=:\d+:\d+)/g, '$1'));
    if ((lines || []).length > max) out.push(`… ${lines.length - max} more frames (full list in the JSON / console)`);
    return out.join('\n');
  };
  const head = t => THEME.head(t);
  const green = s => THEME.val(esc(s));
  const json = o => clip(JSON.stringify(o, null, 2) || String(o), 1500);

  const DIR_TAG = {
    'origin?': ['← origin?', '#9dffcb'],
    'destination?': ['→ destination?', '#ffb86b'],
    'derived?': ['⇢ derived from the value?', '#c9b0ff'],
    'with page': ['▣ shipped with the page', '#9bcbff'],
    'unclear': ['? unclear', '#82a9cc']
  };
  const dirTag = d => { const t = DIR_TAG[d] || DIR_TAG.unclear; return THEME.tag(esc(t[0]), t[1]); };

  const fmtT = ms => (ms >= 1000 ? (ms / 1000).toFixed(2) + 's' : Math.round(ms) + 'ms');
  const KIND_COLOR = { page: '#82a9cc', hooks: '#82a9cc', request: '#ffe66d', response: '#ffe66d', message: '#ffe66d',
                       storage: '#c9b0ff', dom: '#9bcbff', attr: '#9bcbff', code: '#ff7b7b' };

  function timelineHtml(tl, noHead) {
    let h = noHead ? '' : head('Timeline (oldest first)');
    h += `<span style="color:#82a9cc">time is since page load; the second column is the gap from the previous event</span>\n`;
    let prev = null;
    (tl || []).forEach(e => {
      const gap = prev === null ? '' : '+' + fmtT(Math.max(0, e.t - prev));
      prev = e.t;
      if (e.kind === 'hooks') { h += `<span style="color:#82a9cc">${esc(fmtT(e.t).padStart(8))} ${esc(gap.padStart(8))}  ──── ${esc(e.text)} ────</span>\n`; return; }
      h += `${esc(fmtT(e.t).padStart(8))} ${esc(gap.padStart(8))}  <b style="color:${KIND_COLOR[e.kind] || '#e4f3ff'}">${esc(e.kind.toUpperCase().padEnd(8))}</b> ${esc(e.text)}${e.risky ? ' <span style="color:#ff7b7b">⚠</span>' : ''}`;
      if (e.caller) h += `  <span style="color:#82a9cc">← ${esc(e.caller)}</span>`;
      h += '\n';
    });
    h += `<span style="color:#82a9cc">Only events after you pasted the script are recorded. Not hooked: storage written as a property (localStorage.x = …), cookie reads, eval.</span>\n`;
    return h;
  }

  function show(el) {
    parkCard();
    panelMode = 'trace';
    const t = traceQuiet(el);
    lastTrace = t;
    window.__lastTrace = t;
    attachCallPaths(t, null);
    quiet(() => attachTransform(t, el));
    const lad = ladderOf(t.insertedBy && t.insertedBy.stack);
    const outer = lad.filter(f => !f.native).slice(-1)[0];
    const mine = ts = { t, code: 'loading', res: new Map(), fr: null,
      ui: { tab: 'overview', open: new Set(['0'].concat(outer && outer.i ? [String(outer.i)] : [])), sec: new Set(['data', 'xform', 'calls', 'code']), ev: null } };
    paintTrace(true);
    console.log('[Hover Trace]', t, el);
    const live = () => ts === mine && panelMode === 'trace';
    buildCodeView(t).then(async items => {
      t.code = items.map(plainItem);
      mine.code = items;
      // resolve every frame any view may show (source maps included), once
      const frames = new Map();
      const addAll = stk => (stk || []).map(parseFrame).filter(Boolean).forEach(fr => frames.set(keyOf(fr), fr));
      addAll(t.insertedBy && t.insertedBy.stack);
      t.dataSources.forEach(d => addAll(d.requestedBy));
      (t.timeline || []).forEach(e => addAll(e.stack));
      await Promise.all(Array.from(frames.values()).map(async fr => { try { mine.res.set(keyOf(fr), await resolveFrame(fr)); } catch (e) {} }));
      attachCallPaths(t, mine.res);
      if (live()) paintTrace(false);
      const locs = items.map(i => `${i.role}: ${i.frame ? i.frame.url + ':' + i.frame.line + ':' + i.frame.col : i.name + ':' + i.line + ':' + i.col}`);
      if (locs.length) console.log('[Hover Trace] code locations (click to open in Sources):\n' + locs.join('\n'));
      const keys = pickKeys([].concat(...t.dataSources.map(d => d.where)));
      return findFieldReads(keys).then(fr => {
        mine.fr = fr;
        t.fieldReads = { keys: fr.keys, stats: fr.stats, scriptsSearched: fr.scripts, hits: fr.items.map(plainItem) };
        if (live()) { const M = paintTrace(false); t.story = M.story.steps.map(x => x.replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')); }
        if (fr.items.length) console.log('[Hover Trace] code that reads ' + fr.keys.join(', ') + ':\n' + fr.items.map(i => i.name + ':' + i.line + ':' + i.col).join('\n'));
      });
    }).catch(err => {
      mine.code = 'error'; mine.err = String(err);
      if (live()) paintTrace(false);
    });
  }

  // =====================================================================
  // Data → element map (Alt+M) and who-wrote-what overlay (Alt+W)
  // =====================================================================
  let panelMode = null;            // 'trace' | 'map' | 'overlay'
  let mapState = null;             // { el, token, cands, sel, res, elPath }
  let ovlOn = false, ovlDepth = 0, ovlSolo = null, ovlGroups = [], ovlUnrecorded = 0;
  let ovlBoxes = [], mapBoxes = [];
  let redrawTimer = null, rafPending = false;
  const PALETTE = ['#ff7b7b', '#9bcbff', '#9dffcb', '#ffe66d', '#c9b0ff', '#ffb86b', '#55e6e0', '#ffa8dc'];
  const EMBED_GLOBALS = ['__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', '__APOLLO_STATE__', '__PRELOADED_STATE__', '__REDUX_STATE__', '__remixContext'];
  const MUTED = 'style="color:#82a9cc"';

  // Our own layers: never let our DOM work show up in the page's write log.
  function quiet(fn) { const was = busy; busy = true; try { return fn(); } finally { busy = was; } }

  const LAYER_CSS = 'position:fixed;left:0;top:0;width:100vw;height:100vh;pointer-events:none;overflow:hidden;';
  const ovl = document.createElement('div');
  ovl.style.cssText = LAYER_CSS + 'z-index:2147483644;';
  const mapLayer = document.createElement('div');
  mapLayer.style.cssText = LAYER_CSS + 'z-index:2147483645;';
  document.documentElement.appendChild(ovl);
  document.documentElement.appendChild(mapLayer);

  function paintRaw(html, reset) {
    const top = reset ? 0 : panel.scrollTop;
    quiet(() => { panel.innerHTML = html; });
    panel.style.display = 'block';
    panel.scrollTop = top;
  }

  // ----- boxes drawn over page elements -----
  function placeBox(b) {
    const r = b.el.getBoundingClientRect();
    const hidden = r.width < 2 || r.height < 2 || r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth;
    b.div.style.display = hidden ? 'none' : 'block';
    if (!hidden) Object.assign(b.div.style, { left: r.left + 'px', top: r.top + 'px', width: r.width + 'px', height: r.height + 'px' });
  }

  function makeBox(layer, el, color, label, strong) {
    return quiet(() => {
      const div = document.createElement('div');
      div.style.cssText = 'position:absolute;box-sizing:border-box;' + THEME.box(color, strong);
      if (label) {
        const tag = document.createElement('span');
        tag.textContent = label;
        tag.style.cssText = 'position:absolute;white-space:nowrap;' + THEME.label(color);
        div.appendChild(tag);
      }
      layer.appendChild(div);
      const b = { div, el };
      placeBox(b);
      return b;
    });
  }

  function emptyLayer(layer) { quiet(() => { while (layer.firstChild) layer.removeChild(layer.firstChild); }); }

  function onScrollResize() {
    if (!rafPending) {
      rafPending = true;
      requestAnimationFrame(() => { rafPending = false; ovlBoxes.forEach(placeBox); mapBoxes.forEach(placeBox); });
    }
    if (ovlOn) { clearTimeout(redrawTimer); redrawTimer = setTimeout(() => { if (ovlOn) drawOverlay(); }, 300); }
  }

  // ----- who wrote this element -----
  const fnNameOf = line => {
    const m = /^\s*at\s+(?:async\s+)?([^\s(]+)\s+\(/.exec(line || '') || /^([^@\s]*)@/.exec(line || '');
    return m && m[1] ? m[1] : 'anonymous';
  };
  const fileOf = fr => fr.url.split('/').pop().split('?')[0] || fr.url;
  const frameLabel = fr => `${fnNameOf(fr.raw)} @ ${fileOf(fr)}:${fr.line}:${fr.col}`;

  // The write that put CONTENT on a node (innerHTML, textContent...) beats a later plain move.
  function contentRec(node) {
    const rec = domLog.get(node);
    if (!rec) return null;
    return [rec, ...rec.history].find(x => x.sink.label !== 'DOM node insert') || rec;
  }

  function writerOf(el) {
    const kids = Array.from(el.childNodes).filter(n => n.nodeType === 3).slice(0, 6);
    for (const n of kids) { const r = contentRec(n); if (r) return { rec: r, on: n }; }
    for (let p = el; p && p.nodeType === 1; p = p.parentNode) { const r = contentRec(p); if (r) return { rec: r, on: p }; }
    return null;
  }

  // ----- overlay: color every visible text element by the code that wrote it -----
  function groupKey(rec) {
    const frames = (rec.stack || []).map(parseFrame).filter(Boolean);
    if (!frames.length) return { key: 'none:' + rec.via, fr: null };
    const fr = frames[Math.min(ovlDepth, frames.length - 1)];
    return { key: `${fr.url}:${fr.line}:${fr.col}`, fr };
  }

  function collectOverlay() {
    const byKey = new Map();
    let unrecorded = 0, scanned = 0;
    const all = document.body ? document.body.querySelectorAll('*') : [];
    for (const el of all) {
      if (++scanned > 8000) break;
      if (/^(SCRIPT|STYLE|LINK|META|NOSCRIPT|BR|HR|TEMPLATE)$/.test(el.tagName)) continue;
      const own = ownText(el);
      if (el.children.length && !own) continue;
      if (!own && !/^(IMG|INPUT|TEXTAREA|BUTTON|SELECT)$/.test(el.tagName)) continue;
      const r = el.getBoundingClientRect();
      if (r.width < 2 || r.height < 2 || r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth) continue;
      const w = writerOf(el);
      if (!w) { unrecorded++; continue; }
      const g = groupKey(w.rec);
      if (!byKey.has(g.key)) byKey.set(g.key, { key: g.key, fr: g.fr, via: w.rec.via, items: [] });
      byKey.get(g.key).items.push({ el, rec: w.rec });
    }
    const groups = Array.from(byKey.values()).sort((a, b) => b.items.length - a.items.length);
    groups.forEach((g, i) => { g.letter = String.fromCharCode(65 + (i % 26)); g.color = PALETTE[i % PALETTE.length]; });
    return { groups, unrecorded };
  }

  function drawOverlay() {
    emptyLayer(ovl);
    ovlBoxes = [];
    const { groups, unrecorded } = collectOverlay();
    ovlGroups = groups;
    ovlUnrecorded = unrecorded;
    let count = 0;
    groups.forEach(g => {
      if (ovlSolo && ovlSolo !== g.key) return;
      const seqs = Array.from(new Set(g.items.map(i => i.rec.seq))).sort((a, b) => a - b);
      g.items.forEach(it => {
        if (count++ >= 800) return;
        const rank = seqs.indexOf(it.rec.seq) + 1;
        ovlBoxes.push(makeBox(ovl, it.el, g.color, g.letter + (seqs.length > 1 ? rank : ''), false));
      });
    });
    if (panelMode === 'overlay') paintRaw(legendHtml(), false);
  }

  function clearOverlay() { emptyLayer(ovl); ovlBoxes = []; ovlGroups = []; ovlSolo = null; }

  const attrEsc = s => esc(s).replace(/"/g, '&quot;');

  function legendHtml() {
    let h = `${THEME.title('WHO WROTE WHAT', '#ff7b7b')} <span ${MUTED}>Alt+W off · Alt+Shift+W change depth (now ${ovlDepth}) · click a row to show only that group</span>\n`;
    h += `<span ${MUTED}>Visible text elements are grouped by the code location at stack depth ${ovlDepth} (0 = the function that did the write, 1 = its caller, and so on). Letters are groups; the number after a letter is the write order inside that group.</span>\n`;
    ovlGroups.forEach(g => {
      const samples = g.items.slice(0, 3).map(i => '"' + clip(i.rec.preview || ownText(i.el), 28) + '"').join(', ');
      h += `\n<div data-group="${attrEsc(g.key)}" style="cursor:pointer;${ovlSolo === g.key ? 'background:#164f86;' : ''}"><b style="color:${g.color}">■ ${g.letter}</b> ${g.fr ? esc(frameLabel(g.fr)) : esc(g.via)} <span ${MUTED}>${g.items.length} element${g.items.length === 1 ? '' : 's'}, written via ${esc(g.via)}</span>\n  <span ${MUTED}>${esc(samples)}</span></div>`;
    });
    if (!ovlGroups.length) h += '\nNothing visible was written by script since you pasted this.\n';
    h += `\n<span ${MUTED}>Visible text elements with no recorded writer: ${ovlUnrecorded} (server HTML, or written before you pasted the script).</span>\n`;
    return h;
  }

  // ----- data → element map -----
  function pathTokens(path) {
    const out = [];
    String(path).replace(/\[(\d+)\]|([^.\[\]]+)/g, (m, i, k) => { out.push(i !== undefined ? +i : k); return m; });
    return out;
  }
  const getTok = (root, toks) => { let v = root; for (const t of toks) { if (v == null) return undefined; v = v[t]; } return v; };
  const leafOf = (entry, field) => {
    const v = field.length ? getTok(entry, field) : entry;
    return typeof v === 'string' || typeof v === 'number' ? String(v) : null;
  };
  const previewEntry = e => (typeof e === 'string' ? clip(e, 70) : clip(JSON.stringify(e) || String(e), 70));
  function tryJson(r) {
    if (r.__json === undefined) { try { r.__json = JSON.parse(r.body); } catch (e) { r.__json = null; } }
    return r.__json;
  }

  // Every array (in responses, embedded data, ld+json) that has an entry containing the hovered text.
  function findDataArrays(needles) {
    const roots = [];
    requests.forEach(r => {
      if (!r.body) return;
      const j = tryJson(r);
      if (j && typeof j === 'object') roots.push({ label: `${r.kind.toUpperCase()} ${r.method} ${clip(safeDecode(r.url), 70)}`, kind: 'network response', root: j });
    });
    EMBED_GLOBALS.forEach(name => {
      try { if (window[name] && typeof window[name] === 'object') roots.push({ label: 'window.' + name, kind: 'embedded page data', root: window[name] }); } catch (e) {}
    });
    try {
      document.querySelectorAll('script[type="application/json"], script[type="application/ld+json"]').forEach(s => {
        try { roots.push({ label: 'inline <script' + (s.id ? ' id="' + s.id + '"' : '') + '>', kind: 'embedded page data', root: JSON.parse(s.textContent) }); } catch (e) {}
      });
    } catch (e) {}

    const out = [], seen = new Set();
    roots.forEach(R => needles.forEach(n => {
      jsonHits(R.root, n.value).forEach(path => {
        const toks = pathTokens(path);
        toks.forEach((t, pos) => {
          if (typeof t !== 'number') return;
          const arrToks = toks.slice(0, pos);
          const arr = getTok(R.root, arrToks);
          if (!Array.isArray(arr) || arr.length < 2) return;
          const field = toks.slice(pos + 1);
          const key = [R.label, arrToks.join('.'), field.join('.'), n.label].join('|');
          if (seen.has(key)) return;
          seen.add(key);
          out.push({ source: R.label, kind: R.kind, arrPath: arrToks.join('.') || '(root)', array: arr, field, label: n.label, matchedIdx: t });
        });
      });
    }));
    return out;
  }

  const valueOf = (e, label) => {
    if (label === 'text') return ownText(e) || norm(e.textContent || '').slice(0, 200);
    if (label === 'value') return typeof e.value === 'string' ? e.value : '';
    return (e.getAttribute && e.getAttribute(label)) || (typeof e[label] === 'string' ? e[label] : '');
  };

  // Elements that look like the hovered one (same tag and class): the likely output of one render loop.
  function domContext(el) {
    const all = Array.from(document.querySelectorAll('*'));
    const docPos = new Map();
    const pool = [];
    all.forEach((e, i) => {
      docPos.set(e, i);
      if (e.tagName === el.tagName && String(e.className) === String(el.className) &&
          !panel.contains(e) && !ovl.contains(e) && !mapLayer.contains(e) && e !== ui && e !== card) pool.push(e);
    });
    return { docPos, pool };
  }

  function computeMap(ctx, el, cand) {
    const texts = ctx.pool.map(e => norm(valueOf(e, cand.label)).slice(0, 100));
    const used = new Set();
    const assigned = new Map();
    if (ctx.pool.includes(el)) { assigned.set(cand.matchedIdx, el); used.add(el); }
    const entries = cand.array.map((entry, k) => {
      const leaf = leafOf(entry, cand.field);
      const t = leaf == null ? null : norm(leaf).slice(0, 100);
      let found = assigned.get(k) || null;
      if (!found && t && t.length >= 2) {
        for (let i = 0; i < ctx.pool.length && !found; i++) if (!used.has(ctx.pool[i]) && texts[i] === t) found = ctx.pool[i];
        for (let i = 0; i < ctx.pool.length && !found; i++) {
          if (used.has(ctx.pool[i]) || !texts[i]) continue;
          if (t.length >= 4 && (texts[i].includes(t) || (texts[i].length >= 4 && t.includes(texts[i])))) found = ctx.pool[i];
        }
      }
      if (found) used.add(found);
      return { k, text: t, preview: previewEntry(entry), others: (entry && typeof entry === 'object' && !Array.isArray(entry)) ? Object.keys(entry).filter(kk => kk !== cand.field[0]).slice(0, 3).map(kk => kk + ': ' + clip(String(typeof entry[kk] === 'object' ? JSON.stringify(entry[kk]) : entry[kk]), 14)).join(' · ') : '', el: found, domPos: found ? ctx.docPos.get(found) : null, writer: found ? writerOf(found) : null };
    });
    const extra = ctx.pool.filter(e => !used.has(e) && valueOf(e, cand.label)).length;
    return { entries, extra };
  }

  function orderVerdict(res) {
    const m = res.entries.filter(e => e.el);
    if (m.length < 2) return { dom: 'Too few matched elements to compare order.', write: '' };
    const domAsc = m.every((e, i) => i === 0 || e.domPos > m[i - 1].domPos);
    const seqs = m.map(e => (e.writer && e.writer.rec ? e.writer.rec.seq : null));
    let write;
    if (seqs.some(s => s == null)) write = 'Write order unknown for some entries (written before you pasted the script, or by the server).';
    else if (new Set(seqs).size === 1) write = 'All of them were written by one operation (a single innerHTML or text write), so there is no separate write per entry.';
    else if (seqs.every((s, i) => i === 0 || s > seqs[i - 1])) write = 'They were written one after another in array order.';
    else write = 'They were written in a different order than the array.';
    return { dom: domAsc ? 'The page shows them in array order.' : 'The page does NOT show them in array order (sorted, filtered, grouped or paged).', write };
  }

  function drawMap(res, cand) {
    emptyLayer(mapLayer);
    mapBoxes = [];
    res.entries.forEach(en => {
      if (!en.el) return;
      const hov = en.k === cand.matchedIdx;
      mapBoxes.push(makeBox(mapLayer, en.el, hov ? '#ff7b7b' : '#55e6e0', '[' + en.k + ']', hov));
    });
  }

  function clearMap() { mapState = null; emptyLayer(mapLayer); mapBoxes = []; }

  // Code that wrote the mapped elements, grouped by identical call path.
  async function mapCode(st) {
    const mapped = st.res.entries.filter(e => e.writer && e.writer.rec);
    const groups = new Map();
    mapped.forEach(e => {
      const frames = (e.writer.rec.stack || []).map(parseFrame).filter(Boolean);
      const sig = frames.slice(0, 6).map(f => f.url + ':' + f.line + ':' + f.col).join('|') + '#' + e.writer.rec.via;
      if (!groups.has(sig)) groups.set(sig, { rec: e.writer.rec, frames, entries: [] });
      groups.get(sig).entries.push(e);
    });
    const list = Array.from(groups.values()).sort((a, b) => b.entries.length - a.entries.length).slice(0, 3);
    for (const g of list) {
      g.picks = pickFrames(g.frames, 3, 2);
      g.resolved = await Promise.all(g.picks.map(p => resolveFrame(p.fr)));
      g.loops = (g.rec.stack || []).filter(l => /\bArray\.(forEach|map|reduce|filter|flatMap|some|every)\b/.test(l)).length;
    }
    return { list, total: mapped.length };
  }

  const mapFields = (fr, state) => head('Code that reads these fields') + fieldReadsHtml(fr, state);

  function mapCodeHtml(code) {
    let h = head('Code that wrote these elements');
    if (!code.list.length) return h + `<span ${MUTED}>No recorded writes for the matched elements (they were rendered before you pasted the script, or by the server).</span>\n`;
    code.list.forEach((g, gi) => {
      const idx = g.entries.map(e => e.k).join(', ');
      h += `\n${THEME.role('Call path ' + (gi + 1), '#55e6e0')} ${g.entries.length} of ${code.total} elements (entries ${esc(clip(idx, 60))}) · ${esc(g.rec.via)} → ${esc(g.rec.sink.label)}\n`;
      h += `<div style="margin:5px 0;line-height:1.9;">${chainHtml(ladderOf(g.rec.stack), 3, 4)}</div>`;
      if (g.loops) h += `<span ${MUTED}>The call path runs through ${g.loops} array-loop frame${g.loops === 1 ? '' : 's'} (Array.forEach and similar), so this code is called from inside ${g.loops === 1 ? 'a loop' : 'nested loops'}.</span>\n`;
      const samples = g.entries.slice(0, 4).map(e => '"' + clip(e.writer.rec.preview || e.text || '', 30) + '"').join(', ');
      h += `<span ${MUTED}>values that reached the write: ${esc(samples)}</span>\n`;
      g.resolved.forEach((r, i) => {
        const p = g.picks[i];
        const role = i === 0 ? 'WRITE' : 'CALLER';
        const label = i === 0 ? `${g.rec.via} · ${g.rec.sink.label}` : (p.outer ? `outermost captured frame (#${p.idx + 1} of ${g.frames.length})` : 'called from');
        h += `\n${THEME.role(role, ROLE_COL[i === 0 ? 'WRITE' : 'CALL'])} ${esc(label)}${i === 0 && g.rec.sink.risky ? ' <span style="color:#ff7b7b">⚠</span>' : ''}\n`;
        h += resolvedCodeHtml(r);
      });
    });
    return h;
  }

  function mapHtml(st) {
    const c = st.cands[st.sel], res = st.res;
    const matched = res.entries.filter(e => e.el).length;
    const v = orderVerdict(res);
    let h = `${THEME.title('DATA → ELEMENT MAP', '#55e6e0')} <span ${MUTED}>Alt+M closes · click a row to scroll to it</span>\n`;
    h += `<span style="color:#9bcbff">${esc(st.elPath)}</span>\n`;
    h += `<div style="${THEME.surface}line-height:1.6;"><b>${matched} of ${c.array.length}</b> entries in ${Cs(c.arrPath)} <span ${MUTED}>(${esc(c.source)})</span> are on the page, matched on ${esc(c.label)}${c.field.length ? ' field ' + Cs(c.field.join('.')) : ' (the entry itself)'}.` +
      `${res.extra ? '<br><span ' + MUTED + '>' + res.extra + ' similar element(s) on the page match no entry.</span>' : ''}</div>`;
    if (st.cands.length > 1) {
      h += head('Arrays that contain this text (click one to switch)');
      st.cands.forEach((cd, i) => {
        h += `<div data-cand="${i}" style="cursor:pointer;padding:1px 4px;${i === st.sel ? 'background:#164f86;' : ''}">${i === st.sel ? '▶' : '·'} ${esc(cd.source)} → ${esc(cd.arrPath)} <span ${MUTED}>(${cd.array.length} entries, ${cd.mapped} found on the page)</span></div>`;
      });
    }
    h += `<div style="margin:6px 0 2px;line-height:1.6;">Order: ${esc(v.dom)}${v.write ? '<br>' + '       ' + esc(v.write) : ''}</div>`;
    const grid = 'display:grid;grid-template-columns:38px minmax(0,1.35fr) minmax(0,1fr) 96px;gap:8px;padding:3px 4px;align-items:baseline;';
    h += `<div style="${grid}color:#82a9cc;border-bottom:1px solid #82a9cc;margin-top:6px;"><span>#</span><span>in the data</span><span>on the page</span><span>written</span></div>`;
    res.entries.forEach(en => {
      const hov = en.k === c.matchedIdx;
      const shown = en.text != null ? en.text : en.preview;
      if (!en.el) { h += `<div ${MUTED} style="${grid}"><span>[${en.k}]</span><span>${esc(clip(shown, 60))}</span><span>not found on the page</span><span></span></div>`; return; }
      const tail = selectorPath(en.el).split(' > ').slice(-2).join(' > ');
      const rec = en.writer && en.writer.rec;
      h += `<div data-entry="${en.k}" style="${grid}cursor:pointer;border-bottom:1px solid rgba(128,128,128,.22);${hov ? THEME.hitRow : ''}">` +
        `<b style="color:${hov ? '#ff7b7b' : '#55e6e0'}">[${en.k}]</b><span style="overflow-wrap:anywhere;">${esc(clip(shown, 60))}${en.others ? '<br><span ' + MUTED + '>' + esc(en.others) + '</span>' : ''}</span><span style="overflow-wrap:anywhere;">${esc(clip(tail, 46))}</span>` +
        `<span ${MUTED}>${rec ? esc(fmtT(rec.t)) + ' · #' + rec.seq : '—'}</span></div>`;
    });
    return h;
  }


  function showMap(el) {
    parkCard();
    panelMode = 'map';
    const needles = quiet(() => candidates(el));
    const st = { el, token: {}, cands: [], sel: 0, res: null, elPath: selectorPath(el) };
    mapState = st;
    emptyLayer(mapLayer); mapBoxes = [];
    const cands = quiet(() => findDataArrays(needles));
    if (!cands.length) {
      paintRaw(`${THEME.title('DATA → ELEMENT MAP', '#55e6e0')}\n${esc(st.elPath)}\n\nNo array found whose entries contain this element's text. Checked captured network responses, embedded page data and ld+json. Hover one row of a list that was loaded after you pasted the script, then press Alt+M again.`, true);
      return;
    }
    const ctx = quiet(() => domContext(el));
    cands.forEach(c => { c.res = quiet(() => computeMap(ctx, el, c)); c.mapped = c.res.entries.filter(e => e.el).length; });
    const ranked = cands.filter(c => c.mapped >= 1).sort((a, b) => b.mapped - a.mapped || b.array.length - a.array.length).slice(0, 8);
    if (!ranked.length) {
      paintRaw(`${THEME.title('DATA → ELEMENT MAP', '#55e6e0')}\n${esc(st.elPath)}\n\nFound ${cands.length} array(s) containing this text, but none of their entries could be matched to elements on the page (the text may be transformed before display).`, true);
      return;
    }
    st.cands = ranked;
    selectCand(0);
  }

  function selectCand(i) {
    const st = mapState;
    if (!st) return;
    st.sel = i;
    st.res = st.cands[i].res;
    drawMap(st.res, st.cands[i]);
    paintRaw(mapHtml(st) + head('Code that wrote these elements') + `<span ${MUTED}>Loading source code…</span>\n`, true);
    const tok = st.token;
    const stillHere = () => mapState && mapState.token === tok && mapState.sel === i && panelMode === 'map';
    mapCode(st).then(code => {
      const cd = st.cands[i];
      const keys = pickKeys([cd.arrPath, (cd.field || []).join('.')]);
      const base = mapHtml(st) + mapCodeHtml(code);
      if (stillHere()) paintRaw(base + mapFields(null, 'loading'), false);
      return findFieldReads(keys).then(fr => {
        if (stillHere()) paintRaw(base + mapFields(fr), false);
      });
    }).catch(err => {
      if (mapState && mapState.token === tok && panelMode === 'map') paintRaw(mapHtml(st) + head('Code that wrote these elements') + 'Source view failed: ' + esc(String(err)) + '\n', false);
    });
  }

  function onPanelClick(e) {
    const a = e.target && e.target.closest ? e.target.closest('[data-act]') : null;
    if (a && panelMode === 'trace') { handleAct(a.getAttribute('data-act'), a.getAttribute('data-k')); return; }
    const t = e.target && e.target.closest ? e.target.closest('[data-group],[data-cand],[data-entry]') : null;
    if (!t) return;
    if (t.hasAttribute('data-group')) {
      const key = t.getAttribute('data-group');
      ovlSolo = ovlSolo === key ? null : key;
      drawOverlay();
    } else if (t.hasAttribute('data-cand') && mapState) {
      selectCand(+t.getAttribute('data-cand'));
    } else if (t.hasAttribute('data-entry') && mapState && mapState.res) {
      const en = mapState.res.entries[+t.getAttribute('data-entry')];
      if (en && en.el && en.el.scrollIntoView) en.el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }

  // Short summary shown next to the cursor while hovering
  function renderCard(r) {
    const short = s => clip(String(s).replace(/\(eval at [^)]*\), /, '').replace(/^at /, ''), 90);
    let h = `<span style="color:#9bcbff">${esc(clip(r.element.split(' > ').slice(-2).join(' > '), 70))}</span>\n`;
    const f = r.framework;
    h += `<span style="color:#ffe66d">component</span> ` + (f && (f.component || f.source)
      ? green(`${f.framework}${f.component ? ' · ' + f.component : ''}${f.source ? ' · ' + f.source : ''}`)
      : '<span style="color:#82a9cc">none detected</span>') + '\n';
    const ins = r.insertedBy;
    h += `<span style="color:#ffe66d">sink</span> ` + (ins
      ? green(`${ins.sink.label} (${ins.via})`) + (ins.sink.risky ? ' <span style="color:#ff7b7b">⚠ parses markup</span>' : ' <span style="color:#82a9cc">safe</span>') +
        `\n<span style="color:#ffe66d">  by</span> ${green(ins.stack[0] ? short(ins.stack[0]) : 'unknown caller')}`
      : '<span style="color:#82a9cc">not seen (server HTML or before hooks)</span>') + '\n';
    const d = r.dataSources[0];
    h += `<span style="color:#ffe66d">source</span> ` + (d
      ? green(`${d.source} → ${d.where[0]}`) + ` <span style="color:#82a9cc">[${esc(d.sourceKind)}${r.dataSources.length > 1 ? ', +' + (r.dataSources.length - 1) + ' more' : ''}]</span> ${dirTag(d.direction)}`
      : '<span style="color:#82a9cc">no match found</span>') + '\n';
    const risky = (r.flows || []).filter(f => f.risky);
    if (risky.length) h += `<span style="color:#ff7b7b">⚠ candidate flow: ${esc(clip(risky[0].source, 40))} → ${esc(clip(risky[0].sink, 40))}</span>\n`;
    else if ((r.flows || []).length) h += `<span style="color:#82a9cc">flow: ${esc(clip(r.flows[0].source, 40))} → safe sink</span>\n`;
    h += `<span style="color:#82a9cc">${(r.timeline || []).length - 2} timeline events · Alt+Q trace · Alt+M map · Alt+W overlay · Alt+H hide card</span>`;
    return h;
  }

  function positionCard(x, y) {
    const pad = 16, w = card.offsetWidth, hgt = card.offsetHeight;
    let left = x + pad, top = y + pad;
    if (left + w > innerWidth) left = x - w - pad;
    if (top + hgt > innerHeight) top = y - hgt - pad;
    card.style.left = Math.max(0, left) + 'px';
    card.style.top = Math.max(0, top) + 'px';
  }

  // Hide the hover card while a panel opens so it never sits on top of the text you're about to read.
  // It comes back by itself the next time the pointer moves onto a different element.
  function parkCard() { clearTimeout(cardTimer); card.style.display = 'none'; }

  function updateCard(el) {
    if (!cardOn || el !== current) return;
    let r;
    try { r = traceQuiet(el); } catch (err) { return; }
    busy = true;
    try { card.innerHTML = renderCard(r); } finally { busy = false; }
    card.style.display = 'block';
  }

  function onMove(e) {
    const el = e.composedPath ? e.composedPath()[0] : e.target;
    if (!el || el.nodeType !== 1 || el === ui || el === card || panel.contains(el)) return;
    const changed = el !== current;
    current = el;
    const r = el.getBoundingClientRect();
    Object.assign(ui.style, { display: 'block', left: r.left + 'px', top: r.top + 'px', width: r.width + 'px', height: r.height + 'px' });
    if (changed && cardOn) {
      clearTimeout(cardTimer);
      cardTimer = setTimeout(() => updateCard(el), 80); // debounce so fast mouse moves stay cheap
    }
    if (cardOn && card.style.display !== 'none') positionCard(e.clientX, e.clientY);
  }

  function onKey(e) {
    if (e.key === 'Escape') {
      if (mapState) clearMap();
      if (panel.style.display !== 'none') { panel.style.display = 'none'; panelMode = null; }
      return;
    }
    if (!e.altKey) return;
    if (e.code === 'KeyM' && current) {
      e.preventDefault();
      if (mapState && mapState.el === current) { clearMap(); if (panelMode === 'map') { panel.style.display = 'none'; panelMode = null; } }
      else showMap(current);
    }
    else if (e.code === 'KeyW') {
      e.preventDefault();
      if (e.shiftKey) { ovlOn = true; ovlDepth = (ovlDepth + 1) % 6; ovlSolo = null; panelMode = 'overlay'; parkCard(); drawOverlay(); }
      else {
        ovlOn = !ovlOn;
        if (ovlOn) { panelMode = 'overlay'; parkCard(); drawOverlay(); }
        else { clearOverlay(); if (panelMode === 'overlay') { panel.style.display = 'none'; panelMode = null; } }
      }
    }
    else if (e.code === 'KeyH') {
      e.preventDefault();
      cardOn = !cardOn;
      if (!cardOn) { clearTimeout(cardTimer); card.style.display = 'none'; }
      else if (current) updateCard(current);
    }
    else if (e.code === 'KeyQ' && current) { e.preventDefault(); show(current); }
    else if (e.code === 'KeyJ' && lastTrace) {
      e.preventDefault();
      const text = JSON.stringify(lastTrace, null, 2);
      (navigator.clipboard && navigator.clipboard.writeText ? navigator.clipboard.writeText(text) : Promise.reject())
        .then(() => console.log('Trace JSON copied'))
        .catch(() => console.log(text));
    }
  }

  document.addEventListener('mousemove', onMove, true);
  document.addEventListener('keydown', onKey, true);
  panel.addEventListener('click', onPanelClick);
  window.addEventListener('scroll', onScrollResize, true);
  window.addEventListener('resize', onScrollResize);

  window.__traceRequests = requests;
  window.__traceMapState = () => mapState;
  window.__traceCleanup = () => {
    document.removeEventListener('mousemove', onMove, true);
    document.removeEventListener('keydown', onKey, true);
    panel.removeEventListener('click', onPanelClick);
    window.removeEventListener('scroll', onScrollResize, true);
    window.removeEventListener('resize', onScrollResize);
    undo.forEach(fn => { try { fn(); } catch (e) {} });
    clearTimeout(cardTimer);
    clearTimeout(redrawTimer);
    ui.remove(); panel.remove(); card.remove(); ovl.remove(); mapLayer.remove(); themeStyle.remove();
    delete window.__traceCleanup;
    delete window.__setBasePath;
    delete window.__setObjectContext;
    console.log('Hover Trace stopped and hooks removed.');
  };

  console.log('Hover Trace active. Trigger your search/render, then hover and press: Alt+Q trace · Alt+M data→element map · Alt+W who-wrote-what overlay. Stop: __traceCleanup()');
})();