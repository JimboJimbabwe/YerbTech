// Shared helpers. Everything that touches the DOM builds nodes with textContent,
// never innerHTML, because file names and wordlist content are untrusted text.

export function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid === undefined || kid === null || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

export async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const isJson = (res.headers.get('content-type') || '').includes('json');
  const body = isJson ? await res.json().catch(() => null) : await res.text();
  if (!res.ok) {
    const message = (isJson && body && body.error) || (typeof body === 'string' && body) || `Request failed (${res.status})`;
    throw Object.assign(new Error(message), { status: res.status });
  }
  return body;
}

export function startClock(node) {
  const fmt = new Intl.DateTimeFormat(undefined, {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    hour: 'numeric', minute: '2-digit', second: '2-digit',
  });
  const tick = () => { node.textContent = fmt.format(new Date()); };
  tick();
  return setInterval(tick, 1000);
}

/** /project/<name>[/workspace] -> decoded project name */
export function projectFromPath() {
  const parts = location.pathname.split('/').filter(Boolean);
  return parts[0] === 'project' && parts[1] ? decodeURIComponent(parts[1]) : '';
}

export const projectUrl = (name) => `/project/${encodeURIComponent(name)}`;

export function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

export function fmtDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch { /* fall through to the legacy path */ }
  }
  const area = el('textarea', { readonly: true, 'aria-hidden': 'true' });
  area.value = text;
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  if (!ok) throw new Error('The browser blocked clipboard access.');
}
