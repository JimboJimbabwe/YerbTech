// Turns a script's command model (from /api/.../procedures) into a command line for a chosen shell.
// Pure functions, no DOM, so the quoting rules can be tested from Node.
//
// Quoting is the safety-critical part: operator-typed values end up pasted into a terminal.
// Every value that is not plainly safe is single-quoted for the target shell, and line breaks
// (which would split one command into two when pasted) are replaced with spaces.

export const SHELLS = {
  powershell: { label: 'PowerShell', python: 'python' },
  bash: { label: 'bash (Linux)', python: 'python3' },
};

const SAFE = {
  powershell: /^[A-Za-z0-9_@%+=:,./\\-]+$/,
  bash: /^[A-Za-z0-9_@%+=:,./-]+$/,
};

/** Quote one argument for the shell. */
export function quote(shell, value) {
  const s = String(value ?? '').replace(/[\r\n\0]+/g, ' ');
  if (s === '') return "''";
  if (SAFE[shell].test(s) && !s.startsWith('-')) return s;
  if (shell === 'powershell') {
    // PowerShell also treats the curly single quotes as quote characters, so double those too.
    return `'${s.replace(/['‘’‚‛]/g, (c) => c + c)}'`;
  }
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const interpreterFor = (shell, script) => (script.interpreter === 'python' ? SHELLS[shell].python : script.interpreter);

/** Text shown (quoted, so it stays inert if pasted) for a required value that has not been filled in yet. */
export function placeholderFor(item) {
  if (item.kind === 'file') return `<${item.tag.replace('_INPUT', '').toLowerCase()} file>`;
  return `<${(item.flag || item.tag || 'value').replace(/^-+/, '')}>`;
}

/**
 * fields: the model's script.items, each with the operator's current `include` and `value`.
 * Returns { text, missing } where missing counts required values still empty.
 */
export function buildCommand(shell, script, fields, { cd = false } = {}) {
  const parts = [];
  const interp = interpreterFor(shell, script.script);
  if (interp) parts.push(...interp.split(' '));
  parts.push(quote(shell, script.script.path));

  let missing = 0;
  const emit = (item) => {
    const val = String(item.value ?? '').trim();
    if (item.kind === 'switch') return item.flag;
    if (val === '') {
      // An optional value left blank means "just the flag" (covers flags whose value we can't tell).
      if (item.flagUnsure && !item.required) return item.flag;
      if (item.required) {
        missing++;
        return item.flag ? `${item.flag} ${quote(shell, placeholderFor(item))}` : quote(shell, placeholderFor(item));
      }
      return null;
    }
    return item.flag ? `${item.flag} ${quote(shell, val)}` : quote(shell, val);
  };

  const active = fields.filter((f) => f.include || f.required);
  for (const f of active.filter((x) => !x.flag)) { const e = emit(f); if (e) parts.push(e); } // positional first
  for (const f of active.filter((x) => x.flag)) { const e = emit(f); if (e) parts.push(e); }

  let text = parts.join(' ');
  if (cd && script.workdir) {
    text = shell === 'powershell'
      ? `Set-Location -LiteralPath ${quote(shell, script.workdir)}; ${text}`
      : `cd ${quote(shell, script.workdir)} && ${text}`;
  }
  return { text, missing };
}

/** Fresh editable copy of a script's fields (required on, optional off, as the server suggested). */
export const initialFields = (script) => script.items.map((i) => ({ ...i }));

/** Apply a preset (alternative invocation): only its flags are on, with its example values where given. */
export function applyPreset(fields, preset) {
  for (const f of fields) {
    if (f.required) continue;
    const hit = f.flag && Object.prototype.hasOwnProperty.call(preset.active, f.flag);
    f.include = Boolean(hit);
    if (hit && preset.active[f.flag] !== true && f.kind !== 'file') f.value = String(preset.active[f.flag]);
  }
  return fields;
}

/** "Copy all": every script of the assessment in run order, each under a comment. */
export function buildSequence(shell, scripts, opts) {
  return scripts
    .map((s) => `# ${s.position}. ${s.name}\n${buildCommand(shell, s, initialFields(s), opts).text}`)
    .join('\n');
}
