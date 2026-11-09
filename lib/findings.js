'use strict';
/**
 * Findings Entry: one or more findings per WSTG item, written by hand through the GUI's
 * left-pane form. Same shape as every other feature in this project - a JSON file the tool
 * owns (findings.json) plus a readable Markdown twin (findings.md), both in that item's own
 * Outputs/test_outputs/, found the scan-for-WSTG-ID way (resources.locateTest), never a
 * hardcoded category map.
 *
 * A WSTG item can have more than one finding (two separate injection points found in the same
 * test, say), so the file holds an array, not a single object. Each finding gets its own short
 * id so the GUI can address "edit this one" without relying on array position, which would
 * shift under it if an earlier finding were deleted.
 */
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { HttpError } = require('./errors');
const resources = require('./resources');

const RISK_LEVELS = new Set(['None', 'Low', 'Medium', 'High', 'Critical']);

async function findingsDir(project, id) {
  const { testDir } = await resources.locateTest(project, id);
  if (!testDir) throw new HttpError(404, `No folder found for ${id}.`);
  return path.join(testDir, 'Outputs', 'test_outputs');
}

async function findingsPath(project, id) {
  return path.join(await findingsDir(project, id), 'findings.json');
}

async function readFindings(project, id) {
  const file = await findingsPath(project, id);
  let raw;
  try {
    raw = await fs.readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return { wstg_id: id, findings: [] }; // nothing entered yet - not an error
    throw e;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HttpError(500, 'findings.json exists but is not valid JSON.');
  }
  return { wstg_id: id, findings: Array.isArray(parsed.findings) ? parsed.findings : [] };
}

/** Trim strings, drop blanks from arrays, clamp the CVSS score, and never trust a Risk_Level
 * value that isn't one of the five real bands - all free-text fields default to '' rather
 * than null/undefined so the GUI form always has something to bind an <input> to. */
function sanitizeFinding(input, existing) {
  const str = (v, fallback = '') => (typeof v === 'string' ? v.trim() : fallback);
  const strArray = (v) => (Array.isArray(v) ? v.map((s) => String(s).trim()).filter(Boolean) : []);
  const rm = input.Risk_Matrix || {};
  const cwe = input.CWE_Information || {};
  const rem = input.Remediation || {};
  const urls = input.Affected_URLs || {};

  let score = Number(rm.CVSS_Score);
  if (!Number.isFinite(score)) score = null;
  else score = Math.min(10, Math.max(0, Math.round(score * 10) / 10));

  const level = RISK_LEVELS.has(rm.Risk_Level) ? rm.Risk_Level : null;

  const now = new Date().toISOString();
  return {
    id: existing?.id || crypto.randomBytes(4).toString('hex'),
    created_at: existing?.created_at || now,
    updated_at: now,
    Risk_Matrix: {
      CVSS_Vector: str(rm.CVSS_Vector),
      CVSS_Score: score,
      Risk_Level: level,
    },
    CWE_Information: {
      CWE_Number: str(cwe.CWE_Number),
      CWE_Name: str(cwe.CWE_Name),
      CWE_Description: str(cwe.CWE_Description),
      CWE_Why: str(cwe.CWE_Why),
      CWE_Impact: str(cwe.CWE_Impact),
    },
    Remediation: {
      Remediation_Statement: str(rem.Remediation_Statement),
      Recommendation: str(rem.Recommendation),
      Additional_recommendations: strArray(rem.Additional_recommendations),
    },
    Affected_URLs: {
      URLs: strArray(urls.URLs),
    },
  };
}

function renderMarkdown(wstgId, findings) {
  const lines = [`# ${wstgId} — Findings`, '', `**Count:** ${findings.length}`, ''];
  findings.forEach((f, i) => {
    const rm = f.Risk_Matrix || {};
    const cwe = f.CWE_Information || {};
    const rem = f.Remediation || {};
    lines.push(`## Finding ${i + 1}${cwe.CWE_Name ? `: ${cwe.CWE_Name}` : ''}`);
    lines.push(`- **Risk level:** ${rm.Risk_Level || 'not set'} (CVSS ${rm.CVSS_Score ?? '—'}${rm.CVSS_Vector ? `, \`${rm.CVSS_Vector}\`` : ''})`);
    lines.push(`- **CWE:** ${cwe.CWE_Number || '—'} ${cwe.CWE_Name || ''}`.trim());
    lines.push(`- **Recorded:** ${f.created_at}${f.updated_at !== f.created_at ? ` (updated ${f.updated_at})` : ''}`);
    lines.push('');
    if (cwe.CWE_Description) lines.push(`**Description**\n\n${cwe.CWE_Description}\n`);
    if (cwe.CWE_Why) lines.push(`**Why this matters**\n\n${cwe.CWE_Why}\n`);
    if (cwe.CWE_Impact) lines.push(`**Impact**\n\n${cwe.CWE_Impact}\n`);
    if (rem.Remediation_Statement) lines.push(`**Remediation**\n\n${rem.Remediation_Statement}\n`);
    if (rem.Recommendation) lines.push(`**Recommendation**\n\n${rem.Recommendation}\n`);
    if (rem.Additional_recommendations?.length) {
      lines.push('**Additional recommendations**', '');
      for (const r of rem.Additional_recommendations) lines.push(`- ${r}`);
      lines.push('');
    }
    if (f.Affected_URLs?.URLs?.length) {
      lines.push('**Affected URLs**', '');
      for (const u of f.Affected_URLs.URLs) lines.push(`- \`${u}\``);
      lines.push('');
    }
  });
  return lines.join('\n') + '\n';
}

async function writeFindings(project, id, findings) {
  const dir = await findingsDir(project, id);
  await fs.mkdir(dir, { recursive: true });
  const jsonFile = path.join(dir, 'findings.json');
  const mdFile = path.join(dir, 'findings.md');
  const tmpJson = `${jsonFile}.${process.pid}.tmp`;
  const tmpMd = `${mdFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpJson, JSON.stringify({ wstg_id: id, findings }, null, 2) + '\n');
  await fs.rename(tmpJson, jsonFile);
  await fs.writeFile(tmpMd, renderMarkdown(id, findings));
  await fs.rename(tmpMd, mdFile);
}

async function createFinding(project, id, payload) {
  const { findings } = await readFindings(project, id);
  const finding = sanitizeFinding(payload || {}, null);
  findings.push(finding);
  await writeFindings(project, id, findings);
  return finding;
}

async function updateFinding(project, id, findingId, payload) {
  const { findings } = await readFindings(project, id);
  const i = findings.findIndex((f) => f.id === findingId);
  if (i === -1) throw new HttpError(404, 'No such finding.');
  const finding = sanitizeFinding(payload || {}, findings[i]);
  findings[i] = finding;
  await writeFindings(project, id, findings);
  return finding;
}

async function deleteFinding(project, id, findingId) {
  const { findings } = await readFindings(project, id);
  const next = findings.filter((f) => f.id !== findingId);
  if (next.length === findings.length) throw new HttpError(404, 'No such finding.');
  await writeFindings(project, id, next);
  return { ok: true };
}

module.exports = { readFindings, createFinding, updateFinding, deleteFinding, RISK_LEVELS };
