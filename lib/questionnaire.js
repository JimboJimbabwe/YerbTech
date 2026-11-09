'use strict';
/**
 * Questionnaire pipeline: reads the project's static questionnaire_router.json (which WSTG items
 * have a questionnaire, and its runner script name) and questionnaire_inventory.json (the same
 * entries plus the actual questions), joins them, and lets the operator answer on the web - check
 * boxes for true/false-style questions, a text box for anything that needs typing. Nothing here
 * runs a script; it only reads/writes JSON and Markdown.
 *
 * The join key is (WSTG_ID, nth occurrence in file order), same rule the operator's own
 * questionnaire_viewer.py used - an ID that appears twice (WSTG-IDNT-02 has two questionnaires)
 * pairs up positionally. The router entry's own runner filename (minus .py) is the stable id used
 * everywhere below (the "key") and the stem of the saved answer files, since it is already unique
 * per questionnaire by construction.
 *
 * Where answers land: this project's own WSTG-XXXX-NN folder, found the same way the rest of the
 * app finds it (resources.locateTest - a scan for a folder named like the ID, not a hardcoded
 * category map), under Outputs/test_outputs/<key>_answers.{json,md}.
 */
const fs = require('fs/promises');
const path = require('path');
const { HttpError, DataError } = require('./errors');
const { settingsRoot } = require('./settings');
const resources = require('./resources');

const ROUTER_REL = ['Configurations', 'Questionnaires', 'questionnaire_router.json'];
const INVENTORY_REL = ['Configurations', 'Questionnaires', 'questionnaire_inventory.json'];
const ID_RE = /^WSTG-[A-Z]{3,5}-\d{2}$/;

async function readJson(file, label) {
  let text;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') throw new HttpError(404, `${label} is not in this project's Settings/Configurations/Questionnaires folder yet.`);
    throw e;
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new DataError(`${label} is not valid JSON: ${e.message}`);
  }
}

/** key: the runner filename without its extension, or a fallback when the router didn't give one. */
function keyFor(wstgId, runner, n) {
  const stem = String(runner || '').trim().replace(/\.[A-Za-z0-9]+$/, '');
  return stem || `${wstgId}_${n}`;
}

/**
 * Join router + inventory into a flat list of questionnaire items, in router file order.
 * Each item: { key, wstg_id, category, runner, title, polarity, questions }.
 * Returns { items, warnings }.
 */
async function loadData(project) {
  const root = settingsRoot(project.dir);
  const router = await readJson(path.join(root, ...ROUTER_REL), 'questionnaire_router.json');
  const inventory = await readJson(path.join(root, ...INVENTORY_REL), 'questionnaire_inventory.json');
  if (!Array.isArray(router)) throw new DataError('questionnaire_router.json must be a JSON array.');
  if (!Array.isArray(inventory)) throw new DataError('questionnaire_inventory.json must be a JSON array.');

  const invById = new Map();
  for (const e of inventory) {
    const id = e && e.WSTG_ID;
    if (!id) continue;
    if (!invById.has(id)) invById.set(id, []);
    invById.get(id).push(e);
  }

  const warnings = [];
  const seen = new Map();
  const items = [];
  const usedKeys = new Set();

  for (const r of router) {
    const wstgId = r && r.WSTG_ID;
    if (!wstgId) continue;
    const n = seen.get(wstgId) || 0;
    seen.set(wstgId, n + 1);
    const matches = invById.get(wstgId) || [];
    const inv = matches[n] || null;
    if (!inv) warnings.push(`${wstgId} is in the router but has no inventory entry at position ${n + 1}`);
    let key = keyFor(wstgId, r.Questionnaire_runner, n);
    if (usedKeys.has(key)) { warnings.push(`duplicate questionnaire key "${key}" (router runner names must be unique) - skipped a duplicate`); continue; }
    usedKeys.add(key);
    items.push({
      key,
      wstg_id: wstgId,
      category: r.WSTG_CATEGORY_NAME || (inv && inv.WSTG_CATEGORY_NAME) || '(uncategorised)',
      runner: r.Questionnaire_runner || '',
      title: (inv && inv.questionnaire_title) || '',
      polarity: (inv && inv.polarity) || '',
      questions: (inv && inv.questionnaire) || [],
    });
  }

  // Inventory entries the router doesn't know about - still worth seeing, flagged as orphaned.
  for (const [wstgId, entries] of invById) {
    const already = seen.get(wstgId) || 0;
    for (let n = already; n < entries.length; n++) {
      const inv = entries[n];
      warnings.push(`${wstgId} is in the inventory but not the router (questionnaire ${n + 1})`);
      let key = keyFor(wstgId, null, `${n}_orphan`);
      if (usedKeys.has(key)) continue;
      usedKeys.add(key);
      items.push({
        key,
        wstg_id: wstgId,
        category: inv.WSTG_CATEGORY_NAME || '(uncategorised)',
        runner: '(not in router)',
        title: inv.questionnaire_title || '',
        polarity: inv.polarity || '',
        questions: inv.questionnaire || [],
      });
    }
  }

  return { items, warnings };
}

/** Grouped by category, with a count and whether an answer file already exists - for the panel. */
async function listItems(project) {
  const { items, warnings } = await loadData(project);
  const out = [];
  for (const it of items) {
    let answered = false;
    try {
      const { outDir } = await resolveOutputDir(project, it.wstg_id);
      await fs.access(path.join(outDir, `${it.key}_answers.json`));
      answered = true;
    } catch { /* not answered yet, or the WSTG folder doesn't exist yet - either way, false */ }
    out.push({
      key: it.key, wstg_id: it.wstg_id, category: it.category, runner: it.runner,
      title: it.title, polarity: it.polarity, question_count: it.questions.length, answered,
    });
  }
  return { items: out, warnings };
}

async function getItem(project, key) {
  const { items } = await loadData(project);
  const item = items.find((it) => it.key === key);
  if (!item) throw new HttpError(404, `No questionnaire with key "${key}".`);
  let answers = null;
  try {
    const { outDir } = await resolveOutputDir(project, item.wstg_id);
    const text = await fs.readFile(path.join(outDir, `${key}_answers.json`), 'utf8');
    answers = JSON.parse(text).answers || null;
  } catch { /* no saved answers yet */ }
  return { ...item, answers };
}

/** Find the WSTG-XXXX-NN folder the same way the rest of the app does: a scan, not a hardcoded map. */
async function resolveOutputDir(project, wstgId) {
  if (!ID_RE.test(wstgId)) throw new HttpError(400, 'Invalid WSTG ID.');
  const { testDir } = await resources.locateTest(project, wstgId);
  if (!testDir) throw new HttpError(404, `Could not find a ${wstgId} folder in this project's WSTG_Repository.`);
  const outDir = path.join(testDir, 'Outputs', 'test_outputs');
  return { testDir, outDir };
}

/** "ID == VALUE" -> true/false against the answers collected so far. Unparseable -> true (don't hide). */
function evalCondition(cond, answers) {
  if (!cond) return true;
  const m = /^\s*([^=\s][^=]*?)\s*==\s*(.+?)\s*$/.exec(cond);
  if (!m) return true;
  const [, qid, want] = m;
  const got = answers[qid];
  if (got == null) return false;
  const value = typeof got === 'object' && 'value' in got ? got.value : got;
  return String(value) === want;
}

/** Follow-up sub-prompts under a yn question only make sense once it's answered Y (judgment call; the
 * inventory doesn't carry an explicit condition for these, but every follow_up in the data reads that way). */
function followUpsVisible(q, answers) {
  const got = answers[q.id];
  const value = got && typeof got === 'object' && 'value' in got ? got.value : got;
  return value === 'Y';
}

/**
 * Render the saved answers (plus the question text) as Markdown, marking anything hidden by a
 * condition as skipped rather than omitting it, so the record shows every question that existed.
 */
function renderMarkdown(item, answers) {
  const lines = [];
  lines.push(`# ${item.wstg_id} — ${item.title || item.key}`);
  if (item.polarity) lines.push(`Polarity: ${item.polarity}`);
  lines.push(`Runner: ${item.runner || '(none)'}`);
  lines.push(`Saved: ${new Date().toISOString()}`);
  lines.push('');
  let lastGroup = null;
  for (const q of item.questions) {
    const group = q.category_name;
    if (group && group !== lastGroup) {
      lines.push(`## ${q.category ? `${q.category}. ` : ''}${group}`);
      lines.push('');
      lastGroup = group;
    }
    const gated = q.parent_condition && !evalCondition(q.parent_condition, answers);
    const skipped = q.condition && !evalCondition(q.condition, answers);
    lines.push(`**[${q.id}]** ${q.question}`);
    if (gated || skipped) {
      const cond = q.parent_condition || q.condition;
      lines.push(`→ _skipped (condition "${cond}" not met)_`);
    } else {
      const got = answers[q.id];
      const value = got && typeof got === 'object' && 'value' in got ? got.value : got;
      if (value === undefined || value === null || value === '') {
        lines.push(`→ _(no answer)_`);
      } else if (Array.isArray(value)) {
        lines.push(`→ **${value.join(', ') || '(none selected)'}**`);
      } else if (typeof value === 'object') {
        lines.push(`→ **${Object.entries(value).map(([k, v]) => `${k}=${v}`).join(', ')}**`);
      } else {
        lines.push(`→ **${value}**`);
      }
      if (Array.isArray(q.follow_up) && q.follow_up.length && followUpsVisible(q, answers)) {
        for (let i = 0; i < q.follow_up.length; i++) {
          const fuId = `${q.id}__fu${i}`;
          const fuVal = answers[fuId];
          const fv = fuVal && typeof fuVal === 'object' && 'value' in fuVal ? fuVal.value : fuVal;
          lines.push(`  - *${q.follow_up[i]}* → ${fv || '_(no answer)_'}`);
        }
      }
    }
    if (q.note) lines.push(`  _(note: ${q.note})_`);
    lines.push('');
  }
  return lines.join('\n');
}

/**
 * Save the operator's answers for one questionnaire: a JSON file first (the source of truth) then
 * a Markdown rendering (the readable record). Both are written every time the operator saves, so
 * reopening and re-saving keeps them in sync - nothing in Outputs/test_outputs is appended to.
 */
async function saveAnswers(project, key, answers) {
  if (!answers || typeof answers !== 'object' || Array.isArray(answers)) {
    throw new HttpError(400, '"answers" must be an object keyed by question id.');
  }
  const { items } = await loadData(project);
  const item = items.find((it) => it.key === key);
  if (!item) throw new HttpError(404, `No questionnaire with key "${key}".`);

  const { outDir } = await resolveOutputDir(project, item.wstg_id);
  await fs.mkdir(outDir, { recursive: true });

  const savedAt = new Date().toISOString();
  const jsonBody = {
    wstg_id: item.wstg_id,
    questionnaire_title: item.title,
    polarity: item.polarity,
    runner: item.runner,
    saved_at: savedAt,
    answers,
  };
  const jsonFile = path.join(outDir, `${key}_answers.json`);
  const mdFile = path.join(outDir, `${key}_answers.md`);
  const tmpJson = `${jsonFile}.${process.pid}.tmp`;
  const tmpMd = `${mdFile}.${process.pid}.tmp`;

  await fs.writeFile(tmpJson, JSON.stringify(jsonBody, null, 2) + '\n');
  await fs.rename(tmpJson, jsonFile);
  await fs.writeFile(tmpMd, renderMarkdown(item, answers));
  await fs.rename(tmpMd, mdFile);

  return { json: jsonFile, md: mdFile, saved_at: savedAt };
}

module.exports = { loadData, listItems, getItem, resolveOutputDir, saveAnswers, evalCondition, followUpsVisible, renderMarkdown };
