'use strict';
/**
 * Read-only access to a project's Reporting/reporting_index.json - the master index the
 * reporting_overlay.py tool (run via lib/reportingProc.js) writes to. This module never writes
 * it; the overlay owns that file the same way clipboard_interceptor.py owns Mouse_Tool's state.
 * Used for a small summary in the GUI panel so the operator can see step counts without leaving
 * the browser.
 */
const fs = require('fs/promises');
const path = require('path');
const { DataError } = require('./errors');

const INDEX_REL = ['Reporting', 'reporting_index.json'];

async function getSummary(project) {
  const file = path.join(project.dir, ...INDEX_REL);
  let text;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return { file, exists: false, categories: 0, items: 0, steps: 0 };
    throw e;
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new DataError(`reporting_index.json is not valid JSON: ${e.message}`);
  }
  let items = 0;
  let steps = 0;
  for (const cat of Object.values(data || {})) {
    if (!cat || typeof cat !== 'object') continue;
    for (const entry of Object.values(cat)) {
      items += 1;
      steps += Array.isArray(entry?.steps) ? entry.steps.length : 0;
    }
  }
  return { file, exists: true, categories: Object.keys(data || {}).length, items, steps };
}

module.exports = { getSummary };
