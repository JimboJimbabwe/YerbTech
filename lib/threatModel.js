'use strict';
/**
 * Reads a WSTG item's Threat_Model.json (written by tools/param_mapper/threat_rank.py,
 * run outside this app) and serves it to the viewer the same way the existing XML
 * datasets are served - a list to pick from, then the real underlying Burp request
 * for whichever row is picked.
 *
 * The item index path parameter is an index into Threat_Model.json's own "items" array,
 * not anything the client constructs - the server always re-reads the file and resolves
 * the XML path from ITS OWN contents, never from a client-supplied path. That keeps this
 * route from ever being an arbitrary-file-read: whatever xml_file ends up read is only
 * ever one this app's own resources.locateTest + a file this project's own tooling wrote.
 */
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { HttpError } = require('./errors');
const cfg = require('./config');
const resources = require('./resources');
const burp = require('./burp');

async function threatModelPath(project, id) {
  const { testDir } = await resources.locateTest(project, id);
  if (!testDir) return null;
  return path.join(testDir, 'Outputs', 'test_outputs', 'Threat_Model.json');
}

async function readThreatModel(project, id) {
  const file = await threatModelPath(project, id);
  if (!file) throw new HttpError(404, `No folder found for ${id}.`);
  let raw;
  try {
    raw = await fs.readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return null; // not an error - just nothing generated yet
    throw e;
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(500, 'Threat_Model.json exists but is not valid JSON.');
  }
}

/** List shape the viewer's Threat-Model mode renders - one row per ranked association,
 * with the top candidate surfaced directly so the list itself can show it without a
 * second request. */
async function listItems(project, id) {
  const model = await readThreatModel(project, id);
  if (!model) return { generated_at: null, model: null, items: [] };
  const items = (model.items || []).map((it, i) => {
    const top = it.ranked_parameters && it.ranked_parameters[0];
    return {
      item_index: i,
      xml_index: it.endpoint.xml_index,
      method: it.endpoint.method,
      path: it.endpoint.path,
      best_match: it.best_match,
      top_confidence: top ? top.confidence : null,
      ranked_count: (it.ranked_parameters || []).length,
    };
  });
  return { generated_at: model.generated_at, model: model.model, items };
}

/** The real request for one Threat-Model row, in the exact shape burp.getRequest
 * already returns - so the viewer's existing showRequest() needs no changes. */
async function getItemRequest(project, id, itemIndex) {
  const model = await readThreatModel(project, id);
  if (!model) throw new HttpError(404, 'No Threat_Model.json for this assessment yet.');
  const item = (model.items || [])[itemIndex];
  if (!item) throw new HttpError(404, 'No such Threat-Model item.');
  if (!item.xml_file) throw new HttpError(500, 'This Threat-Model item has no xml_file recorded.');
  const full = await burp.getRequest(item.xml_file, item.endpoint.burp_index);
  return { ...full, ranking: { best_match: item.best_match, ranked_parameters: item.ranked_parameters || [] } };
}

/**
 * "Push to Testing": turn selected Threat-Model rows into a file the Burp-side Intruder-loader
 * extension (tools this project ships but doesn't run - see Base_Image/.../Intruder_Loader/)
 * can pick up and feed into sendToIntruder(host, port, https, request).
 *
 * Written to <INTRUDER_QUEUE_DIR>/<project.name>/<wstg_id>__<rand>.json - never anywhere else,
 * so two projects' pushes can never land in the same folder (project.name is already validated
 * filesystem-safe by lib/projects.js). The raw request bytes go in base64 (raw_request_b64), the
 * same choice made for param_mapper.py's body_data_b64 - some requests carry binary bodies or
 * encodings that are not valid UTF-8, and base64 is the only way to put arbitrary bytes inside
 * JSON without quietly corrupting them.
 *
 * A request Burp's own XML already recorded as truncated (over burp.js's per-request cap) is
 * skipped rather than pushed - Intruder would get a cut-off, broken request otherwise.
 */
async function pushToQueue(project, id, itemIndexes) {
  const model = await readThreatModel(project, id);
  if (!model) throw new HttpError(404, 'No Threat_Model.json for this assessment yet.');
  const items = model.items || [];

  const pushed = [];
  const skipped = [];
  const entries = [];
  for (const itemIndex of itemIndexes) {
    const item = items[itemIndex];
    if (!item) { skipped.push({ item_index: itemIndex, reason: 'No such Threat-Model item.' }); continue; }
    if (!item.xml_file) { skipped.push({ item_index: itemIndex, reason: 'This item has no xml_file recorded.' }); continue; }
    let raw;
    try {
      raw = await burp.getRawRequest(item.xml_file, item.endpoint.burp_index);
    } catch (e) {
      skipped.push({ item_index: itemIndex, reason: e.message || 'Could not read the request.' });
      continue;
    }
    if (raw.truncated) {
      skipped.push({ item_index: itemIndex, reason: 'The saved request is truncated (over the per-request size cap) - pushing it would send Intruder a broken request.' });
      continue;
    }
    entries.push({
      host: raw.host,
      port: raw.port,
      https: raw.https,
      raw_request_b64: raw.bytes.toString('base64'),
      project: project.name,
      wstg_id: id,
      xml_index: item.endpoint.xml_index,
      method: item.endpoint.method,
      path: item.endpoint.path,
      best_match: item.best_match || null,
    });
    pushed.push({ item_index: itemIndex, host: raw.host, method: item.endpoint.method, path: item.endpoint.path });
  }

  if (!entries.length) return { pushed, skipped, file: null };

  const dir = path.join(cfg.INTRUDER_QUEUE_DIR, project.name);
  await fs.mkdir(dir, { recursive: true });
  const name = `${id}__${crypto.randomBytes(4).toString('hex')}.json`;
  const file = path.join(dir, name);
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(entries, null, 2) + '\n');
  await fs.rename(tmp, file);
  return { pushed, skipped, file };
}

module.exports = { listItems, getItemRequest, pushToQueue };
