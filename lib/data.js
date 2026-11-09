'use strict';
const fs = require('fs/promises');
const path = require('path');
const cfg = require('./config');
const { DataError } = require('./errors');

const ID_RE = /^WSTG-[A-Z]{4}-\d{2}$/;

// Parsed files are cached by mtime+size, so editing the JSON while the server runs just works.
const fileCache = new Map();

async function readJson(file, label) {
  let st;
  try {
    st = await fs.stat(file);
  } catch (e) {
    if (e.code === 'ENOENT') {
      throw new DataError(`Missing ${label}. Put your copy at ${file}`);
    }
    throw new DataError(`Cannot read ${label}: ${e.message}`);
  }
  const hit = fileCache.get(file);
  if (hit && hit.mtimeMs === st.mtimeMs && hit.size === st.size) return hit.value;

  let value;
  try {
    value = JSON.parse((await fs.readFile(file, 'utf8')).replace(/^﻿/, ''));
  } catch (e) {
    throw new DataError(`${label} is not valid JSON: ${e.message}`);
  }
  const built = { mtimeMs: st.mtimeMs, size: st.size, value, derived: null };
  fileCache.set(file, built);
  return value;
}

function derive(file, build) {
  const entry = fileCache.get(file);
  if (!entry.derived) entry.derived = build(entry.value);
  return entry.derived;
}

/**
 * wstg_reporting.json -> { categories: [{ name, id, tests: [{id, name}] }], byId: Map }
 */
async function getReporting() {
  const file = path.join(cfg.DATA_DIR, cfg.REPORTING_FILE);
  await readJson(file, cfg.REPORTING_FILE);
  return derive(file, (raw) => {
    if (!raw || typeof raw.categories !== 'object' || raw.categories === null) {
      throw new DataError(`${cfg.REPORTING_FILE} has no "categories" object.`);
    }
    const categories = [];
    const byId = new Map();
    for (const [catName, cat] of Object.entries(raw.categories)) {
      const tests = [];
      for (const t of Array.isArray(cat.tests) ? cat.tests : []) {
        if (!t || !ID_RE.test(String(t.id))) continue;
        tests.push({ id: t.id, name: String(t.name ?? t.id) });
        byId.set(t.id, { category: catName, categoryId: cat.id, test: t });
      }
      categories.push({ name: catName, id: cat.id, tests });
    }
    return { categories, byId };
  });
}

/**
 * wstg_io.json -> { byId: Map(id -> entry), unattached: [keys that are not a single test ID] }
 * Keys such as "WSTG-INJT (distributor)" describe a whole category, not one test, so they
 * can't be tied to a folder and are reported instead of silently dropped.
 */
async function getIo() {
  const file = path.join(cfg.DATA_DIR, cfg.IO_FILE);
  await readJson(file, cfg.IO_FILE);
  return derive(file, (raw) => {
    if (!raw || typeof raw.test_cases !== 'object' || raw.test_cases === null) {
      throw new DataError(`${cfg.IO_FILE} has no "test_cases" object.`);
    }
    const byId = new Map();
    const unattached = [];
    for (const [key, entry] of Object.entries(raw.test_cases)) {
      const k = key.trim();
      if (ID_RE.test(k)) byId.set(k, entry);
      else unattached.push(key);
    }
    return { byId, unattached };
  });
}

/* ---------------------------- XML routing ---------------------------- */

const KEY_RE = /^[a-z][a-z0-9_]*$/;
const XML_FILE_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*\.xml$/;
const SCOPE_RE = /^WSTG-[A-Z]{4}(-\d{2})?$/;

function normalizeRouting(raw) {
  const fail = (msg) => { throw new DataError(`${cfg.ROUTING_FILE}: ${msg}`); };
  const strings = (v, what) => {
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) fail(`${what} must be a list.`);
    return v.map(String);
  };
  if (!raw || typeof raw.kinds !== 'object' || raw.kinds === null) fail('there is no "kinds" object.');

  const kinds = [];
  for (const [key, k] of Object.entries(raw.kinds)) {
    if (!KEY_RE.test(key)) fail(`kind "${key}" must use lowercase letters, digits and underscores.`);
    if (!k || typeof k !== 'object') fail(`kind "${key}" must be an object.`);
    const enabled = k.enabled === true;
    const folder = k.folder == null ? null : String(k.folder);
    if (folder !== null && !KEY_RE.test(folder)) fail(`kind "${key}": folder "${folder}" must use lowercase letters, digits and underscores.`);
    if (enabled && !folder) fail(`kind "${key}" is enabled but has no "folder".`);
    if (k.root_element != null && !/^[A-Za-z][\w.-]*$/.test(String(k.root_element))) fail(`kind "${key}": root_element must be an element name.`);

    const categories = [];
    const seenKeys = new Set();
    const seenFiles = new Set();
    for (const [ck, c] of Object.entries(k.categories || {})) {
      const where = `kind "${key}", category "${ck}"`;
      if (!KEY_RE.test(ck)) fail(`${where}: key must use lowercase letters, digits and underscores.`);
      if (!c || typeof c !== 'object') fail(`${where}: must be an object.`);
      const file = String(c.file ?? '');
      if (!XML_FILE_RE.test(file)) fail(`${where}: "file" must be a plain .xml file name, got "${file}".`);
      if (seenKeys.has(ck)) fail(`${where}: duplicate category.`);
      if (seenFiles.has(file.toLowerCase())) fail(`${where}: file "${file}" is used twice.`);
      seenKeys.add(ck);
      seenFiles.add(file.toLowerCase());
      const include = strings(c.include, `${where}: include`);
      const omit = strings(c.omit, `${where}: omit`);
      for (const s of include) if (!SCOPE_RE.test(s)) fail(`${where}: include "${s}" must look like WSTG-INFO or WSTG-INFO-01.`);
      for (const s of omit) if (!ID_RE.test(s)) fail(`${where}: omit "${s}" must be a full ID like WSTG-INFO-07.`);
      categories.push({ key: ck, label: String(c.label ?? ck), file, include, omit });
    }
    if (enabled && !categories.length) fail(`kind "${key}" is enabled but has no categories.`);
    kinds.push({
      key,
      title: String(k.title ?? key),
      enabled,
      folder,
      acceptsTypes: strings(k.accepts_types, `kind "${key}": accepts_types`),
      includeUntyped: k.include_untyped === true,
      rootElement: k.root_element == null ? null : String(k.root_element),
      categories,
    });
  }
  return { kinds };
}

async function getRouting() {
  const file = path.join(cfg.DATA_DIR, cfg.ROUTING_FILE);
  await readJson(file, cfg.ROUTING_FILE);
  return derive(file, normalizeRouting);
}

/** Cross-check the two files against each other. Used for the pre-flight page and the startup log. */
async function validationReport() {
  const [reporting, io] = await Promise.all([getReporting(), getIo()]);
  const testsWithoutIo = [...reporting.byId.keys()].filter((id) => !io.byId.has(id));
  const ioWithoutTest = [...io.byId.keys()].filter((id) => !reporting.byId.has(id));
  return {
    reportingTests: reporting.byId.size,
    ioConfigs: io.byId.size,
    testsWithoutIo,
    ioWithoutTest,
    unattachedKeys: io.unattached,
  };
}

module.exports = { ID_RE, getReporting, getIo, getRouting, validationReport, readJson, derive };
