#!/usr/bin/env node
'use strict';
/**
 * Adds explicit fields to wstg_tools_procedures.json so the command builder doesn't have to guess:
 *   inputs[].takes_value     true when the flag is followed by a value, false for a plain switch,
 *                            null when the docs don't say (the builder then shows an "unsure" hint)
 *   outputs[].flag_required  true when the output flag is not optional in the documented command
 *
 *   node tools/annotate_procedures.js [file]            report only, changes nothing
 *   node tools/annotate_procedures.js [file] --write    keeps <file>.bak, then updates the file
 *
 * Fields that already exist are never overwritten, so you can correct one by hand and re-run.
 */
const fs = require('fs');
const path = require('path');
const { inferTakesValue, outputFlagRequired, splitFlags } = require('../lib/procedures');

const args = process.argv.slice(2);
const write = args.includes('--write');
const file = path.resolve(args.find((a) => !a.startsWith('--')) || path.join(__dirname, '..', 'data', 'json', 'wstg_tools_procedures.json'));
const raw = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''));

let added = 0;
const unsure = [];
for (const [cat, ids] of Object.entries(raw)) {
  if (cat === '_meta' || cat === 'category_run_order' || !ids || typeof ids !== 'object') continue;
  for (const [id, groups] of Object.entries(ids)) {
    for (const group of Object.values(groups || {})) {
      if (!group || typeof group !== 'object') continue;
      for (const s of Object.values(group)) {
        if (!s || typeof s !== 'object') continue;
        const cmd = typeof s.command === 'string' ? s.command : null;
        for (const i of Array.isArray(s.inputs) ? s.inputs : []) {
          if (!splitFlags(i.flag).length || 'takes_value' in i) continue;
          i.takes_value = inferTakesValue(i, cmd);
          added++;
          if (i.takes_value === null) unsure.push(`${id} ${s.name} ${i.flag}`);
        }
        for (const o of Array.isArray(s.outputs) ? s.outputs : []) {
          if (!splitFlags(o.flag).length || 'flag_required' in o) continue;
          o.flag_required = outputFlagRequired(o, cmd);
          added++;
        }
      }
    }
  }
}

console.log(`${added} field${added === 1 ? '' : 's'} ${write ? 'written' : 'would be written'} in ${file}`);
if (unsure.length) {
  console.log(`\n${unsure.length} flag${unsure.length === 1 ? '' : 's'} could not be classified (takes_value is null; fix by hand if you know):`);
  for (const u of unsure) console.log(`  ${u}`);
}
if (write && added) {
  fs.copyFileSync(file, `${file}.bak`);
  fs.writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);
  console.log(`\nBackup: ${file}.bak`);
} else if (!write) {
  console.log('\nDry run. Add --write to apply.');
}
