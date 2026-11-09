'use strict';
const fs = require('fs/promises');
const path = require('path');

/** readdir with types; null when the directory doesn't exist. */
async function listDir(dir) {
  try {
    return await fs.readdir(dir, { withFileTypes: true });
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return null;
    throw e;
  }
}

/** Case-insensitive child lookup (the operator may be on Windows). Returns the real name or null. */
async function findChild(dir, aliases) {
  const list = await listDir(dir);
  if (!list) return null;
  for (const alias of aliases) {
    const want = alias.toLowerCase();
    const hit = list.find((d) => d.name.toLowerCase() === want);
    if (hit) return hit.name;
  }
  return null;
}

/**
 * Walk segments below root, each segment a name or a list of accepted aliases.
 * resolveSub(testDir, ['Inputs', ['Wordlists', 'Wordlist']]) -> absolute path or null.
 */
async function resolveSub(root, segments) {
  let cur = root;
  for (const seg of segments) {
    const real = await findChild(cur, Array.isArray(seg) ? seg : [seg]);
    if (!real) return null;
    cur = path.join(cur, real);
  }
  return cur;
}

/** True for an existing file or directory (follows symlinks, so a symlinked wordlist counts). */
async function exists(p) {
  try {
    const s = await fs.stat(p);
    return s.isFile() || s.isDirectory();
  } catch {
    return false;
  }
}

async function isDir(p) {
  try {
    return (await fs.stat(p)).isDirectory();
  } catch {
    return false;
  }
}

module.exports = { listDir, findChild, resolveSub, exists, isDir };
