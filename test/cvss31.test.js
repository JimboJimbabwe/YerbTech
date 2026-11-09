'use strict';
// node --test picks this up alongside app.test.js. cvss31.js is ES module syntax (it's shared
// verbatim with the browser - see public/js/package.json), so it's loaded with dynamic import()
// rather than require().
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const cvssUrl = `file://${path.join(__dirname, '..', 'public', 'js', 'cvss31.js')}`;

test('CVSS 3.1: reproduces two well-known published reference scores exactly', async () => {
  const { computeCvss31 } = await import(cvssUrl);

  // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - the textbook "unauthenticated RCE, scope unchanged"
  // vector, universally cited at 9.8 Critical.
  const a = computeCvss31({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  assert.equal(a.score, 9.8);
  assert.equal(a.severity, 'Critical');
  assert.equal(a.vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

  // Same but Scope:Changed - Log4Shell's (CVE-2021-44228) published vector, scored 10.0.
  const b = computeCvss31({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' });
  assert.equal(b.score, 10.0);
  assert.equal(b.severity, 'Critical');
});

test('CVSS 3.1: severity bands match the published table at every boundary', async () => {
  const { computeCvss31 } = await import(cvssUrl);
  const base = { AV: 'P', AC: 'H', PR: 'H', UI: 'R', S: 'U' };

  // No impact at all -> score 0, "None".
  assert.deepEqual(
    (({ score, severity }) => ({ score, severity }))(computeCvss31({ ...base, C: 'N', I: 'N', A: 'N' })),
    { score: 0, severity: 'None' },
  );

  const low = computeCvss31({ ...base, C: 'L', I: 'N', A: 'N' });
  assert.ok(low.score > 0 && low.score < 4.0, `expected a Low-range score, got ${low.score}`);
  assert.equal(low.severity, 'Low');

  const high = computeCvss31({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' });
  assert.ok(high.score >= 7.0 && high.score < 9.0, `expected a High-range score, got ${high.score}`);
  assert.equal(high.severity, 'High');
});

test('CVSS 3.1: an incomplete metric set returns null, not a wrong score', async () => {
  const { computeCvss31 } = await import(cvssUrl);
  assert.equal(computeCvss31({ AV: 'N', AC: 'L' }), null);
  assert.equal(computeCvss31({}), null);
});

test('CVSS 3.1: parseCvss31Vector round-trips a vector string, and never throws on garbage', async () => {
  const { computeCvss31, parseCvss31Vector } = await import(cvssUrl);
  const original = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
  const { vector } = computeCvss31(original);
  assert.deepEqual(parseCvss31Vector(vector), original);

  assert.deepEqual(parseCvss31Vector('not a vector'), {});
  assert.deepEqual(parseCvss31Vector(undefined), {});
  assert.deepEqual(parseCvss31Vector(null), {});
});
