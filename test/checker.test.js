'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { analyzeDmarc, analyzeSpf, validDomain } = require('../src/lib/checker');

test('validDomain', () => {
  assert.ok(validDomain('example.com'));
  assert.ok(validDomain('sub.domain.co.uk'));
  assert.ok(!validDomain('nodots'));
  assert.ok(!validDomain('bad domain.com'));
  assert.ok(!validDomain(''));
});

test('DMARC: missing record fails', () => {
  assert.equal(analyzeDmarc([]).status, 'fail');
});

test('DMARC: p=none warns', () => {
  const r = analyzeDmarc(['v=DMARC1; p=none; rua=mailto:reports@example.com']);
  assert.equal(r.status, 'warn');
});

test('DMARC: enforcing policy with rua passes', () => {
  const r = analyzeDmarc(['v=DMARC1; p=reject; rua=mailto:reports@example.com']);
  assert.equal(r.status, 'pass');
});

test('DMARC: missing rua warns even when enforcing', () => {
  assert.equal(analyzeDmarc(['v=DMARC1; p=reject']).status, 'warn');
});

test('DMARC: multiple records fail', () => {
  assert.equal(analyzeDmarc(['v=DMARC1; p=reject', 'v=DMARC1; p=none']).status, 'fail');
});

test('SPF: missing fails, +all fails, ~all passes, no-all warns', () => {
  assert.equal(analyzeSpf([]).status, 'fail');
  assert.equal(analyzeSpf(['v=spf1 include:_spf.google.com +all']).status, 'fail');
  assert.equal(analyzeSpf(['v=spf1 include:_spf.google.com ~all']).status, 'pass');
  assert.equal(analyzeSpf(['v=spf1 include:_spf.google.com']).status, 'warn');
  assert.equal(analyzeSpf(['v=spf1 -all', 'v=spf1 ~all']).status, 'fail'); // duplicates = permerror
});
