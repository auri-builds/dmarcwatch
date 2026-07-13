'use strict';
const test = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');
const AdmZip = require('adm-zip');
const { parseAggregateReport, isDmarcFail } = require('../src/lib/parser');
const { SAMPLE_XML, SINGLE_RECORD_XML } = require('./fixtures');

test('parses a multi-record aggregate report', () => {
  const r = parseAggregateReport(SAMPLE_XML);
  assert.equal(r.orgName, 'google.com');
  assert.equal(r.externalId, '1234567890123456789');
  assert.equal(r.policy.domain, 'example.com');
  assert.equal(r.policy.p, 'quarantine');
  assert.equal(r.dateBegin, 1752278400);
  assert.equal(r.records.length, 2);

  const [ok, bad] = r.records;
  assert.equal(ok.ip, '209.85.220.41');
  assert.equal(ok.count, 42);
  assert.equal(isDmarcFail(ok), false);
  assert.equal(ok.auth.dkim[0].selector, 'google');

  assert.equal(bad.ip, '203.0.113.99');
  assert.equal(bad.disposition, 'quarantine');
  assert.equal(isDmarcFail(bad), true);
});

test('single <record> (not array) parses to one record', () => {
  const r = parseAggregateReport(SINGLE_RECORD_XML);
  assert.equal(r.records.length, 1);
  // aligned SPF passes → not a DMARC failure even though DKIM fails
  assert.equal(isDmarcFail(r.records[0]), false);
  assert.equal(r.policy.pct, 100); // default when absent
});

test('accepts gzip payloads', () => {
  const r = parseAggregateReport(zlib.gzipSync(Buffer.from(SAMPLE_XML)));
  assert.equal(r.records.length, 2);
});

test('accepts zip payloads', () => {
  const zip = new AdmZip();
  zip.addFile('google.com!example.com!1752278400!1752364799.xml', Buffer.from(SAMPLE_XML));
  const r = parseAggregateReport(zip.toBuffer());
  assert.equal(r.policy.domain, 'example.com');
});

test('rejects non-DMARC XML', () => {
  assert.throws(() => parseAggregateReport('<html><body>nope</body></html>'), /missing <feedback>/);
});

test('rejects feedback without policy domain', () => {
  assert.throws(() => parseAggregateReport('<feedback><report_metadata/></feedback>'), /policy_published/);
});
