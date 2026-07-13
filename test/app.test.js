'use strict';
process.env.DB_PATH = ':memory:';
const test = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');
const { app } = require('../src/server');
const { db } = require('../src/db');
const { SAMPLE_XML, FOLLOWUP_XML } = require('./fixtures');

let base;
let server;

test.before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => server.close());

function cookieOf(res) {
  return (res.headers.get('set-cookie') || '').split(';')[0];
}

test('end to end: signup → ingest → dashboard → alerts → dedupe', async (t) => {
  // signup
  const signup = await fetch(`${base}/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'email=msp%40example.com&password=hunter2222',
    redirect: 'manual',
  });
  assert.equal(signup.status, 302);
  const cookie = cookieOf(signup);
  assert.match(cookie, /session=/);

  const token = db.prepare('SELECT ingest_token FROM users WHERE email = ?').get('msp@example.com').ingest_token;

  // bad token rejected
  const bad = await fetch(`${base}/ingest/deadbeef`, { method: 'POST', body: SAMPLE_XML });
  assert.equal(bad.status, 404);

  // ingest gzip report via API
  const ing = await fetch(`${base}/ingest/${token}`, { method: 'POST', body: zlib.gzipSync(Buffer.from(SAMPLE_XML)) });
  assert.equal(ing.status, 200);
  const ingJson = await ing.json();
  assert.equal(ingJson.domain, 'example.com');
  assert.equal(ingJson.records, 2);
  assert.deepEqual(ingJson.newFailingSources, ['203.0.113.99']);

  // duplicate report is skipped
  const dup = await fetch(`${base}/ingest/${token}`, { method: 'POST', body: SAMPLE_XML });
  assert.equal((await dup.json()).duplicate, true);

  // second report: only the genuinely new failing IP alerts
  const fol = await fetch(`${base}/ingest/${token}`, { method: 'POST', body: FOLLOWUP_XML });
  assert.deepEqual((await fol.json()).newFailingSources, ['198.51.100.7']);

  // dashboard shows the domain
  const dash = await fetch(`${base}/app`, { headers: { cookie } });
  const html = await dash.text();
  assert.match(html, /example\.com/);
  assert.match(html, /2 alerts/);

  // domain page shows both failing sources
  const domainId = db.prepare('SELECT id FROM domains WHERE name = ?').get('example.com').id;
  const dpage = await (await fetch(`${base}/app/domain/${domainId}`, { headers: { cookie } })).text();
  assert.match(dpage, /203\.0\.113\.99/);
  assert.match(dpage, /198\.51\.100\.7/);
  assert.match(dpage, /209\.85\.220\.41/);

  // alerts page lists both and marks seen
  const alerts = await (await fetch(`${base}/app/alerts`, { headers: { cookie } })).text();
  assert.match(alerts, /New failing source for example\.com: 203\.0\.113\.99/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM alerts WHERE seen = 0').get().n, 0);

  // app pages require login
  const anon = await fetch(`${base}/app`, { redirect: 'manual' });
  assert.equal(anon.status, 302);

  // another user cannot see this user's domain
  await fetch(`${base}/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'email=other%40example.com&password=hunter2222',
    redirect: 'manual',
  }).then(async (r) => {
    const otherCookie = cookieOf(r);
    const resp = await fetch(`${base}/app/domain/${domainId}`, { headers: { cookie: otherCookie } });
    assert.equal(resp.status, 404);
  });

  // honest metrics events recorded
  const events = db.prepare('SELECT name, COUNT(*) AS n FROM events GROUP BY name').all();
  const byName = Object.fromEntries(events.map((e) => [e.name, e.n]));
  assert.equal(byName.signup, 2);
  assert.equal(byName.report_ingested, 2);
  assert.equal(byName.activation_first_report, 1);
});

test('login with wrong password rejected', async () => {
  const res = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'email=msp%40example.com&password=wrongwrong',
  });
  const html = await res.text();
  assert.match(html, /Invalid email or password/);
});
