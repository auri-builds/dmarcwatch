'use strict';
const express = require('express');
const { db, trackEvent } = require('./db');
const { createUser, authenticate, createSession, destroySession, getSessionUser, requireLogin } = require('./lib/auth');
const { ingestReport } = require('./lib/ingest');
const { checkDomain } = require('./lib/checker');
const { esc, layout, flash, statusPill } = require('./views');

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));

// Minimal cookie parsing — only the session cookie matters.
app.use((req, res, next) => {
  req.cookies = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) req.cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  next();
});
app.use((req, res, next) => { req.user = getSessionUser(req.cookies.session); next(); });

const page = (res, title, body, req) => res.send(layout({ title, body, user: req.user }));

// ---------- Public pages ----------

app.get('/', (req, res) => {
  page(res, 'DMARC monitoring for agencies and small businesses', `
    <h1>Know when your email breaks — before your customers do.</h1>
    <p class="sub">Gmail, Yahoo and Outlook now reject mail from domains without DMARC. DMARCwatch turns the unreadable XML reports into a clear dashboard and alerts you when a legitimate sender starts failing or someone spoofs your domain.</p>
    <div class="card">
      <strong>How it works</strong>
      <ul>
        <li>Sign up and get your personal report-ingest URL.</li>
        <li>Upload the aggregate report files (.xml, .gz, .zip) mailbox providers already send you — or forward them via your own automation.</li>
        <li>See every sending source per domain: who passes, who fails, who's spoofing.</li>
        <li>Get an alert the moment a new failing source appears.</li>
      </ul>
      <a class="btn" href="/signup">Start monitoring free</a>
      <a class="btn" style="background:transparent;color:var(--accent);border:1px solid var(--accent)" href="/checker">Check your domain's DMARC now</a>
    </div>
    <p class="muted">Built for MSPs and agencies managing many client domains: one account, unlimited domains during beta, reports auto-sorted per domain.</p>
  `, req);
});

app.get('/checker', (req, res) => {
  page(res, 'Free DMARC, SPF & DKIM checker', checkerForm(), req);
});

app.post('/checker', async (req, res) => {
  trackEvent('checker_used', { domain: req.body.domain });
  try {
    const result = await checkDomain(req.body.domain, req.body.selector);
    page(res, `Results for ${result.domain}`, checkerForm(req.body.domain, req.body.selector) + checkerResults(result), req);
  } catch {
    page(res, 'Free DMARC, SPF & DKIM checker', checkerForm(req.body.domain) + flash('That does not look like a valid domain.'), req);
  }
});

function checkerForm(domain, selector) {
  return `
    <h1>Free DMARC, SPF &amp; DKIM checker</h1>
    <p class="sub">See in seconds whether your domain meets Google, Yahoo and Microsoft's sender requirements.</p>
    <div class="card"><form method="post" action="/checker">
      <label>Domain</label><input name="domain" placeholder="example.com" value="${esc(domain || '')}" required>
      <label>DKIM selector (optional — we try common ones otherwise)</label><input name="selector" placeholder="google" value="${esc(selector || '')}">
      <button type="submit">Check domain</button>
    </form></div>`;
}

function checkerResults(r) {
  const section = (name, x, extra) => `
    <div class="card">
      <strong>${name}</strong> ${statusPill(x.status)}
      ${x.record ? `<p><code>${esc(x.record)}</code></p>` : ''}
      <ul>${x.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>
      ${extra || ''}
    </div>`;
  const cta = `<p>Records checked are a snapshot — deliverability breaks silently when a provider or vendor changes. <a href="/signup">Monitor ${esc(r.domain)} continuously →</a></p>`;
  return section('DMARC', r.dmarc) + section('SPF', r.spf) + section('DKIM', r.dkim) + `<div class="card">${cta}</div>`;
}

// ---------- Auth ----------

app.get('/signup', (req, res) => page(res, 'Sign up', authForm('signup'), req));
app.get('/login', (req, res) => page(res, 'Log in', authForm('login'), req));

app.post('/signup', (req, res) => {
  try {
    const userId = createUser(req.body.email, req.body.password);
    setSession(res, createSession(userId));
    res.redirect('/app');
  } catch (e) {
    const msg = /UNIQUE/.test(e.message) ? 'An account with that email already exists.' : e.message;
    page(res, 'Sign up', authForm('signup') + flash(msg), req);
  }
});

app.post('/login', (req, res) => {
  const user = authenticate(req.body.email, req.body.password);
  if (!user) return page(res, 'Log in', authForm('login') + flash('Invalid email or password.'), req);
  setSession(res, createSession(user.id));
  res.redirect('/app');
});

app.get('/logout', (req, res) => {
  if (req.cookies.session) destroySession(req.cookies.session);
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/');
});

function setSession(res, token) {
  res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 86400}`);
}

function authForm(kind) {
  const isSignup = kind === 'signup';
  return `
    <h1>${isSignup ? 'Create your account' : 'Log in'}</h1>
    <div class="card"><form method="post" action="/${kind}">
      <label>Email</label><input name="email" type="email" required>
      <label>Password${isSignup ? ' (8+ characters)' : ''}</label><input name="password" type="password" minlength="8" required>
      <button type="submit">${isSignup ? 'Sign up' : 'Log in'}</button>
    </form>
    <p class="muted">${isSignup ? 'Already have an account? <a href="/login">Log in</a>' : 'New here? <a href="/signup">Sign up</a>'}</p></div>`;
}

// ---------- Ingestion ----------

const rawBody = express.raw({ type: () => true, limit: '15mb' });

app.post('/ingest/:token', rawBody, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE ingest_token = ?').get(req.params.token);
  if (!user) return res.status(404).json({ error: 'unknown ingest token' });
  try {
    const result = ingestReport(user.id, req.body);
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: `could not parse report: ${e.message}` });
  }
});

app.post('/app/upload', requireLogin, rawBody, (req, res) => {
  try {
    const result = ingestReport(req.user.id, req.body);
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: `could not parse report: ${e.message}` });
  }
});

// ---------- App ----------

app.get('/app', requireLogin, (req, res) => {
  const domains = db
    .prepare(
      `SELECT d.*,
         (SELECT COUNT(*) FROM reports r WHERE r.domain_id = d.id) AS report_count,
         (SELECT COALESCE(SUM(count),0) FROM sources s WHERE s.domain_id = d.id) AS msg_count,
         (SELECT COALESCE(SUM(count),0) FROM sources s WHERE s.domain_id = d.id AND s.dkim_aligned != 'pass' AND s.spf_aligned != 'pass') AS fail_count,
         (SELECT COUNT(*) FROM alerts a WHERE a.domain_id = d.id AND a.seen = 0) AS open_alerts
       FROM domains d WHERE d.user_id = ? ORDER BY d.name`
    )
    .all(req.user.id);

  const rows = domains.map((d) => {
    const failPct = d.msg_count ? Math.round((100 * d.fail_count) / d.msg_count) : 0;
    const cls = failPct === 0 ? 'pass' : failPct < 5 ? 'warn' : 'fail';
    return `<tr>
      <td><a href="/app/domain/${d.id}">${esc(d.name)}</a></td>
      <td>${d.report_count}</td><td>${d.msg_count}</td>
      <td class="${cls}">${failPct}% failing</td>
      <td>${d.open_alerts ? `<span class="pill fail">${d.open_alerts} alert${d.open_alerts > 1 ? 's' : ''}</span>` : '—'}</td>
    </tr>`;
  }).join('');

  const ingestUrl = `${req.protocol}://${req.get('host')}/ingest/${req.user.ingest_token}`;
  page(res, 'Dashboard', `
    <h1>Your domains</h1>
    ${domains.length ? `<div class="card"><table>
      <tr><th>Domain</th><th>Reports</th><th>Messages</th><th>DMARC failures</th><th>Alerts</th></tr>${rows}</table></div>`
      : `<div class="card"><p>No domains yet — upload your first aggregate report below and the domain appears automatically.</p></div>`}
    <div class="card">
      <strong>Upload aggregate reports</strong>
      <p class="muted">Drop the .xml, .xml.gz or .zip attachments that providers send to your rua= address. Domains are detected automatically.</p>
      <input type="file" id="file" multiple accept=".xml,.gz,.zip">
      <button id="uploadBtn">Upload</button>
      <p id="uploadResult" class="muted"></p>
    </div>
    <div class="card">
      <strong>Automated ingestion (API)</strong>
      <p class="muted">POST raw report files to your private ingest URL — e.g. from a mail rule or script:</p>
      <p><code>curl --data-binary @report.xml.gz ${esc(ingestUrl)}</code></p>
      <p class="muted">A hosted rua= mailbox (reports flow in with zero setup) is coming next — for now, uploads and the API are the ingestion paths.</p>
    </div>
    <p><a href="/app/alerts">View alerts →</a></p>
    <script>
      document.getElementById('uploadBtn').onclick = async () => {
        const files = document.getElementById('file').files;
        const out = document.getElementById('uploadResult');
        if (!files.length) { out.textContent = 'Pick at least one file.'; return; }
        const lines = [];
        for (const f of files) {
          const resp = await fetch('/app/upload', { method: 'POST', body: await f.arrayBuffer() });
          const j = await resp.json();
          lines.push(resp.ok
            ? (j.duplicate ? f.name + ': duplicate, skipped' : f.name + ': ' + j.records + ' records for ' + j.domain + (j.newFailingSources.length ? ' — NEW FAILING: ' + j.newFailingSources.join(', ') : ''))
            : f.name + ': ' + j.error);
        }
        out.textContent = lines.join(' | ');
        setTimeout(() => location.reload(), 1500);
      };
    </script>
  `, req);
});

app.get('/app/domain/:id', requireLogin, (req, res) => {
  const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!domain) return res.status(404).send('not found');

  const sources = db
    .prepare(
      `SELECT ip, SUM(count) AS msgs,
         SUM(CASE WHEN dkim_aligned = 'pass' OR spf_aligned = 'pass' THEN count ELSE 0 END) AS pass_msgs,
         MAX(disposition) AS disposition,
         GROUP_CONCAT(DISTINCT header_from) AS header_froms
       FROM sources WHERE domain_id = ? GROUP BY ip ORDER BY msgs DESC`
    )
    .all(domain.id);

  const latest = db.prepare('SELECT policy_json FROM reports WHERE domain_id = ? ORDER BY date_end DESC LIMIT 1').get(domain.id);
  const policy = latest ? JSON.parse(latest.policy_json) : null;

  const rows = sources.map((s) => {
    const ok = s.pass_msgs === s.msgs;
    const none = s.pass_msgs === 0;
    const cls = ok ? 'pass' : none ? 'fail' : 'warn';
    return `<tr><td><code>${esc(s.ip)}</code></td><td>${s.msgs}</td>
      <td class="${cls}">${ok ? 'passing' : none ? 'failing' : `${s.msgs - s.pass_msgs}/${s.msgs} failing`}</td>
      <td>${esc(s.disposition || '')}</td><td class="muted">${esc(s.header_froms || '')}</td></tr>`;
  }).join('');

  page(res, domain.name, `
    <h1>${esc(domain.name)}</h1>
    ${policy ? `<p class="sub">Published policy: <code>p=${esc(policy.p)}</code> · alignment dkim=${esc(policy.adkim)} spf=${esc(policy.aspf)} · pct=${policy.pct}</p>` : ''}
    <div class="card">
      <strong>Sending sources</strong>
      ${sources.length ? `<table><tr><th>Source IP</th><th>Messages</th><th>DMARC</th><th>Disposition</th><th>Header from</th></tr>${rows}</table>` : '<p class="muted">No data yet.</p>'}
    </div>
    <p><a href="/app">← All domains</a></p>
  `, req);
});

app.get('/app/alerts', requireLogin, (req, res) => {
  const alerts = db
    .prepare(
      `SELECT a.*, d.name AS domain FROM alerts a JOIN domains d ON d.id = a.domain_id
       WHERE d.user_id = ? ORDER BY a.created_at DESC LIMIT 200`
    )
    .all(req.user.id);
  db.prepare('UPDATE alerts SET seen = 1 WHERE domain_id IN (SELECT id FROM domains WHERE user_id = ?)').run(req.user.id);
  page(res, 'Alerts', `
    <h1>Alerts</h1>
    <div class="card">${alerts.length
      ? `<table><tr><th>When (UTC)</th><th>Domain</th><th>Alert</th></tr>${alerts
          .map((a) => `<tr><td class="muted">${esc(a.created_at)}</td><td>${esc(a.domain)}</td><td>${esc(a.message)}</td></tr>`).join('')}</table>`
      : '<p class="muted">No alerts yet. You will see one here when a new failing source appears for any of your domains.</p>'}</div>
    <p class="muted">Email delivery of alerts ships once outbound email is configured; alerts are recorded here from day one.</p>
    <p><a href="/app">← All domains</a></p>
  `, req);
});

// ---------- Founder metrics (honest counters, no vanity) ----------

app.get('/admin/metrics', requireLogin, (req, res) => {
  if (!process.env.ADMIN_EMAIL || req.user.email !== process.env.ADMIN_EMAIL.toLowerCase()) {
    return res.status(403).send('forbidden');
  }
  const count = (name) => db.prepare('SELECT COUNT(*) AS n FROM events WHERE name = ?').get(name).n;
  const users = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  const activated = db.prepare('SELECT COUNT(DISTINCT user_id) AS n FROM domains WHERE first_report_at IS NOT NULL').get().n;
  page(res, 'Metrics', `
    <h1>Metrics</h1>
    <div class="card"><table>
      <tr><th>Metric</th><th>Value</th></tr>
      <tr><td>Signups (accounts)</td><td>${users}</td></tr>
      <tr><td>Activated (≥1 report ingested)</td><td>${activated}</td></tr>
      <tr><td>Reports ingested</td><td>${count('report_ingested')}</td></tr>
      <tr><td>Checker runs</td><td>${count('checker_used')}</td></tr>
      <tr><td>Revenue</td><td>$0 — billing not built yet (ZEV-4)</td></tr>
    </table></div>
  `, req);
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

module.exports = { app };
