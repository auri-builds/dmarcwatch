'use strict';
// Server-rendered views via template literals — no template engine.

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const CSS = `
  :root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; --pass:#4ade80; --warn:#fbbf24; --fail:#f87171; --border:#334155; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background:var(--bg); color:var(--text); line-height:1.55; }
  a { color: var(--accent); text-decoration: none; }
  .wrap { max-width: 880px; margin: 0 auto; padding: 0 20px 60px; }
  header.site { display:flex; justify-content:space-between; align-items:center; padding:18px 0; margin-bottom:28px; border-bottom:1px solid var(--border); }
  header.site .logo { font-weight:700; font-size:18px; color:var(--text); }
  header.site nav a { margin-left:18px; color:var(--muted); }
  header.site nav a:hover { color:var(--text); }
  h1 { font-size: 30px; margin: 20px 0 8px; }
  .sub { color: var(--muted); margin-bottom: 28px; }
  .card { background: var(--card); border:1px solid var(--border); border-radius:10px; padding:20px 22px; margin-bottom:18px; }
  input, select { background:#0b1220; color:var(--text); border:1px solid var(--border); border-radius:6px; padding:10px 12px; font-size:15px; width:100%; }
  label { display:block; margin:12px 0 6px; color:var(--muted); font-size:14px; }
  button, .btn { background:var(--accent); color:#082f49; font-weight:600; border:none; border-radius:6px; padding:10px 18px; font-size:15px; cursor:pointer; display:inline-block; margin-top:14px; }
  table { width:100%; border-collapse: collapse; font-size:14px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:600; }
  .pass { color:var(--pass); } .warn { color:var(--warn); } .fail { color:var(--fail); }
  .pill { display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:600; }
  .pill.pass { background:rgba(74,222,128,.15); } .pill.warn { background:rgba(251,191,36,.15); } .pill.fail { background:rgba(248,113,113,.15); }
  code { background:#0b1220; padding:2px 6px; border-radius:4px; font-size:13px; word-break:break-all; }
  .flash { background:rgba(248,113,113,.12); border:1px solid var(--fail); color:var(--fail); border-radius:8px; padding:10px 14px; margin-bottom:16px; }
  .flash.ok { background:rgba(74,222,128,.12); border-color:var(--pass); color:var(--pass); }
  .muted { color:var(--muted); font-size:14px; }
  ul { padding-left:20px; } li { margin:4px 0; }
`;

function layout({ title, body, user }) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · DMARCwatch</title>
<style>${CSS}</style>
</head><body><div class="wrap">
<header class="site">
  <a class="logo" href="/">DMARC<span style="color:var(--accent)">watch</span></a>
  <nav>
    <a href="/checker">Free checker</a>
    ${user ? `<a href="/app">Dashboard</a><a href="/logout">Log out</a>` : `<a href="/login">Log in</a><a href="/signup">Sign up</a>`}
  </nav>
</header>
${body}
</div></body></html>`;
}

function flash(msg, ok) {
  return msg ? `<div class="flash${ok ? ' ok' : ''}">${esc(msg)}</div>` : '';
}

function statusPill(s) {
  return `<span class="pill ${esc(s)}">${{ pass: 'PASS', warn: 'WARN', fail: 'FAIL' }[s] || esc(s)}</span>`;
}

module.exports = { esc, layout, flash, statusPill };
