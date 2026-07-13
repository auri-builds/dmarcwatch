'use strict';
// Free SPF/DKIM/DMARC record checker — the marketing lead magnet.
const dns = require('node:dns/promises');

const COMMON_DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 's1', 's2', 'mail', 'default', 'dkim', 'mandrill', 'pm', 'zoho'];

function validDomain(domain) {
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain);
}

// Google's DoH JSON API — fallback for resolvers that break on large TXT
// responses (UDP truncation → TCP retry refused).
async function dohQuery(name, type) {
  const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) return [];
  const json = await res.json();
  return (json.Answer || []).map((a) => String(a.data).replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
}

async function txtRecords(name) {
  try {
    const rows = await dns.resolveTxt(name);
    return rows.map((chunks) => chunks.join(''));
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return [];
    try {
      return await dohQuery(name, 'TXT');
    } catch {
      return [];
    }
  }
}

function analyzeDmarc(records) {
  const dmarc = records.filter((r) => r.trim().toLowerCase().startsWith('v=dmarc1'));
  if (dmarc.length === 0) {
    return { status: 'fail', record: null, notes: ['No DMARC record found. Gmail, Yahoo and Outlook now reject or junk bulk mail from domains without DMARC.'] };
  }
  const notes = [];
  let status = 'pass';
  if (dmarc.length > 1) { status = 'fail'; notes.push('Multiple DMARC records found — receivers treat this as no record at all. Remove the extras.'); }
  const record = dmarc[0];
  const tags = Object.fromEntries(record.split(';').map((part) => {
    const [k, ...v] = part.trim().split('=');
    return [k.trim().toLowerCase(), v.join('=').trim()];
  }).filter(([k]) => k));

  const p = (tags.p || '').toLowerCase();
  if (!p) { status = 'fail'; notes.push('Missing required p= tag.'); }
  else if (p === 'none') { if (status === 'pass') status = 'warn'; notes.push('Policy is p=none: you are monitoring only — spoofed mail is still delivered. Move to quarantine/reject once your legitimate sources pass.'); }
  else notes.push(`Enforcement policy active (p=${p}).`);

  if (!tags.rua) { if (status === 'pass') status = 'warn'; notes.push('No rua= tag: nobody is receiving aggregate reports, so you are blind to failures and spoofing.'); }
  else notes.push(`Aggregate reports go to ${tags.rua.replace(/^mailto:/i, '')}.`);

  if (tags.pct && parseInt(tags.pct, 10) < 100) { if (status === 'pass') status = 'warn'; notes.push(`Policy only applies to ${tags.pct}% of mail (pct=${tags.pct}).`); }
  return { status, record, notes };
}

function analyzeSpf(records) {
  const spf = records.filter((r) => r.trim().toLowerCase().startsWith('v=spf1'));
  if (spf.length === 0) {
    return { status: 'fail', record: null, notes: ['No SPF record found. Add one — mailbox providers require it for bulk senders.'] };
  }
  const notes = [];
  let status = 'pass';
  if (spf.length > 1) { status = 'fail'; notes.push('Multiple SPF records found — this is a permanent error (permerror). Merge them into one.'); }
  const record = spf[0];
  if (/[+?]all\s*$/i.test(record)) { status = 'fail'; notes.push('Record ends with +all/?all, which lets anyone send as your domain. Use ~all or -all.'); }
  else if (/~all\s*$/i.test(record)) notes.push('Softfail (~all) terminator — fine, common during rollout.');
  else if (/-all\s*$/i.test(record)) notes.push('Hardfail (-all) terminator — strict, good.');
  else { if (status === 'pass') status = 'warn'; notes.push('No all mechanism at the end — unauthorized senders get a neutral result.'); }
  return { status, record, notes };
}

async function checkDkim(domain, selector) {
  const selectors = selector ? [selector] : COMMON_DKIM_SELECTORS;
  for (const sel of selectors) {
    const name = `${sel}._domainkey.${domain}`;
    const txt = await txtRecords(name);
    const key = txt.find((r) => /v=dkim1|k=rsa|p=/i.test(r));
    if (key) return { status: 'pass', selector: sel, record: key.slice(0, 120) + (key.length > 120 ? '…' : ''), notes: [`DKIM key found at selector "${sel}".`] };
    try {
      const cname = await dns.resolveCname(name);
      if (cname.length) return { status: 'pass', selector: sel, record: `CNAME → ${cname[0]}`, notes: [`DKIM delegated via CNAME at selector "${sel}".`] };
    } catch { /* not a cname; keep trying */ }
  }
  return {
    status: selector ? 'fail' : 'warn',
    selector: selector || null,
    record: null,
    notes: [selector
      ? `No DKIM key found at selector "${selector}".`
      : 'No DKIM key found at common selectors. DKIM selectors are provider-specific — enter yours to check it directly.'],
  };
}

async function checkDomain(rawDomain, dkimSelector) {
  const domain = String(rawDomain).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!validDomain(domain)) throw new Error('invalid domain');
  const [dmarcTxt, spfTxt, dkim] = await Promise.all([
    txtRecords(`_dmarc.${domain}`),
    txtRecords(domain),
    checkDkim(domain, dkimSelector ? String(dkimSelector).trim() : undefined),
  ]);
  return { domain, dmarc: analyzeDmarc(dmarcTxt), spf: analyzeSpf(spfTxt), dkim };
}

module.exports = { checkDomain, analyzeDmarc, analyzeSpf, validDomain };
