'use strict';
const { db, trackEvent } = require('../db');
const { parseAggregateReport, isDmarcFail } = require('./parser');

// Ingest one report payload (xml/gz/zip buffer) for a user. Auto-creates the
// domain row so an MSP can point every client's RUA at one token and have
// domains appear as reports arrive.
function ingestReport(userId, buffer) {
  const report = parseAggregateReport(buffer);
  const domainName = report.policy.domain;

  db.prepare('INSERT OR IGNORE INTO domains (user_id, name) VALUES (?, ?)').run(userId, domainName);
  const domain = db.prepare('SELECT * FROM domains WHERE user_id = ? AND name = ?').get(userId, domainName);

  const inserted = db
    .prepare(
      `INSERT OR IGNORE INTO reports (domain_id, org_name, external_id, date_begin, date_end, policy_json)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(domain.id, report.orgName, report.externalId, report.dateBegin, report.dateEnd, JSON.stringify(report.policy));

  if (inserted.changes === 0) {
    return { duplicate: true, domain: domainName, records: 0, newFailingSources: [] };
  }
  const reportId = Number(inserted.lastInsertRowid);

  // IPs that have already failed for this domain — used to alert only on NEW failing sources.
  const knownFailing = new Set(
    db
      .prepare(
        `SELECT DISTINCT ip FROM sources
         WHERE domain_id = ? AND dkim_aligned != 'pass' AND spf_aligned != 'pass' AND report_id != ?`
      )
      .all(domain.id, reportId)
      .map((r) => r.ip)
  );

  const insertSource = db.prepare(
    `INSERT INTO sources (report_id, domain_id, ip, count, disposition, dkim_aligned, spf_aligned, header_from, envelope_from, auth_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const newFailing = [];
  for (const rec of report.records) {
    insertSource.run(
      reportId, domain.id, rec.ip, rec.count, rec.disposition,
      rec.dkimAligned, rec.spfAligned, rec.headerFrom, rec.envelopeFrom, JSON.stringify(rec.auth)
    );
    if (isDmarcFail(rec) && rec.ip && !knownFailing.has(rec.ip)) {
      knownFailing.add(rec.ip);
      newFailing.push(rec);
    }
  }

  for (const rec of newFailing) {
    db.prepare('INSERT INTO alerts (domain_id, type, message) VALUES (?, ?, ?)').run(
      domain.id,
      'new_failing_source',
      `New failing source for ${domainName}: ${rec.ip} (${rec.count} messages, disposition: ${rec.disposition}) reported by ${report.orgName}`
    );
  }

  if (!domain.first_report_at) {
    db.prepare("UPDATE domains SET first_report_at = datetime('now') WHERE id = ?").run(domain.id);
    trackEvent('activation_first_report', { userId, domain: domainName });
  }
  trackEvent('report_ingested', { userId, domain: domainName, records: report.records.length });

  return { duplicate: false, domain: domainName, records: report.records.length, newFailingSources: newFailing.map((r) => r.ip) };
}

module.exports = { ingestReport };
