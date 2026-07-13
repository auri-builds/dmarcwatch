'use strict';
// Parser for DMARC aggregate reports (RFC 7489 Appendix C feedback XML).
const { XMLParser } = require('fast-xml-parser');
const zlib = require('node:zlib');
const AdmZip = require('adm-zip');

const xmlParser = new XMLParser({
  ignoreAttributes: true,
  parseTagValue: false,
  trimValues: true,
});

function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

// Providers send reports as raw XML, .xml.gz, or .zip. Detect by magic bytes.
function extractXml(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    return zlib.gunzipSync(buf).toString('utf8');
  }
  if (buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4b) {
    const zip = new AdmZip(buf);
    const entry = zip.getEntries().find((e) => e.entryName.toLowerCase().endsWith('.xml'));
    if (!entry) throw new Error('zip archive contains no .xml entry');
    return entry.getData().toString('utf8');
  }
  return buf.toString('utf8');
}

function parseAggregateReport(input) {
  const xml = Buffer.isBuffer(input) ? extractXml(input) : input;
  const doc = xmlParser.parse(xml);
  const fb = doc.feedback;
  if (!fb) throw new Error('not a DMARC aggregate report: missing <feedback> root');

  const meta = fb.report_metadata || {};
  const range = meta.date_range || {};
  const pol = fb.policy_published || {};
  if (!pol.domain) throw new Error('missing <policy_published><domain>');

  const records = asArray(fb.record).map((r) => {
    const row = r.row || {};
    const evaluated = row.policy_evaluated || {};
    const ids = r.identifiers || {};
    const auth = r.auth_results || {};
    return {
      ip: String(row.source_ip || ''),
      count: parseInt(row.count, 10) || 0,
      disposition: String(evaluated.disposition || 'none'),
      // policy_evaluated dkim/spf are the ALIGNED results — the DMARC verdict inputs.
      dkimAligned: String(evaluated.dkim || 'fail'),
      spfAligned: String(evaluated.spf || 'fail'),
      headerFrom: String(ids.header_from || ''),
      envelopeFrom: String(ids.envelope_from || ''),
      auth: {
        dkim: asArray(auth.dkim).map((d) => ({
          domain: String(d.domain || ''),
          result: String(d.result || ''),
          selector: d.selector ? String(d.selector) : undefined,
        })),
        spf: asArray(auth.spf).map((s) => ({
          domain: String(s.domain || ''),
          result: String(s.result || ''),
        })),
      },
    };
  });

  return {
    orgName: String(meta.org_name || 'unknown'),
    email: meta.email ? String(meta.email) : undefined,
    externalId: String(meta.report_id || ''),
    dateBegin: parseInt(range.begin, 10) || null,
    dateEnd: parseInt(range.end, 10) || null,
    policy: {
      domain: String(pol.domain).toLowerCase(),
      adkim: String(pol.adkim || 'r'),
      aspf: String(pol.aspf || 'r'),
      p: String(pol.p || 'none'),
      sp: pol.sp ? String(pol.sp) : undefined,
      pct: pol.pct !== undefined ? parseInt(pol.pct, 10) : 100,
    },
    records,
  };
}

// A source fails DMARC when neither aligned DKIM nor aligned SPF passes.
function isDmarcFail(record) {
  return record.dkimAligned !== 'pass' && record.spfAligned !== 'pass';
}

module.exports = { parseAggregateReport, extractXml, isDmarcFail };
