'use strict';
// Realistic Google-style aggregate report fixture.
const SAMPLE_XML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890123456789</report_id>
    <date_range><begin>1752278400</begin><end>1752364799</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>quarantine</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>42</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from><envelope_from>example.com</envelope_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result><selector>google</selector></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.99</source_ip>
      <count>7</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from><envelope_from>spoofer.example.net</envelope_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>fail</result></dkim>
      <spf><domain>spoofer.example.net</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>`;

// Same domain, different report id, one previously-unseen failing IP.
const FOLLOWUP_XML = SAMPLE_XML
  .replace('1234567890123456789', '9876543210987654321')
  .replace(/203\.0\.113\.99/g, '198.51.100.7');

const SINGLE_RECORD_XML = `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Yahoo</org_name>
    <report_id>yr-1</report_id>
    <date_range><begin>1752278400</begin><end>1752364799</end></date_range>
  </report_metadata>
  <policy_published><domain>solo.example.org</domain><p>none</p></policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>solo.example.org</header_from></identifiers>
    <auth_results><spf><domain>solo.example.org</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>`;

module.exports = { SAMPLE_XML, FOLLOWUP_XML, SINGLE_RECORD_XML };
