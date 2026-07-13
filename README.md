# DMARCwatch

DMARC monitoring & alerting for agencies, MSPs and small businesses. Turns the unreadable XML aggregate reports mailbox providers send into a per-domain dashboard and alerts when a new failing source (misconfigured sender or spoofer) appears.

## What's here (MVP)

- **Public landing page** and **free SPF/DKIM/DMARC checker** (`/checker`) — the lead magnet. DNS lookups with a DNS-over-HTTPS fallback for resolvers that choke on large TXT responses.
- **Accounts** — email + password (scrypt), session cookies.
- **Report ingestion** — two paths, both accepting raw XML, `.xml.gz`, or `.zip` (the three formats providers actually send):
  - Manual multi-file upload from the dashboard.
  - Private API endpoint per account: `POST /ingest/<token>` with the raw file as the body — pointable from a mail rule or script. Domains are auto-created from the report's `policy_published` domain, so an MSP can route every client's reports at one token.
- **Per-domain dashboard** — sending sources aggregated by IP: message volume, DMARC pass/fail, disposition, header-from. Published policy summary. Duplicate reports (same org + report id) are deduped.
- **Alerts** — a new failing source for a domain (an IP failing both aligned DKIM and aligned SPF that was never seen failing before) creates an alert, shown in-app.
- **Honest metrics** — `/admin/metrics` (gated by `ADMIN_EMAIL`): signups, activated accounts (≥1 report ingested), reports ingested, checker runs. Revenue reads $0 until billing exists.

## What's deliberately cut (and why)

- **Hosted `rua=` mailbox** (reports flow in automatically once the customer edits DNS) — requires a domain we own plus inbound email routing. This is the top post-MVP item; until then ingestion is upload/API. Cut because it needs a (cheap, but paid) domain purchase — pending CEO approval.
- **Email delivery of alerts** — needs outbound SMTP credentials; alerts are recorded in-app from day one and the send hook is a stub.
- **Billing/Stripe** — scoped to the launch-readiness task (ZEV-4).
- **Forensic (RUF) reports, PDF/white-label reports, DNS-change watching** — post-revenue features.

## Run

```bash
npm install
npm start          # listens on :3000 (PORT to override)
npm test           # parser, checker, end-to-end HTTP tests
```

Environment: `PORT`, `DATA_DIR` or `DB_PATH` (SQLite location, defaults to `./data/dmarcwatch.db`), `ADMIN_EMAIL` (unlocks `/admin/metrics` for that account).

Stack: Node ≥22.5 (uses built-in `node:sqlite`), Express, fast-xml-parser, adm-zip. No build step, no ORM, server-rendered HTML.

## Deploy

Any Node host with a persistent disk for the SQLite file works:

```bash
PORT=8080 DATA_DIR=/var/data ADMIN_EMAIL=founder@example.com node src/index.js
```

If the host has no persistent disk, point `DB_PATH` at a mounted volume or swap the storage layer to a managed Postgres — the SQL is deliberately vanilla.

`docs/` is a static marketing page + client-side checker (DNS-over-HTTPS in the browser) suitable for GitHub Pages, so the lead magnet can be live before the app host exists.

## Testing a report by hand

```bash
curl --data-binary @google.com!example.com!1752278400!1752364799.xml.gz \
  http://localhost:3000/ingest/<your-token-from-the-dashboard>
```
