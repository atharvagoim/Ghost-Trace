# GhostTrace

**AI-powered digital identity leak and credential exposure detection.**

GhostTrace scans GitHub users, organizations and repositories (including commit history), pasted text and uploaded
projects for exposed passwords, API keys, tokens, private keys and database credentials. A trained machine-learning
model scores how likely each hit is to be a real secret and how much damage it could do, so real leaks rise to the top
and test keys and placeholders sink. Email addresses can be checked against public breach databases, targets can be
monitored continuously, and new high-risk leaks trigger email alerts.

Team: Tanmay Dabholkar, Shirshak Dange, Aayush Doke, Atharva Goim.

## Features

| Area | What it does |
| --- | --- |
| Detection | 49 rules: AWS, GCP, Azure, GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, Twilio, SendGrid, JWT, SSH/PEM keys, database URLs, hard-coded passwords, generic keys, emails and more, plus Shannon-entropy filtering |
| Sources | GitHub API (users, orgs, repos, last N commits per repo), pasted text, file and `.zip` uploads |
| AI risk scoring | Gradient-boosted classifier (scikit-learn) on 24 features: entropy, length, character mix, placeholder patterns, test/docs paths, sensitive files, history-only, rule type. Outputs confidence, a 0–100 risk score, severity and human-readable reasons |
| Breach intel | Email lookups via [XposedOrNot](https://xposedornot.com) (free) or Have I Been Pwned (with an API key); password checks via Pwned Passwords k-anonymity, so the password never leaves the server |
| Monitoring | Scheduled re-scans of GitHub targets and emails, alerting only on credentials or breaches not seen before |
| Alerts | HTML email alerts over any SMTP provider, with a per-user severity threshold |
| Dashboard | KPIs, exposure trend, severity and category breakdowns, risk distribution, most exposed repos, exposure timeline |
| Triage | Search by org/user/repo/file, filter by severity and type, mark rotated or false positive (applies to every copy of the secret) |
| Reports | PDF summary and per-scan reports, CSV export |
| Noise control | Skips code expressions (`os.getenv(...)`, variable names, f-strings), vendored libraries (anything beside a `*.dist-info` folder), licence/author files, and any line marked `ghosttrace:ignore` or `gitleaks:allow`; test and docs paths score lower |
| Privacy | Raw secrets are never stored; only a masked preview and a SHA-256 fingerprint |

## Stack

React 19 + Vite + Tailwind CSS + Motion + Chart.js · FastAPI · MongoDB (pymongo) · scikit-learn · ReportLab · Vercel.

Everything lives in one folder:

```
app/           FastAPI backend (Python)
  detection/     49 detectors + entropy, masking, diff scanning
  ml/            AI risk model (model.joblib is prebuilt and committed)
  intel/         breach lookups (XposedOrNot / HIBP / Pwned Passwords)
  sources/       GitHub API client
  services/      scanner, alerts, monitoring, PDF reports
  routers/       REST API under /api
  db.py          MongoDB access
src/           React frontend
scripts/       setup.mjs (one-command setup) and py.mjs (runs .venv Python)
tests/         pytest suite (runs on an in-memory MongoDB, no server needed)
static/        built frontend (created by npm run build, served by the API)
```

## Run it locally

You need **Python 3.11+** and **Node 20+**. Then, in this folder (PowerShell, Terminal, anything):

```bash
npm run setup     # one time: Python env, all packages, and a .env with a generated SECRET_KEY
npm run dev       # API on :8000 + UI on http://localhost:5173
npm test          # run the tests
```

No virtual-environment activation needed: every command uses `.venv` automatically. If anything goes wrong
(an interrupted install, a broken `.venv`), just run `npm run setup` again; it repairs itself and never touches your `.env`.

By default the app uses an in-memory database that is wiped on restart. To keep data, create a free
[MongoDB Atlas](https://www.mongodb.com/atlas) cluster and paste its connection string into `.env`:

```
MONGODB_URI=mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/
```

Add `GITHUB_TOKEN` there too (classic token, no scopes ticked) so GitHub allows more than 60 requests an hour.

`npm run check` runs lint + tests + the production build, same as CI. To test against a real MongoDB:
`TEST_MONGODB_URI=mongodb://localhost:27017 npm test`.

## Deploy to Vercel

1. Push this folder to GitHub, then import the repo at [vercel.com/new](https://vercel.com/new). No build settings to change:
   `vercel.json` already sets the framework (FastAPI), the build (`npm run build`) and a daily monitoring job.
2. **Database:** in MongoDB Atlas, create a free cluster, add a database user, and under **Network Access** allow
   `0.0.0.0/0` (Vercel has no fixed IP addresses). Copy the connection string. (Or add the *MongoDB Atlas* integration
   from the Vercel Marketplace, which creates the cluster and sets `MONGODB_URI` for you.)
3. **Environment variables** (Vercel → Settings → Environment Variables):

   | Variable | |
   | --- | --- |
   | `MONGODB_URI` | **Required.** Your Atlas connection string. |
   | `SECRET_KEY` | **Required.** `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
   | `GITHUB_TOKEN` | Strongly recommended (60 → 5,000 GitHub requests an hour). Classic token, no scopes. |
   | `CRON_SECRET` | Any long random string; turns on the daily monitoring job. |
   | `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | For email alerts. Gmail: `smtp.gmail.com` + an [app password](https://myaccount.google.com/apppasswords). |

4. Redeploy, then open `https://<your-app>.vercel.app/api/health`. It should say `"database": "connected"`.

The app refuses to start on Vercel without `MONGODB_URI` and `SECRET_KEY`, so a missing setting shows up straight away
instead of as lost data or forgeable logins.

### What changes on Vercel

These switch on automatically when Vercel runs the app:

| | Local | Vercel |
| --- | --- | --- |
| GitHub scans | Background thread | Run inside the browser's request to `/api/scans/{id}/run` (Vercel can freeze a function once it has responded) |
| Scan time limit | None | Stops after 4 minutes and keeps what it found (Hobby functions max out at 5) |
| Monitoring | Every hour | Once a day, through Vercel Cron calling `/api/cron/monitors` |
| Uploads | 20 MB | 4 MB (Vercel's request limit is 4.5 MB) |

Any of them can be overridden with an environment variable of the same name, e.g. `SCAN_TIME_BUDGET_SECONDS`.
