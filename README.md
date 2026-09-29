# UNICC Cyber AI — Investigator Application (Team 4)

A private, internally-deployed web application that helps security investigators analyse
cybersecurity reports: it extracts indicators (CVEs, IPs, domains, hashes), checks them
against historical threats, and asks an AI model (Google Gemini or an on-premise Ollama
model) for an evidence-based summary — while a **human investigator makes the final decision**.

Part of the **UNICC × IIT Gandhinagar AI & Cybersecurity Capstone (Aug–Nov 2026)**.
This repository is **Team 4 — Application, Security & Deployment**: the backend API,
investigator dashboard, login and roles, audit logging, and deployment.

> **Status (end of September 2026):** the application, security and audit layers work and
> are covered by automatic tests. Three parts are **stand-ins until the other teams' modules
> are connected** — see [Integration with Teams 1–3](#integration-with-teams-13).
> Docker packaging is not done yet.

---

## Quick start (Windows, PowerShell)

You need **Python 3.11 or newer** and **Git**. Takes about 5 minutes.

```powershell
# 1. Download the code and go into the folder
git clone https://github.com/avnsganesh/unicc-cyber-ai.git
cd unicc-cyber-ai

# 2. Create a private "toolbox" for this project's packages, and open it
python -m venv .venv
.\.venv\Scripts\Activate.ps1
#    If you see "running scripts is disabled", run this, then the line above again:
#    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Install the packages (exact tested versions)
pip install -r requirements-dev.txt

# 4. Create your settings file from the example, and give it a secret key
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
#    Open .env in Notepad and paste the printed text after  JWT_SECRET=
#    Add GEMINI_API_KEY=... if you have a Gemini key (needed for AI summaries).

# 5. Start the app
uvicorn backend.api.main:app --reload
```

Open **http://127.0.0.1:8000** in your browser.

**First start:** the app creates three accounts with **random passwords** and prints them
**once** in the PowerShell window (`admin_user`, `investigator_1`, `auditor_1`). Save them
somewhere safe — never in chat or in the code. Stop the app with **Ctrl + C**.

Every new PowerShell window needs `cd` into the folder and step 2's `Activate.ps1` line again.

---

## Using the dashboard

Each role sees only the tabs it may use (the server enforces the same rules):

| Role | Can do | Tabs |
|---|---|---|
| **investigator** | Analyse reports, request summaries, record decisions | Investigate |
| **auditor** | Read the audit log | Audit Logs |
| **admin** | Everything above, plus switch the AI backend | Investigate, Audit Logs, System Config |

**Investigation workflow** (Investigate tab):
1. **Ingest report** — paste the report text (up to 200,000 characters), **or** click *Upload file* and
   choose a `.txt`, `.pdf` or `.docx` file (up to 20 MB). The file's text appears in the box, where you can
   check or edit it → *Analyze & Extract Entities*.
2. **Threat matching** — *Run Threat Matching* (currently says "not connected yet"; see below).
3. **Synthesis & decision** — *Synthesize Summary*, then choose **escalate / monitor / dismiss**,
   add notes, *Submit Decision*. The decision and notes are recorded in the audit log.

Practice text: `Host 10.14.6.23 beaconed to 185.220.101[.]47 and secure-update-cdn[.]net, exploiting CVE-2023-23397.`

**Switching the AI model** (admin → System Config): Gemini (API) or Ollama (on-premise).
The investigator workflow stays exactly the same.

---

## Managing users

Run these from the project folder with the toolbox active (the app can be running):

```powershell
python -m backend.manage_users list                            # show all accounts and roles
python -m backend.manage_users add <username> <role>           # role: investigator, auditor or admin
python -m backend.manage_users reset-password <username>       # also logs that user out everywhere
```

Passwords must be 12–72 characters. Nothing appears on screen while you type them — that is
intentional. Passwords are stored only as bcrypt hashes.

---

## Settings

All settings live in a file named **`.env`** (copied from **`.env.example`**, which explains
each one). `.env` is in `.gitignore`, so keys and secrets are never uploaded. Real environment
variables take priority over the file.

| Setting | Default | What it does |
|---|---|---|
| `JWT_SECRET` | random at each start | Signs login passes. **Set it** — otherwise everyone is logged out on every restart. |
| `SESSION_MINUTES` | `60` | How long a login lasts |
| `COOKIE_SECURE` | `false` | Set `true` on any real deployment (HTTPS only) |
| `ALLOWED_ORIGINS` | *(empty)* | Other websites allowed to call the API. Leave empty. |
| `LOGIN_MAX_FAILURES_PER_USER` | `5` | Wrong passwords before an account is blocked |
| `LOGIN_MAX_FAILURES_PER_IP` | `20` | Per computer address; `0` = off (see [Deployment](#deployment-notes)) |
| `LOGIN_BLOCK_MINUTES` | `15` | Length of the block |
| `DEFAULT_LLM_BACKEND` | `gemini` | AI backend on the very first start (`gemini` or `ollama`) |
| `GEMINI_API_KEY` | *(empty)* | Needed for Gemini summaries |
| `GEMINI_MODEL` | `gemini-3.6-flash` | Check current names: <https://ai.google.dev/gemini-api/docs/models> |
| `OLLAMA_HOST` | `http://localhost:11434` | Address of the Ollama server |
| `OLLAMA_MODEL` | `tinyllama` | Must be pulled first: `ollama pull <model>` |
| `DATABASE_URL` | `backend/app.db` | Where the database is stored |

When the app starts it prints a warning for settings that are fine for local testing but not
for real use (for example `COOKIE_SECURE` off, or no Gemini key).

---

## Running the tests

```powershell
pytest -q
```

All tests should pass. They use a temporary in-memory database and a stand-in for the AI model,
so they need no internet, no API key and no Ollama, and they ignore your personal `.env` file.

| File | Covers |
|---|---|
| `test_api.py` | Login, roles, sessions and logout, password rules, guessing limit, audit log, input limits, safe error messages, no fake AI output, browser security headers, report file upload and request-size limits |
| `test_ioc_extractor.py` | Indicator extraction: finds only what is in the text, ignores look-alikes |
| `test_file_extractor.py` | Reading uploaded files: text from .txt/.pdf/.docx, refusing wrong, damaged, password-locked or oversized files and zip bombs |
| `test_settings.py` | Loading settings from `.env`, AI model settings, disabling the per-address limit |

---

## Project structure

```
backend/
  api/main.py            All web endpoints, security middleware, error handling
  auth/auth_service.py   Login passes (JWT) and role checks
  auth/passwords.py      Password hashing (bcrypt)
  auth/sessions.py       Logout and "log out everywhere" after a password reset
  auth/login_limiter.py  Password-guessing limit
  audit/audit_service.py Audit log (append-only, secrets removed)
  ingest/file_extractor.py Reads the text out of an uploaded .txt, .pdf or .docx report
  config.py              Reads settings from .env / environment variables
  database.py, models.py Database connection and tables
  manage_users.py        Command-line user management
frontend/                Investigator dashboard (index.html, app.js, style.css)
llm/gateway/
  interface.py           The contract every AI backend follows (drafted by Team 4 for Team 3)
  adapters.py            Gemini and Ollama backends
  ioc_extractor.py       Stand-in indicator extractor (patterns, no AI)
docs/                    Earlier project notes
.env.example             All settings, explained
requirements.txt         App packages (pinned); requirements-dev.txt adds test tools
```

**API** (all under `/api/v1`; interactive reference at `http://127.0.0.1:8000/docs` while the app runs):

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` | anyone / logged in | Sessions |
| `POST /investigation/upload` | investigator, admin | Read the text of an uploaded report file |
| `POST /investigation/analyze` | investigator, admin | Start an investigation (returns an ID) |
| `POST /investigation/entities` | investigator, admin | Extract indicators from report text |
| `POST /investigation/threats` | investigator, admin | Historical threat matching (not connected yet) |
| `POST /llm/summarize` | investigator, admin | AI summary of the evidence |
| `POST /investigation/decision` | investigator, admin | Record the human decision |
| `GET /admin/audit-logs` | auditor, admin | Latest 100 audit entries |
| `GET`/`POST /admin/config` | admin | Read / switch the AI backend |

---

## Security features

- **No secrets in the code:** signing key and passwords come from settings or are random; old published values are refused.
- **Login protection:** bcrypt passwords (12–72 characters), guessing limit per account and per address, real logout, password reset ends all of that user's sessions, httpOnly cookies.
- **Roles enforced on the server** for every endpoint; each role sees only its own tabs.
- **Audit log:** logins, failed and blocked logins, logouts, investigation steps, decisions, admin changes and audit-log views — with UTC timestamps shown in local time, never passwords or keys.
- **Input rules:** size limits (2 MB per request, 20 MB per uploaded file, 200,000-character reports) — also
  for requests that don't announce their size; allowed values only, simple IDs.
- **Uploaded files:** only `.txt`, `.pdf` and `.docx`, checked against their contents (a renamed program is
  refused). Only the text is read — nothing in a file is ever run — and the file is not kept. Protected
  against "zip bombs" and oversized PDFs. Unreadable files (damaged, password-locked, scanned images, unknown
  text encodings) are refused with a clear reason, never turned into guessed text. The audit log records the
  file's name and fingerprint (SHA-256), which links it to the investigation that used its text.
- **Output safety:** report and AI text is always shown as plain text (no XSS); errors show a reference code, never internal details (admins see details; full text goes to the server and audit logs).
- **Browser rules:** other websites cannot call the API (CORS closed); dashboard files re-checked after updates; investigation data never cached; no files loaded from the internet.
- **No invented output:** if the AI or a module is unavailable, the app says so instead of showing made-up results.

---

## Integration with Teams 1–3

| Part | Now | Owner | To connect |
|---|---|---|---|
| Indicator extraction | Pattern-based stand-in (`llm/gateway/ioc_extractor.py`); finds CVEs, IPs, domains, hashes; no threat-actor or malware names | **Team 1** | Replace the `extract_iocs` call in `backend/api/main.py`; the dashboard needs an `iocs` list |
| Historical threat matching | Returns "not connected yet" and no matches | **Team 2** | Implement in `POST /investigation/threats`; the dashboard will need match categories, confidence and evidence |
| AI gateway, prompts, summaries | Draft Gemini/Ollama adapters (`llm/gateway/`) | **Team 3** | Keep the `LLMInterface` methods, or adapt in `get_llm_gateway` |

**Rule for every module:** if something fails, raise an error — **never return placeholder or
made-up results**. The tests check this.

---

## Deployment notes

- Serve over **HTTPS** and set `COOKIE_SECURE=true`; always set a fixed `JWT_SECRET`.
- Put `DATABASE_URL` in a folder that is **backed up** and survives rebuilds.
- **Behind a proxy or Docker**, all users can appear to come from one address, so the
  per-address guessing limit could block everyone. Run uvicorn with
  `--proxy-headers --forwarded-allow-ips=<proxy address>`, or set `LOGIN_MAX_FAILURES_PER_IP=0`.
- The guessing-limit counts are kept in memory: they reset on restart and aren't shared
  between several server processes.

## Known limitations / next steps

- Docker packaging and on-premise / API deployment configurations are not done yet.
- Uploads read the text of `.txt`, `.pdf` and `.docx` only: no scanned PDFs or images (that would need text
  recognition, OCR), no old `.doc` files, and text inside Word text boxes, headers and footers is skipped.
- No "newly observed threat" query box; no evidence/source display (needs Team 2).
- Audit log page shows the latest 100 entries (no search or export) and is not tamper-proof yet.
- No prompt-injection defence yet (to be done with Team 3), and no "pause the AI" switch.
- A real AI summary has not been verified end-to-end in this app yet (needs a Gemini key or Ollama).
