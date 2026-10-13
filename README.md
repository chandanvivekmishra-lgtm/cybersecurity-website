# Web Vulnerability Scanner

A Python-based Flask security assessment dashboard for authorized web testing. The app performs bounded, read-only checks and produces a working assessment report with a security dashboard and PDF export.

> Use only against websites you own or have explicit permission to assess. This tool is not a substitute for professional penetration testing.

## Project structure

```text
.
├── app.py
├── assistant.py
├── config.py
├── database.py
├── reporting.py
├── scanner.py
├── requirements.txt
├── .env.example
├── static/
│   ├── css/style.css
│   └── js/
├── templates/
│   ├── about_project.html
│   ├── assistant.html
│   ├── base.html
│   ├── dashboard.html
│   ├── report.html
│   └── scanner.html
└── tests/test_app.py
```

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run locally

```powershell
python app.py
```

Open http://127.0.0.1:5000.

## Run continuously on Windows

The project includes a detached Waitress launcher that stays running after the terminal closes:

```powershell
.\start-server.ps1
```

Stop the server with:

```powershell
Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -match 'waitress-serve\.exe.*app:app' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

## Deploy publicly on Render Free

The project includes a Render Blueprint in `render.yaml` configured for the Free web-service plan. Push the repository to GitHub, then in Render choose **New + → Blueprint** and connect this repository. Render builds the Dockerfile and assigns a public HTTPS URL. The container listens on Render's injected `PORT` value (and defaults to port 5000 for local Docker runs).

During Blueprint setup, provide these environment variables when Render prompts for them:

- `ADMIN_USERNAME`: a unique administrator username
- `ADMIN_PASSWORD`: a strong password

Render generates `SECRET_KEY` automatically. Debug mode is disabled. Admin login is disabled unless both admin variables are configured.

Render Free web services can sleep after 15 minutes without inbound traffic; the first visit after sleeping may take a while while the service starts again. The Free plan does not provide persistent disks. This deployment stores SQLite data under `/tmp/scanner.db`, so scan history, registered accounts, and other local database data can be lost when the service restarts or redeploys. The contact form messages are held in process memory and are also temporary. No database or hosting service requiring payment is configured.

This repository is a **web vulnerability scanner**, not a network intrusion detection system (NIDS). Its scanner makes bounded HTTP/HTTPS requests and checks web responses. It does not capture packets or monitor network interfaces; Render's web-service environment is not being used or verified for packet-capture NIDS functionality.

The application is also ready for Docker:

```powershell
docker build -t web-vulnerability-scanner .
docker run --rm -p 5000:5000 -v scanner-data:/data web-vulnerability-scanner
```

## Run with Docker

```powershell
docker build -t web-vulnerability-scanner .
docker run -p 5000:5000 web-vulnerability-scanner
```

## Test

```powershell
pytest -q
```

## Configuration

Set the values shown in `.env.example` in the process environment before starting the app (or use a dotenv loader in your deployment). Set a unique, random `SECRET_KEY` and configure `ADMIN_USERNAME` and `ADMIN_PASSWORD`; the admin login is disabled if its credentials are not configured. Do not commit your `.env` file. Local, private, and link-local targets are blocked unless `ALLOW_LOCAL_TARGETS=1` is set.

## Assessment reports

The scanner requires users to confirm that they own the submitted site or have explicit permission to assess it. Successful scans are saved in SQLite and a paginated PDF is generated automatically and associated with that scan ID. The report download can safely retry generation if it previously failed; it only accepts an existing numeric scan ID and does not read arbitrary filesystem paths. If PDF generation fails, saved scan findings remain available and the report page explains that the download can be retried.

The score starts at 100 and subtracts 35 points for each high-severity finding, 15 for each medium finding, and 5 for each low finding, to a minimum of 0. Risk levels are low (80–100), medium (60–79), high (40–59), and critical (0–39). This is a project-specific prioritization score, not a compliance rating.

The scanner checks the primary final response's selected security headers, cookies, transport, TLS certificate handshake, CORS values, selected disclosure headers, and bounded response-body patterns. Same-origin links can be discovered to depth 1 and a maximum of 10 pages, but those discovered pages are not independently analyzed. Pattern-based XSS and SQL-text findings are heuristic signals, not proof of exploitable vulnerabilities. The About the Project page describes the implemented scope and limitations in more detail.

## Optional AI Security Assistant

The assistant is optional; scanning, the dashboard, and PDF reporting work without an AI API key. To enable provider-backed explanations, set these server environment variables (Render: **Dashboard → service → Environment**):

- `AI_API_KEY`: secret API key for your chosen compatible provider
- `AI_API_BASE_URL`: provider's OpenAI-compatible API base URL (default `https://api.openai.com/v1`)
- `AI_MODEL`: model identifier accepted by that provider (default `gpt-4o-mini`)

Keep keys in the server environment; never put them in frontend code or commit them. Provider requests include only the current question, a limited recent in-memory conversation, and sanitized metadata/evidence from the selected scan or finding. Raw response bodies, cookies, passwords, and tokens are not intentionally sent. Conversations are not stored by this application. External provider availability, terms, and possible usage charges are separate from hosting; no AI provider is required for the basic scanner.

## Included functionality

- Safe URL validation and authorized-target enforcement
- Bounded request handling with timeout, redirect destination validation, response-size limits, and rate limiting
- Same-origin page discovery with crawl depth and page limits
- Real HTTP/HTTPS transport checks
- Security header validation
- Cookie attribute validation
- TLS certificate checks and CORS review
- Risk scoring, OWASP mapping, and deduplicated findings
- SQLite scan history and dashboard reporting
- PDF export for saved reports

## Security boundary

This scanner intentionally supports only authorized targets and performs read-only checks. It does not implement credential theft, brute-force attacks, or destructive exploitation.
