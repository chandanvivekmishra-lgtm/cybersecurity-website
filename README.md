# Web Vulnerability Scanner

A Python-based Flask security assessment dashboard for authorized web testing. The app performs bounded, read-only checks and produces a working assessment report with a security dashboard and PDF export.

> Use only against websites you own or have explicit permission to assess. This tool is not a substitute for professional penetration testing.

## Project structure

```text
.
├── app.py
├── config.py
├── database.py
├── scanner.py
├── requirements.txt
├── .env.example
├── .gitignore
├── Dockerfile
├── .dockerignore
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── scanner.html
│   ├── dashboard.html
│   ├── report.html
│   └── error.html
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

## Deploy permanently

The project includes a Render deployment manifest. Push the repository to GitHub, then create a Render Blueprint from `render.yaml`. Render provides automatic restarts, HTTPS, and persistent disk storage.

Configure all secrets in Render before deploying:

- `SECRET_KEY`: a long random value
- `ADMIN_USERNAME`: a unique administrator username
- `ADMIN_PASSWORD`: a strong password
- `DATABASE_PATH`: `/data/scanner.db`

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
