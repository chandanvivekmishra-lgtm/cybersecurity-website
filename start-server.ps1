$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$waitress = Join-Path $projectRoot ".venv\Scripts\waitress-serve.exe"

if (-not (Test-Path $python)) {
    throw "Virtual environment not found. Run: python -m venv .venv"
}

if (-not (Test-Path $waitress)) {
    & $python -m pip install waitress
}

$logDirectory = Join-Path $projectRoot "logs"
if (-not (Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

$arguments = @(
    "--listen=127.0.0.1:5000",
    "app:app"
)

$existingListener = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
if ($existingListener) {
    Write-Host "Web Vulnerability Scanner is already running on http://127.0.0.1:5000"
    exit 0
}

Start-Process -FilePath $waitress `
    -ArgumentList $arguments `
    -WorkingDirectory $projectRoot `
    -NoNewWindow `
    -PassThru

Write-Host "Web Vulnerability Scanner started at http://127.0.0.1:5000"
