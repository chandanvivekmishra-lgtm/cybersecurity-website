from __future__ import annotations

import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from app import app
from scanner import (
    ScanError,
    ScanPolicy,
    _get_checked_response,
    _read_response_body,
    scan_target,
    validate_target,
)


def test_health_route():
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "service": "web-vulnerability-scanner"}


def test_landing_and_scanner_pages():
    client = app.test_client()
    root_response = client.get("/")
    assert root_response.status_code == 302
    assert root_response.headers["Location"].endswith("/login")

    authenticated_client = app.test_client()
    with authenticated_client.session_transaction() as session:
        session["user_id"] = "test-user"
        session["user_name"] = "Test User"
    assert authenticated_client.get("/").status_code == 200

    assert client.get("/scanner").status_code == 200
    assert client.get("/dashboard").status_code == 200


def test_information_and_policy_pages():
    client = app.test_client()
    routes = [
        "/about",
        "/security-policy",
        "/privacy-policy",
        "/terms-and-conditions",
        "/website-information",
        "/help",
    ]
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200

    about_response = client.get("/about")
    assert b"Chandan Vivekanand Mishra" in about_response.data

    help_response = client.get("/help")
    assert b"chandanvivekmishra@gmail.com" in help_response.data


def test_dashboard_export_endpoints(tmp_path):
    database_path = tmp_path / "scanner.db"
    from database import ScanStore

    store = ScanStore(database_path)
    store.save_scan(
        {
            "target": "https://example.com",
            "final_url": "https://example.com/",
            "status": "completed",
            "score": 82,
            "summary": "No issues found.",
            "response_status": 200,
            "response_size": 1234,
            "severity": "low",
            "risk_level": "low",
            "findings": [],
            "error_message": None,
        }
    )
    original_database_path = app.config["DATABASE_PATH"]
    app.config["DATABASE_PATH"] = str(database_path)
    try:
        csv_response = app.test_client().get("/api/reports/export.csv")
        json_response = app.test_client().get("/api/reports/export.json")
    finally:
        app.config["DATABASE_PATH"] = original_database_path

    assert csv_response.status_code == 200
    assert b"target,score" in csv_response.data.lower()
    assert json_response.status_code == 200
    assert isinstance(json_response.get_json(), list)


def test_contact_form_and_admin_login_flow(monkeypatch):
    test_username = "test-admin"
    import secrets

    test_password = secrets.token_urlsafe(18)
    monkeypatch.setitem(app.config, "ADMIN_USERNAME", test_username)
    monkeypatch.setitem(app.config, "ADMIN_PASSWORD", test_password)
    client = app.test_client()

    contact_response = client.post(
        "/contact",
        data={
            "name": "Test User",
            "email": "test@example.com",
            "subject": "Question",
            "message": "Hello there",
        },
        follow_redirects=True,
    )
    assert contact_response.status_code == 200
    assert b"Thank you" in contact_response.data

    login_response = client.post(
        "/admin/login",
        data={"username": test_username, "password": test_password},
        follow_redirects=True,
    )
    assert login_response.status_code == 200
    assert b"Admin Dashboard" in login_response.data


def test_public_registration_and_login(tmp_path):
    original_database_path = app.config["DATABASE_PATH"]
    app.config["DATABASE_PATH"] = str(tmp_path / "scanner.db")
    client = app.test_client()
    try:
        registration = client.post(
            "/register",
            data={
                "name": "Asha Kumar",
                "email": "asha@example.com",
                "password": "SecurePassword123!",
                "contact": "+91 98765 43210",
            },
            follow_redirects=True,
        )
        assert registration.status_code == 200
        assert b"Welcome, Asha Kumar" in registration.data

        login = client.post(
            "/login",
            data={
                "email": "asha@example.com",
                "password": "SecurePassword123!",
            },
            follow_redirects=True,
        )
        assert login.status_code == 200
        assert b"Dashboard" in login.data
        assert client.get("/account").status_code == 200
    finally:
        app.config["DATABASE_PATH"] = original_database_path


def test_registration_rejects_duplicate_email(tmp_path):
    original_database_path = app.config["DATABASE_PATH"]
    app.config["DATABASE_PATH"] = str(tmp_path / "scanner.db")
    client = app.test_client()
    try:
        payload = {
            "name": "Asha Kumar",
            "email": "asha@example.com",
            "password": "SecurePassword123!",
            "contact": "+91 98765 43210",
        }
        first_registration = client.post("/register", data=payload)
        assert first_registration.status_code == 302
        response = client.post("/register", data=payload)
        assert response.status_code == 409
        assert b"already registered" in response.data.lower()
    finally:
        app.config["DATABASE_PATH"] = original_database_path


def test_advanced_scan_heuristics_and_policy_pages(monkeypatch):
    client = app.test_client()

    for route in ["/faq", "/report-abuse", "/admin/users"]:
        response = client.get(route)
        assert response.status_code == 200

    class LocalServerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = "<html><body><script>alert('x')</script><h1>Index of /</h1>SELECT * FROM users WHERE id = 1</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))

        def log_message(self, _format, *_args):
            del _format, _args
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalServerHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr("config.Config.ALLOW_LOCAL_TARGETS", True)
        result = scan_target(target)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    finding_codes = {finding["code"] for finding in result["findings"]}
    assert "potential_xss" in finding_codes
    assert "potential_sql_injection" in finding_codes
    assert "directory_listing_exposed" in finding_codes


def test_scan_requires_a_target():
    client = app.test_client()
    response = client.post("/api/scan", data={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "A target URL is required."


def test_machine_readable_report_endpoint(tmp_path):
    database_path = tmp_path / "scanner.db"
    from database import ScanStore

    store = ScanStore(database_path)
    scan_id = store.save_scan(
        {
            "target": "https://example.com",
            "final_url": "https://example.com/",
            "status": "completed",
            "score": 80,
            "summary": "No findings detected.",
            "response_status": 200,
            "response_size": 10,
            "findings": [],
            "error_message": None,
        }
    )
    original_database_path = app.config["DATABASE_PATH"]
    app.config["DATABASE_PATH"] = str(database_path)
    try:
        response = app.test_client().get(f"/api/reports/{scan_id}.json")
    finally:
        app.config["DATABASE_PATH"] = original_database_path

    assert response.status_code == 200
    assert response.get_json()["id"] == scan_id
    assert response.get_json()["response_status"] == 200


def test_report_page_exposes_pdf_download(tmp_path):
    database_path = tmp_path / "scanner.db"
    from database import ScanStore

    scan_id = ScanStore(database_path).save_scan({
        "target": "https://example.com",
        "final_url": "https://example.com/",
        "status": "completed",
        "score": 80,
        "summary": "No findings detected.",
        "response_status": 200,
        "response_size": 10,
        "findings": [],
        "error_message": None,
    })
    original_database_path = app.config["DATABASE_PATH"]
    app.config["DATABASE_PATH"] = str(database_path)
    try:
        response = app.test_client().get(f"/reports/{scan_id}")
    finally:
        app.config["DATABASE_PATH"] = original_database_path

    assert response.status_code == 200
    assert b"Download PDF" in response.data
    assert f"/reports/{scan_id}/download.pdf".encode() in response.data


def test_pdf_report_download_endpoint(tmp_path):
    database_path = tmp_path / "scanner.db"
    from database import ScanStore

    store = ScanStore(database_path)
    scan_id = store.save_scan(
        {
            "target": "https://example.com",
            "final_url": "https://example.com/",
            "status": "completed",
            "score": 70,
            "summary": "One high-risk finding detected.",
            "response_status": 200,
            "response_size": 123,
            "severity": "high",
            "risk_level": "high",
            "findings": [{
                "code": "missing_security_header",
                "severity": "high",
                "message": "The Strict-Transport-Security header is missing.",
                "evidence": "Not present",
                "remediation": "Add HSTS.",
                "confidence": "high",
                "owasp": "A5: Security Misconfiguration",
            }],
            "error_message": None,
        }
    )
    original_database_path = app.config["DATABASE_PATH"]
    app.config["DATABASE_PATH"] = str(database_path)
    try:
        response = app.test_client().get(f"/reports/{scan_id}/download.pdf")
    finally:
        app.config["DATABASE_PATH"] = original_database_path

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
    assert response.data.endswith(b"%%EOF\n")
    assert b"startxref" in response.data
    assert b"/Type /Catalog" in response.data


def test_target_validation_rejects_private_addresses(monkeypatch):
    monkeypatch.setattr("config.Config.ALLOW_LOCAL_TARGETS", False)
    try:
        validate_target("http://127.0.0.1:5000")
        validate_target("http://localhost:5000")
    except ScanError:
        pass
    else:
        raise AssertionError("Loopback target should be rejected")


def test_redirect_to_local_target_is_rejected(monkeypatch):
    requested_urls = []

    class RedirectResponse:
        status_code = 302
        headers = {"Location": "http://localhost/admin"}

        def close(self):
            pass

    class FakeSession:
        def get(self, url, **_kwargs):
            requested_urls.append(url)
            return RedirectResponse()

    def reject_local_redirect(url):
        if "localhost" in url:
            raise ScanError("Local, private, and link-local targets are blocked.")
        return url

    monkeypatch.setattr("scanner.validate_target", reject_local_redirect)
    with pytest.raises(ScanError, match="Local, private"):
        _get_checked_response(FakeSession(), "https://public.example/", ScanPolicy())

    assert requested_urls == ["https://public.example/"]


def test_response_body_size_is_enforced_while_streaming():
    class StreamingResponse:
        headers = {}

        def iter_content(self, chunk_size):
            yield b"1234"
            yield b"5678"

    with pytest.raises(ScanError, match="too large"):
        _read_response_body(StreamingResponse(), limit=5)


def test_scan_target_discovers_same_origin_links(monkeypatch):
    class LocalServerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = ""
            if self.path == "/":
                body = '<html><body><a href="/about">About</a><a href="https://example.com/evil">External</a></body></html>'
            elif self.path == "/about":
                body = '<html><body><a href="/">Home</a></body></html>'
            else:
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, _format, *_args):
            del _format, _args
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalServerHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr("config.Config.ALLOW_LOCAL_TARGETS", True)
        result = scan_target(target)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert result["status"] == "completed"
    assert f"http://127.0.0.1:{server.server_port}/about" in result["discovered_urls"]
    assert all("https://example.com" not in url for url in result["discovered_urls"])


def test_scan_target_adds_risk_metadata_and_deduplicates_findings(monkeypatch):
    class LocalServerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, _format, *_args):
            del _format, _args
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalServerHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr("config.Config.ALLOW_LOCAL_TARGETS", True)
        result = scan_target(target)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert result["severity"] in {"low", "medium", "high"}
    assert all("confidence" in finding for finding in result["findings"])
    assert all("owasp" in finding for finding in result["findings"])
    assert all("category" in finding for finding in result["findings"])
    assert result["risk_level"] in {"low", "medium", "high", "critical"}


def test_database_persists_and_retrieves_scan(tmp_path: Path):
    database_path = tmp_path / "scanner.db"
    from database import ScanStore

    store = ScanStore(database_path)
    scan_id = store.save_scan(
        {
            "target": "https://example.com",
            "final_url": "https://example.com/",
            "status": "completed",
            "score": 80,
            "summary": "No findings detected.",
            "response_status": 200,
            "response_size": 10,
            "findings": [],
            "error_message": None,
        }
    )
    scan = store.get_scan(str(scan_id))
    assert scan is not None
    assert scan["id"] == scan_id
    assert scan["final_url"] == "https://example.com/"
    assert scan["response_status"] == 200
    assert scan["response_size"] == 10
    assert scan["findings"] == []


def test_database_schema_is_present(tmp_path: Path):
    database_path = tmp_path / "scanner.db"
    from database import ScanStore

    ScanStore(database_path)
    with sqlite3.connect(database_path) as connection:
        columns = connection.execute("PRAGMA table_info(scans)").fetchall()
    assert {column[1] for column in columns} >= {
        "id", "target", "final_url", "scanned_at", "status", "score",
        "summary", "response_status", "response_size", "results_json"
    }


def test_scan_target_uses_real_http_response(monkeypatch):
    class LocalServerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Server", "nginx/1.2")
            self.send_header("Set-Cookie", "session=abc; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, _format, *_args):
            del _format, _args
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalServerHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr("config.Config.ALLOW_LOCAL_TARGETS", True)
        result = scan_target(target)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert result["status"] == "completed"
    assert result["response_status"] == 200
    assert result["response_size"] > 0
    assert any(finding["code"] == "cookie_without_httponly" for finding in result["findings"])
    assert any(finding["code"] == "cookie_without_samesite" for finding in result["findings"])
    assert any(finding["code"] == "missing_security_header" for finding in result["findings"])
    missing_header_messages = [
        finding["message"]
        for finding in result["findings"]
        if finding["code"] == "missing_security_header"
    ]
    assert not any("Content-Security-Policy" in message for message in missing_header_messages)
    assert not any("X-Content-Type-Options" in message for message in missing_header_messages)
    assert any(finding["code"] == "weak_cors_policy" for finding in result["findings"])
    assert any(finding["code"] == "server_version_disclosure" for finding in result["findings"])
    assert any(finding["code"] == "insecure_transport" for finding in result["findings"])
    assert any(finding["code"] == "missing_security_header" and finding["evidence"] == "Not present" for finding in result["findings"])
    assert all("remediation" in finding for finding in result["findings"])
