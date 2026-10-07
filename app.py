"""Flask application entry point for the Web Vulnerability Scanner."""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from pathlib import Path

import csv
import io

from flask import Flask, Response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import get_db, initialize_database
from scanner import ScanError, scan_target

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.config["DATABASE_PATH"] = str(Config.database_path())
app.config.setdefault("CONTACT_MESSAGES", [])
app.config["ADMIN_USERNAME"] = os.getenv("ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.getenv("ADMIN_PASSWORD", "admin123")
app.config["ADMIN_USERS"] = [
    {"username": "admin", "role": "admin", "status": "active"},
    {"username": "analyst", "role": "analyst", "status": "active"},
    {"username": "auditor", "role": "auditor", "status": "pending"},
]

with app.app_context():
    initialize_database(app.config["DATABASE_PATH"])


def _admin_required():
    """Ensure only authenticated admin users access the admin dashboard."""
    if not session.get("admin_logged_in"):
        return False
    return True


@app.get("/")
def index():
    """Render the landing page for signed-in users, or login for new visitors."""
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.get("/scanner")
def scanner():
    """Render the scanner page."""
    return render_template("scanner.html")


@app.get("/dashboard")
def dashboard():
    """Render the latest scan history dashboard."""
    scans = get_db(app.config["DATABASE_PATH"]).fetch_recent_scans(limit=10)
    total_findings = sum(len(scan["findings"]) for scan in scans)
    high_risk_findings = sum(
        1
        for scan in scans
        for finding in scan["findings"]
        if finding["severity"] == "high"
    )
    average_score = sum(scan["score"] for scan in scans) // len(scans) if scans else 0
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for scan in scans:
        for finding in scan["findings"]:
            severity_counts[finding.get("severity", "low")] = severity_counts.get(finding.get("severity", "low"), 0) + 1
    return render_template(
        "dashboard.html",
        scans=scans,
        total_findings=total_findings,
        high_risk_findings=high_risk_findings,
        average_score=average_score,
        severity_counts=severity_counts,
    )


@app.get("/contact")
def contact():
    """Render contact support page."""
    return render_template(
        "contact.html",
        success_message=session.pop("contact_success", None),
        messages=app.config.get("CONTACT_MESSAGES", []),
    )


@app.get("/register")
def register():
    """Render the public registration page."""
    if session.get("user_id"):
        return redirect(url_for("account"))
    return render_template("register.html")


@app.post("/register")
def register_submit():
    """Register a new user and create a secure authenticated session."""
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "")
    contact = (request.form.get("contact") or "").strip()

    if len(name) < 2 or len(email) < 5 or len(password) < 8:
        return render_template(
            "register.html",
            error_message="Enter a valid name, email, and password of at least 8 characters.",
        ), 400

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return render_template(
            "register.html",
            error_message="Enter a valid email address.",
        ), 400

    store = get_db(app.config["DATABASE_PATH"])
    if store.get_user_by_email(email) is not None:
        return render_template(
            "register.html",
            error_message="This email is already registered.",
        ), 409

    user_id = store.create_user(
        name=name,
        email=email,
        password_hash=generate_password_hash(password),
        contact=contact,
    )
    session.clear()
    session["user_id"] = user_id
    session["user_name"] = name
    return redirect(url_for("account"))


@app.get("/login")
def login():
    """Render the public login page."""
    if session.get("user_id"):
        return redirect(url_for("account"))
    return render_template("login.html")


@app.post("/login")
def login_submit():
    """Authenticate a registered user."""
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "")
    user = get_db(app.config["DATABASE_PATH"]).get_user_by_email(email)

    if user is None or not check_password_hash(user["password_hash"], password):
        return render_template(
            "login.html",
            error_message="Invalid email or password.",
        ), 401

    session.clear()
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    return redirect(url_for("account"))


@app.get("/account")
def account():
    """Render a protected user account dashboard."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    user = get_db(app.config["DATABASE_PATH"]).get_user(user_id)
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template(
        "account.html",
        user=user,
        greeting=f"Welcome, {user['name']}!",
    )


@app.get("/logout")
def logout():
    """Log out the current user."""
    session.clear()
    return redirect(url_for("index"))


@app.post("/contact")
def contact_submit():
    """Accept a support submission."""
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    subject = (request.form.get("subject") or "").strip()
    message = (request.form.get("message") or "").strip()

    if not all([name, email, subject, message]):
        return render_template(
            "contact.html",
            error_message="Please complete all fields before sending your message.",
            messages=app.config.get("CONTACT_MESSAGES", []),
        ), 400

    app.config["CONTACT_MESSAGES"].append(
        {
            "name": name,
            "email": email,
            "subject": subject,
            "message": message,
        }
    )
    session["contact_success"] = "Thank you. Your message has been sent successfully."
    return redirect(url_for("contact"))


@app.get("/admin/login")
def admin_login():
    """Render the admin login screen."""
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")


@app.post("/admin/login")
def admin_login_submit():
    """Authenticate the basic administrator login."""
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    configured_username = app.config.get("ADMIN_USERNAME")
    configured_password = app.config.get("ADMIN_PASSWORD")
    if (
        configured_username
        and configured_password
        and username == configured_username
        and password == configured_password
    ):
        session["admin_logged_in"] = True
        return redirect(url_for("admin_dashboard"))
    return render_template(
        "admin_login.html",
        error_message="Invalid username or password.",
    ), 401


@app.get("/admin/logout")
def admin_logout():
    """Log out the admin session."""
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.get("/admin/dashboard")
def admin_dashboard():
    """Render the admin dashboard with recent support messages."""
    if not _admin_required():
        return redirect(url_for("admin_login"))
    messages = app.config.get("CONTACT_MESSAGES", [])
    return render_template(
        "admin_dashboard.html",
        messages=messages,
        message_count=len(messages),
    )


@app.get("/about")
def about():
    """Render the About Us page."""
    return render_template(
        "legal_page.html",
        title="About Us",
        subtitle="Developed by Chandan Vivekanand Mishra",
        intro="This website is designed to help authorized users assess the security posture of web applications using a focused, read-only vulnerability scanning workflow.",
        bullets=[
            "The platform is built to support responsible security testing for websites and digital assets that the owner has permission to assess.",
            "The scanner inspects common web configuration issues such as missing security headers, insecure cookies, weak HTTP policies, and same-origin discovery patterns.",
            "This project was developed by Chandan Vivekanand Mishra and is intended to provide a professional, practical security assessment dashboard.",
        ],
        sections=[
            {
                "heading": "Our purpose",
                "text": "The platform demonstrates how a lightweight security scan can detect common weaknesses in a readable, actionable format. It helps security teams, developers, and owners review findings, understand risk, and apply recommended hardening steps.",
            },
            {
                "heading": "Mission",
                "text": "To deliver a simple, secure, and responsible scanning experience that prioritizes transparency, safety, and practical remediation guidance for authorized web assessments.",
            },
            {
                "heading": "Developer credit",
                "text": "Developed by Chandan Vivekanand Mishra. This project reflects a modern security dashboard approach focused on utility, clarity, and professional reporting.",
            },
        ],
    )


@app.get("/security-policy")
def security_policy():
    """Render the security policy page."""
    return render_template(
        "legal_page.html",
        title="Security Policy",
        subtitle="Responsible scanning and secure platform practices",
        intro="This website follows a strict security-first operating model designed to support authorized assessments without performing harmful or intrusive testing.",
        bullets=[
            "The scanner is limited to read-only HTTP checks and does not attempt to bypass authentication or exploit vulnerabilities.",
            "All scanning is intentionally bounded by redirect limits, timeouts, crawl depth caps, and request rate controls.",
            "Private, local, and loopback addresses are blocked by default to reduce risk to internal systems.",
        ],
        sections=[
            {
                "heading": "Authorized use only",
                "text": "This service should only be used against websites and applications that you own, operate, or have explicit permission to assess. Using the scanner against third-party or unauthorized systems is not permitted.",
            },
            {
                "heading": "Read-only checks",
                "text": "The web scanner performs safe, non-destructive evaluation of metadata, headers, cookies, responses, and discovery patterns. It does not manipulate credentials, alter server state, or execute exploitation payloads.",
            },
            {
                "heading": "Operational safeguards",
                "text": "The platform includes safe configuration constraints, strict URL validation, scan limits, and monitoring logs to help ensure responsible use and reduce the chance of accidental misuse.",
            },
        ],
    )


@app.get("/privacy-policy")
def privacy_policy():
    """Render the privacy policy page."""
    return render_template(
        "legal_page.html",
        title="Privacy Policy",
        subtitle="How this website handles information",
        intro="This website respects user privacy and is designed to keep assessment data limited to the information needed for scanning and reporting.",
        bullets=[
            "Target URLs and scan metadata may be stored temporarily to generate reports and dashboard history.",
            "The application stores scan results in a local SQLite database for reporting and review purposes.",
            "No sensitive personal credentials are collected or stored as part of this scanner workflow.",
        ],
        sections=[
            {
                "heading": "Data collected",
                "text": "The scanner may record the target URL, final resolved URL, scan status, score, summary, HTTP response details, and discovered findings. This information is retained to support the dashboard and generated reports.",
            },
            {
                "heading": "Use of information",
                "text": "The collected data is used to produce vulnerability assessments, display historical results, and help website owners improve configuration and security posture.",
            },
            {
                "heading": "Data protection",
                "text": "The project uses local storage and standard application security configuration to minimize unnecessary exposure of assessment results. Sensitive or secret data should never be submitted to the scanner.",
            },
        ],
    )


@app.get("/terms-and-conditions")
def terms_and_conditions():
    """Render the terms and conditions page."""
    return render_template(
        "legal_page.html",
        title="Terms and Conditions",
        subtitle="Website usage terms",
        intro="By accessing and using this website, you agree to use the scanner in a responsible and authorized manner.",
        bullets=[
            "Use this service only for websites or applications you own, manage, or are explicitly authorized to assess.",
            "The scanner is provided as-is for informational and security assessment purposes, not as a guarantee of security or compliance.",
            "Users are responsible for ensuring compliance with legal, contractual, and ethical requirements in their jurisdiction.",
        ],
        sections=[
            {
                "heading": "Service status",
                "text": "This service is intended to support automated assessment and reporting of common web security issues. It may change or be updated without prior notice.",
            },
            {
                "heading": "Limitation of liability",
                "text": "The developer and operators do not guarantee that the scanner will identify every issue or that any result represents a complete security audit. Review by qualified personnel remains necessary.",
            },
            {
                "heading": "Acceptable use",
                "text": "Users must not use the platform to target unauthorized systems, exploit vulnerabilities, or interfere with the operation of other services or networks.",
            },
        ],
    )


@app.get("/website-information")
def website_information():
    """Render a general website information page."""
    return render_template(
        "legal_page.html",
        title="Website Information",
        subtitle="Project overview and technical details",
        intro="This website is a lightweight vulnerability scanner and security assessment dashboard built for practical, safe, and readable security review workflows.",
        bullets=[
            "It provides a simple interface for scanning a target URL and reviewing a structured security assessment.",
            "The system captures findings such as missing headers, insecure cookies, weak transport and policy signals, and basic crawled same-origin information.",
            "Results are displayed through an interactive dashboard and downloadable report for secure review and remediation planning.",
        ],
        sections=[
            {
                "heading": "Core purpose",
                "text": "The website combines the scanner engine, persistent scan history, and report presentation into a single operational portal for web security assessment.",
            },
            {
                "heading": "What it checks",
                "text": "The service primarily evaluates common security configuration issues, response metadata, and web policy signals that often expose application security weaknesses.",
            },
            {
                "heading": "Who it is for",
                "text": "It is intended for developers, security engineers, administrators, and authorized reviewers who need a practical, controlled, and readable overview of web security findings.",
            },
        ],
    )


@app.get("/help")
def help_page():
    """Render the Help and support page."""
    return render_template(
        "legal_page.html",
        title="Help & Support",
        subtitle="Contact and assistance information",
        intro="Need assistance with this website or the security assessment workflow? Please use the contact details below for support-related questions.",
        bullets=[
            "Support email: chandanvivekmishra@gmail.com",
            "This platform is intended for authorized web security assessment and responsible usage only.",
            "For issues related to scans, results, or website access, contact the developer directly for guidance.",
        ],
        sections=[
            {
                "heading": "Contact details",
                "text": "Email: chandanvivekmishra@gmail.com",
            },
            {
                "heading": "How we can help",
                "text": "The support contact can assist with security scanner questions, website usage guidance, report interpretation, and general information about the project and its intended purpose.",
            },
            {
                "heading": "Important note",
                "text": "This website is meant for authorized assessment of systems you own or are explicitly permitted to test. Please do not use the service for unauthorized or malicious testing.",
            },
        ],
    )


@app.get("/faq")
def faq():
    """Render the FAQ page."""
    return render_template(
        "legal_page.html",
        title="FAQ",
        subtitle="Common questions and answers",
        intro="Here are the most common questions about using the scanner responsibly and understanding the reporting workflow.",
        bullets=[
            "This scanner is for authorized testing only and does not perform destructive or malicious actions.",
            "The platform checks common web security headers, cookies, redirects, and response configuration issues.",
            "Reports are stored locally and can be exported in PDF, CSV, or JSON formats.",
        ],
        sections=[
            {
                "heading": "What does this tool scan?",
                "text": "It inspects common HTTP and HTTPS security weaknesses, including headers, cookies, redirect behavior, certificate validity, and same-origin discovery patterns.",
            },
            {
                "heading": "Can I scan any website?",
                "text": "No. The scanner is intended only for websites or applications you own or have explicit authorization to assess.",
            },
            {
                "heading": "How are findings ranked?",
                "text": "Findings are scored by severity and mapped to practical security guidance. High-confidence issues are prioritized in the dashboard and report summaries.",
            },
        ],
    )


@app.get("/report-abuse")
def report_abuse():
    """Render the abuse reporting page."""
    return render_template(
        "legal_page.html",
        title="Report Abuse",
        subtitle="Report misuse or unauthorized testing",
        intro="If you believe this system is being used in a way that violates the terms of use or exceeds authorized testing boundaries, report it immediately.",
        bullets=[
            "Please contact the project owner at chandanvivekmishra@gmail.com with details of the issue.",
            "Include the target URL, time of occurrence, and a summary of the suspicious activity.",
            "Only legitimate abuse reports involving unauthorized or harmful usage should be submitted.",
        ],
        sections=[
            {
                "heading": "How to report",
                "text": "Send a clear explanation of the misuse with as much evidence as available, including the affected site, activity details, and any relevant timestamps.",
            },
            {
                "heading": "Why reporting matters",
                "text": "This helps maintain safe, ethical, and authorized use of the scanner and prevents misuse of the project platform.",
            },
        ],
    )


@app.get("/admin/users")
def admin_users():
    """Render the admin users management page."""
    return render_template(
        "admin_users.html",
        users=app.config.get("ADMIN_USERS", []),
    )


@app.get("/reports/<scan_id>")
def report(scan_id: str):
    """Render a persisted scan report."""
    scan = get_db(app.config["DATABASE_PATH"]).get_scan(scan_id)
    if scan is None:
        return render_template("error.html", message="Scan not found."), 404
    return render_template("report.html", scan=scan)


@app.get("/api/reports/<scan_id>.json")
def report_json(scan_id: str):
    """Return a machine-readable scan report."""
    scan = get_db(app.config["DATABASE_PATH"]).get_scan(scan_id)
    if scan is None:
        return {"error": "Scan not found."}, 404
    return scan


@app.get("/api/reports/export.json")
def export_reports_json():
    """Export all saved reports as JSON."""
    scans = get_db(app.config["DATABASE_PATH"]).fetch_recent_scans(limit=1000)
    return scans


@app.get("/api/reports/export.csv")
def export_reports_csv():
    """Export all saved reports as CSV."""
    scans = get_db(app.config["DATABASE_PATH"]).fetch_recent_scans(limit=1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["target", "score", "final_url", "status", "severity", "risk_level", "scanned_at", "findings", "id"])
    for scan in scans:
        writer.writerow([
            scan.get("target", ""),
            scan.get("score", 0),
            scan.get("final_url", ""),
            scan.get("status", ""),
            scan.get("severity", "low"),
            scan.get("risk_level", "low"),
            scan.get("scanned_at", ""),
            len(scan.get("findings", [])),
            scan.get("id"),
        ])
    csv_data = output.getvalue().encode("utf-8")
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=web_vulnerability_reports.csv"},
    )


def _pdf_escape(value: str) -> str:
    """Escape text for use in a PDF literal string."""
    return value.encode("latin-1", errors="replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_pdf_text(value: str, width: int = 82) -> list[str]:
    """Wrap a PDF text line without splitting words unnecessarily."""
    words = value.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _build_pdf(scan: dict) -> bytes:
    """Build a small, self-contained PDF report without a third-party dependency."""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    finding_lines = [
        f"- {item.get('code', 'finding')}: {item.get('message', '')}"
        for item in scan.get("findings", [])
    ] or ["No findings detected."]
    lines = [
        "Security Assessment Report",
        f"Generated: {generated_at}",
        f"Target: {scan.get('target', 'unknown')}",
        f"Score: {scan.get('score', 0)}/100",
        f"Risk: {scan.get('risk_level', scan.get('severity', 'low'))}",
        f"Findings: {len(scan.get('findings', []))}",
        "",
        *finding_lines,
    ]
    content_lines = ["BT", "/F1 18 Tf", "50 790 Td"]
    y = 790
    for line_number, line in enumerate(lines):
        if line_number == 0:
            content_lines.append(f"({ _pdf_escape(line) }) Tj")
            y -= 26
            continue
        if line_number == 1:
            content_lines.extend(["/F1 11 Tf", f"(Generated: {_pdf_escape(line)}) Tj"])
            y -= 22
            continue
        if line_number == 6:
            content_lines.append(f"({ _pdf_escape(line)}) Tj")
            y -= 18
            continue
        if line_number == 7:
            y -= 18
            continue
        for wrapped_line in _wrap_pdf_text(line):
            content_lines.extend([f"{50} {y} Td", f"({_pdf_escape(wrapped_line)}) Tj"])
            y -= 14
            if y < 70:
                break
        if y < 70:
            break
    content_lines.extend(["ET"])
    content = "\n".join(content_lines).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(content)} >>\nstream\n".encode("latin-1") + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf_parts = [b"%PDF-1.4\n"]
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(b"".join(pdf_parts)))
        pdf_parts.append(f"{index} 0 obj\n".encode("latin-1") + obj + b"\nendobj\n")
    xref_offset = len(b"".join(pdf_parts))
    xref_lines = ["xref", f"0 {len(objects) + 1}", "0000000000 65535 f "]
    xref_lines.extend(f"{offset:010d} 00000 n " for offset in offsets[1:])
    pdf_parts.append("\n".join(xref_lines).encode("latin-1"))
    pdf_parts.append(f"trailer\n<< /Root 1 0 R /Size {len(objects) + 1} >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1"))
    return b"".join(pdf_parts)


@app.get("/reports/<scan_id>/download.pdf")
def pdf_report(scan_id: str):
    """Generate a downloadable PDF export for a saved scan."""
    scan = get_db(app.config["DATABASE_PATH"]).get_scan(scan_id)
    if scan is None:
        return {"error": "Scan not found."}, 404
    pdf = _build_pdf(scan)
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename={scan_id}.pdf"})


@app.post("/api/scan")
def scan_api():
    """Run a bounded, read-only scan and persist its findings."""
    target = request.form.get("target", "").strip()
    if not target:
        return {"error": "A target URL is required."}, 400

    try:
        result = scan_target(target)
        scan_id = get_db(app.config["DATABASE_PATH"]).save_scan(result)
        return {
            "scan_id": scan_id,
            "target": result["target"],
            "status": result["status"],
            "score": result["score"],
            "summary": result["summary"],
        }, 201
    except ScanError as exc:
        logger.warning("Rejected scan request: %s", exc)
        return {"error": str(exc)}, 400
    except Exception as exc:  # pragma: no cover - handled by application logging
        logger.exception("Unexpected scan failure")
        return {"error": "The scan could not be completed. Please try again."}, 500


@app.get("/api/health")
def health():
    """Return a simple service health response."""
    return {"status": "ok", "service": "web-vulnerability-scanner"}


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", message="The requested page was not found."), 404


@app.errorhandler(500)
def server_error(_):
    logger.exception("Unhandled application error")
    return render_template("error.html", message="An unexpected error occurred."), 500


if __name__ == "__main__":
    host = app.config["HOST"]
    port = app.config["PORT"]
    debug = app.config["DEBUG"]
    if debug:
        logger.warning("Flask debug mode is enabled; this is not suitable for production.")
    app.run(host=host, port=port, debug=debug)
