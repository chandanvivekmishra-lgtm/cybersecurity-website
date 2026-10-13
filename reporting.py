"""PDF report generation and secret-safe formatting for saved scan results."""

from __future__ import annotations

import html
import io
import re
from datetime import datetime, timezone
from functools import partial
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

SECRET_QUERY_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "auth_token",
    "authorization",
    "client_secret",
    "cookie",
    "id_token",
    "key",
    "password",
    "passwd",
    "secret",
    "session",
    "sessionid",
    "sessiontoken",
    "token",
    "refresh_token",
}

SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(access[_-]?token|api[_-]?key|auth[_-]?token|authorization|"
    r"client[_-]?secret|cookie|id[_-]?token|password|passwd|refresh[_-]?token|"
    r"secret|session(?:id|token)?|token)\s*[:=]\s*[^;\s,&#]+"
)
COOKIE_HEADER = re.compile(r"(?i)\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+")
BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
FINDING_DETAILS = {
    "potential_xss": (
        "A client-side script pattern was present in the sampled response. "
        "The check is heuristic and does not demonstrate that attacker-controlled input executes."
    ),
    "potential_sql_injection": (
        "SQL-like text was present in the sampled response. This can be ordinary page content "
        "and does not demonstrate that input reaches a database query."
    ),
    "directory_listing_exposed": (
        "The sampled response matched a directory-index pattern. Confirm that it is an actual "
        "directory listing and review which files are exposed."
    ),
    "ssl_weakness_signal": (
        "An index-style page pattern was observed over HTTPS. This is not a TLS certificate "
        "or protocol assessment result."
    ),
}
FINDING_IMPACTS = {
    "missing_hsts": "Without an HSTS policy, some browsers may be more susceptible to downgrade or protocol-stripping scenarios.",
    "insecure_transport": "Traffic sent over plain HTTP can be observed or modified by an on-path party.",
    "potential_clickjacking": "If sensitive actions are frameable, a user could be misled into interacting with the page in an unintended context.",
    "weak_cors_policy": "An overly broad CORS policy may allow untrusted origins to read responses when browser credentials and endpoint behavior make that possible.",
    "cookie_without_httponly": "If this is a session cookie, client-side script could read it; the finding does not show that a script vulnerability exists.",
    "cookie_without_samesite": "Cross-site requests may include the cookie depending on browser behavior and the application’s other CSRF protections.",
    "cookie_without_secure": "A cookie without Secure may be sent over an unencrypted HTTP connection if the application serves one.",
    "certificate_issue": "Users may be unable to verify the server identity or establish a trusted TLS connection.",
    "server_version_disclosure": "Version or product details can help an attacker tailor reconnaissance, but do not alone prove a vulnerable server.",
    "framework_version_disclosure": "Implementation details can assist reconnaissance, but do not alone prove an exploitable weakness.",
}
FINDING_METHODS = {
    "missing_hsts": "Checked the primary HTTPS response for the Strict-Transport-Security header.",
    "missing_security_header": "Checked the primary response headers for the named security policy header.",
    "insecure_transport": "Checked the scheme of the final primary response URL.",
    "potential_clickjacking": "Checked the primary response for X-Frame-Options and a Content-Security-Policy header.",
    "weak_cors_policy": "Checked the primary response Access-Control-Allow-Origin value.",
    "certificate_issue": "Attempted a standard TLS certificate-validation handshake with the target host.",
    "cookie_without_httponly": "Checked Set-Cookie attributes without retaining cookie values.",
    "cookie_without_samesite": "Checked Set-Cookie attributes without retaining cookie values.",
    "cookie_without_secure": "Checked Set-Cookie attributes without retaining cookie values.",
    "potential_xss": "Applied a non-executing pattern heuristic to the bounded primary response body.",
    "potential_sql_injection": "Applied a non-executing SQL-text pattern heuristic to the bounded primary response body.",
    "directory_listing_exposed": "Applied a pattern check to the bounded primary response body.",
    "ssl_weakness_signal": "Applied a pattern check to the bounded primary response body; this is not a TLS configuration test.",
    "server_version_disclosure": "Inspected the primary response Server header.",
    "framework_version_disclosure": "Inspected selected implementation-detail headers on the primary response.",
}
FINDING_VERIFICATION = {
    "missing_hsts": "Request the HTTPS URL and confirm Strict-Transport-Security is present with the intended max-age; test subdomains before enabling includeSubDomains.",
    "missing_security_header": "Request the affected page and confirm the intended security header is present and does not break application behavior.",
    "insecure_transport": "Request the HTTP URL and confirm it redirects to HTTPS; verify the final response and HSTS policy.",
    "potential_clickjacking": "Confirm the response has an appropriate frame-ancestors or X-Frame-Options policy, then test legitimate embedding flows.",
    "weak_cors_policy": "Send preflight and ordinary requests from an untrusted Origin and confirm sensitive responses are not authorized for that origin.",
    "certificate_issue": "Validate the certificate chain, hostname, and expiry with a standard TLS client after replacing or renewing it.",
    "cookie_without_httponly": "Inspect Set-Cookie and confirm the relevant cookie includes HttpOnly.",
    "cookie_without_samesite": "Inspect Set-Cookie and confirm the relevant cookie has an explicit SameSite policy.",
    "cookie_without_secure": "Inspect Set-Cookie over HTTPS and confirm the relevant cookie includes Secure.",
    "potential_xss": "Review the relevant source and safely test representative inputs in an authorized test environment; confirm output encoding is context appropriate.",
    "potential_sql_injection": "Review database call sites for parameterized queries and validate with safe tests in an authorized non-production environment.",
    "directory_listing_exposed": "Request the affected directory and confirm it no longer returns an index of files.",
    "ssl_weakness_signal": "Confirm the index-style page is intended or disable directory indexes; use a separate TLS assessment for protocol and certificate checks.",
    "server_version_disclosure": "Inspect the Server response header and confirm product/version details are minimized.",
    "framework_version_disclosure": "Inspect the relevant response headers and confirm unnecessary implementation details are no longer exposed.",
}
HEADER_EXAMPLES = {
    "Strict-Transport-Security": "Strict-Transport-Security: max-age=31536000",
    "Content-Security-Policy": "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "X-Content-Type-Options: nosniff",
    "Referrer-Policy": "Referrer-Policy: strict-origin-when-cross-origin",
    "Permissions-Policy": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
}
FINDING_EXAMPLES = {
    "potential_xss": "Flask/Jinja HTML templates autoescape by default: render untrusted values as {{ value }} and avoid the |safe filter for untrusted content.",
    "potential_sql_injection": 'Python sqlite3 example: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    "potential_clickjacking": "Content-Security-Policy: frame-ancestors 'none' (adjust only if trusted framing is required).",
    "weak_cors_policy": "Access-Control-Allow-Origin: https://trusted.example (allow only reviewed origins; do not reflect arbitrary Origin values).",
    "cookie_without_httponly": "Set-Cookie: __Host-session=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax",
    "cookie_without_samesite": "Set-Cookie: session=<redacted>; SameSite=Lax (choose the policy appropriate to the application).",
    "cookie_without_secure": "Set-Cookie: __Host-session=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax",
    "directory_listing_exposed": "Nginx: autoindex off;",
}


def redact_sensitive_text(value: object, limit: int = 4000) -> str:
    """Remove common secret-bearing header and assignment forms from report text."""
    text = str(value or "")
    text = COOKIE_HEADER.sub("Cookie: [REDACTED]", text)
    text = BEARER_TOKEN.sub("Bearer [REDACTED]", text)
    text = SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    return text[:limit]


def redact_url(value: object) -> str:
    """Retain URL structure while masking common secret query parameters."""
    raw = redact_sensitive_text(value, limit=2048)
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        query = [
            (key, "[REDACTED]" if key.lower().replace("-", "_") in SECRET_QUERY_NAMES else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit(
            (parsed.scheme, host, parsed.path, urlencode(query), "")
        )
    except ValueError:
        return "[URL REDACTED]"


def redact_scan_data(scan: dict) -> dict:
    """Create a safe copy for pages and exports without altering scan behavior."""
    safe_scan = dict(scan)
    for key in ("target", "final_url"):
        if safe_scan.get(key):
            safe_scan[key] = redact_url(safe_scan[key])
    discovered_urls = safe_scan.get("discovered_urls", [])
    safe_scan["discovered_urls"] = [
        redact_url(url) for url in discovered_urls if isinstance(url, str)
    ] if isinstance(discovered_urls, list) else []
    safe_findings = []
    findings = safe_scan.get("findings", [])
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        safe_finding = dict(finding)
        for key in ("message", "evidence", "remediation", "endpoint"):
            if safe_finding.get(key):
                safe_finding[key] = redact_sensitive_text(safe_finding[key])
        if safe_finding.get("endpoint"):
            safe_finding["endpoint"] = redact_url(safe_finding["endpoint"])
        safe_findings.append(safe_finding)
    safe_scan["findings"] = safe_findings
    return safe_scan


def _paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    safe = html.escape(redact_sensitive_text(value)).replace("\n", "<br/>")
    return Paragraph(safe or "Not recorded", style)


def _code_example(finding: dict, message: str) -> str:
    code = str(finding.get("code", ""))
    if code in FINDING_EXAMPLES:
        return FINDING_EXAMPLES[code]
    if finding.get("code") == "missing_security_header":
        match = re.search(r"The (.+?) response header is missing", message)
        header = match.group(1) if match else ""
        example = HEADER_EXAMPLES.get(header)
        if example:
            caution = (
                " Enable HSTS only after HTTPS is correctly configured."
                if header == "Strict-Transport-Security"
                else ""
            )
            return example + caution
    return ""


def _finding_rows(scan: dict, finding: dict, index: int, styles: dict) -> list:
    code = str(finding.get("code", "unknown"))
    message = redact_sensitive_text(finding.get("message", "Unspecified finding"))
    endpoint = redact_url(
        finding.get("endpoint") or scan.get("final_url") or scan.get("target", "")
    )
    explanation = FINDING_DETAILS.get(
        code,
        "The scanner observed the condition described above in the primary HTTP response. "
        "Review its evidence and confirm the application-specific security impact.",
    )
    impact = FINDING_IMPACTS.get(
        code,
        "Impact depends on the application, affected data, and surrounding controls; this automated observation is not proof of exploitation.",
    )
    rows = [
        ["Finding ID", f"F{scan.get('id', 'N/A')}-{index:03d}"],
        ["Title", message],
        ["Category", finding.get("category", "general")],
        ["Severity / confidence", f"{finding.get('severity', 'unknown')} / {finding.get('confidence', 'unknown')}"],
        ["Affected endpoint", endpoint],
        ["Detection method", FINDING_METHODS.get(code, "Read-only inspection of the primary response.")],
        ["Observed evidence", redact_sensitive_text(finding.get("evidence", "Not recorded"))],
        ["Why it matters", explanation],
        ["Potential impact", impact],
        ["Recommended remediation", redact_sensitive_text(finding.get("remediation", "Review this condition in context."))],
        ["Verification", FINDING_VERIFICATION.get(code, "Repeat the relevant check after remediation and review application behavior.")],
        [
            "OWASP reference",
            (
                f"{finding.get('owasp')} — https://owasp.org/www-project-top-ten/"
                if finding.get("owasp")
                else "Not mapped by this check"
            ),
        ],
    ]
    example = _code_example(finding, message)
    if example:
        rows.insert(-1, ["Configuration example", example])

    table_data = [
        [_paragraph(label, styles["label"]), _paragraph(value, styles["body"])]
        for label, value in rows
    ]
    table = LongTable(
        table_data,
        colWidths=[1.35 * inch, 5.55 * inch],
        repeatRows=0,
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf1e8")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d6d6ce")),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return [table, Spacer(1, 16)]


def build_pdf_report(scan: dict) -> bytes:
    """Generate a paginated report from a saved scan and its actual findings."""
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=colors.HexColor("#0b1718"),
            alignment=TA_CENTER,
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#243637"),
            spaceBefore=12,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportBody",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#394444"),
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportSmall",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#596665"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
        )
    )

    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title=f"Security Assessment Report — Scan {scan.get('id', 'N/A')}",
        author="Web Vulnerability Scanner",
    )
    scanned_at = redact_sensitive_text(scan.get("scanned_at", "Not recorded"))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target = redact_url(scan.get("target", "Not recorded"))
    final_url = redact_url(scan.get("final_url") or scan.get("target", "Not recorded"))
    findings = scan.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    by_severity = {
        level: [
            item
            for item in findings
            if isinstance(item, dict) and item.get("severity") == level
        ]
        for level in ("critical", "high", "medium", "low")
    }
    potential_count = sum(
        1
        for finding in findings
        if isinstance(finding, dict)
        and str(finding.get("code", "")).startswith("potential_")
    )
    story = [
        Paragraph("Web Vulnerability Scanner", styles["ReportTitle"]),
        Paragraph("Security Assessment Report", styles["Heading2"]),
        HRFlowable(width="100%", color=colors.HexColor("#9dd43b")),
        Spacer(1, 10),
        Paragraph(f"<b>Scan ID:</b> {scan.get('id', 'Not recorded')}", styles["ReportBody"]),
        Paragraph(f"<b>Target:</b> {html.escape(target)}", styles["ReportBody"]),
        Paragraph(f"<b>Final URL:</b> {html.escape(final_url)}", styles["ReportBody"]),
        Paragraph(f"<b>Scan timestamp (UTC):</b> {html.escape(scanned_at)}", styles["ReportBody"]),
        Paragraph(f"<b>Report generated:</b> {generated_at}", styles["ReportBody"]),
        Paragraph(f"<b>Overall security score:</b> {scan.get('score', 0)}/100", styles["ReportBody"]),
        Paragraph(
            f"<b>Overall risk level:</b> {html.escape(str(scan.get('risk_level', scan.get('severity', 'unknown'))).title())}",
            styles["ReportBody"],
        ),
        Paragraph(
            f"<b>Scan status:</b> {html.escape(str(scan.get('status', 'unknown')))} · "
            f"<b>HTTP response:</b> {html.escape(str(scan.get('response_status', 'not recorded')))} · "
            f"<b>Response size:</b> {html.escape(str(scan.get('response_size', 'not recorded')))} bytes",
            styles["ReportBody"],
        ),
        Paragraph(f"<b>Findings:</b> {len(findings)}", styles["ReportBody"]),
        Paragraph("Executive summary", styles["ReportHeading"]),
        _paragraph(scan.get("summary", "No summary was recorded."), styles["ReportBody"]),
        Paragraph(
            "The score follows the scanner's existing method: start at 100, subtract 35 per high, "
            "15 per medium, and 5 per low finding, with a floor of 0. Risk bands are low (80+), "
            "medium (60–79), high (40–59), and critical (below 40).",
            styles["ReportBody"],
        ),
        Paragraph("Scope and methodology", styles["ReportHeading"]),
        Paragraph(
            "The assessment made bounded, read-only HTTP/HTTPS requests to the submitted target, "
            "validated redirect destinations, and inspected the primary final response's headers, "
            "cookies, TLS certificate handshake (for HTTPS), and a size-limited response body. "
            "Same-origin URLs may be discovered to a maximum depth of 1 and a maximum of 10 pages; "
            "discovered pages are not independently evaluated for findings.",
            styles["ReportBody"],
        ),
        Paragraph(
            f"Automated pattern heuristics produced {potential_count} potential signal(s). "
            "These are not proof of exploitability. Checks not implemented by this scanner, "
            "including authenticated testing, active exploitation, and full application logic review, "
            "were not performed.",
            styles["ReportBody"],
        ),
        Paragraph("Findings by severity", styles["ReportHeading"]),
    ]
    if not findings:
        story.append(Paragraph("No findings were returned by the implemented checks.", styles["ReportBody"]))
    else:
        severity_titles = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        index = 0
        for severity, severity_findings in by_severity.items():
            if not severity_findings:
                continue
            story.append(Paragraph(severity_titles[severity], styles["Heading3"]))
            for finding in severity_findings:
                index += 1
                story.extend(_finding_rows(scan, finding, index, {
                    "label": styles["ReportLabel"],
                    "body": styles["ReportSmall"],
                }))

    story.extend(
        [
            Paragraph("Limitations and items not tested", styles["ReportHeading"]),
            Paragraph(
                "An automated scan is a limited snapshot and cannot guarantee that a website is secure. "
                "Findings can be false positives or false negatives. This scanner does not authenticate, "
                "exploit vulnerabilities, submit forms, assess business logic, or test every discovered URL. "
                "Review evidence and recommendations with qualified personnel.",
                styles["ReportBody"],
            ),
            Paragraph("Ethical use", styles["ReportHeading"]),
            Paragraph(
                "Use this scanner only on systems you own or are explicitly authorized to assess. "
                "The user is responsible for obtaining permission and complying with applicable rules.",
                styles["ReportBody"],
            ),
            Paragraph(
                "OWASP references identify the scanner's existing category mapping and are provided "
                "for further reading; they do not constitute a formal OWASP assessment.",
                styles["ReportSmall"],
            ),
        ]
    )

    def draw_page(page_canvas: canvas.Canvas, document) -> None:
        page_canvas.saveState()
        page_canvas.setStrokeColor(colors.HexColor("#d6d6ce"))
        page_canvas.line(0.65 * inch, 0.48 * inch, 7.85 * inch, 0.48 * inch)
        page_canvas.setFont("Helvetica", 8)
        page_canvas.setFillColor(colors.HexColor("#687171"))
        page_canvas.drawString(0.65 * inch, 0.32 * inch, "Authorized security assessment — review findings in context")
        page_canvas.drawRightString(7.85 * inch, 0.32 * inch, f"Page {document.page}")
        page_canvas.restoreState()

    doc.build(
        story,
        onFirstPage=draw_page,
        onLaterPages=draw_page,
        canvasmaker=partial(canvas.Canvas, pageCompression=0),
    )
    return output.getvalue()
