"""Read-only, bounded HTTP and security-header checks."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests
from requests import RequestException, Response

from config import Config

logger = logging.getLogger(__name__)


class ScanError(ValueError):
    """Raised when a target is unsafe or cannot be scanned."""


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if tag.lower() in {"a", "link", "script", "img", "iframe"} and name.lower() == "href":
                if value:
                    self.links.append(value)


@dataclass(frozen=True)
class ScanPolicy:
    max_redirects: int = Config.MAX_REDIRECTS
    timeout_seconds: float = Config.REQUEST_TIMEOUT_SECONDS
    max_response_bytes: int = Config.MAX_RESPONSE_BYTES
    max_crawl_depth: int = Config.MAX_CRAWL_DEPTH
    max_crawl_pages: int = Config.MAX_CRAWL_PAGES
    request_rate_limit_seconds: float = Config.REQUEST_RATE_LIMIT_SECONDS


def _host_is_local_or_private(hostname: str | None) -> bool:
    """Return whether a hostname resolves to a local/private address."""
    if not hostname:
        return False
    hostname = hostname.rstrip(".")
    if hostname.lower() in {"localhost"} or hostname.lower().endswith(".localhost"):
        return True

    seen: set[str] = set()
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    for record in records:
        sockaddr = record[4]
        address = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else None
        if not address or address in seen:
            continue
        seen.add(address)
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return True
    return False


def validate_target(target: str) -> str:
    """Validate a URL and reject credentials, local/private hosts, and malformed input."""
    raw = target.strip()
    if not raw or len(raw) > 2048:
        raise ScanError("Enter a valid website URL.")
    if any(character in raw for character in ("\n", "\r", "\x00")):
        raise ScanError("The target URL contains invalid characters.")

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ScanError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ScanError("URLs containing credentials are not permitted.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ScanError("The target port is invalid.")
    if parsed.fragment:
        raise ScanError("Fragments are not permitted in scan targets.")

    host = parsed.hostname
    is_literal_ip = re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) is not None or ":" in host
    if is_literal_ip:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ScanError("Enter a valid IP address or hostname.") from exc
        if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
            if not Config.ALLOW_LOCAL_TARGETS:
                raise ScanError("Local, private, and link-local targets are blocked.")
    elif not Config.ALLOW_LOCAL_TARGETS and _host_is_local_or_private(host):
        raise ScanError("Local, private, and link-local targets are blocked.")

    return parsed.geturl()


def _safe_client() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update(Config.REQUEST_HEADERS)
    return session


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "low"
    if score >= 50:
        return "medium"
    return "high"


REMEDIATION_GUIDANCE = {
    "missing_security_header": "Add the missing security header with a restrictive value appropriate for the application.",
    "missing_hsts": "Enable HSTS on HTTPS responses and enforce protocol upgrades for all HTTP requests.",
    "insecure_transport": "Serve the site over HTTPS and redirect HTTP requests to HTTPS with HSTS enabled.",
    "potential_clickjacking": "Add X-Frame-Options or a Content-Security-Policy frame-ancestors directive.",
    "server_version_disclosure": "Remove or normalize server-version details from response headers.",
    "framework_version_disclosure": "Disable framework and diagnostic version headers in production responses.",
    "cookie_without_httponly": "Add the HttpOnly attribute to the cookie and verify it is applied to all session cookies.",
    "cookie_without_samesite": "Add an explicit SameSite=Strict or SameSite=Lax policy to the cookie.",
    "cookie_without_secure": "Add the Secure attribute and reject cookies that are received over HTTP.",
    "weak_cors_policy": "Restrict Access-Control-Allow-Origin to trusted origins and remove wildcard access for sensitive endpoints.",
    "certificate_issue": "Replace or renew the TLS certificate and ensure it is valid for the host and current date.",
}

OWASP_MAP = {
    "missing_security_header": "A5: Security Misconfiguration",
    "missing_hsts": "A5: Security Misconfiguration",
    "insecure_transport": "A5: Security Misconfiguration",
    "potential_clickjacking": "A5: Security Misconfiguration",
    "server_version_disclosure": "A5: Security Misconfiguration",
    "framework_version_disclosure": "A5: Security Misconfiguration",
    "cookie_without_httponly": "A3: Sensitive Data Exposure",
    "cookie_without_samesite": "A5: Security Misconfiguration",
    "cookie_without_secure": "A3: Sensitive Data Exposure",
    "weak_cors_policy": "A5: Security Misconfiguration",
    "certificate_issue": "A5: Security Misconfiguration",
}

FINDING_CATEGORIES = {
    "missing_security_header": "configuration",
    "missing_hsts": "transport",
    "insecure_transport": "transport",
    "potential_clickjacking": "headers",
    "server_version_disclosure": "disclosure",
    "framework_version_disclosure": "disclosure",
    "cookie_without_httponly": "session",
    "cookie_without_samesite": "session",
    "cookie_without_secure": "session",
    "weak_cors_policy": "cors",
    "certificate_issue": "tls",
}


def _finding(
    code: str,
    severity: str,
    message: str,
    evidence: str,
) -> dict[str, str | float]:
    confidence = "medium"
    if severity == "high":
        confidence = "high"
    elif severity == "low":
        confidence = "low"
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "evidence": evidence,
        "remediation": REMEDIATION_GUIDANCE.get(code, "Review this condition and apply the appropriate security control."),
        "confidence": confidence,
        "owasp": OWASP_MAP.get(code, "A5: Security Misconfiguration"),
        "category": FINDING_CATEGORIES.get(code, "general"),
    }


def _deduplicate_findings(findings: list[dict[str, str | float]]) -> list[dict[str, str | float]]:
    unique: dict[tuple[str, str], dict[str, str | float]] = {}
    for finding in findings:
        key = (str(finding["code"]), str(finding["evidence"]))
        if key not in unique:
            unique[key] = finding
    return list(unique.values())


def _risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


def _read_response_body(response: Response, limit: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > limit:
                raise ScanError("The response is too large to inspect safely.")
        except ValueError as exc:
            raise ScanError("The response has an invalid Content-Length header.") from exc

    content = bytearray()
    for chunk in response.iter_content(chunk_size=min(65536, limit + 1)):
        if not chunk:
            continue
        remaining = limit - len(content)
        if len(chunk) > remaining:
            raise ScanError("The response is too large to inspect safely.")
        content.extend(chunk)
    return bytes(content)


def _get_checked_response(
    session: requests.Session,
    url: str,
    policy: ScanPolicy,
) -> Response:
    """Fetch a URL while validating every redirect before following it."""
    current_url = url
    redirect_statuses = {301, 302, 303, 307, 308}

    for redirect_count in range(policy.max_redirects + 1):
        current_url = validate_target(current_url)
        response = session.get(
            current_url,
            allow_redirects=False,
            timeout=policy.timeout_seconds,
            stream=True,
        )
        if response.status_code not in redirect_statuses:
            return response

        location = response.headers.get("Location")
        if not location:
            return response
        if redirect_count == policy.max_redirects:
            response.close()
            raise ScanError("The target redirected too many times.")

        next_url = urljoin(current_url, location)
        response.close()
        current_url = validate_target(next_url)

    raise ScanError("The target redirected too many times.")


def _same_origin(base_url: str, candidate_url: str) -> bool:
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    if candidate.scheme not in {"http", "https"}:
        return False
    if base.hostname is None or candidate.hostname is None:
        return False
    return base.hostname == candidate.hostname and (base.port or (443 if base.scheme == "https" else 80)) == (candidate.port or (443 if candidate.scheme == "https" else 80))


def _extract_links(html_body: str, base_url: str) -> list[str]:
    parser = _LinkExtractor()
    parser.feed(html_body)
    links: list[str] = []
    for ref in parser.links:
        cleaned = ref.strip()
        if not cleaned or cleaned.startswith("mailto:") or cleaned.startswith("javascript:"):
            continue
        resolved = urljoin(base_url, cleaned)
        if _same_origin(base_url, resolved):
            links.append(resolved)
    return links


def _tls_certificate_details(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {}
    host = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
        if not cert:
            return {"status": "not_available"}
        not_after = cert.get("notAfter")
        subject = cert.get("subject")
        common_name = ""
        if isinstance(subject, (list, tuple)):
            for item in subject:
                for key, value in item:
                    if key == "commonName":
                        common_name = value
                        break
        return {
            "status": "ok",
            "subject": common_name or "unknown",
            "not_after": not_after or "unknown",
        }
    except (OSError, ssl.SSLError, ValueError):
        return {"status": "error"}


def _security_findings(response: Response, headers: dict[str, str], tls_info: dict[str, str] | None = None) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    headers = {name.lower(): value for name, value in headers.items()}
    required_headers = {
        "strict-transport-security": ("Strict-Transport-Security", "high"),
        "content-security-policy": ("Content-Security-Policy", "medium"),
        "x-content-type-options": ("X-Content-Type-Options", "medium"),
        "referrer-policy": ("Referrer-Policy", "medium"),
        "permissions-policy": ("Permissions-Policy", "low"),
    }
    if response.url.startswith("https://") and not headers.get("strict-transport-security"):
        findings.append(
            _finding(
                "missing_hsts",
                "high",
                "The HTTPS response does not set Strict-Transport-Security.",
                "Not present",
            )
        )
    for name, (display_name, severity) in required_headers.items():
        if not headers.get(name):
            findings.append(
                _finding(
                    "missing_security_header",
                    severity,
                    f"The {display_name} response header is missing.",
                    "Not present",
                )
            )

    if response.url.startswith("http://"):
        findings.append(
            _finding(
                "insecure_transport",
                "high",
                "The target is served over plain HTTP.",
                response.url,
            )
        )

    if not headers.get("x-frame-options") and not headers.get("content-security-policy"):
        findings.append(
            _finding(
                "potential_clickjacking",
                "medium",
                "No frame-ancestors or X-Frame-Options policy was detected.",
                "Not present",
            )
        )

    cors_value = headers.get("access-control-allow-origin")
    if cors_value in {"*", "null"}:
        findings.append(
            _finding(
                "weak_cors_policy",
                "medium",
                "The site permits cross-origin access too broadly.",
                cors_value,
            )
        )

    server = headers.get("server", "")
    if server and re.search(r"(?:Apache|nginx|lighttpd|IIS)", server, re.IGNORECASE):
        findings.append(
            _finding(
                "server_version_disclosure",
                "low",
                "The response exposes an identifiable server product.",
                server,
            )
        )

    for header, display_name in (
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
        ("x-debug-id", "X-Debug-ID"),
    ):
        if headers.get(header):
            findings.append(
                _finding(
                    "framework_version_disclosure",
                    "low",
                    f"The {display_name} response header exposes implementation details.",
                    headers[header],
                )
            )

    if tls_info and tls_info.get("status") == "error":
        findings.append(
            _finding(
                "certificate_issue",
                "high",
                "The TLS certificate could not be validated for the target host.",
                "Certificate handshake failed",
            )
        )

    return findings


def _pattern_findings(response: Response, body_text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lower_body = body_text.lower()

    if re.search(r"<script|onerror=|javascript:|alert\s*\(", lower_body):
        findings.append(
            _finding(
                "potential_xss",
                "high",
                "The response contains client-side script patterns or inline event handlers that may expose XSS risk.",
                "Inline JavaScript or event-handler patterns detected",
            )
        )

    if re.search(r"select\s+\*\s+from|union\s+select|or\s+1\s*=\s*1|sleep\s*\(|drop\s+table", lower_body):
        findings.append(
            _finding(
                "potential_sql_injection",
                "high",
                "The application output contains SQL-related patterns that may indicate injection exposure in rendered content.",
                "SQL-like query pattern detected in response body",
            )
        )

    if re.search(r"index of /|directory listing|parent directory|apache.*index|nginx.*index", lower_body):
        findings.append(
            _finding(
                "directory_listing_exposed",
                "medium",
                "The server appears to expose directory listing information or indexing metadata.",
                "Directory listing or index page indicators detected",
            )
        )

    if response.url.startswith("https://") and re.search(r"<h1>index of|<title>index of", lower_body):
        findings.append(
            _finding(
                "ssl_weakness_signal",
                "low",
                "The site exposes index page structures over HTTPS and may have weak application-level security posture.",
                "Index visibility detected on secure endpoint",
            )
        )

    return findings


def _cookie_findings(response: Response) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    cookies = response.raw.headers.getlist("Set-Cookie")
    if not cookies:
        return findings

    for cookie in cookies:
        attributes = cookie.lower()
        name = cookie.split(";", 1)[0].split("=", 1)[0]
        if "httponly" not in attributes:
            findings.append(
                _finding(
                    "cookie_without_httponly",
                    "medium",
                    f"The {name} cookie does not have the HttpOnly attribute.",
                    name,
                )
            )
        if "samesite" not in attributes:
            findings.append(
                _finding(
                    "cookie_without_samesite",
                    "medium",
                    f"The {name} cookie does not have the SameSite attribute.",
                    name,
                )
            )
        if "secure" not in attributes and response.url.startswith("https://"):
            findings.append(
                _finding(
                    "cookie_without_secure",
                    "high",
                    f"The {name} cookie does not have the Secure attribute.",
                    name,
                )
            )
    return findings


def _discover_same_origin_urls(session: requests.Session, base_url: str, policy: ScanPolicy) -> list[str]:
    queue: list[tuple[str, int]] = [(base_url, 0)]
    seen: set[str] = set()
    discovered: list[str] = []
    request_delay = policy.request_rate_limit_seconds
    last_request_at = 0.0

    while queue and len(discovered) < policy.max_crawl_pages:
        current_url, depth = queue.pop(0)
        if current_url in seen or depth > policy.max_crawl_depth:
            continue
        seen.add(current_url)
        if current_url not in discovered:
            discovered.append(current_url)

        elapsed = time.monotonic() - last_request_at
        if elapsed < request_delay:
            time.sleep(request_delay - elapsed)
        last_request_at = time.monotonic()

        try:
            response = _get_checked_response(session, current_url, policy)
        except (RequestException, OSError, ValueError):
            continue

        try:
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type.lower() or current_url == base_url:
                try:
                    body = _read_response_body(response, policy.max_response_bytes)
                except ScanError:
                    response.close()
                    continue
                decoded = body.decode("utf-8", errors="ignore")
                for candidate in _extract_links(decoded, response.url):
                    if candidate not in discovered and candidate not in {url for url, _ in queue}:
                        if depth < policy.max_crawl_depth:
                            queue.append((candidate, depth + 1))
            response.close()
        except (RequestException, OSError, ValueError):
            response.close()
            continue

    return discovered


def scan_target(target: str) -> dict[str, object]:
    """Perform a bounded, read-only scan and return persisted report data."""
    normalized_target = validate_target(target)
    parsed = urlparse(normalized_target)
    policy = ScanPolicy()
    session = _safe_client()
    discovered_urls: list[str] = []

    try:
        response = _get_checked_response(session, normalized_target, policy)
        response.raise_for_status()
        response_body = _read_response_body(response, policy.max_response_bytes)
        final_url = response.url
        response_status = response.status_code
        headers = dict(response.headers.items())
        discovered_urls = _discover_same_origin_urls(session, final_url, policy)
        tls_info = _tls_certificate_details(final_url)
    except (RequestException, OSError, ValueError, ScanError) as exc:
        logger.warning("Target scan failed for %s: %s", parsed.hostname, exc)
        raise ScanError("The target could not be reached or did not return a valid response.") from exc
    finally:
        session.close()

    findings = _security_findings(response, headers, tls_info)
    findings.extend(_cookie_findings(response))
    if response_body:
        body_text = response_body.decode("utf-8", errors="ignore")
        findings.extend(_pattern_findings(response, body_text))
    findings = _deduplicate_findings(findings)

    overall_urls = discovered_urls if discovered_urls else [final_url]
    discovered_urls = [url for url in overall_urls if _same_origin(final_url, url)]

    status = "completed"
    score = max(0, 100 - sum({"high": 35, "medium": 15, "low": 5}[item["severity"]] for item in findings))
    risk_level = _risk_level_from_score(score)
    summary = f"{len(findings)} security finding(s) detected."
    if not findings:
        summary = "No security findings were detected in the inspected response."

    return {
        "target": normalized_target,
        "final_url": final_url,
        "status": status,
        "score": score,
        "summary": summary,
        "severity": _severity_from_score(score),
        "risk_level": risk_level,
        "response_status": response_status,
        "response_size": len(response_body),
        "findings": findings,
        "discovered_urls": discovered_urls,
        "checked_at": None,
        "error_message": None,
    }
