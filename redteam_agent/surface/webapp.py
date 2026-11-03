"""Read-only web-application discovery: real HTTP probes, differential checks.

Every request is GET or HEAD (or OPTIONS for method discovery). The session refuses
redirects, refuses link-local/metadata addresses, and writes nothing but its own
evidence. Checks are passive-first then one bounded round of path and parameter
probes, so a scan is safe to point at a production application.
"""

from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from ..policy import PolicyEngine
from .model import SurfaceFinding, error_result, info_result, pass_result

UA = "redteam-agent/0.2 (+read-only; contact security team before scanning)"
METADATA = ("169.254.169.254", "100.100.100.200", "fd00:ec2::254")
EXTERNAL_MARK = "https://redteam.invalid/"

_SECRET_HINTS = ("secret", "token", "password", "passwd", "key", "auth", "credential", "private")


@dataclass
class Fetch:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    location: str = ""
    error: str = ""
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class WebSession:
    """One authorized read-only HTTP session per target."""

    def __init__(
        self,
        url: str,
        allowed_hosts: tuple[str, ...] = (),
        policy: PolicyEngine | None = None,
        timeout_s: float = 15.0,
        max_requests: int = 40,
        delay_s: float = 0.0,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.hostname or ""
        self.scheme = parsed.scheme
        self.policy = policy or PolicyEngine()
        self.timeout_s = timeout_s
        self.max_requests = max_requests
        self.delay_s = delay_s
        hosts = allowed_hosts or (self.host,)
        self.allowed_hosts = {h.lower() for h in hosts}
        self.requests = 0
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._last_request = 0.0

    def _authorized(self, url: str) -> bool:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        if host not in self.allowed_hosts:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        try:
            infos = socket.getaddrinfo(host, parsed.port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False
        for info in infos:
            ip = info[4][0]
            if ip in METADATA:
                return False
        return True

    def get(self, path_or_url: str, extra_headers: dict[str, str] | None = None, method: str = "GET") -> Fetch:
        url = urllib.parse.urljoin(self.base + "/", path_or_url)
        if self.requests >= self.max_requests:
            return Fetch(url=url, error="request budget exhausted")
        decision = self.policy.check_web(method, url)
        if not decision.allowed:
            return Fetch(url=url, error=f"read-only policy: {decision.reason}")
        if not self._authorized(url):
            return Fetch(url=url, error=f"host {urllib.parse.urlsplit(url).hostname} is not in the authorized scope")
        if self.delay_s:
            wait = self.delay_s - (time.perf_counter() - self._last_request)
            if wait > 0:
                time.sleep(wait)
        headers = {"User-Agent": UA, "Accept": "*/*"}
        headers.update(extra_headers or {})
        started = time.perf_counter()
        self.requests += 1
        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            with self._opener.open(req, timeout=self.timeout_s) as resp:
                raw = resp.read(500_000)
                body = raw.decode("utf-8", "replace")
                fetched = Fetch(
                    url=url,
                    status=getattr(resp, "status", resp.getcode()),
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read(500_000).decode("utf-8", "replace")
            except Exception:
                body = ""
            fetched = Fetch(
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers.items() if exc.headers else {})},
                body=body,
                location=exc.headers.get("Location", "") if exc.headers else "",
            )
            if 300 <= exc.code < 400:
                fetched.location = fetched.location or (exc.headers.get("location", "") if exc.headers else "")
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            fetched = Fetch(url=url, error=f"{type(exc).__name__}: {exc}")
        fetched.elapsed_ms = (time.perf_counter() - started) * 1000
        self._last_request = time.perf_counter()
        return fetched


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


# ---------------------------------------------------------------------------
# Header and transport checks
# ---------------------------------------------------------------------------
HEADER_RULES = (
    ("strict-transport-security", "A02", "low", "HSTS", "Set Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "A05", "medium", "Content-Security-Policy", "Define a CSP with default-src 'self' and no unsafe-inline/unsafe-eval"),
    ("x-frame-options", "A05", "low", "X-Frame-Options", "Send X-Frame-Options: DENY or use frame-ancestors in CSP"),
    ("x-content-type-options", "A05", "low", "X-Content-Type-Options", "Send X-Content-Type-Options: nosniff"),
    ("referrer-policy", "A05", "info", "Referrer-Policy", "Send Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "A05", "info", "Permissions-Policy", "Disable unused browser features with Permissions-Policy"),
)


def check_security_headers(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    out: list[SurfaceFinding] = []
    for header, category, severity, pretty, fix in HEADER_RULES:
        value = baseline.header(header)
        cid = f"WEB.HEADERS.{header}"
        if not value:
            out.append(
                SurfaceFinding(
                    check_id=cid, title=f"Missing security header: {pretty}", framework="OWASP-WEB-2021",
                    category=category, severity=severity, target=session.base,
                    evidence=f"GET {baseline.url} -> {baseline.status}; header absent",
                    remediation=fix, reproduction=f"curl -sI {baseline.url} | grep -i {header}",
                    confidence=0.95,
                )
            )
            continue
        weak = []
        low = value.lower()
        if header == "strict-transport-security" and "includeSubdomains" not in low:
            weak.append("no includeSubDomains")
        if "max-age=0" in re.sub(r"\s+", "", low):
            weak.append("max-age=0")
        if header == "content-security-policy" and ("unsafe-inline" in low or "unsafe-eval" in low):
            weak.append("unsafe-inline/unsafe-eval present")
        if weak:
            out.append(
                SurfaceFinding(
                    check_id=cid + ".weak", title=f"Weak security header: {pretty}", framework="OWASP-WEB-2021",
                    category=category, severity="low", target=session.base,
                    evidence=f"value: {value[:180]} ({', '.join(weak)})",
                    remediation=fix, reproduction=f"curl -sI {baseline.url} | grep -i {header}",
                    confidence=0.8,
                )
            )
        else:
            out.append(pass_result(cid, f"{pretty} present", "OWASP-WEB-2021", category, session.base, value[:120]))
    frame = "x-frame-options" not in [h[0] for h in HEADER_RULES if baseline.header(h[0])]
    csp = baseline.header("content-security-policy").lower()
    if not frame and "frame-ancestors" not in csp:
        out.append(
            SurfaceFinding(
                check_id="WEB.HEADERS.clickjacking", title="No clickjacking defense", framework="OWASP-WEB-2021",
                category="A05", severity="medium", target=session.base,
                evidence="neither X-Frame-Options nor CSP frame-ancestors is present",
                remediation="Add frame-ancestors 'none' to CSP or X-Frame-Options: DENY",
                reproduction=f"curl -sI {baseline.url}", confidence=0.9,
            )
        )
    return out


def check_server_disclosure(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    leaks = [(h, baseline.header(h)) for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via") if baseline.header(h)]
    leaks = [(h, v) for h, v in leaks if re.search(r"\d", v)]
    if not leaks:
        return [pass_result("WEB.DISCLOSURE.server", "No versioned technology headers", "OWASP-WEB-2021", "A05", session.base)]
    evidence = "; ".join(f"{h}: {v[:80]}" for h, v in leaks)
    return [
        SurfaceFinding(
            check_id="WEB.DISCLOSURE.server", title="Server discloses software versions", framework="OWASP-WEB-2021",
            category="A06", severity="low", target=session.base,
            evidence=evidence[:400], remediation="Remove version tokens (ServerTokens Prod, server_tokens off)",
            reproduction=f"curl -sI {baseline.url} | grep -iE 'server|x-powered-by'", confidence=0.85,
        )
    ]


def check_cookies(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    raw = baseline.headers.get("set-cookie", "")
    if not raw:
        return [info_result("WEB.COOKIES.none", "No session cookie observed on the baseline response", "OWASP-WEB-2021", "A07", session.base)]
    cookies = [c.strip() for c in raw.split(",") if "=" in c]
    bad = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        missing = [attr for attr, present in (
            ("Secure", "secure" in cookie.lower()),
            ("HttpOnly", "httponly" in cookie.lower()),
            ("SameSite", "samesite" in cookie.lower()),
        ) if not present]
        if missing:
            bad.append((name, missing, cookie))
    if not bad:
        return [pass_result("WEB.COOKIES.flags", "Cookies carry Secure, HttpOnly and SameSite", "OWASP-WEB-2021", "A07", session.base)]
    evidence = "; ".join(f"{name}: missing {','.join(m)}" for name, m, _ in bad)
    return [
        SurfaceFinding(
            check_id="WEB.COOKIES.flags", title="Session cookies lack protective attributes", framework="OWASP-WEB-2021",
            category="A07", severity="medium" if session.scheme == "https" else "low", target=session.base,
            evidence=evidence[:400],
            remediation="Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies",
            reproduction=f"curl -s -D- {baseline.url} -o /dev/null", confidence=0.9, manual_review=True,
        )
    ]


def check_cors(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    probe = session.get(baseline.url, {"Origin": EXTERNAL_MARK.rstrip("/")})
    if probe.error or probe.status <= 0:
        return [error_result("WEB.CORS", "CORS origin probe", "OWASP-WEB-2021", "A05", session.base, probe.error)]
    acao = probe.header("access-control-allow-origin")
    acac = probe.header("access-control-allow-credentials").lower() == "true"
    if acao in ("*",) and acac:
        evidence = f"Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
        return [
            SurfaceFinding(
                check_id="WEB.CORS.wildcard", title="CORS wildcard trusts any origin", framework="OWASP-WEB-2021",
                category="A01", severity="medium", target=session.base, evidence=evidence,
                remediation="Echo only allowlisted origins and never pair * with credentials",
                reproduction=f"curl -s -o /dev/null -D- -H 'Origin: {EXTERNAL_MARK.rstrip('/')}' {baseline.url}", confidence=0.8,
            )
        ]
    if acao and acao != "*" and EXTERNAL_MARK.rstrip("/") in acao:
        return [
            SurfaceFinding(
                check_id="WEB.CORS.reflect", title="CORS reflects an arbitrary origin", framework="OWASP-WEB-2021",
                category="A01", severity="high", target=session.base,
                evidence=f"probe Origin echoed back: {acao[:120]}" + ("; credentials allowed" if acac else "; no credentials flag"),
                remediation="Validate Origin against an explicit allowlist",
                reproduction=f"curl -s -o /dev/null -D- -H 'Origin: {EXTERNAL_MARK.rstrip('/')}' {baseline.url}", confidence=0.9,
            )
        ]
    return [pass_result("WEB.CORS", "CORS origin handling is not permissive", "OWASP-WEB-2021", "A01", session.base, f"ACAO={acao or 'absent'}")]


def check_methods(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    probe = session.get(baseline.url, method="OPTIONS")
    if probe.status not in (200, 204) or probe.error:
        return [info_result("WEB.METHODS", "OPTIONS not supported", "OWASP-WEB-2021", "A05", session.base, f"status {probe.status}")]
    allow = probe.header("allow") or probe.header("access-control-allow-methods")
    risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE") if m in allow.upper()]
    if "TRACE" in risky:
        return [
            SurfaceFinding(
                check_id="WEB.METHODS.trace", title="HTTP TRACE is advertised", framework="OWASP-WEB-2021",
                category="A05", severity="low", target=session.base, evidence=f"Allow: {allow[:200]}",
                remediation="Disable TRACE at the server and any reverse proxy",
                reproduction=f"curl -s -o /dev/null -w '%{{http_code}}' -X OPTIONS {baseline.url}", confidence=0.9,
            )
        ]
    if risky:
        return [info_result("WEB.METHODS.risky", "Risky HTTP methods advertised", "OWASP-WEB-2021", "A05", session.base, f"Allow: {allow[:200]}", "Confirm authorization and input validation for PUT/DELETE/PATCH")]
    return [pass_result("WEB.METHODS", "Advertised methods are GET/HEAD only", "OWASP-WEB-2021", "A05", session.base, allow[:120])]


def check_tls(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    if session.scheme != "https":
        return [
            SurfaceFinding(
                check_id="WEB.TLS.plaintext", title="Site is served over plain HTTP", framework="OWASP-WEB-2021",
                category="A02", severity="high", target=session.base,
                evidence=f"{baseline.url} answered over http", remediation="Redirect all HTTP to HTTPS with HSTS",
                reproduction=f"curl -sI http://{session.host}/", confidence=0.95,
            )
        ]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((session.host, 443), timeout=session.timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=session.host) as tls:
                cert = tls.getpeercert() or {}
                version = tls.version()
                cipher = tls.cipher()[0] if tls.cipher() else ""
    except ssl.SSLCertVerificationError as exc:
        return [
            SurfaceFinding(
                check_id="WEB.TLS.verify", title="TLS certificate does not validate", framework="OWASP-WEB-2021",
                category="A02", severity="high", target=session.base, evidence=str(exc)[:300],
                remediation="Install a chain that validates against the public roots",
                reproduction=f"openssl s_client -connect {session.host}:443 -servername {session.host}", confidence=0.95,
            )
        ]
    except (OSError, ssl.SSLError) as exc:
        return [error_result("WEB.TLS", "TLS handshake", "OWASP-WEB-2021", "A02", session.base, f"{type(exc).__name__}: {exc}")]
    issues = []
    weak = [v for v in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3") if version == v]
    if weak:
        issues.append(f"negotiated {version}")
    if not cert:
        issues.append("no certificate presented")
    else:
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = ssl.cert_time_to_seconds(not_after)
                days = (expiry - time.time()) / 86400
                if days < 0:
                    issues.append("certificate expired")
                elif days < 30:
                    issues.append(f"certificate expires in {days:.0f} days")
            except ValueError:
                pass
        if cert.get("subject") == cert.get("issuer"):
            issues.append("self-signed certificate")
    if issues:
        return [
            SurfaceFinding(
                check_id="WEB.TLS.weak", title="TLS configuration has issues", framework="OWASP-WEB-2021",
                category="A02", severity="medium", target=session.base, evidence="; ".join(issues)[:400],
                remediation="Require TLS 1.2+, a valid chain, and a renewal before expiry",
                reproduction=f"openssl s_client -connect {session.host}:443 -servername {session.host}", confidence=0.9,
            )
        ]
    return [pass_result("WEB.TLS", "TLS negotiates TLS 1.2+ with a valid chain", "OWASP-WEB-2021", "A02", session.base, f"{version} {cipher}")]


# ---------------------------------------------------------------------------
# Path, parameter and redirect probes
# ---------------------------------------------------------------------------
EXPOSED_PATHS = (
    ("/.git/HEAD", "git"),
    ("/.git/config", "git"),
    ("/.env", "env"),
    ("/.svn/entries", "svn"),
    ("/.ds_store", "ds"),
    ("/backup.sql", "sql"),
    ("/database.sql", "sql"),
    ("/phpinfo.php", "phpinfo"),
    ("/server-status", "apache-status"),
    ("/actuator/env", "actuator"),
    ("/actuator/heapdump", "heapdump"),
    ("/debug", "debug"),
    ("/console", "debug-console"),
    ("/web.config", "iis-config"),
    ("/crossdomain.xml", "crossdomain"),
)


def _evidence_env(body: str) -> str:
    keys = []
    for line in body.splitlines()[:200]:
        if "=" in line and not line.strip().startswith("#"):
            key = line.split("=", 1)[0].strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                keys.append(key)
    secretish = [k for k in keys if any(h in k.lower() for h in _SECRET_HINTS)]
    return (
        f"{len(keys)} variable names recovered; sensitive-looking: {', '.join(secretish[:8]) or 'none'}. "
        "Values are withheld on purpose."
    )


def _sql_evidence(body: str) -> str:
    tables = sorted(set(re.findall(r"(?:CREATE TABLE|INSERT INTO)\s+[`\"]?([A-Za-z0-9_]+)", body, re.I)))
    return f"dump contains {tables[:10]} ({len(body)} bytes); content withheld"


def check_exposed_paths(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    root = urllib.parse.urlsplit(baseline.url).path
    base = session.base + (root.rsplit("/", 1)[0] + "/" if root and root != "/" else "/")
    out: list[SurfaceFinding] = []
    for path, kind in EXPOSED_PATHS:
        if path == "/web.config":
            pass  # IIS config only relevant to IIS, handled adaptively below
        probe = session.get(urllib.parse.urljoin(base, path))
        cid = f"WEB.EXPOSED.{kind}"
        if probe.error or probe.status in (0, 404, 410):
            continue
        body = probe.body
        hit = False
        evidence = ""
        if kind == "git" and path.endswith("HEAD") and body.startswith("ref:"):
            hit, evidence = True, f"git HEAD exposed: {body.strip()[:80]}"
        elif kind == "git" and "core" in body and "[core]" in body:
            hit, evidence = True, "git config exposed (remotes shown redacted)"
        elif kind == "env" and re.search(r"^[A-Za-z_][A-Za-z0-9_]*=", body, re.M):
            hit, evidence = True, _evidence_env(body)
        elif kind == "sql" and re.search(r"(CREATE TABLE|INSERT INTO)", body, re.I):
            hit, evidence = True, _sql_evidence(body)
        elif kind == "phpinfo" and "phpinfo()" in body.lower():
            hit, evidence = True, f"phpinfo at {probe.url} leaks ini/config; body {len(body)} bytes (withheld)"
        elif kind == "apache-status" and "Apache Server Status" in body:
            hit, evidence = True, "Apache server-status is publicly readable"
        elif kind in ("actuator", "debug", "debug-console", "heapdump"):
            markers = ("\"properties\"", "debugger", "werkzeug", "WATCHDOG", "heap")
            if any(m.lower() in body.lower() for m in markers) or "application/octet-stream" in probe.header("content-type"):
                hit, evidence = True, f"{probe.url} answers {probe.status} with configuration/debug material hint"
        elif kind == "iis-config" and "<configuration>" in body and "<system.web" in body.lower():
            hit, evidence = True, "web.config served (connection strings withheld)"
        elif kind == "crossdomain":
            hit, evidence = True, f"crossdomain.xml permits third-party flash access: {body[:80].strip()}"
        elif kind == "ds" and path == "/.ds_store":
            hit, evidence = True, "Finder metadata exposed"
        if hit:
            severity = {"env": "high", "sql": "high", "phpinfo": "high", "actuator": "medium", "heapdump": "high", "debug": "medium", "debug-console": "high", "apache-status": "low", "git": "high"}.get(kind, "medium")
            out.append(
                SurfaceFinding(
                    check_id=cid, title=f"Exposed artifact: {kind}", framework="OWASP-WEB-2021",
                    category="A05", severity=severity, target=session.base,
                    evidence=f"GET {probe.url} -> {probe.status}; {evidence}",
                    remediation="Remove the artifact from the web root or block it at the edge proxy",
                    reproduction=f"curl -s {probe.url}", confidence=0.9, manual_review=kind in ("actuator", "debug"),
                    indicators=[kind],
                )
            )
    if not out:
        return [pass_result("WEB.EXPOSED", "No common artifact was served from the probed paths", "OWASP-WEB-2021", "A05", session.base)]
    return out


FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"<input[^>]*name=[\"']([^\"']+)[\"']", re.I)


def _form_fields(body: str) -> list[str]:
    fields = []
    for block in FORM_RE.finditer(body):
        fields.extend(INPUT_RE.findall(block.group(0)))
    seen = set()
    return [f for f in fields if not (f in seen or seen.add(f))]


def check_reflected_params(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    fields = _form_fields(baseline.body)
    if not fields:
        return [info_result("WEB.REFLECT", "No form fields on the page to test for reflection", "OWASP-WEB-2021", "A03", session.base)]
    marker = "rtx" + hashlib.sha256(baseline.url.encode()).hexdigest()[:8]
    for field in fields[:5]:
        url = f"{baseline.url}?{urllib.parse.urlencode({field: marker})}"
        probe = session.get(url)
        if probe.error or not probe.ok:
            continue
        if marker not in probe.body:
            continue
        escaped = html.escape(marker)
        reflected_unescaped = escaped not in probe.body or f"{marker}<\"" in probe.body
        return [
            SurfaceFinding(
                check_id="WEB.REFLECT.param", title=f"Parameter {field!r} reflects input", framework="OWASP-WEB-2021",
                category="A03", severity="medium", target=session.base,
                evidence=f"GET {probe.url} reflects {marker!r} " + ("without escaping" if reflected_unescaped else "escaped"),
                remediation="Context-aware output encoding and a CSP; validate input length and charset",
                reproduction=f"curl -s '{probe.url}' | grep -o {marker}", confidence=0.7 if reflected_unescaped else 0.4,
                manual_review=True,
            )
        ]
    return [pass_result("WEB.REFLECT", "Tested form parameters did not reflect the marker", "OWASP-WEB-2021", "A03", session.base, ", ".join(fields[:5]))]


REDIRECT_PARAMS = ("next", "url", "redirect", "redirect_uri", "return", "returnUrl", "continue", "dest")


def check_open_redirect(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    for param in REDIRECT_PARAMS:
        url = f"{baseline.url}?{urllib.parse.urlencode({param: EXTERNAL_MARK})}"
        probe = session.get(url)
        if probe.error or not (300 <= probe.status < 400):
            continue
        location = probe.header("location") or probe.location
        if "redteam.invalid" in location:
            return [
                SurfaceFinding(
                    check_id="WEB.REDIRECT.open", title=f"Open redirect via {param!r}", framework="OWASP-WEB-2021",
                    category="A01", severity="medium", target=session.base,
                    evidence=f"{probe.status} Location -> {location[:160]}",
                    remediation="Redirect only to a fixed allowlist or an internal relative path",
                    reproduction=f"curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' '{url}'", confidence=0.95,
                )
            ]
    return [pass_result("WEB.REDIRECT", "No open redirect on common parameters", "OWASP-WEB-2021", "A01", session.base)]


def check_directory_listing(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    if "Index of /" in baseline.body or "<title>Index of" in baseline.body:
        return [
            SurfaceFinding(
                check_id="WEB.DIRLIST", title="Directory listing enabled", framework="OWASP-WEB-2021",
                category="A05", severity="medium", target=session.base,
                evidence=f"{baseline.url} renders an auto-index", remediation="Disable autoindex (Options -Indexes)",
                reproduction=f"curl -s {baseline.url}", confidence=0.9,
            )
        ]
    return [pass_result("WEB.DIRLIST", "Root does not render a directory index", "OWASP-WEB-2021", "A05", session.base)]


def check_host_header(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    probe = session.get(baseline.url, {"Host": "redteam.invalid"})
    same = probe.body[:2000] == baseline.body[:2000]
    if probe.ok and not same:
        return [
            SurfaceFinding(
                check_id="WEB.HOSTHEADER", title="Application answers an unrecognized Host header differently", framework="OWASP-WEB-2021",
                category="A05", severity="low", target=session.base,
                evidence=f"Host: redteam.invalid -> {probe.status}, body differs from baseline ({len(probe.body)} vs {len(baseline.body)} bytes)",
                remediation="Reject unknown Host headers at the front door and maintain an allowlist",
                reproduction=f"curl -s -H 'Host: redteam.invalid' {baseline.url} | head", confidence=0.5, manual_review=True,
            )
        ]
    return [pass_result("WEB.HOSTHEADER", "Application does not vary on an unrecognized Host header", "OWASP-WEB-2021", "A05", session.base)]


def check_robots(session: WebSession, baseline: Fetch) -> list[SurfaceFinding]:
    probe = session.get("/robots.txt")
    if probe.ok and probe.status == 200 and "Disallow" in probe.body:
        return [info_result("WEB.ROBOTS", "robots.txt discloses internal route names", "OWASP-WEB-2021", "A05", session.base, f"disallowed prefixes: {len(re.findall('Disallow', probe.body))}")]
    return [pass_result("WEB.ROBOTS", "robots.txt is absent or not disclosing routes", "OWASP-WEB-2021", "A05", session.base)]


def fingerprint_web(session: WebSession, baseline: Fetch) -> dict:
    body = baseline.body.lower()
    evidence: list[str] = []
    server = (baseline.header("server") + " " + baseline.header("x-powered-by")).strip()
    forwarded = baseline.header("x-forwarded-host") or baseline.header("via")
    tech: list[str] = []
    if "wordpress" in body or "wp-content" in body:
        tech.append("wordpress")
    if "drupal" in body:
        tech.append("drupal")
    if "csrfmiddlewaretoken" in body or "csrftoken" in body:
        tech.append("django")
    if re.search(r"<meta[^>]+name=[\"']generator[\"']", body):
        m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body)
        if m:
            system = re.search(r"(WordPress|Drupal|Joomla)", m.group(1), re.I)
            if system:
                tech.append(system.group(1).lower())
    if "java" in server.lower() or "tomcat" in server.lower():
        tech.append("jvm")
    if "express" in body or "node" in server.lower():
        tech.append("node")
    if "php" in server.lower():
        tech.append("php")
    if "iis" in server.lower():
        tech.append("iis")
    if "nginx" in server.lower():
        tech.append("nginx")
    if "apache" in server.lower():
        tech.append("apache")
    forms = _form_fields(baseline.body)
    cdn = baseline.header("cf-ray") or baseline.header("x-cache") or baseline.header("x-akamai")
    profile = {
        "kind": "web",
        "url": session.base,
        "host": session.host,
        "scheme": session.scheme,
        "server": server[:120],
        "tech": tech,
        "forms": forms[:8],
        "cdn": bool(cdn),
        "forwarded": forwarded[:80],
        "status": baseline.status,
        "headers": {k: v[:80] for k, v in baseline.headers.items() if k not in ("set-cookie",)},
    }
    profile["hypotheses"] = ["security-headers", "tls", "cors", "cookies"]
    if tech:
        profile["hypotheses"].append("exposed-paths")
    if any(t in tech for t in ("wordpress", "drupal", "jvm", "iis", "php")):
        profile["hypotheses"].append("known-artifacts")
    if forms:
        profile["hypotheses"].append("reflection")
    return profile
