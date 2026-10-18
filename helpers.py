import hashlib
import ipaddress
import re
import secrets
import string
import time
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

ALIAS_RE = re.compile(r"^[A-Za-z0-9_-]{3,35}$")
CODE_ALPHABET = string.ascii_letters + string.digits

RESERVED_CODES = {
    "api", "static", "assets", "style.css", "favicon.ico", "robots.txt",
    "health", "app", "admin", "login", "logout", "register", "settings",
    "dashboard", "links", "analytics", "campaigns", "create", "export",
    "import", "docs", "help", "qr"
}

BLOCKED_DOMAINS = {
    "malware-traffic.com", "phishing-link.org", "grabify.link", "iplogger.org"
}

class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

def is_private_or_reserved_ip(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False

def validate_destination(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ApiError(400, "invalid_url", "Destination URL is required.")
    
    url = raw_url.strip()

    # Auto-prepend https:// if omitted
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    if len(url) > 2048:
        raise ApiError(400, "invalid_url", "Destination URL cannot exceed 2048 characters.")
    if any(ord(c) < 32 for c in url):
        raise ApiError(400, "invalid_url", "URL contains illegal control characters.")

    try:
        parsed = urlparse(url)
    except Exception:
        raise ApiError(400, "invalid_url", "Malformed URL structure.")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ApiError(400, "invalid_url", "Protocol must be HTTP or HTTPS.")
    if not parsed.hostname:
        raise ApiError(400, "invalid_url", "Destination URL must include a valid hostname.")

    host_lower = parsed.hostname.lower()
    if host_lower in ("localhost", "127.0.0.1", "::1") or is_private_or_reserved_ip(host_lower):
        raise ApiError(400, "security_violation", "Redirecting to localhost or private subnets is prohibited.")

    if host_lower in BLOCKED_DOMAINS:
        raise ApiError(400, "security_violation", "Domain is flagged on the security blocklist.")

    if "@" in (parsed.netloc or ""):
        raise ApiError(400, "invalid_url", "Credentials in URLs (user:pass@host) are prohibited.")

    return url

def validate_alias(alias: str) -> str:
    if not alias:
        raise ApiError(400, "invalid_alias", "Custom alias cannot be empty.")
    if not ALIAS_RE.match(alias):
        raise ApiError(400, "invalid_alias", "Alias must be 3-35 alphanumeric characters, hyphens or underscores.")
    if alias.lower() in RESERVED_CODES:
        raise ApiError(400, "invalid_alias", f"The alias '{alias}' is reserved by the system.")
    return alias

def parse_expires_at(value, allow_past=False):
    if not value:
        return None
    if not isinstance(value, str):
        raise ApiError(400, "invalid_expiry", "Expiry must be a date string.")
    value = value.strip()
    dt = None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(value.rstrip("Z"), fmt)
            break
        except ValueError:
            continue
    if dt is None:
        raise ApiError(400, "invalid_expiry", "Invalid date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM.")
    if len(value) == 10:
        dt = dt.replace(hour=23, minute=59, second=59)
    if not allow_past and dt <= datetime.now():
        raise ApiError(400, "invalid_expiry", "Expiry date must be in the future.")
    return dt

def generate_short_code(length=7) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))

def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:60]

def title_from_url(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return (f"{host} Link" if host else "New Short Link")[:160]

def sanitize_referrer(referrer: str):
    if not referrer:
        return None
    try:
        parsed = urlparse(referrer)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            return parsed.hostname.lower()[:255]
    except Exception:
        pass
    return None

def anonymize_ip(ip: str, secret: str) -> str:
    return hashlib.sha256(f"{secret}|linkpulse|{ip or 'unknown'}".encode("utf-8")).hexdigest()[:24]

_BOT_SIGNATURES = (
    "bot", "crawler", "spider", "slurp", "headless", "facebookexternalhit",
    "embedly", "preview", "monitor", "yandex", "curl", "wget", "python-requests"
)

def classify_user_agent(ua_raw: str):
    if not ua_raw or not ua_raw.strip():
        return "desktop", "Direct / Email", False

    low = ua_raw.lower()
    is_bot = any(sig in low for sig in _BOT_SIGNATURES)

    browser = "Other"
    for name, token in [
        ("Edge", "edg/"), ("Opera", "opr/"), ("Samsung Internet", "samsungbrowser/"),
        ("Firefox", "firefox/"), ("Chrome", "chrome/"), ("Safari", "safari/")
    ]:
        if token in low:
            browser = name
            break

    if is_bot:
        return "bot", "Search Engine / Bot", True
    if "ipad" in low or "tablet" in low:
        return "tablet", browser, False
    if "mobi" in low or "iphone" in low or "android" in low:
        return "mobile", browser, False
    return "desktop", browser, False

class RateLimiter:
    def __init__(self):
        self._hits = {}

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        bucket = self._hits.setdefault(key, deque())
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True