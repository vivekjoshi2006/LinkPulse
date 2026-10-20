import hashlib
import ipaddress
import re
import secrets
import string
import threading
import time
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,35}$")
CODE_CHARS = string.ascii_letters + string.digits

RESERVED_CODES = {
    "account", "admin", "analytics", "api", "app", "assets", "campaigns",
    "create", "dashboard", "docs", "export", "favicon.ico", "health", "help",
    "import", "links", "login", "logout", "qr", "register", "robots.txt",
    "settings", "static", "style.css",
}

BLOCKED_DOMAINS = {
    "grabify.link",
    "instance-data",
    "iplogger.org",
    "malware-traffic.com",
    "metadata.google.internal",
    "phishing-link.org",
}

BOT_SIGNATURES = (
    "bingbot", "bot", "crawler", "curl", "duckduckbot", "embedly",
    "facebookexternalhit", "googlebot", "headless", "monitor", "postman",
    "preview", "python-requests", "slurp", "spider", "twitterbot", "wget",
    "yandex",
)

BROWSER_RULES = (
    ("Edge", "edg/"),
    ("Opera", "opr/"),
    ("Samsung Internet", "samsungbrowser/"),
    ("Firefox", "firefox/"),
    ("Chrome", "chrome/"),
    ("Safari", "safari/"),
)

DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d %H:%M:%S",
)

class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

def get_client_ip(req) -> str:
    cf_ip = req.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()

    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded and forwarded.strip():
        return forwarded.split(",")[0].strip()

    return (req.remote_addr or "127.0.0.1").strip()

def _is_reserved_network(addr) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    )

def is_private_or_reserved_ip(hostname: str) -> bool:
    host = hostname.strip("[]")

    if host.isdigit():
        try:
            return _is_reserved_network(ipaddress.IPv4Address(int(host)))
        except ValueError:
            return False

    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return _is_reserved_network(ip.ipv4_mapped)
        return _is_reserved_network(ip)
    except ValueError:
        return False

def validate_destination(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ApiError(400, "invalid_url", "Destination URL is required.")

    url = raw_url.strip()

    if url.startswith("//"):
        url = f"https:{url}"
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"

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

    host = parsed.hostname.lower().rstrip(".")

    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or is_private_or_reserved_ip(host):
        raise ApiError(400, "security_violation", "Redirecting to localhost or private subnets is prohibited.")

    if host in BLOCKED_DOMAINS:
        raise ApiError(400, "security_violation", "Domain is flagged on the security blocklist.")

    if "@" in (parsed.netloc or ""):
        raise ApiError(400, "invalid_url", "Credentials in URLs (user:pass@host) are prohibited.")

    return url

def validate_alias(alias: str) -> str:
    if not alias or not isinstance(alias, str):
        raise ApiError(400, "invalid_alias", "Custom alias cannot be empty.")

    slug = alias.strip()
    if not ALIAS_PATTERN.match(slug):
        raise ApiError(400, "invalid_alias", "Alias must be 3-35 alphanumeric characters, hyphens or underscores.")

    if slug.lower() in RESERVED_CODES:
        raise ApiError(400, "invalid_alias", f"The alias '{slug}' is reserved by the system.")

    return slug

def parse_expires_at(value, allow_past: bool = False):
    if not value:
        return None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        raw = value.strip().rstrip("Z")
        dt = None
        for fmt in DATE_FORMATS:
            try:
                dt = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue

        if dt is None:
            raise ApiError(400, "invalid_expiry", "Invalid date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM.")
    else:
        raise ApiError(400, "invalid_expiry", "Expiry must be a date string.")

    if isinstance(value, str) and len(value.strip()) == 10:
        dt = dt.replace(hour=23, minute=59, second=59)

    if not allow_past and dt <= datetime.now():
        raise ApiError(400, "invalid_expiry", "Expiry date must be set in the future.")

    return dt

def generate_short_code(length: int = 7) -> str:
    return "".join(secrets.choice(CODE_CHARS) for _ in range(length))

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
    client_ip = (ip or "unknown").strip()
    payload = f"{secret}|linkpulse|{client_ip}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:24]

def classify_user_agent(user_agent: str):
    if not user_agent or not user_agent.strip():
        return "desktop", "Direct / Email", False

    ua = user_agent.lower()
    is_bot = any(sig in ua for sig in BOT_SIGNATURES)
    browser = next((name for name, token in BROWSER_RULES if token in ua), "Other")

    if is_bot:
        return "bot", "Search Engine / Bot", True
    if "ipad" in ua or "tablet" in ua:
        return "tablet", browser, False
    if "mobi" in ua or "iphone" in ua or "android" in ua:
        return "mobile", browser, False

    return "desktop", browser, False

class RateLimiter:
    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()

        with self._lock:
            if now - self._last_cleanup > 300:
                self._hits = {
                    k: bucket for k, bucket in self._hits.items()
                    if bucket and bucket[-1] > now - window
                }
                self._last_cleanup = now

            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= now - window:
                bucket.popleft()

            if len(bucket) >= limit:
                return False

            bucket.append(now)
            return True
