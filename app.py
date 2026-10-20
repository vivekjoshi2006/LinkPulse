import csv
from datetime import datetime, timedelta
import io
import os
from pathlib import Path
import re
import sqlite3
import traceback

from flask import Flask, Response, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from app_config import Config
except ImportError:
    from config import Config

from database import close_db, get_db, get_engine, initialize_database, query_all, query_one
from helpers import (
    ApiError, RateLimiter, anonymize_ip, classify_user_agent,
    generate_short_code, get_client_ip, parse_expires_at, sanitize_referrer,
    slugify, title_from_url, validate_alias, validate_destination
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

ADMIN_USER = os.getenv("ADMIN_USER", "CWC")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "123")

COUNTRY_PATTERNS = (
    (re.compile(r"\b(in|hi|en-in)\b"), "India"),
    (re.compile(r"\b(us|en-us)\b"), "United States"),
    (re.compile(r"\b(gb|uk|en-gb)\b"), "United Kingdom"),
    (re.compile(r"\b(ca|en-ca|fr-ca)\b"), "Canada"),
    (re.compile(r"\b(de|de-de)\b"), "Germany"),
    (re.compile(r"\b(fr|fr-fr)\b"), "France"),
    (re.compile(r"\b(au|en-au)\b"), "Australia"),
)

LINK_SELECT = """
    SELECT l.id, l.title, l.original_url, l.short_code, l.custom_alias,
           l.created_at, l.expires_at, l.click_limit, l.click_count,
           l.password_hash, l.password_plain, l.campaign_id, l.user_id,
           c.name AS campaign_name, c.tag AS campaign_tag,
           CASE WHEN l.status = 'active' AND l.expires_at IS NOT NULL
                     AND l.expires_at < CURRENT_TIMESTAMP
                THEN 'expired' ELSE l.status END AS status
    FROM links l LEFT JOIN campaigns c ON c.id = l.campaign_id
"""

GATE_CARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Protected Link — LinkPulse</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;700;800&display=swap" rel="stylesheet">
  <style>
    body {{
      font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
      display: flex; justify-content: center; align-items: center; min-height: 100vh;
      margin: 0; background-color: #f8fafc;
      background-image: radial-gradient(at 0% 0%, rgba(199, 210, 254, 0.6) 0px, transparent 50%),
                        radial-gradient(at 100% 100%, rgba(254, 215, 170, 0.5) 0px, transparent 50%);
      color: #0f172a;
    }}
    .gate-card {{
      background: rgba(255, 255, 255, 0.94);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid rgba(255, 255, 255, 0.95);
      padding: 2.5rem 2rem; border-radius: 1.5rem;
      box-shadow: 0 25px 60px -15px rgba(99, 102, 241, 0.18);
      width: 100%; max-width: 360px; text-align: center;
    }}
    .lock-icon {{
      width: 52px; height: 52px; background: rgba(99, 102, 241, 0.12);
      color: #4f46e5; border-radius: 16px; font-size: 1.5rem;
      display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem;
    }}
    h2 {{ font-size: 1.45rem; font-weight: 800; margin: 0 0 0.35rem; color: #1e1b4b; }}
    p {{ font-size: 0.88rem; color: #64748b; margin: 0 0 1.25rem; line-height: 1.4; }}
    input {{
      width: 100%; box-sizing: border-box; padding: 0.8rem 1rem;
      border: 1.5px solid #cbd5e1; border-radius: 0.75rem;
      font-size: 0.95rem; font-family: inherit; outline: none; margin-bottom: 0.85rem;
    }}
    input:focus {{ border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15); }}
    button {{
      width: 100%; padding: 0.85rem; border: none; border-radius: 0.75rem;
      background: linear-gradient(135deg, #4f46e5, #7c3aed);
      color: #fff; font-size: 0.92rem; font-weight: 700; cursor: pointer;
      box-shadow: 0 6px 18px rgba(79, 70, 229, 0.3); transition: transform 0.15s ease;
    }}
    button:hover {{ transform: translateY(-1px); }}
  </style>
</head>
<body>
  <div class="gate-card">
    <div class="lock-icon">🔒</div>
    <h2>Protected Link</h2>
    <p>This destination is gated. Enter the access password to continue.</p>
    {error_html}
    <form method="POST">
      <input type="password" name="link_password" placeholder="Enter password" required autofocus />
      <button type="submit">Verify & Continue →</button>
    </form>
  </div>
</body>
</html>"""

app = Flask(__name__, static_folder=None)
app.config.from_object(Config)
app.config["MAX_CONTENT_LENGTH"] = Config.CSV_MAX_BYTES + 1024

initialize_database(Config)
limiter = RateLimiter()
app.teardown_appcontext(close_db)

def exec_db(query, params=()):
    db = get_db()
    cur = db.cursor()
    if get_engine() == "sqlite" and "%s" in query:
        query = query.replace("%s", "?")
    cur.execute(query, params)
    return cur, db

def auto_migrate():
    try:
        if get_engine() == "mysql":
            return

        conn = sqlite3.connect(Config.SQLITE_PATH)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NULL,
                country TEXT DEFAULT 'India',
                age INTEGER NULL,
                role TEXT DEFAULT 'User',
                auth_provider TEXT DEFAULT 'manual',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cur.execute("SELECT id FROM users WHERE username = ?;", (ADMIN_USER,))
        admin = cur.fetchone()
        if not admin:
            cur.execute("""
                INSERT INTO users (name, username, password_hash, role, country, auth_provider)
                VALUES ('Admin', ?, ?, 'Admin', 'India', 'system');
            """, (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD)))
            cur.execute("SELECT id FROM users WHERE username = ?;", (ADMIN_USER,))
            admin = cur.fetchone()

        admin_id = admin[0] if admin else 1

        cur.execute("PRAGMA table_info(links);")
        link_cols = [r[1] for r in cur.fetchall()]
        if link_cols:
            if "user_id" not in link_cols:
                cur.execute("ALTER TABLE links ADD COLUMN user_id INTEGER NULL;")
            cur.execute("UPDATE links SET user_id = ? WHERE user_id IS NULL;", (admin_id,))
            if "password_plain" not in link_cols:
                cur.execute("ALTER TABLE links ADD COLUMN password_plain TEXT NULL;")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_links_user_id ON links(user_id);")

        cur.execute("PRAGMA table_info(campaigns);")
        camp_cols = [r[1] for r in cur.fetchall()]
        if camp_cols:
            if "user_id" not in camp_cols:
                cur.execute("ALTER TABLE campaigns ADD COLUMN user_id INTEGER NULL;")
            cur.execute("UPDATE campaigns SET user_id = ? WHERE user_id IS NULL;", (admin_id,))
            cur.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id);")

        cur.execute("PRAGMA table_info(click_events);")
        click_cols = [r[1] for r in cur.fetchall()]
        if click_cols and "country" not in click_cols:
            cur.execute("ALTER TABLE click_events ADD COLUMN country TEXT DEFAULT 'Local Network';")

        conn.commit()
        conn.close()
    except Exception as e:
        print("Auto-migration notice:", e)

auto_migrate()

def iso(val):
    return val.isoformat(timespec="seconds") if isinstance(val, datetime) else val

def short_url_for(code: str) -> str:
    base = (app.config.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if not base or "127.0.0.1" in base or "localhost" in base:
        try:
            proto = request.headers.get("X-Forwarded-Proto", request.scheme)
            base = f"{proto}://{request.host}"
        except Exception:
            base = "http://localhost:5000"
    return f"{base}/{code}"

def row_to_link(row: dict) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "original_url": row["original_url"],
        "short_code": row["short_code"],
        "custom_alias": row["custom_alias"],
        "short_url": short_url_for(row["custom_alias"] or row["short_code"]),
        "created_at": iso(row["created_at"]),
        "expires_at": iso(row["expires_at"]),
        "click_limit": row["click_limit"],
        "click_count": max(0, row["click_count"]),
        "has_password": bool(row["password_hash"]),
        "password": row.get("password_plain") or "",
        "status": row["status"],
        "campaign_id": row["campaign_id"],
        "campaign_name": row["campaign_name"],
        "campaign_tag": row["campaign_tag"],
        "user_id": row.get("user_id"),
    }

def get_current_user() -> dict:
    user_id = session.get("user_id")
    if not session.get("authenticated") or not user_id:
        raise ApiError(401, "unauthorized", "Authentication required.")

    user = query_one("SELECT * FROM users WHERE id = %s", (user_id,))
    if not user:
        session.clear()
        raise ApiError(401, "unauthorized", "Session invalid. Please sign in again.")

    return user

def get_user_link_or_404(link_id: int, user_id: int) -> dict:
    link = query_one(f"{LINK_SELECT} WHERE l.id = %s", (link_id,))
    if not link:
        raise ApiError(404, "not_found", "Requested short link does not exist.")
    if link.get("user_id") != user_id:
        raise ApiError(403, "forbidden", "You do not have permission to access or modify this link.")
    return link

def json_body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError(400, "bad_request", "Expected valid JSON request body.")
    return body

def detect_country(req) -> str:
    ip = get_client_ip(req)
    lang = (req.headers.get("Accept-Language") or "").lower()

    if ip in ("127.0.0.1", "::1", "localhost"):
        return "India (Local Dev)" if "in" in lang else "Local Network"

    cf_country = req.headers.get("CF-IPCountry")
    if cf_country and len(cf_country) == 2:
        return cf_country.upper()

    for pattern, name in COUNTRY_PATTERNS:
        if pattern.search(lang):
            return name

    return "Global / Direct"

def _user_email(username: str) -> str:
    return username if "@" in username else f"{username.lower()}@linkpulse.io"

def _session_login(user: dict) -> None:
    session["authenticated"] = True
    session["user_id"] = user["id"]
    session["admin_name"] = user["name"]
    session["user_role"] = user["role"]
    session["user_country"] = user["country"]

@app.errorhandler(ApiError)
def handle_api_error(err):
    return jsonify({"error": {"code": err.code, "message": err.message}}), err.status

@app.errorhandler(404)
def handle_404(err):
    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "not_found", "message": "Resource not found."}}), 404
    return Response("<h1>404 — Short URL Not Found</h1>", status=404, mimetype="text/html")

@app.errorhandler(Exception)
def handle_all_exceptions(err):
    trace = traceback.format_exc()
    print("\n[UNHANDLED ERROR]:\n", trace)

    if isinstance(err, ApiError):
        return jsonify({"error": {"code": err.code, "message": err.message}}), err.status

    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "internal_error", "message": str(err)}}), 500

    html = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;padding:2rem;">
        <h1 style="color:#dc2626;">500 Internal Server Error</h1>
        <p><strong>Error Details:</strong> {str(err)}</p>
        <pre style="background:#fee2e2;padding:1rem;border-radius:8px;overflow-x:auto;">{trace}</pre>
        </body></html>"""
    return Response(html, status=500, mimetype="text/html")

@app.route("/login", methods=["GET"])
def serve_login():
    if session.get("authenticated"):
        return redirect("/")
    return send_from_directory(FRONTEND_DIR, "login.html")

@app.post("/api/login")
def api_login():
    data = json_body()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        admin = query_one("SELECT * FROM users WHERE username = %s", (ADMIN_USER,))
        if not admin:
            _, db = exec_db("""
                INSERT INTO users (name, username, password_hash, role, country, auth_provider)
                VALUES ('Admin', %s, %s, 'Admin', 'India', 'system')
            """, (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD)))
            db.commit()
            admin = query_one("SELECT * FROM users WHERE username = %s", (ADMIN_USER,))

        _session_login(admin)
        return jsonify({
            "data": {
                "success": True,
                "name": admin["name"],
                "role": admin["role"],
                "country": admin["country"],
                "email": f"{ADMIN_USER.lower()}@linkpulse.io"
            }
        })

    user = query_one("SELECT * FROM users WHERE username = %s", (username,))
    if user and user.get("password_hash") and check_password_hash(user["password_hash"], password):
        _session_login(user)
        return jsonify({
            "data": {
                "success": True,
                "name": user["name"],
                "role": user["role"],
                "country": user["country"],
                "email": _user_email(user["username"])
            }
        })

    raise ApiError(401, "unauthorized", "Invalid username or password.")

@app.post("/api/register")
def api_register():
    data = json_body()
    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip()
    country = (data.get("country") or "India").strip()
    age = data.get("age")
    role = (data.get("role") or "User").strip()
    password = (data.get("password") or "").strip()

    if not name or not username or not password:
        raise ApiError(400, "bad_request", "Name, username, and password are required.")
    if len(password) < 3:
        raise ApiError(400, "bad_request", "Password must be at least 3 characters.")

    if query_one("SELECT id FROM users WHERE username = %s", (username,)):
        raise ApiError(409, "conflict", "Username is already registered. Please sign in.")

    pwd_hash = generate_password_hash(password)
    try:
        age_val = int(age) if age is not None and str(age).strip() != "" else None
    except ValueError:
        age_val = None

    cur, db = exec_db("""
        INSERT INTO users (name, username, password_hash, country, age, role, auth_provider)
        VALUES (%s, %s, %s, %s, %s, %s, 'manual')
    """, (name, username, pwd_hash, country, age_val, role))
    user_id = cur.lastrowid
    db.commit()

    _session_login({"id": user_id, "name": name, "role": role, "country": country})

    return jsonify({
        "data": {
            "success": True,
            "name": name,
            "role": role,
            "country": country,
            "email": _user_email(username)
        }
    }), 201

@app.post("/api/auth/google")
def api_google_auth():
    data = json_body()
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "Google User").strip()

    if not email or "@" not in email:
        raise ApiError(400, "bad_request", "Valid Google account email required.")

    user = query_one("SELECT * FROM users WHERE username = %s", (email,))
    if not user:
        cur, db = exec_db("""
            INSERT INTO users (name, username, password_hash, country, age, role, auth_provider)
            VALUES (%s, %s, NULL, 'India', 25, 'Admin', 'google')
        """, (name, email))
        user_id = cur.lastrowid
        db.commit()
        role = "Admin"
        country = "India"
    else:
        if user.get("auth_provider") != "google" and user.get("password_hash"):
            raise ApiError(403, "forbidden", "An account with this email exists using password authentication. Please sign in with your password.")
        user_id = user["id"]
        name = user["name"]
        role = user["role"]
        country = user["country"]

    _session_login({"id": user_id, "name": name, "role": role, "country": country})

    return jsonify({
        "data": {
            "success": True,
            "name": name,
            "role": role,
            "country": country,
            "email": email
        }
    })

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/login")

@app.route("/api/account", methods=["GET", "PATCH"])
def account_settings():
    user = get_current_user()

    if request.method == "GET":
        return jsonify({
            "data": {
                "name": user["name"],
                "role": user["role"],
                "country": user["country"],
                "email": _user_email(user["username"])
            }
        })

    data = json_body()
    name = str(data.get("name") or user["name"]).strip()
    role = str(data.get("role") or user["role"]).strip()
    country = str(data.get("country") or user["country"]).strip()

    if not name:
        raise ApiError(400, "bad_request", "Full name cannot be empty.")

    _, db = exec_db("""
        UPDATE users SET name = %s, role = %s, country = %s WHERE id = %s
    """, (name, role, country, user["id"]))
    db.commit()

    session["admin_name"] = name
    session["user_role"] = role
    session["user_country"] = country

    return jsonify({
        "data": {
            "name": name,
            "role": role,
            "country": country,
            "email": _user_email(user["username"])
        }
    })

@app.get("/")
def serve_index():
    if not session.get("authenticated"):
        return redirect("/login")
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.get("/style.css")
def serve_css():
    return send_from_directory(FRONTEND_DIR, "style.css", mimetype="text/css")

@app.get("/Group_Logo.png")
def serve_group_logo():
    return send_from_directory(FRONTEND_DIR, "Group_Logo.png")

@app.get("/favicon.ico")
def serve_favicon():
    return Response(status=204)

@app.get("/api/links")
def list_links():
    user = get_current_user()
    query = (request.args.get("q") or "").strip()

    sql = f"{LINK_SELECT} WHERE l.user_id = %s"
    params = [user["id"]]

    if query:
        sql += " AND (l.title LIKE %s OR l.original_url LIKE %s OR l.short_code LIKE %s)"
        match = f"%{query}%"
        params.extend([match, match, match])

    sql += " ORDER BY l.created_at DESC"
    return jsonify({"data": [row_to_link(row) for row in query_all(sql, params)]})

@app.post("/api/links")
def create_link():
    user = get_current_user()
    ip = get_client_ip(request)

    rate_key = f"create:{user['id']}:{ip}"
    if not limiter.allow(rate_key, app.config["RATE_LIMIT_CREATE"], app.config["RATE_LIMIT_WINDOW_SECONDS"]):
        raise ApiError(429, "rate_limited", "Creation limit reached. Please wait a minute.")

    data = json_body()
    destination = validate_destination(data.get("original_url"))
    title = (data.get("title") or "").strip()[:160] or title_from_url(destination)

    alias = data.get("custom_alias")
    if alias:
        alias = validate_alias(alias.strip())
        if query_one("SELECT id FROM links WHERE short_code = %s OR custom_alias = %s", (alias, alias)):
            raise ApiError(409, "conflict", f"Alias '{alias}' is already in use.")

    code = alias or generate_short_code()
    if not alias:
        for _ in range(10):
            if not query_one("SELECT id FROM links WHERE short_code = %s OR custom_alias = %s", (code, code)):
                break
            code = generate_short_code()

    expires_at = parse_expires_at(data.get("expires_at"), allow_past=False)

    click_limit = data.get("click_limit")
    if click_limit:
        try:
            click_limit = max(1, int(click_limit))
        except (ValueError, TypeError):
            raise ApiError(400, "invalid_limit", "Click limit must be a positive number.")
    else:
        click_limit = None

    password = (data.get("password") or "").strip()
    has_valid_pwd = password and len(password) >= 3
    pwd_hash = generate_password_hash(password) if has_valid_pwd else None
    plain_pwd = password if has_valid_pwd else None

    campaign_id = data.get("campaign_id") or None
    if campaign_id:
        try:
            cid = int(campaign_id)
            campaign_id = cid if query_one("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (cid, user["id"])) else None
        except (ValueError, TypeError):
            campaign_id = None

    cur, db = exec_db("""
        INSERT INTO links (title, original_url, short_code, custom_alias, expires_at, click_limit, password_hash, password_plain, campaign_id, user_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (title, destination, code, alias, expires_at, click_limit, pwd_hash, plain_pwd, campaign_id, user["id"]))

    link_id = cur.lastrowid
    db.commit()

    return jsonify({"data": row_to_link(get_user_link_or_404(link_id, user["id"]))}), 201

@app.patch("/api/links/<int:link_id>")
def update_link(link_id):
    user = get_current_user()
    current = get_user_link_or_404(link_id, user["id"])
    data = json_body()

    title = current["title"]
    destination = current["original_url"]
    click_limit = current["click_limit"]
    expires_at = current["expires_at"]
    campaign_id = current["campaign_id"]
    pwd_hash = current["password_hash"]
    plain_pwd = current.get("password_plain")

    if "title" in data:
        cleaned_title = str(data.get("title") or "").strip()
        if cleaned_title:
            title = cleaned_title[:160]

    if "original_url" in data:
        destination = validate_destination(data.get("original_url"))

    if "click_limit" in data:
        val = data.get("click_limit")
        click_limit = int(val) if val not in (None, "") else None

    if "expires_at" in data:
        expires_at = parse_expires_at(data.get("expires_at"), allow_past=True)

    if "campaign_id" in data:
        cid = data.get("campaign_id")
        if cid:
            try:
                cid_int = int(cid)
                campaign_id = cid_int if query_one("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (cid_int, user["id"])) else None
            except (ValueError, TypeError):
                campaign_id = None
        else:
            campaign_id = None

    if data.get("clear_password"):
        pwd_hash = None
        plain_pwd = None
    elif "password" in data and str(data["password"]).strip() != "":
        raw_pwd = str(data["password"]).strip()
        if len(raw_pwd) < 3:
            raise ApiError(400, "invalid_password", "Password must be at least 3 characters.")
        pwd_hash = generate_password_hash(raw_pwd)
        plain_pwd = raw_pwd

    _, db = exec_db("""
        UPDATE links 
        SET title = %s, original_url = %s, click_limit = %s, expires_at = %s, campaign_id = %s, password_hash = %s, password_plain = %s
        WHERE id = %s AND user_id = %s
    """, (title, destination, click_limit, expires_at, campaign_id, pwd_hash, plain_pwd, link_id, user["id"]))
    db.commit()

    return jsonify({"data": row_to_link(get_user_link_or_404(link_id, user["id"]))})

@app.patch("/api/links/<int:link_id>/status")
def toggle_status(link_id):
    user = get_current_user()
    data = json_body()

    new_status = data.get("status")
    if new_status not in ("active", "disabled"):
        raise ApiError(400, "invalid_status", "Status must be 'active' or 'disabled'.")

    get_user_link_or_404(link_id, user["id"])
    _, db = exec_db("UPDATE links SET status = %s WHERE id = %s AND user_id = %s", (new_status, link_id, user["id"]))
    db.commit()

    return jsonify({"data": row_to_link(get_user_link_or_404(link_id, user["id"]))})

@app.delete("/api/links/<int:link_id>")
def delete_link(link_id):
    user = get_current_user()
    get_user_link_or_404(link_id, user["id"])
    _, db = exec_db("DELETE FROM links WHERE id = %s AND user_id = %s", (link_id, user["id"]))
    db.commit()
    return jsonify({"data": {"deleted": True, "id": link_id}})

@app.post("/api/links/<int:link_id>/simulate-click")
def simulate_click(link_id):
    user = get_current_user()
    link = get_user_link_or_404(link_id, user["id"])

    if link["status"] != "active":
        raise ApiError(400, "link_inactive", f"Cannot simulate click: Link is currently {link['status']}.")

    if link["click_limit"] is not None and link["click_count"] >= link["click_limit"]:
        raise ApiError(400, "limit_reached", "Cannot simulate click: Link has reached its maximum click limit.")

    _, db = exec_db("UPDATE links SET click_count = click_count + 1 WHERE id = %s AND user_id = %s", (link_id, user["id"]))
    country = detect_country(request)
    ip_hash = anonymize_ip(f"simulated-{user['id']}-{datetime.now().timestamp()}", app.config["SECRET_KEY"])

    try:
        exec_db("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot, country)
            VALUES (%s, 'Direct / Demo', 'Mozilla/5.0 LinkPulse Test', 'desktop', 'Chrome', %s, 0, %s)
        """, (link_id, ip_hash, country))
    except Exception:
        exec_db("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot)
            VALUES (%s, 'Direct / Demo', 'Mozilla/5.0 LinkPulse Test', 'desktop', 'Chrome', %s, 0)
        """, (link_id, ip_hash))

    db.commit()
    return jsonify({"data": {"success": True, "clicks": link["click_count"] + 1, "country": country}})

@app.get("/api/campaigns")
def list_campaigns():
    user = get_current_user()
    rows = query_all("""
        SELECT c.id, c.name, c.tag, c.created_at,
               COUNT(l.id) AS link_count,
               COALESCE(SUM(l.click_count), 0) AS click_count
        FROM campaigns c
        LEFT JOIN links l ON l.campaign_id = c.id AND l.user_id = %s
        WHERE c.user_id = %s OR c.user_id IS NULL
        GROUP BY c.id, c.name, c.tag, c.created_at
        ORDER BY c.created_at DESC
    """, (user["id"], user["id"]))

    items = []
    for row in rows:
        item = dict(row)
        if isinstance(item.get("created_at"), datetime):
            item["created_at"] = item["created_at"].isoformat()
        item["click_count"] = int(item.get("click_count") or 0)
        item["link_count"] = int(item.get("link_count") or 0)
        items.append(item)

    return jsonify({"data": items})

@app.post("/api/campaigns")
def create_campaign():
    user = get_current_user()
    data = json_body()

    name = str(data.get("name") or "").strip()
    if not name:
        raise ApiError(400, "invalid_campaign", "Campaign name is required.")

    raw_tag = str(data.get("tag") or "").strip().lstrip("#")
    tag = slugify(raw_tag) if raw_tag else slugify(name)
    if not tag:
        tag = f"camp-{int(datetime.now().timestamp())}"

    existing = query_one(
        "SELECT id FROM campaigns WHERE (LOWER(name) = LOWER(%s) OR LOWER(tag) = LOWER(%s)) AND user_id = %s",
        (name, tag, user["id"])
    )
    if existing:
        raise ApiError(409, "conflict", f"A campaign with this name or tag (#{tag}) already exists.")

    cur, db = exec_db("INSERT INTO campaigns (name, tag, user_id) VALUES (%s, %s, %s)", (name, tag, user["id"]))
    camp_id = cur.lastrowid
    db.commit()

    created = query_one("SELECT * FROM campaigns WHERE id = %s", (camp_id,))
    if created and isinstance(created.get("created_at"), datetime):
        created["created_at"] = created["created_at"].isoformat()

    return jsonify({"data": created}), 201

@app.route("/api/campaigns/<int:campaign_id>", methods=["PATCH"])
def update_campaign(campaign_id):
    user = get_current_user()
    if not query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"])):
        raise ApiError(404, "not_found", "Campaign not found.")

    data = json_body()
    name = str(data.get("name") or "").strip()
    tag = slugify(str(data.get("tag") or name)).strip("-")

    if not name:
        raise ApiError(400, "invalid_campaign", "Campaign name cannot be empty.")

    _, db = exec_db("UPDATE campaigns SET name = %s, tag = %s WHERE id = %s AND user_id = %s", (name, tag, campaign_id, user["id"]))
    db.commit()

    return jsonify({"data": query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))})

@app.delete("/api/campaigns/<int:campaign_id>")
def delete_campaign(campaign_id):
    user = get_current_user()
    if not query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"])):
        raise ApiError(404, "not_found", "Campaign not found.")

    exec_db("UPDATE links SET campaign_id = NULL WHERE campaign_id = %s AND user_id = %s", (campaign_id, user["id"]))
    _, db = exec_db("DELETE FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))
    db.commit()

    return jsonify({"data": {"deleted": True, "id": campaign_id}})

@app.get("/api/analytics/summary")
def analytics_summary():
    user = get_current_user()

    stats = query_one("""
        SELECT COUNT(*) AS total_links,
               SUM(CASE WHEN status = 'active' AND (expires_at IS NULL OR expires_at >= CURRENT_TIMESTAMP) THEN 1 ELSE 0 END) AS active_links,
               COALESCE(SUM(click_count), 0) AS total_clicks
        FROM links
        WHERE user_id = %s
    """, (user["id"],))

    uniques = query_one("""
        SELECT COUNT(DISTINCT ce.ip_hash) AS total_uniques
        FROM click_events ce
        JOIN links l ON l.id = ce.link_id
        WHERE ce.is_bot = 0 AND l.user_id = %s
    """, (user["id"],))

    camps = query_one("SELECT COUNT(*) AS total_campaigns FROM campaigns WHERE user_id = %s", (user["id"],))

    return jsonify({"data": {
        "total_links": max(0, stats["total_links"] or 0) if stats else 0,
        "active_links": max(0, stats["active_links"] or 0) if stats else 0,
        "total_clicks": max(0, stats["total_clicks"] or 0) if stats else 0,
        "unique_visitors": max(0, uniques["total_uniques"] or 0) if uniques else 0,
        "total_campaigns": max(0, camps["total_campaigns"] or 0) if camps else 0,
    }})

@app.get("/api/analytics/clicks")
def analytics_clicks():
    user = get_current_user()

    try:
        days = min(max(int(request.args.get("days", 7)), 1), 90)
    except ValueError:
        days = 7

    today = datetime.now().date()
    start_date = (today - timedelta(days=days - 1)).isoformat()

    rows = query_all("""
        SELECT DATE(ce.clicked_at) AS d, COUNT(*) AS c
        FROM click_events ce
        JOIN links l ON l.id = ce.link_id
        WHERE ce.is_bot = 0 AND ce.clicked_at >= %s AND l.user_id = %s
        GROUP BY DATE(ce.clicked_at)
    """, (start_date, user["id"]))

    counts = {str(r["d"]): max(0, r["c"]) for r in rows}
    series = [
        {"date": dt, "clicks": max(0, counts.get(dt, 0))}
        for dt in ((today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1))
    ]

    return jsonify({"data": series})

@app.get("/api/analytics/breakdown")
def analytics_breakdown():
    user = get_current_user()

    total_row = query_one("""
        SELECT COUNT(*) as c
        FROM click_events ce
        JOIN links l ON l.id = ce.link_id
        WHERE ce.is_bot = 0 AND l.user_id = %s
    """, (user["id"],))
    total_clicks = max(1, (total_row["c"] if total_row and total_row["c"] else 0))

    def fetch_breakdown(expr: str, fallback: str):
        return query_all(f"""
            SELECT COALESCE(NULLIF({expr}, ''), %s) AS source, COUNT(*) AS count
            FROM click_events ce
            JOIN links l ON l.id = ce.link_id
            WHERE ce.is_bot = 0 AND l.user_id = %s
            GROUP BY source ORDER BY count DESC LIMIT 5
        """, (fallback, user["id"]))

    sources = fetch_breakdown("ce.referrer", "Direct / Email")
    devices = fetch_breakdown("ce.device_type", "desktop")

    try:
        countries = fetch_breakdown("ce.country", "Direct / Local")
    except Exception:
        countries = []

    def format_breakdown(records):
        return [
            {
                "name": str(item["source"]),
                "count": max(0, item["count"]),
                "pct": round((item["count"] / total_clicks) * 100)
            }
            for item in records
        ]

    return jsonify({"data": {
        "sources": format_breakdown(sources),
        "devices": format_breakdown(devices),
        "countries": format_breakdown(countries)
    }})

@app.route("/<short_code>", methods=["GET", "POST"])
def redirect_engine(short_code):
    if short_code in {"api", "favicon.ico", "Group_Logo.png", "login", "logout", "robots.txt", "style.css"}:
        return Response(status=404)

    link = query_one(f"{LINK_SELECT} WHERE l.short_code = %s OR l.custom_alias = %s", (short_code, short_code))
    if not link:
        return Response("<h1>404 — Short URL Not Found</h1>", status=404, mimetype="text/html")

    if link["status"] != "active":
        return Response("<h1>Link Expired or Inactive</h1>", status=410, mimetype="text/html")

    if link["click_limit"] is not None and link["click_count"] >= link["click_limit"]:
        return Response("<h1>Click Limit Reached</h1>", status=410, mimetype="text/html")

    ip = get_client_ip(request)

    if link["password_hash"]:
        if request.method == "POST":
            rate_key = f"pw:{short_code}:{ip}"
            limit = app.config.get("RATE_LIMIT_PASSWORD", 8)
            window = app.config.get("RATE_LIMIT_WINDOW_SECONDS", 60)
            if not limiter.allow(rate_key, limit, window):
                return Response(
                    "<h1>429 — Too Many Password Attempts</h1><p>Please wait 60 seconds before trying again.</p>",
                    status=429,
                    mimetype="text/html"
                )

        entered = request.form.get("link_password")
        if not entered or not check_password_hash(link["password_hash"], entered):
            err_html = "<p style='color:#ef4444;font-size:0.85rem;font-weight:600;margin:0.5rem 0;'>Incorrect password. Please try again.</p>" if request.method == "POST" else ""
            return GATE_CARD_HTML.format(error_html=err_html), 200

    ua = request.headers.get("User-Agent") or ""
    device, browser, is_bot = classify_user_agent(ua)
    ref = sanitize_referrer(request.headers.get("Referer"))
    ip_hash = anonymize_ip(ip, app.config["SECRET_KEY"])
    country = detect_country(request)

    db = get_db()
    cur = db.cursor()

    if not is_bot:
        placeholder = "?" if get_engine() == "sqlite" else "%s"
        cur.execute(f"""
            UPDATE links SET click_count = click_count + 1
            WHERE id = {placeholder} AND (click_limit IS NULL OR click_count < click_limit)
        """, (link["id"],))

        if cur.rowcount == 0 and link["click_limit"] is not None:
            return Response("<h1>Click Limit Reached</h1>", status=410, mimetype="text/html")

    is_sqlite = get_engine() == "sqlite"
    ph = "?" if is_sqlite else "%s"

    try:
        cur.execute(f"""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot, country)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
        """, (link["id"], ref, ua[:512], device, browser, ip_hash, 1 if is_bot else 0, country))
    except Exception:
        cur.execute(f"""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
        """, (link["id"], ref, ua[:512], device, browser, ip_hash, 1 if is_bot else 0))

    db.commit()
    return redirect(link["original_url"], code=303 if request.method == "POST" else 302)

@app.route("/api/links/export", methods=["GET"])
def export_csv():
    user = get_current_user()
    rows = query_all(f"{LINK_SELECT} WHERE l.user_id = %s ORDER BY l.created_at DESC", (user["id"],))

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Title", "Destination", "Short URL", "Clicks", "Status", "Expires At", "Click Limit", "Campaign"])

    for row in rows:
        writer.writerow([
            row["title"],
            row["original_url"],
            short_url_for(row["custom_alias"] or row["short_code"]),
            max(0, row["click_count"]),
            row["status"],
            row["expires_at"] or "",
            row["click_limit"] or "",
            row["campaign_name"] or ""
        ])

    return Response(
        "\ufeff" + buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=linkpulse-export-{datetime.now():%Y%m%d}.csv"}
    )

@app.route("/api/links/import", methods=["POST"])
def import_csv():
    user = get_current_user()

    if "file" not in request.files:
        raise ApiError(400, "invalid_file", "No CSV file uploaded.")

    file = request.files["file"]
    if not file or not file.filename:
        raise ApiError(400, "invalid_file", "No CSV file selected.")

    filename = os.path.basename(file.filename)
    if not filename.lower().endswith((".csv", ".txt", ".tsv")):
        raise ApiError(400, "invalid_format", "Please upload a valid .csv file.")

    raw = file.read()
    if len(raw) > app.config["CSV_MAX_BYTES"]:
        raise ApiError(413, "payload_too_large", "CSV file exceeds maximum allowed size.")

    if not raw.strip():
        raise ApiError(400, "empty_file", "The uploaded CSV file is empty.")

    text = None
    for enc in ("utf-8-sig", "utf-16", "utf-8", "latin-1", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue

    if text is None:
        raise ApiError(400, "invalid_encoding", "Unable to decode CSV file. Please ensure it is UTF-8 encoded.")

    campaign_name = filename[:-4].strip() if filename.lower().endswith(".csv") else os.path.splitext(filename)[0].strip()
    campaign_name = (campaign_name or "Imported Campaign")[:120]
    base_tag = slugify(campaign_name) or "campaign"

    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ApiError(400, "empty_file", "The uploaded CSV file contains no content.")

    delimiter = ","
    try:
        sample = "\n".join(lines[:10])
        dialect = csv.Sniffer().sniff(sample, delimiters=";,|\t,")
        delimiter = dialect.delimiter
    except Exception:
        first_line = lines[0]
        delim_counts = {d: first_line.count(d) for d in (",", ";", "\t", "|")}
        best_delim = max(delim_counts, key=delim_counts.get)
        if delim_counts[best_delim] > 0:
            delimiter = best_delim

    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    if not rows:
        raise ApiError(400, "empty_file", "The uploaded CSV file contains no content.")

    def clean_header(val):
        return re.sub(r"[^a-z0-9]", "", str(val).strip().lower())

    header = [clean_header(c) for c in rows[0]]
    dest_idx = -1
    title_idx = -1

    dest_keys = {
        "destination", "destinationurl", "originalurl", "targeturl",
        "longurl", "url", "urls", "link", "links", "target", "website",
        "weburl", "site", "webpage", "shorturl"
    }
    title_keys = {"title", "name", "linktitle", "titlename", "label"}

    for idx, col in enumerate(header):
        if col in dest_keys:
            if dest_idx == -1 or col in ("destination", "originalurl", "destinationurl"):
                dest_idx = idx
        elif col in title_keys:
            title_idx = idx

    is_header = False
    if dest_idx != -1:
        first_cell = str(rows[0][dest_idx]).strip().lower()
        if not (first_cell.startswith("http://") or first_cell.startswith("https://") or "www." in first_cell):
            is_header = True
        else:
            is_header = False
            dest_idx = -1

    data_rows = rows[1:] if is_header else rows
    max_rows = app.config.get("MAX_IMPORT_ROWS", 2500)

    valid_links = []
    seen = set()
    duplicates = 0
    invalid = 0
    errors = []

    for r_idx, row in enumerate(data_rows, start=2 if is_header else 1):
        if r_idx > max_rows:
            break
        if not row or not any(str(c).strip() for c in row):
            continue

        raw_dest = ""
        raw_title = ""

        if dest_idx != -1 and dest_idx < len(row):
            raw_dest = str(row[dest_idx]).strip().strip("\"'<>")
            if title_idx != -1 and title_idx < len(row):
                raw_title = str(row[title_idx]).strip().strip("\"'")

        if not raw_dest:
            for cell in row:
                c_str = str(cell).strip().strip("\"'<>")
                if re.match(r"^https?://", c_str, re.IGNORECASE) or c_str.startswith("www."):
                    raw_dest = c_str
                    break

            if not raw_dest:
                for cell in row:
                    c_str = str(cell).strip().strip("\"'<>")
                    if "." in c_str and " " not in c_str and len(c_str) >= 4:
                        if not c_str.lower().endswith((".csv", ".txt", ".png", ".jpg", ".pdf")):
                            raw_dest = c_str
                            break

            if not raw_title and len(row) > 1:
                for cell in row:
                    c_str = str(cell).strip().strip("\"'")
                    if c_str and c_str != raw_dest and not c_str.startswith(("http://", "https://")):
                        raw_title = c_str
                        break

        if not raw_dest:
            invalid += 1
            errors.append(f"Row {r_idx}: No URL found")
            continue

        if not re.match(r"^https?://", raw_dest, re.IGNORECASE):
            if "." in raw_dest and not raw_dest.startswith(("/", "#", "mailto:", "javascript:")):
                raw_dest = f"https://{raw_dest}"

        try:
            destination = validate_destination(raw_dest)
        except Exception as e:
            invalid += 1
            errors.append(f"Row {r_idx}: {str(e)}")
            continue

        dest_key = destination.lower()
        if dest_key in seen:
            duplicates += 1
            continue
        seen.add(dest_key)

        title = (raw_title or title_from_url(destination)).strip()[:160]
        valid_links.append((title, destination))

    if not valid_links:
        err_msg = f" (Found {invalid} invalid row(s))." if invalid else ""
        raise ApiError(400, "no_valid_links", f"No valid links could be extracted from the CSV file.{err_msg}")

    final_name = campaign_name
    final_tag = base_tag
    counter = 1

    while query_one(
        "SELECT id FROM campaigns WHERE (LOWER(name) = LOWER(%s) OR LOWER(tag) = LOWER(%s)) AND user_id = %s",
        (final_name, final_tag, user["id"])
    ):
        counter += 1
        final_name = f"{campaign_name} ({counter})"
        final_tag = f"{base_tag}-{counter}"

    cur, db = exec_db("INSERT INTO campaigns (name, tag, user_id) VALUES (%s, %s, %s)", (final_name, final_tag, user["id"]))
    campaign_id = cur.lastrowid

    imported = 0
    for title, dest in valid_links:
        code = generate_short_code()
        for _ in range(10):
            if not query_one("SELECT id FROM links WHERE short_code = %s", (code,)):
                break
            code = generate_short_code()

        exec_db("""
            INSERT INTO links (title, original_url, short_code, campaign_id, user_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (title, dest, code, campaign_id, user["id"]))
        imported += 1

    db.commit()

    notes = []
    if duplicates:
        notes.append(f"{duplicates} duplicate{'s' if duplicates != 1 else ''} skipped")
    if invalid:
        notes.append(f"{invalid} invalid row{'s' if invalid != 1 else ''} skipped")

    feedback = f"Campaign '{final_name}' created with {imported} link{'s' if imported != 1 else ''}."
    if notes:
        feedback += f" ({', '.join(notes)})"

    return jsonify({
        "data": {
            "campaign_id": campaign_id,
            "campaign_name": final_name,
            "campaign_tag": final_tag,
            "imported": imported,
            "duplicates": duplicates,
            "failed": invalid,
            "errors": errors[:10],
            "message": feedback
        }
    }), 201

@app.route("/api/campaigns/<int:campaign_id>/details", methods=["GET"])
def get_campaign_details(campaign_id):
    user = get_current_user()
    camp = query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))
    if not camp:
        raise ApiError(404, "not_found", "Campaign not found.")

    assigned_links = query_all("""
        SELECT id, title, short_code, custom_alias, original_url, click_count
        FROM links
        WHERE campaign_id = %s AND user_id = %s
    """, (campaign_id, user["id"]))

    all_links = query_all("""
        SELECT id, title, short_code, custom_alias, campaign_id
        FROM links
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user["id"],))

    return jsonify({
        "data": {
            "campaign": camp,
            "assigned_links": assigned_links,
            "all_links": all_links
        }
    })

@app.route("/api/campaigns/<int:campaign_id>/assign-link", methods=["POST"])
def assign_campaign_link(campaign_id):
    user = get_current_user()
    if not query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"])):
        raise ApiError(404, "not_found", "Campaign not found.")

    data = json_body()
    link_id = data.get("link_id")
    if not link_id:
        raise ApiError(400, "invalid_id", "A valid link_id is required.")

    action = data.get("action", "add")
    get_user_link_or_404(link_id, user["id"])

    if action == "add":
        _, db = exec_db("UPDATE links SET campaign_id = %s WHERE id = %s AND user_id = %s", (campaign_id, link_id, user["id"]))
    else:
        _, db = exec_db("UPDATE links SET campaign_id = NULL WHERE id = %s AND campaign_id = %s AND user_id = %s", (link_id, campaign_id, user["id"]))

    db.commit()
    return jsonify({"data": {"success": True}})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"\n[LinkPulse] Server running on port {port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
