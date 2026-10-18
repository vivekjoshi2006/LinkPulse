import csv
import io
import os
import sqlite3
import traceback
from datetime import datetime, timedelta
from flask import Flask, Response, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import close_db, get_db, get_engine, initialize_database, query_all, query_one
from helpers import (
    ApiError, RateLimiter, anonymize_ip, classify_user_agent,
    generate_short_code, parse_expires_at, sanitize_referrer,
    slugify, title_from_url, validate_alias, validate_destination
)

app = Flask(__name__, static_folder=None)
app.config.from_object(Config)
app.config["MAX_CONTENT_LENGTH"] = Config.CSV_MAX_BYTES + 1024

# 1. Initialize Tables on Startup
initialize_database(Config)

# 2. Auto-Migrate DB on Startup
def auto_migrate():
    try:
        if get_engine() == "mysql":
            return

        conn = sqlite3.connect(Config.SQLITE_PATH)
        cur = conn.cursor()

        # A. Ensure users table exists
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

        # B. Ensure default Admin user exists in users table
        cur.execute("SELECT id FROM users WHERE username = 'CWC';")
        admin_row = cur.fetchone()
        if not admin_row:
            cur.execute("""
                INSERT INTO users (name, username, password_hash, role, country, auth_provider)
                VALUES ('Admin', 'CWC', ?, 'Admin', 'India', 'system');
            """, (generate_password_hash("123"),))
            cur.execute("SELECT id FROM users WHERE username = 'CWC';")
            admin_row = cur.fetchone()
        admin_id = admin_row[0] if admin_row else 1

        # C. Ensure links table has user_id column and backfill orphan links
        cur.execute("PRAGMA table_info(links);")
        link_cols = [r[1] for r in cur.fetchall()]
        if link_cols and "user_id" not in link_cols:
            cur.execute("ALTER TABLE links ADD COLUMN user_id INTEGER NULL;")
        cur.execute("UPDATE links SET user_id = ? WHERE user_id IS NULL;", (admin_id,))

        # D. Ensure campaigns table has user_id column and backfill
        cur.execute("PRAGMA table_info(campaigns);")
        camp_cols = [r[1] for r in cur.fetchall()]
        if camp_cols and "user_id" not in camp_cols:
            cur.execute("ALTER TABLE campaigns ADD COLUMN user_id INTEGER NULL;")
        cur.execute("UPDATE campaigns SET user_id = ? WHERE user_id IS NULL;", (admin_id,))

        # E. Performance & security indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_links_user_id ON links(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id);")

        # F. Ensure click_events table has country column
        cur.execute("PRAGMA table_info(click_events);")
        click_cols = [r[1] for r in cur.fetchall()]
        if click_cols and "country" not in click_cols:
            cur.execute("ALTER TABLE click_events ADD COLUMN country TEXT DEFAULT 'Local Network';")

        conn.commit()
        conn.close()
    except Exception as e:
        print("Auto-migration notice:", e)

auto_migrate()

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

limiter = RateLimiter()
app.teardown_appcontext(close_db)

LINK_SELECT = """
    SELECT l.id, l.title, l.original_url, l.short_code, l.custom_alias,
           l.created_at, l.expires_at, l.click_limit, l.click_count,
           l.password_hash, l.campaign_id, l.user_id,
           c.name AS campaign_name, c.tag AS campaign_tag,
           CASE WHEN l.status = 'active' AND l.expires_at IS NOT NULL
                     AND l.expires_at < CURRENT_TIMESTAMP
                THEN 'expired' ELSE l.status END AS status
    FROM links l LEFT JOIN campaigns c ON c.id = l.campaign_id
"""

def iso(val):
    if isinstance(val, datetime):
        return val.isoformat(timespec="seconds")
    return val

def short_url_for(code):
    base = (app.config.get("PUBLIC_BASE_URL") or "").rstrip("/")
    if not base or "127.0.0.1" in base or "localhost" in base:
        try:
            proto = request.headers.get("X-Forwarded-Proto", request.scheme)
            host = request.host
            base = f"{proto}://{host}"
        except Exception:
            base = "http://localhost:5000"
    return f"{base}/{code}"

def row_to_link(row):
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
        "status": row["status"],
        "campaign_id": row["campaign_id"],
        "campaign_name": row["campaign_name"],
        "campaign_tag": row["campaign_tag"],
        "user_id": row.get("user_id"),
    }

def get_current_user():
    if not session.get("authenticated"):
        raise ApiError(401, "unauthorized", "Authentication required.")
    uid = session.get("user_id")
    if not uid:
        raise ApiError(401, "unauthorized", "Authentication required.")
    user = query_one("SELECT * FROM users WHERE id = %s", (uid,))
    if not user:
        session.clear()
        raise ApiError(401, "unauthorized", "Session invalid. Please sign in again.")
    return user

def get_user_link_or_404(link_id, user_id):
    row = query_one(LINK_SELECT + " WHERE l.id = %s", (link_id,))
    if not row:
        raise ApiError(404, "not_found", "Requested short link does not exist.")
    if row.get("user_id") != user_id:
        raise ApiError(403, "forbidden", "You do not have permission to access or modify this link.")
    return row

def json_body():
    payload = request.get_json(silent=True)
    if payload is None or not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "Expected valid JSON request body.")
    return payload

def detect_country(req):
    cf = req.headers.get("CF-IPCountry")
    if cf and len(cf) == 2:
        return cf.upper()
    lang = (req.headers.get("Accept-Language") or "").lower()
    if "in" in lang: return "India"
    if "us" in lang: return "United States"
    if "gb" in lang or "uk" in lang: return "United Kingdom"
    if "ca" in lang: return "Canada"
    if "de" in lang: return "Germany"
    if "fr" in lang: return "France"
    if "au" in lang: return "Australia"
    if req.remote_addr in ("127.0.0.1", "::1", "localhost"):
        return "India (Local Dev)" if "in" in lang else "Local Network"
    return "Global / Direct"

# ----------------- Error Handlers -----------------

@app.errorhandler(ApiError)
def handle_api_error(e):
    return jsonify({"error": {"code": e.code, "message": e.message}}), e.status

@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "not_found", "message": "Resource not found."}}), 404
    return Response("<h1>404 — Short URL Not Found</h1>", status=404, mimetype="text/html")

@app.errorhandler(Exception)
def handle_all_exceptions(e):
    error_trace = traceback.format_exc()
    print("\n[UNHANDLED ERROR]:\n", error_trace)
    if isinstance(e, ApiError):
        return jsonify({"error": {"code": e.code, "message": e.message}}), e.status
    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "internal_error", "message": str(e)}}), 500
    return Response(
        f"""<!DOCTYPE html><html><body style="font-family:sans-serif;padding:2rem;">
        <h1 style="color:#dc2626;">500 Internal Server Error</h1>
        <p><strong>Error Details:</strong> {str(e)}</p>
        <pre style="background:#fee2e2;padding:1rem;border-radius:8px;overflow-x:auto;">{error_trace}</pre>
        </body></html>""",
        status=500,
        mimetype="text/html"
    )

# ----------------- Credentials & Auth Routes -----------------

ADMIN_USER = os.getenv("ADMIN_USER", "CWC")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "123")

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
        admin_user = query_one("SELECT * FROM users WHERE username = %s", (ADMIN_USER,))
        if not admin_user:
            db = get_db()
            cur = db.cursor()
            cur.execute("""
                INSERT INTO users (name, username, password_hash, role, country, auth_provider)
                VALUES ('Admin', %s, %s, 'Admin', 'India', 'system')
            """, (ADMIN_USER, generate_password_hash(ADMIN_PASSWORD)))
            db.commit()
            admin_user = query_one("SELECT * FROM users WHERE username = %s", (ADMIN_USER,))

        session["authenticated"] = True
        session["user_id"] = admin_user["id"]
        session["admin_name"] = admin_user["name"]
        session["user_role"] = admin_user["role"]
        session["user_country"] = admin_user["country"]
        return jsonify({
            "data": {
                "success": True,
                "name": admin_user["name"],
                "role": admin_user["role"],
                "country": admin_user["country"],
                "email": f"{ADMIN_USER.lower()}@linkpulse.io"
            }
        })

    user = query_one("SELECT * FROM users WHERE username = %s", (username,))
    if user and user.get("password_hash") and check_password_hash(user["password_hash"], password):
        session["authenticated"] = True
        session["user_id"] = user["id"]
        session["admin_name"] = user["name"]
        session["user_role"] = user["role"]
        session["user_country"] = user["country"]
        return jsonify({
            "data": {
                "success": True,
                "name": user["name"],
                "role": user["role"],
                "country": user["country"],
                "email": user["username"] if "@" in user["username"] else f"{user['username'].lower()}@linkpulse.io"
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
        age_int = int(age) if age is not None and str(age).strip() != "" else None
    except ValueError:
        age_int = None

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO users (name, username, password_hash, country, age, role, auth_provider)
        VALUES (%s, %s, %s, %s, %s, %s, 'manual')
    """, (name, username, pwd_hash, country, age_int, role))
    user_id = cur.lastrowid
    db.commit()

    session["authenticated"] = True
    session["user_id"] = user_id
    session["admin_name"] = name
    session["user_role"] = role
    session["user_country"] = country

    return jsonify({
        "data": {
            "success": True,
            "name": name,
            "role": role,
            "country": country,
            "email": username if "@" in username else f"{username.lower()}@linkpulse.io"
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
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            INSERT INTO users (name, username, password_hash, country, age, role, auth_provider)
            VALUES (%s, %s, NULL, 'India', 25, 'Analyst', 'google')
        """, (name, email))
        user_id = cur.lastrowid
        db.commit()
        role = "Analyst"
        country = "India"
    else:
        # Prevent taking over password-based accounts without credentials
        if user.get("auth_provider") != "google" and user.get("password_hash"):
            raise ApiError(403, "forbidden", "An account with this email exists using password authentication. Please sign in with your password.")
        user_id = user["id"]
        name = user["name"]
        role = user["role"]
        country = user["country"]

    session["authenticated"] = True
    session["user_id"] = user_id
    session["admin_name"] = name
    session["user_role"] = role
    session["user_country"] = country

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

# ----------------- Account Settings Profile API -----------------

@app.route("/api/account", methods=["GET", "PATCH"])
def account_settings():
    user = get_current_user()

    if request.method == "GET":
        return jsonify({
            "data": {
                "name": user["name"],
                "role": user["role"],
                "country": user["country"],
                "email": user["username"] if "@" in user["username"] else f"{user['username'].lower()}@linkpulse.io"
            }
        })

    data = json_body()
    name = str(data.get("name") or user["name"]).strip()
    role = str(data.get("role") or user["role"]).strip()
    country = str(data.get("country") or user["country"]).strip()

    if not name:
        raise ApiError(400, "bad_request", "Full name cannot be empty.")

    db = get_db()
    db.cursor().execute("""
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
            "email": user["username"] if "@" in user["username"] else f"{user['username'].lower()}@linkpulse.io"
        }
    })

# ----------------- Static Asset Routes -----------------

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

# ----------------- Link Core API -----------------

@app.get("/api/links")
def list_links():
    user = get_current_user()
    q = (request.args.get("q") or "").strip()
    sql = LINK_SELECT + " WHERE l.user_id = %s"
    params = [user["id"]]
    if q:
        sql += " AND (l.title LIKE %s OR l.original_url LIKE %s OR l.short_code LIKE %s)"
        p = f"%{q}%"
        params.extend([p, p, p])
    sql += " ORDER BY l.created_at DESC"
    rows = query_all(sql, params)
    return jsonify({"data": [row_to_link(r) for r in rows]})

@app.post("/api/links")
def create_link():
    user = get_current_user()
    ip = request.remote_addr or "unknown"
    if not limiter.allow(f"create:{user['id']}:{ip}", app.config["RATE_LIMIT_CREATE"], app.config["RATE_LIMIT_WINDOW_SECONDS"]):
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

    expires_at = parse_expires_at(data.get("expires_at"))
    click_limit = data.get("click_limit")
    if click_limit:
        try:
            click_limit = max(1, int(click_limit))
        except (ValueError, TypeError):
            raise ApiError(400, "invalid_limit", "Click limit must be a positive number.")
    else:
        click_limit = None

    password = data.get("password")
    pwd_hash = generate_password_hash(password.strip()) if password and len(password.strip()) >= 3 else None

    campaign_id = data.get("campaign_id") or None
    if campaign_id:
        try:
            campaign_id = int(campaign_id)
            if not query_one("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"])):
                campaign_id = None
        except (ValueError, TypeError):
            campaign_id = None

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO links (title, original_url, short_code, custom_alias, expires_at, click_limit, password_hash, campaign_id, user_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (title, destination, code, alias, expires_at, click_limit, pwd_hash, campaign_id, user["id"]))

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

    if "title" in data:
        t = str(data.get("title") or "").strip()
        if t: title = t[:160]

    if "original_url" in data:
        destination = validate_destination(data.get("original_url"))

    if "click_limit" in data:
        val = data.get("click_limit")
        click_limit = int(val) if val not in (None, "") else None

    if "expires_at" in data:
        expires_at = parse_expires_at(data.get("expires_at"))

    if "campaign_id" in data:
        cid = data.get("campaign_id")
        if cid:
            try:
                cid = int(cid)
                campaign_id = cid if query_one("SELECT id FROM campaigns WHERE id = %s AND user_id = %s", (cid, user["id"])) else None
            except (ValueError, TypeError):
                campaign_id = None
        else:
            campaign_id = None

    if "password" in data:
        pw = str(data.get("password") or "").strip()
        if pw:
            if len(pw) < 3:
                raise ApiError(400, "invalid_password", "Password must be at least 3 characters.")
            pwd_hash = generate_password_hash(pw)
        else:
            pwd_hash = None  # Clear password protection

    db = get_db()
    db.cursor().execute("""
        UPDATE links 
        SET title = %s, original_url = %s, click_limit = %s, expires_at = %s, campaign_id = %s, password_hash = %s
        WHERE id = %s AND user_id = %s
    """, (title, destination, click_limit, expires_at, campaign_id, pwd_hash, link_id, user["id"]))
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
    db = get_db()
    db.cursor().execute("UPDATE links SET status = %s WHERE id = %s AND user_id = %s", (new_status, link_id, user["id"]))
    db.commit()
    return jsonify({"data": row_to_link(get_user_link_or_404(link_id, user["id"]))})

@app.delete("/api/links/<int:link_id>")
def delete_link(link_id):
    user = get_current_user()
    get_user_link_or_404(link_id, user["id"])
    db = get_db()
    db.cursor().execute("DELETE FROM links WHERE id = %s AND user_id = %s", (link_id, user["id"]))
    db.commit()
    return jsonify({"data": {"deleted": True, "id": link_id}})

# ----------------- Instant Click Simulator Endpoint -----------------

@app.post("/api/links/<int:link_id>/simulate-click")
def simulate_click(link_id):
    user = get_current_user()
    link = get_user_link_or_404(link_id, user["id"])

    if link["status"] != "active":
        raise ApiError(400, "link_inactive", f"Cannot simulate click: Link is currently {link['status']}.")

    if link["click_limit"] is not None and link["click_count"] >= link["click_limit"]:
        raise ApiError(400, "limit_reached", "Cannot simulate click: Link has reached its maximum click limit.")

    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE links SET click_count = click_count + 1 WHERE id = %s AND user_id = %s", (link_id, user["id"]))
    country = detect_country(request)
    try:
        cur.execute("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot, country)
            VALUES (%s, 'Direct / Demo', 'Mozilla/5.0 LinkPulse Test', 'desktop', 'Chrome', 'demo-test-ip', 0, %s)
        """, (link_id, country))
    except Exception:
        cur.execute("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot)
            VALUES (%s, 'Direct / Demo', 'Mozilla/5.0 LinkPulse Test', 'desktop', 'Chrome', 'demo-test-ip', 0)
        """, (link_id,))
    db.commit()
    return jsonify({"data": {"success": True, "clicks": link["click_count"] + 1, "country": country}})

# ----------------- Campaign Management -----------------

@app.get("/api/campaigns")
def list_campaigns():
    user = get_current_user()
    rows = query_all("""
        SELECT c.id, c.name, c.tag, c.created_at,
               COUNT(l.id) AS link_count,
               COALESCE(SUM(l.click_count), 0) AS click_count
        FROM campaigns c
        LEFT JOIN links l ON l.campaign_id = c.id AND l.user_id = %s
        WHERE c.user_id = %s
        GROUP BY c.id, c.name, c.tag, c.created_at
        ORDER BY c.created_at DESC
    """, (user["id"], user["id"]))
    return jsonify({"data": rows})

@app.post("/api/campaigns")
def create_campaign():
    user = get_current_user()
    data = json_body()
    name = str(data.get("name") or "").strip()
    tag = slugify(str(data.get("tag") or name)).strip("-")
    if not name:
        raise ApiError(400, "invalid_campaign", "Campaign name is required.")
    existing = query_one("SELECT id FROM campaigns WHERE (name = %s OR tag = %s) AND user_id = %s", (name, tag, user["id"]))
    if existing:
        raise ApiError(409, "conflict", "You already have a campaign with this name or tag.")
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO campaigns (name, tag, user_id) VALUES (%s, %s, %s)", (name, tag, user["id"]))
    c_id = cur.lastrowid
    db.commit()
    return jsonify({"data": query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (c_id, user["id"]))}), 201

@app.route("/api/campaigns/<int:campaign_id>", methods=["PATCH"])
def update_campaign(campaign_id):
    user = get_current_user()
    camp = query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))
    if not camp:
        raise ApiError(404, "not_found", "Campaign not found.")
    data = json_body()
    name = str(data.get("name") or "").strip()
    tag = slugify(str(data.get("tag") or name)).strip("-")
    if not name:
        raise ApiError(400, "invalid_campaign", "Campaign name cannot be empty.")
    db = get_db()
    db.cursor().execute("UPDATE campaigns SET name = %s, tag = %s WHERE id = %s AND user_id = %s", (name, tag, campaign_id, user["id"]))
    db.commit()
    return jsonify({"data": query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))})

@app.delete("/api/campaigns/<int:campaign_id>")
def delete_campaign(campaign_id):
    user = get_current_user()
    camp = query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))
    if not camp:
        raise ApiError(404, "not_found", "Campaign not found.")
    db = get_db()
    db.cursor().execute("DELETE FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))
    db.commit()
    return jsonify({"data": {"deleted": True, "id": campaign_id}})

# ----------------- Analytics & Graph Telemetry -----------------

@app.get("/api/analytics/summary")
def analytics_summary():
    user = get_current_user()
    stats = query_one("""
        SELECT COUNT(*) AS total_links,
               SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_links,
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
    days = 7
    try:
        days = min(max(int(request.args.get("days", 7)), 1), 90)
    except ValueError:
        pass

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
    series = []
    for i in range(days):
        dt = (today - timedelta(days=i)).isoformat()
        series.append({"date": dt, "clicks": max(0, counts.get(dt, 0))})

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

    sources = query_all("""
        SELECT COALESCE(NULLIF(ce.referrer, ''), 'Direct / Email') AS source, COUNT(*) AS count
        FROM click_events ce
        JOIN links l ON l.id = ce.link_id
        WHERE ce.is_bot = 0 AND l.user_id = %s
        GROUP BY source ORDER BY count DESC LIMIT 5
    """, (user["id"],))
    devices = query_all("""
        SELECT COALESCE(NULLIF(ce.device_type, ''), 'desktop') AS source, COUNT(*) AS count
        FROM click_events ce
        JOIN links l ON l.id = ce.link_id
        WHERE ce.is_bot = 0 AND l.user_id = %s
        GROUP BY source ORDER BY count DESC LIMIT 5
    """, (user["id"],))
    try:
        countries = query_all("""
            SELECT COALESCE(NULLIF(ce.country, ''), 'Direct / Local') AS source, COUNT(*) AS count
            FROM click_events ce
            JOIN links l ON l.id = ce.link_id
            WHERE ce.is_bot = 0 AND l.user_id = %s
            GROUP BY source ORDER BY count DESC LIMIT 5
        """, (user["id"],))
    except Exception:
        countries = []

    def present(rows):
        return [{"name": str(item["source"]), "count": max(0, item["count"]),
                 "pct": round((item["count"] / total_clicks) * 100)}
                for item in rows]

    return jsonify({"data": {
        "sources": present(sources),
        "devices": present(devices),
        "countries": present(countries)
    }})

# ----------------- Redirection Engine -----------------

@app.route("/<short_code>", methods=["GET", "POST"])
def redirect_engine(short_code):
    if short_code in ("favicon.ico", "robots.txt", "api", "login", "logout"):
        return Response(status=404)

    row = query_one(LINK_SELECT + " WHERE l.short_code = %s OR l.custom_alias = %s", (short_code, short_code))
    if not row:
        return Response("<h1>404 — Short URL Not Found</h1>", status=404, mimetype="text/html")

    if row["status"] != "active":
        return Response("<h1>Link Expired or Inactive</h1>", status=410, mimetype="text/html")

    # Enforce Click Cap Before Evaluating Password/Redirect
    if row["click_limit"] is not None and row["click_count"] >= row["click_limit"]:
        return Response("<h1>Click Limit Reached</h1>", status=410, mimetype="text/html")

    # 1. Password Verification Gate with Rate Limiting
    if row["password_hash"]:
        ip = request.remote_addr or "unknown"
        if request.method == "POST":
            if not limiter.allow(f"pw:{short_code}:{ip}", app.config.get("RATE_LIMIT_PASSWORD", 8), app.config.get("RATE_LIMIT_WINDOW_SECONDS", 60)):
                return Response("<h1>429 — Too Many Password Attempts</h1><p>Please wait 60 seconds before trying again.</p>", status=429, mimetype="text/html")

        provided_password = request.form.get("link_password")
        if not provided_password or not check_password_hash(row["password_hash"], provided_password):
            error_html = "<p style='color:#ef4444;font-size:0.85rem;font-weight:600;margin:0.5rem 0;'>Incorrect password. Please try again.</p>" if request.method == "POST" else ""
            return f"""<!DOCTYPE html>
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
</html>""", 200

    # 2. Telemetry and Bot Classification
    ua = request.headers.get("User-Agent") or ""
    device, browser, is_bot = classify_user_agent(ua)
    ref = sanitize_referrer(request.headers.get("Referer"))
    ip_hash = anonymize_ip(request.remote_addr, app.config["SECRET_KEY"])
    country = detect_country(request)

    db = get_db()
    cur = db.cursor()

    if not is_bot:
        cur.execute("""
            UPDATE links SET click_count = click_count + 1
            WHERE id = %s AND (click_limit IS NULL OR click_count < click_limit)
        """, (row["id"],))

        if cur.rowcount == 0 and row["click_limit"] is not None:
            return Response("<h1>Click Limit Reached</h1>", status=410, mimetype="text/html")

    try:
        cur.execute("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot, country)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (row["id"], ref, ua[:512], device, browser, ip_hash, 1 if is_bot else 0, country))
    except Exception:
        cur.execute("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (row["id"], ref, ua[:512], device, browser, ip_hash, 1 if is_bot else 0))

    db.commit()

    return redirect(row["original_url"], code=302)

# ----------------- CSV Import / Export -----------------

@app.route("/api/links/export", methods=["GET"])
def export_csv():
    user = get_current_user()
    rows = query_all(LINK_SELECT + " WHERE l.user_id = %s ORDER BY l.created_at DESC", (user["id"],))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Title", "Destination", "Short URL", "Clicks", "Status", "Expires At", "Click Limit", "Campaign"])
    for r in rows:
        writer.writerow([
            r["title"], r["original_url"], short_url_for(r["custom_alias"] or r["short_code"]),
            max(0, r["click_count"]), r["status"], r["expires_at"] or "",
            r["click_limit"] or "", r["campaign_name"] or ""
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
    raw = file.read()
    if len(raw) > app.config["CSV_MAX_BYTES"]:
        raise ApiError(413, "payload_too_large", "CSV file exceeds maximum allowed size.")

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ApiError(400, "invalid_encoding", "CSV must be UTF-8 encoded.")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ApiError(400, "invalid_csv", "CSV is empty or has no header row.")
    imported, failed, errors = 0, 0, []

    db = get_db()
    for idx, row in enumerate(reader, start=2):
        if idx - 1 > app.config["MAX_IMPORT_ROWS"]:
            break
        try:
            dest = validate_destination(row.get("Destination") or row.get("url") or "")
            title = (row.get("Title") or title_from_url(dest)).strip()
            
            # Collision-safe code generator
            code = generate_short_code()
            for _ in range(5):
                if not query_one("SELECT id FROM links WHERE short_code = %s", (code,)):
                    break
                code = generate_short_code()

            db.cursor().execute("""
                INSERT INTO links (title, original_url, short_code, user_id) VALUES (%s, %s, %s, %s)
            """, (title, dest, code, user["id"]))
            imported += 1
        except Exception as e:
            failed += 1
            errors.append(f"Row {idx}: {str(e)}")

    db.commit()
    return jsonify({"data": {"imported": imported, "failed": failed, "errors": errors[:20]}})

# ----------------- Campaign Links Details & Assignment -----------------

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
    camp = query_one("SELECT * FROM campaigns WHERE id = %s AND user_id = %s", (campaign_id, user["id"]))
    if not camp:
        raise ApiError(404, "not_found", "Campaign not found.")
    data = json_body()
    link_id = data.get("link_id")
    if not link_id:
        raise ApiError(400, "invalid_id", "A valid link_id is required.")
    action = data.get("action", "add")
    get_user_link_or_404(link_id, user["id"])
    db = get_db()
    if action == "add":
        db.cursor().execute("UPDATE links SET campaign_id = %s WHERE id = %s AND user_id = %s", (campaign_id, link_id, user["id"]))
    else:
        db.cursor().execute("UPDATE links SET campaign_id = NULL WHERE id = %s AND campaign_id = %s AND user_id = %s", (link_id, campaign_id, user["id"]))
    db.commit()
    return jsonify({"data": {"success": True}})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"\n[LinkPulse] Server running on port {port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
