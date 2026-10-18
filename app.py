"""LinkPulse - Main Application Server & API Engine."""

import csv
import io
import os
import sqlite3
import traceback
from datetime import datetime, timedelta
from flask import Flask, Response, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import close_db, get_db, initialize_database, query_all, query_one
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

# 2. Auto-Migrate DB on Startup (Adds 'country' column if missing)
def auto_migrate():
    try:
        if Config.DB_ENGINE == "mysql":
            return
        conn = sqlite3.connect(Config.SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(click_events);")
        cols = [r[1] for r in cur.fetchall()]
        if cols and "country" not in cols:
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
           l.password_hash, l.campaign_id,
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
            base = "http://127.0.0.1:5000"
    return f"{base}/{code}"

def row_to_link(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "original_url": row["original_url"],
        "short_code": row["short_code"],
        "custom_alias": row["custom_alias"],
        "short_url": short_url_for(row["short_code"]),
        "created_at": iso(row["created_at"]),
        "expires_at": iso(row["expires_at"]),
        "click_limit": row["click_limit"],
        "click_count": max(0, row["click_count"]),
        "has_password": bool(row["password_hash"]),
        "status": row["status"],
        "campaign_id": row["campaign_id"],
        "campaign_name": row["campaign_name"],
        "campaign_tag": row["campaign_tag"],
    }

def get_link_or_404(link_id):
    row = query_one(LINK_SELECT + " WHERE l.id = %s", (link_id,))
    if not row:
        raise ApiError(404, "not_found", "Requested short link does not exist.")
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

# ----------------- Error Handlers (With Real Tracebacks) -----------------

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
    print("\n🚨 UNHANDLED 500 CRASH:\n", error_trace)
    if isinstance(e, ApiError):
        return jsonify({"error": {"code": e.code, "message": e.message}}), e.status
    if request.path.startswith("/api/"):
        return jsonify({"error": {"code": "internal_error", "message": str(e), "trace": error_trace}}), 500
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

@app.route("/login", methods=["GET", "POST"])
def serve_login():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            session["authenticated"] = True
            session["admin_name"] = username
            if request.is_json:
                return jsonify({"data": {"success": True, "message": "Login successful"}})
            return redirect("/")
        if request.is_json:
            raise ApiError(401, "unauthorized", "Invalid username or password.")
        return redirect("/login")

    if session.get("authenticated"):
        return redirect("/")
    return send_from_directory(FRONTEND_DIR, "login.html")

@app.post("/api/login")
def api_login():
    data = json_body()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        session["authenticated"] = True
        session["admin_name"] = username
        return jsonify({"data": {"success": True, "message": "Login successful"}})
    raise ApiError(401, "unauthorized", "Invalid username or password.")

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/login")

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
    q = (request.args.get("q") or "").strip()
    sql = LINK_SELECT
    params = []
    if q:
        sql += " WHERE l.title LIKE %s OR l.original_url LIKE %s OR l.short_code LIKE %s"
        p = f"%{q}%"
        params = [p, p, p]
    sql += " ORDER BY l.created_at DESC"
    rows = query_all(sql, params)
    return jsonify({"data": [row_to_link(r) for r in rows]})

@app.post("/api/links")
def create_link():
    ip = request.remote_addr or "unknown"
    if not limiter.allow(f"create:{ip}", app.config["RATE_LIMIT_CREATE"], app.config["RATE_LIMIT_WINDOW_SECONDS"]):
        raise ApiError(429, "rate_limited", "Creation limit reached. Please wait a minute.")

    data = json_body()
    destination = validate_destination(data.get("original_url"))
    title = (data.get("title") or "").strip()[:160] or title_from_url(destination)

    alias = data.get("custom_alias")
    if alias:
        alias = validate_alias(alias.strip())
        if query_one("SELECT id FROM links WHERE short_code = %s", (alias,)):
            raise ApiError(409, "conflict", f"Alias '{alias}' is already in use.")

    code = alias or generate_short_code()
    if not alias:
        for _ in range(10):
            if not query_one("SELECT id FROM links WHERE short_code = %s", (code,)):
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
        except (ValueError, TypeError):
            campaign_id = None

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO links (title, original_url, short_code, custom_alias, expires_at, click_limit, password_hash, campaign_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (title, destination, code, alias, expires_at, click_limit, pwd_hash, campaign_id))
    link_id = cur.lastrowid
    db.commit()

    return jsonify({"data": row_to_link(get_link_or_404(link_id))}), 201

@app.patch("/api/links/<int:link_id>")
def update_link(link_id):
    current = get_link_or_404(link_id)
    data = json_body()
    title = current["title"]
    destination = current["original_url"]
    click_limit = current["click_limit"]
    expires_at = current["expires_at"]

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

    db = get_db()
    db.cursor().execute("""
        UPDATE links SET title = %s, original_url = %s, click_limit = %s, expires_at = %s
        WHERE id = %s
    """, (title, destination, click_limit, expires_at, link_id))
    db.commit()
    return jsonify({"data": row_to_link(get_link_or_404(link_id))})

@app.patch("/api/links/<int:link_id>/status")
def toggle_status(link_id):
    data = json_body()
    new_status = data.get("status")
    if new_status not in ("active", "disabled"):
        raise ApiError(400, "invalid_status", "Status must be 'active' or 'disabled'.")
    get_link_or_404(link_id)
    db = get_db()
    db.cursor().execute("UPDATE links SET status = %s WHERE id = %s", (new_status, link_id))
    db.commit()
    return jsonify({"data": row_to_link(get_link_or_404(link_id))})

@app.delete("/api/links/<int:link_id>")
def delete_link(link_id):
    get_link_or_404(link_id)
    db = get_db()
    db.cursor().execute("DELETE FROM links WHERE id = %s", (link_id,))
    db.commit()
    return jsonify({"data": {"deleted": True, "id": link_id}})

# ----------------- Instant Click Simulator Endpoint -----------------

@app.post("/api/links/<int:link_id>/simulate-click")
def simulate_click(link_id):
    link = get_link_or_404(link_id)
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE links SET click_count = click_count + 1 WHERE id = %s", (link_id,))
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
    rows = query_all("""
        SELECT c.id, c.name, c.tag, c.created_at,
               COUNT(l.id) AS link_count,
               COALESCE(SUM(l.click_count), 0) AS click_count
        FROM campaigns c LEFT JOIN links l ON l.campaign_id = c.id
        GROUP BY c.id, c.name, c.tag, c.created_at
        ORDER BY c.created_at DESC
    """)
    return jsonify({"data": rows})

@app.post("/api/campaigns")
def create_campaign():
    data = json_body()
    name = str(data.get("name") or "").strip()
    tag = slugify(str(data.get("tag") or name)).strip("-")
    if not name:
        raise ApiError(400, "invalid_campaign", "Campaign name is required.")
    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO campaigns (name, tag) VALUES (%s, %s)", (name, tag))
    c_id = cur.lastrowid
    db.commit()
    return jsonify({"data": query_one("SELECT * FROM campaigns WHERE id = %s", (c_id,))}), 201

@app.route("/api/campaigns/<int:campaign_id>", methods=["PATCH"])
def update_campaign(campaign_id):
    data = json_body()
    name = str(data.get("name") or "").strip()
    tag = slugify(str(data.get("tag") or name)).strip("-")
    if not name:
        raise ApiError(400, "invalid_campaign", "Campaign name cannot be empty.")
    db = get_db()
    db.cursor().execute("UPDATE campaigns SET name = %s, tag = %s WHERE id = %s", (name, tag, campaign_id))
    db.commit()
    return jsonify({"data": query_one("SELECT * FROM campaigns WHERE id = %s", (campaign_id,))})

@app.delete("/api/campaigns/<int:campaign_id>")
def delete_campaign(campaign_id):
    db = get_db()
    db.cursor().execute("DELETE FROM campaigns WHERE id = %s", (campaign_id,))
    db.commit()
    return jsonify({"data": {"deleted": True, "id": campaign_id}})

# ----------------- Analytics & Graph Telemetry -----------------

@app.get("/api/analytics/summary")
def analytics_summary():
    stats = query_one("""
        SELECT COUNT(*) AS total_links,
               SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_links,
               COALESCE(SUM(click_count), 0) AS total_clicks
        FROM links
    """)
    uniques = query_one("SELECT COUNT(DISTINCT ip_hash) AS total_uniques FROM click_events WHERE is_bot = 0")
    camps = query_one("SELECT COUNT(*) AS total_campaigns FROM campaigns")

    return jsonify({"data": {
        "total_links": max(0, stats["total_links"] or 0),
        "active_links": max(0, stats["active_links"] or 0),
        "total_clicks": max(0, stats["total_clicks"] or 0),
        "unique_visitors": max(0, uniques["total_uniques"] or 0),
        "total_campaigns": max(0, camps["total_campaigns"] or 0),
    }})

@app.get("/api/analytics/clicks")
def analytics_clicks():
    days = 7
    try:
        days = min(max(int(request.args.get("days", 7)), 1), 90)
    except ValueError:
        pass

    today = datetime.now().date()
    start_date = (today - timedelta(days=days - 1)).isoformat()

    rows = query_all("""
        SELECT DATE(clicked_at) AS d, COUNT(*) AS c
        FROM click_events
        WHERE is_bot = 0 AND clicked_at >= %s
        GROUP BY DATE(clicked_at)
    """, (start_date,))

    counts = {str(r["d"]): max(0, r["c"]) for r in rows}
    series = []
    for i in range(days):
        dt = (today - timedelta(days=i)).isoformat()
        series.append({"date": dt, "clicks": max(0, counts.get(dt, 0))})

    return jsonify({"data": series})

@app.get("/api/analytics/breakdown")
def analytics_breakdown():
    total_clicks = query_one("SELECT COUNT(*) as c FROM click_events WHERE is_bot = 0")["c"] or 1
    total_clicks = max(1, total_clicks)

    sources = query_all("""
        SELECT COALESCE(NULLIF(referrer, ''), 'Direct / Email') AS source, COUNT(*) AS count
        FROM click_events WHERE is_bot = 0 GROUP BY source ORDER BY count DESC LIMIT 5
    """)
    devices = query_all("""
        SELECT COALESCE(NULLIF(device_type, ''), 'desktop') AS source, COUNT(*) AS count
        FROM click_events WHERE is_bot = 0 GROUP BY source ORDER BY count DESC LIMIT 5
    """)
    try:
        countries = query_all("""
            SELECT COALESCE(NULLIF(country, ''), 'Direct / Local') AS source, COUNT(*) AS count
            FROM click_events WHERE is_bot = 0 GROUP BY source ORDER BY count DESC LIMIT 5
        """)
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
    if short_code in ("favicon.ico", "robots.txt"):
        return Response(status=404)

    row = query_one(LINK_SELECT + " WHERE l.short_code = %s", (short_code,))
    if not row:
        return Response("<h1>404 — Short URL Not Found</h1>", status=404, mimetype="text/html")

    if row["status"] != "active":
        return Response("<h1>Link Expired or Inactive</h1>", status=410, mimetype="text/html")

    # 1. Password Verification Gate
    if row["password_hash"]:
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

    # 2. Telemetry and Real Bot Classification
    ua = request.headers.get("User-Agent") or ""
    device, browser, is_bot = classify_user_agent(ua)
    ref = sanitize_referrer(request.headers.get("Referer"))
    ip_hash = anonymize_ip(request.remote_addr, app.config["SECRET_KEY"])
    country = detect_country(request)

    db = get_db()
    cur = db.cursor()

    # Only real human visits increment the click
    if not is_bot:
        cur.execute("""
            UPDATE links SET click_count = click_count + 1
            WHERE id = %s AND (click_limit IS NULL OR click_count < click_limit)
        """, (row["id"],))

        if cur.rowcount == 0 and row["click_limit"] is not None:
            return Response("<h1>Click Limit Reached</h1>", status=410, mimetype="text/html")

    # Safe Insert (Works even if country column was missing)
    try:
        cur.execute("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot, country)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (row["id"], ref, ua[:512], device, browser, 1 if is_bot else 0, country))
    except Exception:
        cur.execute("""
            INSERT INTO click_events (link_id, referrer, user_agent, device_type, browser, ip_hash, is_bot)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (row["id"], ref, ua[:512], device, browser, 1 if is_bot else 0))
        
    db.commit()

    return redirect(row["original_url"], code=302)

# ----------------- CSV Import / Export -----------------

@app.route("/api/links/export", methods=["GET"])
def export_csv():
    rows = query_all(LINK_SELECT + " ORDER BY l.created_at DESC")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Title", "Destination", "Short URL", "Clicks", "Status", "Expires At", "Click Limit", "Campaign"])
    for r in rows:
        writer.writerow([
            r["title"], r["original_url"], short_url_for(r["short_code"]),
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
            code = generate_short_code()
            db.cursor().execute("""
                INSERT INTO links (title, original_url, short_code) VALUES (%s, %s, %s)
            """, (title, dest, code))
            imported += 1
        except Exception as e:
            failed += 1
            errors.append(f"Row {idx}: {str(e)}")

    db.commit()
    return jsonify({"data": {"imported": imported, "failed": failed, "errors": errors[:20]}})

# ----------------- Campaign Links Details & Assignment -----------------

@app.route("/api/campaigns/<int:campaign_id>/details", methods=["GET"])
def get_campaign_details(campaign_id):
    camp = query_one("SELECT * FROM campaigns WHERE id = %s", (campaign_id,))
    if not camp:
        raise ApiError(404, "not_found", "Campaign not found.")
    assigned_links = query_all("SELECT id, title, short_code, original_url, click_count FROM links WHERE campaign_id = %s", (campaign_id,))
    all_links = query_all("SELECT id, title, short_code, campaign_id FROM links ORDER BY created_at DESC")
    return jsonify({
        "data": {
            "campaign": camp,
            "assigned_links": assigned_links,
            "all_links": all_links
        }
    })

@app.route("/api/campaigns/<int:campaign_id>/assign-link", methods=["POST"])
def assign_campaign_link(campaign_id):
    data = json_body()
    link_id = data.get("link_id")
    action = data.get("action", "add")
    db = get_db()
    if action == "add":
        db.cursor().execute("UPDATE links SET campaign_id = %s WHERE id = %s", (campaign_id, link_id))
    else:
        db.cursor().execute("UPDATE links SET campaign_id = NULL WHERE id = %s AND campaign_id = %s", (link_id, campaign_id))
    db.commit()
    return jsonify({"data": {"success": True}})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"\n🚀 LinkPulse Server running on port {port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
